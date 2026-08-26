use std::sync::atomic::{AtomicU64, Ordering};

use super::Cpu;
use crate::bus::prim::Requester;

const LINE_SIZE: usize = 32; // to match hw
const LINE_COUNT: usize = 4096; // 512 = 16KiB, 1024 = 32KiB, etc.... real arm926ej-s has between 4 - 128k. bigger is better, right?
const CACHE_OFF: u64 = 1; // cache disabled at startup time
const EXT_CACHE_OFF: u64 = 2; // external software control shuts off cache (can re-enable)

#[derive(Default)]
pub struct CacheControl {
    /// *** Low two bits are disable bits ***
    /// upper 62 bits are the epoch counter for invalidation
    epoch: AtomicU64,
}

impl CacheControl {
    pub fn disable_permanently(&self) {
        self.epoch.fetch_or(CACHE_OFF, Ordering::Release);
        self.invalidate();
    }

    pub fn set_disabled(&self, disabled: bool) {
        if disabled {
            self.epoch
                .try_update(Ordering::AcqRel, Ordering::Acquire, |s| {
                    Some(s.wrapping_add(4) | EXT_CACHE_OFF)
                })
                .unwrap();
        } else {
            self.epoch.fetch_and(!EXT_CACHE_OFF, Ordering::Release);
        }
    }

    pub fn invalidate(&self) {
        self.epoch.fetch_add(4, Ordering::Release);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FetchContext {
    translation: u64, // tlb cleared
    control: u32, // cp15 c1
    domains: u32, // dacr
    privileged: bool, // mode().is_privileged()
}

#[derive(Clone, Default)]
struct Line {
    tag: u32,
    valid: bool,
    bytes: [u8; LINE_SIZE],
    last_ctx: Option<FetchContext>,
}

pub(crate) struct InstructionCache {
    lines: Box<[Line]>,
    ic_epoch: u64,
}

impl Default for InstructionCache {
    fn default() -> Self {
        Self {
            lines: vec![Line::default(); LINE_COUNT].into_boxed_slice(),
            ic_epoch: 0,
        }
    }
}

impl InstructionCache {
    fn line(&mut self, addr: u32) -> &mut Line {
        &mut self.lines[(addr as usize / LINE_SIZE) % LINE_COUNT]
    }

    pub fn invalidate(&mut self) {
        for line in &mut self.lines {
            line.valid = false;
            line.last_ctx = None;
        }
    }

    pub fn invalidate_mva(&mut self, addr: u32) {
        let line = self.line(addr);
        if line.tag == addr & !(LINE_SIZE as u32 - 1) {
            line.valid = false;
            line.last_ctx = None;
        }
    }

    fn observe(&mut self, epoch: u64) -> bool {
        let epoch = epoch >> 2;
        if self.ic_epoch != epoch {
            self.invalidate();
            self.ic_epoch = epoch;
        }
        epoch & (CACHE_OFF | EXT_CACHE_OFF) == 0
    }

    fn read<const N: usize>(&mut self, addr: u32, context: FetchContext) -> Option<[u8; N]> {
        // Do we even want to acknowledge the fact that 1K pages are technically possible?
        // I for one, do not.
        //
        // let end = addr.checked_add(N as u32 - 1)?;
        // if addr >> 10 != end >> 10 {
            // return None;
        // }

        let within = addr as usize % LINE_SIZE;
        if within + N <= LINE_SIZE {
            let line = self.line(addr);
            if line.valid
                && line.tag == addr & !(LINE_SIZE as u32 - 1)
                && line.last_ctx == Some(context)
            {
                return line.bytes[within..within + N].try_into().ok();
            }
            return None;
        }
        // safegaurd against halfword aligned reads... hmmm
        let mut result = [0; N];
        for (i, byte) in result.iter_mut().enumerate() {
            let current = addr + i as u32;
            let line = self.line(current);
            if !line.valid
                || line.tag != current & !(LINE_SIZE as u32 - 1)
                || line.last_ctx != Some(context)
            {
                return None;
            }
            *byte = line.bytes[current as usize % LINE_SIZE];
        }
        Some(result)
    }
}

impl Cpu {
    pub fn fetch16(&mut self, addr: u32) -> anyhow::Result<u16> {
        Ok(u16::from_be_bytes(self.fetch_instruction(addr)?))
    }

    pub fn fetch32(&mut self, addr: u32) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(self.fetch_instruction(addr)?))
    }

    fn fetch_context(&self) -> FetchContext {
        FetchContext {
            translation: self.p15.translation_epoch.get(),
            control: self.p15.c1_ctrl.0,
            domains: self.p15.c3_dacr.0,
            privileged: self.reg.cpsr.0 & 0xf == 0, // This is essentially self.reg.cpsr.mode().is_privileged() but faster
        }
    }

    fn fetch_instruction<const N: usize>(&mut self, addr: u32) -> anyhow::Result<[u8; N]> {
        use super::mmu::prim::{Access, TLBReq};

        let enabled = self
            .p15
            .icache
            .observe(self.cache_control.epoch.load(Ordering::Acquire))
            && self.p15.c1_ctrl.icache_enabled();
        let context = self.fetch_context();
        if enabled {
            if let Some(bytes) = self.p15.icache.read(addr, context) {
                return Ok(bytes);
            }
            // miss
        }

        // refresh everything and fetch the instr the long way
        let bus = self.bus.read();
        let translation = self.translate_with_bus(TLBReq::new(addr, Access::Read), &bus)?;
        let paddr = translation.paddr;

        let memory = bus.fetch_memory(paddr, N);
        if !enabled || !translation.cacheable || memory.is_none() {
            let mut bytes = [0; N];
            match N {
                2 => bytes.copy_from_slice(&bus.read16(Requester::Arm, paddr)?.to_be_bytes()),
                4 => bytes.copy_from_slice(&bus.read32(Requester::Arm, paddr)?.to_be_bytes()),
                _ => unreachable!(),
            }
            return Ok(bytes);
        }

        let mut result: [u8; N] = memory.unwrap().try_into().unwrap();
        let mut offset = 0;
        while offset < N {
            let Some(vaddr) = addr.checked_add(offset as u32) else {
                break;
            };
            let Some(physical) = paddr.checked_add(offset as u32) else {
                break;
            };
            let tag = vaddr & !(LINE_SIZE as u32 - 1);
            let within = vaddr as usize % LINE_SIZE;
            let count = (LINE_SIZE - within).min(N - offset);

            // extra safe o7
            if addr >> 12 != vaddr >> 12 {
                let matches = self
                    .translate_with_bus(TLBReq::new(vaddr, Access::Read), &bus)
                    .is_ok_and(|next| next.cacheable && next.paddr == physical);
                if !matches {
                    offset += count;
                    continue;
                }
            }

            if let Some(bytes) = bus.line_for_instr(physical & !(LINE_SIZE as u32 - 1)) {
                if bus.same_fetchable_memory(paddr, physical, offset) {
                    let line = self.p15.icache.line(vaddr);
                    if !line.valid || line.tag != tag { // fill cache
                        line.tag = tag;
                        line.bytes = bytes;
                        line.valid = true;
                    }
                    line.last_ctx = Some(context);
                    result[offset..offset + count]
                        .copy_from_slice(&line.bytes[within..within + count]);
                }
            }
            offset += count;
        }
        Ok(result)
    }
}
