//! Implementation of the memory-management unit.

pub mod prim;

use crate::cpu::mmu::prim::*;
use crate::cpu::Cpu;

use anyhow::{bail, Context};

/// These are the top-level "public" functions providing read/write accesses.
impl Cpu {
    pub fn read32(&self, addr: u32) -> anyhow::Result<u32> {
        let paddr = self.translate(TLBReq::new(addr, Access::Read))?;
        let res = self.bus.read().read32(paddr)?;
        Ok(res)
    }
    pub fn read16(&self, addr: u32) -> anyhow::Result<u16> {
        let paddr = self.translate(TLBReq::new(addr, Access::Read))?;
        let res = self.bus.read().read16(paddr)?;
        Ok(res)
    }
    pub fn read8(&self, addr: u32) -> anyhow::Result<u8> {
        let paddr = self.translate(TLBReq::new(addr, Access::Read))?;
        let res = self.bus.read().read8(paddr)?;
        Ok(res)
    }

    pub fn write32(&mut self, addr: u32, val: u32) -> anyhow::Result<()> {
        let paddr = self.translate(TLBReq::new(addr, Access::Write))?;
        self.bus.write().write32(paddr, val)
    }
    pub fn write16(&mut self, addr: u32, val: u32) -> anyhow::Result<()> {
        let paddr = self.translate(TLBReq::new(addr, Access::Write))?;
        self.bus.write().write16(paddr, val as u16)
    }
    pub fn write8(&mut self, addr: u32, val: u32) -> anyhow::Result<()> {
        let paddr = self.translate(TLBReq::new(addr, Access::Write))?;
        self.bus.write().write8(paddr, val as u8)
    }
}

/// These are the functions used to perform virtual-to-physical translation.
impl Cpu {
    /// Resolve a section descriptor, returning a physical address.
    fn resolve_section(&self, req: TLBReq, d: SectionDescriptor) -> anyhow::Result<u32> {
        let ctx = self.get_ctx(d.domain());
        if ctx.validate(&req, d.ap()) {
            Ok(d.base_addr() | req.vaddr.section_idx())
        } else {
            bail!("resolve_section: Domain access faults are unimplemented, vaddr={:08x}", req.vaddr.0)
        }
    }

    /// Resolve a coarse descriptor, returning a physical address.
    #[allow(unreachable_patterns)]
    fn resolve_coarse(&self, req: TLBReq, d: CoarseDescriptor) -> anyhow::Result<u32> {
        let desc = match self.l2_fetch(req.vaddr, L1Descriptor::Coarse(d)) {
            Ok(val) => val,
            Err(reason) => return Err(reason),
        };
        match desc {
            L2Descriptor::SmallPage(entry) => {
                let ctx = self.get_ctx(d.domain());
                if ctx.validate(&req, entry.get_ap(req.vaddr)) {
                    Ok(entry.base_addr() | req.vaddr.small_page_idx())
                } else {
                    dbg!(self.p15.c3_dacr.domain(d.domain()));
                    bail!("resolve_coarse: Domain access faults are unimplemented, vaddr={:08x}", req.vaddr.0)
                }
            },
            _ => bail!("L2 descriptor {:?} unimplemented, vaddr={:08x}", desc, req.vaddr.0),
        }
    }

    /// Get the context for computing permissions associated with some PTE.
    fn get_ctx(&self, dom: u32) -> PermissionContext {
        PermissionContext { 
            domain_mode: self.p15.c3_dacr.domain(dom),
            is_priv: self.reg.cpsr.mode().is_privileged(),
            sysprot: self.p15.c1_ctrl.sysprot_enabled(),
            romprot: self.p15.c1_ctrl.romprot_enabled(),
        }
    }

    /// Given some virtual address, return the first-level PTE.
    fn l1_fetch(&self, vaddr: VirtAddr) -> anyhow::Result<L1Descriptor> {
        let addr = (self.p15.read_ttbr() & 0xffff_c000) | vaddr.l1_idx() << 2;
        let val = self.p15.l1_fetch(addr, &self.bus)?;

        let res = L1Descriptor::from_u32(val);
        if let L1Descriptor::Fault(_) = res {
            bail!("L1 Fault descriptor unimpl, vaddr={vaddr:08x}");
        }
        Ok(res)
    }

    /// Given some virtual address and a particular first-level PTE, return
    /// the second-level PTE.
    fn l2_fetch(&self, vaddr: VirtAddr, d: L1Descriptor) -> anyhow::Result<L2Descriptor> {
        let addr = match d {
            L1Descriptor::Coarse(e) => {
                e.base_addr() | vaddr.l2_idx_coarse() << 2
            },
            _ => bail!("l2_fetch requires an L1::Coarse descriptor"),
        };
        let val = self.bus.read().read32(addr)?;

        L2Descriptor::from_u32_checked(val).with_context(|| format!("l2_fetch: VirtualAddr: 0x{:x} L1Descriptor: {d:?}", vaddr.0))
    }

    /// Translate a virtual address into a physical address.
    pub fn translate(&self, req: TLBReq) -> anyhow::Result<u32> {
        if self.p15.c1_ctrl.mmu_enabled() {
            match self.l1_fetch(req.vaddr)? {
                L1Descriptor::Section(entry) => Ok(self.resolve_section(req, entry)?),
                L1Descriptor::Coarse(entry) => self.resolve_coarse(req, entry),
                other => bail!("TLB first-level descriptor {other:?} unimplemented"),
            }
        } else {
            Ok(req.vaddr.0)
        }
    }
}

