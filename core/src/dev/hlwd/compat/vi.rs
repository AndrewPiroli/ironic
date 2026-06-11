use anyhow::bail;
use log::{debug, info, warn};
use parking_lot::RwLock;

use std::sync::Arc;
use std::thread::{self, Builder, JoinHandle};
use std::time::{Duration, Instant};

use crate::bus::Bus;
use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

const DI_STATUS: u32 = 1 << 31;
const DI_ENABLE: u32 = 1 << 28;
const DI_VERTICAL_SHIFT: u32 = 16;
const DI_VERTICAL_MASK: u32 = 0x03ff << DI_VERTICAL_SHIFT;
const DI_HORIZONTAL_MASK: u32 = 0x03ff;
const DI_WRITABLE_MASK: u32 = !DI_STATUS;

/// Legacy Video Interface
///
/// Yes, it sadly needs to support all of this weird incorrect-size access stuff,
/// some software like CEIL1NG_CAT, other ppcskel-derived software, and everything
/// built with PowerBlocks, relies on dumping a blob of 16-bit values into VI, and this
/// technically works on real hardware.
///
/// https://www.gc-forever.com/yagcd/chap5.html#sec5.3
#[derive(Default, Debug, Clone)]
pub struct VideoInterface {
    /// Virtical Timing Register
    pub vtr: u16,
    /// Display Configuration Register
    pub dcr: u16,
    /// Horizontal Timing 0
    pub htr0: u32,
    /// Horizontal Timing 1
    pub htr1: u32,
    /// Odd Field Vertical Timing Register
    pub vto: u32,
    /// Even Field Vertical Timing Register
    pub vte: u32,
    /// Odd Field Burst Blanking Interval Register
    pub bbei: u32,
    /// Even Field Burst Blanking Interval Register
    pub bboi: u32,
    /// Top Field Base Register (L) (External Framebuffer Half 1)
    pub tfbl: u32,
    /// Top Field Base Register (R) (Only valid in 3D Mode)
    pub tfbr: u32,
    /// Bottom Field Base Register (L) (External Framebuffer Half 2)
    pub bfbl: u32,
    /// Bottom Field Base Register (R) (Only valid in 3D Mode)
    pub bfbr: u32,
    /// current vertical Position (of raster beam)
    pub dpv: u16,
    /// current horizontal Position (of raster beam) (?)
    pub dph: u16,
    /// Display Interrupt 0
    pub di0: u32,
    /// Display Interrupt 1
    pub di1: u32,
    /// Display Interrupt 2
    pub di2: u32,
    /// Display Interrupt 3
    pub di3: u32,
    /// Display Latch Register 0
    pub dl0: u32,
    /// /// Display Latch Register 1
    pub dl1: u32,
    /// Scaling Width Register
    pub hsw: u16,
    /// Horizontal Scaling Register
    pub hsr: u16,
    /// Filter Coefficient Table 0 (AA)
    pub fct0: u32,
    /// Filter Coefficient Table 1
    pub fct1: u32,
    /// Filter Coefficient Table 2
    pub fct2: u32,
    /// Filter Coefficient Table 3
    pub fct3: u32,
    /// Filter Coefficient Table 4
    pub fct4: u32,
    /// Filter Coefficient Table 5
    pub fct5: u32,
    /// Filter Coefficient Table 6
    pub fct6: u32,
    pub unk_68: u32,
    /// VI Clock Select Register
    pub viclk: u16,
    /// VI DTV Status Register
    pub visel: u16,
    pub unk_70: u16,
    /// Border HBE (Horizontal Blank End)
    pub hbe: u16,
    /// Border HBS (Horizontal Blank Start)
    pub hbs: u16,
    pub unk_76: u16,
    pub unk_78: u32,
    pub unk_7c: u32
}

#[derive(Debug, Clone, Copy)]
struct DisplayInterrupt {
    idx: usize,
    reg: u32,
}

impl DisplayInterrupt {
    fn new(idx: usize, reg: u32) -> Self {
        Self { idx, reg }
    }

    fn enabled(self) -> bool {
        (self.reg & DI_ENABLE) != 0
    }

    fn vertical(self) -> u32 {
        (self.reg & DI_VERTICAL_MASK) >> DI_VERTICAL_SHIFT
    }

    fn horizontal(self) -> u32 {
        self.reg & DI_HORIZONTAL_MASK
    }

    fn frame_offset(self, frame_duration: Duration, frame_lines: u32) -> Duration {
        let line = self.vertical().min(frame_lines.saturating_sub(1));
        let dot = self.horizontal().min(1023);
        let position = (line as u128 * 1024) + dot as u128;
        let frame = frame_lines as u128 * 1024;
        let nanos = frame_duration.as_nanos() * position / frame;
        Duration::from_nanos(nanos as u64)
    }
}

impl VideoInterface {
    pub fn spawn_irq_thread(bus: Arc<RwLock<Bus>>) -> std::io::Result<JoinHandle<()>> {
        Builder::new().name("ViThread".to_owned()).spawn(move || {
            loop {
                let (frame_duration, frame_lines, mut interrupts) = {
                    let bus = bus.read();
                    let frame_duration = bus.hlwd.vi.frame_duration();
                    let frame_lines = bus.hlwd.vi.frame_lines();
                    let interrupts = bus.hlwd.vi.display_interrupts();
                    (frame_duration, frame_lines, interrupts)
                };

                let frame_start = Instant::now();
                interrupts.sort_by_key(|di| di.frame_offset(frame_duration, frame_lines));

                for di in interrupts {
                    let event_at = frame_start + di.frame_offset(frame_duration, frame_lines);
                    if let Some(delay) = event_at.checked_duration_since(Instant::now()) {
                        thread::sleep(delay);
                    }

                    let mut bus = bus.write();
                    let hlwd = &mut bus.hlwd;
                    if hlwd.vi.fire_display_interrupt(di.idx) {
                        debug!(target: "VI", "Firing DI{}", di.idx);
                    }
                }

                if let Some(delay) = (frame_start + frame_duration).checked_duration_since(Instant::now()) {
                    thread::sleep(delay);
                }
            }
        })
    }

    fn frame_duration(&self) -> Duration {
        match (self.dcr & 0x0300) >> 8 {
            1 => Duration::from_millis(20),
            _ => Duration::from_millis(16),
        }
    }

    fn frame_lines(&self) -> u32 {
        match (self.dcr & 0x0300) >> 8 {
            1 => 625,
            _ => 525,
        }
    }

    fn display_interrupts(&self) -> Vec<DisplayInterrupt> {
        [self.di0, self.di1, self.di2, self.di3]
            .into_iter()
            .enumerate()
            .map(|(idx, reg)| DisplayInterrupt::new(idx, reg))
            .filter(|di| di.enabled())
            .collect()
    }

    pub fn irq_pending(&self) -> bool {
        [self.di0, self.di1, self.di2, self.di3]
            .into_iter()
            .any(|reg| (reg & DI_STATUS) != 0 && (reg & DI_ENABLE) != 0)
    }

    fn fire_display_interrupt(&mut self, idx: usize) -> bool {
        let reg = match idx {
            0 => &mut self.di0,
            1 => &mut self.di1,
            2 => &mut self.di2,
            3 => &mut self.di3,
            _ => return false,
        };

        let was_pending = (*reg & DI_STATUS) != 0;
        let enabled = (*reg & DI_ENABLE) != 0;
        *reg |= DI_STATUS;

        enabled && !was_pending
    }

    fn write_di_register(reg: &mut u32, val: u32) {
        *reg = val & DI_WRITABLE_MASK;
    }

    fn write_di_register_hi(reg: &mut u32, val: u16) {
        let hi = (val as u32) << 16;
        *reg = (*reg & 0x0000ffff) | (hi & DI_WRITABLE_MASK);
    }

    fn write_di_register_lo(reg: &mut u32, val: u16) {
        *reg = (*reg & 0xffff0000) | val as u32;
    }
}

impl MmioDeviceMultiWidth for VideoInterface {
    fn read8(&self, off: usize) -> anyhow::Result<BusPacket> {
        bail!("VI unsupported 8-bit read from offset {off:x}");
    }

    fn read16(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.vtr,
            0x02 => self.dcr,
            0x04 => (self.htr0 >> 16) as u16,
            0x06 => (self.htr0 & 0xffff) as u16,
            0x08 => (self.htr1 >> 16) as u16,
            0x0a => (self.htr1 & 0xffff) as u16,
            0x0c => (self.vto >> 16) as u16,
            0x0e => (self.vto & 0xffff) as u16,
            0x10 => (self.vte >> 16) as u16,
            0x12 => (self.vte & 0xffff) as u16,
            0x14 => (self.bbei >> 16) as u16,
            0x16 => (self.bbei & 0xffff) as u16,
            0x18 => (self.bboi >> 16) as u16,
            0x1a => (self.bboi & 0xffff) as u16,
            0x1c => (self.tfbl >> 16) as u16,
            0x1e => (self.tfbl & 0xffff) as u16,
            0x20 => (self.tfbr >> 16) as u16,
            0x22 => (self.tfbr & 0xffff) as u16,
            0x24 => (self.bfbl >> 16) as u16,
            0x26 => (self.bfbl & 0xfff) as u16,
            0x28 => (self.bfbr >> 16) as u16,
            0x2a => (self.bfbr & 0xffff) as u16,
            0x2c => self.dpv,
            0x2e => self.dph,
            0x30 => (self.di0 >> 16) as u16,
            0x32 => (self.di0 & 0xffff) as u16,
            0x34 => (self.di1 >> 16) as u16,
            0x36 => (self.di1 & 0xffff) as u16,
            0x38 => (self.di2 >> 16) as u16,
            0x3a => (self.di2 & 0xffff) as u16,
            0x3c => (self.di3 >> 16) as u16,
            0x3e => (self.di3 & 0xffff) as u16,
            0x40 => (self.dl0 >> 16) as u16,
            0x42 => (self.dl0 & 0xffff) as u16,
            0x44 => (self.dl1 >> 16) as u16,
            0x46 => (self.dl1 & 0xffff) as u16,
            0x48 => self.hsw,
            0x4a => self.hsr,
            0x4c => (self.fct0 >> 16) as u16,
            0x4e => (self.fct0 & 0xffff) as u16,
            0x50 => (self.fct1 >> 16) as u16,
            0x52 => (self.fct1 & 0xffff) as u16,
            0x54 => (self.fct2 >> 16) as u16,
            0x56 => (self.fct2 & 0xffff) as u16,
            0x58 => (self.fct3 >> 16) as u16,
            0x5a => (self.fct3 & 0xffff) as u16,
            0x5c => (self.fct4 >> 16) as u16,
            0x5e => (self.fct4 & 0xffff) as u16,
            0x60 => (self.fct5 >> 16) as u16,
            0x62 => (self.fct5 & 0xffff) as u16,
            0x64 => (self.fct6 >> 16) as u16,
            0x66 => (self.fct6 & 0xffff) as u16,
            0x68 => (self.unk_68 >> 16) as u16,
            0x6a => (self.unk_68 & 0xffff) as u16,
            0x6c => self.viclk,
            0x6e => self.visel,
            0x70 => self.unk_70,
            0x72 => self.hbe,
            0x74 => self.hbs,
            0x76 => self.unk_76,
            0x78 => (self.unk_78 >> 16) as u16,
            0x7a => (self.unk_78 & 0xffff) as u16,
            0x7c => (self.unk_7c >> 16) as u16,
            0x7e => (self.unk_7c & 0xffff) as u16,
            _ => { bail!("VI 16-bit read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Half(val))
    }
    fn read32(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => ((self.vtr as u32) << 16) | (self.dcr as u32),
            0x04 => self.htr0,
            0x08 => self.htr1,
            0x0c => self.vto,
            0x10 => self.vte,
            0x14 => self.bbei,
            0x18 => self.bboi,
            0x1c => self.tfbl,
            0x20 => self.tfbr,
            0x24 => self.bfbl,
            0x28 => self.bfbr,
            0x2c => ((self.dpv as u32) << 16) | (self.dph as u32),
            0x30 => self.di0,
            0x34 => self.di1,
            0x38 => self.di2,
            0x3c => self.di3,
            0x40 => self.dl0,
            0x44 => self.dl1,
            0x48 => ((self.hsw as u32) << 16) | (self.hsr as u32),
            0x4c => self.fct0,
            0x50 => self.fct1,
            0x54 => self.fct2,
            0x58 => self.fct3,
            0x5c => self.fct4,
            0x60 => self.fct5,
            0x64 => self.fct6,
            0x68 => self.unk_68,
            0x6c => ((self.viclk as u32) << 16) | (self.visel as u32),
            0x70 => ((self.unk_70 as u32) << 16) | (self.hbe as u32),
            0x74 => ((self.hbs as u32) << 16) | (self.unk_76 as u32),
            0x78 => self.unk_78,
            0x7c => self.unk_7c,
            _ => { bail!("VI 32-bit read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }


    fn write8(&mut self, off: usize, val: u8) -> anyhow::Result<Option<BusTask>> {
        bail!("VI unsupported 8-bit write {val:02x} to offset {off:x}");
    }

    fn write16(&mut self, off: usize, val: u16) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => self.vtr = val,
            0x02 => {
                debug!(target: "VI", "DCR={:04x}", val);
                if ((val & 0x0300) >> 8) != ((self.dcr & 0x0300) >> 8) {
                    match (val & 0x0300) >> 8 {
                        0 => info!(target: "VI", "New video mode: NTSC"),
                        1 => info!(target: "VI", "New video mode: PAL"),
                        2 => info!(target: "VI", "New video mode: MPAL"),
                        3 => info!(target: "VI", "New video mode: DEBUG"),
                        _ => unreachable!()
                    };
                };
                self.dcr = val;
            },
            0x04 => { self.htr0 &= 0x0000ffff; self.htr0 |= (val as u32) << 16; },
            0x06 => { self.htr0 &= 0xffff0000; self.htr0 |= val as u32; },
            0x08 => { self.htr1 &= 0x0000ffff; self.htr1 |= (val as u32) << 16; },
            0x0a => { self.htr1 &= 0xffff0000; self.htr1 |= val as u32; },
            0x0c => { self.vto &= 0x0000ffff; self.vto |= (val as u32) << 16; },
            0x0e => { self.vto &= 0xffff0000; self.vto |= val as u32; },
            0x10 => { self.vte &= 0x0000ffff; self.vte |= (val as u32) << 16; },
            0x12 => { self.vte &= 0xffff0000; self.vte |= val as u32; },
            0x14 => { self.bbei &= 0x0000ffff; self.bbei |= (val as u32) << 16; },
            0x16 => { self.bbei &= 0xffff0000; self.bbei |= val as u32; },
            0x18 => { self.bboi &= 0x0000ffff; self.bboi |= (val as u32) << 16; },
            0x1a => { self.bboi &= 0xffff0000; self.bboi |= val as u32; },
            0x1c => { self.tfbl &= 0x0000ffff; self.tfbl |= (val as u32) << 16; info!(target: "VI", "TFBL @ {:08x}", self.tfbl); },
            0x1e => { self.tfbl &= 0xffff0000; self.tfbl |= val as u32; info!(target: "VI", "TFBL @ {:08x}", self.tfbl); },
            0x20 => { self.tfbr &= 0x0000ffff; self.tfbr |= (val as u32) << 16; },
            0x22 => { self.tfbr &= 0xffff0000; self.tfbr |= val as u32; },
            0x24 => { self.bfbl &= 0x0000ffff; self.bfbl |= (val as u32) << 16; },
            0x26 => { self.bfbl &= 0xfff0000; self.bfbl |= val as u32; },
            0x28 => { self.bfbr &= 0x0000ffff; self.bfbr |= (val as u32) << 16; },
            0x2a => { self.bfbr &= 0xffff0000; self.bfbr |= val as u32; },
            0x2c => warn!(target: "VI", "Writing to DPV makes no sense"),
            0x2e => warn!(target: "VI", "Writing to DPH makes no sense"),
            0x30 => Self::write_di_register_hi(&mut self.di0, val),
            0x32 => Self::write_di_register_lo(&mut self.di0, val),
            0x34 => Self::write_di_register_hi(&mut self.di1, val),
            0x36 => Self::write_di_register_lo(&mut self.di1, val),
            0x38 => Self::write_di_register_hi(&mut self.di2, val),
            0x3a => Self::write_di_register_lo(&mut self.di2, val),
            0x3c => Self::write_di_register_hi(&mut self.di3, val),
            0x3e => Self::write_di_register_lo(&mut self.di3, val),
            0x40 => { self.dl0 &= 0x0000ffff; self.dl0 |= (val as u32) << 16; },
            0x42 => { self.dl0 &= 0xffff0000; self.dl0 |= val as u32; },
            0x44 => { self.dl1 &= 0x0000ffff; self.dl1 |= (val as u32) << 16; },
            0x46 => { self.dl1 &= 0xffff0000; self.dl1 |= val as u32; },
            0x48 => self.hsw = val,
            0x4a => self.hsr = val,
            0x4c => { self.fct0 &= 0x0000ffff; self.fct0 |= (val as u32) << 16; },
            0x4e => { self.fct0 &= 0xffff0000; self.fct0 |= val as u32; },
            0x50 => { self.fct1 &= 0x0000ffff; self.fct1 |= (val as u32) << 16; },
            0x52 => { self.fct1 &= 0xffff0000; self.fct1 |= val as u32; },
            0x54 => { self.fct2 &= 0x0000ffff; self.fct2 |= (val as u32) << 16; },
            0x56 => { self.fct2 &= 0xffff0000; self.fct2 |= val as u32; },
            0x58 => { self.fct3 &= 0x0000ffff; self.fct3 |= (val as u32) << 16; },
            0x5a => { self.fct3 &= 0xffff0000; self.fct3 |= val as u32; },
            0x5c => { self.fct4 &= 0x0000ffff; self.fct4 |= (val as u32) << 16; },
            0x5e => { self.fct4 &= 0xffff0000; self.fct4 |= val as u32; },
            0x60 => { self.fct5 &= 0x0000ffff; self.fct5 |= (val as u32) << 16; },
            0x62 => { self.fct5 &= 0xffff0000; self.fct5 |= val as u32; },
            0x64 => { self.fct6 &= 0x0000ffff; self.fct6 |= (val as u32) << 16; },
            0x66 => { self.fct6 &= 0xffff0000; self.fct6 |= val as u32; },
            0x68 => { self.unk_68 &= 0x0000ffff; self.unk_68 |= (val as u32) << 16; },
            0x6a => { self.unk_68 &= 0xffff0000; self.unk_68 |= val as u32; },
            0x6c => {
                if val == 1 {
                    info!(target: "VI", "Setting video clock to 54MHz");
                } else if val == 0 {
                    info!(target: "VI", "Setting video clock to 27MHz");
                } else {
                    warn!("Trying to set bogus VI clock speed {val:x}");
                }
                self.viclk = val;
            },
            0x6e => self.visel = val,
            0x70 => self.unk_70 = val,
            0x72 => self.hbe = val,
            0x74 => self.hbs = val,
            0x76 => self.unk_76 = val,
            0x78 => { self.unk_78 &= 0x0000ffff; self.unk_78 |= (val as u32) << 16; },
            0x7a => { self.unk_78 &= 0xffff0000; self.unk_78 |= val as u32; },
            0x7c => { self.unk_7c &= 0x0000ffff; self.unk_7c |= (val as u32) << 16; },
            0x7e => { self.unk_7c &= 0xffff0000; self.unk_7c |= val as u32; },
            _ => { bail!("VI 16-bit write {val:04x} to undefined offset {off:x}"); },
        }
        Ok(None)
    }

    fn write32(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => { self.vtr = (val >> 16) as u16; self.dcr = (val & 0xffff) as u16; },
            0x04 => self.htr0 = val,
            0x08 => self.htr1 = val,
            0x0c => self.vto = val,
            0x10 => self.vte = val,
            0x14 => self.bbei = val,
            0x18 => self.bboi = val,
            0x1c => { self.tfbl = val; info!(target: "VI", "TFBL @ {:08x}", self.tfbl); },
            0x20 => self.tfbr = val,
            0x24 => self.bfbl = val,
            0x28 => self.bfbr = val,
            0x2c => warn!(target: "VI", "Writing to DPV/DPH makes no sense"),
            0x30 => Self::write_di_register(&mut self.di0, val),
            0x34 => Self::write_di_register(&mut self.di1, val),
            0x38 => Self::write_di_register(&mut self.di2, val),
            0x3c => Self::write_di_register(&mut self.di3, val),
            0x40 => self.dl0 = val,
            0x44 => self.dl1 = val,
            0x48 => { self.hsw = (val >> 16) as u16; self.hsr = (val & 0xffff) as u16; },
            0x4c => self.fct0 = val,
            0x50 => self.fct1 = val,
            0x54 => self.fct2 = val,
            0x58 => self.fct3 = val,
            0x5c => self.fct4 = val,
            0x60 => self.fct5 = val,
            0x64 => self.fct6 = val,
            0x68 => self.unk_68 = val,
            0x6c => { self.viclk = (val >> 16) as u16; self.visel = (val & 0xffff) as u16; },
            0x70 => { self.unk_70 = (val >> 16) as u16; self.hbe = (val & 0xffff) as u16; },
            0x74 => { self.hbs = (val >> 16) as u16; self.unk_76 = (val & 0xffff) as u16; },
            0x78 => self.unk_78 = val,
            0x7c => self.unk_7c = val,
            _ => { bail!("VI 32-bit write {val:08x} to undefined offset {off:x}"); },
        }
        Ok(None)
    }
}
