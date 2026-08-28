use log::debug;
use anyhow::bail;

use crate::bus::Bus;
use crate::bus::mmio::*;
use crate::bus::prim::*;
use crate::bus::task::*;
use crate::dev::hlwd::compat::pi::FlipperIrq;

/// Transfer-Complete Interrupt status (r/w1c).
const DISR_TCINT: u32 = 0x0000_0004;
/// Device-Error Interrupt status (r/w1c).
const DISR_DEINT: u32 = 0x0000_0010;

#[derive(Default, Debug, Copy, Clone)]
enum DriveState {
   #[default] Ready
}

/// Legacy disc drive interface.
#[derive(Default, Debug, Clone)]
#[allow(dead_code)]
pub struct DriveInterface {
    disr: u32,
    dicvr: u32,
    dicmdbuf: [u32; 3],
    dimar: u32,
    dilength: u32,
    dicr: u32,
    diimmbuf: u32,
    dicfg: u32,

    drive_state: DriveState
}
impl DriveInterface {
    fn do_cmd(&mut self) -> Option<BusTask> {
        let dma: bool = self.dicr & 0x0000_0002 == 0x0000_0002;
        let write: bool = self.dicr & 0x0000_0004 == 0x0000_0004;

        if dma && write {
            debug!(target: "DI", "DMA xfer from {:x}, {}B, [ {:x}, {:x}, {:x} ]", self.dimar, self.dilength, self.dicmdbuf[0], self.dicmdbuf[1], self.dicmdbuf[2]);
        }
        else if dma {
            debug!(target: "DI", "DMA xfer to {:x}, {}B, [ {:x}, {:x}, {:x} ]", self.dimar, self.dilength, self.dicmdbuf[0], self.dicmdbuf[1], self.dicmdbuf[2]);
        }
        else {
            debug!(target: "DI", "Immediate xfer [ {:x}, {:x}, {:x} ]", self.dicmdbuf[0], self.dicmdbuf[1], self.dicmdbuf[2]);
        }

        Some(BusTask::Di { error: true })
    }
}

impl Bus {
    pub fn handle_task_di(&mut self, error: bool) -> anyhow::Result<()> {
        let di = &mut self.hlwd.di;
        di.dicr &= !0x0000_0001; // TSTART self-clears on completion
        di.disr |= if error { DISR_DEINT } else { DISR_TCINT };

        let masked = if error {
            di.disr & 0x0000_0020 != 0 // DEINTMASK
        } else {
            di.disr & 0x0000_0008 != 0 // TCINTMASK
        };

        if masked {
            self.hlwd.pi.set_level(FlipperIrq::Di, true);
        }
        Ok(())
    }
}

impl MmioDevice for DriveInterface {
    type Width = u32;
    fn read(&self, _access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.disr,
            0x04 => self.dicvr,
            0x08..=0x10 => self.dicmdbuf[(off - 0x08) / 4],
            0x14 => self.dimar,
            0x18 => self.dilength,
            0x1c => self.dicr,
            0x20 => self.diimmbuf,
            0x24 => self.dicfg,
            _ => { bail!("DI read to undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }
    fn write(&mut self, _access: AccessContext, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => {
                const DISR_W1C_MASK: u32 = 0x0000_0054;
                let mut new_val = val;

                if (new_val & DISR_W1C_MASK) != 0 {
                    new_val &= !(new_val & DISR_W1C_MASK);
                }

                // keep un-cleared W1C bits
                new_val |= (self.disr & DISR_W1C_MASK) & !(new_val & DISR_W1C_MASK);

                self.disr = new_val;
            },
            0x04 => {
                const DICVR_W1C_MASK: u32 = 0x0000_0004; // CVRINT
                const DICVR_RO_MASK: u32 = 0x0000_0001; // CVR
                let mut new_val = val;

                if (new_val & DICVR_W1C_MASK) != 0 {
                    new_val &= !(new_val & DICVR_W1C_MASK);
                }

                new_val &= !DICVR_RO_MASK;
                new_val |= self.dicvr & DICVR_RO_MASK;

                self.dicvr = new_val;
            },
            0x08..=0x10 => self.dicmdbuf[(off - 0x08) / 4] = val,
            0x14 => self.dimar = val,
            0x18 => self.dilength = val,
            0x1c => {
                self.dicr = val & !0x0000_00001;

                if val & 0x0000_0001 == 0x0000_0001 {
                    // TSTART=1, begin a transfer
                    return Ok(self.do_cmd());
                }
            },
            0x20 => self.diimmbuf = val,
            _ => { bail!("DI write {val:08x?} to undefined offset {off:x}"); },
        }
        Ok(None)
    }
}


