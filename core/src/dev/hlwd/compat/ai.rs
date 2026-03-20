use anyhow::bail;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Legacy Audio interface
#[derive(Default, Debug, Clone)]
pub struct AudioInterface {
    pub control: u32,
    pub volume: u32,
    pub sample_cnt: u32,
    pub int_timing: u32
}
impl MmioDevice for AudioInterface {
    type Width = u32;
    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.control,
            0x04 => self.volume,
            0x08 => self.sample_cnt,
            0x0c => self.int_timing,
            _ => { bail!("AI read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }
    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => self.control = val,
            0x04 => self.volume = val,
            0x08 => self.sample_cnt = val,
            0x0c => self.int_timing = val,
            _ => { bail!("AI write {val:08x} to undefined offset {off:x}"); },
        }
        Ok(None)
    }
}
