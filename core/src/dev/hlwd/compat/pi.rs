use anyhow::bail;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Legacy Processor interface
/// TODO: intsr/intmr probably need to connected to IrqInterface
/// TODO: need functionality for reset somehow
/// TODO: when the GX FIFO is implemented, those registers would need to be connected to it
#[derive(Default, Debug, Clone)]
pub struct ProcessorInterface {
    pub intsr: u32,
    pub intmr: u32,
    pub fifo_base_start: u32,
    pub fifo_base_end: u32,
    pub fifo_cur_write_ptr: u32,
    pub unk_18: u32,
    pub unk_1c: u32,
    pub unk_20: u32,
    pub reset: u32,
    pub unk_28: u32,
    pub unk_2c: u32,
}
impl MmioDevice for ProcessorInterface {
    type Width = u32;
    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.intsr,
            0x04 => self.intmr,
            0x08 => self.fifo_base_start,
            0x10 => self.fifo_base_end,
            0x14 => self.fifo_cur_write_ptr,
            0x18 => self.unk_18,
            0x1c => self.unk_1c,
            0x20 => self.unk_20,
            0x24 => self.reset,
            0x28 => self.unk_28,
            0x2c => self.unk_2c,
            _ => { bail!("PI read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }
    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => self.intsr = val,
            0x04 => self.intmr = val,
            0x08 => self.fifo_base_start = val,
            0x10 => self.fifo_base_end = val,
            0x14 => self.fifo_cur_write_ptr = val,
            0x18 => self.unk_18 = val,
            0x1c => self.unk_1c = val,
            0x20 => self.unk_20 = val,
            0x24 => self.reset = val,
            0x28 => self.unk_28 = val,
            0x2c => self.unk_2c = val,
            _ => { bail!("PI write {val:08x} to undefined offset {off:x}"); },
        }
        Ok(None)
    }
}
