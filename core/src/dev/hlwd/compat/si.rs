use anyhow::bail;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Legacy Serial interface
/// TODO: This is nowhere near accurrate, these registers all have real side effects.
/// However, this is good enough to at least get software that uses them booting, until it can be
/// properly implemented.
#[derive(Default, Debug, Clone)]
pub struct SerialInterface {
    pub outbuf: [u32; 4],
    pub inbuf_h: [u32; 4],
    pub inbuf_l: [u32; 4],
    pub poll: u32,
    pub comcsr: u32,
    pub sr: u32,
    pub exilk: u32
}
impl MmioDevice for SerialInterface {
    type Width = u32;
    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 | 0x0c | 0x18 | 0x24 => self.outbuf[off / 0xc],
            0x04 | 0x10 | 0x1c | 0x28 => self.inbuf_h[off / 0xc],
            0x08 | 0x14 | 0x20 | 0x2c => self.inbuf_l[off / 0xc],
            0x30 => self.poll,
            0x34 => self.comcsr,
            0x38 => self.sr,
            0x3c => self.exilk,
            _ => { bail!("SI read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }
    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 | 0x0c | 0x18 | 0x24 => self.outbuf[off / 0xc] = val,
            0x04 | 0x10 | 0x1c | 0x28 => self.inbuf_h[off / 0xc] = val,
            0x08 | 0x14 | 0x20 | 0x2c => self.inbuf_l[off / 0xc] = val,
            0x30 => self.poll = val,
            0x34 => self.comcsr = val,
            0x38 => self.sr = val,
            0x3c => self.exilk = val,
            _ => { bail!("SI write {val:08x} to undefined offset {off:x}"); },
        }
        Ok(None)
    }
}
