use anyhow::bail;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Like Dolphin's delay; games seem to get generally upset if we don't
const PE_FINISH_MIN_DELAY: u32 = 4096;

/// GX Pixel Engine (PE)
#[derive(Default, Debug, Clone)]
pub struct PixelEngine {
    pub z_conf: u16,
    pub alpha_conf: u16,
    pub dest_alpha: u16,
    pub alpha_mode: u16,
    pub alpha_read: u16,
    pub intsr: u16,
    pub token: u16,
    pending_finish: Option<u32>,
}
impl PixelEngine {
    fn assert_finish_irq(&mut self) {
        self.intsr |= 0x0008;
    }

    pub fn request_finish_irq(&mut self) {
        self.pending_finish = Some(PE_FINISH_MIN_DELAY);
    }

    pub fn tick(&mut self, instrs: u32) {
        if let Some(remaining) = self.pending_finish {
            if remaining <= instrs {
                self.assert_finish_irq();
                self.pending_finish = None;
            } else {
                self.pending_finish = Some(remaining - instrs);
            }
        }
    }

    /// Whether the Finish line is asserted
    pub fn finish_pending(&self) -> bool {
        (self.intsr & 0x0008) != 0 && (self.intsr & 0x0002) != 0
    }
}
impl MmioDevice for PixelEngine {
    type Width = u16;
    fn read(&self, _access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.z_conf,
            0x02 => self.alpha_conf,
            0x04 => self.dest_alpha,
            0x06 => self.alpha_mode,
            0x08 => self.alpha_read,
            0x0a => self.intsr,
            0x0e => self.token,
            _ => bail!("PE read to undefined offset {off:x}"),
        };
        Ok(BusPacket::Half(val))
    }
    fn write(&mut self, _access: AccessContext, off: usize, val: u16) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => self.z_conf = val,
            0x02 => self.alpha_conf = val,
            0x04 => self.dest_alpha = val,
            0x06 => self.alpha_mode = val,
            0x08 => self.alpha_read = val,
            // bits 0-1 (Token/Finish IRQ enable) are plain read/write
            // bits 2-3 (Token/Finish IRQ status) are W1C
            0x0a => self.intsr = (val & 0x0003) | (self.intsr & !val & 0x000c),
            0x0e => self.token = val,
            _ => bail!("PE write {val:08x} to undefined offset {off:x}"),
        }
        Ok(None)
    }
}
