use anyhow::bail;
use log::info;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Legacy Video Interface
#[derive(Default, Debug, Clone)]
pub struct VideoInterface {
    pub clk: u16
}
impl MmioDeviceMultiWidth for VideoInterface {
    fn read8(&self, off: usize) -> anyhow::Result<BusPacket> {
        bail!("VI unsupported 8-bit read from offset {off:x}");
    }

    fn read16(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x6c => self.clk,
            _ => { bail!("VI 16-bit read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Half(val))
    }
    fn read32(&self, off: usize) -> anyhow::Result<BusPacket> {
        let _val = match off {
            _ => { bail!("VI 32-bit read from undefined offset {off:x}"); },
        };
        //Ok(BusPacket::Word(val))
    }


    fn write8(&mut self, off: usize, val: u8) -> anyhow::Result<Option<BusTask>> {
        bail!("VI unsupported 8-bit write {val:02x} to offset {off:x}");
    }

    fn write16(&mut self, off: usize, val: u16) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x6c => {
                if val == 1 {
                    info!(target: "VI", "Setting video clock to 54MHz");
                } else if val == 0 {
                    info!(target: "VI", "Setting video clock to 27MHz");
                } else {
                    bail!("Trying to set bogus VI clock speed {val:x}");
                }
                self.clk = val as u16;
            }
            _ => { bail!("VI 16-bit write {val:04x} to undefined offset {off:x}"); },
        }
        Ok(None)
    }

    fn write32(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            _ => { bail!("VI 32-bit write {val:08x} to undefined offset {off:x}"); },
        }
        //Ok(None)
    }
}
