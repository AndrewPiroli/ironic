
use anyhow::bail;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Representing the Enhanced Host Controller Interface.
#[derive(Default)]
pub struct EhcInterface {
    pub usbcmd: u32,
    pub usbsts: u32,
    pub usbintr: u32,
    pub unk_a4: u32,
    pub unk_b0: u32,
    pub unk_b4: u32,
    pub unk_cc: u32,
}
impl EhcInterface {
    pub fn new() -> Self {
        EhcInterface {
            usbcmd: 0x0000_0001, /* RS=1 */
            usbsts: 0,
            usbintr: 0,
            unk_a4: 0,
            unk_b0: 0,
            unk_b4: 0,
            unk_cc: 0,
        }
    }
}

impl MmioDevice for EhcInterface {
    type Width = u32;

    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            /*
             * The real intended value is 0x10, but it appears like this due
             * to the hardware byteswapper.  Software masks out everything
             * but the lowest 8 bits.
             */
            0x00 => 0x0100_0010,
            0x10 => self.usbcmd,
            0x14 => self.usbsts,
            0x18 => self.usbintr,
            0xa4 => self.unk_a4,
            0xb0 => self.unk_b0,
            0xb4 => self.unk_b4,
            0xcc => self.unk_cc,
            _ => { bail!("Unimplemented EHCI read at offset {off:04x}"); },
        };
        Ok(BusPacket::Word(val))
    }

    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x10 => {
                if (self.usbcmd & 1 == 0) && (val & 1 == 1) {
                    // setting RS=1, set HCHALTED=0
                    self.usbsts &= !0x0000_1000;
                }
                else if (self.usbcmd & 1 == 1) && (val & 1 == 0) {
                    // setting RS=0, set HCHALTED=1
                    self.usbsts |= 0x0000_1000;
                }
                self.usbcmd = val;
            },
            0x14 => self.usbsts = val,
            0x18 => self.usbintr = val,
            0xa4 => self.unk_a4 = val,
            0xb0 => self.unk_b0 = val,
            0xb4 => self.unk_b4 = val,
            0xcc => self.unk_cc = val,
            _ => { bail!("Unimplemented EHCI write to {off:04x}"); },
        }
        Ok(None)
    }
}

//impl Bus {
//    pub fn handle_task_ehci(&mut self, val: u32) {
//        let local_ref = self.dev.clone();
//        let mut dev = local_ref.write().unwrap();
//        let ehci = &mut dev.ehci;
//    }
//}


