
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
const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_RESET: u32 = 1 << 1;
const USBCMD_RESET_VALUE: u32 = 0x0008_0000;
const USBSTS_HALTED: u32 = 1 << 12;
const USBSTS_W1C: u32 = 0x3f;

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

    fn read(&self, _access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
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

    fn write(&mut self, _access: AccessContext, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x10 => {
                if val & USBCMD_RESET != 0 {
                    self.usbcmd = USBCMD_RESET_VALUE;
                    self.usbsts = USBSTS_HALTED;
                    self.usbintr = 0;
                } else {
                    self.usbcmd = val;
                    if val & USBCMD_RUN != 0 {
                        self.usbsts &= !USBSTS_HALTED;
                    } else {
                        self.usbsts |= USBSTS_HALTED;
                    }
                }
            },
            // Interrupt status bits are W1C, HCHalted is read-only
            0x14 => self.usbsts &= !(val & USBSTS_W1C),
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


