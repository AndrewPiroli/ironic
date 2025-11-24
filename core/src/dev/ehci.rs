
use anyhow::bail;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Representing the SHA interface.
#[derive(Default)]
pub struct EhcInterface {
    pub unk_14: u32,
    pub unk_a4: u32,
    pub unk_b0: u32,
    pub unk_b4: u32,
    pub unk_cc: u32,
}
impl EhcInterface {
    pub fn new() -> Self {
        EhcInterface {
            unk_14: 0,
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
            0x14 => self.unk_14,
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
            0x14 => self.unk_14 = val,
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


