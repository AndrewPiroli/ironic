
pub mod util;

use anyhow::bail;
use log::{debug, trace, warn, log_enabled};

use crate::bus::*;
use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;
use crate::dev::hlwd::irq::*;

pub struct ShaCommand {
    len: u32,
    irq: bool,
}
impl From<u32> for ShaCommand {
    fn from(x: u32) -> ShaCommand {
        ShaCommand { 
            irq: (x & 0x4000_0000) != 0,
            len: (((x & 0x0000_0fff) + 1) * 0x40),
        }
    }
}

/// Representing the SHA interface.
#[derive(Default)]
pub struct ShaInterface {
    ctrl: u32,
    src: u32,

    /// The internal state of the SHA-1 engine.
    state: util::Sha1State,
}
impl ShaInterface {
    pub fn new() -> Self {
        ShaInterface {
            state: util::Sha1State::new(),
            ctrl: 0,
            src: 0,
        }
    }
    ///// Reset the state of the SHA interface.
    //fn reset(&mut self) {
    //    self.ctrl = 0;
    //    self.src = 0;
    //    self.state.digest[0] = 0;
    //    self.state.digest[1] = 0;
    //    self.state.digest[2] = 0;
    //    self.state.digest[3] = 0;
    //    self.state.digest[4] = 0;
    //}
}

impl MmioDevice for ShaInterface {
    type Width = u32;

    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => 0, //self.ctrl,
            0x08 => self.state.digest[0],
            0x0c => self.state.digest[1],
            0x10 => self.state.digest[2],
            0x14 => self.state.digest[3],
            0x18 => self.state.digest[4],
            _ => { bail!("Unimplemented SHA read at offset {off:04x}"); },
        };
        Ok(BusPacket::Word(val))
    }

    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => {
                self.ctrl = val;
                debug!(target: "SHA", "SHA ctrl write {:08x}", val);
                if (val & 0x8000_0000) != 0 {
                    return Ok(Some(BusTask::Sha(val)));
                }
            },
            0x04 => self.src = val,
            0x08 => self.state.digest[0] = val,
            0x0c => self.state.digest[1] = val,
            0x10 => self.state.digest[2] = val,
            0x14 => self.state.digest[3] = val,
            0x18 => self.state.digest[4] = val,
            _ => { bail!("Unhandled write32 to {off:08x}"); },
        }
        Ok(None)
    }
}

impl Bus {
    pub fn handle_task_sha(&mut self, val: u32) -> anyhow::Result<()> {
        let cmd = ShaCommand::from(val);

        let mut sha_buf = vec![0u8; cmd.len as usize];

        // The hardware reads from the closest 64-byte boundary >= src.
        // If it isnt, throw a warning and perform a DMA read from the next 64-byte aligned address.
        let mut src = self.sha.src;
        if (src & 0x3f) != 0 {
            warn!(target: "SHA", "Unaligned SHA src address {:08x}; DMA will read from next 64-byte boundary", src);
        }
        src = (src + 0x3f) & !0x3f;
        self.dma_read(src, &mut sha_buf)?;
        if log_enabled!(target: "SHA", log::Level::Trace) {
            let mut msg = format!("SHA DMA Buffer dump: {} bytes\n", sha_buf.len());
            for chunk in sha_buf.chunks(8) {
                let mut space = false;
                for byte in chunk {
                    msg += &format!("{byte:02x}");
                    if space { msg+= " "; }
                    space = !space;
                }
                msg += "\n";
            }
            trace!(target: "SHA", "{msg}");
        }

        self.sha.state.update(&sha_buf);

        debug!(target: "SHA", "SHA Digest addr={:08x} read_from={:08x} len={:08x}", self.sha.src, src, cmd.len);
        debug!(target: "SHA", "SHA buffer {:02x?}", self.sha.state.digest);

        // Mark the command as completed
        self.sha.src += cmd.len;
        self.sha.ctrl &= 0x7fff_ffff;

        if cmd.irq { 
            self.hlwd.irq.assert(HollywoodIrq::Sha);
        }
        Ok(())
    }
}


