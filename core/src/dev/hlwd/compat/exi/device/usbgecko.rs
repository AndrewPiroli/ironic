use log::{debug, info, warn};
use super::EXITransferRequest;
use super::super::EXITransfer;

#[derive(Debug, Clone, Default)]
pub struct UsbGeckoDevice;

// Mostly implementing what can be gathered about the protocol from the Linux driver:
// https://github.com/torvalds/linux/blob/master/arch/powerpc/platforms/embedded6xx/usbgecko_udbg.c
// ... there isn't much in terms of docs for it, sadly.
impl UsbGeckoDevice {
    pub fn transfer_imm(&mut self, req: EXITransferRequest) -> anyhow::Result<u32> {
        debug!(target: "UG", "stub USB Gecko transfer: {req:?}");
        if req.kind != EXITransfer::ReadWrite {
            warn!(target: "UG", "USB Gecko only does rw transfers");
            return Ok(0x0000_0000)
        }

        let cmd = (req.data & 0xf000_0000) >> 28;
        match cmd {
            0x9 => Ok(0x0470_0000), // ID
            0xa => Ok(0x0000_0000), // Read (from computer)
            0xb => { // Write (to computer)
                let ch = (((req.data & 0x0ff0_0000) >> 20) as u8) as char;
                // TODO: output to a file?  recording the output 1 character at a time to the main
                // log isn't particularly helpful...
                info!(target: "UG", "got char: {}", ch);
                // FIXME: Priiloader expects this bit to be set on writes for OSReport-to-USBGecko;
                // is this right?
                Ok(0x0400_0000)
            },
            0xc => Ok(0x0400_0000), // Check if TX FIFO is ready (it always is here)
            0xd => Ok(0x0000_0000), // Check if RX FIFO is ready (it never is here, no input support)
            _ => {
                warn!(target: "UG", "Unrecognized USB Gecko command: {cmd:x}");
                Ok(0x0000_0000)
            }
        }
    }
}
