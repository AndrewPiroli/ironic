use log::debug;
use super::EXITransferRequest;

#[derive(Debug, Clone, Default)]
pub struct UsbGeckoDevice;

impl UsbGeckoDevice {
    pub fn transfer_imm(&mut self, req: EXITransferRequest) -> anyhow::Result<u32> {
        debug!(target: "EXI", "stub USB Gecko transfer: {req:?}");
        Ok(0)
    }
}
