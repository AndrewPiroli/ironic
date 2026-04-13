use super::EXITransferRequest;
use log::debug;

#[derive(Debug, Clone, Default)]
pub struct SdGeckoDevice;

impl SdGeckoDevice {
    pub fn transfer_imm(&mut self, req: EXITransferRequest) -> anyhow::Result<u32> {
        debug!(target: "EXI", "stub SD Gecko transfer: {req:?}");
        Ok(0xffff_ffff)
    }
}


