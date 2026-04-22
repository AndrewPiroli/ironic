use super::EXITransferRequest;
use log::debug;

#[derive(Debug, Clone, Default)]
pub struct RtcDevice;

impl RtcDevice {
    pub fn transfer_imm(&mut self, req: EXITransferRequest) -> anyhow::Result<u32> {
        debug!(target: "EXI", "stub RTC transfer: {req:?}");
        Ok(0xffff_ffff)
    }
}
