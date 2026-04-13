use super::EXITransferRequest;
use log::debug;

#[derive(Debug, Clone, Default)]
pub struct MemoryCardDevice;

impl MemoryCardDevice {
    pub fn transfer_imm(&mut self, req: EXITransferRequest) -> anyhow::Result<u32> {
        debug!(target: "EXI", "stub memory card transfer: {req:?}");
        Ok(0xffff_ffff)
    }
}
