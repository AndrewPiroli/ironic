//todo: figure out wifi card
use anyhow::bail;
use super::device::{CmdRes, Command};

#[derive(Debug, Default)]
pub(super) struct WiFi4318;

impl WiFi4318 {
    pub(super) fn new() -> Self {
        Self
    }
    pub(super) fn present(&self) -> bool {
        false
    }
    pub(super) fn command(&mut self, _cmd: Command, _arg: u32) -> CmdRes {
        log::warn!(target: super::SdhcSlot::Sd1.log_target(),
            "Sdio command swallowed. WiFi is not quite ready yet, Sorry!");
        CmdRes::default()
    }
    pub(super) fn read_data(&self, _buf: &mut [u8]) -> anyhow::Result<()> {
        bail!("WiFi device is not implemented")
    }
    pub(super) fn write_data(&mut self, _buf: &[u8]) -> anyhow::Result<()> {
        bail!("WiFi device is not implemented")
    }
    pub(super) fn end_transfer(&mut self, _aborted: bool) {}
}
