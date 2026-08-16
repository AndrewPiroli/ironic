use anyhow::bail;

use super::card::Card;
use super::sdio::WiFi4318;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDir {
    /// Device to host (CMD17/CMD18, CMD53 read).
    Read,
    /// Host to device (CMD24/CMD25, CMD53 write).
    Write,
    /// Device to Host for SD Status Register (ACMD13/CMD6)
    SdStatusRead,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Response {
    /// R1, R3, R4, R5, R6, R7. Part 1 [39:8] to Part 2 [31:0]
    Regular(u32),
    // AutoCMD12(u32), // Part 1 [39:8] to Part 2 [127:96]
    /// Part 1 [127:8] to Part 2 [119:0]
    R2(u128),
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct CmdRes {
    pub response: Option<Response>,
    pub transfer: Option<TxDir>,
}

#[derive(Debug, Clone)]
pub(super) struct Command {
    pub index: u8,
    _ty: CommandType,
    _data_present: bool,
    // command_idx_ck: bool,
    // crc_ck: bool,
    _response: bool,
}

impl From<u32> for Command {
    fn from(value: u32) -> Self {
        Self {
            index: ((value & 0x3f00) >> 8) as u8,
            _ty: CommandType::new(((value & (1<<6)) >> 6) == 1, ((value & (1<<7)) >> 7) == 1),
            _data_present: ((value & (1<<5)) >> 5 == 1),
            // command_idx_ck: ((value & (1<<4)) >> 5 == 1),
            // crc_ck: ((value & (1<<3)) >> 5 == 1),
            _response: value & 0b11 != 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CommandType {
    /// CMD12, CMD52 for writing I/O Abort in CCCR
    Abort,
    /// CMD52 for writing Function Select in CCCR
    Resume,
    /// CMD 52 for writing Bus Suspend in CCCR
    Suspend,
    /// All other commands
    Normal,
}
impl CommandType {
    fn new(bit6: bool, bit7: bool) -> Self {
        match (bit6, bit7) {
            (true, true) => Self::Abort,
            (true, false) => Self::Resume,
            (false, true) => Self::Suspend,
            (false, false) => Self::Normal,
        }
    }
}

#[derive(Debug)]
pub(super) enum SdDevice {
    Card(Card),
    Sdio(WiFi4318),
}

impl SdDevice {
    pub(super) fn present(&self) -> bool {
        match self {
            Self::Card(c) => c.present(),
            Self::Sdio(d) => d.present(),
        }
    }

    pub(super) fn command(&mut self, cmd: Command, arg: u32) -> CmdRes {
        match self {
            Self::Card(c) => c.command(cmd, arg),
            Self::Sdio(d) => d.command(cmd, arg),
        }
    }

    pub(super) fn read_data(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        match self {
            Self::Card(c) => c.read_data(buf),
            Self::Sdio(d) => d.read_data(buf),
        }
    }

    pub(super) fn read_status(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        match self {
            Self::Card(c) => {
                if buf.len() == c.sdstatus.len() {
                    buf.copy_from_slice(&c.sdstatus[..]);
                    Ok(())
                }
                else { bail!("SD Status always 512 bits regardless of block len") }
            },
            Self::Sdio(_) => unimplemented!(),
        }
    }

    pub(super) fn write_data(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Card(c) => c.write_data(buf),
            Self::Sdio(d) => d.write_data(buf),
        }
    }

    pub(super) fn end_transfer(&mut self, aborted: bool) {
        match self {
            Self::Card(c) => c.end_transfer(aborted),
            Self::Sdio(d) => d.end_transfer(aborted),
        }
    }
}
