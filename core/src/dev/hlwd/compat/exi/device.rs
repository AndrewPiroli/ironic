use super::{EXIFreq, EXITransfer};
pub mod sdgecko;
pub mod usbgecko;
pub mod rtc;
pub mod memorycard;
use sdgecko::*;
use usbgecko::*;
use rtc::*;
use memorycard::*;


/// Representing a particular EXI device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EXIDeviceKind {
    MemoryCard,
    Rtc,
    UsbGecko,
    SdGecko,
}

impl EXIDeviceKind {
    pub const fn location(self) -> (usize, usize) {
        match self {
            Self::MemoryCard => (0, 0),
            Self::Rtc => (0, 1),
            Self::UsbGecko => (1, 0),
            Self::SdGecko => (2, 0),
        }
    }

    pub fn resolve(channel: usize, cs: usize) -> Option<Self> {
        match (channel, cs) {
            (0, 0) => Some(Self::MemoryCard),
            (0, 1) => Some(Self::Rtc),
            (1, 0) => Some(Self::UsbGecko),
            (2, 0) => Some(Self::SdGecko),
            _ => None,
        }
    }
}

/// Decoded information for a single immediate EXI transfer.
#[derive(Debug, Clone, Copy)]
pub struct EXITransferRequest {
    pub channel: usize,
    pub cs: usize,
    pub len: u32,
    pub kind: EXITransfer,
    pub data: u32,
    pub clk: EXIFreq,
}

/// Concrete device storage for a single EXI chip-select line.
#[derive(Debug, Clone)]
pub enum EXIDeviceSlot {
    None,
    MemoryCard(MemoryCardDevice),
    Rtc(RtcDevice),
    UsbGecko(UsbGeckoDevice),
    SdGecko(SdGeckoDevice),
}

impl Default for EXIDeviceSlot {
    fn default() -> Self {
        Self::None
    }
}

impl EXIDeviceSlot {
    pub fn kind(&self) -> Option<EXIDeviceKind> {
        match self {
            Self::None => None,
            Self::MemoryCard(_) => Some(EXIDeviceKind::MemoryCard),
            Self::Rtc(_) => Some(EXIDeviceKind::Rtc),
            Self::UsbGecko(_) => Some(EXIDeviceKind::UsbGecko),
            Self::SdGecko(_) => Some(EXIDeviceKind::SdGecko),
        }
    }

    pub fn transfer_imm(&mut self, req: EXITransferRequest) -> anyhow::Result<u32> {
        match self {
            Self::None => Ok(0xffff_ffff),
            Self::MemoryCard(dev) => dev.transfer_imm(req),
            Self::Rtc(dev) => dev.transfer_imm(req),
            Self::UsbGecko(dev) => dev.transfer_imm(req),
            Self::SdGecko(dev) => dev.transfer_imm(req),
        }
    }
}
