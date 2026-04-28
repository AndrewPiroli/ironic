pub mod device;
use anyhow::bail;
use log::warn;
use device::*;
use device::sdgecko::*;
use device::usbgecko::*;
use device::rtc::*;
use device::memorycard::*;

use crate::bus::mmio::*;
use crate::bus::prim::*;
use crate::bus::task::*;

/// Representing user-configurable EXI clock freqencies.
#[derive(Debug, Clone, Copy)]
pub enum EXIFreq {
    Clk1Mhz, Clk2Mhz, Clk4Mhz, Clk8Mhz, Clk16Mhz, Clk32Mhz, Undef
}
impl From<u32> for EXIFreq {
    fn from(x: u32) -> Self {
        match x {
            0b000 => Self::Clk1Mhz,
            0b001 => Self::Clk2Mhz,
            0b010 => Self::Clk4Mhz,
            0b011 => Self::Clk8Mhz,
            0b100 => Self::Clk16Mhz,
            0b101 => Self::Clk32Mhz,
            0b110 | 0b111 => Self::Undef,
            _ => unreachable!(),
        }
    }
}

/// Representing an EXI transfer type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EXITransfer {
    Read, Write, ReadWrite, Undef,
}
impl From<u32> for EXITransfer {
    fn from(x: u32) -> Self {
        match x {
            0b00 => Self::Read,
            0b01 => Self::Write,
            0b10 => Self::ReadWrite,
            0b11 => Self::Undef,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EXIChannelAction {
    None,
    ImmediateTransfer(EXITransferRequest),
    DmaTransfer,
}

/// Container for the state associated with an EXI channel, determined by the
/// current value of the channel's status and control registers.
#[derive(Debug, Clone, Copy)]
pub struct ChannelState {
    /// Device connected flag
    pub ext: bool,

    /// External Insertion Interrupt Flag
    pub ext_int: bool,
    /// External Insertion Interrupt Mask
    pub ext_msk: bool,

    /// Currently-selected EXI chip-select, if any.
    pub cs: Option<usize>,
    /// The logical device mapped to the selected chip-select.
    pub dev: Option<EXIDeviceKind>,
    /// Channel clock frequency
    pub clk: EXIFreq,

    /// Transfer Complete Interrupt Flag
    pub tc_int: bool,
    /// Transfer Complete Interrupt Mask
    pub tc_msk: bool,

    /// EXI Interrupt flag
    pub exi_int: bool,
    /// EXI Interrupt mask
    pub exi_msk: bool,

    /// Size of pending immediate transfer in bytes
    pub imm_len: u32,
    /// The type of pending transfer
    pub transfer_type: EXITransfer,
    /// DMA transfer mode (otherwise, immediate transfer)
    pub dma: bool,
    /// Transfer status bit
    pub transfer: bool,
}

impl ChannelState {
    fn decode_cs(sts: u32) -> Option<usize> {
        match (sts & 0x0000_0380) >> 7 {
            0b001 => Some(0),
            0b010 => Some(1),
            0b100 => Some(2),
            _ => None,
        }
    }

    fn from_chn(chn: usize, sts: u32, ctrl: u32) -> Self {
        // Status register bits
        let ext     = sts & 0x0000_1000 != 0;
        let ext_int = sts & 0x0000_0800 != 0;
        let ext_msk = sts & 0x0000_0400 != 0;
        let tc_int  = sts & 0x0000_0008 != 0;
        let tc_msk  = sts & 0x0000_0004 != 0;
        let exi_int = sts & 0x0000_0002 != 0;
        let exi_msk = sts & 0x0000_0001 != 0;

        let cs      = Self::decode_cs(sts);
        let dev     = cs.and_then(|cs| EXIDeviceKind::resolve(chn, cs));
        let clk     = EXIFreq::from((sts & 0x0000_0070) >> 4);

        // Control register bits.
        let imm_len = ((ctrl & 0x0000_0030) >> 4) + 1;
        let transfer_type = EXITransfer::from((ctrl & 0x0000_000c) >> 2);
        let dma = ctrl & 0x0000_0002 != 0;
        let transfer = ctrl & 0x0000_0001 != 0;

        ChannelState {
            ext, ext_int, ext_msk, 
            cs, dev, clk,
            tc_int, tc_msk, 
            exi_int, exi_msk,
            imm_len, transfer_type, dma, transfer
        }
    }
}

/// Representing a single channel on the external interface.
#[derive(Debug, Clone)]
pub struct EXIChannel {
    /// Channel index
    idx: usize,
    /// Status register value
    pub csr: u32,
    /// DMA address register value
    pub mar: u32,
    /// DMA length register value
    pub len: u32,
    /// Control register value
    pub ctrl: u32,
    /// Immediate data register value
    pub data: u32,
    /// Channel state
    pub state: ChannelState,
}

impl EXIChannel {
    pub fn new(idx: usize) -> Self {
        EXIChannel {
            idx, csr: 0, mar: 0, len: 0, data: 0, ctrl: 0,
            state: ChannelState::from_chn(idx, 0, 0),
        }
    }

    fn update_state(&mut self) {
        self.state = ChannelState::from_chn(self.idx, self.csr, self.ctrl);
    }

    fn update_csr_device_bits(&mut self, has_device: bool) {
        if has_device {
            self.csr |= 0x0000_1000;
        } else {
            self.csr &= !0x0000_1000;
        }
        self.update_state();
    }
}

/// Per-channel read/write handlers.
impl EXIChannel {
    pub fn read(&self, off: usize) -> anyhow::Result<u32> {
        let res = match off {
            0x00 => self.csr,
            0x04 => self.mar,
            0x08 => self.len,
            0x0c => self.ctrl,
            0x10 => self.data,
            _ => bail!("EXI chn{} OOB read at {off:08x}", self.idx),
        };
        log::debug!(target: "EXI", "chn{} read {res:08x} from offset {off:x}", self.idx);
        Ok(res)
    }

    pub fn write(&mut self, off: usize, val: u32) -> anyhow::Result<EXIChannelAction> {
        log::debug!(target: "EXI", "chn{} write {val:08x} at {off:08x}", self.idx);
        match off {
            0x00 => self.csr = val,
            0x04 => self.mar = val,
            0x08 => self.len = val,
            0x0c => self.ctrl = val,
            0x10 => self.data = val,
            _ => bail!("EXI chn{} OOB write {val:08x} at {off:08x}", self.idx),
        }

        self.update_state();

        if !matches!(off, 0x00 | 0x0c) || !self.state.transfer {
            return Ok(EXIChannelAction::None);
        }

        self.ctrl &= !1;
        self.update_state();

        if self.state.dma {
            return Ok(EXIChannelAction::DmaTransfer);
        }

        let Some(cs) = self.state.cs else {
            return Ok(EXIChannelAction::None);
        };

        Ok(EXIChannelAction::ImmediateTransfer(EXITransferRequest {
            channel: self.idx,
            cs,
            len: self.state.imm_len,
            kind: self.state.transfer_type,
            data: self.data,
            clk: self.state.clk,
        }))
    }
}

/// Legacy external interface (EXI).
#[derive(Debug, Clone)]
pub struct EXInterface {
    /// EXI channel state
    pub channels: [EXIChannel; 3],
    /// Attached EXI devices by [channel][chip-select]
    pub devices: [[EXIDeviceSlot; 3]; 3],
    /// Buffer for Broadway bootstrap instructions
    pub ppc_bootstrap: Box<[u32; 0x10]>,
}

impl Default for EXInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl EXInterface {
    fn build_devices() -> [[EXIDeviceSlot; 3]; 3] {
        let mut devices = std::array::from_fn(|_| std::array::from_fn(|_| EXIDeviceSlot::None));

        devices[0][0] = EXIDeviceSlot::MemoryCard(MemoryCardDevice);
        devices[0][1] = EXIDeviceSlot::Rtc(RtcDevice);
        devices[1][0] = EXIDeviceSlot::UsbGecko(UsbGeckoDevice::default());
        devices[2][0] = EXIDeviceSlot::SdGecko(SdGeckoDevice);

        devices
    }

    pub fn new() -> Self {
        let devices = Self::build_devices();
        let mut exi = Self {
            channels: [EXIChannel::new(0), EXIChannel::new(1), EXIChannel::new(2)],
            devices,
            ppc_bootstrap: Box::new([0; 0x10]),
        };
        exi.refresh_presence_bits();
        exi
    }

    fn refresh_presence_bits(&mut self) {
        for channel_idx in 0..self.channels.len() {
            let has_device = self.devices[channel_idx][0].kind().is_some();
            self.channels[channel_idx].update_csr_device_bits(has_device);
        }
    }

    fn route_action(&mut self, action: EXIChannelAction) -> anyhow::Result<()> {
        match action {
            EXIChannelAction::None => Ok(()),
            EXIChannelAction::DmaTransfer => {
                warn!(target: "EXI", "EXI DMA transfers are not supported yet");
                Ok(())
            },
            EXIChannelAction::ImmediateTransfer(req) => {
                let result = self.devices[req.channel][req.cs].transfer_imm(req)?;
                self.channels[req.channel].data = result;
                Ok(())
            }
        }
    }

    fn write_channel(&mut self, channel_idx: usize, off: usize, val: u32) -> anyhow::Result<()> {
        let action = self.channels[channel_idx].write(off, val)?;
        self.refresh_presence_bits();
        self.route_action(action)
    }
}

impl MmioDevice for EXInterface {
    type Width = u32;

    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00..=0x10 => self.channels[0].read(off)?,
            0x14..=0x24 => self.channels[1].read(off - 0x14)?,
            0x28..=0x38 => self.channels[2].read(off - 0x28)?,
            0x40..=0x7c => self.ppc_bootstrap[(off - 0x40) / 4],
            _ => bail!("EXI read to undef offset {off:x}"),
        };
        Ok(BusPacket::Word(val))
    }

    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00..=0x10 => self.write_channel(0, off, val)?,
            0x14..=0x24 => self.write_channel(1, off - 0x14, val)?,
            0x28..=0x38 => self.write_channel(2, off - 0x28, val)?,
            0x40..=0x7c => self.ppc_bootstrap[(off - 0x40) / 4] = val,
            _ => bail!("EXI write {val:08x} to {off:x}"),
        }
        Ok(None)
    }
}
