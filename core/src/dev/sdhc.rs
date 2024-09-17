#![allow(clippy::needless_return, clippy::zero_prefixed_literal)]
pub(crate) mod card;
pub(crate) mod wifi;

pub use card::*;
pub use wifi::*;

use anyhow::anyhow;
use anyhow::bail;
use log::debug;
use log::error;
use log::log_enabled;
use log::trace;
use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;
use crate::bus::Bus;

use crate::mem::BigEndianMemory;

/// Changing this to false will disable DMA support
const SDHC_ENABLE_DMA: bool = true;

#[derive(Debug)]
pub enum SDHCTask {
    RaiseInt,
    SendBufReadReady,
    SendBufWriteReady,
    IOPoll,
    DoDMARead,
    DoDMAWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The Transaction State of the emulated SD card.
/// The SD Interface and Bus Tasks will check and update this as I/O is performed on the card
pub enum DeviceTXStatus {
    /// No Transaction in progress. The default state.
    None,
    /// A multi-block Read transaction has been issued, but the SD Interface hasn't told anyone yet.
    MultiReadPending,
    /// A multi-block Read transaction in progress, the SD Interface is redirecting reads from its Buffer Data Port to the Card's backing memory
    MultiReadInProgress,
    /// A multi-block Write transaction has been issued, but the SD Interface hasn't told anyone yet.
    MultiWritePending,
    /// A multi-block Read transaction in progress, the SD Interface is redirecting writes to it's Buffer Data Port to the Card's backing memory
    MultiWriteInProgress,
    /// The SD Interface is performing DMA Read operations on the Card's backing memory.
    DMAReadInProgress,
    /// The SD Interface is performing DMA Write operations on the Card's backing memory.
    DMAWriteInProgress,
}

impl Default for DeviceTXStatus {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Copy, Clone)]
enum SDRegisters {
    SystemAddress,
    BlockSize,
    BlockCount,
    Argument,
    TxMode,
    Command,
    Response,
    BufferDataPort,
    PresentState,
    HostControl,
    PowerControl,
    BlockGapControl,
    WakeupControl,
    ClockControl,
    TimeoutControl,
    SoftwareReset,
    NormalIntStatus,
    ErrorIntStatus,
    NormalIntStatusEnable,
    ErrorIntStatusEnable,
    NormalIntSignalEnable,
    ErrorIntSignalEnable,
    AutoCMD12ErrorStatus,
    Capabilities,
    MaxCurrentCapabilities,
    SlotIntStatus,
    HostControllerVersion,
}

impl SDRegisters {
    // writes are always 32 bit, but some registers are smaller than that, so we need to test old and new
    fn get_affected_registers(off: usize, old: u32, new: u32) -> Vec<SDRegisters> {
        let mut ret = Vec::with_capacity(4);
        let mut shift = 0u32;
        for reg in (off..off+4).filter_map(Self::reg_from_offset) {
            // is this a large (32bit +) register?
            if reg.bytecount_of_reg() >= 4 {
                if old != new || reg.must_always_handle_writes() {
                    ret.push(reg);
                }
                return ret;
            }
            // Else, build a mask for the next register
            let mask: u32 = ((1 << (reg.bytecount_of_reg() * 8)) - 1) << shift;
            if reg.must_always_handle_writes() || old & mask != new & mask {
                ret.push(reg);
            }
            shift += reg.bytecount_of_reg() as u32 * 8;
            debug_assert!(shift <= 32);
        }
        ret
    }

    fn base_offset(&self) -> usize {
        match self {
            SDRegisters::SystemAddress => 0x0,
            SDRegisters::BlockSize => 0x4,
            SDRegisters::BlockCount => 0x6,
            SDRegisters::Argument => 0x8,
            SDRegisters::TxMode => 0xc,
            SDRegisters::Command => 0xe,
            SDRegisters::Response => 0x10,
            SDRegisters::BufferDataPort => 0x20,
            SDRegisters::PresentState => 0x24,
            SDRegisters::HostControl => 0x28,
            SDRegisters::PowerControl => 0x29,
            SDRegisters::BlockGapControl => 0x2a,
            SDRegisters::WakeupControl => 0x2b,
            SDRegisters::ClockControl => 0x2c,
            SDRegisters::TimeoutControl => 0x2e,
            SDRegisters::SoftwareReset => 0x2f,
            SDRegisters::NormalIntStatus => 0x30,
            SDRegisters::ErrorIntStatus => 0x32,
            SDRegisters::NormalIntStatusEnable => 0x34,
            SDRegisters::ErrorIntStatusEnable => 0x36,
            SDRegisters::NormalIntSignalEnable => 0x38,
            SDRegisters::ErrorIntSignalEnable => 0x3a,
            SDRegisters::AutoCMD12ErrorStatus => 0x3c,
            SDRegisters::Capabilities => 0x40,
            SDRegisters::MaxCurrentCapabilities => 0x48,
            SDRegisters::SlotIntStatus => 0xfc,
            SDRegisters::HostControllerVersion => 0xfe,
        }
    }
    fn reg_from_offset(off: usize) -> Option<Self> {
        Some(match off {
            0x0 => SDRegisters::SystemAddress,
            0x4 => SDRegisters::BlockSize,
            0x6 => SDRegisters::BlockCount,
            0x8 => SDRegisters::Argument,
            0xc => SDRegisters::TxMode,
            0xe => SDRegisters::Command,
            0x10 => SDRegisters::Response,
            0x20 => SDRegisters::BufferDataPort,
            0x24 => SDRegisters::PresentState,
            0x28 => SDRegisters::HostControl,
            0x29 => SDRegisters::PowerControl,
            0x2a => SDRegisters::BlockGapControl,
            0x2b => SDRegisters::WakeupControl,
            0x2c => SDRegisters::ClockControl,
            0x2e => SDRegisters::TimeoutControl,
            0x2f => SDRegisters::SoftwareReset,
            0x30 => SDRegisters::NormalIntStatus,
            0x32 => SDRegisters::ErrorIntStatus,
            0x34 => SDRegisters::NormalIntStatusEnable,
            0x36 => SDRegisters::ErrorIntStatusEnable,
            0x38 => SDRegisters::NormalIntSignalEnable,
            0x3a => SDRegisters::ErrorIntSignalEnable,
            0x3c => SDRegisters::AutoCMD12ErrorStatus,
            0x40 => SDRegisters::Capabilities,
            0x48 => SDRegisters::MaxCurrentCapabilities,
            0xfc => SDRegisters::SlotIntStatus,
            0xfe => SDRegisters::HostControllerVersion,
            _ => { return None; },
        })
    }
    fn bytecount_of_reg(&self) -> usize {
        match self {
            SDRegisters::SystemAddress => 4,
            SDRegisters::BlockSize => 2,
            SDRegisters::BlockCount => 2,
            SDRegisters::Argument => 4,
            SDRegisters::TxMode => 2,
            SDRegisters::Command => 2,
            SDRegisters::Response => 16,
            SDRegisters::BufferDataPort => 4,
            SDRegisters::PresentState => 4,
            SDRegisters::HostControl => 1,
            SDRegisters::PowerControl => 1,
            SDRegisters::BlockGapControl => 1,
            SDRegisters::WakeupControl => 1,
            SDRegisters::ClockControl => 2,
            SDRegisters::TimeoutControl => 1,
            SDRegisters::SoftwareReset => 1,
            SDRegisters::NormalIntStatus => 2,
            SDRegisters::ErrorIntStatus => 2,
            SDRegisters::NormalIntStatusEnable => 2,
            SDRegisters::ErrorIntStatusEnable => 2,
            SDRegisters::NormalIntSignalEnable => 2,
            SDRegisters::ErrorIntSignalEnable => 2,
            SDRegisters::AutoCMD12ErrorStatus => 2,
            SDRegisters::Capabilities => 8,
            SDRegisters::MaxCurrentCapabilities => 8,
            SDRegisters::SlotIntStatus => 2,
            SDRegisters::HostControllerVersion => 2,
        }
    }
    // These registers have RW1C bits or additional logic that must run on any write, even if the register is ultimiately unchanged
    fn must_always_handle_writes(&self) -> bool {
        matches!(self,
            SDRegisters::BufferDataPort |
            SDRegisters::Command |
            SDRegisters::NormalIntStatus |
            SDRegisters::ErrorIntStatus |
            SDRegisters::SystemAddress
        )
    }
    fn run_write_handler<D: SDHCDevice>(&self, iface: &mut SDInterface<D>, old: u32, new: u32) -> Option<SDHCTask> {
        let shift: usize;
        let mask: u32;
        if self.bytecount_of_reg() >= 4 {
            shift = 0;
            mask = 0xffff_ffff;
        }
        else {
            // Calculate shift to move the register in question to the right most position
            shift = (self.base_offset() & 0x3) * 8;
            mask = (1 << (self.bytecount_of_reg() * 8)) - 1;
        }
        let old = (old >> shift) & mask;
        let mut new = (new >> shift) & mask;
        debug!(target: "SDHC", "write handler for {self:?} {old:x} {new:x}");
        match self {
            SDRegisters::Command => {
                let x = Command::from(new);
                if log_enabled!(target: "SDHC", log::Level::Debug) {
                    dbg!(&x);
                }
                // let cmd = x.index;
                if let Some(response) = iface.device.issue(x, iface.raw_read(SDRegisters::Argument.base_offset())){
                    self.apply_response(iface, response);
                }
                if iface.cmd_complete() {
                    return Some(SDHCTask::RaiseInt);
                }
            }
            SDRegisters::NormalIntStatus => {
                const RW1C_MASK: u32 = 0x1ff; // mask of the bits that are rw1c, all others are reserved or ROC.
                let clearbits = (old & RW1C_MASK) ^ (new & RW1C_MASK);
                let int_new = (old & !RW1C_MASK) | clearbits;
                debug!(target: "SDHC", "normalintstatus {old:b} {int_new:b}");
                iface.setreg(*self, int_new);
                // The host driver will write here to acknowledge a CMD complete
                // If there is a pending transfer that's supposed to be associated with that command
                // This is the time to kick it off.
                match iface.device.tx_status() {
                    DeviceTXStatus::MultiReadPending => { // Multi Block Read
                        if new & 1 == 1 {
                            let use_dma = iface.raw_read(SDRegisters::TxMode.base_offset()) & 0x1 == 1;
                            if use_dma {
                                if !SDHC_ENABLE_DMA {
                                    error!(target:"SDHC", "Software Attempted to use DMA, which is disabled.");
                                    return None;
                                }
                                iface.device.set_tx_status(DeviceTXStatus::DMAReadInProgress);
                                return Some(SDHCTask::DoDMARead);
                            }
                            else {
                                iface.device.set_tx_status(DeviceTXStatus::MultiReadInProgress);
                                return Some(SDHCTask::SendBufReadReady);
                            }
                        }
                    },
                    DeviceTXStatus::MultiWritePending => {
                        if new & 1 == 1 {
                            let use_dma = iface.raw_read(SDRegisters::TxMode.base_offset()) & 0x1 == 1;
                            if use_dma {
                                if !SDHC_ENABLE_DMA {
                                    error!(target:"SDHC", "Software Attempted to use DMA, which is disabled.");
                                    return None;
                                }
                                iface.device.set_tx_status(DeviceTXStatus::DMAWriteInProgress);
                                return Some(SDHCTask::DoDMAWrite);
                            }
                            else {
                                iface.device.set_tx_status(DeviceTXStatus::MultiWriteInProgress);
                                return Some(SDHCTask::SendBufWriteReady);
                            }
                        }
                    },
                    DeviceTXStatus::None | DeviceTXStatus::MultiReadInProgress | DeviceTXStatus::MultiWriteInProgress | DeviceTXStatus::DMAReadInProgress | DeviceTXStatus::DMAWriteInProgress => { // No action taken here
                        return None;
                    },
                }
            },
            SDRegisters::ErrorIntStatus => {
                const RW1C_MASK: u32 = 0xf1ff; // mask of the bits that are rw1c, all others are reserved or ROC.
                let clearbits = (old & RW1C_MASK) ^ (new & RW1C_MASK);
                let new = (old & !RW1C_MASK) | clearbits;
                iface.setreg(*self, new);
            },
            SDRegisters::NormalIntSignalEnable => {
                debug!(target: "SDHC", "Normal Int Signal Enable {new:b}");
                iface.setreg(*self, new);
                if iface.do_pending_ints() || iface.insert_card() || iface.first_ack() {
                    return Some(SDHCTask::RaiseInt);
                }
            },
            SDRegisters::NormalIntStatusEnable => {
                debug!(target: "SDHC", "Normal Int Status Enable {new:b}");
                iface.setreg(*self, new);
                if iface.do_pending_ints() || iface.insert_card() || iface.first_ack() {
                    return Some(SDHCTask::RaiseInt);
                }
            },
            SDRegisters::ClockControl => {
                // set internal clock stable (bit 1) based on internal clock enable (bit 0)
                match new & 0b1 {
                    0b0 => {
                        new &= 0xffff_fffc;
                    }
                    0b1 => {
                        new |= 0b10;
                    }
                    _=> {}
                }
                iface.setreg(*self, new);
            },
            SDRegisters::SoftwareReset => {
                if new & 1 == 1 {
                    iface.reset();
                }
                else { unimplemented!("DAT and CMD line resets"); }
            },
            SDRegisters::BufferDataPort => {
                match iface.device.tx_status() {
                    DeviceTXStatus::None |
                    DeviceTXStatus::MultiReadPending |
                    DeviceTXStatus::MultiReadInProgress |
                    DeviceTXStatus::DMAReadInProgress |
                    DeviceTXStatus::DMAWriteInProgress |
                    DeviceTXStatus::MultiWritePending => {
                        error!(target: "SDHC", "Software wrote to the BufferDataPort but there is no non-DMA write transaction.");
                        // intentionally drop the write here
                    }
                    DeviceTXStatus::MultiWriteInProgress => {
                        let index = iface.device.data_index();
                        {
                            let mut v = iface.device.lock_data();
                            if v.data.len() < index+4 || index+4 > iface.device.data_stop() {
                                return None;
                            }
                            iface.device.set_data_index(index+4);
                            v.write(index, new).unwrap();
                        }
                    },
                }
            },
            SDRegisters::SystemAddress => {
                iface.setreg(*self, new);
                if old & 0xff00_0000 != new & 0xff00_0000 {
                    if iface.device.tx_status() == DeviceTXStatus::DMAReadInProgress {
                        return Some(SDHCTask::DoDMARead);
                    }
                    else if iface.device.tx_status() == DeviceTXStatus::DMAWriteInProgress {
                        return Some(SDHCTask::DoDMAWrite);
                    }
                }
            }
            SDRegisters::TxMode |
            SDRegisters::BlockCount |
            SDRegisters::BlockSize |
            SDRegisters::Argument |
            SDRegisters::ErrorIntStatusEnable |
            SDRegisters::ErrorIntSignalEnable |
            SDRegisters::TimeoutControl |
            SDRegisters::PowerControl => {
                // No special handling needed for these registers
                iface.setreg(*self, new);
            },
            other => {
                error!(target: "SDHC", "Unhandled write to register: {other:?}");
                iface.setreg(*other, new);
            }
        }
        None
    }
    fn apply_response<D: SDHCDevice>(&self, iface: &mut SDInterface<D>, response: Response) {
        match response {
            Response::Regular(r) => {
                iface.raw_write(SDRegisters::Response.base_offset(), r);
            },
            Response::R2(r) => {
                iface.raw_write(SDRegisters::Response.base_offset(),      ((r >> 00) & 0xffff_ffff) as u32);
                iface.raw_write(SDRegisters::Response.base_offset() + 04, ((r >> 32) & 0xffff_ffff) as u32);
                iface.raw_write(SDRegisters::Response.base_offset() + 08, ((r >> 64) & 0xffff_ffff) as u32);
                iface.raw_write(SDRegisters::Response.base_offset() + 12, ((r >> 96) & 0xffff_ffff) as u32);
            }
        }
    }
}

#[repr(C, align(64))]
pub struct SDInterface<D: SDHCDevice> {
    register_file: [u8; 256],
    pending_interrupt_flags: u32,
    insert_raised: bool,
    first_ack: bool,
    device: D,
    device_available: bool,
    device_tx_status: DeviceTXStatus,
}

impl<D: SDHCDevice> SDInterface<D> {
    fn raw_read(&self, off: usize) -> u32 {
        let p = (&self.register_file) as *const [u8;256] as *const u32;
        assert!(off & 0xffff_fffc == off); // alignment
        let off = off >> 2;
        assert!(off < 64); //length
        let ret = unsafe { *(p.add(off)) };
        trace!(target: "SDHC", "raw_read 0x{:x} = 0x{ret:x}", off << 2);
        ret
    }
    fn raw_write(&mut self, off: usize, val: u32) {
        let p = (&mut self.register_file) as *mut [u8;256] as *mut u32;
        assert!(off & 0xffff_fffc == off); // alignment
        let off = off >> 2;
        assert!(off < 64); //length
        unsafe { *(p.add(off)) = val; };
        trace!(target: "SDHC", "raw_write 0x{:x} = 0x{val:x}", off << 2);
    }
    fn setreg(&mut self, reg: SDRegisters, val: u32) {
        match reg.bytecount_of_reg() {
            4 => {
                self.raw_write(reg.base_offset(), val);
                return;
            },
            5.. => { unimplemented!(); },
            _ => {},
        }
        let val_shift = (reg.base_offset() & 0x3) * 8;
        let mask: u32 = ((1 << (reg.bytecount_of_reg()*8)) - 1) << val_shift;
        let old = self.raw_read(reg.base_offset() & 0xffff_fffc) & !mask;
        let new = old | ((val << val_shift) & mask);
        self.raw_write(reg.base_offset() & 0xffff_fffc, new);
    }
    fn ck_int_enabled(&self, int: u32) -> bool {
        let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
        let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
        signal & int != 0 && status & int != 0
    }
    fn do_pending_ints(&mut self) -> bool {
        if self.pending_interrupt_flags == 0 {
            return false;
        }
        let mut nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
        let mut found = false;
        for i in 0..32 {
            let int = self.pending_interrupt_flags & (1 << i);
            if self.ck_int_enabled(int) {
                found = true;
                self.pending_interrupt_flags &= !int;
                nisr |= int;
            }
        }
        if found {
            let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
            self.setreg(SDRegisters::NormalIntStatus, nisr);
            self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
        }
        return found;
    }
    // returns true if the interrupt should be raised now, false if it's masked and will be raised later
    fn raise_int(&mut self, int: u32) -> bool {
        if self.ck_int_enabled(int) {
            let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
            let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
            self.setreg(SDRegisters::NormalIntStatus, nisr | int);
            self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
            true
        }
        else {
            self.pending_interrupt_flags |= int;
            false
        }
    }
    fn reset(&mut self) {
        debug!(target: "SDHC", "SD interface software reset");
        let mut new = Self::default();
        let card_detection_circuit_status = self.raw_read(SDRegisters::PresentState.base_offset()) & 0x70000;
        new.raw_write(SDRegisters::PresentState.base_offset(), card_detection_circuit_status);
        new.insert_raised = self.insert_raised;
        *self = new;
    }
    fn insert_card(&mut self) -> bool {
        if self.insert_raised || !self.device_available {
            return false;
        }
        let current_state = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, current_state | (1<<16) | (1<<17) | (1 << 18)); // card inserted
        self.insert_raised = true;
        const INSERT_INT_MASK: u32 = 1 << 6;
        return self.raise_int(INSERT_INT_MASK);
    }
    fn first_ack(&mut self) -> bool {
        if self.first_ack {
            return false;
        }
        self.first_ack = true;
        debug!(target: "SDHC", "Sending inital ack for card setup");
        const CMD_COMPLETE_MASK: u32 = 1;
        return self.raise_int(CMD_COMPLETE_MASK);
    }
    fn cmd_complete(&mut self) -> bool {
        debug!(target: "SDHC", "CMD complete int");
        const CMD_COMPLETE_MASK: u32 = 1;
        return self.raise_int(CMD_COMPLETE_MASK);
    }
    fn buffer_ready_read(&mut self) -> bool {
        let blocks_remaining = self.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16;
        if blocks_remaining > 0 {
            self.device.set_data_stop(self.device.data_index() + 512);
            self.setreg(SDRegisters::BlockCount, blocks_remaining.saturating_sub(1));
        }
        else {
            return false;
        }
        trace!(target: "SDHC", "Buffer Ready Read");
        // Present State Buffer Read Enable (11) & Read Tx Active (9) & Command Inhibit (DAT) (1)
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, ps | 1<<11 | 1<<9| 1 << 1);
        // Set Buffer Read Ready Int
        const BUFFER_READ_READY_MASK: u32 = 1 << 5;
        return self.raise_int(BUFFER_READ_READY_MASK);
    }
    fn buffer_ready_write(&mut self) -> bool {
        let blocks_remaining = self.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16; // p83
        if blocks_remaining > 0 {
            // tell card it's rw_stop
            self.device.set_data_stop(self.device.data_index() + 512);
            self.setreg(SDRegisters::BlockCount, blocks_remaining.saturating_sub(1));
        }
        else {
            return false;
        }
        trace!(target: "SDHC", "Buffer Ready Write");
        // Present State Buffer Write Enable (11) & Write Tx Active (9) & Command Inhibit (DAT) (1)
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, ps | 1<<10 | 1<<8 | 1 << 1);
        // Set Buffer Write Ready Int
        const BUFFER_WRITE_READY_MASK: u32 = 1 << 4;
        return self.raise_int(BUFFER_WRITE_READY_MASK);
    }
    fn tx_complete(&mut self) -> bool {
        debug!(target: "SDHC", "Tx Complete");
        match self.device.tx_status() {
            DeviceTXStatus::None |
            DeviceTXStatus::MultiReadPending |
            DeviceTXStatus::MultiWritePending => {
                error!(target: "SDHC", "Requested Tx complete but no transfer is active.");
                return false;
            },
            DeviceTXStatus::MultiWriteInProgress => {
                // Clear Block Count Register
                self.setreg(SDRegisters::BlockCount, 0);
                // clear PS Buffer write enable & Write Tx Active & CMD Inhibit (DAT)
                let ps = self.raw_read(SDRegisters::PresentState.base_offset());
                const KILL_MASK: u32 = !(1 << 10 | 1 << 8 | 1 << 1);
                self.setreg(SDRegisters::PresentState, ps & KILL_MASK);
                self.device.set_tx_status(DeviceTXStatus::None);
                self.device.set_state(CardState::Trans);
                const TRANSFER_COMPLETE_MASK: u32 = 1 << 1;
                return self.raise_int(TRANSFER_COMPLETE_MASK);
            },
            DeviceTXStatus::MultiReadInProgress => {
                // Clear Block Count Register
                self.setreg(SDRegisters::BlockCount, 0);
                // clear PS Buffer read enable & Read Tx Active & CMD Inhibit (DAT)
                let ps = self.raw_read(SDRegisters::PresentState.base_offset());
                const KILL_MASK: u32 = !(1 << 11 | 1 << 9 | 1 << 1);
                self.setreg(SDRegisters::PresentState, ps & KILL_MASK);
                const TRANSFER_COMPLETE_MASK: u32 = 1 << 1;
                self.device.set_tx_status(DeviceTXStatus::None);
                self.device.set_state(CardState::Trans);
                return self.raise_int(TRANSFER_COMPLETE_MASK);
            },
            DeviceTXStatus::DMAReadInProgress => {
                // Clear Block Count Register
                self.setreg(SDRegisters::BlockCount, 0);
                // clear PS Read Tx Active & CMD Inhibit (DAT)
                let ps = self.raw_read(SDRegisters::PresentState.base_offset());
                const KILL_MASK: u32 = !(1 << 9 | 1 << 1);
                self.setreg(SDRegisters::PresentState, ps & KILL_MASK);
                self.device.set_tx_status(DeviceTXStatus::None);
                self.device.set_state(CardState::Trans);
                const TRANSFER_COMPLETE_MASK: u32 = 1 << 1;
                return self.raise_int(TRANSFER_COMPLETE_MASK);
            },
            DeviceTXStatus::DMAWriteInProgress => {
                // Clear Block Count Register
                self.setreg(SDRegisters::BlockCount, 0);
                // clear PS Buffer  Write Tx Active & CMD Inhibit (DAT)
                let ps = self.raw_read(SDRegisters::PresentState.base_offset());
                const KILL_MASK: u32 = !(1 << 8 | 1 << 1);
                self.setreg(SDRegisters::PresentState, ps & KILL_MASK);
                self.device.set_tx_status(DeviceTXStatus::None);
                self.device.set_state(CardState::Trans);
                const TRANSFER_COMPLETE_MASK: u32 = 1 << 1;
                return self.raise_int(TRANSFER_COMPLETE_MASK);
            }
        }
    }
    fn dma_int(&mut self) -> bool {
        const DMA_INT: u32 = 1 << 3;
        match self.device_tx_status {
            DeviceTXStatus::None |
            DeviceTXStatus::MultiReadPending |
            DeviceTXStatus::MultiReadInProgress |
            DeviceTXStatus::MultiWritePending |
            DeviceTXStatus::MultiWriteInProgress => {
                error!(target: "SDHC", "Asked for a DMA Interrupt but no DMA transfer is in progress");
                return false;
            },
            DeviceTXStatus::DMAReadInProgress | DeviceTXStatus::DMAWriteInProgress  => {
                return self.raise_int(DMA_INT);
            },
        }
    }
}

impl<D: SDHCDevice> Default for SDInterface<D> {
    fn default() -> Self {
        let (card, card_available) = D::try_new();
        let mut new = Self { register_file: [0;256], pending_interrupt_flags: 0, insert_raised: false, first_ack: false, device: card, device_available: card_available, device_tx_status: DeviceTXStatus::None };
        // Fill HWInit registers
        // Capabilities Register
        const VOLTAGE_SUPPORT_3_3V: u32 = 1 << 24;
        const SD_BASE_CLK_10MHZ: u32 = 10 << 8;
        const DMA_SUPPORT: u32 = (SDHC_ENABLE_DMA as u32) << 22;
        new.raw_write(SDRegisters::Capabilities.base_offset(), VOLTAGE_SUPPORT_3_3V | SD_BASE_CLK_10MHZ | DMA_SUPPORT);
        // Maximum Current Capabilities Register
        const CURRENT_CAP_3_3V_MAX: u32 = 0xff;
        new.raw_write(SDRegisters::MaxCurrentCapabilities.base_offset(), CURRENT_CAP_3_3V_MAX);
        // End HWInit Registers
        debug!(target: "SDHC", "init sdhc");
        new
    }
}

impl<D: SDHCDevice> MmioDevice for SDInterface<D> {
    type Width = u32;

    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        trace!(target: "SDHC", "MMIO read: 0x{off:x}");
        if off == SDRegisters::BufferDataPort.base_offset() {
            match self.device.tx_status() {
                DeviceTXStatus::None |
                DeviceTXStatus::MultiReadPending |
                DeviceTXStatus::MultiWritePending |
                DeviceTXStatus::MultiWriteInProgress |
                DeviceTXStatus::DMAReadInProgress |
                DeviceTXStatus::DMAWriteInProgress => { error!(target: "SDHC", "Software tried reading the BufferDataPort but there is no non-DMA read transaction."); }
                DeviceTXStatus::MultiReadInProgress => {
                    let index = self.device.data_index();
                    {
                        let v = self.device.lock_data();
                        if v.data.len() < index+4 || index+4 > self.device.data_stop() {
                            return Err(anyhow!("out of range! {index:?} {:?} {} ", v.data.len(), self.device.data_stop()));
                        }
                        self.device.set_data_index(index+4);
                        let ret: u32 = v.read(index).unwrap();
                        return Ok(BusPacket::Word(ret));
                    }
                },
            }
        }
        Ok(BusPacket::Word(self.raw_read(off)))
    }

    fn write(&mut self, off: usize, val: Self::Width) -> anyhow::Result<Option<BusTask>> {
        debug!(target: "SDHC", "MMIO write: 0x{off:x} = 0x{val:x}");
        // first read the current line to get the old
        let old = self.raw_read(off);
        let regs = SDRegisters::get_affected_registers(off, old, val);
        debug!(target: "SDHC", "{:?}", &regs);
        //fixme: multiple tasks?
        let mut tasks = Vec::new();
        for reg in regs {
            if let Some(task) = reg.run_write_handler(self, old, val) {
                tasks.push(task);
            }
        }
        if tasks.is_empty() {
            Ok(None)
        }
        else {
            Ok(Some(BusTask::SDHC(tasks.pop().unwrap())))
        }
    }
}

impl Bus {
    pub(crate) fn handle_task_sdhc(&mut self, task: SDHCTask) {
        use super::hlwd::irq::HollywoodIrq;
        match task {
            SDHCTask::RaiseInt => {
                debug!(target: "SDHC", "Raising SDHC interrupt.");
                self.hlwd.irq.assert(HollywoodIrq::Sdhc);
            },
            SDHCTask::SendBufReadReady => {
                match self.sd0.buffer_ready_read() {
                    true => {
                        self.tasks.push(
                            Task { kind: BusTask::SDHC(SDHCTask::IOPoll), target_cycle: self.cycle+10000 }
                        );
                        self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                    },
                    false => {
                        unimplemented!();
                    },
                }
            },
            SDHCTask::SendBufWriteReady => {
                match self.sd0.buffer_ready_write() {
                    true => {
                        self.tasks.push(
                            Task { kind: BusTask::SDHC(SDHCTask::IOPoll), target_cycle: self.cycle+10000 }
                        );
                        self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                    },
                    false => {
                        unimplemented!();
                    },
                }
            },
            SDHCTask::DoDMARead => {
                let sysaddr = self.sd0.raw_read(SDRegisters::SystemAddress.base_offset());
                let buff_boundry = 0x1000u32 << ((self.sd0.raw_read(SDRegisters::BlockSize.base_offset()) & 0x7000) >> 12);
                let stop_addr = match sysaddr.checked_add(buff_boundry) { // mini always sets 512k boundry size, even if that would overrun the address space
                    Some(x) => (x + 1) & !(buff_boundry - 1),
                    None => u32::MAX,
                };
                let mut block_count = self.sd0.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16;
                let mut current_addr = sysaddr;
                debug!(target: "SDHC", "Starting DMA Read Tx to sysaddr: {sysaddr:x}");
                let mut local_buf = vec![0;512];
                while current_addr+512 < stop_addr && block_count > 0 {
                    let offset = self.sd0.device.rw_index.load(std::sync::atomic::Ordering::Relaxed);
                    self.sd0.device.backing_mem.lock().read_buf(offset, &mut local_buf).unwrap();
                    self.dma_write(current_addr, &local_buf).unwrap();
                    self.sd0.device.rw_index.store(offset + 512, std::sync::atomic::Ordering::Relaxed);
                    local_buf.fill(0);
                    block_count -= 1;
                    current_addr += 512;
                }
                let send_dma_int = current_addr >= stop_addr;
                let send_tx_complete = block_count == 0;
                debug!(target: "SDHC", "DMA Transfer completed after {} blocks. Reached DMA Boundry: {send_dma_int}. Reached Block Count: {send_tx_complete}", (current_addr-sysaddr) / 512);
                self.sd0.setreg(SDRegisters::BlockCount, block_count);
                self.sd0.setreg(SDRegisters::SystemAddress, current_addr);
                if send_tx_complete { // TX Complete has higher priority than DMA complete. Never send both!
                    if self.sd0.tx_complete() {
                        self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                    }
                }
                else if send_dma_int {
                    if self.sd0.dma_int() {
                        self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                    }
                }
                else {
                    unreachable!("SDHC DMA Logic Error");
                }
            },
            SDHCTask::DoDMAWrite => {
                let sysaddr: u32 = self.sd0.raw_read(SDRegisters::SystemAddress.base_offset());
                let buff_boundry = 0x1000u32 << ((self.sd0.raw_read(SDRegisters::BlockSize.base_offset()) & 0x7000) >> 12);
                let stop_addr = match sysaddr.checked_add(buff_boundry) { // mini always sets 512k boundry size, even if that would overrun the address space
                    Some(x) => (x + 1) & !(buff_boundry - 1),
                    None => u32::MAX,
                };
                let mut block_count = self.sd0.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16;
                let mut current_addr = sysaddr;
                debug!(target: "SDHC", "Starting DMA Write Tx from sysaddr: {sysaddr:x}");
                let mut local_buf = vec![0;512];
                while current_addr+512 < stop_addr && block_count > 0 {
                    self.dma_read(current_addr, &mut local_buf).unwrap();
                    let offset = self.sd0.device.rw_index.load(std::sync::atomic::Ordering::Relaxed);
                    self.sd0.device.backing_mem.lock().write_buf(offset, &local_buf).unwrap();
                    self.sd0.device.rw_index.store(offset + 512, std::sync::atomic::Ordering::Relaxed);
                    local_buf.fill(0);
                    block_count -= 1;
                    current_addr += 512;
                }
                let send_dma_int = current_addr >= stop_addr;
                let send_tx_complete = block_count == 0;
                debug!(target: "SDHC", "DMA Transfer completed after {} blocks. Reached DMA Boundry: {send_dma_int}. Reached Block Count: {send_tx_complete}", (current_addr-sysaddr) / 512);
                self.sd0.setreg(SDRegisters::BlockCount, block_count);
                self.sd0.setreg(SDRegisters::SystemAddress, current_addr);
                if send_tx_complete { // TX Complete has higher priority than DMA complete. Never send both!
                    if self.sd0.tx_complete() {
                        self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                    }
                }
                else if send_dma_int {
                    if self.sd0.dma_int() {
                        self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                    }
                }
                else {
                    unreachable!("SDHC DMA Logic Error");
                }
            }
            SDHCTask::IOPoll => {
                let rw_index = self.sd0.device.rw_index.load(std::sync::atomic::Ordering::Relaxed);
                trace!(target: "SDHC", "SDHC IOPOLL {} {}", rw_index, self.sd0.device.rw_stop);
                match self.sd0.device.tx_status() {
                    DeviceTXStatus::None |
                    DeviceTXStatus::MultiReadPending |
                    DeviceTXStatus::MultiWritePending => {},
                    DeviceTXStatus::DMAReadInProgress | DeviceTXStatus::DMAWriteInProgress => {
                        error!(target: "SDHC", "Improper state for SDHC IOPOLLing.");
                    }
                    DeviceTXStatus::MultiReadInProgress => {
                        if rw_index >= self.sd0.device.rw_stop {
                            let blocks_remain = self.sd0.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16;
                            if blocks_remain > 0 {
                                self.tasks.push(
                                    Task { kind: BusTask::SDHC(SDHCTask::SendBufReadReady), target_cycle: self.cycle + 10000 }
                                );
                            }
                            else if self.sd0.tx_complete() {
                               self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                            }
                        }
                        else {
                            self.tasks.push(
                                Task { kind: BusTask::SDHC(SDHCTask::IOPoll), target_cycle: self.cycle+10000 }
                            );
                        }
                    },
                    DeviceTXStatus::MultiWriteInProgress => {
                        if rw_index >= self.sd0.device.rw_stop {
                            let blocks_remain = self.sd0.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16;
                            if blocks_remain > 0 {
                                self.tasks.push(
                                    Task { kind: BusTask::SDHC(SDHCTask::SendBufWriteReady), target_cycle: self.cycle + 10000 }
                                );
                            }
                            else if self.sd0.tx_complete() {
                                self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                            }
                        }
                        else {
                            self.tasks.push(
                                Task { kind: BusTask::SDHC(SDHCTask::IOPoll), target_cycle: self.cycle+10000 }
                            );
                        }
                    }
                }
            },
        }
    }
}

pub trait SDHCDevice: Sized {
    fn try_new() -> (Self, bool);
    /// Issue a command to the emulated SD device.
    fn issue(&mut self, cmd: Command, argument: u32) -> Option<Response>;
    fn tx_status(&self) -> DeviceTXStatus;
    fn set_tx_status(&mut self, new: DeviceTXStatus);
    fn _state(&self) -> CardState;
    fn set_state(&mut self, new: CardState);
    fn data_index(&self) -> usize;
    fn set_data_index(&self, new: usize);
    fn data_stop(&self) -> usize;
    fn set_data_stop(&mut self, new: usize);
    fn lock_data(&self) -> parking_lot::MutexGuard<BigEndianMemory>;
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Card States as defined in Part 1
pub enum CardState {
    Idle,
    Ready,
    Ident,
    Stby,
    Trans,
    Data,
    Rcv,
    Prg,
    Dis,
    Ina,
}

impl Default for CardState {
    fn default() -> Self {
        Self::Idle
    }
}

impl CardState {
    // Part1 simplified version 2 - Table 4-35
    fn bits_for_card_status(&self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::Ready => 1,
            Self::Ident => 2,
            Self::Stby => 3,
            Self::Trans => 4,
            Self::Data => 5,
            Self::Rcv => 6,
            Self::Prg => 7,
            Self::Dis => 8,
            Self::Ina => panic!(),
            // 9-14 reserved
            // 15 reserved for io mode
        }
    }
}

#[derive(Debug, Clone)]
pub struct Command {
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