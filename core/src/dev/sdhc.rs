#![allow(clippy::needless_return, clippy::zero_prefixed_literal)]
mod card;
mod device;
mod sdio;

use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::bail;
use log::{trace, debug, warn, error};

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;
use crate::bus::Bus;
use super::hlwd::irq::HollywoodIrq;
use card::Card;
use device::{CmdRes, Response, SdDevice, TxDir};
use sdio::WiFi4318;

const BLOCK_LEN: usize = 512;
const IO_POLL_INTERVAL: usize = 10000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdhcSlot {
    /// Front SD Slot
    Sd0,
    /// WiFi card slot
    Sd1,
}

impl SdhcSlot {
    fn irq(self) -> HollywoodIrq {
        match self {
            Self::Sd0 => HollywoodIrq::Sdhc,
            Self::Sd1 => HollywoodIrq::Wifi,
        }
    }

    pub(crate) const fn log_target(self) -> &'static str {
        match self {
            Self::Sd0 => "SDHC::sd0",
            Self::Sd1 => "SDHC::sd1",
        }
    }
}

#[derive(Debug)]
pub enum SDHCTask {
    RaiseInt,
    SendBufferReady(TxDir),
    IOPoll,
    DoDma(TxDir),
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
    /// Writes are always 32 bit, but some registers are smaller than that
    /// So we need to shift and mask the old value with the new value to determine which registers are affected
    ///
    /// Returns Vec as up to 4 8 bit registers could be updated in a single shot, but this is unlikely to happen in practice
    /// Most Host Drivers only write to a single register at a time.
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
    /// These registers have RW1C bits or additional logic that must run on any write, even if the register is ultimiately unchanged
    fn must_always_handle_writes(&self) -> bool {
        matches!(self,
            SDRegisters::BufferDataPort |
            SDRegisters::Command |
            SDRegisters::NormalIntStatus |
            SDRegisters::ErrorIntStatus |
            SDRegisters::SystemAddress
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferState {
    Idle,
    Pending(TxDir),
    Pio(TxDir),
    Dma(TxDir),
}

#[repr(C, align(64))]
pub struct SDInterface {
    register_file: [u8; 256],
    slot: SdhcSlot,
    pending_interrupt_flags: u32,
    insert_raised: bool,
    first_ack: bool,
    tx: TransferState,
    block_bytes_left: AtomicU32,
    device: SdDevice,
}

impl SDInterface {
    pub fn new_sd0() -> Self {
        Self::new(SdhcSlot::Sd0, SdDevice::Card(Card::new()))
    }

    pub fn new_sd1() -> Self {
        Self::new(SdhcSlot::Sd1, SdDevice::Sdio(WiFi4318::new()))
    }

    fn new(slot: SdhcSlot, device: SdDevice) -> Self {
        let mut new = Self {
            register_file: [0; 256],
            slot,
            pending_interrupt_flags: 0,
            insert_raised: false,
            first_ack: false,
            tx: TransferState::Idle,
            block_bytes_left: AtomicU32::new(0),
            device,
        };
        new.init_hwinit_regs();
        debug!(target: slot.log_target(), "SD Interface Initialized");
        new
    }

    fn init_hwinit_regs(&mut self) {
        // Capabilities Register
        const VOLTAGE_SUPPORT_3_3V: u32 = 1 << 24;
        const SD_BASE_CLK_10MHZ: u32 = 10 << 8;
        const DMA_SUPPORT: u32 = 1 << 22;
        self.raw_write(SDRegisters::Capabilities.base_offset(), VOLTAGE_SUPPORT_3_3V | SD_BASE_CLK_10MHZ | DMA_SUPPORT);
        // Maximum Current Capabilities Register
        const CURRENT_CAP_3_3V_MAX: u32 = 0xff;
        self.raw_write(SDRegisters::MaxCurrentCapabilities.base_offset(), CURRENT_CAP_3_3V_MAX);
    }
}

impl SDInterface {
    fn run_write_handler(&mut self, reg: SDRegisters, old: u32, new: u32) -> Option<SDHCTask> {
        let shift: usize;
        let mask: u32;
        if reg.bytecount_of_reg() >= 4 {
            shift = 0;
            mask = 0xffff_ffff;
        }
        else {
            // Calculate shift to move the register in question to the right most position
            shift = (reg.base_offset() & 0x3) * 8;
            mask = (1 << (reg.bytecount_of_reg() * 8)) - 1;
        }
        let old = (old >> shift) & mask;
        let mut new = (new >> shift) & mask;
        debug!(target: self.slot.log_target(), "write handler for {reg:?} {old:x} {new:x}");
        match reg {
            SDRegisters::Command => {
                let cmd = device::Command::from(new);
                debug!(target: self.slot.log_target(), "Command {cmd:?}");
                let arg = self.raw_read(SDRegisters::Argument.base_offset());
                let CmdRes { response, transfer } = self.device.command(cmd, arg);
                if let Some(response) = response {
                    self.apply_response(response);
                }
                if let Some(dir) = transfer {
                    self.tx = TransferState::Pending(dir);
                }
                if self.cmd_complete() {
                    return Some(SDHCTask::RaiseInt);
                }
            }
            SDRegisters::NormalIntStatus => {
                const RW1C_MASK: u32 = 0x1ff; // mask of the bits that are rw1c, all others are reserved or ROC.
                let clearbits = (old & RW1C_MASK) ^ (new & RW1C_MASK);
                let int_new = (old & !RW1C_MASK) | clearbits;
                debug!(target: self.slot.log_target(), "normalintstatus {old:b} {int_new:b}");
                self.setreg(reg, int_new);
                // The host driver will write here to acknowledge a CMD complete
                // If there is a pending transfer that's supposed to be associated with that command
                // This is the time to kick it off.
                if new & 1 == 1 && let TransferState::Pending(dir) = self.tx {
                    let use_dma = self.raw_read(SDRegisters::TxMode.base_offset()) & 0x1 == 1;
                    if use_dma {
                        self.tx = TransferState::Dma(dir);
                        return Some(SDHCTask::DoDma(dir));
                    }
                    self.tx = TransferState::Pio(dir);
                    return Some(SDHCTask::SendBufferReady(dir));
                }
            },
            SDRegisters::ErrorIntStatus => {
                const RW1C_MASK: u32 = 0xf1ff; // mask of the bits that are rw1c, all others are reserved or ROC.
                let clearbits = (old & RW1C_MASK) ^ (new & RW1C_MASK);
                let new = (old & !RW1C_MASK) | clearbits;
                self.setreg(reg, new);
            },
            SDRegisters::NormalIntSignalEnable | SDRegisters::NormalIntStatusEnable => {
                debug!(target: self.slot.log_target(), "{reg:?} {new:b}");
                self.setreg(reg, new);
                if self.do_pending_ints() || self.insert_card() || self.first_ack() {
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
                self.setreg(reg, new);
            },
            SDRegisters::SoftwareReset => {
                if new & 0b001 != 0 {
                    self.reset_all();
                }
                else {
                    if new & 0b010 != 0 {
                        self.reset_cmd_line();
                    }
                    if new & 0b100 != 0 {
                        self.reset_dat_line();
                    }
                }
            },
            SDRegisters::BufferDataPort => {
                if self.tx != TransferState::Pio(TxDir::Write) {
                    error!(target: self.slot.log_target(), "Software wrote to the BufferDataPort but there is no non-DMA write transaction.");
                    // intentionally drop the write here
                }
                else if self.take_pio_word().is_none() {
                    // The driver overran the block; drop the write.
                    error!(target: self.slot.log_target(), "Software wrote past the end of the current block.");
                }
                else if let Err(e) = self.device.write_data(&new.to_be_bytes()) {
                    error!(target: self.slot.log_target(), "BufferDataPort write failed: {e:#}");
                }
            },
            SDRegisters::SystemAddress => {
                self.setreg(reg, new);
                if old & 0xff00_0000 != new & 0xff00_0000
                    && let TransferState::Dma(dir) = self.tx {
                    return Some(SDHCTask::DoDma(dir));
                }
            }
            SDRegisters::HostControl |
            SDRegisters::TxMode |
            SDRegisters::BlockCount |
            SDRegisters::BlockSize |
            SDRegisters::Argument |
            SDRegisters::ErrorIntStatusEnable |
            SDRegisters::ErrorIntSignalEnable |
            SDRegisters::TimeoutControl |
            SDRegisters::PowerControl => {
                // No special handling needed for these registers
                self.setreg(reg, new);
            },
            other => {
                warn!(target: self.slot.log_target(), "Unhandled write to register: {other:?}");
                self.setreg(other, new);
            }
        }
        None
    }
    fn apply_response(&mut self, response: Response) {
        match response {
            Response::Regular(r) => {
                self.raw_write(SDRegisters::Response.base_offset(), r);
            },
            Response::R2(r) => {
                self.raw_write(SDRegisters::Response.base_offset(),      ((r >> 00) & 0xffff_ffff) as u32);
                self.raw_write(SDRegisters::Response.base_offset() + 04, ((r >> 32) & 0xffff_ffff) as u32);
                self.raw_write(SDRegisters::Response.base_offset() + 08, ((r >> 64) & 0xffff_ffff) as u32);
                self.raw_write(SDRegisters::Response.base_offset() + 12, ((r >> 96) & 0xffff_ffff) as u32);
            }
        }
    }
}

impl SDInterface {
    fn raw_read(&self, off: usize) -> u32 {
        let p = (&self.register_file) as *const [u8;256] as *const u32;
        assert!(off & 0xffff_fffc == off); // alignment
        let off = off >> 2;
        assert!(off < 64); //length
        let ret = unsafe { *(p.add(off)) };
        trace!(target: self.slot.log_target(), "raw_read 0x{:x} = 0x{ret:x}", off << 2);
        ret
    }
    fn raw_write(&mut self, off: usize, val: u32) {
        let p = (&mut self.register_file) as *mut [u8;256] as *mut u32;
        assert!(off & 0xffff_fffc == off); // alignment
        let off = off >> 2;
        assert!(off < 64); //length
        unsafe { *(p.add(off)) = val; };
        trace!(target: self.slot.log_target(), "raw_write 0x{:x} = 0x{val:x}", off << 2);
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
    fn reset_all(&mut self) {
        debug!(target: self.slot.log_target(), "SD interface software reset for ALL");
        let card_detection_circuit_status = self.raw_read(SDRegisters::PresentState.base_offset()) & 0x70000;
        self.register_file = [0; 256];
        self.pending_interrupt_flags = 0;
        self.first_ack = false;
        self.block_bytes_left.store(0, Ordering::Relaxed);
        self.init_hwinit_regs();
        self.raw_write(SDRegisters::PresentState.base_offset(), card_detection_circuit_status);
        self.abort_transfer();
    }
    fn abort_transfer(&mut self) {
        if self.tx != TransferState::Idle {
            self.tx = TransferState::Idle;
            self.block_bytes_left.store(0, Ordering::Relaxed);
            self.device.end_transfer(true);
        }
    }
    fn reset_cmd_line(&mut self) {
        debug!(target: self.slot.log_target(), "SD interface software reset for CMD line");
        // Clear the following bits in Present State Register
        // - Command Inhibit (CMD) bit 0
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        const PS_CMD_RESET: u32 = 0x1;
        self.setreg(SDRegisters::PresentState, ps & !PS_CMD_RESET);
        // Clear the following bits in Normal Interrupt Status Register
        // - Command Complete bit 0
        let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset()) & 0x0000_ffff;
        const NISR_CMD_RESET: u32 = 0x1;
        self.setreg(SDRegisters::NormalIntStatus, nisr & !NISR_CMD_RESET);
        // In case any of these got stashed, clear from pending interrupts as well
        self.pending_interrupt_flags &= !NISR_CMD_RESET;
    }
    fn reset_dat_line(&mut self) {
        debug!(target: self.slot.log_target(), "SD interface software reset for DAT line");
        // Clear & init Buffer Data Port
        self.setreg(SDRegisters::BufferDataPort, 0);
        // Clear the following bits in Present State Register
        // - Buffer Read Enable     bit 11
        // - Buffer Write Enable    bit 10
        // - Read Transfer Active   bit  9
        // - Write Transfer Active  bit  8
        // - DAT Line Active        bit  2
        // - Command Inhibit (DAT)  bit  1
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        const PS_DAT_RESET: u32 = 0xF06;
        self.setreg(SDRegisters::PresentState, ps & !PS_DAT_RESET);
        // Clear the following bits in Block Gap Control Register
        // - Continue Request          bit 1
        // - Stop at Block Gap Request bit 0
        let bgcr = (self.raw_read(SDRegisters::BlockGapControl.base_offset() & 0xffff_fffc) & 0x00ff_0000) >> 16;
        const BG_DAT_RESET: u32 = 0x3;
        self.setreg(SDRegisters::BlockGapControl, bgcr & !BG_DAT_RESET);
        // Clear the following bits in Normal Interrupt Status Register
        // - Buffer Read Ready  bit 5
        // - Buffer Write Ready bit 4
        // - DMA Interrupt      bit 3
        // - Block Gap Event    bit 2
        // - Transfer complete  bit 1
        let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset()) & 0x0000_ffff;
        const NISR_DAT_RESET: u32 = 0x3E;
        self.setreg(SDRegisters::NormalIntStatus, nisr & !NISR_DAT_RESET);
        // In case any of these got stashed, clear from pending interrupts as well
        self.pending_interrupt_flags &= !NISR_DAT_RESET;
        // Spec tells us to "Reset DMA circuit" as well.
        // Not really sure what that means *exactly*, but we will clear any transactions in progress with the card
        // This may cause errors to be logged to the console, but shouldn't be a big deal otherwise.
        self.abort_transfer();
    }
    fn insert_card(&mut self) -> bool {
        if self.insert_raised || !self.device.present() {
            return false;
        }
        let current_state = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, current_state | (1<<16) | (1<<17) | (1 << 18)); // card inserted
        self.insert_raised = true;
        const INSERT_INT_MASK: u32 = 1 << 6;
        return self.raise_int(INSERT_INT_MASK);
    }
    fn first_ack(&mut self) -> bool {
        if self.first_ack || !self.device.present() {
            return false;
        }
        self.first_ack = true;
        debug!(target: self.slot.log_target(), "Sending inital ack for card setup");
        const CMD_COMPLETE_MASK: u32 = 1;
        return self.raise_int(CMD_COMPLETE_MASK);
    }
    fn cmd_complete(&mut self) -> bool {
        debug!(target: self.slot.log_target(), "CMD complete int");
        const CMD_COMPLETE_MASK: u32 = 1;
        return self.raise_int(CMD_COMPLETE_MASK);
    }
    fn blocks_remaining(&self) -> u32 {
        self.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16
    }
    fn take_pio_word(&self) -> Option<()> {
        let left = self.block_bytes_left.load(Ordering::Relaxed);
        let remaining = left.checked_sub(4)?;
        self.block_bytes_left.store(remaining, Ordering::Relaxed);
        Some(())
    }
    fn buffer_ready(&mut self, dir: TxDir) -> bool {
        let blocks_remaining = self.blocks_remaining();
        if blocks_remaining == 0 {
            return false;
        }
        self.block_bytes_left.store(BLOCK_LEN as u32, Ordering::Relaxed);
        self.setreg(SDRegisters::BlockCount, blocks_remaining - 1);
        trace!(target: self.slot.log_target(), "Buffer Ready {dir:?}");
        // Present State: Buffer Enable & Transfer Active for this direction, plus
        // Command Inhibit (DAT) (1)
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, ps | Self::ps_transfer_bits(dir, false) | 1 << 1);
        // Set Buffer Read/Write Ready Int
        let int = match dir {
            TxDir::Read => 1 << 5,
            TxDir::Write => 1 << 4,
        };
        return self.raise_int(int);
    }
    fn ps_transfer_bits(dir: TxDir, is_dma: bool) -> u32 {
        let (buffer_enable, transfer_active) = match dir {
            //         Buffer Read Enable, Read Transfer Active
            TxDir::Read => (1 << 11, 1 << 9),
            //         Buffer Write Enable, Write Transfer Active
            TxDir::Write => (1 << 10, 1 << 8),
        };
        if is_dma { transfer_active } else { buffer_enable | transfer_active }
    }
    fn tx_complete(&mut self) -> bool {
        debug!(target: self.slot.log_target(), "Tx Complete");
        let (dir, is_dma) = match self.tx {
            TransferState::Idle | TransferState::Pending(_) => {
                error!(target: self.slot.log_target(), "Requested Tx complete but no transfer is active.");
                return false;
            },
            TransferState::Pio(dir) => (dir, false),
            TransferState::Dma(dir) => (dir, true),
        };
        // Clear Block Count Register
        self.setreg(SDRegisters::BlockCount, 0);
        // Clear this transfer's Present State bits & CMD Inhibit (DAT)
        let kill_mask = Self::ps_transfer_bits(dir, is_dma) | 1 << 1;
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, ps & !kill_mask);
        self.tx = TransferState::Idle;
        self.block_bytes_left.store(0, Ordering::Relaxed);
        self.device.end_transfer(false);
        const TRANSFER_COMPLETE_MASK: u32 = 1 << 1;
        return self.raise_int(TRANSFER_COMPLETE_MASK);
    }
    fn dma_int(&mut self) -> bool {
        const DMA_INT: u32 = 1 << 3;
        if !matches!(self.tx, TransferState::Dma(_)) {
            error!(target: self.slot.log_target(), "Asked for a DMA Interrupt but no DMA transfer is in progress");
            return false;
        }
        return self.raise_int(DMA_INT);
    }
}

impl MmioDevice for SDInterface {
    type Width = u32;

    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        trace!(target: self.slot.log_target(), "MMIO read: 0x{off:x}");
        if off == SDRegisters::BufferDataPort.base_offset() {
            return self.read_buffer_data_port();
        }
        Ok(BusPacket::Word(self.raw_read(off)))
    }

    fn write(&mut self, off: usize, val: Self::Width) -> anyhow::Result<Option<BusTask>> {
        debug!(target: self.slot.log_target(), "MMIO write: 0x{off:x} = 0x{val:x}");
        let old = self.raw_read(off);
        let regs = SDRegisters::get_affected_registers(off, old, val);
        debug!(target: self.slot.log_target(), "affected registers: {:?}", &regs);
        let mut send_task = None;
        for reg in regs {
            if let Some(task) = self.run_write_handler(reg, old, val) {
                if send_task.is_none() {
                    send_task = Some(BusTask::SDHC(self.slot, task));
                }
                else {
                    error!(target: self.slot.log_target(), "Multiple SDHC Tasks returned from a single write. This is not supported.");
                }
            }
        }
        return Ok(send_task);
    }
}

impl SDInterface {
    fn read_buffer_data_port(&self) -> anyhow::Result<BusPacket> {
        if self.tx != TransferState::Pio(TxDir::Read) {
            error!(target: self.slot.log_target(), "Software tried reading the BufferDataPort but there is no non-DMA read transaction.");
            return Ok(BusPacket::Word(self.raw_read(SDRegisters::BufferDataPort.base_offset())));
        }
        if self.take_pio_word().is_none() {
            bail!("SDHC read past the end of the current block");
        }
        let mut buf = [0u8; 4];
        self.device.read_data(&mut buf)?;
        Ok(BusPacket::Word(u32::from_be_bytes(buf)))
    }
}

impl Bus {
    fn sdhc(&mut self, slot: SdhcSlot) -> &mut SDInterface {
        match slot {
            SdhcSlot::Sd0 => &mut self.sd0,
            SdhcSlot::Sd1 => &mut self.sd1,
        }
    }
    fn sdhc_schedule(&mut self, slot: SdhcSlot, task: SDHCTask) {
        self.tasks.push(Task {
            kind: BusTask::SDHC(slot, task),
            target_cycle: self.cycle + IO_POLL_INTERVAL,
        });
    }
    pub(crate) fn handle_task_sdhc(&mut self, slot: SdhcSlot, task: SDHCTask) {
        let irq = slot.irq();
        let log = slot.log_target();
        match task {
            SDHCTask::RaiseInt => {
                debug!(target: log, "Raising SDHC interrupt.");
                self.hlwd.irq.assert(irq);
            },
            SDHCTask::SendBufferReady(dir) => {
                if !self.sdhc(slot).buffer_ready(dir) {
                    unimplemented!("SDHC could not open the next {dir:?} block");
                }
                self.sdhc_schedule(slot, SDHCTask::IOPoll);
                self.hlwd.irq.assert(irq);
            },
            SDHCTask::DoDma(dir) => { // carefulling in progress
                let sysaddr = self.sdhc(slot).raw_read(SDRegisters::SystemAddress.base_offset());
                let buff_boundry = 0x1000u32 << ((self.sdhc(slot).raw_read(SDRegisters::BlockSize.base_offset()) & 0x7000) >> 12);
                let stop_addr = match sysaddr.checked_add(buff_boundry) { // mini always sets 512k boundry size, even if that would overrun the address space
                    Some(x) => (x + 1) & !(buff_boundry - 1),
                    None => u32::MAX,
                };
                let mut block_count = self.sdhc(slot).blocks_remaining();
                let mut current_addr = sysaddr;
                debug!(target: log, "Starting DMA {dir:?} Tx at sysaddr: {sysaddr:x}");
                let block_len = BLOCK_LEN as u32;
                let mut buf = vec![0u8; BLOCK_LEN];
                while current_addr + block_len < stop_addr && block_count > 0 {
                    match dir {
                        TxDir::Read => {
                            self.sdhc(slot).device.read_data(&mut buf).unwrap();
                            self.dma_write(current_addr, &buf).unwrap();
                        },
                        TxDir::Write => {
                            self.dma_read(current_addr, &mut buf).unwrap();
                            self.sdhc(slot).device.write_data(&buf).unwrap();
                        },
                    }
                    block_count -= 1;
                    current_addr += block_len;
                }
                let send_dma_int = current_addr >= stop_addr;
                let send_tx_complete = block_count == 0;
                debug!(target: log, "DMA Transfer completed after {} blocks. Reached DMA Boundry: {send_dma_int}. Reached Block Count: {send_tx_complete}", (current_addr-sysaddr) / block_len);
                self.sdhc(slot).setreg(SDRegisters::BlockCount, block_count);
                self.sdhc(slot).setreg(SDRegisters::SystemAddress, current_addr);
                if send_tx_complete { // TX Complete has higher priority than DMA complete. Never send both!
                    if self.sdhc(slot).tx_complete() {
                        self.hlwd.irq.assert(irq);
                    }
                }
                else if send_dma_int {
                    // Paused at a DMA buffer boundary; the driver resumes us by
                    // writing the next System Address.
                    if self.sdhc(slot).dma_int() {
                        self.hlwd.irq.assert(irq);
                    }
                }
                else {
                    unreachable!("SDHC DMA Logic Error");
                }
            },
            SDHCTask::IOPoll => {
                let left = self.sdhc(slot).block_bytes_left.load(Ordering::Relaxed);
                trace!(target: log, "SDHC IOPOLL: {left} bytes left in block");
                let dir = match self.sdhc(slot).tx {
                    TransferState::Idle | TransferState::Pending(_) => return,
                    TransferState::Dma(_) => {
                        error!(target: log, "Improper state for SDHC IOPOLLing.");
                        return;
                    },
                    TransferState::Pio(dir) => dir,
                };
                if left > 0 {
                    self.sdhc_schedule(slot, SDHCTask::IOPoll);
                }
                else if self.sdhc(slot).blocks_remaining() > 0 {
                    self.sdhc_schedule(slot, SDHCTask::SendBufferReady(dir));
                }
                else if self.sdhc(slot).tx_complete() {
                    self.hlwd.irq.assert(irq);
                }
            },
        }
    }
}
