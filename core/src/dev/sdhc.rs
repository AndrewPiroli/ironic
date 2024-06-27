pub(crate) mod card;

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
use card::*;

#[derive(Debug)]
pub enum SDHCTask {
    RaiseInt,
    SendBufReadReady,
    SendBufWriteReady,
    IOPoll,
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
        match self {
            SDRegisters::BufferDataPort |
            SDRegisters::Command |
            SDRegisters::NormalIntStatus |
            SDRegisters::ErrorIntStatus => true,
            _ => false,
        }
    }
    fn run_write_handler(&self, iface: &mut NewSDInterface, old: u32, new: u32) -> Option<SDHCTask> {
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
                let x = card::Command::from(new);
                if log_enabled!(target: "SDHC", log::Level::Debug) {
                    dbg!(&x);
                }
                // let cmd = x.index;
                if let Some(response) = iface.card.issue(x, iface.raw_read(SDRegisters::Argument.base_offset())){
                    self.apply_response(iface, response);
                }
                if let Some(task) = iface.cmd_complete() {
                    return Some(task);
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
                match iface.card.tx_status {
                    CardTXStatus::MultiReadPending => { // Multi Block Read
                        if new & 1 == 1 {
                            iface.card.tx_status = CardTXStatus::MultiReadInProgress;
                            return Some(SDHCTask::SendBufReadReady);
                        }
                    },
                    CardTXStatus::MultiWritePending => {
                        if new & 1 == 1 {
                            iface.card.tx_status = CardTXStatus::MultiWriteInProgress;
                            return Some(SDHCTask::SendBufWriteReady);
                        }
                    },
                    CardTXStatus::None | CardTXStatus::MultiReadInProgress | CardTXStatus::MultiWriteInProgress => { // No action taken here
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
                debug!(target:"SDHC", "Normal Int Signal Enable {new:b}");
                iface.setreg(*self, new);
                if let Some(do_insert_int) = iface.insert_card() {
                    return Some(do_insert_int);
                }
                if let Some(first_ack) = iface.first_ack() {
                    return Some(first_ack);
                }
            },
            SDRegisters::NormalIntStatusEnable => {
                debug!(target: "SDHC", "Normal Int Status Enable {new:b}");
                iface.setreg(*self, new);
                if let Some(do_insert_int) = iface.insert_card() {
                    return Some(do_insert_int);
                }
                if let Some(first_ack) = iface.first_ack() {
                    return Some(first_ack);
                }
            },
            SDRegisters::ClockControl => {
                // set internal clock stable (bit 1) based on internal clock enable (bit 0)
                match new & 0b1 {
                    0b0 => {
                        new = new & 0xffff_fffc;
                    }
                    0b1 => {
                        new = new | 0b10;
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
                match iface.card.tx_status {
                    CardTXStatus::None |
                    CardTXStatus::MultiReadPending |
                    CardTXStatus::MultiReadInProgress |
                    CardTXStatus::MultiWritePending => {
                        panic!()
                    }
                    CardTXStatus::MultiWriteInProgress => {
                        let index = iface.card.rw_index.load(std::sync::atomic::Ordering::Relaxed);
                        {
                            let mut v = iface.card.backing_mem.lock();
                            if v.data.len() < index+4 || index+4 > iface.card.rw_stop {
                                // return Err(anyhow!("out of range! {index:?} {:?} {} ", v.data.len(), iface.card.rw_stop));
                                return None;
                            }
                            iface.card.rw_index.store(index+4, std::sync::atomic::Ordering::Relaxed);
                            v.write(index, new).unwrap();
                            //println!("{index:08x} {ret:08x}");
                            //return Ok(BusPacket::Word(ret));
                        }
                    },
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
    fn apply_response(&self, iface: &mut NewSDInterface, response: Response) {
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
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardTXStatus {
    None,
    MultiReadPending,
    MultiReadInProgress,
    MultiWritePending,
    MultiWriteInProgress,
}

impl Default for CardTXStatus {
    fn default() -> Self {
        Self::None
    }
}

#[repr(C, align(64))]
pub struct NewSDInterface {
    register_file: [u8; 256],
    insert_raised: bool,
    first_ack: bool,
    card: Card,
    card_available: bool,
    tx_status: CardTXStatus,
}

impl NewSDInterface {
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
    fn reset(&mut self) {
        debug!(target: "SDHC", "SD interface software reset");
        let mut new = Self::default();
        let card_detection_circuit_status = self.raw_read(SDRegisters::PresentState.base_offset()) & 0x70000;
        new.raw_write(SDRegisters::PresentState.base_offset(), card_detection_circuit_status);
        new.insert_raised = self.insert_raised;
        *self = new;
    }
    fn insert_card(&mut self) -> Option<SDHCTask> {
        if self.insert_raised || !self.card_available {
            return None;
        }
        let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
        let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
        const INSERT_INT_MASK: u32 = 1 << 6;
        if signal & INSERT_INT_MASK != 0 && status & INSERT_INT_MASK != 0 {
            let current_state = self.raw_read(SDRegisters::PresentState.base_offset());
            self.setreg(SDRegisters::PresentState, current_state | (1<<16) | (1<<17) | (1 << 18)); // card inserted
            let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
            let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
            self.setreg(SDRegisters::NormalIntStatus, nisr | 0x1); // command complete
            self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
            self.insert_raised = true;
            return Some(SDHCTask::RaiseInt);
        }
        None
    }
    fn first_ack(&mut self) -> Option<SDHCTask> {
        if self.first_ack {
            return None;
        }
        let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
        let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
        const CMD_COMPLETE_MASK: u32 = 1;
        if signal & CMD_COMPLETE_MASK != 0 && status & CMD_COMPLETE_MASK != 0 {
            let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
            let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
            self.setreg(SDRegisters::NormalIntStatus, nisr | 0x1); // command complete
            self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
            self.first_ack = true;
            debug!(target: "SDHC", "Sending inital ack for card setup");
            return Some(SDHCTask::RaiseInt);
        }
        None
    }
    fn cmd_complete(&mut self) -> Option<SDHCTask> {
        let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
        let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
        const CMD_COMPLETE_MASK: u32 = 1;
        if signal & CMD_COMPLETE_MASK != 0 && status & CMD_COMPLETE_MASK != 0 {
            let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
            let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
            self.setreg(SDRegisters::NormalIntStatus, nisr | 0x1); // command complete
            self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
            debug!(target: "SDHC", "CMD complete int");
            return Some(SDHCTask::RaiseInt);
        }
        None
    }
    fn buffer_ready_read(&mut self) -> bool {
        // 25
        let blocks_remaining = self.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16; // p83
        if blocks_remaining > 0 {
            // tell card it's rw_stop
            self.card.rw_stop = self.card.rw_index.load(std::sync::atomic::Ordering::Relaxed) + 512;
            self.setreg(SDRegisters::BlockCount, blocks_remaining.saturating_sub(1));
        }
        else {
            error!("asdf");
            return false;
        }
        error!(target: "SDHC", "buffer read ready");
        // Present State Buffer Read Enable (11) & Read Tx Active (9) & Command Inhibit (DAT) (1)
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, ps | 1<<11 | 1<<9| 1 << 1);
        // Set Buffer Read Ready Int
        let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
        let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
        const BUFFER_READ_READY_MASK: u32 = 1 << 5;
        if signal & BUFFER_READ_READY_MASK != 0 && status & BUFFER_READ_READY_MASK != 0 {
            let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
            let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
            self.setreg(SDRegisters::NormalIntStatus, nisr | BUFFER_READ_READY_MASK);
            self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
        }
        else {
            error!("fdsfasd");
            return false;
        }
        true
    }
    fn buffer_ready_write(&mut self) -> bool {
        let blocks_remaining = self.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16; // p83
        if blocks_remaining > 0 {
            // tell card it's rw_stop
            self.card.rw_stop = self.card.rw_index.load(std::sync::atomic::Ordering::Relaxed) + 512;
            self.setreg(SDRegisters::BlockCount, blocks_remaining.saturating_sub(1));
        }
        else {
            error!("asdf");
            return false;
        }
        error!(target: "SDHC", "buffer write ready");
        // Present State Buffer Write Enable (11) & Write Tx Active (9) & Command Inhibit (DAT) (1)
        let ps = self.raw_read(SDRegisters::PresentState.base_offset());
        self.setreg(SDRegisters::PresentState, ps | 1<<10 | 1<<8 | 1 << 1);
        // Set Buffer Write Ready Int
        let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
        let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
        const BUFFER_WRITE_READY_MASK: u32 = 1 << 4;
        if signal & BUFFER_WRITE_READY_MASK != 0 && status & BUFFER_WRITE_READY_MASK != 0 {
            let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
            let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
            self.setreg(SDRegisters::NormalIntStatus, nisr | BUFFER_WRITE_READY_MASK);
            self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
        }
        else {
            error!("fdsfasd");
            return false;
        }
        true
    }
    fn tx_complete(&mut self) {
        debug!(target: "SDHC", "Tx Complete");
        match self.card.tx_status {
            CardTXStatus::None |
            CardTXStatus::MultiReadPending |
            CardTXStatus::MultiWritePending |
            CardTXStatus::MultiWriteInProgress => {
                // Clear Block Count Register
                self.setreg(SDRegisters::BlockCount, 0);
                // clear PS Buffer write enable & Write Tx Active & CMD Inhibit (DAT)
                let ps = self.raw_read(SDRegisters::PresentState.base_offset());
                const KILL_MASK: u32 = !(1<<10 | 1<<8 | 1 << 1);
                self.setreg(SDRegisters::PresentState, ps & KILL_MASK);
                let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
                let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
                const TRANSFER_COMPLETE_MASK: u32 = 1 << 1;
                if signal & TRANSFER_COMPLETE_MASK != 0 && status & TRANSFER_COMPLETE_MASK != 0 {
                    let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
                    let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
                    self.setreg(SDRegisters::NormalIntStatus, nisr | TRANSFER_COMPLETE_MASK);
                    self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
                }
                self.card.tx_status = CardTXStatus::None;
                self.card.state = CardState::Trans;
            },
            CardTXStatus::MultiReadInProgress => {
                // Clear Block Count Register
                self.setreg(SDRegisters::BlockCount, 0);
                // clear PS Buffer read enable & Read Tx Active & CMD Inhibit (DAT)
                let ps = self.raw_read(SDRegisters::PresentState.base_offset());
                const KILL_MASK: u32 = !(1<<11 | 1<<9 | 1 << 1);
                self.setreg(SDRegisters::PresentState, ps & KILL_MASK);
                let signal = self.raw_read(SDRegisters::NormalIntSignalEnable.base_offset());
                let status = self.raw_read(SDRegisters::NormalIntStatusEnable.base_offset());
                const TRANSFER_COMPLETE_MASK: u32 = 1 << 1;
                if signal & TRANSFER_COMPLETE_MASK != 0 && status & TRANSFER_COMPLETE_MASK != 0 {
                    let nisr = self.raw_read(SDRegisters::NormalIntStatus.base_offset());
                    let sisr = self.raw_read(SDRegisters::SlotIntStatus.base_offset()) & 0xffff;
                    self.setreg(SDRegisters::NormalIntStatus, nisr | TRANSFER_COMPLETE_MASK);
                    self.setreg(SDRegisters::SlotIntStatus, sisr | 0x1); // slot 1
                }
                self.card.tx_status = CardTXStatus::None;
                self.card.state = CardState::Trans;
            },
        }
    }
}

impl Default for NewSDInterface {
    fn default() -> Self {
        let (card, card_available) = Card::try_new();
        let mut new = Self { register_file: [0;256], insert_raised: false, first_ack: false, card, card_available, tx_status: CardTXStatus::None };
        // Fill HWInit registers
        // Advertise 3.3v support in Capabilities Register
        // Advertise 10Mhz base clock
        new.raw_write(SDRegisters::Capabilities.base_offset(), 1 << 24 | (10 <<8));
        // Advertise the maximum current capability for 3.3v
        new.raw_write(SDRegisters::MaxCurrentCapabilities.base_offset(), 0xff);
        // End HWInit Registers
        debug!(target: "SDHC", "init sdhc");
        new
    }
}

impl MmioDevice for NewSDInterface {
    type Width = u32;

    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        trace!(target: "SDHC", "MMIO read: 0x{off:x}");
        if off == SDRegisters::BufferDataPort.base_offset() {
            match self.card.tx_status {
                CardTXStatus::None |
                CardTXStatus::MultiReadPending |
                CardTXStatus::MultiWritePending  => {},
                CardTXStatus::MultiWriteInProgress => { panic!(); }
                CardTXStatus::MultiReadInProgress => {
                    let index = self.card.rw_index.load(std::sync::atomic::Ordering::Relaxed);
                    {
                        let v = self.card.backing_mem.lock();
                        if v.data.len() < index+4 || index+4 > self.card.rw_stop {
                            return Err(anyhow!("out of range! {index:?} {:?} {} ", v.data.len(), self.card.rw_stop));
                        }
                        self.card.rw_index.store(index+4, std::sync::atomic::Ordering::Relaxed);
                        let ret: u32 = v.read(index).unwrap();
                        //println!("{index:08x} {ret:08x}");
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

#[derive(Default)]
pub struct WLANInterface {
    pub unk_24: u32,
    pub unk_40: u32,
    pub unk_fc: u32,
}

impl MmioDevice for WLANInterface {
    type Width = u32;
    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x24 => self.unk_24,
            //0x24 => 0x0001_0000, //self.unk_24,
            //0x40 => 0x0040_0000, //self.unk_24,
            //0xfc => self.unk_fc,
            _ => { bail!("SDHC1 read at {off:x} unimpl"); },
        };
        Ok(BusPacket::Word(val))
    }
    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        bail!("SDHC1 write {val:08x} at {off:x} unimpl")
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
            }
            SDHCTask::IOPoll => {
                let rw_index = self.sd0.card.rw_index.load(std::sync::atomic::Ordering::Relaxed);
                trace!(target: "SDHC", "SDHC IOPOLL {} {}", rw_index, self.sd0.card.rw_stop);
                match self.sd0.card.tx_status {
                    CardTXStatus::None |
                    CardTXStatus::MultiReadPending |
                    CardTXStatus::MultiWritePending => {},
                    CardTXStatus::MultiReadInProgress => {
                        if rw_index >= self.sd0.card.rw_stop {
                            let blocks_remain = self.sd0.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16;
                            if blocks_remain > 0 {
                                self.tasks.push(
                                    Task { kind: BusTask::SDHC(SDHCTask::SendBufReadReady), target_cycle: self.cycle + 10000 }
                                );
                            }
                            else {
                                self.sd0.tx_complete();
                                self.hlwd.irq.assert(HollywoodIrq::Sdhc);
                            }
                        }
                        else {
                            self.tasks.push(
                                Task { kind: BusTask::SDHC(SDHCTask::IOPoll), target_cycle: self.cycle+10000 }
                            );
                        }
                    },
                    CardTXStatus::MultiWriteInProgress => {
                        if rw_index >= self.sd0.card.rw_stop {
                            let blocks_remain = self.sd0.raw_read(SDRegisters::BlockCount.base_offset() & 0xffff_fffc) >> 16;
                            if blocks_remain > 0 {
                                self.tasks.push(
                                    Task { kind: BusTask::SDHC(SDHCTask::SendBufReadReady), target_cycle: self.cycle + 10000 }
                                );
                            }
                            else {
                                self.sd0.tx_complete();
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
