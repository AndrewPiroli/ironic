use std::{num::NonZeroU16, sync::atomic::AtomicUsize};
use std::sync::atomic::Ordering;
use log::debug;
use parking_lot::{Mutex, MutexGuard};
use super::{CardState, DeviceTXStatus, SDHCDevice};
use crate::mem::BigEndianMemory;

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

#[derive(Debug)]
pub struct Card {
    pub state: CardState,
    pub backing_mem: Mutex<BigEndianMemory>,
    acmd: bool,
    ocr: OcrReg,
    cid: CidReg,
    /// Relative Card Address. The Host Driver will help us assign one and then use this to select us as the Active card.
    rca: Option<NonZeroU16>,
    csd: CsdReg,
    /// The Card is selected by the Host Driver
    selected: bool,
    /// Pointer into the Backing Mem to keep track of multi-block transfers
    pub rw_index: AtomicUsize,
    /// The end address for the multi-block transfer. Should equal the initial rw_index + BlockCount*BlockSize
    pub rw_stop: usize,
    pub tx_status: DeviceTXStatus,
}

impl SDHCDevice for Card {
    fn try_new() -> (Self, bool) {
        const FILENAME: &str = "sd.img";
        let mut len = 0usize;
        let backing_mem: BigEndianMemory;
        let mut card_inserted = true;
        if let Ok(f) = std::fs::File::open(FILENAME)
            && let Ok(metadata) = f.metadata() {
            len = metadata.len() as usize;
            backing_mem = BigEndianMemory::new(len, Some(FILENAME), false).unwrap_or_else(|_|{
                card_inserted = false;
                BigEndianMemory::new(len, None, false).unwrap()
            });
        }
        else {
            card_inserted = false;
            backing_mem = BigEndianMemory::new(len, None, false).unwrap();
        }
        (Self {
            state: Default::default(),
            backing_mem: Mutex::new(backing_mem),
            acmd: Default::default(),
            ocr: Default::default(),
            cid: Default::default(),
            rca: Default::default(),
            csd: CsdReg::new_with_num_block(len / 512),
            selected: Default::default(),
            rw_index: Default::default(),
            rw_stop: Default::default(),
            tx_status: Default::default()
        }, card_inserted)
    }
    /// Issue a command to the emulated SD card. Unimplemented commands will terminate the emulator.
    fn issue(&mut self, cmd: Command, argument: u32) -> Option<Response> {
        let acmd = std::mem::replace(&mut self.acmd, false);
        match (acmd, cmd.index) {
            (false, 0) => { return Some(self.cmd0(argument)); },
            (false, 8) => {
                return Some(self.cmd8(argument));
            },
            (true, 41) => { return Some(self.acmd41(argument)); },
            (false, 2) => { return Some(self.cmd2(argument)); },
            (false, 3) => { return Some(self.cmd3(argument)); },
            (false, 9) => { return Some(self.cmd9(argument)); },
            (false, 7) => { return self.cmd7(argument); },
            (false, 16) => { return Some(self.cmd16(argument)); },
            (false, 18) => { return Some(self.cmd18(argument)); }
            (false, 25) => { return Some(self.cmd25(argument)); }
            (_, 55) => {
                self.acmd = true;
                return Some(Response::Regular(0));
            }
            _ => unimplemented!(),
        }
    }
    fn tx_status(&self) -> DeviceTXStatus {
        self.tx_status
    }
    fn set_tx_status(&mut self, new: DeviceTXStatus) {
        self.tx_status = new;
    }
    fn _state(&self) -> CardState {
        self.state
    }
    fn set_state(&mut self, new: CardState) {
        self.state = new;
    }
    fn data_index(&self) -> usize {
        self.rw_index.load(Ordering::Relaxed)
    }
    fn set_data_index(&self, new: usize) {
        self.rw_index.store(new, Ordering::Relaxed)
    }
    fn data_stop(&self) -> usize {
        self.rw_stop
    }
    fn set_data_stop(&mut self, new: usize) {
        self.rw_stop = new;
    }
    fn lock_data(&self) -> MutexGuard<BigEndianMemory> {
        self.backing_mem.lock()
    }
}

impl Card {
    fn cmd8(&mut self, argument: u32) -> Response {
        // CMD8 echo back in response
        Response::Regular(argument & 0xfff)
    }
    fn cmd0(&mut self, _argument: u32) -> Response {
        self.state = CardState::Idle;
        Response::Regular(0)
    }
    fn acmd41(&mut self, _argument: u32) -> Response {
        self.state = CardState::Ready;
        Response::Regular(self.ocr.0)
    }
    fn cmd2(&mut self, _argument: u32) -> Response {
        self.state = CardState::Ident;
        Response::R2(self.cid.0)
    }
    fn cmd3(&mut self, _argument: u32) -> Response {
        self.state = CardState::Stby;
        self.rca = Some(NonZeroU16::new(0x4321).unwrap());
        match self.rca {
            Some(existing) => {
                self.rca = Some(existing.checked_add(1).unwrap())
            },
            None => self.rca = Some(NonZeroU16::new(0x4321).unwrap()),
        }
        Response::Regular((self.rca.unwrap().get() as u32) << 16 | self.state.bits_for_card_status() as u32)
    }
    fn cmd9(&mut self, _argument: u32) -> Response {
        Response::R2(self.csd.0)
    }
    fn cmd7(&mut self, argument: u32) -> Option<Response> {
        let selected_addr = (argument >> 16) as u16;
        if let Some(rca) = self.rca && selected_addr == rca.get() {
            if self.state == CardState::Dis {
                self.state = CardState::Prg;
            }
            else {
                self.state = CardState::Trans;
            }
            debug!(target: "SDHC", "card selected");
            self.selected = true;
            return None;
        }
        else {
            self.selected = false;
            debug!(target: "SDHC", "card diselected");
            if self.state == CardState::Prg {
                self.state = CardState::Dis;
            }
            else {
                self.state = CardState::Stby;
            }
        }
        None
    }
    fn cmd16(&self, argument: u32) -> Response {
        let mut response = (self.state.bits_for_card_status() as u32) << 9;
        if argument != 512 {
            response |= 1 << 29; // block len error
        }
        Response::Regular(response)
    }
    fn cmd18(&mut self, argument: u32) -> Response {
        log::debug!(target: "SDHC", "Issued multi block transfer(R): {} bytes", argument * 512);
        self.state = CardState::Data;
        self.rw_index.store(argument as usize * 512 , std::sync::atomic::Ordering::Relaxed);
        let response = (self.state.bits_for_card_status() as u32) << 9;
        self.tx_status = DeviceTXStatus::MultiReadPending;
        Response::Regular(response)
    }
    fn cmd25(&mut self, argument: u32) -> Response {
        log::debug!(target: "SDHC", "Issued multi block transfer(W): {} bytes", argument * 512);
        self.state = CardState::Rcv;
        self.rw_index.store(argument as usize * 512 , std::sync::atomic::Ordering::Relaxed);
        let response = (self.state.bits_for_card_status() as u32) << 9;
        self.tx_status = DeviceTXStatus::MultiWritePending;
        Response::Regular(response)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
/// The card response to commands.
/// Different types are for mapping the Part 1 response field bits to Part 2 Response Register bits
pub enum Response {
    /// R1, R3, R4, R5, R6, R7. Part 1 [39:8] to Part 2 [31:0]
    Regular(u32),
    // AutoCMD12(u32), // Part 1 [39:8] to Part 2 [127:96]
    /// Part 1 [127:8] to Part 2 [119:0]
    R2(u128),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OcrReg(u32);

impl Default for OcrReg {
    fn default() -> Self {
        Self((1 << 31 /* powerup complete */) | (1 << 30 /* High capacity card */) | (1 << 20 /* 3.3v */))
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Operation Condition Register of the emulated SD card.
/// Mostly does not matter.
struct CidReg(u128);

impl Default for CidReg {
    fn default() -> Self {
        let man_id:u128 = 0xffff << 120;
        let oid: u128 = (65 << 119) | (80 << 118); // AP
        let pnm: u128 = (73 << 117) | (82 << 116) | (79 << 115) | (78 << 114) | (89 << 113);
        let crc = 0; // FIXME !!
        Self(man_id | oid | pnm | crc | 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Card Specific Data Register of the emulated SD card.
/// Defines to the Host Driver what kind of card we are and what we support.
struct CsdReg(u128);

impl CsdReg {
    fn new_with_num_block(num_blocks: usize) -> Self {
        let num_blocks = ((num_blocks & 0x3fffff) + 1) as u128; // mask to 22 bit, spec builds in an additional +1 as well.
        let x =
            (1 << 126) | //structure ver 2
            (0xe << 112) | // TAAC fixed defintion
            (0x32 << 96) | // trans speed for 25Mhz
            (0b010110110101 << 84) | // command classes - mandatory only
            (0x9 << 80) | // block len fixed to 512
            (num_blocks << 48) | // (8191 + 1) * 512k = 4Gbyte card
            (1 << 46) | // erase block en fixed
            (0x7f << 39) | // sector size fixed
            (0b10 << 26) | //write speed factor fixed
            (9 << 22) | // write bl len fixed
            (3 << 10) // file format other
        ;
        Self(x >> 8) /* mini is off, or we are - probably us!! */
    }
}
