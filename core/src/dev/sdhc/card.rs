use std::{num::NonZeroU16, sync::atomic::{AtomicUsize, Ordering}};
use log::{debug, error, warn};

use crate::mem::BigEndianMemory;
use super::device::{CmdRes, Command, Response, TxDir};

const LOG: &str = super::SdhcSlot::Sd0.log_target();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CardCapacity {
    /// Standard Capacity SD Memory Card (up to and including 2 GB).
    /// Uses byte addressing for memory access commands.
    /// Uses CSD Version 1.0.
    /// Does not respond to CMD8 (presents as a v1.x card).
    StandardCapacity,
    /// High Capacity SD Memory Card (more than 2 GB, up to 32 GB).
    /// Uses block (512 byte) addressing for memory access commands.
    /// Uses CSD Version 2.0.
    /// Responds to CMD8.
    HighCapacity,
}
impl CardCapacity {
    fn from_bytes(len: usize) -> Self {
        const TWO_GB: usize = 2 * 1024 * 1024 * 1024;
        if len > TWO_GB {
            CardCapacity::HighCapacity
        } else {
            CardCapacity::StandardCapacity
        }
    }
}

use parking_lot::Mutex;
#[derive(Debug)]
pub(super) struct Card {
    available: bool,
    state: CardState,
    backing_mem: Mutex<BigEndianMemory>,
    acmd: bool,
    ocr: OcrReg,
    cid: CidReg,
    /// Relative Card Address. The Host Driver will help us assign one and then use this to select us as the Active card.
    rca: Option<NonZeroU16>,
    csd: CsdReg,
    /// Whether this card is SDSC (<=2GB) or SDHC (>2GB).
    capacity: CardCapacity,
    /// The Card is selected by the Host Driver
    selected: bool,
    /// Cursor into the backing memory for the transfer in progress.
    rw_index: AtomicUsize,
}

impl Card {
    pub(super) fn new() -> Self {
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
        let capacity = CardCapacity::from_bytes(len);
        debug!(target: LOG, "SD card image size: {} bytes, capacity type: {:?}", len, capacity);
        Self {
            available: card_inserted,
            state: Default::default(),
            backing_mem: Mutex::new(backing_mem),
            acmd: Default::default(),
            ocr: OcrReg::new(capacity),
            cid: Default::default(),
            rca: Default::default(),
            csd: CsdReg::new(len, capacity),
            capacity,
            selected: Default::default(),
            rw_index: Default::default(),
        }
    }
}

impl Card {
    pub(super) fn present(&self) -> bool {
        self.available
    }

    pub(super) fn command(&mut self, cmd: Command, argument: u32) -> CmdRes {
        let acmd = std::mem::replace(&mut self.acmd, false);
        let (response, transfer) = match (acmd, cmd.index) {
            (false, 0)  => (Some(self.cmd0(argument)), None),
            (false, 8)  => (self.cmd8(argument), None),
            (true, 41)  => (Some(self.acmd41(argument)), None),
            (false, 2)  => (Some(self.cmd2(argument)), None),
            (false, 3)  => (Some(self.cmd3(argument)), None),
            (false, 9)  => (Some(self.cmd9(argument)), None),
            (false, 7)  => (self.cmd7(argument), None),
            (false, 16) => (Some(self.cmd16(argument)), None),
            (false, 18) => (Some(self.cmd18(argument)), Some(TxDir::Read)),
            (false, 25) => (Some(self.cmd25(argument)), Some(TxDir::Write)),
            (true, 6)   => (Some(self.acmd6(argument)), None),
            (_, 55) => {
                self.acmd = true;
                (Some(Response::Regular(0)), None)
            }
            _ => {
                error!(target: LOG, "SD Card {}CMD{} not implemented", match acmd { true => "A", false => ""}, cmd.index);
                panic!();
            },
        };
        CmdRes { response, transfer }
    }

    pub(super) fn read_data(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        let index = self.rw_index.load(Ordering::Relaxed);
        self.backing_mem.lock().read_buf(index, buf)?;
        self.rw_index.store(index + buf.len(), Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn write_data(&mut self, buf: &[u8]) -> anyhow::Result<()> {
        let index = self.rw_index.load(Ordering::Relaxed);
        self.backing_mem.lock().write_buf(index, buf)?;
        self.rw_index.store(index + buf.len(), Ordering::Relaxed);
        Ok(())
    }

    pub(super) fn end_transfer(&mut self, aborted: bool) {
        if aborted {
            warn!(target: LOG, "card transfer aborted at byte offset {}",
                self.rw_index.load(Ordering::Relaxed));
        }
        self.state = CardState::Trans;
    }
    fn cmd8(&mut self, argument: u32) -> Option<Response> {
        match self.capacity {
            CardCapacity::HighCapacity => {
                Some(Response::Regular(argument & 0xfff))
            },
            CardCapacity::StandardCapacity => {
                None
            },
        }
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
            debug!(target: LOG, "card selected");
            self.selected = true;
            return None;
        }
        else {
            self.selected = false;
            debug!(target: LOG, "card diselected");
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
            error!(target: LOG, "CMD16 with block len != 512 is not currently supported");
            response |= 1 << 29; // block len error
        }
        Response::Regular(response)
    }
    /// SDHC: argument is a block address
    /// SDSC: argument is already a byte address
    fn argument_to_byte_offset(&self, argument: u32) -> usize {
        match self.capacity {
            CardCapacity::HighCapacity => argument as usize * 512,
            CardCapacity::StandardCapacity => argument as usize,
        }
    }
    fn cmd18(&mut self, argument: u32) -> Response {
        let byte_offset = self.argument_to_byte_offset(argument);
        log::debug!(target: LOG, "Issued multi block transfer(R): byte offset {} (arg=0x{:x}, {:?})", byte_offset, argument, self.capacity);
        self.state = CardState::Data;
        self.rw_index.store(byte_offset, Ordering::Relaxed);
        Response::Regular((self.state.bits_for_card_status() as u32) << 9)
    }
    fn cmd25(&mut self, argument: u32) -> Response {
        let byte_offset = self.argument_to_byte_offset(argument);
        log::debug!(target: LOG, "Issued multi block transfer(W): byte offset {} (arg=0x{:x}, {:?})", byte_offset, argument, self.capacity);
        self.state = CardState::Rcv;
        self.rw_index.store(byte_offset, Ordering::Relaxed);
        Response::Regular((self.state.bits_for_card_status() as u32) << 9)
    }
    fn acmd6(&mut self, _argument: u32) -> Response {
        // Set bus width command, we aren't emulating individual SD bus cycles, so this is just a stub
        Response::Regular((self.state.bits_for_card_status() as u32) << 9)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Card States as defined in Part 1
enum CardState {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Operation Condition Register of the emulated SD card.
/// Mostly does not matter.
struct OcrReg(u32);

impl OcrReg {
    fn new(capacity: CardCapacity) -> Self {
        let ccs = match capacity {
            CardCapacity::HighCapacity => 1 << 30, // CCS = 1: High Capacity
            CardCapacity::StandardCapacity => 0,    // CCS = 0: Standard Capacity
        };
        Self((1 << 31 /* powerup complete */) | ccs | (1 << 20 /* 3.3v */))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    fn new(len: usize, capacity: CardCapacity) -> Self {
        match capacity {
            CardCapacity::HighCapacity => Self::new_v2(len / 512),
            CardCapacity::StandardCapacity => Self::new_v1(len),
        }
    }

    /// Build CSD Version 2.0 for SDHC cards (>2GB).
    /// C_SIZE is in units of 512KB: memory capacity = (C_SIZE+1) * 512K byte
    fn new_v2(num_blocks: usize) -> Self {
        let num_blocks = ((num_blocks & 0x3fffff) + 1) as u128; // mask to 22 bit, spec builds in an additional +1 as well.
        let x =
            (1 << 126) | //structure ver 2
            (0xe << 112) | // TAAC fixed defintion
            (0x32 << 96) | // trans speed for 25Mhz
            (0b010110110101 << 84) | // command classes - mandatory only
            (0x9 << 80) | // block len fixed to 512
            (num_blocks << 48) | // card size in blocks
            (1 << 46) | // erase block en fixed
            (0x7f << 39) | // sector size fixed
            (0b10 << 26) | //write speed factor fixed
            (9 << 22) | // write bl len fixed
            (3 << 10) // file format other
        ;
        Self(x >> 8) /* mini is off, or we are - probably us!! */
    }

    /// Build CSD Version 1.0 for SDSC cards (<=2GB).
    /// Uses the C_SIZE / C_SIZE_MULT / READ_BL_LEN encoding per SD Physical Layer spec Table 5-4.
    ///
    /// memory capacity = BLOCKNR * BLOCK_LEN
    /// BLOCKNR = (C_SIZE+1) * MULT
    /// MULT = 2^(C_SIZE_MULT+2)
    /// BLOCK_LEN = 2^READ_BL_LEN
    fn new_v1(len: usize) -> Self {
        // ?? worth supporting oddly sized cards ??
        //
        // C_SIZE is 12 bits (0..4095), C_SIZE_MULT is 3 bits (0..7), READ_BL_LEN is 9,10, or 11.
        //
        // try READ_BL_LEN = 9 (512 bytes) first, then 10 (1024), then 11 (2048).
        // for each, try C_SIZE_MULT from 0..7.
        // Pick the first combination that works.
        //
        let mut read_bl_len: u128 = 9;
        let mut c_size: u128 = 0;
        let mut c_size_mult: u128 = 0;
        let mut found = false;

        for bl_len in [9u32, 10, 11] {
            let block_len = 1usize << bl_len;
            if len % block_len != 0 {
                continue;
            }
            let total_blocks = len / block_len;
            for mult_val in 0u32..=7 {
                let mult = 1usize << (mult_val + 2);
                if total_blocks % mult != 0 {
                    continue;
                }
                let cs = (total_blocks / mult).saturating_sub(1); // C_SIZE = BLOCKNR/MULT - 1
                if cs <= 0xFFF { // C_SIZE fits in 12 bits
                    read_bl_len = bl_len as u128;
                    c_size = cs as u128;
                    c_size_mult = mult_val as u128;
                    found = true;
                    break;
                }
            }
            if found { break; }
        }

        if !found {
            // Fallback: pick something reasonable. Use 512-byte blocks and max out C_SIZE_MULT.
            // This handles odd-sized images by rounding down
            let block_len = 512usize;
            let mult = 1usize << 9; // C_SIZE_MULT=7 -> MULT=512
            let total_blocks = len / block_len;
            c_size = ((total_blocks / mult).saturating_sub(1).min(0xFFF)) as u128;
            c_size_mult = 7;
            read_bl_len = 9;
            warn!(target: LOG, "CSD v1: using fallback encoding, capacity may not match exactly");
        }

        debug!(target: LOG, "CSD v1: READ_BL_LEN={}, C_SIZE={}, C_SIZE_MULT={}", read_bl_len, c_size, c_size_mult);

        // CSD v1.0 bit layout (128 bits, [127:0]):
        //  [127:126] CSD_STRUCTURE = 0 (v1.0)
        //  [125:120] reserved = 0
        //  [119:112] TAAC
        //  [111:104] NSAC
        //  [103:96]  TRAN_SPEED
        //  [95:84]   CCC
        //  [83:80]   READ_BL_LEN
        //  [79]      READ_BL_PARTIAL = 1
        //  [78]      WRITE_BLK_MISALIGN = 0
        //  [77]      READ_BLK_MISALIGN = 0
        //  [76]      DSR_IMP = 0
        //  [75:74]   reserved = 0
        //  [73:62]   C_SIZE (12 bits)
        //  [61:59]   VDD_R_CURR_MIN
        //  [58:56]   VDD_R_CURR_MAX
        //  [55:53]   VDD_W_CURR_MIN
        //  [52:50]   VDD_W_CURR_MAX
        //  [49:47]   C_SIZE_MULT (3 bits)
        //  [46]      ERASE_BLK_EN = 1
        //  [45:39]   SECTOR_SIZE = 0x7f (128 write blocks)
        //  [38:32]   WP_GRP_SIZE = 0
        //  [31]      WP_GRP_ENABLE = 0
        //  [30:29]   reserved = 0
        //  [28:26]   R2W_FACTOR = 0b010 (4x)
        //  [25:22]   WRITE_BL_LEN = READ_BL_LEN
        //  [21]      WRITE_BL_PARTIAL = 0
        //  [20:16]   reserved = 0
        //  [15]      FILE_FORMAT_GRP = 0
        //  [14]      COPY = 0
        //  [13]      PERM_WRITE_PROTECT = 0
        //  [12]      TMP_WRITE_PROTECT = 0
        //  [11:10]   FILE_FORMAT = 0b11 (other)
        //  [9:8]     reserved = 0
        //  [7:1]     CRC = 0 (not checked ????)
        //  [0]       always 1
        let x: u128 =
            (0u128 << 126) |                    // CSD_STRUCTURE = 0 (v1.0)
            (0x26u128 << 112) |                 // TAAC = 0x26 (1ms, matches typical SDSC)
            (0x00u128 << 104) |                 // NSAC = 0
            (0x32u128 << 96) |                  // TRAN_SPEED = 25MHz
            (0b010110110101u128 << 84) |        // CCC - mandatory classes
            (read_bl_len << 80) |               // READ_BL_LEN
            (0u128 << 79) |                     // READ_BL_PARTIAL = 0
            (0u128 << 78) |                     // WRITE_BLK_MISALIGN = 0
            (0u128 << 77) |                     // READ_BLK_MISALIGN = 0
            (0u128 << 76) |                     // DSR_IMP = 0
            (c_size << 62) |                    // C_SIZE (12 bits)
            (0b011u128 << 59) |                 // VDD_R_CURR_MIN = 10mA
            (0b011u128 << 56) |                 // VDD_R_CURR_MAX = 25mA
            (0b011u128 << 53) |                 // VDD_W_CURR_MIN = 10mA
            (0b011u128 << 50) |                 // VDD_W_CURR_MAX = 25mA
            (c_size_mult << 47) |               // C_SIZE_MULT
            (1u128 << 46) |                     // ERASE_BLK_EN = 1
            (0x7fu128 << 39) |                  // SECTOR_SIZE = 127 (128 blocks)
            (0u128 << 32) |                     // WP_GRP_SIZE = 0
            (0u128 << 31) |                     // WP_GRP_ENABLE = 0
            (0b010u128 << 26) |                 // R2W_FACTOR = 4x
            (read_bl_len << 22) |               // WRITE_BL_LEN = READ_BL_LEN
            (0u128 << 21) |                     // WRITE_BL_PARTIAL = 0
            (0b11u128 << 10) |                  // FILE_FORMAT = other
            1u128                               // always 1 bit
        ;
        Self(x >> 8) /* fuck me idk */
    }
}
