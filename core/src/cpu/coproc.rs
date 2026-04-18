//! Coprocessor register definitions and functionality.

use std::{cell::RefCell, collections::HashMap, hash::BuildHasherDefault};
use parking_lot::RawRwLock;
use parking_lot::lock_api::RwLockReadGuard;

use crate::bus::Bus;
use fxhash::FxHasher32;

/// The system control register (p15 register 1).
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct ControlRegister(pub u32);
impl ControlRegister {
    pub fn mmu_enabled(&self) -> bool     { (self.0 & 0x0000_0001) != 0 }
    pub fn afault_enabled(&self) -> bool  { (self.0 & 0x0000_0002) != 0 }
    pub fn dcache_enabled(&self) -> bool  { (self.0 & 0x0000_0004) != 0 }
    pub fn wbuffer_enabled(&self) -> bool { (self.0 & 0x0000_0008) != 0 }
    pub fn be_enabled(&self) -> bool      { (self.0 & 0x0000_0080) != 0 }
    pub fn sysprot_enabled(&self) -> bool { (self.0 & 0x0000_0100) != 0 }
    pub fn romprot_enabled(&self) -> bool { (self.0 & 0x0000_0200) != 0 }
    pub fn icache_enabled(&self) -> bool  { (self.0 & 0x0000_1000) != 0 }
    pub fn hivec_enabled(&self) -> bool   { (self.0 & 0x0000_2000) != 0 }
    pub fn thumb_disabled(&self) -> bool  { (self.0 & 0x0000_8000) != 0 }
}

/// Domain access control register (DACR).
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct DACRegister(pub u32);
impl DACRegister {
    /// Return the mode associated with the provided domain index (0-15).
    pub fn domain(&self, idx: u32) -> DomainMode {
        assert!(idx < 16);
        DomainMode::from((self.0 >> (idx * 2)) & 0b11)
    }
}

/// Access control modes associated with some memory domain.
#[derive(Debug)]
pub enum DomainMode {
    /// All accesses generate a domain fault.
    NoAccess = 0b00,
    /// Accesses are checked against permission bits in a TLB entry.
    Client   = 0b01,
    /// Unimplemented/unpredictable for ARMv5
    Reserved = 0b10,
    /// Accesses proceed without checking permission bits in a TLB entry.
    Manager  = 0b11,
}
impl From<u32> for DomainMode {
    fn from(x: u32) -> Self {
        use DomainMode::*;
        match x {
            0b00 => NoAccess, 0b01 => Client,
            0b10 => Reserved, 0b11 => Manager,
            _ => unreachable!("Invalid domain acess mode bits"),
        }
    }
}


/// Registers in the System control coprocessor.
#[derive(Debug)]
pub enum SystemControlReg {
    Control, PageControl, AccessControl,
    FaultStatus, FaultAddress,
    CacheControl, TlbControl, CacheLockdown, TlbLockdown,
}
impl From<u32> for SystemControlReg {
    fn from(x: u32) -> Self {
        use SystemControlReg::*;
        match x {
            1 => Control,
            2 => PageControl,
            3 => AccessControl,
            5 => FaultStatus,
            6 => FaultAddress,
            7 => CacheControl,
            8 => TlbControl,
            9 => CacheLockdown,
            10 => TlbLockdown,
            _ => panic!("Invalid p15 register number {x}"),
        }
    }
}

pub struct FlagRes {
    pub n: Option<bool>,
    pub z: Option<bool>,
    pub c: Option<bool>,
    pub v: Option<bool>,
}


/// Container for the System Control coprocessor (p15).
pub struct SystemControl {
    /// System control register
    pub c1_ctrl: ControlRegister,
    /// Translation table base register 0
    c2_ttbr0: u32,
    /// Domain access control register
    pub c3_dacr: DACRegister,
    /// Fault status register (data)
    pub c5_dfsr: u32,
    /// Fault status register (instruction)
    pub c5_ifsr: u32,
    /// Fault address register (data)
    pub c6_dfar: u32,
    /// Holds a cache of L1 MMU translations
    l1_tlb: RefCell<HashMap<u32, u32, BuildHasherDefault<FxHasher32>>>,
}

impl Default for SystemControl {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemControl {
    pub fn new() -> Self {
        SystemControl {
            c1_ctrl: ControlRegister(0),
            c2_ttbr0: 0,
            c3_dacr: DACRegister(0),
            c5_dfsr: 0,
            c5_ifsr: 0,
            c6_dfar: 0,
            l1_tlb: RefCell::new(HashMap::with_hasher(BuildHasherDefault::<FxHasher32>::default())),
        }
    }

    /// Returns a set of status flags; called by mrc when rt=15.
    pub fn read_alt(&self, reg: u32, crm: u32, opcd2: u32) -> FlagRes {
        use SystemControlReg::*;
        match SystemControlReg::from(reg) {
            CacheControl => match (crm, opcd2) {
                (10, 3) => FlagRes { n: None, z: Some(true), c: None, v: None },
                (14, 3) => FlagRes { n: None, z: Some(true), c: None, v: None }, //clean and invalidate entire DCache
                _ => panic!(""),
            },
            _ => panic!("Unimpl p15 read_alt {:?} crm={crm} opcd2={opcd2}", 
                SystemControlReg::from(reg)),
        }
    }

    pub fn read(&self, reg: u32, crm: u32, opcd2: u32) -> u32 {
        use SystemControlReg::*;
        match SystemControlReg::from(reg) {
            Control => match (crm, opcd2) {
                (0, 0) => self.c1_ctrl.0,
                _ => panic!("Unimpl p15 read {:?} crm={crm} opcd2={opcd2}", 
                    SystemControlReg::from(reg)),
            },
            AccessControl => match (crm, opcd2) {
                (0, 0) => self.c3_dacr.0,
                _ => panic!("Unimpl p15 read {:?} crm={crm} opcd2={opcd2}", 
                    SystemControlReg::from(reg)),
            },
            PageControl => match (crm, opcd2) {
                (0, 0) => self.read_ttbr(),
                _ => panic!("Unimpl p15 read {:?} crm={crm} opcd2={opcd2}",
                    SystemControlReg::from(reg)),
            },
            _ => panic!("Unimpl p15 read {:?} crm={crm} opcd2={opcd2}", 
                SystemControlReg::from(reg)),
        }
    }

    pub fn write(&mut self, val: u32, reg: u32, crm: u32, opcd2: u32) {
        use SystemControlReg::*;
        match SystemControlReg::from(reg) {
            Control => match (crm, opcd2) {
                (0, 0) => {
                    self.clear_tlb(); // They could be doing something interesting, like shutting off the MMU
                    self.c1_ctrl.0 = val
                },
                _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}",
                    val, SystemControlReg::from(reg), crm, opcd2),
            },

            PageControl => match (crm, opcd2) {
                (0, 0) => {
                    self.clear_tlb();
                    self.write_ttbr(val)
                },
                _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}",
                    val, SystemControlReg::from(reg), crm, opcd2),
            },

            AccessControl => match (crm, opcd2) {
                (0, 0) => {
                    self.c3_dacr = DACRegister(val);
                },
                _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}",
                    val, SystemControlReg::from(reg), crm, opcd2),
            },

            FaultStatus => match (crm, opcd2) {
                (0, 0) => self.c5_dfsr = val,
                (0, 1) => self.c5_ifsr = val,
                _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}",
                    val, SystemControlReg::from(reg), crm, opcd2),
            },
            FaultAddress => match (crm, opcd2) {
                (0, 0) => self.c6_dfar = val,
                _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}",
                    val, SystemControlReg::from(reg), crm, opcd2),
            },

            CacheControl => match (crm, opcd2) {
                (0, 4) => { // wait for interrupt
                    // This isn't implemented currently. Since interrupts are serviced immediately, we should be able to no-op right?
                },
                (5, 0) => {}, // Invalidate entire icache
                (6, 0) => {}, // Invalidate entire dcache
                (6, 1) => {}, // Invalidate dcache line
                (10, 1) => {}, // Clean dcache line
                (10, 4) => {}, // Drain write buffer
                _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}",
                    val, SystemControlReg::from(reg), crm, opcd2),
            },

            TlbControl => match (crm, opcd2) {
                (7, 0) => { self.clear_tlb(); }, // Invalidate entire TLB
                _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}",
                    val, SystemControlReg::from(reg), crm, opcd2),
            },

            _ => panic!("Unimpl P15 write {:08x} {:?} crm={} opcd2={}", 
                val, SystemControlReg::from(reg), crm, opcd2),
        }
    }
}

impl SystemControl {
    pub fn write_ttbr(&mut self, new: u32) {
        self.clear_tlb();
        self.c2_ttbr0 = new;
    }

    pub fn read_ttbr(&self) -> u32 {
        self.c2_ttbr0
    }

    /// Perform the actual L1 lookup
    /// Technically this is an MMU operation, but having it here is easier for now.
    pub fn l1_fetch(&self, addr: u32, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<u32> {
        let mut tlb_inner = self.l1_tlb.borrow_mut();
        let val = match tlb_inner.get(&addr) {
            Some(val) => *val, // TLB hit
            None => { // miss
                let val = bus.read32(addr)?;
                tlb_inner.insert(addr, val);
                val
            },
        };
        Ok(val)
    }

    pub fn clear_tlb(&self) {
        self.l1_tlb.borrow_mut().clear();
    }
}
