#![allow(clippy::unusual_byte_groupings)]
use std::hint::unreachable_unchecked;

use anyhow::bail;
use log::error;

/// Definitions for types related to the MMU/TLB and address translation.

use crate::cpu::coproc::DomainMode;

/// Some kind of memory access (used for determining permissions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access { Read, Write, Debug }

/// Token for a request to the MMU, to translate a virtual address.
#[derive(Debug, Clone, Copy)]
pub struct TLBReq {
    pub vaddr: VirtAddr,
    pub kind: Access,
}
impl TLBReq {
    pub fn new(vaddr: u32, kind: Access) -> Self {
        TLBReq { vaddr: VirtAddr(vaddr), kind }
    }
}

/// Tokens for permissions associated with some TLB entry.
#[derive(Debug)]
pub enum TLBPermission { NA, RO, RW }
impl TLBPermission {
    /// Given some context and the access protection bits from a particular 
    /// PTE, compute the effective permissions.
    pub fn resolve(ctx: &PermissionContext, ap: u32) -> Self {
        use TLBPermission::*;
        if ap & (!0b11) != 0 {
            error!(target: "MMU", "Invalid `ap` during PTE resolution");
        }
        let ap = ap & 0b11;
        match (ap, ctx.sysprot, ctx.romprot) {
            (0b00, false, false)=> NA,
            (0b00, true, false) => if ctx.is_priv { RO } else { NA },
            (0b00, false, true) => RO,
            (0b01, _, _)        => if ctx.is_priv { RW } else { NA },
            (0b10, _, _)        => if ctx.is_priv { RW } else { RO },
            (0b11, _, _)        => RW,
            _ => { unsafe { core::hint::unreachable_unchecked() } }
        }
    }
}

/// Contextual state, used to determine whether or not some permissions on a 
/// particular page table entry are relevant/satisfied.
pub struct PermissionContext {
    /// The mode associated with the relevant domain.
    pub domain_mode: DomainMode,
    /// Whether or not we are in a privileged CPU mode.
    pub is_priv: bool,
    /// The state of the system protection bit in p15 r1.
    pub sysprot: bool,
    /// The state of the ROM protection bit in p15 r1.
    pub romprot: bool,
}
impl PermissionContext {

    /// Validate a request against this context. 
    /// Returns true if the context satisfies the provided request.
    pub fn validate(&self, req: &TLBReq, ap: u32) -> bool {
        // Ignore permission checking on out-of-band requests to the MMU.
        if req.kind == Access::Debug { return true; }

        match self.domain_mode {
            // Actually compute the permissions and check them.
            DomainMode::Client => {
                match TLBPermission::resolve(self, ap) {
                    TLBPermission::NA => false,
                    TLBPermission::RO => req.kind == Access::Read,
                    TLBPermission::RW => true,
                }
            },
            // All requests on this domain are allowed.
            DomainMode::Manager => true,
            // All requests on this domain are disallowed.
            DomainMode::NoAccess => false,
            DomainMode::Reserved => {
                error!(target: "MMU", "Use of invalid \"Reserved\" Domain Mode");
                false
            }
        }
    }
}



/// A virtual address.
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct VirtAddr(pub u32);
impl VirtAddr {
    const L1_IDX: u32           = 0b1111_1111_1111_0000_0000_0000_0000_0000;
    const SECTION_IDX: u32      = 0b0000_0000_0000_1111_1111_1111_1111_1111;

    const L2_IDX_COARSE: u32    = 0b0000_0000_0000_1111_1111_0000_0000_0000;
    //const LARGEPAGE_IDX: u32    = 0b0000_0000_0000_0000_1111_1111_1111_1111;
    const SMALLPAGE_IDX: u32    = 0b0000_0000_0000_0000_0000_1111_1111_1111;
    //const TINYPAGE_IDX: u32     = 0b0000_0000_0000_0000_0000_0011_1111_1111;

    pub fn l1_idx(&self) -> u32 { (self.0 & Self::L1_IDX) >> 20 }
    pub fn section_idx(&self) -> u32 { self.0 & Self::SECTION_IDX }
    pub fn l2_idx_coarse(&self) -> u32 { (self.0 & Self::L2_IDX_COARSE) >> 12 }
    pub fn small_page_idx(&self) -> u32 { self.0 & Self::SMALLPAGE_IDX }
}

impl core::fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <u32 as core::fmt::LowerHex>::fmt(&self.0, f)
    }
}


/// Different types of first-level page table entries.
#[derive(Debug)]
pub enum L1Descriptor {
    Fault(u32),
    //Fault(FaultDescriptor),
    Coarse(CoarseDescriptor),
    Section(SectionDescriptor),
    //Fine(FineDescriptor),
}
impl L1Descriptor {
    pub fn from_u32(x: u32) -> Self {
        match x & 0b11 {
            0b00 => L1Descriptor::Fault(0),
            0b01 => L1Descriptor::Coarse(CoarseDescriptor(x)),
            0b10 => L1Descriptor::Section(SectionDescriptor(x)),
            0b11 => panic!("L1 Fine-page descriptor unimplemented"),
            _ => unreachable!(),
        }
    }
}

/// A section descriptor entry in the first-level page table.
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct SectionDescriptor(pub u32);
impl SectionDescriptor {

    const ADDR_MASK: u32 = 0b111111111111_00000000_00_0_0000_000_00;
    const AP_MASK: u32   = 0b000000000000_00000000_11_0_0000_000_00;
    const DOM_MASK: u32  = 0b000000000000_00000000_00_0_1111_000_00;

    pub fn base_addr(&self) -> u32 { self.0 & Self::ADDR_MASK }
    pub fn ap(&self) -> u32 { (self.0 & Self::AP_MASK) >> 10 }
    pub fn domain(&self) -> u32 { (self.0 & Self::DOM_MASK) >> 5 }
}

/// A coarse page table descriptor in the first-level page table.
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct CoarseDescriptor(pub u32);
impl CoarseDescriptor {

    const ADDR_MASK: u32 =  0b11111111111111111111_0_0000_000_00;
    const DOM_MASK: u32  =  0b00000000000000000000_0_1111_000_00;

    pub fn base_addr(&self) -> u32 { self.0 & Self::ADDR_MASK }
    pub fn domain(&self) -> u32 { (self.0 & Self::DOM_MASK) >> 5 }
    pub fn ap(&self) -> u32 { panic!(""); }
}


/// Different types of second-level page table entries.
#[derive(Debug)]
pub enum L2Descriptor {
    SmallPage(SmallPageDescriptor),
}
impl L2Descriptor {
    pub fn from_u32(x: u32) -> Self {
        Self::from_u32_checked(x).unwrap()
    }
    pub fn from_u32_checked(x: u32) -> anyhow::Result<Self> {
        match x & 0b11 {
            0b00 => bail!("L2 Fault descriptor unimplemented at: {x:x}"),
            0b01 => bail!("L2 Large page descriptor unimplemented at: {x:x}"),
            0b10 => Ok(L2Descriptor::SmallPage(SmallPageDescriptor(x))),
            0b11 => bail!("L2 Tiny page descriptor unimplemented: at: {x:x}"),
            _ => unsafe { unreachable_unchecked() },
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct SmallPageDescriptor(pub u32);
impl SmallPageDescriptor {

    const ADDR_MASK: u32 = 0b11111111111111111111_00_00_00_00_0_0_00;
    const AP3_MASK: u32  = 0b00000000000000000000_11_00_00_00_0_0_00;
    const AP2_MASK: u32  = 0b00000000000000000000_00_11_00_00_0_0_00;
    const AP1_MASK: u32  = 0b00000000000000000000_00_00_11_00_0_0_00;
    const AP0_MASK: u32  = 0b00000000000000000000_00_00_00_11_0_0_00;

    pub fn get_ap(&self, vaddr: VirtAddr) -> u32 {
        ((self.0 >> 4) >> ((vaddr.0 >> 9) & 0b0110)) & 0b11
    }

    pub fn base_addr(&self) -> u32 { self.0 & Self::ADDR_MASK }
    pub fn ap3(&self) -> u32 { (self.0 & Self::AP3_MASK) >> 10 }
    pub fn ap2(&self) -> u32 { (self.0 & Self::AP2_MASK) >> 8 }
    pub fn ap1(&self) -> u32 { (self.0 & Self::AP1_MASK) >> 6 }
    pub fn ap0(&self) -> u32 { (self.0 & Self::AP0_MASK) >> 4 }
}


