//! Implementation of the memory-management unit.

pub mod prim;

use crate::cpu::mmu::prim::*;
use crate::cpu::Cpu;
use crate::bus::Bus;

use parking_lot::RawRwLock;
use parking_lot::lock_api::{RwLockReadGuard, RwLockWriteGuard};

use anyhow::{bail, Context};

/// These are the top-level "public" functions providing read/write accesses.
impl Cpu {
    pub fn read32(&self, addr: u32) -> anyhow::Result<u32> {
        let paddr = self.translate(TLBReq::new(addr, Access::Read))?;
        let res = self.bus.read().read32(paddr)?;
        Ok(res)
    }
    pub fn read32_with_bus(&self, addr: u32, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<u32> {
        let paddr = self.translate_with_bus(TLBReq::new(addr, Access::Read), &bus)?;
        let res = bus.read32(paddr)?;
        Ok(res)
    }
    pub fn read16(&self, addr: u32) -> anyhow::Result<u16> {
        let paddr = self.translate(TLBReq::new(addr, Access::Read))?;
        let res = self.bus.read().read16(paddr)?;
        Ok(res)
    }
    pub fn read16_with_bus(&self, addr: u32, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<u16> {
        let paddr = self.translate_with_bus(TLBReq::new(addr, Access::Read), &bus)?;
        let res = bus.read16(paddr)?;
        Ok(res)
    }
    pub fn read8(&self, addr: u32) -> anyhow::Result<u8> {
        let paddr = self.translate(TLBReq::new(addr, Access::Read))?;
        let res = self.bus.read().read8(paddr)?;
        Ok(res)
    }
    pub fn read8_with_bus(&self, addr: u32, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<u8> {
        let paddr = self.translate_with_bus(TLBReq::new(addr, Access::Read), &bus)?;
        let res = bus.read8(paddr)?;
        Ok(res)
    }

    pub fn write32(&mut self, addr: u32, val: u32) -> anyhow::Result<()> {
        let paddr = self.translate(TLBReq::new(addr, Access::Write))?;
        self.bus.write().write32(paddr, val)
    }
    pub fn write16(&mut self, addr: u32, val: u32) -> anyhow::Result<()> {
        let paddr = self.translate(TLBReq::new(addr, Access::Write))?;
        self.bus.write().write16(paddr, val as u16)
    }
    pub fn write8(&mut self, addr: u32, val: u32) -> anyhow::Result<()> {
        let paddr = self.translate(TLBReq::new(addr, Access::Write))?;
        self.bus.write().write8(paddr, val as u8)
    }
}

/// These are the functions used to perform virtual-to-physical translation.
impl Cpu {
    /// Resolve a section descriptor, returning a physical address.
    fn resolve_section(&self, req: TLBReq, d: SectionDescriptor) -> anyhow::Result<u32> {
        let ctx = self.get_ctx(d.domain());
        if ctx.validate(&req, d.ap()) {
            Ok(d.base_addr() | req.vaddr.section_idx())
        } else {
            bail!("resolve_section: Domain access faults are unimplemented, vaddr={:08x}", req.vaddr.0)
        }
    }

    /// Resolve a page table descriptor, returning a physical address.
    fn resolve_page_table(&self, req: TLBReq, d: L1Descriptor, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<u32> {
        let domain = match d {
            L1Descriptor::Coarse(ref e) => e.domain(),
            L1Descriptor::Fine(ref e)   => e.domain(),
            _ => bail!("resolve_page_table: expected Coarse or Fine descriptor"),
        };
        let desc = match self.l2_fetch(req.vaddr, d, bus) {
            Ok(val) => val,
            Err(reason) => return Err(reason),
        };
        match desc {
            L2Descriptor::SmallPage(entry) => {
                let ctx = self.get_ctx(domain);
                if ctx.validate(&req, entry.get_ap(req.vaddr)) {
                    Ok(entry.base_addr() | req.vaddr.small_page_idx())
                } else {
                    dbg!(self.p15.c3_dacr.domain(domain));
                    bail!("resolve_page_table: Domain access faults are unimplemented, vaddr={:08x}", req.vaddr.0)
                }
            },
        }
    }

    /// Get the context for computing permissions associated with some PTE.
    fn get_ctx(&self, dom: u32) -> PermissionContext {
        PermissionContext { 
            domain_mode: self.p15.c3_dacr.domain(dom),
            is_priv: self.reg.cpsr.mode().is_privileged(),
            sysprot: self.p15.c1_ctrl.sysprot_enabled(),
            romprot: self.p15.c1_ctrl.romprot_enabled(),
        }
    }

    /// Given some virtual address, return the first-level PTE.
    fn l1_fetch(&self, vaddr: VirtAddr, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<L1Descriptor> {
        let addr = (self.p15.read_ttbr() & 0xffff_c000) | vaddr.l1_idx() << 2;
        let val = self.p15.l1_fetch(addr, bus)?;

        let res = L1Descriptor::from_u32(val);
        if let L1Descriptor::Fault(_) = res {
            bail!(format!("pc={:08x} L1 Fault descriptor unimpl, vaddr={:08x}",
                self.read_fetch_pc(), vaddr.0));
        }
        Ok(res)
    }

    /// Given some virtual address and a particular first-level PTE, return
    /// the second-level PTE.
    fn l2_fetch(&self, vaddr: VirtAddr, d: L1Descriptor, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<L2Descriptor> {
        let addr = match d {
            L1Descriptor::Coarse(e) => {
                e.base_addr() | (vaddr.l2_idx_coarse() << 2)
            },
            L1Descriptor::Fine(e) => {
                e.base_addr() | (vaddr.l2_idx_fine() << 2)
            }
            _ => bail!("l2_fetch requires an L1::Coarse or L1::Fine descriptor"),
        };
        let val = bus.read32(addr)?;

        L2Descriptor::from_u32_checked(val).with_context(|| format!("l2_fetch: VirtualAddr: 0x{:x} L1Descriptor: {d:?}", vaddr.0))
    }

    /// Translate a virtual address into a physical address
    pub fn translate(&self, req: TLBReq) -> anyhow::Result<u32> {
        let bus = self.bus.read();
        self.translate_with_bus(req, &bus)
    }

    /// Translate a virtual address into a physical address using an existing bus lock
    pub fn translate_with_bus(&self, req: TLBReq, bus: &RwLockReadGuard<'_, RawRwLock, Bus>) -> anyhow::Result<u32> {
        if self.p15.c1_ctrl.mmu_enabled() {
            match self.l1_fetch(req.vaddr, &bus)? {
                L1Descriptor::Section(entry) => Ok(self.resolve_section(req, entry)?),
                L1Descriptor::Coarse(entry) => self.resolve_page_table(req, L1Descriptor::Coarse(entry), &bus),
                L1Descriptor::Fine(entry) => self.resolve_page_table(req, L1Descriptor::Fine(entry), &bus),
                other => bail!("TLB first-level descriptor {other:?} unimplemented"),
            }
        } else {
            Ok(req.vaddr.0)
        }
    }
}

