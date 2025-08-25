//! ## Notes
//! I've re-written this code more times than I'd like to admit, in an attempt
//! to make it less ugly. I guess this is fine.

use anyhow::bail;

use crate::bus::*;
use crate::bus::prim::*;

/// Top-level read/write functions for performing physical memory accesses.
impl Bus {
    /// Perform a 32-bit physical memory read.
    pub fn read32(&self, addr: u32) -> anyhow::Result<u32> {
        let msg = self.do_read(addr, BusWidth::W)?;
        match msg {
            BusPacket::Word(res) => Ok(res),
            _ => unreachable!(),
        }
    }

    /// Perform a 16-bit physical memory read.
    pub fn read16(&self, addr: u32) -> anyhow::Result<u16> {
        let msg = self.do_read(addr, BusWidth::H)?;
        match msg {
            BusPacket::Half(res) => Ok(res),
            _ => unreachable!(),
        }
    }

    /// Perform an 8-bit physical memory read.
    pub fn read8(&self, addr: u32) -> anyhow::Result<u8> {
        let msg = self.do_read(addr, BusWidth::B)?;
        match msg {
            BusPacket::Byte(res) => Ok(res),
            _ => unreachable!(),
        }
    }

    /// Perform a 32-bit physical memory write.
    pub fn write32(&mut self, addr: u32, val: u32) -> anyhow::Result<()> {
        self.do_write(addr, BusPacket::Word(val))
    }
    /// Perform a 16-bit physical memory write.
    pub fn write16(&mut self, addr: u32, val: u16) -> anyhow::Result<()> {
        self.do_write(addr, BusPacket::Half(val))
    }
    /// Perform an 8-bit physical memory write.
    pub fn write8(&mut self, addr: u32, val: u8) -> anyhow::Result<()> {
        self.do_write(addr, BusPacket::Byte(val))
    }

    /// Perform a DMA write operation.
    pub fn dma_write(&mut self, addr: u32, buf: &[u8]) -> anyhow::Result<()> {
        self.do_dma_write(addr, buf, false)?;
        Ok(())
    }
    /// Perform a DMA read operation.
    pub fn dma_read(&self, addr: u32, buf: &mut [u8]) -> anyhow::Result<()> {
        self.do_dma_read(addr, buf, false)?;
        Ok(())
    }

    /// Perform a DMA write operation.
    pub fn debug_write(&mut self, addr: u32, buf: &[u8]) -> anyhow::Result<usize> {
        self.do_dma_write(addr, buf, true)
    }
    /// Perform a DMA read operation.
    pub fn debug_read(&self, addr: u32, buf: &mut [u8]) -> anyhow::Result<usize> {
        self.do_dma_read(addr, buf, true)
    }

}

impl Bus {
    /// Dispatch a physical read access (to memory, or some I/O device).
    fn do_read(&self, addr: u32, width: BusWidth) -> anyhow::Result<BusPacket> {
        let handle = match self.decode_phys_addr(addr) {
            Some (h)=> {h},
            None => { bail!("Unresolved physical address {addr:08x}. current cycle count: {}", self.cycle); }
        };

        let off = (addr & handle.mask) as usize;
        let resp = match handle.dev {
            Device::Mem(dev) => self.do_mem_read(dev, off, width)?,
            Device::Io(dev) => self.do_mmio_read(dev, off, width)?,
        };
        Ok(resp)
    }

    /// Dispatch a physical write access (to memory, or some I/O device).
    fn do_write(&mut self, addr: u32, msg: BusPacket) -> anyhow::Result<()> {
        let handle = match self.decode_phys_addr(addr) {
            Some(val) => val,
            None => { bail!("Unresolved physical address {addr:08x}"); },
        };

        let off = (addr & handle.mask) as usize;
        match handle.dev {
            Device::Mem(dev) => self.do_mem_write(dev, off, msg)?,
            Device::Io(dev) => self.do_mmio_write(dev, off, msg)?,
        };
        Ok(())
    }
}

impl Bus {
    /// Dispatch a physical read access to some memory device.
    fn do_mem_read(&self, dev: MemDevice, off: usize, width: BusWidth) -> anyhow::Result<BusPacket> {
        use MemDevice::*;
        use BusPacket::*;
        let target_ref = match dev {
            MaskRom => &self.mrom,
            Sram0   => &self.sram0,
            Sram1   => &self.sram1,
            Mem1    => &self.mem1,
            Mem2    => &self.mem2,
        };
        Ok(match width {
            BusWidth::W => Word(target_ref.read::<u32>(off)?),
            BusWidth::H => Half(target_ref.read::<u16>(off)?),
            BusWidth::B => Byte(target_ref.read::<u8>(off)?),
        })
    }

    /// Dispatch a physical write access to some memory device.
    fn do_mem_write(&mut self, dev: MemDevice, off: usize, msg: BusPacket) -> anyhow::Result<()> {
        use MemDevice::*;
        use BusPacket::*;
        let target_ref = match dev {
            MaskRom => { bail!("Writes on mask ROM are unsupported"); },
            Sram0   => &mut self.sram0,
            Sram1   => &mut self.sram1,
            Mem1    => &mut self.mem1,
            Mem2    => &mut self.mem2,
        };
        match msg {
            Word(val) => target_ref.write::<u32>(off, val)?,
            Half(val) => target_ref.write::<u16>(off, val)?,
            Byte(val) => target_ref.write::<u8>(off, val)?,
        };
        Ok(())
    }
}

impl Bus {
    /// Dispatch a DMA write to some memory device.
    fn do_dma_write(&mut self, addr: u32, buf: &[u8], permissive: bool) -> anyhow::Result<usize> {
        use MemDevice::*;
        let handle = match self.decode_phys_addr(addr){
            Some(val) => val,
            None => {
                bail!("Unresolved physical address {addr:08x}");
            }
        };

        let off = (addr & handle.mask) as usize;
        let cnt = match handle.dev {
            Device::Mem(dev) => { match dev {
                MaskRom => { bail!("Bus error: DMA write on mask ROM"); },
                Sram0   => self.sram0.write_buf(off, buf, permissive)?,
                Sram1   => self.sram1.write_buf(off, buf, permissive)?,
                Mem1    => self.mem1.write_buf(off, buf, permissive)?,
                Mem2    => self.mem2.write_buf(off, buf, permissive)?,
            }},
            _ => { bail!("Bus error: DMA write on memory-mapped I/O region"); },
        };
        Ok(cnt)
    }

    /// Dispatch a DMA read to some memory device.
    fn do_dma_read(&self, addr: u32, buf: &mut [u8], permissive: bool) -> anyhow::Result<usize> {
        use MemDevice::*;
        let handle = match self.decode_phys_addr(addr) {
                Some(val) => val,
                None => { bail!("Unresolved physical address {addr:08x}"); }
        };

        let off = (addr & handle.mask) as usize;
        let cnt = match handle.dev {
            Device::Mem(dev) => { match dev {
                MaskRom if permissive => self.mrom.read_buf(off, buf, true)?,
                MaskRom => { bail!("Bus error: DMA read on mask ROM".to_string()); },
                Sram0   => self.sram0.read_buf(off, buf, permissive)?,
                Sram1   => self.sram1.read_buf(off, buf, permissive)?,
                Mem1    => self.mem1.read_buf(off, buf, permissive)?,
                Mem2    => self.mem2.read_buf(off, buf, permissive)?,
            }},
            _ => { bail!("Bus error: DMA read on memory-mapped I/O region".to_string()); },
        };
        Ok(cnt)
    }
}


