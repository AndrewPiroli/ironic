//! ## Notes
//! I've re-written this code more times than I'd like to admit, in an attempt
//! to make it less ugly. I guess this is fine.

use crate::bus::*;
use crate::bus::prim::*;

/// Top-level read/write functions for performing physical memory accesses.
impl Bus {
    /// Perform a 32-bit physical memory read.
    pub fn read32(&self, addr: u32) -> Result<u32, String> {
        let msg = self.do_read(addr, BusWidth::W);
        match msg {
            Ok(BusPacket::Word(res)) => Ok(res),
            Ok(_) => unreachable!(),
            Err(reason) => Err(reason),
        }
    }

    /// Perform a 16-bit physical memory read.
    pub fn read16(&self, addr: u32) -> Result<u16, String> {
        let msg = self.do_read(addr, BusWidth::H);
        match msg {
            Ok(BusPacket::Half(res)) => Ok(res),
            Ok(_) => unreachable!(),
            Err(reason) => Err(reason),
        }
    }

    /// Perform an 8-bit physical memory read.
    pub fn read8(&self, addr: u32) -> Result<u8, String> {
        let msg = self.do_read(addr, BusWidth::B);
        match msg {
            Ok(BusPacket::Byte(res)) => Ok(res),
            Ok(_) => unreachable!(),
            Err(reason) => Err(reason),
        }
    }

    /// Perform a 32-bit physical memory write.
    pub fn write32(&mut self, addr: u32, val: u32) -> Result<(), String> {
        self.do_write(addr, BusPacket::Word(val))
    }
    /// Perform a 16-bit physical memory write.
    pub fn write16(&mut self, addr: u32, val: u16) -> Result<(), String> {
        self.do_write(addr, BusPacket::Half(val))
    }
    /// Perform an 8-bit physical memory write.
    pub fn write8(&mut self, addr: u32, val: u8) -> Result<(), String> {
        self.do_write(addr, BusPacket::Byte(val))
    }

    /// Perform a DMA write operation.
    pub fn dma_write(&mut self, addr: u32, buf: &[u8]) -> Result<(), String> {
        self.do_dma_write(addr, buf)
    }
    /// Perform a DMA read operation.
    pub fn dma_read(&self, addr: u32, buf: &mut [u8]) -> Result<(), String> {
        self.do_dma_read(addr, buf)
    }

}

impl Bus {
    /// Dispatch a physical read access (to memory, or some I/O device).
    fn do_read(&self, addr: u32, width: BusWidth) -> Result<BusPacket, String> {
        let handle = match self.decode_phys_addr(addr) {
            Some (h)=> {h},
            None => { return Err(format!("Unresolved physical address {:08x}. current cycle count: {}", addr, self.cycle)); }
        };

        let off = (addr & handle.mask) as usize;
        let resp = match handle.dev {
            Device::Mem(dev) => self.do_mem_read(dev, off, width)?,
            Device::Io(dev) => self.do_mmio_read(dev, off, width)?,
        };
        Ok(resp)
    }

    /// Dispatch a physical write access (to memory, or some I/O device).
    fn do_write(&mut self, addr: u32, msg: BusPacket) -> Result<(), String> {
        let handle = match self.decode_phys_addr(addr) {
            Some(val) => val,
            None => { return Err(format!("Unresolved physical address {:08x}", addr)); },
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
    fn do_mem_read(&self, dev: MemDevice, off: usize, width: BusWidth) -> Result<BusPacket, String> {
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
    fn do_mem_write(&mut self, dev: MemDevice, off: usize, msg: BusPacket) -> Result<(), String> {
        use MemDevice::*;
        use BusPacket::*;
        let target_ref = match dev {
            MaskRom => { return Err("Writes on mask ROM are unsupported".to_string()); },
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
    fn do_dma_write(&mut self, addr: u32, buf: &[u8]) -> Result<(), String> {
        use MemDevice::*;
        let handle = match self.decode_phys_addr(addr){
            Some(val) => val,
            None => {
                return Err(format!("Unresolved physical address {:08x}", addr));
            }
        };

        let off = (addr & handle.mask) as usize;
        match handle.dev {
            Device::Mem(dev) => { match dev {
                MaskRom => { return Err("Bus error: DMA write on mask ROM".to_string()); },
                Sram0   => self.sram0.write_buf(off, buf)?,
                Sram1   => self.sram1.write_buf(off, buf)?,
                Mem1    => self.mem1.write_buf(off, buf)?,
                Mem2    => self.mem2.write_buf(off, buf)?,
            }},
            _ => { return Err("Bus error: DMA write on memory-mapped I/O region".to_string()); },
        }
        Ok(())
    }

    /// Dispatch a DMA read to some memory device.
    fn do_dma_read(&self, addr: u32, buf: &mut [u8]) -> Result<(), String> {
        use MemDevice::*;
        let handle = match self.decode_phys_addr(addr) {
                Some(val) => val,
                None => { return Err(format!("Unresolved physical address {:08x}", addr)); }
        };

        let off = (addr & handle.mask) as usize;
        match handle.dev {
            Device::Mem(dev) => { match dev {
                MaskRom => { return Err("Bus error: DMA read on mask ROM".to_string()); },
                Sram0   => self.sram0.read_buf(off, buf)?,
                Sram1   => self.sram1.read_buf(off, buf)?,
                Mem1    => self.mem1.read_buf(off, buf)?,
                Mem2    => self.mem2.read_buf(off, buf)?,
            }},
            _ => { return Err("Bus error: DMA read on memory-mapped I/O region".to_string()); },
        }
        Ok(())
    }
}


