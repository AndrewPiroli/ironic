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
        self.do_dma_write(addr, buf)
    }
    /// Perform a DMA read operation.
    pub fn dma_read(&self, addr: u32, buf: &mut [u8]) -> anyhow::Result<()> {
        self.do_dma_read(addr, buf)
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
            _ => bail!("Invalid read width"),
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
            _ => bail!("Invalid write width"),
        };
        Ok(())
    }
}

impl Bus {
    /// Dispatch a DMA write to some memory device.
    fn do_dma_write(&mut self, addr: u32, buf: &[u8]) -> anyhow::Result<()> {
        use MemDevice::*;
        if self.resolve_dma_sram(addr).is_some() {
            let mut addr = addr;
            let mut buf = buf;
            while !buf.is_empty() {
                let Some((dev, off, available)) = self.resolve_dma_sram(addr) else {
                    bail!("DMA write crossed the end of the SRAM aperture at {addr:08x}");
                };
                let len = available.min(buf.len());
                match dev {
                    Sram0 => self.sram0.write_buf(off, &buf[..len])?,
                    Sram1 => self.sram1.write_buf(off, &buf[..len])?,
                    _ => unreachable!(),
                }
                addr = addr.checked_add(len as u32)
                    .ok_or_else(|| anyhow::anyhow!("DMA write address overflow"))?;
                buf = &buf[len..];
            }
            return Ok(());
        }

        let handle = match self.decode_phys_addr(addr){
            Some(val) => val,
            None => {
                bail!("Unresolved physical address {addr:08x}");
            }
        };

        let off = (addr & handle.mask) as usize;
        match handle.dev {
            Device::Mem(dev) => { match dev {
                MaskRom => { bail!("Bus error: DMA write on mask ROM"); },
                Sram0   => self.sram0.write_buf(off, buf)?,
                Sram1   => self.sram1.write_buf(off, buf)?,
                Mem1    => self.mem1.write_buf(off, buf)?,
                Mem2    => self.mem2.write_buf(off, buf)?,
            }},
            Device::Io(dev) => {
                let Ok(burst) = <[u8; 32]>::try_from(buf) else {
                    bail!("Bus error: unsupported {}B DMA write to I/O device {dev:?}", buf.len());
                };
                self.do_mmio_write(dev, off, BusPacket::_32Byte(burst))?;
            },
        }
        Ok(())
    }

    /// Dispatch a DMA read to some memory device.
    fn do_dma_read(&self, addr: u32, buf: &mut [u8]) -> anyhow::Result<()> {
        use MemDevice::*;
        if self.resolve_dma_sram(addr).is_some() {
            let mut addr = addr;
            let mut buf = buf;
            while !buf.is_empty() {
                let Some((dev, off, available)) = self.resolve_dma_sram(addr) else {
                    bail!("DMA read crossed the end of the SRAM aperture at {addr:08x}");
                };
                let len = available.min(buf.len());
                match dev {
                    Sram0 => self.sram0.read_buf(off, &mut buf[..len])?,
                    Sram1 => self.sram1.read_buf(off, &mut buf[..len])?,
                    _ => unreachable!(),
                }
                addr = addr.checked_add(len as u32)
                    .ok_or_else(|| anyhow::anyhow!("DMA read address overflow"))?;
                buf = &mut buf[len..];
            }
            return Ok(());
        }

        let handle = match self.decode_phys_addr(addr) {
                Some(val) => val,
                None => { bail!("Unresolved physical address {addr:08x}"); }
        };

        let off = (addr & handle.mask) as usize;
        match handle.dev {
            Device::Mem(dev) => { match dev {
                MaskRom => { bail!("Bus error: DMA read on mask ROM".to_string()); },
                Sram0   => self.sram0.read_buf(off, buf)?,
                Sram1   => self.sram1.read_buf(off, buf)?,
                Mem1    => self.mem1.read_buf(off, buf)?,
                Mem2    => self.mem2.read_buf(off, buf)?,
            }},
            _ => { bail!("Bus error: DMA read on memory-mapped I/O region".to_string()); },
        }
        Ok(())
    }
}


