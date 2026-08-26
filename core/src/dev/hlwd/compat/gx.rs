pub mod cp;
pub mod pe;
pub mod bp;
pub mod xf;

use anyhow::bail;

use crate::bus::mmio::*;
use crate::bus::prim::*;
use crate::bus::task::*;

use cp::CommandProcessor;
use pe::PixelEngine;
use bp::BlittingProcessor;
use xf::TransformUnit;

/// Legacy GX GPU
/// XXX: double-check these descriptions, to the best I can tell
/// from checking Dolphin this is where each of these things land,
/// but they're quite interconnected so it's annoying to tell
///
/// This isn't really a single MMIO device, rather a bunch of intertwined
/// units, all a part of the GX pipeline, some of which have MMIO regions.
///
/// - The Command Processor (CP) decodes commands out of the FIFO, sending
///   them off to whichever unit needs them.
/// - The Pixel Engine (PE) does several things, including notably
///   the EFB -> XFB copy.
/// - The Blitting Processor (BP) does several things, notably being an
///   interface for some PE functions (like the EFB -> XFB copy), as well
///   as dealing with texturing, scaling, and more.
#[derive(Default, Debug, Clone)]
pub struct GX {
    pub cp: CommandProcessor,
    pub pe: PixelEngine,
    pub bp: BlittingProcessor,
    pub xf: TransformUnit,
}

impl MmioDeviceMultiWidth for GX {
    fn read8(&self, access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        match off {
            0x0000..=0x0fff => self.cp.read8(access, off),
            _ => bail!("GX 8-bit read to undefined offset {off:x}"),
        }
    }
    fn read16(&self, access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        match off {
            0x0000..=0x0fff => self.cp.read16(access, off),
            0x1000..=0x1fff => self.pe.read(access, off - 0x1000),
            _ => bail!("GX 16-bit read to undefined offset {off:x}"),
        }
    }
    fn read32(&self, access: AccessContext, off: usize) -> anyhow::Result<BusPacket> {
        match off {
            0x0000..=0x0fff => self.cp.read32(access, off),
            _ => bail!("GX 32-bit read to undefined offset {off:x}"),
        }
    }
    fn write8(&mut self, access: AccessContext, off: usize, val: u8) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x0000..=0x0fff => self.cp.write8(access, off, val),
            _ => bail!("GX 8-bit write {val:08x} to undefined offset {off:x}"),
        }
    }
    fn write16(&mut self, access: AccessContext, off: usize, val: u16) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x0000..=0x0fff => self.cp.write16(access, off, val),
            0x1000..=0x1fff => self.pe.write(access, off - 0x1000, val),
            _ => bail!("GX 16-bit write {val:08x} to undefined offset {off:x}"),
        }
    }
    fn write32(&mut self, access: AccessContext, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x0000..=0x0fff => self.cp.write32(access, off, val),
            _ => bail!("GX 32-bit write {val:08x} to undefined offset {off:x}"),
        }
    }
}
