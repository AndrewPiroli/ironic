use anyhow::bail;
use log::debug;

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

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
            // Build a mask for the next register
            let mask: u32 = ((1 << (reg.bytecount_of_reg() * 8)) - 1) << shift;
            if old & mask != new & mask {
                ret.push(reg);
            }
            shift += reg.bytecount_of_reg() as u32 * 8;
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
    fn run_write_handler(&self, iface: &mut NewSDInterface, old: u32, new: u32) {
        // Calculate shift to move the register in question to the right most position
        let shift = (self.base_offset() & 0x3) * 8;
        let mask: u32 = (1 << (self.bytecount_of_reg() * 8)) - 1;
        let _old = (old >> shift) & mask;
        let mut new = (new >> shift) & mask;
        match self {
            SDRegisters::ClockControl => {
                // set internal clock stable (bit 1) based on internal clock enable (bit 0)
                match new & 0b11 {
                    0b11 | 0b00 => {return;},
                    0b10 => {
                        debug!(target: "SDHC", "Internal Clock Disable");
                        new = new & 0xffff_fffc;
                    }
                    0b01 => {
                        debug!(target:"SDHC", "Internal Clock Enable");
                        new = new & 0b10;
                    }
                    _=> { unreachable!() }
                }
                iface.setreg(*self, new);
            }
            SDRegisters::SoftwareReset => {
                if new & 1 == 1 {
                    iface.reset();
                }
                else { unimplemented!("DAT and CMD line resets"); }
            }
            _ => unimplemented!()
        }
    }
}

#[repr(C, align(64))]
pub struct NewSDInterface {
    register_file: [u8; 256],
}

impl NewSDInterface {
    fn raw_read(&self, off: usize) -> u32 {
        let p = (&self.register_file) as *const [u8;256] as *const u32;
        assert!(off & 0xffff_fffc == off); // alignment
        let off = off >> 2;
        assert!(off < 64); //length
        let ret = unsafe { *(p.add(off)) };
        debug!(target: "SDHC", "raw_read 0x{:x} = 0x{ret:x}", off << 2);
        ret
    }
    fn raw_write(&mut self, off: usize, val: u32) {
        let p = (&mut self.register_file) as *mut [u8;256] as *mut u32;
        assert!(off & 0xffff_fffc == off); // alignment
        let off = off >> 2;
        assert!(off < 64); //length
        unsafe { *(p.add(off)) = val; };
        debug!(target: "SDHC", "raw_write 0x{:x} = 0x{val:x}", off << 2);
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
        let mask: u32 = (1 << reg.bytecount_of_reg()) - 1;
        let old = self.raw_read(reg.base_offset() & 0xffff_fffc) & !mask;
        let new = old | ((val << val_shift) & mask);
        self.raw_write(reg.base_offset() & 0xffff_fffc, new);
    }
    fn reset(&mut self) {
        debug!(target: "SDHC", "SD interface software reset");
        *self = Self::default();
    }
}

impl Default for NewSDInterface {
    fn default() -> Self {
        let new = Self { register_file: [0;256] };
        debug!(target: "SDHC", "init sdhc");
        new
    }
}

impl MmioDevice for NewSDInterface {
    type Width = u32;

    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        Ok(BusPacket::Word(self.raw_read(off)))
    }

    fn write(&mut self, off: usize, val: Self::Width) -> anyhow::Result<Option<BusTask>> {
        // first read the current line to get the old
        let old = self.raw_read(off);
        // perform write
        self.raw_write(off, val);
        let new = self.raw_read(off);
        let regs = SDRegisters::get_affected_registers(off, old, new);
        debug!(target: "SDHC", "{:?}", &regs);
        for reg in regs {
            reg.run_write_handler(self, old, new);
        }
        Ok(None)
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
