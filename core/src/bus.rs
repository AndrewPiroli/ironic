pub mod prim;
pub mod decode;
pub mod dispatch;
pub mod mmio;
pub mod task;
use std::env::current_dir;

use crate::bus::task::*;

use crate::mem::*;
use crate::dev::hlwd::*;
use crate::dev::aes::*;
use crate::dev::sha::*;
use crate::dev::nand::*;
use crate::dev::ehci::*;
use crate::dev::ohci::*;
use crate::dev::sdhc::*;

use gimli::BigEndian;
use gimli::DebugFrame;
use gimli::Dwarf;
use gimli::EndianArcSlice;

#[derive(Default)]
pub struct DebugInfo {
    pub debuginfo: Option<Dwarf<EndianArcSlice<BigEndian>>>,
    pub debug_frames: Option<DebugFrame<EndianArcSlice<BigEndian>>>,
    pub last_pc: Option<u32>,
    pub last_lr: Option<u32>,
    pub last_sp: Option<u32>,
}

/// Implementation of an emulated bus.
///
/// In this model, the bus itself owns all memories and system devices.
pub struct Bus {
    // System memories
    pub mrom: BigEndianMemory,
    pub sram0: BigEndianMemory,
    pub sram1: BigEndianMemory,
    pub mem1: BigEndianMemory,
    pub mem2: BigEndianMemory,

    // System devices
    pub hlwd: Hollywood,
    pub nand: NandInterface,
    pub aes: AesInterface,
    pub sha: ShaInterface,
    pub ehci: EhcInterface,
    pub ohci0: OhcInterface,
    pub ohci1: OhcInterface,
    pub sd0: NewSDInterface,
    pub sd1: WLANInterface,

    /// True when the ROM mapping is disabled.
    pub rom_disabled: bool,
    /// True when the SRAM mirror is enabled.
    pub mirror_enabled: bool,

    /// Queue for pending work on I/O devices.
    pub tasks: Vec<Task>,
    pub cycle: usize,
    pub debuginfo: Box<DebugInfo>,
}
impl Bus {
    pub fn new()-> anyhow::Result<Self> {
        Ok(Bus {
            mrom: BigEndianMemory::new(0x0000_2000, Some("./boot0.bin"), false)?,
            sram0: BigEndianMemory::new(0x0001_0000, None, false)?,
            sram1: BigEndianMemory::new(0x0001_0000, None, false)?,
            mem1: BigEndianMemory::new(0x0180_0000, None, false)?,
            mem2: BigEndianMemory::new(0x0400_0000, None, false)?,

            hlwd: Hollywood::new()?,
            nand: NandInterface::new("./nand.bin")?,
            aes: AesInterface::new(),
            sha: ShaInterface::new(),
            ehci: EhcInterface::new(),
            ohci0: OhcInterface { idx: 0, ..Default::default() },
            ohci1: OhcInterface { idx: 1, ..Default::default() },
            sd0: NewSDInterface::default(),
            sd1: WLANInterface::default(),

            rom_disabled: false,
            mirror_enabled: false,
            tasks: Vec::new(),
            cycle: 0,
            debuginfo: Box::default(),
        })
    }

    pub fn install_debuginfo(&mut self, debuginfo: Dwarf<EndianArcSlice<BigEndian>>) {
        self.debuginfo.debuginfo = Some(debuginfo);
    }

    pub fn install_debug_frames(&mut self, debug_frames: DebugFrame<EndianArcSlice<BigEndian>>) {
        self.debuginfo.debug_frames = Some(debug_frames);
    }

    pub fn update_debug_location(&mut self, pc: Option<u32>, lr: Option<u32>, sp: Option<u32>) {
        if let Some(pc) = pc { self.debuginfo.last_pc = Some(pc); }
        if let Some(lr) = lr { self.debuginfo.last_lr = Some(lr); }
        if let Some(sp) = sp { self.debuginfo.last_sp = Some(sp); }
    } 

    pub fn dump_memory(&self, suffix: &'static str) -> anyhow::Result<std::path::PathBuf> {
        let dir = current_dir()?;

        let mut sram0_dir = dir.clone();
        sram0_dir.push("sram0");
        sram0_dir.set_extension(suffix);
        self.sram0.dump(&sram0_dir)?;

        let mut sram1_dir = dir.clone();
        sram1_dir.push("sram1");
        sram1_dir.set_extension(suffix);
        self.sram1.dump(&sram1_dir)?;

        let mut mem1_dir = dir.clone();
        mem1_dir.push("mem1");
        mem1_dir.set_extension(suffix);
        self.mem1.dump(&mem1_dir)?;

        let mut mem2_dir = dir.clone();
        mem2_dir.push("mem2");
        mem2_dir.set_extension(suffix);
        self.mem2.dump(&mem2_dir)?;
        Ok(dir)
    }
}

