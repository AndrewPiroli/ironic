pub mod prim;
pub mod decode;
pub mod dispatch;
pub mod mmio;
pub mod task;
use std::env::current_dir;
use std::path::Path;
use std::sync::atomic::AtomicU32;
use std::sync::OnceLock;
use log::error;

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
use gimli::Dwarf;
use gimli::EndianArcSlice;

#[derive(Default)]
pub struct DebugInfo {
    pub debuginfo: OnceLock<Dwarf<EndianArcSlice<BigEndian>>>,
    pub last_pc: AtomicU32,
    pub last_lr: AtomicU32,
}

pub static DEBUGINFO: DebugInfo = DebugInfo {
    debuginfo: OnceLock::new(),
    last_pc: AtomicU32::new(0),
    last_lr: AtomicU32::new(0),
};

/// Implementation of an emulated bus.
///
/// In this model, the bus itself owns all memories and system devices.
pub struct Bus {
    pub cache_control: std::sync::Arc<crate::cpu::icache::CacheControl>,
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
    pub sd0: SDInterface,
    pub sd1: SDInterface,

    /// True when the ROM mapping is disabled.
    pub rom_disabled: bool,
    /// True when the SRAM mirror is enabled.
    pub mirror_enabled: bool,

    /// Queue for pending work on I/O devices.
    pub tasks: Vec<Task>,
    pub cycle: usize,
}
impl Bus {
    pub fn new(boot0: &Path, nand: &Path, otp: &Path, seeprom: &Path, sd: Option<&Path>) -> anyhow::Result<Self> {
        Ok(Bus {
            cache_control: Default::default(),
            mrom: BigEndianMemory::from_file(0x0000_2000, boot0, false)?,
            sram0: BigEndianMemory::new(0x0001_0000),
            sram1: BigEndianMemory::new(0x0001_0000),
            mem1: BigEndianMemory::new(0x0180_0000),
            mem2: BigEndianMemory::new(0x0400_0000),

            hlwd: Hollywood::new(otp, seeprom)?,
            nand: NandInterface::new(nand)?,
            aes: AesInterface::new(),
            sha: ShaInterface::new(),
            ehci: EhcInterface::new(),
            ohci0: OhcInterface { idx: 0, ..Default::default() },
            ohci1: OhcInterface { idx: 1, ..Default::default() },
            sd0: SDInterface::new_sd0(sd)?,
            sd1: SDInterface::new_sd1(),

            rom_disabled: false,
            mirror_enabled: false,
            tasks: Vec::new(),
            cycle: 0,
        })
    }

    pub fn install_debuginfo(&mut self, debuginfo: Dwarf<EndianArcSlice<BigEndian>>) {
        if !DEBUGINFO.debuginfo.set(debuginfo).is_ok() {
            error!(target: "Other", "Debug info already installed");
        }
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

