pub mod prim;
pub mod decode;
pub mod dispatch;
pub mod mmio;
pub mod task;
use std::env::temp_dir;

use crate::bus::task::*;

use crate::mem::*;
use crate::dev::hlwd::*;
use crate::dev::aes::*;
use crate::dev::sha::*;
use crate::dev::nand::*;
use crate::dev::ehci::*;
use crate::dev::ohci::*;
use crate::dev::sdhc::*;


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
    pub sd0: SDInterface,
    pub sd1: WLANInterface,

    /// True when the ROM mapping is disabled.
    pub rom_disabled: bool,
    /// True when the SRAM mirror is enabled.
    pub mirror_enabled: bool,

    /// Queue for pending work on I/O devices.
    pub tasks: Vec<Task>,
    pub cycle: usize,
    pub debug: bool,
    pub debug_allowed_cycles: u64,
}
impl Bus {
    pub fn new()-> anyhow::Result<Self> {
        Ok(Bus {
            mrom: BigEndianMemory::new(0x0000_2000, Some("./boot0.bin"))?,
            sram0: BigEndianMemory::new(0x0001_0000, None)?,
            sram1: BigEndianMemory::new(0x0001_0000, None)?,
            mem1: BigEndianMemory::new(0x0180_0000, None)?,
            mem2: BigEndianMemory::new(0x0400_0000, None)?,

            hlwd: Hollywood::new()?,
            nand: NandInterface::new("./nand.bin")?,
            aes: AesInterface::new(),
            sha: ShaInterface::new(),
            ehci: EhcInterface::new(),
            ohci0: OhcInterface { idx: 0, ..Default::default() },
            ohci1: OhcInterface { idx: 1, ..Default::default() },
            sd0: SDInterface::default(),
            sd1: WLANInterface::default(),

            rom_disabled: false,
            mirror_enabled: false,
            tasks: Vec::new(),
            cycle: 0,
            debug: false,
            debug_allowed_cycles: 0,
        })
    }

    pub fn dump_memory(&self, suffix: &'static str) -> anyhow::Result<std::path::PathBuf> {
        let dir = temp_dir();

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

