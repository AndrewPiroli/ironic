
use anyhow::bail;

use crate::bus::*;
use crate::bus::prim::*;
use crate::bus::task::*;

/// Interface used by the bus to perform some access on an I/O device.
pub trait MmioDevice {
    /// Width of accesses supported on this device.
    type Width;

    /// Handle a read, returning some result.
    fn read(&self, off: usize) -> anyhow::Result<BusPacket>;
    /// Handle a write, optionally returning a task for the bus.
    fn write(&mut self, off: usize, val: Self::Width) -> anyhow::Result<Option<BusTask>>;
}

/// Interface used by the bus to perform some access on an I/O device that has multiple widths.
pub trait MmioDeviceMultiWidth {
    /// Handle a 32-bit read, returning some result.
    fn read32(&self, off: usize) -> anyhow::Result<BusPacket>;
    /// Handle a 16-bit read, returning some result.
    fn read16(&self, off: usize) -> anyhow::Result<BusPacket>;
    /// Handle a 8-bit read, returning some result.
    fn read8(&self, off: usize) -> anyhow::Result<BusPacket>;

    /// Handle a 32-bit write, optionally returning a task for the bus.
    fn write32(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>>;
    /// Handle a 16-bit write, optionally returning a task for the bus.
    fn write16(&mut self, off: usize, val: u16) -> anyhow::Result<Option<BusTask>>;
    /// Handle a 8-bit write, optionally returning a task for the bus.
    fn write8(&mut self, off: usize, val: u8) -> anyhow::Result<Option<BusTask>>;
}

impl Bus {
    /// Dispatch a physical read access to some memory-mapped I/O device.
    pub fn do_mmio_read(&self, dev: IoDevice, off: usize, width: BusWidth) -> anyhow::Result<BusPacket> {
        use IoDevice::*;
        match (width, dev) {
            (BusWidth::W, Nand)  => self.nand.read(off),
            (BusWidth::W, Aes)   => self.aes.read(off),
            (BusWidth::W, Sha)   => self.sha.read(off),
            (BusWidth::W, Ehci)  => self.ehci.read(off),
            (BusWidth::W, Ohci0) => self.ohci0.read(off),
            (BusWidth::W, Ohci1) => self.ohci1.read(off),
            (BusWidth::W, Sdhc0) => self.sd0.read(off),
            (BusWidth::W, Sdhc1) => self.sd1.read(off),

            (BusWidth::W, Hlwd)  => self.hlwd.read(off),
            (BusWidth::W, Ahb)   => self.hlwd.ahb.read(off),
            (BusWidth::W, Vi)    => self.hlwd.vi.read32(off),
            (BusWidth::W, Di)    => self.hlwd.di.read(off),
            (BusWidth::W, Exi)   => self.hlwd.exi.read(off),
            (BusWidth::W, Si)    => self.hlwd.si.read(off),
            (BusWidth::W, Ai)    => self.hlwd.ai.read(off),
            (BusWidth::H, Vi)    => self.hlwd.vi.read16(off),
            (BusWidth::H, Mi)    => self.hlwd.mi.read(off),
            (BusWidth::H, Ddr)   => self.hlwd.ddr.read(off),
            _ => { bail!("Unsupported read {width:?} for {dev:?} at {off:x}"); },
        }
    }

    /// Dispatch a physical write access to some memory-mapped I/O device.
    pub fn do_mmio_write(&mut self, dev: IoDevice, off: usize, msg: BusPacket) -> anyhow::Result<()> {
        use IoDevice::*;
        use BusPacket::*;
        let task = match (msg, dev) {
            (Word(val), Nand)  => self.nand.write(off, val),
            (Word(val), Aes)   => self.aes.write(off, val),
            (Word(val), Sha)   => self.sha.write(off, val),
            (Word(val), Ehci)  => self.ehci.write(off, val),
            (Word(val), Ohci0) => self.ohci0.write(off, val),
            (Word(val), Ohci1) => self.ohci1.write(off, val),
            (Word(val), Sdhc0) => self.sd0.write(off, val),
            (Word(val), Sdhc1) => self.sd1.write(off, val),


            (Word(val), Hlwd)  => self.hlwd.write(off, val),
            (Word(val), Vi)    => self.hlwd.vi.write32(off, val),
            (Word(val), Si)    => self.hlwd.si.write(off, val),
            (Word(val), Ahb)   => self.hlwd.ahb.write(off, val),
            (Word(val), Exi)   => self.hlwd.exi.write(off, val),
            (Word(val), Di)    => self.hlwd.di.write(off, val),
            (Word(val), Ai)    => self.hlwd.ai.write(off, val),
            (Half(val), Vi)    => self.hlwd.vi.write16(off, val),
            (Half(val), Mi)    => self.hlwd.mi.write(off, val),
            (Half(val), Ddr)   => self.hlwd.ddr.write(off, val),

            _ => { bail!("Unsupported write {msg:?} for {dev:?} at {off:x}"); },
        };
        match task {
            // If the device returned some task, schedule it
            Ok(task) => {
                if let Some(t) = task {
                    self.tasks.push(Task { kind: t, target_cycle: self.cycle }); // All types get scheduled on this cycle
                    Ok(())
                }
                else {Ok(())}
            },
            Err(reason) => Err(reason)
        }
    }
}


impl Bus {
    /// Emulate a slice of work on the system bus.
    pub fn step(&mut self, cpu_cycle: usize) -> anyhow::Result<()> {
        self.handle_step_hlwd(cpu_cycle)?;
        if !self.tasks.is_empty() {
            self.drain_tasks()?;
        }
        self.cycle += 1;
        Ok(())
    }

    /// Dispatch all of the pending tasks on the Bus.
    fn drain_tasks(&mut self) -> anyhow::Result<()> {
        let mut idx = 0;
        while idx != self.tasks.len() {
            if self.tasks[idx].target_cycle <= self.cycle {
                let task = self.tasks.remove(idx);
                match task.kind {
                    BusTask::Nand(x) => self.handle_task_nand(x)?,
                    BusTask::Aes(x) => self.handle_task_aes(x)?,
                    BusTask::Sha(x) => self.handle_task_sha(x)?,
                    BusTask::Mi{kind, data} => self.handle_task_mi(kind, data)?,
                    BusTask::SetRomDisabled(x) => self.rom_disabled = x,
                    BusTask::SetMirrorEnabled(x) => self.mirror_enabled = x,
                    BusTask::SDHC(task) => self.handle_task_sdhc(task),
                }
            } else {
                idx += 1;
            }
        }
        Ok(())
    }
}

