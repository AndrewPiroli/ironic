
use anyhow::bail;
use log::error;

use crate::bus::*;
use crate::bus::prim::*;
use crate::bus::task::*;

/// Interface used by the bus to perform some access on an I/O device.
pub trait MmioDevice {
    /// Width of accesses supported on this device.
    type Width;

    /// Handle a read, returning some result.
    fn read(&self, access: AccessContext, off: usize) -> anyhow::Result<BusPacket>;
    /// Handle a write, optionally returning a task for the bus.
    fn write(&mut self, access: AccessContext, off: usize, val: Self::Width) -> anyhow::Result<Option<BusTask>>;
}

/// Interface used by the bus to perform some access on an I/O device that has multiple widths.
pub trait MmioDeviceMultiWidth {
    /// Handle a 32-bit read, returning some result.
    fn read32(&self, access: AccessContext, off: usize) -> anyhow::Result<BusPacket>;
    /// Handle a 16-bit read, returning some result.
    fn read16(&self, access: AccessContext, off: usize) -> anyhow::Result<BusPacket>;
    /// Handle a 8-bit read, returning some result.
    fn read8(&self, access: AccessContext, off: usize) -> anyhow::Result<BusPacket>;

    /// Handle a 32-bit write, optionally returning a task for the bus.
    fn write32(&mut self, access: AccessContext, off: usize, val: u32) -> anyhow::Result<Option<BusTask>>;
    /// Handle a 16-bit write, optionally returning a task for the bus.
    fn write16(&mut self, access: AccessContext, off: usize, val: u16) -> anyhow::Result<Option<BusTask>>;
    /// Handle a 8-bit write, optionally returning a task for the bus.
    fn write8(&mut self, access: AccessContext, off: usize, val: u8) -> anyhow::Result<Option<BusTask>>;
}

impl Bus {
    fn denied_read(reason: anyhow::Error, width: BusWidth) -> anyhow::Result<BusPacket> {
        error!(target: "BUS", "Dropping denied MMIO read: {reason}");
        Ok(match width {
            BusWidth::B => BusPacket::Byte(0),
            BusWidth::H => BusPacket::Half(0),
            BusWidth::W => BusPacket::Word(0),
            BusWidth::_32B => BusPacket::_32Byte([0; 32]),
        })
    }

    fn handle_mmio_read_result(result: anyhow::Result<BusPacket>, width: BusWidth) -> anyhow::Result<BusPacket> {
        match result {
            Err(reason) if reason.downcast_ref::<AccessError>().is_some() => {
                Self::denied_read(reason, width)
            },
            result => result,
        }
    }

    fn handle_mmio_write_result(result: anyhow::Result<Option<BusTask>>) -> anyhow::Result<Option<BusTask>> {
        match result {
            Err(reason) if reason.downcast_ref::<AccessError>().is_some() => {
                error!(target: "BUS", "Dropping denied MMIO write: {reason}");
                Ok(None)
            },
            result => result,
        }
    }

    fn check_mmio_access(&self, access: AccessContext, dev: IoDevice) -> anyhow::Result<()> {
        if access.privilege.is_none() {
            if access.requester == Requester::Arm {
                return Err(AccessError(format!("ARM cannot access legacy MMIO device {dev:?}")).into());
            }
            return Ok(());
        }

        if access.is_kernel() {
            return Ok(());
        }

        let bit = match (access.requester, dev) {
            (Requester::Ppc, IoDevice::Nand) => Some(1),
            (Requester::Ppc, IoDevice::Aes) => Some(2),
            (Requester::Ppc, IoDevice::Sha) => Some(3),
            (Requester::Ppc, IoDevice::Ehci) => Some(4),
            (Requester::Ppc, IoDevice::Ohci0) => Some(5),
            (Requester::Ppc, IoDevice::Ohci1) => Some(6),
            (Requester::Ppc, IoDevice::Sdhc0) => Some(7),
            (Requester::Ppc, IoDevice::Sdhc1) => Some(8),
            (Requester::Arm, IoDevice::Nand) => Some(17),
            (Requester::Arm, IoDevice::Aes) => Some(18),
            (Requester::Arm, IoDevice::Sha) => Some(19),
            (Requester::Arm, IoDevice::Ehci) => Some(20),
            (Requester::Arm, IoDevice::Ohci0) => Some(21),
            (Requester::Arm, IoDevice::Ohci1) => Some(22),
            (Requester::Arm, IoDevice::Sdhc0) => Some(23),
            (Requester::Arm, IoDevice::Sdhc1) => Some(24),
            (_, IoDevice::Ahb | IoDevice::Mi | IoDevice::Ddr) => {
                return Err(AccessError(format!("User {access:?} cannot access privileged MMIO device {dev:?}")).into());
            },
            _ => None,
        };

        if let Some(bit) = bit {
            if (self.hlwd.busctrl.ahbprot & (1 << bit)) == 0 {
                return Err(AccessError(format!("AHBPROT denies {access:?} access to {dev:?}")).into());
            }
        }
        Ok(())
    }

    /// Dispatch a physical read access to some memory-mapped I/O device.
    pub fn do_mmio_read(&self, access: AccessContext, dev: IoDevice, off: usize, width: BusWidth) -> anyhow::Result<BusPacket> {
        if let Err(reason) = self.check_mmio_access(access, dev) {
            return Self::denied_read(reason, width);
        }
        use IoDevice::*;
        let result = match (width, dev) {
            (BusWidth::W, Nand)  => self.nand.read(access, off),
            (BusWidth::W, Aes)   => self.aes.read(access, off),
            (BusWidth::W, Sha)   => self.sha.read(access, off),
            (BusWidth::W, Ehci)  => self.ehci.read(access, off),
            (BusWidth::W, Ohci0) => self.ohci0.read(access, off),
            (BusWidth::W, Ohci1) => self.ohci1.read(access, off),
            (BusWidth::W, Sdhc0) => self.sd0.read(access, off),
            (BusWidth::W, Sdhc1) => self.sd1.read(access, off),

            (BusWidth::_32B, PiFifo) => self.hlwd.pi_fifo.read(access, off),
            (BusWidth::W, Hlwd)  => self.hlwd.read(access, off),
            (BusWidth::W, Ahb)   => self.hlwd.ahb.read(access, off),
            (BusWidth::W, Gx)    => self.hlwd.gx.read32(access, off),
            (BusWidth::W, Vi)    => self.hlwd.vi.read32(access, off),
            (BusWidth::W, Pi)    => self.hlwd.pi.read(access, off),
            (BusWidth::W, Dsp)   => self.hlwd.dsp.read32(access, off),
            (BusWidth::W, Di)    => self.hlwd.di.read(access, off),
            (BusWidth::W, Exi)   => self.hlwd.exi.read(access, off),
            (BusWidth::W, Si)    => self.hlwd.si.read(access, off),
            (BusWidth::W, Ai)    => self.hlwd.ai.read(access, off),
            (BusWidth::H, Gx)    => self.hlwd.gx.read16(access, off),
            (BusWidth::H, Vi)    => self.hlwd.vi.read16(access, off),
            (BusWidth::H, Dsp)   => self.hlwd.dsp.read16(access, off),
            (BusWidth::H, Mi)    => self.hlwd.mi.read(access, off),
            (BusWidth::H, Ddr)   => self.hlwd.ddr.read(access, off),
            _ => { bail!("Unsupported read {width:?} for {dev:?} at {off:x}"); },
        };
        Self::handle_mmio_read_result(result, width)
    }

    /// Dispatch a physical write access to some memory-mapped I/O device.
    pub fn do_mmio_write(&mut self, access: AccessContext, dev: IoDevice, off: usize, msg: BusPacket) -> anyhow::Result<()> {
        if let Err(reason) = self.check_mmio_access(access, dev) {
            error!(target: "BUS", "Dropping denied MMIO write: {reason}");
            return Ok(());
        }
        use IoDevice::*;
        use BusPacket::*;
        let task = match (msg, dev) {
            (_32Byte(val), PiFifo) => self.hlwd.pi_fifo.write(access, off, val),
            (Word(val), Nand)  => self.nand.write(access, off, val),
            (Word(val), Aes)   => self.aes.write(access, off, val),
            (Word(val), Sha)   => self.sha.write(access, off, val),
            (Word(val), Ehci)  => self.ehci.write(access, off, val),
            (Word(val), Ohci0) => self.ohci0.write(access, off, val),
            (Word(val), Ohci1) => self.ohci1.write(access, off, val),
            (Word(val), Sdhc0) => self.sd0.write(access, off, val),
            (Word(val), Sdhc1) => self.sd1.write(access, off, val),

            (Word(val), Hlwd)  => self.hlwd.write(access, off, val),
            (Word(val), Gx)    => self.hlwd.gx.write32(access, off, val),
            (Word(val), Vi)    => self.hlwd.vi.write32(access, off, val),
            (Word(val), Pi)    => self.hlwd.pi.write(access, off, val),
            (Word(val), Dsp)   => self.hlwd.dsp.write32(access, off, val),
            (Word(val), Si)    => self.hlwd.si.write(access, off, val),
            (Word(val), Ahb)   => self.hlwd.ahb.write(access, off, val),
            (Word(val), Exi)   => self.hlwd.exi.write(access, off, val),
            (Word(val), Di)    => self.hlwd.di.write(access, off, val),
            (Word(val), Ai)    => self.hlwd.ai.write(access, off, val),
            (Half(val), Gx)    => self.hlwd.gx.write16(access, off, val),
            (Half(val), Vi)    => self.hlwd.vi.write16(access, off, val),
            (Half(val), Dsp)   => self.hlwd.dsp.write16(access, off, val),
            (Half(val), Mi)    => self.hlwd.mi.write(access, off, val),
            (Half(val), Ddr)   => self.hlwd.ddr.write(access, off, val),

            _ => { bail!("Unsupported write {msg:?} for {dev:?} at {off:x}"); },
        };
        match Self::handle_mmio_write_result(task) {
            // If the device returned some task, schedule it
            Ok(task) => {
                if let Some(t) = task {
                    self.tasks.push(Task { kind: t, target_cycle: self.cycle, access }); // All types get scheduled on this cycle
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
                let access = task.access;
                match task.kind {
                    BusTask::Nand(x) => self.handle_task_nand(x)?,
                    BusTask::Aes(x) => self.handle_task_aes(x)?,
                    BusTask::Sha(x) => self.handle_task_sha(x)?,
                    BusTask::Mi{kind, data} => self.handle_task_mi(access, kind, data)?,
                    BusTask::SetRomDisabled(x) => self.rom_disabled = x,
                    BusTask::SetMirrorEnabled(x) => self.mirror_enabled = x,
                    BusTask::SDHC(unit, task) => self.handle_task_sdhc(access, unit, task),
                    BusTask::PiFifo(burst) => self.handle_task_pi_fifo(burst)?,
                }
            } else {
                idx += 1;
            }
        }
        Ok(())
    }
}

