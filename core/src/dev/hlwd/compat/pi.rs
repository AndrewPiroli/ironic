use anyhow::bail;
use log::{debug, info};

use crate::bus::prim::*;
use crate::bus::mmio::*;
use crate::bus::task::*;

/// Flipper IRQ lines for INTSR/INTMR
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum FlipperIrq {
    GpRuntimeError   = 0x0000_0001,
    ResetSwitch      = 0x0000_0002,
    Di               = 0x0000_0004,
    Si               = 0x0000_0008,
    Exi              = 0x0000_0010,
    Ai               = 0x0000_0020,
    Dsp              = 0x0000_0040,
    Mi               = 0x0000_0080,
    Vi               = 0x0000_0100,
    PeToken          = 0x0000_0200,
    PeFinish         = 0x0000_0400,
    CpFifo           = 0x0000_0800,
    Debugger         = 0x0000_1000,
    Hsp              = 0x0000_2000,
    HollywoodIrqs    = 0x0000_4000,

    // Not technically an IRQ
    ResetSwitchState = 0x0001_0000
}

#[derive(Debug, Default, Clone)]
#[repr(transparent)]
pub struct IrqBits(pub u32);
impl IrqBits {
    pub fn set(&mut self, irqnum: FlipperIrq) { 
        self.0 |= irqnum as u32; 
    }
    pub fn toggle(&mut self, irqnum: FlipperIrq) { 
        self.0 ^= irqnum as u32; 
    }
    pub fn unset(&mut self, irqnum: FlipperIrq) { 
        self.0 &= !(irqnum as u32); 
    }
    pub fn is_set(&self, irqnum: FlipperIrq) -> bool {
        (self.0 & irqnum as u32) != 0
    }

    pub fn gp_runtime_error(&self) -> bool  { (self.0 & 0x0000_0001) != 0 }
    pub fn reset_switch(&self) -> bool      { (self.0 & 0x0000_0002) != 0 }
    pub fn di(&self) -> bool                { (self.0 & 0x0000_0004) != 0 }
    pub fn si(&self) -> bool                { (self.0 & 0x0000_0008) != 0 }
    pub fn exi(&self) -> bool               { (self.0 & 0x0000_0010) != 0 }
    pub fn ai(&self) -> bool                { (self.0 & 0x0000_0020) != 0 }
    pub fn dsp(&self) -> bool               { (self.0 & 0x0000_0040) != 0 }
    pub fn mi(&self) -> bool                { (self.0 & 0x0000_0080) != 0 }
    pub fn vi(&self) -> bool                { (self.0 & 0x0000_0100) != 0 }
    pub fn pe_token(&self) -> bool          { (self.0 & 0x0000_0200) != 0 }
    pub fn pe_finish(&self) -> bool         { (self.0 & 0x0000_0400) != 0 }
    pub fn cp_fifo(&self) -> bool           { (self.0 & 0x0000_0800) != 0 }
    pub fn debugger(&self) -> bool          { (self.0 & 0x0000_1000) != 0 }
    pub fn hsp(&self) -> bool               { (self.0 & 0x0000_2000) != 0 }
    pub fn hollywood_irqs(&self) -> bool    { (self.0 & 0x0000_4000) != 0 }
}

/// Legacy Processor Interface
/// TODO: need functionality for reset somehow
/// TODO: when the GX FIFO is implemented, those registers would need to be connected to it
#[derive(Default, Debug, Clone)]
pub struct ProcessorInterface {
    pub intsr: IrqBits,
    pub intmr: IrqBits,
    pub fifo_base_start: u32,
    pub fifo_base_end: u32,
    pub fifo_cur_write_ptr: u32,
    pub unk_18: u32,
    pub unk_1c: u32,
    pub unk_20: u32,
    pub reset: u32,
    pub unk_28: u32,
    pub unk_2c: u32,

    /// Set when assert() fires a new interrupt; cleared after the IPC
    /// server reads it for the piggybacked IRQ byte.  This is a latch,
    /// not a level — every unmasked assert() produces a new interrupt
    /// regardless of whether INTSR was already set.
    pub irq_latch: bool,

    /// At least one unmasked IRQ is pending (INTSR & INTMR != 0).
    /// This is the steady-state level for the output line, but the
    /// latch above is what actually triggers new interrupts.
    pub irq_output: bool
}

impl ProcessorInterface {
    /// Assert a Flipper IRQ.  Always fires a new interrupt to Broadway
    /// as long as the IRQ is unmasked in INTMR — even if the INTSR bit
    /// is already set (i.e. not yet acknowledged by software).
    pub fn assert(&mut self, irq: FlipperIrq) {
        if self.intmr.is_set(irq) {
            info!(target:"PI", "Asserting PI IRQ {:08x}", irq as u32);
            self.intsr.set(irq);
            self.irq_latch = true;
            self.update_irq_lines();
        }
    }

    /// Recalculate irq_output after a register write.
    fn update_irq_lines(&mut self) {
        // Ignore Reset Switch State
        self.irq_output = ((self.intsr.0 & !0x0001_0000) & self.intmr.0) != 0;
    }
}

impl MmioDevice for ProcessorInterface {
    type Width = u32;
    fn read(&self, off: usize) -> anyhow::Result<BusPacket> {
        let val = match off {
            0x00 => self.intsr.0,
            0x04 => self.intmr.0,
            0x08 => self.fifo_base_start,
            0x10 => self.fifo_base_end,
            0x14 => self.fifo_cur_write_ptr,
            0x18 => self.unk_18,
            0x1c => self.unk_1c,
            0x20 => self.unk_20,
            0x24 => self.reset,
            0x28 => self.unk_28,
            0x2c => self.unk_2c,
            _ => { bail!("PI read from undefined offset {off:x}"); },
        };
        Ok(BusPacket::Word(val))
    }
    fn write(&mut self, off: usize, val: u32) -> anyhow::Result<Option<BusTask>> {
        match off {
            0x00 => {
                debug!(target: "PI", "status bits {:08x} cleared", val);
                self.intsr.0 &= !val;
            },
            0x04 => {
                info!(target: "PI", "INTMR={val:08x}");
                self.intmr.0 = val;
            },
            0x08 => self.fifo_base_start = val,
            0x10 => self.fifo_base_end = val,
            0x14 => self.fifo_cur_write_ptr = val,
            0x18 => self.unk_18 = val,
            0x1c => self.unk_1c = val,
            0x20 => self.unk_20 = val,
            0x24 => self.reset = val,
            0x28 => self.unk_28 = val,
            0x2c => self.unk_2c = val,
            _ => { bail!("PI write {val:08x} to undefined offset {off:x}"); },
        }
        self.update_irq_lines();
        Ok(None)
    }
}
