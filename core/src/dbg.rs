pub mod ios;

use fxhash::FxHashSet;

use crate::bus::prim::BusWidth;

use std::sync::mpmc::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bytes(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugCommands {
    /// Read Registers
    ReadRegs([u32; 17]),
    /// Write Registers
    WriteRegs([u32;17]),
    /// Step n times
    Step(u32),
    /// Read bytes at a VirtualAddress with specified organization
    Peek(u32, BusWidth, Bytes),
    /// Write to a VirtualAddress with organization
    Poke(u32, BusWidth, Box<[u8]>),
    /// Move Data
    Data(Box<[u8]>),
    /// User requested break
    CtrlC,
    /// Acknowledgement
    Ack,
    /// Failure
    Fail,
    /// Debugger Disconnected
    Kms,
    /// Resume execution
    Resume,
    /// List Breakpoints
    ListBreakpoints(FxHashSet<u32>),
    /// Add breakpoint
    AddBkpt(u32),
    /// Remove breakpoint
    RemoveBkpt(u32),
    /// Request dissassembly of some memory, true for ARM mode, false for Thumb
    Diassemble((u32, bool)),
    /// Check or Set Console Debug Print mode
    ConsoleDebug(Option<bool>),
}

#[derive(Debug)]
pub struct DebugProxy {
    pub emu_tx: Sender<DebugCommands>,
    pub emu_rx: Receiver<DebugCommands>,
    pub dbg_tx: Sender<DebugCommands>,
    pub dbg_rx: Receiver<DebugCommands>,
}

impl DebugProxy {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        let (tx2, rx2) = channel();
        Self { 
            emu_tx: tx,
            emu_rx: rx2,
            dbg_tx: tx2,
            dbg_rx: rx
        }
    }
}
impl Clone for DebugProxy {
    fn clone(&self) -> Self {
        Self {
            emu_tx: self.emu_tx.clone(),
            emu_rx: self.emu_rx.clone(),
            dbg_tx: self.dbg_tx.clone(),
            dbg_rx: self.dbg_rx.clone()
        }
    }
}