use gdbstub::conn::ConnectionExt;
use gdbstub::stub::run_blocking::BlockingEventLoop;
use gdbstub::stub::{run_blocking, GdbStub, SingleThreadStopReason};
use gdbstub::target::ext::breakpoints::{Breakpoints, HwBreakpoint, SwBreakpoint};
use gdbstub::target::Target;
use gdbstub::arch::Arch;
use gdbstub::target::ext::base::singlethread::*;
use gdbstub_arch::arm::{ArmBreakpointKind, reg::ArmCoreRegs, reg::id::ArmCoreRegId};

use std::net::TcpStream;
use std::ptr::copy_nonoverlapping;
use std::sync::mpmc::*;

use log::error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugCommands {
    /// Emulator Requested Stop
    EmuStop(SingleThreadStopReason<u32>),
    /// Read Registers
    ReadRegs([u32; 17]),
    /// Write Registers
    WriteRegs([u32;17]),
    /// Step n times
    Step(u32),
    /// Read at a VirtualAddress
    Peek(u32, usize),
    /// Write to a VirtualAddress
    Poke(u32, Box<[u8]>),
    /// Move Data
    Data(Box<[u8]>),
    /// User pressed Ctrl-C in gdb
    CtrlC,
    /// Acknowledgement
    Ack,
    /// Debugger Disconnected
    Kms,
    /// Resume execution
    Resume,
    /// Add breakpoint
    AddBkpt(u32),
    /// Remove breakpoint
    RemoveBkpt(u32),
}

pub struct DebugProxy {
    pub emu_tx: Sender<DebugCommands>,
    pub emu_rx: Receiver<DebugCommands>,
    pub sr_tx: Sender<SingleThreadStopReason<u32>>,
    sr_rx: Receiver<SingleThreadStopReason<u32>>,
    dbg_tx: Sender<DebugCommands>,
    dbg_rx: Receiver<DebugCommands>,
}

impl DebugProxy {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        let (tx2, rx2) = channel();
        let (sr_tx, sr_rx) = channel();
        Self { 
            emu_tx: tx,
            emu_rx: rx2,
            sr_tx,
            sr_rx,
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
            sr_tx: self.sr_tx.clone(),
            sr_rx: self.sr_rx.clone(),
            dbg_tx: self.dbg_tx.clone(),
            dbg_rx: self.dbg_rx.clone()
        }
    }
}

pub struct Armv5TE;
impl Arch for Armv5TE {
    type Usize = u32;
    type Registers = ArmCoreRegs;
    type BreakpointKind = ArmBreakpointKind;
    type RegId = ArmCoreRegId;
}

impl Target for DebugProxy {
    type Arch = Armv5TE;
    type Error = ();
    fn base_ops(&mut self) -> gdbstub::target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
        gdbstub::target::ext::base::BaseOps::SingleThread(self)
    }
    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }
}
impl SingleThreadBase for DebugProxy {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> gdbstub::target::TargetResult<(), Self> {
        self.dbg_tx.send(DebugCommands::ReadRegs([0;17])).unwrap();
        let cpuregs = self.dbg_rx.recv().unwrap();
        if let DebugCommands::ReadRegs(cpuregs) = cpuregs {
            unsafe { copy_nonoverlapping(cpuregs.as_ptr(), regs.r.as_mut_ptr(), 13); }
            regs.sp = cpuregs[13];
            regs.lr = cpuregs[14];
            regs.pc = cpuregs[15];
            regs.cpsr = cpuregs[16];
        }
        else { dbg!(cpuregs); panic!() }
        Ok(())
    }

    fn write_registers(&mut self, regs: &<Self::Arch as Arch>::Registers) -> gdbstub::target::TargetResult<(), Self> {
        let mut cpuregs = [0;17];
        unsafe { copy_nonoverlapping(regs.r.as_ptr(), cpuregs.as_mut_ptr(), 13); }
        cpuregs[13] = regs.sp;
        cpuregs[14] = regs.lr;
        cpuregs[15] = regs.pc;
        cpuregs[16] = regs.cpsr;
        self.dbg_tx.send(DebugCommands::WriteRegs(cpuregs)).unwrap();
        if let DebugCommands::Ack = self.dbg_rx.recv().unwrap() {}
        else { panic!() }
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> gdbstub::target::TargetResult<usize, Self> {
        self.dbg_tx.send(DebugCommands::Peek(start_addr, data.len())).unwrap();
        if let DebugCommands::Data(readres) = self.dbg_rx.recv().unwrap() {
            let len = core::cmp::min(data.len(), readres.len());
            unsafe { copy_nonoverlapping(readres.as_ptr(), data.as_mut_ptr(), len); }
            return Ok(len)
        }
        panic!()
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> gdbstub::target::TargetResult<(), Self> {
        self.dbg_tx.send(DebugCommands::Poke(start_addr, Box::from(data))).unwrap();
        if let DebugCommands::Ack = self.dbg_rx.recv().unwrap() {
            Ok(())
        }
        else { panic!() }
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadResume for DebugProxy {
    fn resume(&mut self, signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        let _ = signal;
        self.dbg_tx.send(DebugCommands::Resume).unwrap();
        if let DebugCommands::Ack = self.dbg_rx.recv().unwrap() {
            Ok(())
        }
        else { panic!() }
    }
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for DebugProxy {
    fn step(&mut self, signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        let _ = signal;
        self.dbg_tx.send(DebugCommands::Step(1)).unwrap();
        if let DebugCommands::Ack = self.dbg_rx.recv().unwrap() {
            Ok(())
        }
        else { panic!() }
    }
}

impl Breakpoints for DebugProxy {
    fn support_sw_breakpoint(&mut self) -> Option<gdbstub::target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
        None
    }
    fn support_hw_breakpoint(&mut self) -> Option<gdbstub::target::ext::breakpoints::HwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for DebugProxy {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        let _ = kind;
        self.dbg_tx.send(DebugCommands::AddBkpt(addr)).unwrap();
        if let DebugCommands::Ack = self.dbg_rx.recv().unwrap() {
            Ok(true)
        }
        else {
            Ok(false)
        }
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        let _ = kind;
        self.dbg_tx.send(DebugCommands::RemoveBkpt(addr)).unwrap();
        if let DebugCommands::Ack = self.dbg_rx.recv().unwrap() {
            Ok(true)
        }
        else {
            Ok(false)
        }
    }
}
impl HwBreakpoint for DebugProxy {
    fn add_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        self.add_sw_breakpoint(addr, kind)
    }

    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> gdbstub::target::TargetResult<bool, Self> {
        self.remove_sw_breakpoint(addr, kind)
    }
}

enum GdbEventLoop {}

impl gdbstub::stub::run_blocking::BlockingEventLoop for GdbEventLoop {
    type Target = DebugProxy;

    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;

    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        gdbstub::stub::run_blocking::Event<Self::StopReason>,
        gdbstub::stub::run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        use std::time::Duration;
        loop {
            // ck for message
            if target.sr_rx.len() != 0 {
                match target.sr_rx.recv_timeout(Duration::from_nanos(0)) {
                    Ok(sr) => {
                        return Ok(run_blocking::Event::TargetStopped(sr));
                    }
                    _ => {},
                }
            }
            match conn.peek() {
                Ok(Some(byte)) => {
                    // don't forget to read out this data
                    let _ = conn.read().unwrap();
                    return Ok(run_blocking::Event::IncomingData(byte));
                },
                Ok(None) => {}
                Err(e) => { return Err(run_blocking::WaitForStopReasonError::Connection(e)); },
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        target.dbg_tx.send(DebugCommands::CtrlC).unwrap();
        Ok(None)
    }
}

pub fn gdb_thread(mut proxy: DebugProxy, stream: TcpStream) {
    let boxed = Box::new(stream) as Box<dyn ConnectionExt<Error = std::io::Error>>;
    let x = GdbStub::<'_, DebugProxy, <GdbEventLoop as BlockingEventLoop>::Connection>::new(boxed);
    match x.run_blocking::<GdbEventLoop>(&mut proxy) {
        Ok(dc) => {
            match dc {
                gdbstub::stub::DisconnectReason::Disconnect => {
                    proxy.dbg_tx.send(DebugCommands::Kms).unwrap();
                    return;
                },
                gdbstub::stub::DisconnectReason::Kill |
                gdbstub::stub::DisconnectReason::TargetExited(_) |
                gdbstub::stub::DisconnectReason::TargetTerminated(_) => todo!(),
            }
        },
        Err(y) => {
            if y.is_target_error() {
                return;
            }
            else if y.is_connection_error() {
                proxy.dbg_tx.send(DebugCommands::Kms).unwrap();
                return
            }
            else {
                error!("GDBSTUB err: {y:?}");
                return;
            }
        },
    }
}