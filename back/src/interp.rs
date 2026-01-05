//! The interpreter backend.

pub mod arm;
pub mod thumb;
pub mod dispatch;
pub mod lut;

use anyhow::anyhow;
use fxhash::FxHashSet;
use gimli::{BigEndian, read::*};
use ironic_core::bus::prim::BusWidth;
use log::{error, info};
use parking_lot::RwLock;

use std::sync::Arc;
use std::fs;
use std::time::Duration;

extern crate elf;

use crate::back::*;
use crate::interp::lut::*;
use crate::interp::dispatch::DispatchRes;

use crate::decode::arm::*;
use crate::decode::thumb::*;

use ironic_core::bus::*;
use ironic_core::cpu::{Cpu, CpuRes};
use ironic_core::cpu::reg::Reg;
use ironic_core::cpu::excep::ExceptionType;
use ironic_core::dbg::DebugProxy;

static PPC_EARLY_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A list of known boot1 hashes in OTP
/// https://wiibrew.org/wiki/Boot1
static BOOT1_VERSIONS: &[([u32;5], &str)] = &[
    ([0x0, 0x0, 0x0, 0x0, 0x0], "? - OTP NOT FACTORY PROGRAMMED!"),
    ([0xb30c32b9, 0x62c7cd08, 0xabe33d01, 0x5b9b8b1d, 0xb1097544], "a"),
    ([0xef3ef781, 0x09608d56, 0xdf5679a6, 0xf92e13f7, 0x8bbddfdf], "b"),
    ([0xd220c8a4, 0x86c631d0, 0xdf5adb31, 0x96ecbc66, 0x8780cc8d], "c"),
    ([0xf793068a, 0x09e80986, 0xe2a023c0, 0xc23f0614, 0x0ed16974], "d"),
];


/// Current stage in the platform's boot process.
#[derive(PartialEq)]
pub enum BootStatus { 
    /// Execution in the mask ROM.
    Boot0,
    /// Execution in the first-stage bootloader.
    Boot1,
    /// Execution in the second-stage bootloader stub.
    Boot2Stub,
    /// Execution in the second-stage bootloader.
    Boot2,
    /// Execution in the kernel.
    IOSKernel,

    /// Execution in a user-loaded foreign kernel.
    UserKernelStub,
    UserKernel,
}

impl ToString for BootStatus {
    fn to_string(&self) -> String {
        match self {
            Self::Boot0 => "Boot0",
            Self::Boot1 => "Boot1",
            Self::Boot2Stub => "Boot2Stub",
            Self::Boot2 => "Boot2",
            Self::IOSKernel => "IOSKernel",
            Self::UserKernelStub => "UserKernelStub",
            Self::UserKernel => "UserKernel",
        }.to_owned()
    }
}

enum DebugState {
    Run,
    Pause,
    SingleStep,
    DoneStepPause,
    HitBkpt,
}
impl ToString for DebugState {
    fn to_string(&self) -> String {
        match self {
            Self::Run => "Run",
            Self::Pause => "Pause",
            Self::SingleStep => "SingleStep",
            Self::DoneStepPause => "DoneStepPause",
            Self::HitBkpt => "HitBkpt",
        }.to_owned()
    }
}

struct Debugger {
    state: DebugState,
    proxy: DebugProxy,
    bkpts: FxHashSet<u32>,
}

/// Backend for interpreting-style emulation. 
///
/// Right now, the main loop works like this:
///
/// - Execute all pending work on the bus
/// - Update the state of any signals from the bus to the CPU
/// - Decode/dispatch an instruction, mutating the CPU state
///
/// For now it's sufficient to perfectly interleave bus and CPU cycles, but
/// maybe at some point it will become more efficient to let dispatched
/// instructions return some hint to the backend (requesting that a bus cycle
/// should be completed before the next instruction).

pub struct InterpBackend {
    /// Reference to a bus (attached to memories and devices).
    pub bus: Arc<RwLock<Bus>>,

    /// The CPU state.
    pub cpu: Cpu,

    /// Number of CPU cycles elapsed.
    pub cpu_cycle: usize,
    /// Number of bus cycles elapsed.
    pub bus_cycle: usize,

    /// Buffer for semi-hosting debug writes.
    pub svc_buf: String,
    /// Current stage in the platform boot process.
    pub boot_status: BootStatus,
    pub custom_kernel: Option<String>,
    debugger: Option<Debugger>,
}
impl InterpBackend {
    pub fn new(bus: Arc<RwLock<Bus>>, custom_kernel: Option<String>, ppc_early_on: bool, debugger: Option<DebugProxy>) -> Self {
        if ppc_early_on {
            PPC_EARLY_ON.store(true, std::sync::atomic::Ordering::Release);
        }

        let mut ret = InterpBackend {
            svc_buf: String::new(),
            cpu: Cpu::new(bus.clone()),
            boot_status: BootStatus::Boot0,
            cpu_cycle: 0,
            bus_cycle: 0,
            bus,
            custom_kernel,
            debugger: None,
        };
        if let Some(proxy) = debugger {
            ret.debugger = Some(Debugger { state: DebugState::DoneStepPause, proxy: proxy, bkpts: FxHashSet::default() });
        }
        ret
    }
}

impl InterpBackend {
    /// Check if we need to update the current boot stage.
    pub fn update_boot_status(&mut self) {
        match self.boot_status {
            BootStatus::Boot0 => {
                if self.cpu.read_fetch_pc() == 0xfff0_0000 {
                    if let Some(bus) = self.bus.try_read_for(Duration::new(1,0)) { // Try to detect boot1 version
                        let boot1_otp_hash =
                        [
                            bus.hlwd.otp.read(0),
                            bus.hlwd.otp.read(1),
                            bus.hlwd.otp.read(2),
                            bus.hlwd.otp.read(3),
                            bus.hlwd.otp.read(4),
                        ];
                        let mut version = "? (unknown)";
                        for known_versions in BOOT1_VERSIONS {
                            if boot1_otp_hash == known_versions.0 {
                                version = known_versions.1;
                                break;
                            }
                        }
                        info!(target: "Other", "Entered boot1. Version: boot1{version}");
                    }
                    else { // Couldn't get bus -> no problem skip it.
                        info!(target: "Other", "Entered boot1");
                    }
                    self.boot_status = BootStatus::Boot1;
                }
            }
            BootStatus::Boot1 => {
                if self.cpu.read_fetch_pc() == 0xfff0_0058 {
                    info!(target: "Other", "Entered boot2 stub");
                    self.boot_status = BootStatus::Boot2Stub;
                }
            }
            BootStatus::Boot2Stub => {
                if self.cpu.read_fetch_pc() == 0xffff_0000 {
                    info!(target: "Other", "Entered boot2");
                    self.boot_status = BootStatus::Boot2;
                }
            }
            BootStatus::Boot2 => {
                if self.cpu.read_fetch_pc() == 0xffff_2224 {
                    info!(target: "Other", "Entered kernel");
                    self.boot_status = BootStatus::IOSKernel;
                }
            }
            BootStatus::IOSKernel => {
                if self.cpu.read_fetch_pc() == 0x0001_0000 {
                    info!(target: "Other", "Entered foreign kernel stub");
                    self.boot_status = BootStatus::UserKernelStub;
                }
            }
            BootStatus::UserKernelStub=> {
                if self.cpu.read_fetch_pc() == 0xffff_0000 {
                    info!(target: "Other", "Entered foreign kernel");
                    self.boot_status = BootStatus::UserKernel;
                }
            },
            _ => {},
        }
    }

    /// Write semihosting debug strings to stdout.
    pub fn svc_read(&mut self) -> anyhow::Result<()> {
        use ironic_core::cpu::mmu::prim::{TLBReq, Access};

        // On the SVC calls, r1 should contain a pointer to some buffer.
        // They might be virtual addresses, so we need to do an out-of-band
        // request to MMU code in order to resolve the actual location.
        let paddr = match self.cpu.translate(
            TLBReq::new(self.cpu.reg.r[1], Access::Debug)
        ) {
            Ok(val) => val,
            Err(reason) => return Err(reason),
        };

        // Pull the buffer out of guest memory
        // Official code only sends 15 chars + null byte at a time
        // Probably a limitation of their early semihosting hardware
        // We buffer that internally until we see a newline, that's our cue to print
        let mut line_buf = [0u8; 16];
        self.bus.read().dma_read(paddr, &mut line_buf)?;

        let s = std::str::from_utf8(&line_buf)?
            .trim_matches(char::from(0));
        self.svc_buf += s;

        if let Some(idx) = self.svc_buf.find('\n') {
            let string: String = self.svc_buf.chars()
                .take(idx).collect();
            info!(target: "SVC", "{string}");
            self.svc_buf.clear();
        }
        Ok(())
    }

    /// Log IOS syscalls to stdout.
    pub fn syscall_log(&mut self, opcd: u32) {
        info!(target: "Other", "IOS syscall {opcd:08x}, lr={:08x}", self.cpu.reg[Reg::Lr]);
    }

    /// Write the current instruction to stdout.
    pub fn dbg_print(&mut self) -> anyhow::Result<()> {
        let pc = self.cpu.read_fetch_pc();
        if self.cpu.dbg_on {
            if self.cpu.reg.cpsr.thumb() {
                let opcd = self.cpu.read16(pc)?;
                let inst = ThumbInst::decode(opcd);
                if let ThumbInst::BlImmSuffix = inst {
                    return Ok(());
                }
                let name = format!("{:?}", ThumbInst::decode(opcd));
                info!(target: "Other", "({opcd:08x}) {name:12} {:x?}", self.cpu.reg);
                //info!(target: "Other", "{:?}", self.cpu.reg);
            } else {
                let opcd = self.cpu.read32(pc)?;
                let name = format!("{:?}", ArmInst::decode(opcd));
                info!(target: "Other", "({opcd:08x}) {name:12} {:x?}", self.cpu.reg);
                //info!(target: "Other", "{:?}", self.cpu.reg);
            };
        }
        Ok(())
    }

    /// Patch containing a call to ThreadCancel()
    const THREAD_CANCEL_PATCH: [u8; 0x8] = [
        // e6000050 .word   0xe6000050
        0xe6, 0x00, 0x00, 0x50,
        // e12fff1e bx      lr
        0xe1, 0x2f, 0xff, 0x1e,
    ];

    /// Skyeye intentionally kills a bunch of threads, specifically NCD, KD,
    /// WL, and WD; presumably to avoid having to deal with emulating WLAN.
    pub fn hotpatch_check(&mut self) -> anyhow::Result<()> {
        use ironic_core::cpu::mmu::prim::{TLBReq, Access};
        if self.boot_status == BootStatus::IOSKernel {
            let pc = self.cpu.read_fetch_pc();
            let vaddr = match pc {
                0x13d9_0024 | // NCD
                0x13db_0024 | // KD
                0x13ed_0024 | // WL
                0x13eb_0024 => Some(pc), // WD
                _ => None
            };
            if let Some(vaddr) = vaddr {
                let paddr = self.cpu.translate(
                    TLBReq::new(vaddr, Access::Debug)
                )?;
                info!(target: "Other", "DBG hotpatching module entrypoint {paddr:08x}");
                info!(target: "Other", "{:?}", self.cpu.reg);
                self.bus.write().dma_write(paddr,
                    &Self::THREAD_CANCEL_PATCH)?;
            }
        }
        Ok(())
    }

    /// Do a single step of the CPU.
    pub fn cpu_step(&mut self) -> CpuRes {
        assert!((self.cpu.read_fetch_pc() & 1) == 0);

        // Sample the IRQ line. If the IRQ line is high and IRQs are not 
        // disabled in the CPSR, take an IRQ exception. 
        if !self.cpu.reg.cpsr.irq_disable() && self.cpu.irq_input {
            if let Err(reason) = self.cpu.generate_exception(ExceptionType::Irq){
                return CpuRes::HaltEmulation(reason);
            };
        }

        // Fetch/decode/execute an ARM or Thumb instruction depending on
        // the state of the Thumb flag in the CPSR.
        let disp_res = if self.cpu.reg.cpsr.thumb() {
            self.dbg_print().unwrap_or_default(); // Ok to fail - just a debug print
            let opcd = match self.cpu.read16(self.cpu.read_fetch_pc()) {
                Ok(val) => val,
                Err(reason) => {
                    return CpuRes::HaltEmulation(reason);
                }
            };
            let func = INTERP_LUT.thumb.lookup(opcd);
            func.0(&mut self.cpu, opcd)
        } else {
            self.dbg_print().unwrap_or_default(); // Ok to fail - just a debug print
            let opcd = match self.cpu.read32(self.cpu.read_fetch_pc()) {
                Ok(val) => val,
                Err(reason) => {
                    return CpuRes::HaltEmulation(reason);
                }
            };
            match self.cpu.reg.cond_pass(opcd) {
                Ok(cond_did_pass) => {
                    if cond_did_pass {
                        let func = INTERP_LUT.arm.lookup(opcd);
                        func.0(&mut self.cpu, opcd)
                    } else {
                        DispatchRes::CondFailed
                    }
                },
                Err(reason) => {
                    DispatchRes::FatalErr(reason)
                }
            }
        };

        // Depending on the instruction, adjust the program counter
        let cpu_res = match disp_res {
            DispatchRes::Breakpoint => {
                // self.debugger_attached = true;
                self.cpu.increment_pc();
                CpuRes::StepOk
            }
            DispatchRes::RetireBranch => { CpuRes::StepOk },
            DispatchRes::RetireOk | 
            DispatchRes::CondFailed => {
                self.cpu.increment_pc(); 
                CpuRes::StepOk
            },

            DispatchRes::Exception(e) => {
                if e == ExceptionType::Swi {
                    // Detect if this is an SVC 0xAB
                    // If so this is a semihosting debug print and we need to handle it
                    // Note, the PC has not yet been advanced!
                    if self.cpu.reg.cpsr.thumb() {
                        let opcd = self.cpu.read16(self.cpu.read_fetch_pc()).unwrap_or_default(); // Fail gracefully
                        if opcd == 0xdfab { // thumb svc 0xAB
                            self.cpu.increment_pc();
                            return CpuRes::Semihosting;
                        }
                    }
                    else {
                        let opcd = self.cpu.read32(self.cpu.read_fetch_pc()).unwrap_or_default(); // Fail gracefully
                        // strip condition (it must have already passed) and opcode bits
                        let opcd = opcd & 0x00ff_ffff;
                        if opcd == 0xAB {
                            self.cpu.increment_pc();
                            return CpuRes::Semihosting;
                        }
                    }
                    // fall through all other Swis to the exception handler
                }
                if let Err(reason) = self.cpu.generate_exception(e){
                    return CpuRes::HaltEmulation(reason);
                };
                CpuRes::StepException(e)
            },

            DispatchRes::FatalErr(reason) => {
                CpuRes::HaltEmulation(reason)
            },
        };

        self.update_boot_status();
        cpu_res
    }

    fn remote_dbg(&mut self) -> bool {
        use ironic_core::dbg::DebugCommands;
        use ironic_core::cpu::mmu::prim::*;
        use ironic_core::cpu::reg::Reg;
        use ironic_core::cpu::psr::Psr;
        use core::ptr::copy_nonoverlapping;
        let debugger = self.debugger.as_mut().unwrap();
        let x = &debugger.proxy;
        let (tx, rx) = (&x.emu_tx, &x.emu_rx);
        loop {
            if let DebugState::DoneStepPause | DebugState::HitBkpt = debugger.state {
                debugger.state = DebugState::Pause;
            }
            match rx.recv_timeout(Duration::from_nanos(1)) {
                Ok(dc) => match dc {
                    DebugCommands::ReadRegs(_) => {
                        let mut reply = [0u32;17];
                        unsafe {
                            copy_nonoverlapping(self.cpu.reg.r.as_ptr(), reply.as_mut_ptr(), 13);
                        }
                        reply[13] = self.cpu.reg[Reg::Sp];
                        reply[14] = self.cpu.reg[Reg::Lr];
                        reply[15] = self.cpu.read_fetch_pc();
                        reply[16] = self.cpu.reg.cpsr.0;
                        tx.send(DebugCommands::ReadRegs(reply)).unwrap();
                    },
                    DebugCommands::WriteRegs(new_regs) => {
                        unsafe {
                            copy_nonoverlapping(new_regs.as_ptr(), self.cpu.reg.r.as_mut_ptr(), 13);
                        }
                        self.cpu.reg[Reg::Sp] = new_regs[13];
                        self.cpu.reg[Reg::Lr] = new_regs[14];
                        self.cpu.write_exec_pc(new_regs[15]);
                        self.cpu.reg.cpsr = Psr(new_regs[16]);
                        tx.send(DebugCommands::Ack).unwrap();
                    },
                    DebugCommands::Step(n) => {
                        if n > 1 { unimplemented!() }
                        debugger.state = DebugState::SingleStep;
                        tx.send(DebugCommands::Ack).unwrap();
                    },
                    DebugCommands::Peek(peek_va, org, sz ) => {
                        use ironic_core::bus::prim::BusWidth;
                        let sz = sz.0 as usize;
                        let pa = self.cpu.translate(TLBReq { vaddr: VirtAddr(peek_va), kind: Access::Debug }).unwrap();
                        let mut data = vec!(0u8; sz);
                        {
                            let bus = self.bus.write();
                            match org {
                                BusWidth::B => {
                                    bus.debug_read(pa, &mut data).unwrap();
                                },
                                BusWidth::H => {
                                    let mut unfortunate_memcpy = vec!(0u16;(sz / 2) + 1);
                                    let org_len = sz / 2;
                                    for i in 0..org_len {
                                        unfortunate_memcpy[i] = u16::from_be(bus.read16(pa + (2*i as u32)).unwrap());
                                    }
                                    data.copy_from_slice(unsafe { core::slice::from_raw_parts(unfortunate_memcpy.as_ptr() as *const u8, sz) });
                                },
                                BusWidth::W => {
                                    let mut unfortunate_memcpy = vec!(0u32;(sz / 4) + 1);
                                    let org_len = sz / 4;
                                    for i in 0..org_len {
                                        unfortunate_memcpy[i] = u32::from_be(bus.read32(pa + (4*i as u32)).unwrap());
                                    }
                                    data.copy_from_slice(unsafe { core::slice::from_raw_parts(unfortunate_memcpy.as_ptr() as *const u8, sz) });
                                },
                            }
                        }
                        data.truncate(sz);
                        tx.send(DebugCommands::Data(data.into_boxed_slice())).unwrap();
                    },
                    DebugCommands::Poke(poke_va, org, data) => {
                        let pa = self.cpu.translate(TLBReq { vaddr: VirtAddr(poke_va), kind: Access::Debug }).unwrap();
                        {
                            let mut bus = self.bus.write();
                            match org {
                                BusWidth::B => {
                                    bus.debug_write(pa, &data).unwrap();
                                },
                                BusWidth::H => {
                                    let data2:Vec<u16> = data.chunks_exact(2).into_iter().map(|x|u16::from_ne_bytes([x[1], x[0]])).collect();
                                    for (cnt, h) in data2.iter().enumerate() {
                                        bus.write16(pa + (cnt as u32 *2), *h).unwrap();
                                    }
                                },
                                BusWidth::W => {
                                    let data4:Vec<u32> = data.chunks_exact(4).into_iter().map(|x|u32::from_ne_bytes([x[3], x[2], x[1], x[0]])).collect();
                                    for (cnt, h) in data4.iter().enumerate() {
                                        bus.write32(pa + (cnt as u32 *2), *h).unwrap();
                                    }
                                },
                            }
                        }
                        tx.send(DebugCommands::Ack).unwrap();
                    },
                    DebugCommands::Resume => {
                        // update dbgstate
                        debugger.state = DebugState::Run;
                        tx.send(DebugCommands::Ack).unwrap();
                    }
                    DebugCommands::CtrlC => {
                        debugger.state = DebugState::SingleStep;
                        tx.send(DebugCommands::Ack).unwrap();
                    }
                    DebugCommands::Kms => {
                        return true;
                    }
                    DebugCommands::ListBreakpoints(_) => {
                        tx.send(DebugCommands::ListBreakpoints(debugger.bkpts.clone())).unwrap();
                    }
                    DebugCommands::AddBkpt(addr) => {
                        debugger.bkpts.insert(addr);
                        tx.send(DebugCommands::Ack).unwrap();
                    },
                    DebugCommands::RemoveBkpt(addr) => {
                        debugger.bkpts.remove(&addr);
                        tx.send(DebugCommands::Ack).unwrap();
                    },
                    DebugCommands::Diassemble((addr, arm_mode)) => {
                        let paddr = self.cpu.translate(TLBReq { vaddr: VirtAddr(addr), kind: Access::Debug }).unwrap();
                        let bus = self.cpu.bus.read();
                        let dissassemble_res = if arm_mode {
                            let opcd = bus.read32(paddr).unwrap();
                            drop(bus);
                            crate::bits::disassembly::disassmble_arm(opcd, addr)
                        } else {
                            let opcd = bus.read16(paddr).unwrap();
                            drop(bus);
                            crate::bits::disassembly::disassmble_thumb(opcd, addr)
                        };
                        let response = match dissassemble_res {
                            Ok(s) => { s.into_bytes().into_boxed_slice() },
                            Err(err) => {
                                let mut s = format!("Error {} disassembling {addr}\n", if arm_mode {"ARM" } else { "Thumb" });
                                s += &err.to_string();
                                s.into_bytes().into_boxed_slice()
                            },
                        };
                        tx.send(DebugCommands::Data(response)).unwrap();
                    }
                    DebugCommands::ConsoleDebug(set) => {
                        if let Some(set) = set {
                            self.cpu.dbg_on = set;
                            tx.send(DebugCommands::Ack).unwrap();
                        }
                        else {
                            tx.send(DebugCommands::ConsoleDebug(Some(self.cpu.dbg_on))).unwrap();
                        }
                    },
                    DebugCommands::VirtualToPhysical(access, vaddr) => {
                        use ironic_core::cpu::mmu::prim::*;
                        let request = TLBReq::new(vaddr, access);
                        match self.cpu.translate(request) {
                            Ok(paddr) => tx.send(DebugCommands::VirtualToPhysical(access, paddr)).unwrap(),
                            Err(err) => tx.send(DebugCommands::Fail(Some(err.to_string()))).unwrap(),
                        }
                    },
                    #[allow(unused_assignments)]
                    DebugCommands::Status(mut s) => {
                        let (mut rom, mut mirror) = ("Unknown", "Unknown");
                        if let Some(bus) = self.bus.try_read_for(Duration::from_millis(150)) {
                            rom = if bus.rom_disabled { "Masked" } else { "Enabled" };
                            mirror = if bus.mirror_enabled { "Enabled" } else { "Disabled" };
                        }
                        s = format!("Boot Status: {}\nDebug Status: {}\nCPU Cycle: {}\nBus Cycle: {}\nMirror Config:\n - Boot0: {}\n - SRAM Mirror: {}",
                            self.boot_status.to_string(),
                            debugger.state.to_string(),
                            self.cpu_cycle,
                            self.bus_cycle,
                            rom,
                            mirror,
                        );
                        tx.send(DebugCommands::Status(s)).unwrap();
                    }
                    DebugCommands::Data(_) |
                    DebugCommands::Fail(_) |
                    DebugCommands::Ack => todo!(),
                },
                Err(_) => {},
            }
            match debugger.state {
                DebugState::Run => break false,
                DebugState::Pause => continue,
                DebugState::HitBkpt |
                DebugState::DoneStepPause => { unreachable!() },
                DebugState::SingleStep => {
                    break false;
                },
            }
        }
    }
}

impl Backend for InterpBackend {
    fn run(&mut self) -> anyhow::Result<()> {
        if self.custom_kernel.is_some() {
            // Read the user supplied kernel file
            let filename = self.custom_kernel.as_ref().unwrap();
            let mut kernel_bytes = fs::read(filename).map_err(|ioerr| anyhow!("Error opening kernel file: {filename}. Got error: {ioerr}"))?;
            let kernel_elf = elf::File::open_stream(&mut std::io::Cursor::new(&mut kernel_bytes))?;
            match validate_custom_kernel(&kernel_elf.ehdr) {
                std::result::Result::Ok(_) => {/* We have a valid ELF (probably) */},
                std::result::Result::Err(p) => {
                    error!(target: "Custom Kernel", "!!!!!!!!!!");
                    error!(target: "Custom Kernel", "Custom Kernel ELF header validation failed. Things may not work as expected.");
                    error!(target: "Custom Kernel", "Failed validations:");
                    for problem in p {
                        error!(target: "Custom Kernel", "{}", problem);
                    }
                    error!(target: "Custom Kernel", "!!!!!!!!!");
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    // We try to continue, chances are we crash and burn shortly after this
                    // but on the chance this mangled ELF executes for a while via dumb luck
                    // we sleep for a few seconds to let the user see the error.
                }
            }
            match load_custom_kernel_debuginfo(&kernel_elf) {
                Ok(debuginfo) => {self.bus.write().install_debuginfo(debuginfo)},
                Err(err) => {error!(target: "Custom Kernel", "Failed to load debuginfo for kernel: {err}")},
            }

            let headers = kernel_elf.phdrs;
            let mut bus = self.bus.write();
            // We are relying on the mirror being available
            // Or else we would be writing to mask ROM.
            bus.rom_disabled = true;
            bus.mirror_enabled = true;
            // A basic ELF loader
            for header in headers.iter() {
                if header.progtype == elf::types::PT_LOAD && header.filesz > 0 {
                    let start = header.offset as usize;
                    let end = start + header.filesz as usize;
                    info!(target: "Custom Kernel", "Loading offset: {:#10x}  phys addr: {:#10x} filesz: {:#10x}", header.offset, header.paddr, header.filesz);
                    bus.dma_write(header.paddr as u32, &kernel_bytes[start..end])?;
                }
            }
            self.boot_status = BootStatus::UserKernel;
            if PPC_EARLY_ON.load(std::sync::atomic::Ordering::Acquire) {
                bus.hlwd.ppc_on = true;
            }
        }
        loop {
            // Take ownership of the bus to deal with any pending tasks
            {
                let mut bus = self.bus.write();
                bus.step(self.cpu_cycle)?;
                self.bus_cycle += 1;
                bus.update_debug_location(Some(self.cpu.read_fetch_pc()), Some(self.cpu.reg.r[14]), Some(self.cpu.reg.r[13]));
                self.cpu.irq_input = bus.hlwd.irq.arm_irq_output;
            }

            // Before each CPU step, check if we need to patch any close code
            self.hotpatch_check().unwrap_or_default();

            // check if the debugger has anything for us.
            if let Some(debugger) = &mut self.debugger {
                if debugger.bkpts.contains(&self.cpu.read_fetch_pc()) {
                    debugger.state = DebugState::HitBkpt;
                }
                self.remote_dbg();
            }

            let res = self.cpu_step();
            match res {
                CpuRes::StepOk => {},
                CpuRes::HaltEmulation(reason) => {
                    error!(target: "Other", "CPU returned fatal error: {reason:#}");
                    error!(target: "Other", "{:?}", self.cpu.reg);
                    let pc = self.cpu.read_fetch_pc();
                    if self.cpu.reg.cpsr.thumb() {
                        if let Ok(opcd) = self.cpu.read16(pc){
                            error!(target: "Other",
                                "Possibly faulting instruction: {}",
                                crate::bits::disassembly::disassmble_thumb(opcd, pc).unwrap_or("Unknown".to_owned())
                            );
                        }
                    }
                    else if let Ok(opcd) = self.cpu.read32(pc){
                        error!(target: "Other",
                            "Possibly faulting instrcution: {}",
                            crate::bits::disassembly::disassmble_arm(opcd, pc).unwrap_or("Unknown".to_owned())
                        );
                    }
                    break;
                },
                CpuRes::StepException(e) => {
                    match e {
                        ExceptionType::Undef(_) => {},
                        ExceptionType::Irq => {},
                        ExceptionType::Swi => {},
                        _ => {
                            info!(target: "Other", "Unimplemented exception type {e:?}");
                            break;
                        }
                    }
                },
                CpuRes::Semihosting => {
                    self.svc_read().unwrap_or_else(|reason|{
                        info!(target: "Other", "FIXME: svc_read got error {reason}");
                    });
                }
            }
            if let Some(debugger) = &mut self.debugger && let DebugState::SingleStep = debugger.state {
                debugger.state = DebugState::DoneStepPause;
            }
            self.cpu_cycle += 1;
        }
        info!(target: "Other", "CPU stopped at pc={:08x}", self.cpu.read_fetch_pc());
        Ok(())
    }
}

macro_rules! elf_header_expect_equal {
    ($vec:ident, $have:expr, $want:expr, $message:expr) => {
        if $have != $want {
            $vec.push(format!("{}. Expected: {} Got: {}", $message, $want, $have));
        }
    };
}

fn validate_custom_kernel(header: &elf::types::FileHeader) -> std::result::Result<(), Vec<String>> {
    use elf::types::*;
    let mut problems: Vec<String> = Vec::with_capacity(0);
    elf_header_expect_equal!(problems, header.class, ELFCLASS32, "ELF Class is not 32-bit");
    elf_header_expect_equal!(problems, header.data, ELFDATA2MSB, "ELF Data is not big endian");
    elf_header_expect_equal!(problems, header.version, EV_CURRENT, "ELF Version is not known to us");
    elf_header_expect_equal!(problems, header.osabi, ELFOSABI_SYSV, "ELF ABI is not known to us");
    elf_header_expect_equal!(problems, header.elftype, ET_EXEC, "Our ELF loader only implements EXEC type ELF");
    elf_header_expect_equal!(problems, header.machine, EM_ARM, "ELF Type is not 32-bit ARM");
    elf_header_expect_equal!(problems, header.entry, 0xffff_0000u64, "Entry point of ELF does not match CPU reset vector");
    if problems.is_empty() {
        std::result::Result::Ok(())
    }
    else {
        std::result::Result::Err(problems)
    }
}

fn load_custom_kernel_debuginfo(kernel_elf: &elf::File) -> anyhow::Result<Dwarf<EndianArcSlice<BigEndian>>> {
    let loader = |id: gimli::SectionId| -> core::result::Result<EndianArcSlice<BigEndian>, gimli::Error> {
        match kernel_elf.get_section(id.name()) {
            Some(section) => {
                let d = section.data.as_slice();
                Ok(EndianArcSlice::new(Arc::from(d), BigEndian))
            },
            None => Ok(EndianArcSlice::new(Arc::new([]), BigEndian)),
        }
    };
    Ok(Dwarf::load(loader)?)
}