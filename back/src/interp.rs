//! The interpreter backend.

pub mod arm;
pub mod thumb;
pub mod dispatch;
pub mod lut;

use anyhow::{anyhow, bail};
use log::{error, info};

use std::io::{Read, Seek};
use std::sync::{Arc, RwLock};
use std::fs;

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

thread_local! {
    /// Enable PPC early, makes IPC with Custom Kernels easier
    static PPC_EARLY_ON: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

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
    debugger_attached: bool,
}
impl InterpBackend {
    pub fn new(bus: Arc<RwLock<Bus>>, custom_kernel: Option<String>, ppc_early_on: bool) -> Self {
        if ppc_early_on {
            PPC_EARLY_ON.with(|c| c.set(true));
        }
        InterpBackend {
            svc_buf: String::new(),
            cpu: Cpu::new(bus.clone()),
            boot_status: BootStatus::Boot0,
            cpu_cycle: 0,
            bus_cycle: 0,
            bus,
            custom_kernel,
            debugger_attached: false,
        }
    }
}

impl InterpBackend {
    /// Check if we need to update the current boot stage.
    pub fn update_boot_status(&mut self) {
        match self.boot_status {
            BootStatus::Boot0 => {
                if self.cpu.read_fetch_pc() == 0xfff0_0000 {
                    if let Ok(bus) = self.bus.try_read() { // Try to detect boot1 version
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
        self.bus.read().map_err(|e| anyhow!(e.to_string()))?.dma_read(paddr, &mut line_buf)?;

        let s = std::str::from_utf8(&line_buf)?
            .trim_matches(char::from(0));
        self.svc_buf += s;

        if let Some(idx) = self.svc_buf.find('\n') {
            let string: String = self.svc_buf.chars()
                .take(idx).collect();
            info!(target: "Other", "SVC {string}");
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
        // e3a00000 mov     r0, #0
        //0xe3, 0xa0, 0x00, 0x00,
        // e3a01006 mov     r1, #6
        //0xe3, 0xa0, 0x10, 0x06,
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
                self.bus.write().map_err(|e| anyhow!(e.to_string()))?.dma_write(paddr,
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
                self.debugger_attached = true;
                self.cpu.increment_pc();
                CpuRes::StepOk
            }
            DispatchRes::RetireBranch => { CpuRes::StepOk },
            DispatchRes::RetireOk | 
            DispatchRes::CondFailed => {
                self.cpu.increment_pc(); 
                CpuRes::StepOk
            },

            // NOTE: Skyeye doesn't take SWI exceptions at all, but I wonder
            // why this is permissible. What does the hardware actually do?
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
}

impl Backend for InterpBackend {
    fn run(&mut self) -> anyhow::Result<()> {
        if self.custom_kernel.is_some() {
            // Read the user supplied kernel file
            let filename = self.custom_kernel.as_ref().unwrap();
            let maybe_kernel_file = fs::File::open(filename);
            let mut kernel_file = match maybe_kernel_file {
                Ok(f) => f,
                Err(e) => {
                    bail!("Error opening kernel file: {filename}, got error: {e}");
                },
            };
            let mut kernel_bytes:Vec<u8> = Vec::with_capacity(kernel_file.metadata()?.len() as usize);
            kernel_file.read_to_end(&mut kernel_bytes)?;
            // Reuse the file for the ELF parser
            kernel_file.rewind()?;
            let kernel_elf = match elf::File::open_stream(&mut kernel_file) {
                Ok(res) => res,
                Err(e)  => { bail!("Custom Kernel ELF error: {e:?}"); },
            };
            match validate_custom_kernel(&kernel_elf.ehdr) {
                CustomKernelValidationResult::Ok => {/* We have a valid ELF (probably) */},
                CustomKernelValidationResult::Problem(p) => {
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

            let headers = kernel_elf.phdrs;
            let mut bus = self.bus.write().map_err(|_| anyhow!("Custom kernel load: Bus access failed"))?;
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
            if PPC_EARLY_ON.with(|c| c.get()) {
                bus.hlwd.ppc_on = true;
            }
        }
        loop {
            // Take ownership of the bus to deal with any pending tasks
            {
                let mut bus = self.bus.write().unwrap();
                bus.step(self.cpu_cycle)?;
                self.bus_cycle += 1;
                self.cpu.irq_input = bus.hlwd.irq.arm_irq_output;
            }

            // Before each CPU step, check if we need to patch any close code
            // I'm ok swallowing the possible Err result here because the only way this can error is
            // failing to translate the address the PC is at. This is obviously very rare, and in
            // the case it does happen we will know very soon anyway.
            self.hotpatch_check().unwrap_or_default();

            let res = self.cpu_step();
            match res {
                CpuRes::StepOk => {},
                CpuRes::HaltEmulation(reason) => {
                    info!(target: "Other", "CPU returned fatal error: {reason}");
                    info!(target: "Other", "{:?}", self.cpu.reg);
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
            self.cpu_cycle += 1;
        }
        info!(target: "Other", "CPU stopped at pc={:08x}", self.cpu.read_fetch_pc());
        Ok(())
    }
}

enum CustomKernelValidationResult {
    Ok,
    Problem(Vec<String>)
}

macro_rules! elf_header_expect_equal {
    ($vec:ident, $have:expr, $want:expr, $message:expr) => {
        if $have != $want {
            $vec.push(format!("{}. Expected: {} Got: {}", $message, $want, $have));
        }
    };
}

fn validate_custom_kernel(header: &elf::types::FileHeader) -> CustomKernelValidationResult {
    let mut problems: Vec<String> = Vec::with_capacity(0);
    elf_header_expect_equal!(problems, header.class, elf::types::ELFCLASS32, "ELF Class is not 32-bit");
    elf_header_expect_equal!(problems, header.data, elf::types::ELFDATA2MSB, "ELF Data is not big endian");
    elf_header_expect_equal!(problems, header.version, elf::types::EV_CURRENT, "ELF Version is not known to us");
    elf_header_expect_equal!(problems, header.osabi, elf::types::ELFOSABI_SYSV, "ELF ABI is not known to us");
    elf_header_expect_equal!(problems, header.elftype, elf::types::ET_EXEC, "Our ELF loader only implements EXEC type ELF");
    elf_header_expect_equal!(problems, header.machine, elf::types::EM_ARM, "ELF Type is not 32-bit ARM");
    elf_header_expect_equal!(problems, header.entry, 0xffff_0000u64, "Entry point of ELF does not match CPU reset vector");
    if problems.is_empty() {
        CustomKernelValidationResult::Ok
    }
    else {
        CustomKernelValidationResult::Problem(problems)
    }
}
