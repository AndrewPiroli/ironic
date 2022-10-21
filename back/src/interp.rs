//! The interpreter backend.

pub mod arm;
pub mod thumb;
pub mod dispatch;
pub mod lut;

use anyhow::{anyhow, bail};

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
    pub fn new(bus: Arc<RwLock<Bus>>, custom_kernel: Option<String>) -> Self {
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
                    println!("Entered boot1");
                    self.boot_status = BootStatus::Boot1;
                }
            }
            BootStatus::Boot1 => {
                if self.cpu.read_fetch_pc() == 0xfff0_0058 { 
                    println!("Entered boot2 stub");
                    self.boot_status = BootStatus::Boot2Stub;
                }
            }
            BootStatus::Boot2Stub => {
                if self.cpu.read_fetch_pc() == 0xffff_0000 { 
                    println!("Entered boot2");
                    self.boot_status = BootStatus::Boot2;
                }
            }
            BootStatus::Boot2 => {
                if self.cpu.read_fetch_pc() == 0xffff_2224 { 
                    println!("Entered kernel");
                    self.boot_status = BootStatus::IOSKernel;
                }
            }
            BootStatus::IOSKernel => {
                if self.cpu.read_fetch_pc() == 0x0001_0000 { 
                    println!("Entered foreign kernel stub");
                    self.boot_status = BootStatus::UserKernelStub;
                }
            }
            BootStatus::UserKernelStub=> {
                if self.cpu.read_fetch_pc() == 0xffff_0000 {
                    println!("Entered foreign kernel");
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
            println!("SVC {string}");
            self.svc_buf.clear();
        }
        Ok(())
    }

    /// Log IOS syscalls to stdout.
    pub fn syscall_log(&mut self, opcd: u32) {
        println!("IOS syscall {opcd:08x}, lr={:08x}", self.cpu.reg[Reg::Lr]);
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
                println!("({opcd:08x}) {name:12} {:x?}", self.cpu.reg);
                //println!("{:?}", self.cpu.reg);
            } else {
                let opcd = self.cpu.read32(pc)?;
                let name = format!("{:?}", ArmInst::decode(opcd));
                println!("({opcd:08x}) {name:12} {:x?}", self.cpu.reg);
                //println!("{:?}", self.cpu.reg);
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
                println!("DBG hotpatching module entrypoint {paddr:08x}");
                println!("{:?}", self.cpu.reg);
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
                    self.cpu.increment_pc();
                    CpuRes::Semihosting
                } else {
                    if let Err(reason) = self.cpu.generate_exception(e){
                        return CpuRes::HaltEmulation(reason);
                    };
                    CpuRes::StepException(e)
                }
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
            let headers = kernel_elf.phdrs;
            // We have a valid ELF (probably)
            let mut bus = self.bus.write().map_err(|e| anyhow!(e.to_string()))?;
            // We are relying on the mirror being available
            // Or else we would be writing to mask ROM.
            bus.rom_disabled = true;
            bus.mirror_enabled = true;
            // A basic ELF loader
            for header in headers.iter() {
                if header.progtype == elf::types::ProgType(1) && header.filesz > 0 { // progtype 1 == PT_LOAD
                    let start = header.offset as usize;
                    let end = start + header.filesz as usize;
                    println!("CUSTOM KERNEL: LOADING offset: {:#10x}  phys addr: {:#10x} filesz: {:#10x}", header.offset, header.paddr, header.filesz);
                    bus.dma_write(header.paddr as u32, &kernel_bytes[start..end])?;
                }
            }
            self.boot_status = BootStatus::UserKernel;
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
                    println!("CPU returned fatal error: {reason}");
                    break;
                },
                CpuRes::StepException(e) => {
                    match e {
                        ExceptionType::Undef(_) => {},
                        ExceptionType::Irq => {},
                        _ => {
                            println!("Unimplemented exception type {e:?}");
                            break;
                        }
                    }
                },
                CpuRes::Semihosting => {
                    self.svc_read().unwrap_or_else(|reason|{
                        println!("FIXME: svc_read got error {reason}");
                    });
                }
            }
            self.cpu_cycle += 1;
        }
        println!("CPU stopped at pc={:08x}", self.cpu.read_fetch_pc());
        Ok(())
    }
}
