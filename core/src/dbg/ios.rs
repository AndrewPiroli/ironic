//! Logging for IOS syscalls.
//!
//! Note that a lot of this depends on the version being booted.
//! For now, it's sufficient to just assume we're on IOS58.

use crate::cpu::Cpu;
use crate::cpu::reg::Reg;
use crate::cpu::mmu::prim::{Access, TLBReq};

use log::{info, trace, log_enabled};

/// NOTE: `skyeye-starlet` does something like this; wonder if there's a
/// better way of keeping track of the threads?
#[derive(Debug)]
pub enum ExecutionCtx {
    UNK,
    CRY,
    ES,
    FS,
    KRN,
    DIP,
    STM,
    OH0,
    OH1,
    SO,
    ETH,
    SDI,
    NCD,
    WD,
    WL,
    KD,
}
impl From<u32> for ExecutionCtx {
    fn from(pc: u32) -> Self {
        use ExecutionCtx::*;
        match (pc & 0xffff_0000) >> 16 {
            0x1386 => CRY,
            0x138a => OH0,
            0x138b => OH1,
            0x13aa => ETH,
            0x13b6 => SO,
            0x13d9 => NCD,
            0x13db => KD,
            0x13eb => WD,
            0x13ed => WL,
            0x2000 => FS,
            0x2010 => ES,
            0x2020 => DIP,
            0x2030 => STM,
            0x2040 => SDI,
            0xffff => KRN,
            _ => UNK,
        }
    }
}


/// Typed arguments to a syscall. 
pub enum ArgType { Ptr, StrPtr, Int, Uint }

/// Format arguments for some IOS syscall.
pub struct SyscallDef {
    pub name: &'static str,
    pub arg: &'static [ArgType],
}

/// Shorthand for declaring a syscall definition.
macro_rules! scdef {
    ($name:literal, $($arg:ident),*) => {
        SyscallDef { name: $name, arg: &[$(ArgType::$arg,)*] } 
    }
}

/// Read a NUL-terminated string from memory.  
/// 
/// NOTE: This is not particularly rigorous or safe.
pub fn read_string(cpu: &Cpu, ptr: u32) -> anyhow::Result<String> {
    let paddr = cpu.translate(TLBReq::new(ptr, Access::Debug))?;

    let mut line_buf = [0u8; 64];
    cpu.bus.read().dma_read(paddr, &mut line_buf)?;
    if log_enabled!(target: "SYSCALL", log::Level::Trace) {
        let mut msg = String::new();
        for chunk in line_buf.chunks_exact(8) {
            msg += &format!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}\n", chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]);
        }
        trace!(target: "SYSCALL", "Line buffer dump:\n{msg}");
    }

    let mut end: Option<usize> = None;
    for (i, b) in line_buf.iter().enumerate() {
        if *b == 0x00 { end = Some(i); break; } 
    }
    let s = if let Some(end) = end {
        std::str::from_utf8(&line_buf[..=end]).unwrap()
    } else {
        std::str::from_utf8(&line_buf).unwrap()
    };
    Ok(s.trim_matches(char::from(0)).to_string())
}

pub fn get_syscall_desc(idx: u32) -> Option<SyscallDef> {

    // Ignore some syscalls
    match idx { 
        0x0a..=0x10 |
        //0x11..=0x13 | 0x15 |
        0x16 | 0x18 | 0x19 | 0x1a | 
        0x1d..=0x1f | 0x21 | 0x22 |
        0x63 | 0x68 | 0x6a | 0x6d |
        0x2a | 0x2f | 0x3f | 0x30 |
        0x40 | 0x4f | 0x61 | 0x6b |
        0x6c | 0x6e | 0x66          => return None,
        _ => { },
    }

    match idx {
        0x00 => Some(scdef!("ThreadCreate", Ptr, Ptr, Ptr, Uint, Uint, Uint)),
        0x02 => Some(scdef!("ThreadCancel", )),
        0x03 => Some(scdef!("ThreadGetID", )),
        0x04 => Some(scdef!("ThreadGetPid", )),
        0x05 => Some(scdef!("ThreadContinue", Uint)),
        0x08 => Some(scdef!("ThreadGetPrio", Uint)),
        0x09 => Some(scdef!("ThreadSetPrio", Int, Int)),
        0x0a => Some(scdef!("MqueueCreate", Ptr, Int)),
        0x0b => Some(scdef!("MqueueDestroy", Ptr)),
        0x0c => Some(scdef!("MqueueSend", Uint, Uint, Uint)),
        0x0e => Some(scdef!("MqueueRecv", Ptr, Uint)),
        0x0f => Some(scdef!("MqueueRegisterHandler", Int, Int, Uint)),
        0x10 => Some(scdef!("MqueueDestroyHandler", Ptr, Ptr, Ptr)),
        0x11 => Some(scdef!("TimerCreate", Int, Int, Int, Uint)),
        0x12 => Some(scdef!("TimerRestart", Uint, Int, Int)),
        0x13 => Some(scdef!("TimerStop", Uint)),
        0x14 => Some(scdef!("TimerDestroy", Uint)),
        0x15 => Some(scdef!("TimerNow", )),
        0x16 => Some(scdef!("HeapCreate", Ptr, Int)),
        0x18 => Some(scdef!("HeapAlloc", Int, Uint)),
        0x19 => Some(scdef!("HeapAllocAligned", Int, Uint, Uint)),
        0x1a => Some(scdef!("HeapFree", Int, Ptr)),
        0x1b => Some(scdef!("RegisterDevice", StrPtr, Int)),
        0x1c => Some(scdef!("Open", StrPtr, Int)),
        0x1d => Some(scdef!("Close", Int)),
        0x1e => Some(scdef!("Read", Int, Ptr, Uint)),
        0x1f => Some(scdef!("Write", Int, Ptr, Uint)),
        0x21 => Some(scdef!("Ioctl", Int, Uint, Ptr, Uint, Ptr, Uint)),
        0x22 => Some(scdef!("Ioctlv", Int, Uint, Uint, Uint, Ptr)),
        0x2a => Some(scdef!("ResourceReply", Ptr, Uint)),
        0x2b => Some(scdef!("SetUid", Int)),
        0x2d => Some(scdef!("SetGid", Int)),
        0x2f => Some(scdef!("AhbMemFlush", Int)),
        0x30 => Some(scdef!("CcAhbMemFlush", Int)),
        0x32 => Some(scdef!("EnableIrqDI", )),
        0x33 => Some(scdef!("EnableIrqSDHC", )),
        0x34 => Some(scdef!("EnableIrq", )),
        0x35 => Some(scdef!("IobufPoolAccessNOP", )),
        0x3f => Some(scdef!("SyncBeforeRead", Ptr)),
        0x40 => Some(scdef!("SyncAfterWrite", Ptr)),
        0x41 => Some(scdef!("PpcBoot", StrPtr)),
        0x42 => Some(scdef!("IosBoot", StrPtr)),
        0x43 => Some(scdef!("BootNewIosKernel", Ptr, Uint)),
        0x46 => Some(scdef!("DIResetCheck", )),
        0x47 => Some(scdef!("WhichKernel", Ptr, Ptr)), //get_kernel_flavor
        0x4d => Some(scdef!("KernelGetVersion", )),
        0x4f => Some(scdef!("VirtToPhys", Ptr)),
        0x50 => Some(scdef!("DVDVideoSet", Uint)),
        0x51 => Some(scdef!("DVDVideoGet", )),
        0x52 => Some(scdef!("EXICtrlBit4Toggle", Uint)),
        0x54 => Some(scdef!("SetAhbProt", Uint)),
        0x55 => Some(scdef!("GetBusClock", )),
        0x56 => Some(scdef!("PokeGpio", Uint, Uint)),
        0x59 => Some(scdef!("LoadPPC", Ptr)),
        0x5a => Some(scdef!("LoadModule", StrPtr)),
        0x63 => Some(scdef!("IoscGetData", Uint, Uint, Uint)),
        0x68 => Some(scdef!("IoscEncryptAsync", Uint, Uint, Uint)),
        0x6a => Some(scdef!("IoscDecryptAsync", Uint, Uint, Uint)),
        0x6d => Some(scdef!("IoscGenBlockmac", Uint, Uint, Uint)),
        _ => None,
    }
}


/// Resolve information about an IOS syscall and its arguments.
pub fn log_syscall(cpu: &mut Cpu, opcd: u32) {
    // Get the syscall index (and ignore some)
    let idx = (opcd & 0x00ff_ffe0) >> 5;
    let res = get_syscall_desc(idx);
    if res.is_none() {
        return;
    }
    let syscall = res.unwrap();
    let mut arg_buf = String::new();
    for (idx, arg) in syscall.arg.iter().enumerate() {
        let val = cpu.reg[idx as u32];
        match arg {
            ArgType::Ptr => { 
                arg_buf.push_str(&format!("0x{val:08x}"));
            },
            ArgType::StrPtr => {
                let s = read_string(cpu, val);
                if s.is_err() { return; }
                let s = s.unwrap();
                arg_buf.push_str(&format!("\"{s}\""));
            },
            ArgType::Int => {
                arg_buf.push_str(&format!("{val}"));
            },
            ArgType::Uint => {
                arg_buf.push_str(&format!("0x{val:x}"));
            },
        }
        if idx < syscall.arg.len()-1 {
            arg_buf.push_str(", ");
        }
    }
    info!(target: "SYSCALL", "[{:?}] {}({arg_buf}) (lr={:08x})",
        ExecutionCtx::from(cpu.read_fetch_pc()),
        syscall.name, cpu.reg[Reg::Lr]
    );
}

