use ironic_core::cpu::Cpu;
use ironic_core::cpu::excep::ExceptionType;
use log::{debug, info};
use crate::bits::arm::*;
use crate::interp::DispatchRes;
use anyhow::anyhow;

/// Breakpoint instruction:
/// ffff = Immediately stop emulator (dumps RAM)
/// fffe = cpu debug print toggle
/// fffd = cpu debug print on
/// fffc = cpu debug print off
/// fffb = dump RAM and continue
/// All other values, store in scratch reg and wait for debugger
pub fn bkpt(cpu: &mut Cpu, op: BkptBits) -> DispatchRes {
    let cmd = op.imm16() as u16;
    info!(target: "Other", "Breakpoint instruction: {cmd:#x}");

    match cmd {
        0xffff => { return DispatchRes::FatalErr(anyhow!("Breakpoint 0xffff - stopping emulation")) }
        0xfffc..=0xfffe => {
            match cmd & 0x3 {
                0b10 => { cpu.dbg_on = !cpu.dbg_on; }
                0b01 => { cpu.dbg_on = true; }
                0b00 => {cpu.dbg_on = false; }
                _ => { unreachable!() }
            }
            return DispatchRes::RetireOk;
        },
        0xfffb => {
            let bus = cpu.bus.read().expect("breakpoint instruction - bus access");
            match bus.dump_memory("bkpt.bin") {
                Ok(path) => {
                    debug!(target: "Other", "Dumped RAM to {}", path.to_string_lossy());
                    return DispatchRes::RetireOk;
                },
                Err(e) => { return DispatchRes::FatalErr(e); }
            }
        },
        _      => {},
    }
    cpu.scratch = cmd as u32;
    DispatchRes::Breakpoint
}

pub fn svc(_cpu: &mut Cpu, _op: u32) -> DispatchRes {
    DispatchRes::Exception(ExceptionType::Swi)
}