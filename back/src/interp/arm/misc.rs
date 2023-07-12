use ironic_core::cpu::Cpu;
use ironic_core::cpu::excep::ExceptionType;
use log::{debug, info};
use crate::bits::arm::*;
use crate::interp::DispatchRes;
use anyhow::anyhow;

/// Breakpoint instruction:
/// ff = Immediately stop emulator (dumps RAM)
/// fe = cpu debug print toggle
/// fd = cpu debug print on
/// fc = cpu debug print off
/// fb = dump RAM and continue
/// All other values, store in scratch reg and wait for debugger
pub fn bkpt(cpu: &mut Cpu, op: BkptBits) -> DispatchRes {
    let cmd = op.imm16() as u16;
    info!(target: "Other", "Breakpoint instruction: {cmd:#x}");

    match cmd {
        0xff => { return DispatchRes::FatalErr(anyhow!("Breakpoint 0xffff - stopping emulation")) }
        0xfc..=0xfe => {
            match cmd & 0x3 {
                0b10 => { cpu.dbg_on = !cpu.dbg_on; }
                0b01 => { cpu.dbg_on = true; }
                0b00 => {cpu.dbg_on = false; }
                _ => { unreachable!() }
            }
            return DispatchRes::RetireOk;
        },
        0xfb => {
            let bus = cpu.bus.read();
            match bus.dump_memory("bkpt.bin") {
                Ok(path) => {
                    debug!(target: "Other", "Dumped RAM to {}/*.bkpt.bin", path.to_string_lossy());
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