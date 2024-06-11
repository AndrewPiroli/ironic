use crate::bits::thumb::*;
use crate::interp::DispatchRes;
use ironic_core::cpu::{reg::Reg, Cpu};
use ironic_core::cpu::excep::ExceptionType;
use anyhow::anyhow;
use log::{debug, info};

pub fn svc(_cpu: &mut Cpu, _op: MiscBits) -> DispatchRes {
    DispatchRes::Exception(ExceptionType::Swi)
}

/// Breakpoint instruction:
/// ff = Immediately stop emulator (dumps RAM)
/// fe = cpu debug print toggle
/// fd = cpu debug print on
/// fc = cpu debug print off
/// fb = dump RAM and continue
/// fa = print cycle
/// All other values, store in scratch reg and wait for debugger
pub fn bkpt(cpu: &mut Cpu, op: MiscBits) -> DispatchRes {
    let cmd = op.imm8() as u8;
    info!(target:"Other", "Breakpoint instruction: {cmd:#x}");

    match cmd {
        0xff => { return DispatchRes::FatalErr(anyhow!("Breakpoint 0xff - stopping emulation")) }
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
        0xfa => {
            println!("AP DBG internal {:?}", cpu.reg);
        }
        _      => {},
    }
    cpu.scratch = cmd as u32;
    DispatchRes::Breakpoint
}