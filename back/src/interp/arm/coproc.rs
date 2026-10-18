//! Implementation of co-processor instructions.

use ironic_core::cpu::Cpu;
use crate::bits::arm::*;
use crate::interp::DispatchRes;

pub fn mcr(cpu: &mut Cpu, op: MoveCoprocBits) -> DispatchRes {
    assert_eq!(op.coproc(), 15);
    cpu.p15.write(cpu.reg[op.rt()], op.crn(), op.crm(), op.opc2());
    DispatchRes::RetireOk
}

pub fn mrc(cpu: &mut Cpu, op: MoveCoprocBits) -> DispatchRes {
    assert_eq!(op.coproc(), 15);
    if op.rt() != 15 {
        let val = cpu.p15.read(op.crn(), op.crm(), op.opc2());
        cpu.reg[op.rt()] = val;
    } else {
        let val = cpu.p15.read_alt(op.crn(), op.crm(), op.opc2());
        if let Some(n) = val.n { cpu.reg.cpsr.set_n(n); }
        if let Some(z) = val.z { cpu.reg.cpsr.set_z(z); }
        if let Some(c) = val.c { cpu.reg.cpsr.set_c(c); }
        if let Some(v) = val.v { cpu.reg.cpsr.set_v(v); }
    }
    DispatchRes::RetireOk
}
