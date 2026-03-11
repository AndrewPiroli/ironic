
use ironic_core::cpu::Cpu;
use crate::bits::arm::*;
use crate::interp::DispatchRes;

pub fn umull(cpu: &mut Cpu, op: SignedMlBits) -> DispatchRes {
    let rm_val = cpu.reg[op.rm()] as u64;
    let rn_val = cpu.reg[op.rn()] as u64;
    let res = rm_val * rn_val;

    let res_hi = ((res & 0xffff_ffff_0000_0000) >> 32) as u32;
    let res_lo =  (res & 0x0000_0000_ffff_ffff) as u32;
    cpu.reg[op.rdhi()] = res_hi;
    cpu.reg[op.rdlo()] = res_lo;
    if op.s() {
        cpu.reg.cpsr.set_n((res_hi & 0x8000_0000) != 0);
        cpu.reg.cpsr.set_z((res_hi == 0) && (res_lo == 0));
    }
    DispatchRes::RetireOk
}


pub fn mul(cpu: &mut Cpu, op: MulBits) -> DispatchRes {
    let rm_val = cpu.reg[op.rm()] as u64;
    let rn_val = cpu.reg[op.rn()] as u64;
    let res = ((rm_val * rn_val) & 0x0000_0000_ffff_ffff) as u32;
    cpu.reg[op.rd()] = res;
    if op.s() {
        cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
        cpu.reg.cpsr.set_z(res == 0);
    }
    DispatchRes::RetireOk
}

pub fn umlal(cpu: &mut Cpu, op: SignedMlBits) -> DispatchRes {
    let rm_val = cpu.reg[op.rm()] as u64;
    let rn_val = cpu.reg[op.rn()] as u64;
    let existing: u64 = ((cpu.reg[op.rdhi()] as u64) << 32) | cpu.reg[op.rdlo()] as u64;

    let res = (rm_val*rn_val)+existing;
    let res_hi = ((res & 0xffff_ffff_0000_0000) >> 32) as u32;
    let res_lo =  (res & 0x0000_0000_ffff_ffff) as u32;

    cpu.reg[op.rdhi()] = res_hi;
    cpu.reg[op.rdlo()] = res_lo;
    if op.s() {
        cpu.reg.cpsr.set_n((res_hi & 0x8000_0000) != 0);
        cpu.reg.cpsr.set_z((res_hi == 0) && (res_lo == 0));
    }
    DispatchRes::RetireOk
}

