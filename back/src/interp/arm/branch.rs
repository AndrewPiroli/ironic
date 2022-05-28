//! Implementation of branching instructions.

use ironic_core::cpu::Cpu;
use ironic_core::cpu::reg::Reg;
use crate::bits::arm::*;
use crate::interp::DispatchRes;

pub fn sign_extend(x: u32, source_bits: i32, dest_bits: i32) -> i32 {
    if ((x as i32 >> (source_bits - 1)) & 1) != 0 {
        x as i32 | ((1 << dest_bits)-(1 << source_bits))
    } else { 
        x as i32 
    }
}

pub fn bl_imm(cpu: &mut Cpu, op: BranchBits) -> DispatchRes {
    let offset = sign_extend(op.imm24(), 24, 30) << 2;
    let new_lr = cpu.read_fetch_pc().wrapping_add(4);
    let dest_pc = (cpu.read_exec_pc() as i32).wrapping_add(offset) as u32;

    cpu.reg[Reg::Lr] = new_lr;
    cpu.write_exec_pc(dest_pc);
    DispatchRes::RetireBranch
}
pub fn b(cpu: &mut Cpu, op: BranchBits) -> DispatchRes {
    let offset = sign_extend(op.imm24(), 24, 30) << 2;
    let target = (cpu.read_exec_pc() as i32).wrapping_add(offset) as u32;
    cpu.write_exec_pc(target);
    DispatchRes::RetireBranch
}
pub fn bx(cpu: &mut Cpu, op: BxBits) -> DispatchRes {
    let dest_pc = cpu.reg[op.rm()];
    cpu.reg.cpsr.set_thumb(dest_pc & 1 != 0);
    cpu.write_exec_pc(dest_pc & 0xffff_fffe);
    DispatchRes::RetireBranch
}

pub fn blx_immm(cpu: &mut Cpu, op: BranchBits) -> DispatchRes {
    let mut offset = (sign_extend(op.imm24(), 24, 30) as u32) << 2;
    if(((op.h() as u32) << 1) == 0){
        offset = offset & !2;
    }
    let new_lr = cpu.read_fetch_pc().wrapping_add(4);
    let dest_pc = (cpu.read_exec_pc()).wrapping_add(4 + offset);

    cpu.reg.cpsr.set_thumb(true);
    cpu.reg.pc = dest_pc;
    cpu.reg[Reg::Lr] = new_lr;
    DispatchRes::RetireBranch
}

