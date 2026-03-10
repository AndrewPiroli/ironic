
use crate::bits::thumb::*;
use crate::interp::DispatchRes;
use ironic_core::cpu::Cpu;
use ironic_core::cpu::reg::{Reg, Cond};
use anyhow::anyhow;
use log::error;

pub fn sign_extend(x: u32, bits: i32) -> i32 {
    if ((x as i32 >> (bits - 1)) & 1) != 0 { 
        x as i32 | !0 << bits 
    } else { 
        x as i32 
    }
}

pub fn bl_prefix(cpu: &mut Cpu, op: BlBits) -> DispatchRes {
    let offset = sign_extend((op.imm11() as u32) << 12, 23);
    let res = (cpu.read_exec_pc() as i32).wrapping_add(offset);
    cpu.scratch = res as u32;
    cpu.dispatching_double_wide_instr = true;
    DispatchRes::RetireOk
}
pub fn bl_imm_suffix(cpu: &mut Cpu, op: BlBits) -> DispatchRes {
    cpu.dispatching_double_wide_instr = false;
    assert!(op.h() == 0x3);
    let offset = (op.imm11() as u32) << 1;
    let dest_pc = cpu.scratch.wrapping_add(offset);
    let new_lr = cpu.read_fetch_pc().wrapping_add(2) | 1;
    cpu.reg[Reg::Lr] = new_lr;
    cpu.write_exec_pc(dest_pc);
    DispatchRes::RetireBranch
}
pub fn blx_imm_suffix(cpu: &mut Cpu, op: BlBits) -> DispatchRes {
    cpu.dispatching_double_wide_instr = false;
    assert!(op.h() == 0x1);
    let new_lr = cpu.read_fetch_pc().wrapping_add(2) | 1;
    let dest_pc = (cpu.scratch.wrapping_add((op.imm11() << 1) as u32)) & 0xfffffffc;
    cpu.reg[Reg::Lr] = new_lr;
    cpu.reg.cpsr.set_thumb(false);
    cpu.write_exec_pc(dest_pc);
    DispatchRes::RetireBranch
}
pub fn bx(cpu: &mut Cpu, op: BxBits) -> DispatchRes {
    let dest_pc = if op.rm() == 15 {
        // temporary shity cIOS hack
        // they literally just flick between ARM and thumb using a bx pc
        // with no regard to alignment
        let new_pc = cpu.read_exec_pc();
        if new_pc & 0b11 != 0 {
            error!(target: "Other", "bx pc alignment failed!! Hotfixing for you this time.. please fix your code.");
            new_pc & 0xffff_fffc
        }
        else {
            new_pc
        }
    } else {
        cpu.reg[op.rm()]
    };
    cpu.reg.cpsr.set_thumb(dest_pc & 1 != 0);
    cpu.write_exec_pc(dest_pc & 0xffff_fffe);
    DispatchRes::RetireBranch
}

pub fn blx_reg(cpu: &mut Cpu, op: BxBits) -> DispatchRes {
    assert_ne!(op.rm(), 15);
    let new_lr = cpu.read_fetch_pc().wrapping_add(2) | 1;
    let dest_pc = cpu.reg[op.rm()];
    cpu.reg.cpsr.set_thumb(dest_pc & 1 != 0);
    cpu.reg[Reg::Lr] = new_lr;
    cpu.write_exec_pc(dest_pc & 0xffff_fffe);
    DispatchRes::RetireBranch
}

pub fn b_unconditional(cpu: &mut Cpu, op: BranchAltBits) -> DispatchRes {
    let offset = sign_extend(op.imm11() as u32, 11) << 1;
    if offset == -4 {
        return DispatchRes::FatalErr(anyhow!("Unconditional branch would loop forever pc={:08x}", cpu.read_fetch_pc()));
    }
    let dest_pc = (cpu.read_exec_pc() as i32).wrapping_add(offset) as u32;

    cpu.write_exec_pc(dest_pc);
    DispatchRes::RetireBranch
}

pub fn b(cpu: &mut Cpu, op: BranchBits) -> DispatchRes {
    let op_cond = Cond::try_from(op.cond() as u32);
    match op_cond {
        Ok(cond) => {
            if cpu.reg.is_cond_satisfied(cond) {
                let offset = sign_extend(op.imm8() as u32, 8) << 1;
                //let offset = ((op.imm8() as u32) << 1) as i32;
                let dest_pc = (cpu.read_exec_pc() as i32).wrapping_add(offset) as u32;
                cpu.write_exec_pc(dest_pc);
                DispatchRes::RetireBranch
            } else {
                DispatchRes::RetireOk
            }
        },
        Err(reason) => {
            DispatchRes::FatalErr(reason)
        }
    }
}
