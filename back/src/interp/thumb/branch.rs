
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
    use crate::decode::thumb::ThumbInst;
    let prefix_offset = sign_extend((op.imm11() as u32) << 12, 23);
    let base = (cpu.read_exec_pc() as i32).wrapping_add(prefix_offset) as u32;
    // manually advance and fetch the next instruction
    cpu.reg.pc = cpu.reg.pc.wrapping_add(2);
    let intermediate_pc = cpu.read_fetch_pc();
    let next_op = match cpu.read16(intermediate_pc) {
        Ok(next_op) => BlBits(next_op),
        Err(x) => return DispatchRes::FatalErr(x.context("Coudn't fetch the next PC for 32-bit Thumb branch".to_owned())),
    };
    // Decode and execute second instruction
    let dest_pc: u32;
    let new_lr = cpu.read_fetch_pc().wrapping_add(2) | 1;
    match ThumbInst::decode(next_op.0) {
        ThumbInst::BlxImmSuffix => {
            debug_assert_eq!(next_op.h(), 0x1);
            dest_pc = (base.wrapping_add((next_op.imm11() << 1) as u32)) & 0xfffffffc;
            cpu.reg.cpsr.set_thumb(false);
        },
        ThumbInst::BlImmSuffix => {
            debug_assert_eq!(next_op.h(), 0x3);
            let suffix_offset = (next_op.imm11() as u32) << 1;
            dest_pc = base.wrapping_add(suffix_offset);
        },
        _ => { return DispatchRes::FatalErr(anyhow!("Instruction after BlPrefix is not Bl or Blx suffix.")); }
    }
    cpu.reg[Reg::Lr] = new_lr;
    cpu.write_exec_pc(dest_pc);
    DispatchRes::RetireBranch
}

pub fn bl_imm_suffix(_cpu: &mut Cpu, _op: BlBits) -> DispatchRes {
    // Implementation of 32-bit Thumb BL(X) is handled in bl_prefix
    DispatchRes::FatalErr(anyhow!("Attempted to directly dispatch BlImmSuffix without prefix instruction"))
}
pub fn blx_imm_suffix(_cpu: &mut Cpu, _op: BlBits) -> DispatchRes {
    // Implementation of 32-bit Thumb BL(X) is handled in bl_prefix
    DispatchRes::FatalErr(anyhow!("Attempted to directly dispatch BlxImmSuffix without prefix instruction"))
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
