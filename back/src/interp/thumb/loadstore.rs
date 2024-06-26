
use crate::bits::thumb::*;
use crate::interp::DispatchRes;
use anyhow::bail;
use ironic_core::cpu::Cpu;
use ironic_core::cpu::reg::Reg;

pub fn sign_extend(x: u32, bits: i32) -> i32 {
    if ((x as i32 >> (bits - 1)) & 1) != 0 { 
        x as i32 | !0 << bits 
    } else { 
        x as i32 
    }
}

#[derive(Debug, PartialEq)]
enum Width { Byte, Half, Word, SignedByte, SignedHalf }


pub fn ldr_lit(cpu: &mut Cpu, op: LoadStoreAltBits) -> DispatchRes {
    let imm = (op.imm8() * 4) as u32;
    let addr = (cpu.read_exec_pc() & 0xffff_fffc).wrapping_add(imm);

    let res = match cpu.read32(addr){
        Ok(val) => val,
        Err(reason) => {
            return DispatchRes::FatalErr(reason);
        }
    };
    if op.rt() == 15 {
        cpu.write_exec_pc(res);
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rt()] = res;
        DispatchRes::RetireOk
    }
}


/// Generic load (register).
fn load_reg(cpu: &mut Cpu, rn: u16, rm: u16, rt: u16, width: Width) -> anyhow::Result<()> {
    let addr = cpu.reg[rn].wrapping_add(cpu.reg[rm]);
    let res: u32 = match width {
        Width::Byte => cpu.read8(addr)? as u32,
        Width::Half => cpu.read16(addr)? as u32,
        Width::Word => cpu.read32(addr)?,
        Width::SignedHalf => {
            let val = cpu.read16(addr)? as u32;
            sign_extend(val, 16) as u32
        },
        Width::SignedByte => {
            let val = cpu.read8(addr)? as u32;
            sign_extend(val, 8) as u32
        }
    };
    cpu.reg[rt] = res;
    Ok(())
}
pub fn ldr_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match load_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Word) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn ldrh_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match load_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Half) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn ldrb_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match load_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Byte) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn ldrsb_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match load_reg(cpu, op.rn(), op.rm(), op.rt(), Width::SignedByte) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn ldrsh_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match load_reg(cpu, op.rn(), op.rm(), op.rt(), Width::SignedHalf) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}



/// Generic load (immediate).
fn load_imm(cpu: &mut Cpu, rn: u16, rt: u16, imm_n: u32, width: Width) -> anyhow::Result<()> {
    let imm = match width {
        Width::Byte => imm_n, 
        Width::Half => imm_n << 1,
        Width::Word => imm_n << 2,
        _ => {
            bail!("load_imm width argument: {width:?} not acceptable!");
        },
    };

    let addr = cpu.reg[rn].wrapping_add(imm);
    let res: u32 = match width {
        Width::Byte => cpu.read8(addr)? as u32,
        Width::Half => cpu.read16(addr)? as u32,
        Width::Word => cpu.read32(addr)?,
        _ => unreachable!()
    };
    cpu.reg[rt] = res;
    Ok(())
}
pub fn ldr_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    match load_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Word) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn ldrb_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    match load_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Byte) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn ldrh_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    match load_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Half) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn ldr_imm_sp(cpu: &mut Cpu, op: LoadStoreAltBits) -> DispatchRes {
    match load_imm(cpu, 13, op.rt(), op.imm8() as u32, Width::Word) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}


/// Generic store (register).
fn store_reg(cpu: &mut Cpu, rn: u16, rm: u16, rt: u16, width: Width) -> anyhow::Result<()> { //FIXME Proper gaurd against Width variants
    let addr = cpu.reg[rn].wrapping_add(cpu.reg[rm]);
    let val: u32 = cpu.reg[rt];
    match width {
        Width::Byte => cpu.write8(addr, val),
        Width::Half => cpu.write16(addr, val),
        Width::Word => cpu.write32(addr, val),
        _ => unreachable!(),
    }
}
pub fn str_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match store_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Word) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn strb_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match store_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Byte) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn strh_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    match store_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Half) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}



/// Generic store (immediate).
fn store_imm(cpu: &mut Cpu, rn: u16, rt: u16, imm_n: u32, width: Width) -> anyhow::Result<()> {
    let imm = match width {
        Width::Byte => imm_n, 
        Width::Half => imm_n << 1,
        Width::Word => imm_n << 2,
        _ => unreachable!(),
    };

    let addr = cpu.reg[rn].wrapping_add(imm);
    let val: u32 = cpu.reg[rt];
    match width {
        Width::Byte => cpu.write8(addr, val),
        Width::Half => cpu.write16(addr, val),
        Width::Word => cpu.write32(addr, val),
        _ => unreachable!(),
    }
}
pub fn str_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    match store_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Word) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn strb_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    match store_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Byte) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn strh_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    match store_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Half) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn str_imm_sp(cpu: &mut Cpu, op: LoadStoreAltBits) -> DispatchRes {
    match store_imm(cpu, 13, op.rt(), op.imm8() as u32, Width::Word) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}




pub fn ldm(cpu: &mut Cpu, op: LoadStoreMultiBits) -> DispatchRes {
    let num_regs = op.register_list().count_ones();
    let writeback = (op.register_list() & (1 << op.rn())) == 0;

    let start_addr = cpu.reg[op.rn()];
    let end_addr = start_addr + (4 * num_regs);
    let mut addr = start_addr;
    for i in 0..8 {
        if (op.register_list() & (1 << i)) != 0 {
            let val = match cpu.read32(addr){
                Ok(val) => val,
                Err(reason) => {
                    return DispatchRes::FatalErr(reason);
                }
            };
            cpu.reg[i as u32] = val;
            addr += 4;
        }
    }

    assert!(end_addr == addr);
    if writeback {
        cpu.reg[op.rn()] = end_addr;
    }
    DispatchRes::RetireOk
}

pub fn stm(cpu: &mut Cpu, op: LoadStoreMultiBits) -> DispatchRes {
    let num_regs = op.register_list().count_ones();
    let start_addr = cpu.reg[op.rn()];
    let end_addr = start_addr + (4 * num_regs);
    let mut addr = start_addr;
    for i in 0..8 {
        if (op.register_list() & (1 << i)) != 0 {
            match cpu.write32(addr, cpu.reg[i as u32]) {
                Ok(_) => {},
                Err(reason) => { return DispatchRes::FatalErr(reason); }
            };
            addr += 4;
        }
    }
    cpu.reg[op.rn()] = end_addr;
    DispatchRes::RetireOk
}

pub fn push(cpu: &mut Cpu, op: PushBits) -> DispatchRes {
    let num_regs = if op.m() {
        op.register_list().count_ones() + 1
    } else {
        op.register_list().count_ones()
    };

    let start_addr = cpu.reg[Reg::Sp] - (4 * num_regs);
    let end_addr = cpu.reg[Reg::Sp] - 4;
    let mut addr = start_addr;
    for i in 0..8 {
        if (op.register_list() & (1 << i)) != 0 {
            match cpu.write32(addr, cpu.reg[i as u32]) {
                Ok(_) => {},
                Err(reason) => {return DispatchRes::FatalErr(reason) }
            };
            addr += 4;
        }
    }
    if op.m() {
        match cpu.write32(addr, cpu.reg[Reg::Lr]) {
            Ok(_) => {},
            Err(reason) => { return DispatchRes::FatalErr(reason); }
        };
        addr += 4;
    }
    assert!(end_addr == addr - 4);
    cpu.reg[Reg::Sp] = start_addr;

    DispatchRes::RetireOk
}

pub fn pop(cpu: &mut Cpu, op: PopBits) -> DispatchRes {
    let num_regs = if op.p() {
        op.register_list().count_ones() + 1
    } else {
        op.register_list().count_ones()
    };
    let start_addr = cpu.reg[Reg::Sp];
    let end_addr = start_addr + (4 * num_regs);
    let mut addr = start_addr;
    for i in 0..8 {
        if (op.register_list() & (1 << i)) != 0 {
            let val = match cpu.read32(addr){
                Ok(val) => val,
                Err(reason) => {
                    return DispatchRes::FatalErr(reason);
                }
            };
            cpu.reg[i as u32] = val;
            addr += 4;
        }
    }

    let new_pc = if op.p() {
        let saved_lr = match cpu.read32(addr) {
            Ok(val) => val,
            Err(reason) => {
                return DispatchRes::FatalErr(reason);
            }
        };
        addr += 4;
        Some(saved_lr)
    } else { 
        None 
    };
    assert!(end_addr == addr);
    cpu.reg[Reg::Sp] = end_addr;

    if let Some(new_pc) = new_pc {
        cpu.reg.cpsr.set_thumb(new_pc & 1 != 0);
        cpu.write_exec_pc(new_pc & 0xffff_fffe);
        DispatchRes::RetireBranch
    } else {
        DispatchRes::RetireOk
    }
}


