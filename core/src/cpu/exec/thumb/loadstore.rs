
use crate::cpu::*;
use crate::cpu::reg::*;
use crate::cpu::exec::thumb::bits::*;
use crate::bus::*;

#[derive(Debug, PartialEq)]
enum Width { Byte, Half, Word }


pub fn ldr_lit(cpu: &mut Cpu, op: LoadStoreAltBits) -> DispatchRes {
    let imm = (op.imm8() * 4) as u32;
    let addr = (cpu.read_exec_pc() & 0xffff_fffc).wrapping_add(imm);

    let res = cpu.mmu.read32(addr);
    if op.rt() == 15 {
        cpu.write_exec_pc(res);
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rt()] = res;
        DispatchRes::RetireOk
    }
}


/// Generic load (register).
fn load_reg(cpu: &mut Cpu, rn: u16, rm: u16, rt: u16, width: Width) {
    let addr = cpu.reg[rn].wrapping_add(cpu.reg[rm]);
    let res: u32 = match width {
        Width::Byte => cpu.mmu.read8(addr) as u32,
        Width::Half => cpu.mmu.read16(addr) as u32,
        Width::Word => cpu.mmu.read32(addr),
    };
    cpu.reg[rt] = res;
}
pub fn ldr_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    load_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Word);
    DispatchRes::RetireOk
}
pub fn ldrb_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    load_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Byte);
    DispatchRes::RetireOk
}


/// Generic load (immediate).
fn load_imm(cpu: &mut Cpu, rn: u16, rt: u16, imm_n: u32, width: Width) {
    // Byte stores do not shift the immediate
    let imm = if width == Width::Byte { imm_n } else { imm_n << 2 };
    let addr = cpu.reg[rn].wrapping_add(imm);
    let res: u32 = match width {
        Width::Byte => cpu.mmu.read8(addr) as u32,
        Width::Half => cpu.mmu.read16(addr) as u32,
        Width::Word => cpu.mmu.read32(addr),
    };
    cpu.reg[rt] = res;
}
pub fn ldr_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    load_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Word);
    DispatchRes::RetireOk
}
pub fn ldrb_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    load_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Byte);
    DispatchRes::RetireOk
}
pub fn ldrh_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    load_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Half);
    DispatchRes::RetireOk
}
pub fn ldr_imm_sp(cpu: &mut Cpu, op: LoadStoreAltBits) -> DispatchRes {
    load_imm(cpu, 13, op.rt(), op.imm8() as u32, Width::Word);
    DispatchRes::RetireOk
}


/// Generic store (register).
fn store_reg(cpu: &mut Cpu, rn: u16, rm: u16, rt: u16, width: Width) {
    let addr = cpu.reg[rn].wrapping_add(cpu.reg[rm]);
    let val: u32 = cpu.reg[rt];
    match width {
        Width::Byte => cpu.mmu.write8(addr, val),
        Width::Half => cpu.mmu.write16(addr, val),
        Width::Word => cpu.mmu.write32(addr, val),
    }
}
pub fn str_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    store_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Word);
    DispatchRes::RetireOk
}
pub fn strb_reg(cpu: &mut Cpu, op: LoadStoreRegBits) -> DispatchRes {
    store_reg(cpu, op.rn(), op.rm(), op.rt(), Width::Byte);
    DispatchRes::RetireOk
}


/// Generic store (immediate).
fn store_imm(cpu: &mut Cpu, rn: u16, rt: u16, imm_n: u32, width: Width) {
    // Byte stores do not shift the immediate
    let imm = if width == Width::Byte { imm_n } else { imm_n << 2 };
    let addr = cpu.reg[rn].wrapping_add(imm);
    let val: u32 = cpu.reg[rt];
    match width {
        Width::Byte => cpu.mmu.write8(addr, val),
        Width::Half => cpu.mmu.write16(addr, val),
        Width::Word => cpu.mmu.write32(addr, val),
    }
}
pub fn str_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    store_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Word);
    DispatchRes::RetireOk
}
pub fn strb_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    store_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Byte);
    DispatchRes::RetireOk
}
pub fn strh_imm(cpu: &mut Cpu, op: LoadStoreImmBits) -> DispatchRes {
    store_imm(cpu, op.rn(), op.rt(), op.imm5() as u32, Width::Half);
    DispatchRes::RetireOk
}
pub fn str_imm_sp(cpu: &mut Cpu, op: LoadStoreAltBits) -> DispatchRes {
    store_imm(cpu, 13, op.rt(), op.imm8() as u32, Width::Word);
    DispatchRes::RetireOk
}


pub fn ldm(cpu: &mut Cpu, op: LoadStoreMultiBits) -> DispatchRes {
    let num_regs = op.register_list().count_ones();
    let writeback = (op.register_list() & (1 << op.rn())) == 0;

    let start_addr = cpu.reg[op.rn()];
    let end_addr = start_addr + (4 * num_regs);
    let mut addr = start_addr;
    for i in 0..8 {
        if (op.register_list() & (1 << i)) != 0 {
            let val = cpu.mmu.read32(addr);
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
            cpu.mmu.write32(addr, cpu.reg[i as u32]);
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
            cpu.mmu.write32(addr, cpu.reg[i as u32]);
            addr += 4;
        }
    }
    if op.m() {
        cpu.mmu.write32(addr, cpu.reg[Reg::Lr]);
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
            let val = cpu.mmu.read32(addr);
            cpu.reg[i as u32] = val;
            addr += 4;
        }
    }

    let new_pc = if op.p() { 
        let saved_lr = cpu.mmu.read32(addr);
        addr += 4;
        Some(saved_lr)
    } else { 
        None 
    };
    assert!(end_addr == addr);
    cpu.reg[Reg::Sp] = end_addr;

    if new_pc.is_some() {
        panic!("  POP pc={:08x} is unimplmented", new_pc.unwrap());
    } else {
        DispatchRes::RetireOk
    }
}


