//! Load/store instructions.


use anyhow::bail;
use ironic_core::cpu::Cpu;
use ironic_core::cpu::reg::CpuMode;
use ironic_core::cpu::alu::*;
use crate::bits::arm::*;
use crate::interp::DispatchRes;

pub fn do_amode(rn: u32, imm: u32, u: bool, p: bool, w: bool) -> anyhow::Result<(u32, u32)> {
    let res = if u { rn.wrapping_add(imm) } else { rn.wrapping_sub(imm) };
    match (p, w) {
        (false, false)  => Ok((rn, res)),
        (true, false)   => Ok((res, rn)),
        (true, true)    => Ok((res, res)),
        (false, true)   => bail!("Unsupported addressing mode?"),
    }
}

pub fn do_amode_lit(pc: u32, imm: u32, p: bool, u: bool) -> u32 {
    match (p, u) {
        (true, true) => pc.wrapping_add(imm),
        (true, false) => pc.wrapping_sub(imm),
        _ => pc
    }
}

pub fn ldrb_imm(cpu: &mut Cpu, op: LsImmBits) -> DispatchRes {
    assert_ne!(op.rt(), 15);
    let res = if op.rn() == 15 {
        assert!(!op.w());
        let addr = do_amode_lit(cpu.read_exec_pc(), op.imm12(), op.p(), op.u());
        cpu.read8(addr)
    } else {
        let (addr, wb_addr) = match do_amode(cpu.reg[op.rn()],
            op.imm12(), op.u(), op.p(), op.w()){
                Ok(val) => val,
                Err(reason) => { return DispatchRes::FatalErr(reason); }
            };
        cpu.reg[op.rn()] = wb_addr;
        cpu.read8(addr)
    };
    let res = match res {
        Ok(val) => val,
        Err(reason) => {
            return DispatchRes::FatalErr(reason);
        }
    };
    cpu.reg[op.rt()] = res as u32;
    DispatchRes::RetireOk
}

pub fn ldrh_imm(cpu: &mut Cpu, op: LsSignedImmBits) -> DispatchRes {
    assert_ne!(op.rt(), 15);
    let offset = (op.imm4h() << 4) | op.imm4l();
    let (addr,wb_addr) = match do_amode(cpu.reg[op.rn()], offset, op.u(), op.p(), op.w()) {
        Ok(val) => val,
        Err(reason) => { return DispatchRes::FatalErr(reason); }
    };
    let res = match cpu.read16(addr) {
        Ok(val) => val,
        Err(reason) => {
            return DispatchRes::FatalErr(reason);
        }
    };
    cpu.reg[op.rt()] = res as u32;
    cpu.reg[op.rn()] = wb_addr;
    DispatchRes::RetireOk
}



pub fn ldr_imm(cpu: &mut Cpu, op: LsImmBits) -> DispatchRes {
    let res = if op.rn() == 15 {
        assert!(!op.w());
        let addr = do_amode_lit(cpu.read_exec_pc(), op.imm12(), op.p(), op.u());
        cpu.read32(addr)
    } else {
        let (addr, wb_addr) = match do_amode(cpu.reg[op.rn()],
            op.imm12(), op.u(), op.p(), op.w()){
                Ok(val) => val,
                Err(reason) => { return DispatchRes::FatalErr(reason); }
            };
        cpu.reg[op.rn()] = wb_addr;
        cpu.read32(addr)
    };
    let res = match res {
        Ok(val) => val,
        Err(reason) => {
            return DispatchRes::FatalErr(reason);
        }
    };
    if op.rt() == 15 {
        cpu.reg.cpsr.set_thumb(res & 1 != 0);
        cpu.write_exec_pc(res & 0xffff_fffe);
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rt()] = res;
        DispatchRes::RetireOk
    }
}

pub fn str_imm(cpu: &mut Cpu, op: LsImmBits) -> DispatchRes {
    let (addr, wb_addr) = match do_amode(cpu.reg[op.rn()],
    op.imm12(), op.u(), op.p(), op.w()){
        Ok(val) => val,
        Err(reason) => { return DispatchRes::FatalErr(reason); }
    };
    cpu.reg[op.rn()] = wb_addr;
    match cpu.write32(addr, cpu.reg[op.rt()]) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}
pub fn strb_imm(cpu: &mut Cpu, op: LsImmBits) -> DispatchRes {
    let (addr, wb_addr) = match do_amode(cpu.reg[op.rn()],
    op.imm12(), op.u(), op.p(), op.w()){
        Ok(val) => val,
        Err(reason) => { return DispatchRes::FatalErr(reason); }
    };
    cpu.reg[op.rn()] = wb_addr;
    match cpu.write8(addr, cpu.reg[op.rt()]) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}




pub fn ldr_reg(cpu: &mut Cpu, op: LsRegBits) -> DispatchRes {
    let (offset, _) = barrel_shift(ShiftArgs::Reg { rm: cpu.reg[op.rm()],
        stype: op.stype(), imm5: op.imm5(), c_in: cpu.reg.cpsr.c()
    });

    let (addr, wb_addr) = match do_amode(cpu.reg[op.rn()],
        offset, op.u(), op.p(), op.w()) {
            Ok(val) => val,
            Err(reason) => { return DispatchRes::FatalErr(reason); }
    };
    let val = match cpu.read32(addr) {
        Ok(val) => val,
        Err(reason) => {
            return DispatchRes::FatalErr(reason);
        }
    };

    cpu.reg[op.rn()] = wb_addr;
    if op.rt() == 15 {
        cpu.write_exec_pc(val);
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rt()] = val;
        DispatchRes::RetireOk
    }
}

pub fn str_reg(cpu: &mut Cpu, op: LsRegBits) -> DispatchRes {
    let (offset, _) = barrel_shift(ShiftArgs::Reg { rm: cpu.reg[op.rm()],
        stype: op.stype(), imm5: op.imm5(), c_in: cpu.reg.cpsr.c()
    });

    let (addr, wb_addr) = match do_amode(cpu.reg[op.rn()],
        offset, op.u(), op.p(), op.w()){
            Ok(val) => val,
            Err(reason) => { return DispatchRes::FatalErr(reason); }
        };

    let val = cpu.reg[op.rt()];
    match cpu.write32(addr, val) {
        Ok(_) => {
            cpu.reg[op.rn()] = wb_addr;
            DispatchRes::RetireOk
        },
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}




pub fn stm_user(cpu: &mut Cpu, op: StmRegUserBits) -> DispatchRes {
    assert_ne!(op.rn(), 15);
    let reglist = op.register_list();
    let len = reglist.count_ones() * 4;
    let mut addr = if op.u() { 
        cpu.reg[op.rn()]
    } else {
        cpu.reg[op.rn()] - len
    };
    if op.p() == op.u() {
        addr += 4;
    }

    // Executing in Usr/Sys is actually unpredictable according to ARM ARM
    let current_mode = cpu.reg.cpsr.mode();
    if current_mode != CpuMode::Usr { 
        cpu.reg.swap_bank(current_mode, CpuMode::Usr); 
    }
    for i in 0..16 {
        if (reglist & (1 << i)) != 0 {
            let val = cpu.reg[i as u32];
            match cpu.write32(addr, val) {
                Ok(_) => {},
                Err(reason) => { return DispatchRes::FatalErr(reason); } 
            }
            addr += 4;
        }
    }
    if current_mode != CpuMode::Usr { 
        cpu.reg.swap_bank(CpuMode::Usr, current_mode); 
    }
    DispatchRes::RetireOk
}

pub fn ldm_user(cpu: &mut Cpu, op: LdmRegUserBits) -> DispatchRes {
    assert_ne!(op.rn(), 15);
    let reglist = op.register_list();
    if (reglist >> 15) & 1 == 1 { // S bit is set, so if the PC is set, we restore the SPSR and branch, if we aren't touching the PC, we just use Usr mode registers.
        return ldm_user_pc(cpu, op);
    }

    let len = reglist.count_ones() * 4;
    let mut addr = if op.u() { 
        cpu.reg[op.rn()]
    } else {
        cpu.reg[op.rn()] - len
    };
    if op.p() == op.u() {
        addr += 4;
    }

    // Executing in Usr/Sys is actually unpredictable according to ARM ARM
    let current_mode = cpu.reg.cpsr.mode();
    if current_mode != CpuMode::Usr { 
        cpu.reg.swap_bank(current_mode, CpuMode::Usr); 
    }
    for i in 0..16 {
        if (reglist & (1 << i)) != 0 {
            let val = match cpu.read32(addr) {
                Ok(val) => val,
                Err(reason) => {
                    return DispatchRes::FatalErr(reason);
                }
            };
            cpu.reg[i as u32] = val;
            addr += 4;
        }
    }
    if current_mode != CpuMode::Usr { 
        cpu.reg.swap_bank(CpuMode::Usr, current_mode); 
    }

    DispatchRes::RetireOk
}

pub fn ldm_user_pc(cpu: &mut Cpu, op: LdmRegUserBits) -> DispatchRes {
    let reglist = op.register_list();
    let len = reglist.count_ones() * 4;
    let mut addr = if op.u() {
        cpu.reg[op.rn()]
    } else {
        cpu.reg[op.rn()] - len
    };
    if op.p() == op.u() {
        addr += 4;
    }

    let current_mode = cpu.reg.cpsr.mode();
    if current_mode != CpuMode::Usr { 
        cpu.reg.swap_bank(current_mode, CpuMode::Usr); 
    }
    for i in 0..=14 {
        if (reglist & (1 << i)) != 0 {
            let val = match cpu.read32(addr) {
                Ok(val) => val,
                Err(reason) => {
                    return DispatchRes::FatalErr(reason);
                }
            };
            cpu.reg[i as u32] = val;
            addr += 4;
        }
    }

    let new_pc = match cpu.read32(addr) {
        Ok(val) => val,
        Err(reason) => {
            return DispatchRes::FatalErr(reason);
        }
    };
    addr += 4;
    if op.w() {
        cpu.reg[op.rn()] = addr;
    }
    if let Err(reason) = cpu.exception_return(new_pc){
        return DispatchRes::FatalErr(reason);
    };

    DispatchRes::RetireBranch
}

pub fn ldmib(cpu: &mut Cpu, op: LsMultiBits) -> DispatchRes {
    assert_ne!(op.rn(), 15);
    let reglist = op.register_list();
    let mut addr = cpu.reg[op.rn()] + 4;
    let wb_addr = addr + (reglist.count_ones() * 4);

    for i in 0..16 {
        if (reglist & (1 << i)) != 0 {
            cpu.reg[i as u32] = match cpu.read32(addr){
                Ok(val) => val,
                Err(reason) => {
                    return DispatchRes::FatalErr(reason);
                }
            };
            addr += 4;
        }
    }
    assert!(addr == wb_addr);
    if op.w() { 
        cpu.reg[op.rn()] = wb_addr;
    }
    DispatchRes::RetireOk
}


pub fn ldmia(cpu: &mut Cpu, op: LsMultiBits) -> DispatchRes {
    assert_ne!(op.rn(), 15);
    let reglist = op.register_list();
    let mut addr = cpu.reg[op.rn()];
    let wb_addr = addr + (reglist.count_ones() * 4);

    let mut branch = false;
    for i in 0..16 {
        if (reglist & (1 << i)) != 0 {
            if i == 15 {
                let temp_addr = match cpu.read32(addr) {
                    Ok(val) => val,
                    Err(reason) => {
                        return DispatchRes::FatalErr(reason);
                    }
                };
                let new_pc = temp_addr & 0xfffffffe;
                cpu.reg.cpsr.set_thumb(new_pc & 1 != 1);
                cpu.write_exec_pc(new_pc);
                branch = true;
                addr += 4;
            } else {
                let temp_addr = match cpu.read32(addr) {
                    Ok(val) => val,
                    Err(reason) => {
                        return DispatchRes::FatalErr(reason);
                    }
                };
                cpu.reg[i as u32] = temp_addr;
                addr += 4;
            }
        }
    }
    assert!(addr == wb_addr);
    if op.w() { 
        cpu.reg[op.rn()] = wb_addr;
    }

    if branch {
        DispatchRes::RetireBranch
    } else {
        DispatchRes::RetireOk
    }
}



pub fn stmdb(cpu: &mut Cpu, op: LsMultiBits) -> DispatchRes {
    assert_ne!(op.rn(), 15);
    let reglist = op.register_list();
    let mut addr = cpu.reg[op.rn()] - (reglist.count_ones() * 4);
    let wb_addr = addr;

    for i in 0..16 {
        if (reglist & (1 << i)) != 0 {
            let val = if i == 15 {
                cpu.read_exec_pc()
            } else {
                cpu.reg[i as u32]
            };
            match cpu.write32(addr, val)  {
                Ok(_) => {},
                Err(reason) => { return DispatchRes::FatalErr(reason); }
            };
            addr += 4;
        }
    }
    if op.w() { 
        cpu.reg[op.rn()] = wb_addr;
    }
    DispatchRes::RetireOk
}

pub fn stm(cpu: &mut Cpu, op: LsMultiBits) -> DispatchRes {
    assert_ne!(op.rn(), 15);

    let reglist = op.register_list();
    let mut addr = cpu.reg[op.rn()];
    let wb_addr = addr + (reglist.count_ones() * 4);

    for i in 0..16 {
        if (reglist & (1 << i)) != 0 {
            let val = if i == 15 {
                cpu.read_exec_pc()
            } else {
                cpu.reg[i as u32]
            };
            match cpu.write32(addr, val) {
                Ok(_) => {},
                Err(reason) => { return DispatchRes::FatalErr(reason); }
            };
            addr += 4;
        }
    }

    assert!(addr == wb_addr);
    if op.w() { 
        cpu.reg[op.rn()] = wb_addr;
    }
    DispatchRes::RetireOk
}

pub fn strh_imm(cpu: &mut Cpu, op: LsSignedImmBits) -> DispatchRes {
    let offset = (op.imm4h() << 4) | op.imm4l();
    let (addr, wb_addr) = match do_amode(cpu.reg[op.rn()],
        offset, op.u(), op.p(), op.w()) {
            Ok(val) => val,
            Err(reason) => { return DispatchRes::FatalErr(reason); }
        };
    cpu.reg[op.rn()] = wb_addr;
    match cpu.write16(addr, cpu.reg[op.rt()]) {
        Ok(_) => DispatchRes::RetireOk,
        Err(reason) => DispatchRes::FatalErr(reason)
    }
}

