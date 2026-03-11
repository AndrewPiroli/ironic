//! Data-processing instructions.

use anyhow::anyhow;
use ironic_core::cpu::Cpu;
use ironic_core::cpu::alu::*;
use crate::bits::arm::*;
use crate::interp::DispatchRes;

/// Set all of the condition flags.
macro_rules! set_all_flags { 
    ($cpu:ident, $n:ident, $z:ident, $c:ident, $v:ident) => {
        $cpu.reg.cpsr.set_n($n);
        $cpu.reg.cpsr.set_z($z);
        $cpu.reg.cpsr.set_c($c);
        $cpu.reg.cpsr.set_v($v);
    }
}

pub fn add_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    let (val, _) = barrel_shift(ShiftArgs::Imm {
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c()
    });
    let (res, n, z, c, v) = add_generic(cpu.reg[op.rn()], val);
    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            set_all_flags!(cpu, n, z, c, v);
        }
        DispatchRes::RetireOk
    }
}

pub fn rsb_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    let (val, _) = barrel_shift(ShiftArgs::Imm {
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c()
    });
    let (res, n, z, c, v) = sub_generic(val, cpu.reg[op.rn()]);
    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            set_all_flags!(cpu, n, z, c, v);
        }
        DispatchRes::RetireOk
    }
}

pub fn sub_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    let (val, _) = barrel_shift(ShiftArgs::Imm {
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c()
    });
    let rn_val = if op.rn() == 15 {
        cpu.read_exec_pc()
    } else {
        cpu.reg[op.rn()]
    };

    let (res, n, z, c, v) = sub_generic(rn_val, val);
    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            set_all_flags!(cpu, n, z, c, v);
        }
        DispatchRes::RetireOk
    }
}

pub fn mvn_imm(cpu: &mut Cpu, op: MovImmBits) -> DispatchRes {
    assert_ne!(op.rd(), 15);

    let (val, carry) = barrel_shift(ShiftArgs::Imm { 
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c() 
    });
    let res = !val;
    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
            cpu.reg.cpsr.set_z(res == 0);
            cpu.reg.cpsr.set_c(carry);
        }
        DispatchRes::RetireOk
    }
}

pub fn mov_imm(cpu: &mut Cpu, op: MovImmBits) -> DispatchRes {
    assert_ne!(op.rd(), 15);
    let (res, carry) = barrel_shift(ShiftArgs::Imm { 
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c() 
    });
    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
            cpu.reg.cpsr.set_z(res == 0);
            cpu.reg.cpsr.set_c(carry);
        }
        DispatchRes::RetireOk
    }
}


pub fn add_reg(cpu: &mut Cpu, op: DpRegBits) -> DispatchRes {
    let rm = if op.rm() == 15 { cpu.read_exec_pc() } else { cpu.reg[op.rm()] };
    let (val, _) = barrel_shift(ShiftArgs::Reg { rm, 
        stype: op.stype(), imm5: op.imm5(), c_in: cpu.reg.cpsr.c()
    });

    let rn_val = if op.rn() == 15 {
        cpu.read_exec_pc()
    } else {
        cpu.reg[op.rn()]
    };

    let (res, n, z, c, v) = add_generic(rn_val, val);

    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            set_all_flags!(cpu, n, z, c, v);
        }
        DispatchRes::RetireOk
    }
}

pub fn rsb_reg(cpu: &mut Cpu, op: DpRegBits) -> DispatchRes {
    let (val, _) = barrel_shift(ShiftArgs::Reg { rm: cpu.reg[op.rm()],
        stype: op.stype(), imm5: op.imm5(), c_in: cpu.reg.cpsr.c()
    });
    let (res, n, z, c, v) = sub_generic(val, cpu.reg[op.rn()]);
    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            set_all_flags!(cpu, n, z, c, v);
        }
        DispatchRes::RetireOk
    }
}

pub fn sub_reg(cpu: &mut Cpu, op: DpRegBits) -> DispatchRes {
    let rm = if op.rm() == 15 { cpu.read_exec_pc() } else { cpu.reg[op.rm()] };
    let (val, _) = barrel_shift(ShiftArgs::Reg { rm, 
        stype: op.stype(), imm5: op.imm5(), c_in: cpu.reg.cpsr.c()
    });
    let (res, n, z, c, v) = sub_generic(cpu.reg[op.rn()], val);
    if op.rd() == 15 {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            set_all_flags!(cpu, n, z, c, v);
        }
        DispatchRes::RetireOk
    }

}

pub fn mvn_reg(cpu: &mut Cpu, op: MovRegBits) -> DispatchRes {
    let (val, carry) = barrel_shift(ShiftArgs::Reg { rm: cpu.reg[op.rm()],
        stype: op.stype(), imm5: op.imm5(), c_in: cpu.reg.cpsr.c(),
    });
    let res = !val;
    if op.rd() == 15  {
        if op.s() {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
            cpu.reg.cpsr.set_z(res == 0);
            cpu.reg.cpsr.set_c(carry);
        }
        DispatchRes::RetireOk
    }
}

pub fn mov_reg(cpu: &mut Cpu, op: MovRegBits) -> DispatchRes {
    let rm = if op.rm() == 15 { cpu.read_exec_pc() } else { cpu.reg[op.rm()] };
    let (res, carry) = barrel_shift(ShiftArgs::Reg { rm,
        stype: op.stype(), imm5: op.imm5(), c_in: cpu.reg.cpsr.c()
    });
    if op.rd() == 15 {
        if op.s() { 
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else { 
            cpu.write_exec_pc(res); 
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[op.rd()] = res;
        if op.s() {
            cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
            cpu.reg.cpsr.set_z(res == 0);
            cpu.reg.cpsr.set_c(carry);
        }
        DispatchRes::RetireOk
    }
}

pub fn mov_rsr(cpu: &mut Cpu, op: MovRsrBits) -> DispatchRes {
    debug_assert!(op.0 & 0x2000090 != 0x90); // bits set I==0, bit4==1, bit7==1 means not a mov instruction.
    let (val, carry) = barrel_shift(
        ShiftArgs::RegShiftReg { rm: cpu.reg[op.rm()], stype: op.stype(), rs: cpu.reg[op.rs()], c_in: cpu.reg.cpsr.c() }
    );
    match (op.s(), op.rd() == 15) {
        (true, true) => { // S + PC == exception return
            if let Err(reason) = cpu.exception_return(val){
                return DispatchRes::FatalErr(reason);
            };
            DispatchRes::RetireBranch
        },
        (true, false) => { // S + no PC == set flags
            cpu.reg[op.rd()] = val;
            let (n,z,c, v) = (
                ((val >> 31) & 0x1 == 1), // N
                val == 0, // Z
                carry, // C
                cpu.reg.cpsr.v() // V
            );
            set_all_flags!(cpu, n, z, c, v);
            DispatchRes::RetireOk
        },
        (false, true) => { // no S + PC == branch
            cpu.write_exec_pc(val);
            DispatchRes::RetireBranch
        },
        (false, false) => { // no S + no PC == normal move/shift no flags
            cpu.reg[op.rd()] = val;
            DispatchRes::RetireOk
        }
    }
}

pub fn mvn_rsr(cpu: &mut Cpu, op: MovRsrBits) -> DispatchRes {
    let (val, carry) = barrel_shift(
        ShiftArgs::RegShiftReg { rm: cpu.reg[op.rm()], stype: op.stype(), rs: cpu.reg[op.rs()], c_in: cpu.reg.cpsr.c() }
    );
    let val = !val;
    match (op.s(), op.rd() == 15) {
        (true, true) => { // S + PC == exception return
            if let Err(reason) = cpu.exception_return(val){
                return DispatchRes::FatalErr(reason);
            };
            DispatchRes::RetireBranch
        },
        (true, false) => { // S + no PC == set flags
            cpu.reg[op.rd()] = val;
            let (n,z,c, v) = (
                ((val >> 31) & 0x1 == 1), // N
                val == 0, // Z
                carry, // C
                cpu.reg.cpsr.v() // V
            );
            set_all_flags!(cpu, n, z, c, v);
            DispatchRes::RetireOk
        },
        (false, true) => { // no S + PC == branch
            cpu.write_exec_pc(val);
            DispatchRes::RetireBranch
        },
        (false, false) => { // no S + no PC == normal move/shift no flags
            cpu.reg[op.rd()] = val;
            DispatchRes::RetireOk
        }
    }
}

pub fn orr_rsr(cpu: &mut Cpu, op: DpRsrBits) -> DispatchRes {
    assert_ne!(op.rd(), 15);

    let (val, carry) = barrel_shift(ShiftArgs::RegShiftReg {
        rm: cpu.reg[op.rm()], 
        stype: op.stype(), 
        rs: cpu.reg[op.rs()],
        c_in: cpu.reg.cpsr.c()
    });

    let res = cpu.reg[op.rn()] | val;
    if op.s() {
        cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
        cpu.reg.cpsr.set_z(res == 0);
        cpu.reg.cpsr.set_c(carry);
    }
    cpu.reg[op.rd()] = res;
    DispatchRes::RetireOk
}
pub fn and_rsr(cpu: &mut Cpu, op: DpRsrBits) -> DispatchRes {
    assert_ne!(op.rd(), 15);

    let (val, carry) = barrel_shift(ShiftArgs::RegShiftReg {
        rm: cpu.reg[op.rm()], 
        stype: op.stype(), 
        rs: cpu.reg[op.rs()],
        c_in: cpu.reg.cpsr.c()
    });

    let res = cpu.reg[op.rn()] & val;
    if op.s() {
        cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
        cpu.reg.cpsr.set_z(res == 0);
        cpu.reg.cpsr.set_c(carry);
    }
    cpu.reg[op.rd()] = res;
    DispatchRes::RetireOk
}



#[allow(unreachable_patterns)]
fn do_bitwise_reg(cpu: &mut Cpu, opcd: DpRegBits, op: BitwiseOp) -> DispatchRes {
    let rn = opcd.rn();
    let rm = opcd.rm();
    let rd = opcd.rd();
    let imm5 = opcd.imm5();
    let s = opcd.s();
    let stype = opcd.stype();
    assert_ne!(rd, 15);
    let (val, carry) = barrel_shift(ShiftArgs::Reg {
        rm: cpu.reg[rm], stype, imm5, c_in: cpu.reg.cpsr.c()
    });
    let base = cpu.reg[rn];
    let res = match op {
        BitwiseOp::And => base & val,
        BitwiseOp::Bic => base & !val,
        BitwiseOp::Orr => base | val,
        BitwiseOp::Eor => base ^ val,
        _ => { return DispatchRes::FatalErr(anyhow!("ARM reg bitwise {op:?} unimpl")); },
    };
    if rd == 15 {
        if s {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[rd] = res;
        if s {
            cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
            cpu.reg.cpsr.set_z(res == 0);
            cpu.reg.cpsr.set_c(carry);
        }
        DispatchRes::RetireOk
    }
}
pub fn orr_reg(cpu: &mut Cpu, op: DpRegBits) -> DispatchRes {
    do_bitwise_reg(cpu, op, BitwiseOp::Orr)
}
pub fn eor_reg(cpu: &mut Cpu, op: DpRegBits) -> DispatchRes {
    do_bitwise_reg(cpu, op, BitwiseOp::Eor)
}
pub fn and_reg(cpu: &mut Cpu, op: DpRegBits) -> DispatchRes {
    do_bitwise_reg(cpu, op, BitwiseOp::And)
}
pub fn bic_reg(cpu: &mut Cpu, op: DpRegBits) -> DispatchRes {
    do_bitwise_reg(cpu, op, BitwiseOp::Bic)
}


#[allow(unreachable_patterns)]
fn do_bitwise_imm(cpu: &mut Cpu, rn: u32, rd: u32, imm: u32, 
    s: bool, op: BitwiseOp) -> DispatchRes {
    assert_ne!(rd, 15);
    let (val, carry) = barrel_shift(ShiftArgs::Imm { 
        imm12: imm, c_in: cpu.reg.cpsr.c() 
    });
    let base = cpu.reg[rn];
    let res = match op {
        BitwiseOp::And => base & val,
        BitwiseOp::Bic => base & !val,
        BitwiseOp::Orr => base | val,
        BitwiseOp::Eor => base ^ val,
        _ => { return DispatchRes::FatalErr(anyhow!("ARM imm bitwise {op:?} unimplemented")); },
    };
    if rd == 15 {
        if s {
            if let Err(reason) = cpu.exception_return(res){
                return DispatchRes::FatalErr(reason);
            };
        } else {
            cpu.write_exec_pc(res);
        }
        DispatchRes::RetireBranch
    } else {
        cpu.reg[rd] = res;
        if s {
            cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
            cpu.reg.cpsr.set_z(res == 0);
            cpu.reg.cpsr.set_c(carry);
        }
        DispatchRes::RetireOk
    }
}
pub fn and_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    do_bitwise_imm(cpu, op.rn(), op.rd(), op.imm12(), op.s(), BitwiseOp::And)
}
pub fn bic_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    do_bitwise_imm(cpu, op.rn(), op.rd(), op.imm12(), op.s(), BitwiseOp::Bic)
}
pub fn orr_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    do_bitwise_imm(cpu, op.rn(), op.rd(), op.imm12(), op.s(), BitwiseOp::Orr)
}
pub fn eor_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    do_bitwise_imm(cpu, op.rn(), op.rd(), op.imm12(), op.s(), BitwiseOp::Eor)
}




pub fn cmn_imm(cpu: &mut Cpu, op: DpTestImmBits) -> DispatchRes {
    let (val, _) = barrel_shift(ShiftArgs::Imm {
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c()
    });
    let (_, n, z, c, v) = add_generic(cpu.reg[op.rn()], val);
    set_all_flags!(cpu, n, z, c, v);
    DispatchRes::RetireOk
}

pub fn cmp_imm(cpu: &mut Cpu, op: DpTestImmBits) -> DispatchRes {
    let (val, _) = barrel_shift(ShiftArgs::Imm {
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c()
    });
    let (_, n, z, c, v) = sub_generic(cpu.reg[op.rn()], val);
    set_all_flags!(cpu, n, z, c, v);
    DispatchRes::RetireOk
}

pub fn cmp_reg(cpu: &mut Cpu, op: DpTestRegBits) -> DispatchRes {
    let (val, _) = barrel_shift(ShiftArgs::Reg {
        rm: cpu.reg[op.rm()], 
        stype: op.stype(), 
        imm5: op.imm5(), 
        c_in: cpu.reg.cpsr.c()
    });

    let (_, n, z, c, v) = sub_generic(cpu.reg[op.rn()], val);
    set_all_flags!(cpu, n, z, c, v);
    DispatchRes::RetireOk
}


pub fn tst_imm(cpu: &mut Cpu, op: DpTestImmBits) -> DispatchRes {
    let (val, carry) = barrel_shift(ShiftArgs::Imm {
        imm12: op.imm12(), c_in: cpu.reg.cpsr.c()
    });
    let res = cpu.reg[op.rn()] & val;
    cpu.reg.cpsr.set_n(res & 0x8000_0000 != 0);
    cpu.reg.cpsr.set_z(res == 0);
    cpu.reg.cpsr.set_c(carry);
    DispatchRes::RetireOk
}

pub fn tst_reg(cpu: &mut Cpu, op: DpTestRegBits) -> DispatchRes {
    let (val, carry) = barrel_shift(ShiftArgs::Reg {
        rm: cpu.reg[op.rm()], 
        stype: op.stype(), 
        imm5: op.imm5(), 
        c_in: cpu.reg.cpsr.c()
    });

    let res = cpu.reg[op.rn()] & val;
    cpu.reg.cpsr.set_n(res & 0x8000_0000 != 0);
    cpu.reg.cpsr.set_z(res == 0);
    cpu.reg.cpsr.set_c(carry);
    DispatchRes::RetireOk
}

pub fn clz(cpu: &mut Cpu, op: ClzBits) -> DispatchRes {
    assert_ne!(op.rm(), 15);
    assert_ne!(op.rd(), 15);

    let rm = cpu.reg[op.rm()];
    let res = rm.leading_zeros();
    cpu.reg[op.rd()] = res;

    DispatchRes::RetireOk
}

pub fn bic_rsr(cpu: &mut Cpu, op: DpRsrBits) -> DispatchRes {
    assert!(!(op.s() && op.rd() == 15)); //FIXME: this is not always the case, good enough for now

    let (val, carry) = barrel_shift(ShiftArgs::RegShiftReg {
        rm: cpu.reg[op.rm()],
        stype: op.stype(),
        rs: cpu.reg[op.rs()],
        c_in: cpu.reg.cpsr.c()
    });

    //let base = cpu.reg[op.rd()];
    let res = cpu.reg[op.rn()] & !val;

    if op.s() {
        cpu.reg.cpsr.set_n((res & 0x8000_0000) != 0);
        cpu.reg.cpsr.set_z(res == 0);
        cpu.reg.cpsr.set_c(carry);
    }

    cpu.reg[op.rd()] = res;

    DispatchRes::RetireOk
}

pub fn adc_imm(cpu: &mut Cpu, op: DpImmBits) -> DispatchRes {
    let val = cpu.reg[op.rn()].wrapping_add(cpu.reg.cpsr.c() as u32);
    let (res, n, z, c,v ) = add_generic(val, op.imm12());
    match (op.rd() == 15, op.s()) {
        (true, true) => {
            if let Err(reason) = cpu.exception_return(res) {
                return DispatchRes::FatalErr(reason);
            }
            DispatchRes::RetireBranch
        },
        (true, false) => {
            cpu.write_exec_pc(val);
            DispatchRes::RetireBranch
        },
        (false, true) => {
            cpu.reg[op.rd()] = res;
            set_all_flags!(cpu, n, z, c, v);
            DispatchRes::RetireOk
        },
        (false, false) => {
            cpu.reg[op.rd()] = res;
            DispatchRes::RetireOk
        },
    }
}

pub fn teq_imm(cpu: &mut Cpu, op: DpTestImmBits) -> DispatchRes {
    let (val, carry) = barrel_shift(ShiftArgs::Imm {
        imm12: op.imm12(),
        c_in: cpu.reg.cpsr.c(),
    });

    let res = cpu.reg[op.rn()] ^ val;
    cpu.reg.cpsr.set_n(res & 0x8000_0000 != 0);
    cpu.reg.cpsr.set_z(res == 0);
    cpu.reg.cpsr.set_c(carry);
    DispatchRes::RetireOk
}

pub fn teq_reg(cpu: &mut Cpu, op: DpTestRegBits) -> DispatchRes {
    let (val, carry) = barrel_shift(ShiftArgs::Reg {
        rm: cpu.reg[op.rm()],
        stype: op.stype(),
        imm5: op.imm5(),
        c_in: cpu.reg.cpsr.c(),
    });

    let res = cpu.reg[op.rn()] ^ val;
    cpu.reg.cpsr.set_n(res & 0x8000_0000 != 0);
    cpu.reg.cpsr.set_z(res == 0);
    cpu.reg.cpsr.set_c(carry);
    DispatchRes::RetireOk
}