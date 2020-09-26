//! Types used for dispatching instructions.

use crate::cpu::*;
use crate::cpu::armv5::*;
use crate::cpu::armv5::decode::*;

use crate::cpu::armv5::interp;
use crate::cpu::armv5::interp::branch;
use crate::cpu::armv5::interp::loadstore;
use crate::cpu::armv5::interp::dataproc;

/// A function pointer to an ARM instruction implementation.
#[derive(Clone, Copy)]
pub struct ArmFn(pub fn(&mut Cpu, u32) -> DispatchRes);

/// Implementing [InstLutEntry] maps each instruction to a function.
impl InstLutEntry for ArmFn {
    type Inst = ArmInst;
    fn from_inst(inst: ArmInst) -> Self {
        use ArmInst::*;
        use std::mem::transmute;

        // We use this to coerce the borrow checker into taking pointers to
        // functions which take a newtype wrapping a u32 (for bitfields).
        macro_rules! cfn { ($func:expr) => { unsafe {
            transmute::<*const fn(), fn(&mut Cpu, u32) -> DispatchRes>
                ($func as *const fn())
        }}}

        match inst {
            LdrLit | LdrImm     => ArmFn(loadstore::ldr_imm_or_lit),
            SubImm | SubSpImm   => ArmFn(cfn!(dataproc::sub_imm)),

            StrImm              => ArmFn(cfn!(loadstore::str_imm)),

            Stmdb               => ArmFn(cfn!(loadstore::stmdb)),
            BlImm               => ArmFn(cfn!(branch::bl_imm)),
            B                   => ArmFn(cfn!(branch::b)),
            MovImm              => ArmFn(cfn!(dataproc::mov_imm)),
            MovReg              => ArmFn(cfn!(dataproc::mov_reg)),
            AddImm              => ArmFn(cfn!(dataproc::add_imm)),
            _ => ArmFn(interp::unimpl_instr),
        }
    }
}

/// An ARMv5 lookup table.
pub struct ArmLut { 
    pub data: [ArmFn; 0x1000] 
}
impl InstLut for ArmLut {
    const LUT_SIZE: usize = 0x1000;
    type Entry = ArmFn;
    type Instr = ArmInst;
    type Index = usize;

    fn lookup(&self, opcd: u32) -> ArmFn { 
        self.data[Self::opcd_to_idx(opcd)] 
    }

    fn idx_to_opcd(idx: usize) -> u32 {
        (((idx & 0x0ff0) << 16) | ((idx & 0x000f) << 4)) as u32
    }

    fn opcd_to_idx(opcd: u32) -> usize {
        (((opcd >> 16) & 0x0ff0) | ((opcd >> 4) & 0x000f)) as usize
    }

    fn create_lut(default_entry: ArmFn) -> Self {
        let mut lut = ArmLut {
            data: [default_entry; 0x1000],
        };
        for i in 0..Self::LUT_SIZE {
            let opcd = ArmLut::idx_to_opcd(i);
            lut.data[i as usize] = ArmFn::from_inst(ArmInst::decode(opcd));
        }
        lut
    }
}

/// Container for lookup tables
pub struct Lut {
    pub arm: ArmLut,
}
impl Lut {
    pub fn new() -> Self {
        Lut {
            arm: ArmLut::create_lut(ArmFn(interp::unimpl_instr)),
        }
    }
}


