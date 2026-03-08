//! ARM/Thumb instruction dispatch for the interpreter backend.

use ironic_core::cpu::excep::ExceptionType;
use ironic_core::cpu::Cpu;
use crate::interp::{ArmFn, ThumbFn};
use crate::interp::{arm, thumb};
use crate::decode::arm::ArmInst;
use crate::decode::thumb::ThumbInst;
use anyhow::anyhow;
/// The result of dispatching an instruction.
#[derive(Debug)]
pub enum DispatchRes {
    /// There was some fatal error dispatching the instruction.
    /// This probably means that emulation should halt.
    FatalErr(anyhow::Error),
    /// This instruction was not executed because the associated condition 
    /// could not be met, and the program counter must be incremented. 
    CondFailed,
    /// This instruction retired and resulted in a branch, and program counter 
    /// has already been adjusted to the new value.
    RetireBranch,
    /// This instruction retired successfully and the PC must be incremented.
    RetireOk,
    /// This instruction resulted in an exception.
    Exception(ExceptionType),
    /// A breakpoint instruction has been executed, the emulator pauses and waites for the debugger.
    Breakpoint
}


/// Handler for unimplemented ARM instructions.
pub fn arm_unimpl_instr(cpu: &mut Cpu, op: u32) -> DispatchRes {
    if (op & 0xe600_0000) != 0xe600_0000 {
        return DispatchRes::FatalErr(anyhow!("pc={:08x} Couldn't dispatch instruction {op:08x} ({:?})",
        cpu.read_fetch_pc(), ArmInst::decode(op)));
    }
    DispatchRes::Exception(ExceptionType::Undef(op))
}

/// Handler for unimplemented Thumb instructions.
pub fn thumb_unimpl_instr(cpu: &mut Cpu, op: u16) -> DispatchRes {
    DispatchRes::FatalErr(anyhow!("pc={:08x} Couldn't dispatch Thumb instruction {op:04x} ({:?})",
        cpu.read_fetch_pc(), ThumbInst::decode(op)))
}

// We use these macros to coerce the borrow checker into taking pointers to
// functions which take a newtype wrapping a u32/u16 (for bitfields).
macro_rules! afn { ($func:expr) => { unsafe {
    std::mem::transmute::<*const fn(), fn(&mut Cpu, u32) -> DispatchRes>
        ($func as *const fn())
}}}

macro_rules! tfn { ($func:expr) => { unsafe {
    std::mem::transmute::<*const fn(), fn(&mut Cpu, u16) -> DispatchRes>
        ($func as *const fn())
}}}



/// Map each decoded instruction to an implementation of an ARM instruction.
impl ArmFn {
    pub const fn from_inst(inst: ArmInst) -> Self {
        use ArmInst::*;
        match inst {
            MsrImm      => ArmFn(afn!(arm::status::msr_imm)),
            MsrReg      => ArmFn(afn!(arm::status::msr_reg)),
            Mrs         => ArmFn(afn!(arm::status::mrs)),
            Umull       => ArmFn(afn!(arm::multiply::umull)),
            Umlal       => ArmFn(afn!(arm::multiply::umlal)),
            Mul         => ArmFn(afn!(arm::multiply::mul)),

            LdrImm      => ArmFn(afn!(arm::loadstore::ldr_imm)),
            LdrbImm     => ArmFn(afn!(arm::loadstore::ldrb_imm)),
            LdrhImm     => ArmFn(afn!(arm::loadstore::ldrh_imm)),
            SubImm      => ArmFn(afn!(arm::dataproc::sub_imm)),
            SubReg      => ArmFn(afn!(arm::dataproc::sub_reg)),

            LdrReg      => ArmFn(afn!(arm::loadstore::ldr_reg)),
            StrReg      => ArmFn(afn!(arm::loadstore::str_reg)),

            Ldmib       => ArmFn(afn!(arm::loadstore::ldmib)),
            Ldm         => ArmFn(afn!(arm::loadstore::ldmia)),
            LdmRegUser  => ArmFn(afn!(arm::loadstore::ldm_user)),

            StrImm      => ArmFn(afn!(arm::loadstore::str_imm)),
            StrbImm     => ArmFn(afn!(arm::loadstore::strb_imm)),
            Stmdb       => ArmFn(afn!(arm::loadstore::stmdb)),
            Stm         => ArmFn(afn!(arm::loadstore::stm)),
            StmRegUser  => ArmFn(afn!(arm::loadstore::stm_user)),
            StrhImm     => ArmFn(afn!(arm::loadstore::strh_imm)),
            StrhReg     => ArmFn(afn!(arm::loadstore::strh_reg)),

            Mcr         => ArmFn(afn!(arm::coproc::mcr)),
            Mrc         => ArmFn(afn!(arm::coproc::mrc)),

            BlxImm     => ArmFn(afn!(arm::branch::blx_immm)),
            B           => ArmFn(afn!(arm::branch::b)),
            Bx          => ArmFn(afn!(arm::branch::bx)),
            BlImm       => ArmFn(afn!(arm::branch::bl_imm)),

            RsbImm      => ArmFn(afn!(arm::dataproc::rsb_imm)),
            RsbReg      => ArmFn(afn!(arm::dataproc::rsb_reg)),
            MovImm      => ArmFn(afn!(arm::dataproc::mov_imm)),
            MvnImm      => ArmFn(afn!(arm::dataproc::mvn_imm)),
            MvnReg      => ArmFn(afn!(arm::dataproc::mvn_reg)),
            MvnRegShiftReg=> ArmFn(afn!(arm::dataproc::mvn_rsr)),
            MovReg      => ArmFn(afn!(arm::dataproc::mov_reg)),
            MovRegShiftReg=> ArmFn(afn!(arm::dataproc::mov_rsr)),
            AddImm      => ArmFn(afn!(arm::dataproc::add_imm)),
            AddReg      => ArmFn(afn!(arm::dataproc::add_reg)),
            AdcImm      => ArmFn(afn!(arm::dataproc::adc_imm)),
            OrrImm      => ArmFn(afn!(arm::dataproc::orr_imm)),
            OrrReg      => ArmFn(afn!(arm::dataproc::orr_reg)),
            EorReg      => ArmFn(afn!(arm::dataproc::eor_reg)),
            EorImm      => ArmFn(afn!(arm::dataproc::eor_imm)),
            AndImm      => ArmFn(afn!(arm::dataproc::and_imm)),
            AndReg      => ArmFn(afn!(arm::dataproc::and_reg)),
            CmnImm      => ArmFn(afn!(arm::dataproc::cmn_imm)),
            CmpImm      => ArmFn(afn!(arm::dataproc::cmp_imm)),
            CmpReg      => ArmFn(afn!(arm::dataproc::cmp_reg)),
            TstReg      => ArmFn(afn!(arm::dataproc::tst_reg)),
            TstImm      => ArmFn(afn!(arm::dataproc::tst_imm)),
            TeqReg      => ArmFn(afn!(arm::dataproc::teq_reg)),
            TeqImm      => ArmFn(afn!(arm::dataproc::teq_imm)),
            BicImm      => ArmFn(afn!(arm::dataproc::bic_imm)),
            BicReg      => ArmFn(afn!(arm::dataproc::bic_reg)),
            BicRegShiftReg => ArmFn(afn!(arm::dataproc::bic_rsr)),
            Clz         => ArmFn(afn!(arm::dataproc::clz)),

            OrrRegShiftReg => ArmFn(afn!(arm::dataproc::orr_rsr)),
            AndRegShiftReg => ArmFn(afn!(arm::dataproc::and_rsr)),
            Bkpt        => ArmFn(afn!(arm::misc::bkpt)),
            Svc         => ArmFn(afn!(arm::misc::svc)),
            _           => ArmFn(arm_unimpl_instr),
        }
    }
}


impl ThumbFn {
    pub const fn from_inst(inst: ThumbInst) -> Self {
        use ThumbInst::*;
        match inst {
            Push        => ThumbFn(tfn!(thumb::loadstore::push)),
            Pop         => ThumbFn(tfn!(thumb::loadstore::pop)),
            Ldm         => ThumbFn(tfn!(thumb::loadstore::ldm)),
            Stm         => ThumbFn(tfn!(thumb::loadstore::stm)),
            LdrLit      => ThumbFn(tfn!(thumb::loadstore::ldr_lit)),
            LdrReg      => ThumbFn(tfn!(thumb::loadstore::ldr_reg)),
            LdrbReg     => ThumbFn(tfn!(thumb::loadstore::ldrb_reg)),
            LdrhReg     => ThumbFn(tfn!(thumb::loadstore::ldrh_reg)),
            LdrsbReg    => ThumbFn(tfn!(thumb::loadstore::ldrsb_reg)),
            LdrshReg    => ThumbFn(tfn!(thumb::loadstore::ldrsh_reg)),
            LdrImm      => ThumbFn(tfn!(thumb::loadstore::ldr_imm)),
            LdrbImm     => ThumbFn(tfn!(thumb::loadstore::ldrb_imm)),
            LdrhImm     => ThumbFn(tfn!(thumb::loadstore::ldrh_imm)),
            LdrImmAlt   => ThumbFn(tfn!(thumb::loadstore::ldr_imm_sp)),
            StrImmAlt   => ThumbFn(tfn!(thumb::loadstore::str_imm_sp)),
            StrReg      => ThumbFn(tfn!(thumb::loadstore::str_reg)),
            StrbReg     => ThumbFn(tfn!(thumb::loadstore::strb_reg)),
            StrhReg     => ThumbFn(tfn!(thumb::loadstore::strh_reg)),
            StrImm      => ThumbFn(tfn!(thumb::loadstore::str_imm)),
            StrbImm     => ThumbFn(tfn!(thumb::loadstore::strb_imm)),
            StrhImm     => ThumbFn(tfn!(thumb::loadstore::strh_imm)),

            Neg         => ThumbFn(tfn!(thumb::dataproc::neg)),
            CmpImm      => ThumbFn(tfn!(thumb::dataproc::cmp_imm)),
            CmpReg      => ThumbFn(tfn!(thumb::dataproc::cmp_reg)),
            CmpRegAlt   => ThumbFn(tfn!(thumb::dataproc::cmp_reg_alt)),
            MovReg      => ThumbFn(tfn!(thumb::dataproc::mov_reg)),
            MovRegShiftReg => ThumbFn(tfn!(thumb::dataproc::mov_rsr)),
            BicReg      => ThumbFn(tfn!(thumb::dataproc::bic_reg)),
            TstReg      => ThumbFn(tfn!(thumb::dataproc::tst_reg)),
            MvnReg      => ThumbFn(tfn!(thumb::dataproc::mvn_reg)),
            MovRegAlt   => ThumbFn(tfn!(thumb::dataproc::mov_reg_alt)),
            MovImm      => ThumbFn(tfn!(thumb::dataproc::mov_imm)),
            AddRegAlt   => ThumbFn(tfn!(thumb::dataproc::add_reg_alt)),
            AddReg      => ThumbFn(tfn!(thumb::dataproc::add_reg)),
            SubReg      => ThumbFn(tfn!(thumb::dataproc::sub_reg)),
            AddImm      => ThumbFn(tfn!(thumb::dataproc::add_imm)),
            SubImm      => ThumbFn(tfn!(thumb::dataproc::sub_imm)),
            AddImmAlt   => ThumbFn(tfn!(thumb::dataproc::add_imm_alt)),
            SubImmAlt   => ThumbFn(tfn!(thumb::dataproc::sub_imm_alt)),
            AddSpImmAlt => ThumbFn(tfn!(thumb::dataproc::add_sp_imm_alt)),
            AddSpImm    => ThumbFn(tfn!(thumb::dataproc::add_sp_imm)),
            SubSpImm    => ThumbFn(tfn!(thumb::dataproc::sub_sp_imm)),
            AndReg      => ThumbFn(tfn!(thumb::dataproc::and_reg)),
            OrrReg      => ThumbFn(tfn!(thumb::dataproc::orr_reg)),
            EorReg      => ThumbFn(tfn!(thumb::dataproc::eor_reg)),
            SbcReg      => ThumbFn(tfn!(thumb::dataproc::sbc_reg)),
            AdcReg      => ThumbFn(tfn!(thumb::dataproc::adc_reg)),
            Mul         => ThumbFn(tfn!(thumb::dataproc::mul_reg)),

            BlPrefix    => ThumbFn(tfn!(thumb::branch::bl_prefix)),
            BlImmSuffix => ThumbFn(tfn!(thumb::branch::bl_imm_suffix)),
            BlxReg      => ThumbFn(tfn!(thumb::branch::blx_reg)),
            Bx          => ThumbFn(tfn!(thumb::branch::bx)),
            B           => ThumbFn(tfn!(thumb::branch::b)),
            BAlt        => ThumbFn(tfn!(thumb::branch::b_unconditional)),
            BlxImmSuffix=> ThumbFn(tfn!(thumb::branch::blx_imm_suffix)),
            Svc         => ThumbFn(tfn!(thumb::misc::svc)),
            Bkpt        => ThumbFn(tfn!(thumb::misc::bkpt)),
            _           => ThumbFn(thumb_unimpl_instr),
        }
    }
}
