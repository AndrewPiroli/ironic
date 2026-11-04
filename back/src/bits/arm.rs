//! Wrapper types for representing ARM instructions as bitfields.

use super::{xDisplay, DisassemblyContext};

/// ['Stc', 'LdcImm']
#[repr(transparent)]
pub struct LsCoprocBits(pub u32);
impl LsCoprocBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn imm8(&self) -> u32 { self.0 & 0x000000ff }
} impl xDisplay for LsCoprocBits {} // Ununused instruction

/// ['MvnReg', 'MovReg']
#[repr(transparent)]
pub struct MovRegBits(pub u32);
impl MovRegBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm5(&self) -> u32 { (self.0 & 0x00000f80) >> 7 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for MovRegBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        use ironic_core::cpu::alu::ShiftType;
        if self.s() { f.push('s'); }
        f.push_str(&format!(" r{}, r{}", self.rd(), self.rm()));
        if self.imm5() != 0 { // pretty sure this is right
            f.push_str(match ShiftType::from(self.stype()) {
                ShiftType::Lsl => "lsl ",
                ShiftType::Lsr => "lsr ",
                ShiftType::Asr => "asr ",
                ShiftType::Ror => "ror ",
            });
            f.push_str(&format!("0x{:x}", self.imm5()));
        }
        Ok(())
    }
}

/// ['Qdadd', 'Qsub', 'Qadd', 'Qdsub']
#[repr(transparent)]
pub struct QBits(pub u32);
impl QBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for QBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{} r{} r{}", self.rd(), self.rm(), self.rn()));
        Ok(())
    }
}

/// ['Bx', 'Bxj', 'BlxReg']
#[repr(transparent)]
pub struct BxBits(pub u32);
impl BxBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for BxBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{}", self.rm()));
        Ok(())
    }
}

/// ['Clz']
#[repr(transparent)]
pub struct ClzBits(pub u32);
impl ClzBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for ClzBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{} r{}", self.rd(), self.rm()));
        Ok(())
    }
}

/// ['Bkpt']
#[repr(transparent)]
pub struct BkptBits(pub u32);
impl BkptBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn imm16(&self) -> u32 { (self.imm12() << 4) | (self.imm4()) }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { (self.0 & 0x000fff00) >> 8 }
    #[inline(always)]
    pub fn imm4(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for BkptBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("#0x{:x}", self.imm16()));
        Ok(())
    }
}

/// ['MsrReg']
#[repr(transparent)]
pub struct MsrRegBits(pub u32);
impl MsrRegBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn r(&self) -> bool { (self.0 & 0x00400000) != 0 }
    #[inline(always)]
    pub fn mask(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}

impl xDisplay for MsrRegBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.r() { f.push_str("spsr_"); } else { f.push_str("cpsr_"); }
        const PSR_MASKS: [char;4] = ['c', 'x', 's', 'f'];
        for (i, psr_mask_char) in PSR_MASKS.iter().enumerate() {
            if (self.mask() >> i) & 0x1 == 1 {
                f.push(*psr_mask_char);
            }
        }
        f.push_str(&format!(" r{}", self.rn()));
        Ok(())
    }
}

/// ['MrsRegBanked']
#[repr(transparent)]
pub struct MrsRegBankedBits(pub u32);
impl MrsRegBankedBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn r(&self) -> bool { (self.0 & 0x00400000) != 0 }
    #[inline(always)]
    pub fn m1(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn m(&self) -> bool { (self.0 & 0x00000100) != 0 }
} impl xDisplay for MrsRegBankedBits {} // unused instruction

/// ['MsrRegBanked']
#[repr(transparent)]
pub struct MsrRegBankedBits(pub u32);
impl MsrRegBankedBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn r(&self) -> bool { (self.0 & 0x00400000) != 0 }
    #[inline(always)]
    pub fn m1(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn m(&self) -> bool { (self.0 & 0x00000100) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
} impl xDisplay for MsrRegBankedBits {} // unused instruction

/// ['Mrs']
#[repr(transparent)]
pub struct MrsBits(pub u32);
impl MrsBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn r(&self) -> bool { (self.0 & 0x00400000) != 0 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
}
impl xDisplay for MrsBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{}, {}psr", self.rd(), if self.r() {"s"} else {"c"}, ));
        Ok(())
    }
}

/// ['Smull', 'Umlal', 'Smlal', 'Umull']
#[repr(transparent)]
pub struct SignedMlBits(pub u32);
impl SignedMlBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rdhi(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rdlo(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for SignedMlBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.s() { f.push_str("s "); }
        f.push_str(&format!("r{}, r{}, r{}, r{}", self.rdhi(), self.rdlo(), self.rm(), self.rn()));
        Ok(())
    }
}

/// ['Mul']
#[repr(transparent)]
pub struct MulBits(pub u32);
impl MulBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for MulBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.s() { f.push_str("s "); }
        f.push_str(&format!("r{}, r{}, r{}", self.rd(), self.rm(), self.rn()));
        Ok(())
    }
}

/// ['Mla']
#[repr(transparent)]
pub struct MlaBits(pub u32);
impl MlaBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn ra(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for MlaBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.s() { f.push_str("s "); }
        f.push_str(&format!("r{}, r{}, r{}", self.rd(), self.rm(), self.rn()));
        Ok(())
    }
}

/// ['MovImm', 'MvnImm']
#[repr(transparent)]
pub struct MovImmBits(pub u32);
impl MovImmBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
}
impl xDisplay for MovImmBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.s() { f.push('s'); }
        let (imm, _) = ironic_core::cpu::alu::rot_by_imm(self.imm12(), false /* doesn't matter */);
        f.push_str(&format!(" r{}, #0x{:x}", self.rd(), imm));
        Ok(())
    }
}

/// ['PldReg']
#[repr(transparent)]
pub struct PldRegBits(pub u32);
impl PldRegBits {
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn r(&self) -> bool { (self.0 & 0x00400000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn imm5(&self) -> u32 { (self.0 & 0x00000f80) >> 7 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
} impl xDisplay for PldRegBits {}

/// ['Mcrr', 'Mrrc']
#[repr(transparent)]
pub struct MoveCoprocDoubleBits(pub u32);
impl MoveCoprocDoubleBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rt2(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn coproc(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn opc1(&self) -> u32 { (self.0 & 0x000000f0) >> 4 }
    #[inline(always)]
    pub fn crm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for MoveCoprocDoubleBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("p{}, {}, r{}, r{}, {}", self.coproc(), self.opc1(), self.rt(), self.rt2(), self.crm()));
        Ok(())
    }
}

/// ['Smulwb']
#[repr(transparent)]
pub struct SmulwbBits(pub u32);
impl SmulwbBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn m(&self) -> bool { (self.0 & 0x00000040) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for SmulwbBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{}, r{}, r{}", self.rd(), self.rn(), self.rm()));
        Ok(())
    }
}

/// ['Smlawb']
#[repr(transparent)]
pub struct SmlawbBits(pub u32);
impl SmlawbBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn ra(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn m(&self) -> bool { (self.0 & 0x00000040) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for SmlawbBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{}, r{}, r{}, r{}", self.rd(), self.rn(), self.rm(), self.ra()));
        Ok(())
    }
}

/// ['Smlalbb']
#[repr(transparent)]
pub struct SmalbbBits(pub u32);
impl SmalbbBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rdhi(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rdlo(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn m(&self) -> bool { (self.0 & 0x00000040) != 0 }
    #[inline(always)]
    pub fn n(&self) -> bool { (self.0 & 0x00000020) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for SmalbbBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{}, r{}, r{}, r{}", self.rdlo(), self.rdhi(), self.rn(), self.rm()));
        Ok(())
    }
}

/// ['TeqRegShiftReg', 'CmnRegShiftReg', 'TstRegShiftReg', 'CmpRegShiftReg']
#[repr(transparent)]
pub struct DpTestRsrBits(pub u32);
impl DpTestRsrBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rs(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for DpTestRsrBits {} // unused instruction

/// ['Smlaxy']
#[repr(transparent)]
pub struct SmlaxyBits(pub u32);
impl SmlaxyBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn ra(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn y(&self) -> bool { (self.0 & 0x00000040) != 0 }
    #[inline(always)]
    pub fn x(&self) -> bool { (self.0 & 0x00000020) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for SmlaxyBits {
    fn fmt(&self, f: &mut String, ctx: DisassemblyContext) -> anyhow::Result<()> {
        let _ = ctx;
        f.push_str(&format!("r{}, r{}, r{}, r{}", self.rd(), self.rn(), self.rm(), self.ra()));
        Ok(())
    }

    fn required_context(&self) -> DisassemblyContext {
        DisassemblyContext::NotNeeded
    }
}

/// ['Smulbb']
#[repr(transparent)]
pub struct SmulbbBits(pub u32);
impl SmulbbBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn m(&self) -> bool { (self.0 & 0x00000040) != 0 }
    #[inline(always)]
    pub fn n(&self) -> bool { (self.0 & 0x00000020) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { self.0 & 0x0000000f }
} impl xDisplay for SmulbbBits {} // unused instruction

/// ['PldImm']
#[repr(transparent)]
pub struct PldImmBits(pub u32);
impl PldImmBits {
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn r(&self) -> bool { (self.0 & 0x00400000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
} impl xDisplay for PldImmBits {} // unused instruction

/// ['LdrsbImm', 'StrhImm', 'LdrshImm', 'StrdImm', 'LdrhImm', 'LdrdImm']
#[repr(transparent)]
pub struct LsSignedImmBits(pub u32);
impl LsSignedImmBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm4h(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn imm4l(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for LsSignedImmBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        let mut offset = (self.imm4h() as i64) << 4 | self.imm4l() as i64; // maybe?
        if self.u() { offset *= -1; }
        f.push_str(&format!("r{}, [r{}, #{:#x}]", self.rt(), self.rn(), offset));
        Ok(())
    }
}

/// ['StrdReg', 'LdrsbReg', 'LdrshReg', 'LdrdReg', 'LdrhReg', 'StrhReg']
#[repr(transparent)]
pub struct LsSignedRegBits(pub u32);
impl LsSignedRegBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}

impl xDisplay for LsSignedRegBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{}, [r{}, r{}]", self.rt(), self.rn(), self.rm()));
        Ok(())
    }
}

/// ['AndRegShiftReg', 'AdcRegShiftReg', 'OrrRegShiftReg', 'EorRegShiftReg', 'RscRegShiftReg', 'SbcRegShiftReg', 'AddRegShiftReg', 'BicRegShiftReg', 'RsbRegShiftReg', 'SubRegShiftReg']
#[repr(transparent)]
pub struct DpRsrBits(pub u32);
impl DpRsrBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rs(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for DpRsrBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        use ironic_core::cpu::alu::ShiftType;
        f.push_str(&format!("r{}, r{}, ", self.rd(), self.rn()));
        let shift = ShiftType::from(self.stype());
        f.push_str(match shift {
            ShiftType::Lsl => "lsl ",
            ShiftType::Lsr => "lsr ",
            ShiftType::Asr => "asr ",
            ShiftType::Ror => "ror ",
        });
        f.push_str(&format!("r{}", self.rs()));
        Ok(())
    }
}

/// ['MovRegShiftReg', 'MvnRegShiftReg']
#[repr(transparent)]
pub struct MovRsrBits(pub u32);
impl MovRsrBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn i(&self) -> bool { (self.0 & 0x02000000) != 0}
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn rs(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for MovRsrBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        use ironic_core::cpu::alu::ShiftType;
        f.push_str(&format!("r{}, r{}, ", self.rd(), self.rm()));
        let shift = ShiftType::from(self.stype());
        f.push_str(match shift {
            ShiftType::Lsl => "lsl ",
            ShiftType::Lsr => "lsr ",
            ShiftType::Asr => "asr ",
            ShiftType::Ror => "ror ",
        });
        f.push_str(&format!("r{}", self.rs()));
        Ok(())
    }
}

/// ['CmpReg', 'TstReg', 'CmnReg', 'TeqReg']
#[repr(transparent)]
pub struct DpTestRegBits(pub u32);
impl DpTestRegBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn imm5(&self) -> u32 { (self.0 & 0x00000f80) >> 7 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for DpTestRegBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        use ironic_core::cpu::alu::ShiftType;
        f.push_str(&format!("r{}, r{}, ", self.rn(), self.rm()));
        let shift = ShiftType::from(self.stype());
        f.push_str(match shift {
            ShiftType::Lsl => "lsl ",
            ShiftType::Lsr => "lsr ",
            ShiftType::Asr => "asr ",
            ShiftType::Ror => "ror ",
        });
        f.push_str(&format!("#{}", self.imm5()));
        Ok(())
    }
}

/// ['Mrc', 'Mcr']
#[repr(transparent)]
pub struct MoveCoprocBits(pub u32);
impl MoveCoprocBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn opc1(&self) -> u32 { (self.0 & 0x00e00000) >> 21 }
    #[inline(always)]
    pub fn crn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn coproc(&self) -> u32 { (self.0 & 0x00000f00) >> 8 }
    #[inline(always)]
    pub fn opc2(&self) -> u32 { (self.0 & 0x000000e0) >> 5 }
    #[inline(always)]
    pub fn crm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for MoveCoprocBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("p{}, {}, r{}, {}, {}, {}", self.coproc(), self.opc1(), self.rt(), self.crn(), self.crm(), self.opc2()));
        Ok(())
    }
}

/// ['MovImmAlt']
#[repr(transparent)]
pub struct MovImmAltBits(pub u32);
impl MovImmAltBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn imm4(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
} impl xDisplay for MovImmAltBits {} // unused instruction

/// ['CmnImm', 'CmpImm', 'TstImm', 'TeqImm']
#[repr(transparent)]
pub struct DpTestImmBits(pub u32);
impl DpTestImmBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
}
impl xDisplay for DpTestImmBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        let (imm, _) = ironic_core::cpu::alu::rot_by_imm(self.imm12(), false /* doesn't matter */);
        f.push_str(&format!("r{}, #0x{:x}", self.rn(), imm));
        Ok(())
    }
}

/// ['LdrbtAlt', 'StrbtAlt', 'LdrtAlt', 'StrtAlt']
#[repr(transparent)]
pub struct LsTransAltBits(pub u32);
impl LsTransAltBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm5(&self) -> u32 { (self.0 & 0x00000f80) >> 7 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
} impl xDisplay for LsTransAltBits {} // unused instruction

/// ['SbcReg', 'OrrReg', 'BicReg', 'AddReg', 'RscReg', 'EorReg', 'AdcReg', 'SubReg', 'AndReg', 'RsbReg']
#[repr(transparent)]
pub struct DpRegBits(pub u32);
impl DpRegBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm5(&self) -> u32 { (self.0 & 0x00000f80) >> 7 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for DpRegBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.s() { f.push_str("s "); }

        use ironic_core::cpu::alu::ShiftType;
        let shift = match ShiftType::from(self.stype()) {
            ShiftType::Lsl => "lsl ",
            ShiftType::Lsr => "lsr ",
            ShiftType::Asr => "asr ",
            ShiftType::Ror => "ror ",
        };
        f.push_str(&format!("r{}, r{}, r{}, {shift} #0x{:x}", self.rd(), self.rn(), self.rm(), self.imm5()));
        Ok(())
    }
}

/// ['AddImm', 'AdcImm', 'RsbImm', 'OrrImm', 'BicImm', 'SubImm', 'AndImm', 'RscImm', 'EorImm', 'SbcImm']
#[repr(transparent)]
pub struct DpImmBits(pub u32);
impl DpImmBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn s(&self) -> bool { (self.0 & 0x00100000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rd(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
}
impl xDisplay for DpImmBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.s() { f.push_str("s "); }
        let (imm, _) = ironic_core::cpu::alu::rot_by_imm(self.imm12(), false /* doesn't matter */);
        f.push_str(&format!("r{}, r{}, #0x{:x}", self.rd(), self.rn() ,imm));
        Ok(())
    }
}

/// ['Ldrbt', 'Strbt', 'Ldrt', 'Strt']
#[repr(transparent)]
pub struct LsTransBits(pub u32);
impl LsTransBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
} impl xDisplay for LsTransBits {} // unused instruction

/// Formats a register list for instructions like ldm and stm
fn format_register_list(list: u32) -> String {
    fn format_register(index: u32) -> &'static str {
        match index {
            0..=12 => &["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"][index as usize],
            13 => "sp",
            14 => "lr",
            15 => "pc",
            _ => unreachable!(),
        }
    }
    let mut reglist = String::new();
    let mut start = None;
    let mut end = None;
    // format collapsable registers (0-12)
    for i in 0..=12 {
        if (list & (1 << i)) != 0 {
            if start.is_none() {
                start = Some(i);
            }
            end = Some(i);
        } else if let (Some(s), Some(e)) = (start, end) {
            if s == e {
                reglist += &format_register(s);
            } else if s+1 == e {
                reglist += &format!("{}, {}", &format_register(s), &format_register(e));
            } else {
                reglist += &format!("{}-{}", format_register(s), format_register(e));
            }
            reglist += ", ";
            start = None;
            end = None;
        }
    }
    if let (Some(s), Some(e)) = (start, end) {
        if s == e {
            reglist += &format_register(s);
        } else if s+1 == e {
            reglist += &format!("{}, {}", &format_register(s), &format_register(e));
        } else {
            reglist += &format!("{}-{}", format_register(s), format_register(e));
        }
        reglist += ", ";
    }
    // never collapse sp, lr, pc
    for i in 13..=15 {
        if (list & (1 << 1)) != 0 {
            reglist += format_register(i);
            reglist += ", ";
        }
    }
    if reglist.ends_with(", ") {
        reglist.pop();
        reglist.pop();
    }
    reglist
}

/// ['Stm', 'Stmda', 'Ldmda', 'Ldmib', 'Ldmdb', 'Ldm', 'Stmdb', 'Stmib']
#[repr(transparent)]
pub struct LsMultiBits(pub u32);
impl LsMultiBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn register_list(&self) -> u32 { self.0 & 0x0000ffff }
    #[inline(always)]
    fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    fn s(&self) -> bool { (self.0 & 0x00400000) != 0 }
    /// Helper for disassembly formatting
    fn addressing_mode(&self) -> &str {
        match (self.p(), self.u()) {
            (true, true)   => "ib",
            (true, false)  => "db",
            (false, true)  => "ia",
            (false, false) => "da",
        }
    }
}
impl xDisplay for LsMultiBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        let reglist = format_register_list(self.register_list());
        f.push_str(&format!("{}, r{}", self.addressing_mode(), self.rn(), ));
        if self.w() { f.push_str("!, "); } else { f.push_str(", "); }
        f.push_str(&format!("{{ {reglist} }}"));
        if self.s() { f.push('^'); }
        Ok(())
    }
}

/// ['MsrImm']
#[repr(transparent)]
pub struct MsrImmBits(pub u32);
impl MsrImmBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn r(&self) -> bool { (self.0 & 0x00400000) != 0 }
    #[inline(always)]
    pub fn mask(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
}
impl xDisplay for MsrImmBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        if self.r() { f.push_str("spsr_"); } else { f.push_str("cpsr_"); }
        const PSR_MASKS: [char;4] = ['c', 'x', 's', 'f'];
        for (i, psr_mask_char) in PSR_MASKS.iter().enumerate() {
            if (self.mask() >> i) & 0x1 == 1 {
                f.push(*psr_mask_char);
            }
        }
        let (imm, _) = ironic_core::cpu::alu::rot_by_imm(self.imm12(), false /* doesn't matter */);
        f.push_str(&format!(", #0x{imm:x}"));
        Ok(())
    }
}

/// ['LdrReg', 'StrbReg', 'LdrbReg', 'StrReg']
#[repr(transparent)]
pub struct LsRegBits(pub u32);
impl LsRegBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm5(&self) -> u32 { (self.0 & 0x00000f80) >> 7 }
    #[inline(always)]
    pub fn stype(&self) -> u32 { (self.0 & 0x00000060) >> 5 }
    #[inline(always)]
    pub fn rm(&self) -> u32 { self.0 & 0x0000000f }
}
impl xDisplay for LsRegBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        use ironic_core::cpu::alu::ShiftType;
        let shift = match ShiftType::from(self.stype()) {
            ShiftType::Lsl => "lsl",
            ShiftType::Lsr => "lsr",
            ShiftType::Asr => "asr",
            ShiftType::Ror => "ror",
        };
        f.push_str(&format!("r{}, [r{}, {shift} #0x{:x}]", self.rt(), self.rn(), self.imm5()));
        Ok(())
    }
}

/// ['LdmRegUser']
#[repr(transparent)]
pub struct LdmRegUserBits(pub u32);
impl LdmRegUserBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn register_list(&self) -> u32 { self.0 & 0x0000ffff }
    #[inline(always)]
    fn s(&self) -> bool { (self.0 & 0x00400000) != 0 }
    /// Helper for disassembly formatting
    fn addressing_mode(&self) -> &str {
        match (self.p(), self.u()) {
            (true, true)   => "ib",
            (true, false)  => "db",
            (false, true)  => "ia",
            (false, false) => "da",
        }
    }
}
impl xDisplay for LdmRegUserBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        let reglist = format_register_list(self.register_list());
        f.push_str(&format!("{}, r{}", self.addressing_mode(), self.rn(), ));
        if self.w() { f.push_str("!, "); } else { f.push_str(", "); }
        f.push_str(&format!("{{ {reglist} }}"));
        if self.s() { f.push('^'); }
        Ok(())
    }
}

/// ['StrImm', 'StrbImm', 'LdrbImm', 'LdrImm']
#[repr(transparent)]
pub struct LsImmBits(pub u32);
impl LsImmBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn rt(&self) -> u32 { (self.0 & 0x0000f000) >> 12 }
    #[inline(always)]
    pub fn imm12(&self) -> u32 { self.0 & 0x00000fff }
}
impl xDisplay for LsImmBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        f.push_str(&format!("r{}, [r{}, #0x{:x}]", self.rt(), self.rn(), self.imm12()));
        Ok(())
    }
}

/// ['StmRegUser']
#[repr(transparent)]
pub struct StmRegUserBits(pub u32);
impl StmRegUserBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn p(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn u(&self) -> bool { (self.0 & 0x00800000) != 0 }
    #[inline(always)]
    pub fn rn(&self) -> u32 { (self.0 & 0x000f0000) >> 16 }
    #[inline(always)]
    pub fn register_list(&self) -> u32 { self.0 & 0x0000ffff }
    #[inline(always)]
    fn w(&self) -> bool { (self.0 & 0x00200000) != 0 }
    #[inline(always)]
    fn s(&self) -> bool { (self.0 & 0x00400000) != 0 }
    /// Helper for disassembly formatting
    fn addressing_mode(&self) -> &str {
        match (self.p(), self.u()) {
            (true, true)   => "ib",
            (true, false)  => "db",
            (false, true)  => "ia",
            (false, false) => "da",
        }
    }
}
impl xDisplay for StmRegUserBits {
    fn fmt(&self, f: &mut String, _: DisassemblyContext) -> anyhow::Result<()> {
        let reglist = format_register_list(self.register_list());
        f.push_str(&format!("{}, r{}", self.addressing_mode(), self.rn(), ));
        if self.w() { f.push_str("!, "); } else { f.push_str(", "); }
        f.push_str(&format!("{{ {reglist} }}"));
        if self.s() { f.push('^'); }
        Ok(())
    }
}

/// ['Svc', 'B', 'BlImm', 'BlxImm']
#[repr(transparent)]
pub struct BranchBits(pub u32);
impl BranchBits {
    #[inline(always)]
    pub fn cond(&self) -> u32 { (self.0 & 0xf0000000) >> 28 }
    #[inline(always)]
    pub fn h(&self) -> bool { (self.0 & 0x01000000) != 0 }
    #[inline(always)]
    pub fn imm24(&self) -> u32 { self.0 & 0x00ffffff }
}
impl xDisplay for BranchBits {
    fn fmt(&self, f: &mut String, ctx: DisassemblyContext) -> anyhow::Result<()> {
        // FIXME: BlxImm needs to handle H bit
        use anyhow::bail;
        let (blx, base) = match ctx {
            DisassemblyContext::BlxDiscriminantAndPC(blx_base) => blx_base,
            _ => bail!("PC context required")
        };
        let mut addr = base as i64 + (crate::interp::arm::branch::sign_extend(self.imm24(), 24, 30) << 2) as i64;
        if blx { addr += ((self.h() as u32) as i64) << 1}
        f.push_str(&format!("0x{addr:x}"));
        Ok(())
    }
    fn required_context(&self) -> DisassemblyContext {
        DisassemblyContext::BlxDiscriminantAndPC((false, 0))
    }
}
