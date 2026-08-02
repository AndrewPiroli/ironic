#![deny(unsafe_op_in_unsafe_fn)]

/// Emulated CPU state and common operations.
pub mod cpu;
/// Implementation of emulated memories.
pub mod mem;
/// Implementation of system devices.
pub mod dev;

/// Implementation of an abstract system bus.
pub mod bus;
/// Implementation of runtime debugging features.
pub mod dbg;

pub mod logtarget {

use strum::VariantArray;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(strum::AsRefStr, strum::IntoStaticStr, strum::Display, strum::VariantArray, strum::EnumString)]
#[strum(ascii_case_insensitive)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum LogTarget {
    AES,
    #[strum(to_string = "Custom Kernel", serialize = "custom_kernel", serialize = "kernel")]
    CustomKernel,
    DEBUG_PORT,
    DSP,
    EXI,
    HLWD,
    IPC,
    IRQ,
    MEMSAVE,
    MMU,
    NAND,
    OTP,
    PI,
    PPC,
    RTPATCH,
    SDHC,
    SEEPROM,
    SHA,
    SVC,
    SYSCALL,
    UG,
    VI,
    xHCI,
    Other,
}

impl LogTarget {
    pub fn all() -> &'static [LogTarget] {
        <LogTarget as VariantArray>::VARIANTS
    }
    pub fn as_log_str(self) -> &'static str {
        self.into()
    }
}
}
