#![deny(unsafe_op_in_unsafe_fn)]
#![feature(thread_local)]

pub mod back;
pub mod bits;
pub mod decode;

pub mod interp;

pub mod ipc;
pub mod ppc;

#[cfg(have_ppcemu)]
pub mod ppclle;

#[cfg(not(have_ppcemu))]
pub mod ppclle {
    use crate::back::Backend;
    use std::sync::Arc;
    use parking_lot::RwLock;
    use ironic_core::bus::Bus;
    /// Stub implementation of PPC LLE system
    /// 
    /// If you can see this, your build did not
    /// detect libppcemu OR libclang and PPC LLE is not available.
    struct PpcEmu;
    impl PpcEmu {
        #[allow(unused)]
        pub fn new(bus: Arc<RwLock<Bus>>) -> Self {
            Self
        }
    }
    impl Backend for PpcEmu {
        fn run(&mut self) -> anyhow::Result<()> {
            anyhow::bail!("PPC LLE not available, install libclang & set up libppcemu in cronic/ directory")
        }
    }
}