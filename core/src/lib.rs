#![allow(stable_features)]
#![feature(const_mut_refs, let_chains)]

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

