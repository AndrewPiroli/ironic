
/// Emulated system topology.
pub mod topo;

/// Implementation of an emulated ARM926EJS core.
pub mod cpu;
/// Implementation of emulated memories.
pub mod mem;
/// Implementation of system devices.
pub mod dev;

/// Abstractions for implementing a system bus.
pub mod bus;
/// Abstractions for implementing runtime debugging features.
pub mod dbg;
