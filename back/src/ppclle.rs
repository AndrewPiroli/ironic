#![cfg(have_ppcemu)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
use ironic_core::bus::Bus;
use std::sync::Arc;
use parking_lot::RwLock;
use crate::back::Backend;

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/ppcemu_bindings.rs"));
}

#[thread_local]
static mut LIBPPCEMU_BUS: *mut RwLock<Bus> = core::ptr::dangling_mut();
#[thread_local]
static mut TLS_INIT: bool = false;

unsafe extern "C" fn bus_hook(emu: *mut bindings::ppcemu_state, addr: u32, len: core::ffi::c_uint, data: *mut core::ffi::c_void, write: bool) { unsafe {
    todo!()
}}


struct PpcEmu {
    bus: Arc<RwLock<Bus>>,
    state: *mut bindings::ppcemu_state,
}

impl PpcEmu {
    #[allow(unused)]
    pub fn new(bus: Arc<RwLock<Bus>>) -> Self { unsafe {
        use bindings::*;
        let temp = bus.clone();
        LIBPPCEMU_BUS = Arc::into_raw(temp) as *mut RwLock<Bus>;
        TLS_INIT = true;
        let state = ppcemu_init(ppcemu_cpu_model_PPCEMU_CPU_MODEL_BROADWAY, Some(bus_hook), 243000, 3);
        Self {
            bus, // idk if we need this... I don't trust the arc <-> ptr conversion just yet
            state
        }
    }}
}

impl Drop for PpcEmu {
    fn drop(&mut self) { unsafe {
        if TLS_INIT == true {
            TLS_INIT = false;
            let _ = drop(Arc::from_raw(LIBPPCEMU_BUS));
            LIBPPCEMU_BUS = core::ptr::null_mut();
        }
    }}
}

impl Backend for PpcEmu {
    fn run(&mut self) -> anyhow::Result<()> {
        todo!()
    }
}