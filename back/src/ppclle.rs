#![cfg(have_ppcemu)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
use ironic_core::bus::Bus;
use ironic_core::dev::hlwd::irq::*;
use std::sync::Arc;
use parking_lot::RwLock;
use std::thread;
use std::time::Duration;
use log::{info, debug, error};
use crate::back::Backend;

pub(crate) mod bindings {
    include!(concat!(env!("OUT_DIR"), "/ppcemu_bindings.rs"));
}

#[thread_local]
static mut LIBPPCEMU_BUS: *mut RwLock<Bus> = core::ptr::dangling_mut();
#[thread_local]
static mut TLS_INIT: bool = false;

const EXI_VECTOR_LO: u32 = 0xfff00100;
const EXI_VECTOR_HI: u32 = 0xfff00200;
const EXI_VECTOR_TARGET: u32 = 0x0d806840;

fn addr_in_valid_range(addr: u32) -> bool {
    (0x0000_0000..=0x01ff_ffff).contains(&addr)
        || (0x0c00_0000..=0xdfff_ffff).contains(&addr)
        || (0x1000_0000..=0x13ff_ffff).contains(&addr)
}

/// FIXME: helps performance a lot but ugly
fn try_write_bounded(bus: &RwLock<Bus>) -> parking_lot::RwLockWriteGuard<'_, Bus> {
    for _ in 0..4096 {
        if let Some(guard) = bus.try_write() {
            return guard;
        }
        std::hint::spin_loop();
    }
    bus.write()
}

fn try_read_bounded(bus: &RwLock<Bus>) -> parking_lot::RwLockReadGuard<'_, Bus> {
    for _ in 0..4096 {
        if let Some(guard) = bus.try_read() {
            return guard;
        }
        std::hint::spin_loop();
    }
    bus.read()
}

unsafe extern "C" fn bus_hook(
    _emu: *mut bindings::ppcemu_state,
    addr: u32,
    len: core::ffi::c_uint,
    data: *mut core::ffi::c_void,
    is_write: bool,
) {
    unsafe {
        let bus: &RwLock<Bus> = &*LIBPPCEMU_BUS;

        if (EXI_VECTOR_LO..=EXI_VECTOR_HI).contains(&addr) && len == 4 {
            if is_write {
                return;
            }
            let target = (addr - EXI_VECTOR_LO) + EXI_VECTOR_TARGET;
            let val = match try_read_bounded(bus).read32(target) {
                Ok(v) => v,
                Err(e) => { error!(target: "PPCLLE", "EXI vector read failed at {target:08x}: {e}"); 0 }
            };
            (data as *mut u8).copy_from_nonoverlapping(val.to_be_bytes().as_ptr(), 4);
            return;
        }

        if !addr_in_valid_range(addr) {
            error!(target: "PPCLLE", "Unknown bus address: {addr:08x} (len={len}, write={is_write})");
            return;
        }

        match len {
            1 => {
                if is_write {
                    let val = *(data as *const u8);
                    if let Err(e) = try_write_bounded(bus).write8(addr, val) {
                        error!(target: "PPCLLE", "write8 to {addr:08x} failed: {e}");
                    }
                } else {
                    let val = match try_read_bounded(bus).read8(addr) {
                        Ok(v) => v,
                        Err(e) => { error!(target: "PPCLLE", "read8 from {addr:08x} failed: {e}"); 0 }
                    };
                    *(data as *mut u8) = val;
                }
            }
            2 => {
                if is_write {
                    let mut raw = [0u8; 2];
                    (data as *const u8).copy_to_nonoverlapping(raw.as_mut_ptr(), 2);
                    let val = u16::from_be_bytes(raw);
                    if let Err(e) = try_write_bounded(bus).write16(addr, val) {
                        error!(target: "PPCLLE", "write16 to {addr:08x} failed: {e}");
                    }
                } else {
                    let val = match try_read_bounded(bus).read16(addr) {
                        Ok(v) => v,
                        Err(e) => { error!(target: "PPCLLE", "read16 from {addr:08x} failed: {e}"); 0 }
                    };
                    (data as *mut u8).copy_from_nonoverlapping(val.to_be_bytes().as_ptr(), 2);
                }
            }
            4 => {
                if is_write {
                    let mut raw = [0u8; 4];
                    (data as *const u8).copy_to_nonoverlapping(raw.as_mut_ptr(), 4);
                    let val = u32::from_be_bytes(raw);
                    if let Err(e) = try_write_bounded(bus).write32(addr, val) {
                        error!(target: "PPCLLE", "write32 to {addr:08x} failed: {e}");
                    }
                } else {
                    let val = match try_read_bounded(bus).read32(addr) {
                        Ok(v) => v,
                        Err(e) => { error!(target: "PPCLLE", "read32 from {addr:08x} failed: {e}"); 0 }
                    };
                    (data as *mut u8).copy_from_nonoverlapping(val.to_be_bytes().as_ptr(), 4);
                }
            }
            32 => {
                // Cacheline fill/writeback: raw bytes, no numeric byte-swap needed.
                let slice = core::slice::from_raw_parts_mut(data as *mut u8, 32);
                if is_write {
                    if let Err(e) = try_write_bounded(bus).dma_write(addr, slice) {
                        error!(target: "PPCLLE", "cacheline writeback to {addr:08x} failed: {e}");
                    }
                } else if let Err(e) = try_read_bounded(bus).dma_read(addr, slice) {
                    error!(target: "PPCLLE", "cacheline fill from {addr:08x} failed: {e}");
                }
            }
            _ => {
                error!(target: "PPCLLE", "Unsupported bus access width: {len} bytes at {addr:08x}");
            }
        }
    }
}

pub struct PpcEmu {
    bus: Arc<RwLock<Bus>>,
    state: *mut bindings::ppcemu_state,
    // Custom binary to load
    ppc_kernel: Option<String>,
}

// For loading custom binary
unsafe fn wii_test_init(state: *mut bindings::ppcemu_state) {
    use bindings::*;
    unsafe {
        ppcemu_set_msr(state, PPCEMU_MSR_FP | PPCEMU_MSR_ME | PPCEMU_MSR_RI);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_HID0, 0x00187510);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_HID2_GEKKO, 0xA0000000);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_HID4, 0x83900000);
        for sprn in [
            ppcemu_sprn_PPCEMU_SPRN_IBAT0U, ppcemu_sprn_PPCEMU_SPRN_IBAT1U,
            ppcemu_sprn_PPCEMU_SPRN_IBAT2U, ppcemu_sprn_PPCEMU_SPRN_IBAT3U,
            ppcemu_sprn_PPCEMU_SPRN_DBAT0U, ppcemu_sprn_PPCEMU_SPRN_DBAT1U,
            ppcemu_sprn_PPCEMU_SPRN_DBAT2U, ppcemu_sprn_PPCEMU_SPRN_DBAT3U,
            ppcemu_sprn_PPCEMU_SPRN_IBAT4U, ppcemu_sprn_PPCEMU_SPRN_IBAT5U,
            ppcemu_sprn_PPCEMU_SPRN_IBAT6U, ppcemu_sprn_PPCEMU_SPRN_IBAT7U,
            ppcemu_sprn_PPCEMU_SPRN_DBAT4U, ppcemu_sprn_PPCEMU_SPRN_DBAT5U,
            ppcemu_sprn_PPCEMU_SPRN_DBAT6U, ppcemu_sprn_PPCEMU_SPRN_DBAT7U,
        ] {
            ppcemu_set_spr(state, sprn, 0x00000000);
        }
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_IBAT0L, 0x00000002);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_IBAT0U, 0x80001FFF);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT0L, 0x00000002);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT0U, 0x80001FFF);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_IBAT4L, 0x10000002);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_IBAT4U, 0x90001FFF);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT4L, 0x10000002);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT4U, 0x90001FFF);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT1L, 0x0000002A);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT1U, 0xC0001FFF);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT5L, 0x1000002A);
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_DBAT5U, 0xD0001FFF);
        for sprn in [
            ppcemu_sprn_PPCEMU_SPRN_GQR0, ppcemu_sprn_PPCEMU_SPRN_GQR1,
            ppcemu_sprn_PPCEMU_SPRN_GQR2, ppcemu_sprn_PPCEMU_SPRN_GQR3,
            ppcemu_sprn_PPCEMU_SPRN_GQR4, ppcemu_sprn_PPCEMU_SPRN_GQR5,
            ppcemu_sprn_PPCEMU_SPRN_GQR6, ppcemu_sprn_PPCEMU_SPRN_GQR7,
        ] {
            ppcemu_set_spr(state, sprn, 0x00000000);
        }
        for sprn in [
            ppcemu_sprn_PPCEMU_SPRN_MMCR0, ppcemu_sprn_PPCEMU_SPRN_MMCR1,
            ppcemu_sprn_PPCEMU_SPRN_PMC1, ppcemu_sprn_PPCEMU_SPRN_PMC2,
            ppcemu_sprn_PPCEMU_SPRN_PMC3, ppcemu_sprn_PPCEMU_SPRN_PMC4,
        ] {
            ppcemu_set_spr(state, sprn, 0x00000000);
        }
        ppcemu_set_spr(state, ppcemu_sprn_PPCEMU_SPRN_HID0, 0x001E7510);
        ppcemu_set_msr(
            state,
            PPCEMU_MSR_FP | PPCEMU_MSR_ME | PPCEMU_MSR_RI | PPCEMU_MSR_DR | PPCEMU_MSR_IR,
        );
    }
}

impl PpcEmu {
    #[allow(unused)]
    pub fn new(bus: Arc<RwLock<Bus>>, ppc_kernel: Option<String>) -> Self { unsafe {
        use bindings::*;
        let temp = bus.clone();
        LIBPPCEMU_BUS = Arc::into_raw(temp) as *mut RwLock<Bus>;
        TLS_INIT = true;
        let state = ppcemu_init(ppcemu_cpu_model_PPCEMU_CPU_MODEL_BROADWAY, Some(bus_hook), 243000, 3);

        // Let libppcemu know when we get an IRQ
        let state_addr = state as usize;
        bus.write().hlwd.pi.pi_irq_callback = Some(IrqCallback(Arc::new(move |asserted| {
            unsafe {
                ppcemu_external_interrupt(state_addr as *mut ppcemu_state, asserted);
            }
        })));

        Self {
            bus, // idk if we need this... I don't trust the arc <-> ptr conversion just yet
            state,
            ppc_kernel,
        }
    }}

    // PPC ELF loader
    fn load_ppc_kernel(&self, path: &str) -> Option<u32> {
        let result: anyhow::Result<u32> = (|| {
            let bytes = std::fs::read(path)?;
            let elf_file = elf::File::open_stream(&mut std::io::Cursor::new(&bytes))
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let mut bus = self.bus.write();
            for header in elf_file.phdrs.iter() {
                if header.progtype == elf::types::PT_LOAD && header.filesz > 0 {
                    let phys_addr = (header.paddr as u32) & !(0x3 << 30);
                    info!(target: "PPCLLE", "Loading PPC kernel segment: offset {:#x} vaddr {:#x} -> phys addr {:#x} filesz {:#x}",
                        header.offset, header.paddr, phys_addr, header.filesz);
                    let start = header.offset as usize;
                    let end = start + header.filesz as usize;
                    bus.dma_write(phys_addr, &bytes[start..end])?;
                }
            }
            Ok(elf_file.ehdr.entry as u32)
        })();

        match result {
            Ok(entry) => Some(entry),
            Err(e) => {
                error!(target: "PPCLLE", "Failed to load PPC kernel from {path}: {e}");
                None
            }
        }
    }

    fn wait_for_ack(&mut self) {
        debug!(target: "PPCLLE", "waiting for ACK ...");
        loop {
            if self.bus.read().hlwd.irq.ppc_irq_output {
                debug!(target: "PPCLLE", "got irq");
                let mut bus = self.bus.write();

                if bus.hlwd.ipc.state.ppc_ack {
                    bus.hlwd.ipc.state.ppc_ack = false;
                    debug!(target: "PPCLLE", "got ACK");
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    break;
                }
                if bus.hlwd.ipc.state.ppc_req {
                    let armmsg = bus.hlwd.ipc.arm_msg;
                    debug!(target: "PPCLLE", "Got extra message from ARM {armmsg:08x}");
                    bus.hlwd.ipc.state.ppc_req = false;
                    bus.hlwd.ipc.state.arm_ack = true;
                    bus.hlwd.irq.ppc_irq_status.unset(HollywoodIrq::PpcIpc);
                    bus.hlwd.irq.update_irq_lines();
                    continue;
                }

                drop(bus);
                error!(target: "PPCLLE", "Invalid IRQ state");
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
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
        info!(target: "PPCLLE", "PPC LLE backend thread started");

        self.bus.write().hlwd.ipc.state.ppc_ctrl_write(0x36);

        loop {
            if self.bus.read().hlwd.ppc_on {
                info!(target: "PPCLLE", "Broadway came online");
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }

        self.wait_for_ack();

        self.bus.write().hlwd.ipc.state.arm_ack = true;
        thread::sleep(Duration::from_millis(100));

        unsafe {
            // to work around libogc bugs
            bindings::ppcemu_set_cache_mode(
                self.state,
                bindings::ppcemu_cache_mode_PPCEMU_CACHE_MODE_PERMISSIVE,
            );

            // FIXME: RT turns out to be bad for DOL/RVL_SDK software since it calibrates against VI
            bindings::ppcemu_set_timing_mode(
                self.state,
                bindings::ppcemu_timing_mode_PPCEMU_TIMING_MODE_SYNTH,
            );

            if let Some(path) = self.ppc_kernel.clone() {
                if let Some(pc) = self.load_ppc_kernel(&path) {
                    info!(target: "PPCLLE", "Setting up CPU state for manually-staged PPC kernel");
                    wii_test_init(self.state);
                    info!(target: "PPCLLE", "Overriding PC to custom kernel entry point {pc:08x}");
                    bindings::ppcemu_set_pc(self.state, pc);
                }
            }

            info!(target: "PPCLLE", "Entering step loop");

            const RESET_POLL_INTERVAL: u32 = 4096;
            let mut steps_since_reset_poll: u32 = 0;
            let mut ppc_was_on = true;

            const CORE_CYCLES_PER_INSTR: u64 = 3;
            const TICKS_PER_TB: u64 = 4 * 3; // 4 * c2b_mult
            loop {
                bindings::ppcemu_step(self.state);

                steps_since_reset_poll += 1;
                if steps_since_reset_poll < RESET_POLL_INTERVAL {
                    continue;
                }
                steps_since_reset_poll = 0;

                {
                    let mut bus = try_write_bounded(&self.bus);
                    let vi_irq = bus.hlwd.vi.irq_pending();
                    bus.hlwd.pi.set_level(ironic_core::dev::hlwd::compat::pi::FlipperIrq::Vi, vi_irq);
                    bus.hlwd.gx.pe.tick(RESET_POLL_INTERVAL);
                    let pe_irq = bus.hlwd.gx.pe.finish_pending();
                    bus.hlwd.pi.set_level(ironic_core::dev::hlwd::compat::pi::FlipperIrq::PeFinish, pe_irq);
                }

                {
                    let bus = try_read_bounded(&self.bus);
                    let now_on = bus.hlwd.ppc_on;
                    drop(bus);

                    if ppc_was_on && !now_on {
                        debug!(target: "PPCLLE", "PPC reset asserted, waiting for release");
                    } else if !ppc_was_on && now_on {
                        info!(target: "PPCLLE", "PPC reset released, restarting core");
                        bindings::ppcemu_reset(self.state);
                        bindings::ppcemu_set_timing_mode(
                            self.state,
                            bindings::ppcemu_timing_mode_PPCEMU_TIMING_MODE_SYNTH,
                        );
                    }
                    ppc_was_on = now_on;
                }
            }
        }
    }
}