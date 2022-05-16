
use ironic_core::bus::*;
use ironic_backend::interp::*;
use ironic_backend::back::*;
use ironic_backend::ppc::*;
use ironic_backend::debug::*;

use std::sync::{Arc, RwLock};
use std::thread::Builder;
use std::env;

/// User-specified backend type.
pub enum BackendType {
    Interpreter,
    JIT
}

/// Map from input string to a backend type.
fn parse_backend(s: &str) -> Option<BackendType> {
    match s {
        "interp" => Some(BackendType::Interpreter),
        "jit" => Some(BackendType::JIT),
        _ => None
    }
}

fn dump_memory(bus: &Bus) {
    bus.sram0.dump("/tmp/sram0.bin");
    bus.sram1.dump("/tmp/sram1.bin");
    bus.mem1.dump("/tmp/mem1.bin");
    bus.mem2.dump("/tmp/mem2.bin");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: {} {{interp|jit}} [custom_kernel.elf]", args[0]);
        return;
    }

    // Let the user specify the backend
    let backend = parse_backend(args[1].as_str());
    if backend.is_none() {
        println!("usage: {} {{interp|jit}} [custom_kernel.elf]", args[0]);
        return;
    }

    let custom_kernel:Option<String> = match args.len() {
        3 => Some(args[2].to_owned()),
        _ => None,
    };

    // The bus is shared between any threads we spin up
    let bus = Arc::new(RwLock::new(Bus::new()));

    // Fork off the backend thread
    let emu_bus = bus.clone();
    let emu_thread = match backend.unwrap() {
        BackendType::Interpreter => {
            Builder::new().name("EmuThread".to_owned()).spawn(move || {
                let mut back = InterpBackend::new(emu_bus, custom_kernel);
                back.run();
            }).unwrap()
        },
        _ => panic!("unimplemented backend"),
    };

    // Fork off the PPC HLE thread
    let ppc_bus = bus.clone();
    let ppc_thread = Builder::new().name("IpcThread".to_owned()).spawn(move || {
        let mut back = PpcBackend::new(ppc_bus);
        back.run();
    }).unwrap();

    // Finally fork the DEBUG thread
    let debug_bus = bus.clone();
    let debug_thread = Builder::new().name("DebugThread".to_owned()).spawn( move || {
        println!("DEBUG");
        let mut back = DebugBackend::new(debug_bus);
        back.run();
    });

    //ppc_thread.join().unwrap();
    emu_thread.join().unwrap();

    let bus_ref = bus.write().unwrap();
    dump_memory(&bus_ref);
    println!("Bus cycles elapsed: {}", bus_ref.cycle);
}

