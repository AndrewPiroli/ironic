#![deny(unsafe_op_in_unsafe_fn)]

use addr2line::Context;
use gimli::BigEndian;
use gimli::EndianSlice;
use ironic_core::bus::*;
use ironic_core::dev::hlwd::compat::exi::UsbGeckoDevice;
use ironic_core::dev::hlwd::compat::vi::VideoInterface;
use ironic_backend::interp::*;
use ironic_backend::back::*;
use ironic_backend::ppc::*;
use log::info;
use log::{debug, error};
use parking_lot::RwLock;

use std::io::Write;
use std::process;
use std::sync::Arc;
use std::thread::Builder;
use std::time::Duration;

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// Path to a custom kernel ELF
    #[clap(short, long)]
    custom_kernel: Option<String>,
    /// Enable the PPC HLE server (default = False)
    #[clap(short, long)]
    ppc_hle: bool,
    /// Attach an emulated USB Gecko whose serial stream is
    /// served over TCP on 127.0.0.1 port 55021 by default
    /// When this flag is absent, guest software sees an empty slot.
    #[clap(short, long, value_name = "PORT", num_args = 0..=1, default_missing_value = "55021")]
    usbgecko: Option<u16>,
    /// Define log levels for the program
    #[clap(long, default_value="info")]
    logging: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let custom_kernel = args.custom_kernel.clone();
    let enable_ppc_hle = args.ppc_hle;

    env_logger::builder()
        .parse_filters(&args.logging)
        .format(|buf, record| {
            let target = record.target();
            if target == "SVC" {
                writeln!(buf, "[{}] {}", record.target(), record.args())
            } else {
                use colored::Colorize;
                let level = match record.level() {
                    level @ log::Level::Debug => level.as_str().cyan(),
                    level @ log::Level::Trace => level.as_str().bright_cyan(),
                    level => level.as_str().normal(),
                };
                writeln!(buf, "[{}][{}] {}", record.target(), level, record.args())
            }
        })
        .init();

    // The bus is shared between any threads we spin up
    let mut bus = match Bus::new() {
        Ok(val) => val,
        Err(reason) => {
            println!("Failed to construct emulator Bus: {reason}");
            process::exit(-1);
        }
    };

    // TODO: rework this into a Backend.
    if let Some(port) = args.usbgecko {
        let gecko = UsbGeckoDevice::default();
        match gecko.spawn_server_thread(port) {
            Ok(_) => bus.hlwd.exi.attach_usbgecko(gecko),
            Err(reason) => {
                println!("Failed to start USB Gecko server on port {port}: {reason}");
                process::exit(-1);
            }
        }
    }

    let bus = Arc::new(RwLock::new(bus));
    let _vi_thread = VideoInterface::spawn_irq_thread(bus.clone()).unwrap();

    // Setup panic hook
    // We try to avoid panics inside the emulator, but it can happen so try to dump guest memory.
    let panic_bus = bus.clone();
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info|{
        'attempt_fancy_crashdump: {
            use std::sync::atomic::Ordering::Relaxed;
            // We only care if the emulator thread crashes, so check the thread name and see whodunnit
            let thread = std::thread::current();
            if thread.name() == Some("EmuThread") {
                if let Some(bus) = panic_bus.try_read_for(Duration::new(3, 0)) {
                    // Dump emulator memory.
                    println!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    match bus.dump_memory("crash.bin") {
                        Ok(p) => println!("Emulator crashed! Dumped RAM to {}/*.crash.bin", p.to_string_lossy()),
                        Err(e) => println!("Emulator crashed! Failed to dump RAM: {e}"),
                    }
                    println!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                    match bus.nand.data.dump_writes() {
                        Ok(_) => println!("NAND WRITES DUMPED TO {}", bus.nand.data.write_index),
                        Err(e) => println!("FAILED TO DUMP NAND WRITE DATA: {e}"),
                    }
                } else {
                    println!("Failed to get the Bus lock in time, it's stuck!");
                    println!("Skipping RAM and NAND dumps");
                }
                // Attempt a debuginfo enhanced crashdump.
                let Some(debuginfo) = DEBUGINFO.debuginfo.get() else {
                    println!("No debug info installed, can not continue crashdump");
                    break 'attempt_fancy_crashdump;
                };
                let pc = DEBUGINFO.last_pc.load(Relaxed);
                let lr = DEBUGINFO.last_lr.load(Relaxed);
                #[allow(deprecated)] // God these 2 crates are stupid
                let debuginfo_b = debuginfo.borrow(|section|{
                    EndianSlice::new(section, BigEndian)
                });
                match addr2line::Context::from_dwarf(debuginfo_b) {
                    Ok(addr2line_ctx) => {
                        let _ = enhanced_crashdump(addr2line_ctx, pc, lr);
                    },
                    Err(err) => println!("Failed to initialize addr2line, cannot procede with crashdump! {err}"),
                }
            }
        }
        orig_hook(panic_info);
    }));

    // Setup Ctrl-C handler
    let ctrl_c_bus = bus.clone();
    ctrlc::set_handler(move ||{
        debug!(target: "MEMSAVE", "BEMemory Ctrl-C handler. Good luck!");
        let bus = match ctrl_c_bus.try_read_for(Duration::new(5, 0)) {
            Some(b) => b,
            None => {
                println!("Failed to unlock Bus in 5 seconds, it's stuck!");
                println!("Unable to persist NAND writes, sorry.");
                std::process::exit(0);
            }
        };
        match bus.nand.data.dump_writes() {
            Ok(_) => info!(target: "MEMSAVE", "NAND writes saved sucessfully"),
            Err(e) => error!(target: "MEMSAVE", "NAND writes failed to save {e}"),
        }
        // We are now responsible for terminating the program
        // TODO: cleanup nicely?
        std::process::exit(0);
    }).unwrap();

    // Fork off the backend thread
    let emu_bus = bus.clone();
    let ppc_early_on = custom_kernel.is_some() && enable_ppc_hle;
    let emu_thread = Builder::new().name("EmuThread".to_owned()).spawn(move || {
        let mut back = InterpBackend::new(emu_bus, custom_kernel, ppc_early_on);
        if let Err(reason) = back.run() {
            println!("InterpBackend returned an Err: {reason}");
        };
    }).unwrap();

    // Fork off the PPC HLE thread
    if enable_ppc_hle {
        let ppc_bus = bus.clone();
        let _ = Some(Builder::new().name("IpcThread".to_owned()).spawn(move || {
            let mut back = PpcBackend::new(ppc_bus);
            if let Err(reason) = back.run(){
                println!("PPC Backend returned an Err: {reason}");
            };
        }).unwrap());
    }

    let _ = emu_thread.join();

    let bus_ref = bus.read();
    match bus_ref.dump_memory("bin") {
        Ok(path) => {
            debug!(target: "Other", "Dumped ram to {}/*.bin", path.to_string_lossy())
        }
        Err(e) => {
            error!(target: "Other", "Failed to dump ram: {e:?}");
        }
    }
    match bus_ref.nand.data.dump_writes() {
        Ok(_) => info!(target: "MEMSAVE", "NAND writes saved sucessfully"),
        Err(e) => error!(target: "MEMSAVE", "NAND writes failed to save {e}"),
    }
    println!("Bus cycles elapsed: {}", bus_ref.cycle);
    process::exit(0);

}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::Display, strum::VariantNames, strum::EnumString)]
#[strum(ascii_case_insensitive)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
enum LogTarget {
    AES,
    DEBUG_PORT,
    EXI,
    HLWD,
    IPC,
    IRQ,
    VI,
    MEMSAVE,
    NAND,
    OTP,
    PPC,
    SDHC,
    SEEPROM,
    SHA,
    SYSCALL,
    SVC,
    UG,
    xHCI,
    RTPATCH,
    Other,
}

fn enhanced_crashdump(addr2line_ctx: Context<EndianSlice<BigEndian>>, pc: u32, lr: u32) -> anyhow::Result<()> {
    // addr2line of PC and LR
    {
        let pc_line = addr2line_ctx.find_location(pc as u64).unwrap_or_default();
        let lr_line = addr2line_ctx.find_location(lr as u64).unwrap_or_default();
        println!("addr2line\nPC:{pc:08x} Loc:{}\nLR:{lr:08x} Loc:{}", fmt_location(pc_line), fmt_location(lr_line));
    }
    Ok(())
}

fn fmt_location(loc: Option<addr2line::Location>) -> String {
    if let Some(real_loc) = loc {
        format!("{}:{}:{}", real_loc.file.unwrap_or("??"), real_loc.line.unwrap_or(0), real_loc.column.unwrap_or(0))
    }
    else {
        "??:0".to_owned()
    }
}
