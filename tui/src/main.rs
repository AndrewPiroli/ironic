#![deny(unsafe_op_in_unsafe_fn)]

use addr2line::Context;
use gimli::BigEndian;
use gimli::EndianSlice;
use ironic_core::bus::*;
use ironic_backend::interp::*;
use ironic_backend::back::*;
use ironic_backend::ppc::*;
use log::info;
use log::{debug, error};
use strum::VariantNames;
use parking_lot::RwLock;

use std::panic;
use std::process;
use std::sync::Arc;
use std::thread::Builder;
use std::time::Duration;

use clap::{Parser, ValueEnum};

const LOGGING_EXAMPLE_TXT: &str = "
Example usage for --logging
 Set base log level to INFO: `--logging info`
 Set base log level to WARN but override SHA to DEBUG: --logging warn,sha:debug
 Set base log level to ERROR but override SHA to TRACE and AES to DEBUG: --logging ERROR,sha:trace,aes:DEBUG";

/// User-specified backend type.
#[derive(Clone, Debug, ValueEnum)]
pub enum BackendType {
    Interp,
    JIT
}

impl std::fmt::Display for BackendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Parser, Debug)]
struct Args {
    /// Emulator backend to use
    #[clap(short, long, default_value = "interp")]
    backend: BackendType,
    /// Path to a custom kernel ELF
    #[clap(short, long)]
    custom_kernel: Option<String>,
    /// Enable the PPC HLE server (default = False)
    #[clap(short, long)]
    ppc_hle: Option<bool>,
    /// Define log levels for the program
    #[clap(long, default_value="info")]
    logging: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    handle_logging_argument(args.logging)?;
    let custom_kernel = args.custom_kernel.clone();
    let enable_ppc_hle = args.ppc_hle.unwrap_or(false);

    // The bus is shared between any threads we spin up
    let bus = match Bus::new() {
        Ok(val) => val,
        Err(reason) => {
            println!("Failed to construct emulator Bus: {reason}");
            process::exit(-1);
        }
    };

    let bus = Arc::new(RwLock::new(bus));

    // Setup panic hook
    // We try to avoid panics inside the emulator, but it can happen so try to dump guest memory.
    let panic_bus = bus.clone();
    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info|{
        'attempt_fancy_crashdump: {
            // We only care if the emulator thread crashes, so check the thread name and see whodunnit
            let thread = std::thread::current();
            if thread.name() == Some("EmuThread") {
                let bus = match panic_bus.try_read_for(Duration::new(3, 0)) {
                    Some(b) => b,
                    None => {
                        println!("Failed to get the Bus lock in time, it's stuck!");
                        println!("Unable to procede with a crash dump");
                        break 'attempt_fancy_crashdump;
                    },
                };
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
                // Attempt a debuginfo enhanced crashdump.
                if bus.debuginfo.debuginfo.is_none() {
                    println!("Debug location never saved to bus, can not continue crashdump");
                    break 'attempt_fancy_crashdump;
                }
                let pc = bus.debuginfo.last_pc.unwrap();
                let lr = bus.debuginfo.last_lr.unwrap();
                let _sp = bus.debuginfo.last_sp.unwrap();
                if let Some(ref debuginfo) = bus.debuginfo.debuginfo {
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
    let emu_thread = match args.backend {
        BackendType::Interp => {
            let ppc_early_on = custom_kernel.is_some() && enable_ppc_hle;
            Builder::new().name("EmuThread".to_owned()).spawn(move || {
                let mut back = InterpBackend::new(emu_bus, custom_kernel, ppc_early_on);
                if let Err(reason) = back.run() {
                    println!("InterpBackend returned an Err: {reason}");
                };
            }).unwrap()
        },
        _ => panic!("unimplemented backend"),
    };

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::Display, strum::EnumVariantNames, strum::EnumString)]
#[strum(ascii_case_insensitive)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
enum LogTarget {
    AES,
    DEBUG_PORT,
    EXI,
    HLWD,
    IPC,
    IRQ,
    MEMSAVE,
    NAND,
    OTP,
    PPC,
    SDHC,
    SEEPROM,
    SHA,
    SYSCALL,
    SVC,
    xHCI,
    Other,
}

fn setup_logger(base_level: log::LevelFilter, target_level_overrides: &[(LogTarget, log::LevelFilter)]) -> anyhow::Result<()> {
    use fern::colors::{Color, ColoredLevelConfig};
    let colors = ColoredLevelConfig::default().debug(Color::Cyan).trace(Color::BrightCyan);
    let mut config = fern::Dispatch::new().level(base_level);
    for specific_override in target_level_overrides {
        config = config.level_for(specific_override.0.to_string(), specific_override.1);
    }
    config = config.format(move |out, message, record| {
        if record.target() == "SVC" {
            out.finish(format_args!("[SVC] {}", message));
        }
        else {
            out.finish(format_args!(
                "[{}][{}] {}",
                record.target(),
                colors.color(record.level()),
                message
            ))
        }
    }).chain(std::io::stdout());
    Ok(config.apply()?)
}

// I'm sorry for this monster
fn handle_logging_argument(log_string: String) -> anyhow::Result<()> {
    if !log_string.contains(',') {
        if let Ok(base_only) = log_string.parse::<log::LevelFilter>() {
            return setup_logger(base_only, &[]);
        }
        anyhow::bail!(
            "Failed to parse --logging argument: Base-level must be `off`, `error`, `warn`, `info`, `debug`, or `trace`. You supplied \"{log_string}\"{LOGGING_EXAMPLE_TXT}"
        );
    }
    let mut split = log_string.split(',');
    let maybe_base_level = split.next().expect("BUG parsing logging argument! First call to Split.next() should always be Some(...)");
    if let Ok(base_level) = maybe_base_level.parse::<log::LevelFilter>() {
        let mut target_level_overrides: Vec<(LogTarget, log::LevelFilter)> = Vec::new();
        for part in split {
            let mut inner = part.split(':');
            let maybe_target = inner.next().expect("BUG parsing logging argument! First call to Split.next() should always be Some(...)");
            if let Ok(target) = maybe_target.parse::<LogTarget>()
            {
                let maybe_specific_override = inner.next().expect("BUG parsing logging argument! If we got this far, this call to Split.next() should return Some(...)");
                if let Ok(specific_override) = maybe_specific_override.parse::<log::LevelFilter>()
                {
                    target_level_overrides.push((target, specific_override));
                }
                else {
                    //parsing level failed
                    anyhow::bail!(
                        "Failed to parse --logging argument: Log level for target: {target} is not valid. Log level must be be `off`, `error`, `warn`, `info`, `debug`, or `trace`. You supplied \"{maybe_specific_override}\"{LOGGING_EXAMPLE_TXT}"
                    )
                }
            }
            else {
                // parsing target failed
                anyhow::bail!(
                    "Failed to parse --logging argument: Not a valid logging subsystem/target! You specified: \"{maybe_target}\"\nValid options are:\n{:#?}{LOGGING_EXAMPLE_TXT}",
                    LogTarget::VARIANTS
                );
            }
        }
        return setup_logger(base_level, target_level_overrides.as_slice());
    }
    else {
        // Failed to parse base level
        anyhow::bail!(
            "Failed to parse --logging argument: Base-level must be `off`, `error`, `warn`, `info`, `debug`, or `trace`. You supplied \"{maybe_base_level}\"{LOGGING_EXAMPLE_TXT}"
        );
    }
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