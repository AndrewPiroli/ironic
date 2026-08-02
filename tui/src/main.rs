#![deny(unsafe_op_in_unsafe_fn)]

use ironic_core::bus::*;
use ironic_core::dev::hlwd::compat::exi::UsbGeckoDevice;
use ironic_core::dev::hlwd::compat::vi::VideoInterface;
use ironic_core::logtarget::LogTarget;
use ironic_backend::cleanup;
use ironic_backend::interp::*;
use ironic_backend::back::*;
use ironic_backend::ppc::*;
use log::debug;
use parking_lot::RwLock;

use std::process;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::Builder;

use clap::Parser;

const LOGGING_EXAMPLE_TXT: &str = "
Example usage for --logging
 Set base log level to INFO: `--logging info`
 Set base log level to WARN but override SHA to DEBUG: --logging warn,sha:debug
 Set base log level to ERROR but override SHA to TRACE and AES to DEBUG: --logging ERROR,sha:trace,aes:DEBUG";

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
    handle_logging_argument(args.logging)?;
    let custom_kernel = args.custom_kernel.clone();
    let enable_ppc_hle = args.ppc_hle;

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
    cleanup::install_panic_hook(&bus);

    // Setup Ctrl-C handler
    let ctrl_c_bus = bus.clone();
    ctrlc::set_handler(move ||{
        debug!(target: "MEMSAVE", "BEMemory Ctrl-C handler. Good luck!");
        if let Some(bus) = cleanup::lock_for_cleanup(&ctrl_c_bus) {
            cleanup::persist_nand_writes(&bus);
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

    // The interpreter has stopped
    bus.read().shutdown.store(true, Ordering::Release);

    let bus_ref = bus.read();
    cleanup::persist_and_dump(&bus_ref, "bin");
    println!("Bus cycles elapsed: {}", bus_ref.cycle);
    process::exit(0);

}

fn setup_logger(base_level: log::LevelFilter, target_level_overrides: &[(LogTarget, log::LevelFilter)]) -> anyhow::Result<()> {
    use fern::colors::{Color, ColoredLevelConfig};
    let colors = ColoredLevelConfig::default().debug(Color::Cyan).trace(Color::BrightCyan);
    let mut config = fern::Dispatch::new().level(base_level);
    for specific_override in target_level_overrides {
        config = config.level_for(specific_override.0.as_log_str(), specific_override.1);
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
                let valid: Vec<&str> = LogTarget::all().iter().map(|t| t.as_log_str()).collect();
                anyhow::bail!(
                    "Failed to parse --logging argument: Not a valid logging subsystem/target! You specified: \"{maybe_target}\"\nValid options are:\n{valid:#?}{LOGGING_EXAMPLE_TXT}"
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
