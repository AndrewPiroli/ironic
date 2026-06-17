// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error;
use ironic_core::bus::Bus;
use log::{Record, Level, Metadata};
use slint::Model;
use fxhash::FxHashMap;
use slint::{ComponentHandle, VecModel};
use std::sync::Arc;
use parking_lot::RwLock;
use std::thread::Builder;
use ironic_backend::interp::InterpBackend;
use ironic_backend::back::Backend;
slint::include_modules!();

struct IronicGuiLogger {
    uihandle: slint::Weak<AppWindow>,
    base_level: Level,
    target_levels: FxHashMap<String, Level>
}
impl  IronicGuiLogger {
    fn new(uihandle: slint::Weak<AppWindow>) -> Self {
        Self { uihandle, base_level: Level::Info, target_levels: Default::default() }
    }
}
impl log::Log for IronicGuiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        match self.target_levels.get(metadata.target()) {
            None => { metadata.level() <= self.base_level }
            Some(lvl) => { metadata.level() <= *lvl }
        }
    }

    fn log(&self, record: &Record) {
        dbg!(&record);
        if self.enabled(record.metadata()) {
            let facility = record.target().to_owned();
            let txt = record.args().to_string();
            let level = record.metadata().level().to_string();
            let _ = self.uihandle.upgrade_in_event_loop(|l|{
                let temp = l.get_logs();
                let current = temp.as_any().downcast_ref::<VecModel<LogDesc>>().unwrap();
                current.push(LogDesc { facility: facility.into(), level: level.into(), txt: txt.into() });
            });
        }
    }

    fn flush(&self) {}
}
fn start_logging(ui: slint::Weak<AppWindow>) {
    let logger = Box::leak(Box::new(IronicGuiLogger::new(ui)));
    log::set_logger(logger).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
}

fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;
    start_logging(ui.as_weak());
    let bus = Arc::new(RwLock::new(Bus::new().unwrap()));
    let _emu_thread = Builder::new().name("EmuThread".to_owned()).spawn(move || {
        let mut back = InterpBackend::new(bus, None, false);
        if let Err(reason) = back.run() {
            println!("InterpBackend returned an Err: {reason}");
        };
    }).unwrap();
    ui.run()?;
    Ok(())
}