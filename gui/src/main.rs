// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::VecDeque;
use std::error::Error;
use std::rc::Rc;
use std::sync::Arc;
use std::thread::Builder;
use std::time::Duration;

use fxhash::FxHashMap;
use ironic_backend::back::Backend;
use ironic_backend::interp::InterpBackend;
use ironic_core::bus::Bus;
use ironic_core::dev::hlwd::compat::vi::VideoInterface;
use log::{Level, Metadata, Record};
use parking_lot::{Mutex, RwLock};
use slint::{ComponentHandle, Model, Timer, TimerMode, VecModel};

slint::include_modules!();

/// How often the UI drains the pending log buffer.
const LOG_DRAIN_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum rows kept in the UI model. Rows past this are dropped oldest-first.
const MAX_UI_ROWS: usize = 5_000;
/// Maximum records buffered between drains. Protects against the emulator
/// out-running the event loop (it will, easily, at debug/trace levels).
const MAX_PENDING: usize = 100_000;

struct LogLine {
    facility: String,
    level: &'static str,
    txt: String,
}

/// Shared, lock-protected hand-off between the emulator threads and the UI thread.
type LogSink = Arc<Mutex<VecDeque<LogLine>>>;

struct IronicGuiLogger {
    sink: LogSink,
    base_level: Level,
    target_levels: FxHashMap<String, Level>,
}

impl IronicGuiLogger {
    fn new(sink: LogSink) -> Self {
        Self { sink, base_level: Level::Info, target_levels: Default::default() }
    }
}

impl log::Log for IronicGuiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        match self.target_levels.get(metadata.target()) {
            None => metadata.level() <= self.base_level,
            Some(lvl) => metadata.level() <= *lvl,
        }
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = LogLine {
            facility: record.target().to_owned(),
            level: record.level().as_str(),
            txt: record.args().to_string(),
        };
        let mut sink = self.sink.lock();
        if sink.len() >= MAX_PENDING {
            sink.pop_front();
        }
        sink.push_back(line);
    }

    fn flush(&self) {}
}

fn start_logging(sink: LogSink) {
    let logger = Box::leak(Box::new(IronicGuiLogger::new(sink)));
    log::set_logger(logger).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
}

/// Moves everything buffered by the logger into the UI model, trimming the
/// model back down to `MAX_UI_ROWS` if it grew too far.
fn drain_logs(sink: &LogSink, model: &Rc<VecModel<LogDesc>>, ui: &AppWindow) {
    let pending: VecDeque<LogLine> = {
        let mut guard = sink.lock();
        if guard.is_empty() {
            return;
        }
        std::mem::take(&mut *guard)
    };

    for line in pending {
        model.push(LogDesc {
            facility: line.facility.into(),
            level: line.level.into(),
            txt: line.txt.into(),
        });
    }

    // Trim in bulk rather than one `remove(0)` at a time; each removal is a
    // separate model notification and an O(n) shift.
    let count = model.row_count();
    if count > MAX_UI_ROWS {
        let keep: Vec<LogDesc> = model.iter().skip(count - MAX_UI_ROWS).collect();
        model.set_vec(keep);
    }

    ui.invoke_scroll_to_bottom();
}

/// Resets the `running` flag on the UI when the emulator thread exits, whether
/// it returned normally, errored, or panicked.
struct RunningGuard(slint::Weak<AppWindow>);
impl Drop for RunningGuard {
    fn drop(&mut self) {
        let _ = self.0.upgrade_in_event_loop(|ui| ui.set_running(false));
    }
}

fn start_emulator(ui: slint::Weak<AppWindow>) {
    let spawned = Builder::new().name("EmuThread".to_owned()).spawn(move || {
        let _guard = RunningGuard(ui);

        let bus = match Bus::new() {
            Ok(bus) => Arc::new(RwLock::new(bus)),
            Err(reason) => {
                log::error!(target: "Other", "Failed to construct emulator Bus: {reason}");
                return;
            }
        };

        if let Err(reason) = VideoInterface::spawn_irq_thread(bus.clone()) {
            log::error!(target: "VI", "Failed to spawn the VI IRQ thread: {reason}");
            return;
        }

        let mut back = InterpBackend::new(bus, None, false);
        if let Err(reason) = back.run() {
            log::error!(target: "Other", "InterpBackend returned an Err: {reason}");
        }
    });

    if let Err(reason) = spawned {
        log::error!(target: "Other", "Failed to spawn the emulator thread: {reason}");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;

    let sink: LogSink = Arc::new(Mutex::new(VecDeque::new()));
    start_logging(sink.clone());

    // The property has to be backed by a `VecModel` we own; the default value of
    // a `[LogDesc]` property is an empty model that cannot be downcast to one.
    let log_model = Rc::new(VecModel::<LogDesc>::default());
    ui.set_logs(log_model.clone().into());

    let drain_timer = Timer::default();
    {
        let ui = ui.as_weak();
        let sink = sink.clone();
        let log_model = log_model.clone();
        drain_timer.start(TimerMode::Repeated, LOG_DRAIN_INTERVAL, move || {
            if let Some(ui) = ui.upgrade() {
                drain_logs(&sink, &log_model, &ui);
            }
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_start_emu(move || {
            let Some(ui) = weak.upgrade() else { return };
            if ui.get_running() {
                return;
            }
            ui.set_running(true);
            start_emulator(ui.as_weak());
        });
    }

    ui.run()?;
    Ok(())
}
