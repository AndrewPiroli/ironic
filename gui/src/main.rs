// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod logger;

use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::Builder;
use std::time::{Duration, Instant};

use ironic_backend::back::Backend;
use ironic_backend::cleanup;
use ironic_backend::interp::InterpBackend;
use ironic_core::bus::Bus;
use ironic_core::dev::hlwd::compat::vi::VideoInterface;
use ironic_core::logtarget::LogTarget;
use log::{Level, LevelFilter};
use parking_lot::RwLock;
use slint::{CloseRequestResponse, ComponentHandle, Model, Timer, TimerMode, VecModel};

use logger::LogSink;

slint::include_modules!();

/// How often the UI drains the pending log buffer.
const LOG_DRAIN_INTERVAL: Duration = Duration::from_millis(100);
/// Maximum rows kept in the UI model. Rows past this are dropped oldest-first.
const MAX_UI_ROWS: usize = 5_000;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

struct Session {
    shutdown: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

type SessionCell = Rc<RefCell<Option<Session>>>;

/// Move everything buffered by the logger into the UI model, fixing the model
/// back down to `MAX_UI_ROWS` if it grew too far.
fn drain_logs(sink: &LogSink, model: &Rc<VecModel<LogDesc>>, ui: &AppWindow) {
    let pending = logger::take_pending(sink);
    if pending.is_empty() {
        return;
    }

    for line in pending {
        model.push(LogDesc {
            facility: line.facility.into(),
            level: line.level.into(),
            txt: line.txt.into(),
        });
    }

    // todo: figure out types better
    let count = model.row_count();
    if count > MAX_UI_ROWS {
        let keep: Vec<LogDesc> = model.iter().skip(count - MAX_UI_ROWS).collect();
        model.set_vec(keep);
    }

    ui.invoke_scroll_to_bottom();
}

//hatred

fn override_from_index(index: i32) -> Option<LevelFilter> {
    match index {
        1 => Some(LevelFilter::Off),
        2 => Some(LevelFilter::Error),
        3 => Some(LevelFilter::Warn),
        4 => Some(LevelFilter::Info),
        5 => Some(LevelFilter::Debug),
        6 => Some(LevelFilter::Trace),
        _ => None,
    }
}

fn base_from_index(index: i32) -> LevelFilter {
    match index {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}

fn build_options_model(config: &logger::LevelConfig) -> Rc<VecModel<LogOptionDesc>> {
    let rows: Vec<LogOptionDesc> = LogTarget::all()
        .iter()
        .map(|target| LogOptionDesc {
            name: target.as_log_str().into(),
            level: match config.target_override(*target) {
                None => 0,
                Some(f) => f as i32 + 1,
            },
        })
        .collect();
    Rc::new(VecModel::from(rows))
}


fn start_emulator(ui: slint::Weak<AppWindow>, session: &SessionCell) {
    let shutdown = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));

    let thread_ui = ui.clone();
    let thread_shutdown = shutdown.clone();
    let thread_finished = finished.clone();
    let spawned = Builder::new().name("EmuThread".to_owned()).spawn(move || {
        let _guard = ExitGuard { ui: thread_ui, finished: thread_finished };

        let bus = match Bus::with_shutdown(thread_shutdown) {
            Ok(bus) => Arc::new(RwLock::new(bus)),
            Err(reason) => {
                log::error!(target: "Other", "Failed to construct emulator Bus: {reason}");
                return;
            }
        };
        cleanup::install_panic_hook(&bus);

        if let Err(reason) = VideoInterface::spawn_irq_thread(bus.clone()) {
            log::error!(target: "VI", "Failed to spawn the VI IRQ thread: {reason}");
            return;
        }

        let mut back = InterpBackend::new(bus.clone(), None, false);
        if let Err(reason) = back.run() {
            log::error!(target: "Other", "InterpBackend returned an Err: {reason}");
        }
        // The interpreter has stopped

        bus.read().shutdown.store(true, Ordering::Release);
        if let Some(bus) = cleanup::lock_for_cleanup(&bus) {
            cleanup::persist_and_dump(&bus, "bin");
            log::info!(target: "Other", "Bus cycles elapsed: {}", bus.cycle);
        }
    });

    match spawned {
        Ok(_) => {
            *session.borrow_mut() = Some(Session { shutdown, finished });
        }
        Err(reason) => {
            log::error!(target: "Other", "Failed to spawn the emulator thread: {reason}");
            if let Some(ui) = ui.upgrade() {
                ui.set_running(false);
                ui.set_status("Idle".into());
            }
        }
    }
}

/// Resets UI state when the emulator thread exits, however it exits.
struct ExitGuard {
    ui: slint::Weak<AppWindow>,
    finished: Arc<AtomicBool>,
}

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
        let _ = self.ui.upgrade_in_event_loop(|ui| {
            ui.set_running(false);
            ui.set_stopping(false);
            ui.set_status("Idle".into());
        });
    }
}




fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;

    let sink = logger::new_sink();
    let log_config = logger::init(sink.clone(), Level::Info);

    let log_model = Rc::new(VecModel::<LogDesc>::default());
    ui.set_logs(log_model.clone().into());

    ui.set_base_level(log_config.base() as i32);
    ui.set_log_options(build_options_model(&log_config).into());

    let session: SessionCell = Rc::new(RefCell::new(None));

    let drain_timer = Timer::default();
    {
        let ui_weak = ui.as_weak();
        let sink = sink.clone();
        let log_model = log_model.clone();
        drain_timer.start(TimerMode::Repeated, LOG_DRAIN_INTERVAL, move || {
            if let Some(ui) = ui_weak.upgrade() {
                drain_logs(&sink, &log_model, &ui);
            }
        });
    }

    // start button
    {
        let ui_weak = ui.as_weak();
        let session = session.clone();
        ui.on_start_emu(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if ui.get_running() || ui.get_stopping() {
                return;
            }
            ui.set_running(true);
            ui.set_status("Running".into());
            start_emulator(ui.as_weak(), &session);
        });
    }

    // stop button
    {
        let ui_weak = ui.as_weak();
        let session = session.clone();
        ui.on_stop_emu(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if let Some(active) = session.borrow().as_ref() {
                log::info!(target: "Other", "Stop requested, winding down the emulator");
                ui.set_stopping(true);
                ui.set_status("Stopping...".into());
                active.shutdown.store(true, Ordering::Release);
            }
        });
    }

    // clear log
    {
        let log_model = log_model.clone();
        ui.on_clear_logs(move || log_model.set_vec(Vec::new()));
    }

    // options: base level
    {
        let config = log_config.clone();
        ui.on_base_level_picked(move |index| config.set_base(base_from_index(index)));
    }

    // options: per-target overrides
    {
        let config = log_config.clone();
        ui.on_target_level_picked(move |row, index| {
            let Some(target) = LogTarget::all().get(row as usize) else {
                return;
            };
            config.set_target_override(*target, override_from_index(index));
        });
    }

    // close via gui handler (defer to shutdown emu and save shit)
    {
        let ui_weak = ui.as_weak();
        let session = session.clone();
        let close_watch: Rc<RefCell<Option<Timer>>> = Rc::new(RefCell::new(None));
        ui.window().on_close_requested(move || {
            let Some(ui) = ui_weak.upgrade() else {
                return CloseRequestResponse::HideWindow;
            };
            let Some(active) = session.borrow().as_ref().map(|s| (s.shutdown.clone(), s.finished.clone())) else {
                return CloseRequestResponse::HideWindow;
            };
            let (shutdown, finished) = active;
            if finished.load(Ordering::Acquire) {
                return CloseRequestResponse::HideWindow;
            }

            log::info!(target: "Other", "Window closed, waiting for the emulator to shut down");
            ui.set_stopping(true);
            ui.set_status("Shutting down...".into());
            shutdown.store(true, Ordering::Release);

            let timer = Timer::default();
            let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
            timer.start(TimerMode::Repeated, Duration::from_millis(50), move || {
                if finished.load(Ordering::Acquire) || Instant::now() >= deadline {
                    let _ = slint::quit_event_loop();
                }
            });
            *close_watch.borrow_mut() = Some(timer);

            CloseRequestResponse::KeepWindowShown
        });
    }

    ui.run()?;
    Ok(())
}
