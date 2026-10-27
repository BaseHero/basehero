use crate::error::CommandError;
use crate::views::AppEvent;
use crate::{commands, secrets};
use bh_core::{Core, CoreConfig, Url};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};

/// Where app events go: every window, or a test's capture.
pub type Sink = Arc<dyn Fn(AppEvent) + Send + Sync>;

/// One per process: the core, the server new accounts use, and the sink.
pub struct AppState {
    pub core: Core,
    pub server: Url,
    pub sink: Sink,
}

impl AppState {
    pub fn open(config: CoreConfig, server: Url, sink: Sink) -> Result<AppState, CommandError> {
        Ok(Self {
            core: Core::open(config)?,
            server,
            sink,
        })
    }
}

/// What startup left: the open state, or why it couldn't open, which every
/// command then returns, so the UI shows the key error screen.
pub struct Startup(Result<AppState, CommandError>);

impl Startup {
    pub fn open(app: &AppHandle) -> Startup {
        let opened = open(app);
        if let Err(error) = &opened {
            eprintln!("BaseHero couldn't open: {}: {}", error.kind, error.message);
        }
        Startup(opened)
    }

    pub fn state(&self) -> Result<&AppState, CommandError> {
        self.0.as_ref().map_err(Clone::clone)
    }
}

/// Loads the master key, builds the secret store, checks its canary and
/// opens the core.
fn open(app: &AppHandle) -> Result<AppState, CommandError> {
    let storage = |message: String| CommandError {
        kind: "Storage".into(),
        message,
    };
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| storage(e.to_string()))?;
    #[cfg(any(target_os = "macos", target_os = "android"))]
    let master = Some(secrets::master_key(app)?);
    #[cfg(not(any(target_os = "macos", target_os = "android")))]
    let master = None;
    let secrets = secrets::store(&data_dir, master)?;
    secrets::check_canary(&*secrets)?;
    let server = commands::app_info()
        .server
        .parse::<Url>()
        .map_err(|e| storage(e.to_string()))?;
    let app = app.clone();
    let sink: Sink = Arc::new(move |event| {
        let _ = app.emit("bh:event", event);
    });
    AppState::open(CoreConfig { data_dir, secrets }, server, sink)
}
