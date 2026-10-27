//! Shared by the shell's integration tests; each test uses part of it.
#![allow(dead_code)]

use basehero_app_lib::state::AppState;
use basehero_app_lib::views::AppEvent;
use bh_core::{CoreConfig, FileSecretStore, Url};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// What a state sent to its sink, and the temporary directory it keeps its
/// data in, which lasts as long as this does.
#[derive(Clone)]
pub struct Events {
    seen: Arc<(Mutex<Vec<AppEvent>>, Condvar)>,
    dir: Arc<tempfile::TempDir>,
}

impl Events {
    /// The first event, seen or still to come, that matches; panics after 5 s.
    pub fn wait_for(&self, pred: impl Fn(&AppEvent) -> bool) -> AppEvent {
        let (seen, arrived) = &*self.seen;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = seen.lock().unwrap();
        loop {
            if let Some(event) = seen.iter().find(|e| pred(e)) {
                return event.clone();
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_else(|| panic!("no matching event within 5 s; saw {:?}", *seen));
            seen = arrived.wait_timeout(seen, left).unwrap().0;
        }
    }

    pub fn data_dir(&self) -> &Path {
        self.dir.path()
    }
}

/// A state in a new temporary directory, with plain-file secrets and a sink
/// that captures events.
pub fn state_at(server: Url) -> (AppState, Events) {
    let dir = tempfile::tempdir().unwrap();
    let events = Events {
        seen: Arc::default(),
        dir: Arc::new(dir),
    };
    (open_at(events.data_dir(), server, &events), events)
}

/// Another state over `events`' directory, as after a restart.
pub fn open_at(dir: &Path, server: Url, events: &Events) -> AppState {
    let secrets = Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap());
    let seen = events.seen.clone();
    let sink = Arc::new(move |event| {
        let (list, arrived) = &*seen;
        list.lock().unwrap().push(event);
        arrived.notify_all();
    });
    let config = CoreConfig {
        data_dir: dir.to_path_buf(),
        secrets,
    };
    AppState::open(config, server, sink).unwrap()
}
