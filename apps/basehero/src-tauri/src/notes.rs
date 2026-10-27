//! Open editor handles to core documents. The core owns the document and persists edits.
use crate::error::CommandError;
use bh_core::{AccountId, Base, BaseId, Mode, NoteDoc, ObjectId};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tauri::async_runtime::JoinHandle;
use tokio::sync::broadcast::error::RecvError;

pub struct NoteOpened {
    pub session: u64,
    pub state: Vec<u8>,
    pub read_only: bool,
}

struct Session {
    window: String,
    account: AccountId,
    base: BaseId,
    note: NoteDoc,
    read_only: bool,
    forwarder: JoinHandle<()>,
}

pub struct NoteSessions {
    next: AtomicU64,
    sessions: Mutex<HashMap<u64, Session>>,
}

impl Default for NoteSessions {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(2),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl NoteSessions {
    pub fn open(
        &self,
        window: &str,
        account: AccountId,
        base: &Base,
        id: ObjectId,
        sink: Box<dyn Fn(Vec<u8>) + Send + Sync>,
    ) -> Result<NoteOpened, CommandError> {
        base.get(id)?.ok_or_else(not_found)?;
        let read_only = base.mode() == Mode::ReadOnly;
        let note = base.note(id)?;
        let mut updates = note.subscribe();
        let state = note.state();
        let session = self.next.fetch_add(1, Ordering::Relaxed);
        let forward_note = note.clone();
        let forwarder = tauri::async_runtime::spawn(async move {
            loop {
                match updates.recv().await {
                    Ok(update) if update.origin != session => sink(update.update),
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        // Drop the stale backlog; subscribe before the snapshot so edits
                        // racing with state() still reach this editor.
                        updates = forward_note.subscribe();
                        sink(forward_note.state());
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
        self.sessions.lock().unwrap().insert(
            session,
            Session {
                window: window.to_owned(),
                account,
                base: base.id(),
                note,
                read_only,
                forwarder,
            },
        );
        Ok(NoteOpened {
            session,
            state,
            read_only,
        })
    }

    pub fn apply(&self, session: u64, update: &[u8]) -> Result<(), CommandError> {
        let sessions = self.sessions.lock().unwrap();
        let open = sessions.get(&session).ok_or_else(not_found)?;
        if open.read_only {
            return Err(bh_core::Error::ReadOnly.into());
        }
        open.note.apply(session, update).map_err(Into::into)
    }

    pub fn close(&self, session: u64) {
        self.sessions.lock().unwrap().remove(&session);
    }

    pub fn close_window(&self, window: &str) {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, session| session.window != window);
    }

    pub fn close_base(&self, account: AccountId, base: BaseId) {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, session| session.account != account || session.base != base);
    }

    pub fn close_account(&self, account: AccountId) {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, session| session.account != account);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.forwarder.abort();
    }
}

fn not_found() -> CommandError {
    CommandError {
        kind: "NotFound".into(),
        message: "Note session not found".into(),
    }
}
