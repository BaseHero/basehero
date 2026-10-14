//! Native-only adapter. No store is opened and no note is bound until a real
//! account session supplies an authority source and a device database. In
//! particular, the shell never creates a synthetic account or default note.
use std::sync::Mutex;

use bh_storage::{
    DeviceDatabase,
    coordinator::{AuthoritySource, Coordinator},
};
use serde::Serialize;
use tauri::{Manager, WebviewWindow};

type BoundCoordinator = Coordinator<Box<dyn AuthoritySource + Send>>;
pub struct NoteHost(Mutex<Option<BoundCoordinator>>);
impl Default for NoteHost {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}
impl NoteHost {
    /// Called only after the native account session has established authority.
    /// Replacing a session invalidates every prior window generation.
    #[allow(dead_code)]
    pub fn install(&self, database: DeviceDatabase, authority: Box<dyn AuthoritySource + Send>) {
        let mut guard = self.0.lock().expect("note host lock");
        let previous = guard.as_ref().map_or(0, Coordinator::generation_counter);
        let mut coordinator = Coordinator::new(database, authority);
        coordinator.carry_generation(previous);
        *guard = Some(coordinator);
    }
    fn invalidate(&self, window: &str) {
        if let Some(host) = self.0.lock().expect("note host lock").as_mut() {
            host.invalidate(window);
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Opened {
    state: Vec<u8>,
    generation: u64,
    sequence: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Acknowledged {
    request_id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Incoming {
    generation: u64,
    sequence: u64,
    update: Vec<u8>,
}

#[tauri::command]
fn note_binding(window: WebviewWindow, host: tauri::State<'_, NoteHost>) -> Option<Vec<u8>> {
    let guard = host.0.lock().expect("note host lock");
    let scope = guard.as_ref()?.bound_scope(window.label());
    scope.map(|scope| scope.key.note.to_vec())
}

#[tauri::command]
fn note_open(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    note: Vec<u8>,
) -> Result<Opened, &'static str> {
    let note: [u8; 32] = note.try_into().map_err(|_| "note unavailable")?;
    let mut guard = host.0.lock().expect("note host lock");
    let opened = guard
        .as_mut()
        .ok_or("note unavailable")?
        .open(window.label(), note)
        .map_err(|_| "note unavailable")?;
    Ok(Opened {
        state: opened.state,
        generation: opened.generation,
        sequence: opened.sequence,
    })
}

#[tauri::command]
fn note_commit(
    window: WebviewWindow,
    host: tauri::State<'_, NoteHost>,
    generation: u64,
    request_id: String,
    update: Vec<u8>,
) -> Result<Acknowledged, &'static str> {
    let request: [u8; 16] = decode_request(&request_id).ok_or("invalid request")?;
    let mut guard = host.0.lock().expect("note host lock");
    let coordinator = guard.as_mut().ok_or("note unavailable")?;
    // Dispatch while holding the host lock: subscribers cannot observe a later
    // update ahead of this one. Only numeric fields are interpolated into the
    // bundled WebView's DOM event, not document text or untrusted markup. This
    // avoids granting the page the general Tauri event-listen IPC permission.
    coordinator
        .commit(window.label(), generation, request, &update, |delivery| {
            if let Some(target) = window.app_handle().get_webview_window(&delivery.window) {
                let payload = Incoming {
                    generation: delivery.generation,
                    sequence: delivery.sequence,
                    update: delivery.update,
                };
                if let Ok(json) = serde_json::to_string(&payload) {
                    let _ = target.eval(format!(
                        "window.dispatchEvent(new CustomEvent('bh-note-update',{{detail:{json}}}))"
                    ));
                }
            }
        })
        .map_err(|_| "note commit failed")?;
    Ok(Acknowledged { request_id })
}

#[tauri::command]
fn note_close(window: WebviewWindow, host: tauri::State<'_, NoteHost>, generation: u64) {
    if let Some(coordinator) = host.0.lock().expect("note host lock").as_mut() {
        coordinator.close_generation(window.label(), generation);
    }
}
fn decode_request(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

pub fn builder() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .manage(NoteHost::default())
        .invoke_handler(tauri::generate_handler![
            note_binding,
            note_open,
            note_commit,
            note_close
        ])
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Started {
                webview
                    .app_handle()
                    .state::<NoteHost>()
                    .invalidate(webview.label());
            }
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::Destroyed) {
                window
                    .app_handle()
                    .state::<NoteHost>()
                    .invalidate(window.label());
            }
        })
}
