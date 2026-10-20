//! The pairing commands, bound to the app's pairing host
//! (`bh_host::pairing`): each names only the calling window, its page and
//! its bound account, never an account, base, container or key.
use bh_host::{
    pairing::{JoinStatus, PairingHost, PairingStatus, Refusal, Scope, Shown, Ticket},
    sync::SyncHost,
};

fn scope(window: &tauri::WebviewWindow, notes: &crate::note_host::NoteHost) -> Scope {
    let label = window.label().to_owned();
    Scope {
        page: notes.page(&label),
        container: notes.owner().bound_container(&label),
        window: label,
    }
}

/// This device's name as the showing device sees it: a model name only.
pub(crate) fn device_label() -> Vec<u8> {
    #[cfg(target_os = "android")]
    {
        std::process::Command::new("getprop")
            .arg("ro.product.model")
            .output()
            .ok()
            .and_then(|output| bh_host::pairing::label(&output.stdout))
            .unwrap_or_else(|| "Android phone".into())
            .into_bytes()
    }
    #[cfg(target_os = "macos")]
    {
        b"Mac".to_vec()
    }
    #[cfg(not(any(target_os = "android", target_os = "macos")))]
    {
        b"Computer".to_vec()
    }
}

/// Show a pairing code from the calling window's account.
#[tauri::command]
pub async fn pairing_show(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    sync: tauri::State<'_, SyncHost>,
    pairing: tauri::State<'_, PairingHost>,
) -> Result<Shown, &'static str> {
    pairing
        .show(scope(&window, &notes), &sync)
        .map_err(Refusal::message)
}

#[tauri::command]
pub fn pairing_status(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    pairing: tauri::State<'_, PairingHost>,
    session: String,
) -> Result<PairingStatus, &'static str> {
    pairing
        .status(&scope(&window, &notes), &session)
        .map_err(Refusal::message)
}

/// The person approves the shown candidate; the native confirmation follows.
#[tauri::command]
pub fn pairing_approve(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    pairing: tauri::State<'_, PairingHost>,
    session: String,
) -> Result<PairingStatus, &'static str> {
    pairing
        .approve(&scope(&window, &notes), &session)
        .map_err(Refusal::message)
}

#[tauri::command]
pub fn pairing_cancel(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    pairing: tauri::State<'_, PairingHost>,
    session: String,
) -> Result<PairingStatus, &'static str> {
    pairing
        .cancel(&scope(&window, &notes), &session)
        .map_err(Refusal::message)
}

/// The person asks, with a fresh confirmation, to finish an account change
/// that waits for them (after a restart lost the pairing's approval).
#[tauri::command]
pub async fn pairing_reconfirm(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    sync: tauri::State<'_, SyncHost>,
) -> Result<(), &'static str> {
    let handle = scope(&window, &notes)
        .container
        .and_then(|container| sync.handle(container))
        .ok_or(Refusal::Unavailable.message())?;
    handle
        .ops
        .reconfirm()
        .await
        .map_err(|_| "confirmation not given")?;
    handle.client.wake();
    Ok(())
}

/// Join an account with a scanned or pasted code, from the setup window of
/// a device with no account.
#[tauri::command]
pub async fn pairing_join(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, crate::account_host::SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    pairing: tauri::State<'_, PairingHost>,
    qr_text: String,
) -> Result<Ticket, &'static str> {
    crate::account_host::ensure_setup_window(&window, &notes)?;
    pairing
        .join(window.label(), &accounts, &sync, &qr_text, device_label())
        .map_err(Refusal::message)
}

#[tauri::command]
pub fn pairing_join_status(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    pairing: tauri::State<'_, PairingHost>,
    ticket: String,
) -> Result<JoinStatus, &'static str> {
    crate::account_host::ensure_setup_window(&window, &notes)?;
    pairing
        .join_status(window.label(), &ticket)
        .map_err(Refusal::message)
}
