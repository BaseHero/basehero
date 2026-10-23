//! Window-bound routes to the account host's verified device view and controls.
//! The page receives names and eligibility, never a key, container or account id.
use crate::account_host::{AccountOperation, Screen, SharedAccountHost};
use bh_account::recovery::RecoveryCode;
use bh_host::{
    devices::{self, AlertItem, DevicesView},
    pairing::{JoinStatus, PairingHost},
    sync::SyncHost,
};

fn device_id(hex: &str) -> Result<[u8; 32], &'static str> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err("invalid device");
    }
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&bytes[2 * i..2 * i + 2]).map_err(|_| "invalid device")?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| "invalid device")?;
    }
    Ok(id)
}

/// Only the main account window or one bound note window reaches controls.
fn window_allowed(
    window: &tauri::WebviewWindow,
    notes: &crate::note_host::NoteHost,
    accounts: &SharedAccountHost,
) -> Result<(), &'static str> {
    match notes.owner().bound_container(window.label()) {
        Some(id) if accounts.controls_account(id) => Ok(()),
        None if window.label() == "main" => Ok(()), // kit save has no note binding
        _ => Err("devices unavailable"),
    }
}

/// Reopen only the staged kit of this window's currently routed account.
/// A foreign note window cannot read its code, even if it knows this route.
#[tauri::command]
pub fn devices_kit_screen(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
) -> Result<Option<Screen>, &'static str> {
    window_allowed(&window, &notes, &accounts)?;
    Ok(accounts
        .screen()
        .filter(|screen| matches!(screen, Screen::NewKit { .. })))
}

#[tauri::command]
pub fn devices_view(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
) -> Result<DevicesView, &'static str> {
    window_allowed(&window, &notes, &accounts)?;
    devices::view(&accounts, &sync).ok_or("devices unavailable")
}

async fn run_device_operation(
    accounts: &SharedAccountHost,
    sync: &SyncHost,
    operation: AccountOperation,
) -> Result<Screen, &'static str> {
    // Device controls can grow beyond JavaBridge's IPC dispatch stack.
    // Construct their future when this adapter runs on the async runtime.
    Box::pin(devices::run(accounts, sync, operation)).await
}

async fn run(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    operation: AccountOperation,
) -> Result<Screen, &'static str> {
    window_allowed(&window, &notes, &accounts)?;
    run_device_operation(&accounts, &sync, operation).await
}

#[tauri::command]
pub async fn devices_request_removal(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    device: String,
) -> Result<Screen, &'static str> {
    run(
        window,
        notes,
        accounts,
        sync,
        AccountOperation::RequestRemoval {
            device: device_id(&device)?,
        },
    )
    .await
}
#[tauri::command]
pub async fn devices_cancel_removal(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    request: u64,
) -> Result<Screen, &'static str> {
    run(
        window,
        notes,
        accounts,
        sync,
        AccountOperation::CancelRemoval { request },
    )
    .await
}
#[tauri::command]
pub async fn devices_remove_now(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    device: String,
    password: String,
    code: String,
) -> Result<Screen, &'static str> {
    run(
        window,
        notes,
        accounts,
        sync,
        AccountOperation::RemoveNow {
            device: device_id(&device)?,
            password,
            code,
        },
    )
    .await
}
#[tauri::command]
pub async fn devices_remove_self(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    without_sync: bool,
) -> Result<Screen, &'static str> {
    run(
        window,
        notes,
        accounts,
        sync,
        AccountOperation::RemoveSelf { without_sync },
    )
    .await
}
#[tauri::command]
pub async fn account_change_password(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    current: String,
    new_password: Option<String>,
    code: Option<String>,
) -> Result<Screen, &'static str> {
    run(
        window,
        notes,
        accounts,
        sync,
        AccountOperation::ChangePassword {
            current,
            new: new_password,
            code,
        },
    )
    .await
}
#[tauri::command]
pub async fn account_confirm_new_kit(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
) -> Result<Screen, &'static str> {
    run(
        window,
        notes,
        accounts,
        sync,
        AccountOperation::ConfirmNewKit,
    )
    .await
}
#[tauri::command]
pub fn alerts_list(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
) -> Result<Vec<AlertItem>, &'static str> {
    Ok(devices_view(window, notes, accounts, sync)?.alerts)
}

/// Local checksum only: an invalid kit never contacts the recovery service.
#[tauri::command]
pub fn account_check_code(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    code: String,
) -> Result<bool, &'static str> {
    crate::account_host::ensure_setup_window(&window, &notes)?;
    Ok(RecoveryCode::from_kit_text(&code).is_ok())
}
async fn recover_setup(
    label: &str,
    accounts: &SharedAccountHost,
    sync: &SyncHost,
    pairing: &PairingHost,
    password: String,
    code: String,
) -> Result<Screen, String> {
    // Like the other account setup commands, keep the large workflow future
    // out of the command future constructed on Android's JavaBridge thread.
    Box::pin(pairing.setup_screen(
        label,
        accounts,
        sync,
        AccountOperation::Recover { password, code },
    ))
    .await
    .map_err(str::to_owned)
}

#[tauri::command]
pub async fn account_recover(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    accounts: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, SyncHost>,
    pairing: tauri::State<'_, PairingHost>,
    password: String,
    code: String,
) -> Result<Screen, String> {
    crate::account_host::ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    if RecoveryCode::from_kit_text(&code).is_err() {
        return Ok(Screen::RecoverRefused {
            reason: "not_recognised",
            tries_left: None,
            next_try_ms: None,
        });
    }
    recover_setup(window.label(), &accounts, &sync, &pairing, password, code).await
}
#[tauri::command]
pub fn account_recovery_status(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    pairing: tauri::State<'_, PairingHost>,
) -> Result<Option<JoinStatus>, &'static str> {
    crate::account_host::ensure_setup_window(&window, &notes)?;
    Ok(pairing.recovery_status(window.label()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn native_ipc_host_operation_futures_stay_below_64_kib() {
        let owner = Arc::new(bh_device::Owner::default());
        let accounts = bh_host::accounts::AccountHost::<
            bh_host::test_support::FakeStore,
            bh_host::test_support::PlainProtector,
        >::new(owner.clone(), None)
        .into_state();
        let sync = SyncHost::new(bh_host::sync::Configured::Missing, owner);
        let pairing = PairingHost::default();
        let setup = pairing.setup_screen("main", &accounts, &sync, AccountOperation::Startup);
        eprintln!(
            "raw setup_screen future: {} bytes",
            std::mem::size_of_val(&setup)
        );
        let platform_accounts =
            crate::account_host::account_host(Arc::new(bh_device::Owner::default())).into_state();
        let recover = recover_setup(
            "main",
            &platform_accounts,
            &sync,
            &pairing,
            String::new(),
            String::new(),
        );
        eprintln!(
            "recovery IPC helper future: {} bytes",
            std::mem::size_of_val(&recover)
        );
        assert!(
            std::mem::size_of_val(&recover) < 8 * 1024,
            "keep the recovery helper small enough to embed within IPC dispatch"
        );
        let operations = [
            AccountOperation::RequestRemoval { device: [0; 32] },
            AccountOperation::CancelRemoval { request: 1 },
            AccountOperation::RemoveNow {
                device: [0; 32],
                password: String::new(),
                code: String::new(),
            },
            AccountOperation::RemoveSelf {
                without_sync: false,
            },
            AccountOperation::ChangePassword {
                current: String::new(),
                new: None,
                code: None,
            },
            AccountOperation::ConfirmNewKit,
        ];
        for operation in operations {
            let future = devices::run(&accounts, &sync, operation);
            eprintln!(
                "raw devices::run future: {} bytes",
                std::mem::size_of_val(&future)
            );
            assert!(std::mem::size_of_val(&future) < 64 * 1024);
        }
        let adapter =
            run_device_operation(&platform_accounts, &sync, AccountOperation::ConfirmNewKit);
        eprintln!(
            "device IPC adapter future: {} bytes",
            std::mem::size_of_val(&adapter)
        );
        assert!(std::mem::size_of_val(&adapter) < 8 * 1024);
    }

    #[test]
    fn malformed_device_ids_are_not_forwarded() {
        assert_eq!(device_id(&"ff".repeat(32)), Ok([255; 32]));
        assert_eq!(device_id("00"), Err("invalid device"));
        assert_eq!(device_id(&"gg".repeat(32)), Err("invalid device"));
    }
}
