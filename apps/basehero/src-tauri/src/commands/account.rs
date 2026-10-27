use crate::error::CommandError;
use crate::state::AppState;
use crate::views::{SecretString, SignInForm, SignUpForm, SignedUp};
use bh_core::{AccountId, AccountSummary, DeviceId, DeviceSummary, SignIn, SignUp};

fn not_found() -> CommandError {
    CommandError {
        kind: "NotFound".into(),
        message: "Not found".into(),
    }
}

pub fn accounts(state: &AppState) -> Result<Vec<AccountSummary>, CommandError> {
    Ok(state.core.accounts())
}

pub async fn sign_up(state: &AppState, form: SignUpForm) -> Result<SignedUp, CommandError> {
    let (account, kit) = state
        .core
        .sign_up(SignUp {
            server: state.server.clone(),
            invite: form.invite,
            email: form.email,
            password: form.password.into_inner(),
            device_name: form.device_name,
        })
        .await?;
    let id = account.id();
    // The account is installed already: never lose the one-time kit because
    // creating its first base failed. Retry when this account next signs in.
    if account.bases().is_empty() {
        let _ = account.create_base("Personal").await;
    }
    let summary = AccountSummary {
        id,
        email: account.email(),
        kind: account.kind(),
    };
    let _ = state.listen(id);
    Ok(SignedUp {
        account: summary,
        kit: kit.display().into(),
    })
}

pub async fn sign_in_start(state: &AppState, form: SignInForm) -> Result<String, CommandError> {
    let pending = state
        .core
        .sign_in(SignIn {
            server: state.server.clone(),
            email: form.email,
            password: form.password.into_inner(),
            device_name: form.device_name,
        })
        .await?;
    let id = AccountId::random().to_string();
    let mut entries = state.pending.lock().unwrap();
    entries.insert(id.clone(), std::sync::Arc::new(pending));
    drop(entries);
    state.active_pending.lock().unwrap().insert(id.clone());
    state.expire_pending(id.clone());
    Ok(id)
}

pub async fn sign_in_with_kit(
    state: &AppState,
    pending: &str,
    kit: &str,
) -> Result<AccountSummary, CommandError> {
    let entry = {
        state
            .pending
            .lock()
            .unwrap()
            .get(pending)
            .cloned()
            .ok_or_else(not_found)?
    };
    let account = entry.with_kit(kit).await?;
    state.pending.lock().unwrap().remove(pending);
    state.active_pending.lock().unwrap().remove(pending);
    state.listen(account.id())?;
    if account.bases().is_empty() {
        let _ = account.create_base("Personal").await;
    }
    state
        .core
        .accounts()
        .into_iter()
        .find(|a| a.id == account.id())
        .ok_or_else(not_found)
}

pub fn sign_in_cancel(state: &AppState, pending: &str) -> Result<(), CommandError> {
    state.pending.lock().unwrap().remove(pending);
    state.active_pending.lock().unwrap().remove(pending);
    let entry = state.approvals.lock().unwrap().remove(pending);
    if let Some(entry) = entry {
        entry.stop();
        tauri::async_runtime::spawn(async move {
            let _ = entry.handle.lock().await.cancel().await;
        });
    }
    Ok(())
}

pub async fn sign_out(state: &AppState, id: AccountId) -> Result<(), CommandError> {
    let result = state.core.account(id)?.sign_out().await;
    // The core forgets the account before erasing its files, so release its handles
    // whenever it's gone, even if erasing then failed.
    if state.core.account(id).is_err() {
        state.forget_account(id);
        state.notes.close_account(id);
        state.stop_listening(id);
    }
    result?;
    Ok(())
}

fn saved_path(state: &AppState, id: AccountId) -> Result<std::path::PathBuf, CommandError> {
    state.core.account(id)?;
    Ok(state
        .data_dir
        .join("accounts")
        .join(id.to_string())
        .join("kit-saved"))
}

pub async fn new_kit(
    state: &AppState,
    id: AccountId,
    password: &str,
) -> Result<SecretString, CommandError> {
    let path = saved_path(state, id)?;
    // Clear the saved marker first: if storage fails, do not rotate a kit
    // whose only copy the caller would never receive.
    match std::fs::remove_file(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(storage(error)),
    }
    Ok(state
        .core
        .account(id)?
        .new_kit(password)
        .await?
        .display()
        .into())
}

fn storage(error: std::io::Error) -> CommandError {
    CommandError {
        kind: "Storage".into(),
        message: error.to_string(),
    }
}

pub fn kit_saved(state: &AppState, id: AccountId) -> Result<bool, CommandError> {
    let path = saved_path(state, id)?;
    match std::fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage(error)),
    }
}

pub fn set_kit_saved(state: &AppState, id: AccountId) -> Result<(), CommandError> {
    let path = saved_path(state, id)?;
    std::fs::write(path, b"1").map_err(storage)
}

pub async fn devices(state: &AppState, id: AccountId) -> Result<Vec<DeviceSummary>, CommandError> {
    Ok(state.core.account(id)?.devices().await?)
}

/// Revokes a device; removing this device also signs out of the app shell.
pub async fn remove_device(
    state: &AppState,
    id: AccountId,
    device: DeviceId,
) -> Result<(), CommandError> {
    let result = state.core.account(id)?.remove_device(device).await;
    if state.core.account(id).is_err() {
        state.forget_account(id);
        state.notes.close_account(id);
        state.stop_listening(id);
    }
    result?;
    Ok(())
}
