use crate::error::CommandError;
use crate::state::AppState;
use crate::views::{SecretString, SignInForm, SignUpForm, SignedUp};
use bh_core::{
    AccountId, AccountSummary, AccountUsage, DeviceId, DeviceSummary, KitStatus, SignIn, SignUp,
};

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
    // If the account-data write failed, this one-time displayed kit cannot
    // be shown again; the person can make a new kit after signing in.
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
        crate::state::sync_hidden_recents(&state.core);
    }
    result?;
    Ok(())
}

pub async fn new_kit(
    state: &AppState,
    id: AccountId,
    password: &str,
) -> Result<SecretString, CommandError> {
    let kit = state.core.account(id)?.new_kit(password).await?;
    Ok(kit.display().into())
}

pub fn kit_status(state: &AppState, id: AccountId) -> Result<KitStatus, CommandError> {
    Ok(state.core.account(id)?.kit_status()?)
}

pub fn show_kit(state: &AppState, id: AccountId) -> Result<SecretString, CommandError> {
    let kit = state
        .core
        .account(id)?
        .recovery_kit()?
        .ok_or(bh_core::Error::NotFound)?;
    Ok(kit.display().into())
}

pub async fn set_kit_saved(state: &AppState, id: AccountId, kit: &str) -> Result<(), CommandError> {
    let kit = bh_core::RecoveryKit::parse(kit)?;
    Ok(state.core.account(id)?.set_kit_saved(&kit).await?)
}

pub async fn devices(state: &AppState, id: AccountId) -> Result<Vec<DeviceSummary>, CommandError> {
    Ok(state.core.account(id)?.devices().await?)
}

pub async fn set_app_cap(
    state: &AppState,
    id: AccountId,
    device: DeviceId,
    cap_micro_usd: u64,
) -> Result<(), CommandError> {
    Ok(state
        .core
        .account(id)?
        .set_app_cap(device, cap_micro_usd)
        .await?)
}

pub async fn usage(
    state: &AppState,
    id: AccountId,
    month: Option<&str>,
) -> Result<AccountUsage, CommandError> {
    Ok(state.core.account(id)?.usage(month).await?)
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
        crate::state::sync_hidden_recents(&state.core);
    }
    result?;
    Ok(())
}
