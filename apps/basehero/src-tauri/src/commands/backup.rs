use crate::error::CommandError;
use crate::state::AppState;
use crate::views::{SecretString, SignUpForm, SignedUp};
use bh_core::{
    AccountId, BackupLocation, BackupStatus, BaseId, CheckReport, DeviceId, RestorableBase,
    RestoreSummary, Url,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;

/// One account/device with a readable backup in a chosen folder.
#[derive(Clone, Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct BackupListing {
    #[ts(type = "string")]
    pub account: AccountId,
    #[ts(type = "string")]
    pub device: DeviceId,
    pub email: String,
    #[ts(type = "string")]
    pub server: Url,
    pub written_at: i64,
}

impl From<bh_core::BackupListing> for BackupListing {
    fn from(listing: bh_core::BackupListing) -> Self {
        Self {
            account: listing.account,
            device: listing.device,
            email: listing.email,
            server: listing.server,
            written_at: listing.written_at,
        }
    }
}
impl From<&BackupListing> for bh_core::BackupListing {
    fn from(listing: &BackupListing) -> Self {
        Self {
            account: listing.account,
            device: listing.device,
            email: listing.email.clone(),
            server: listing.server.clone(),
            written_at: listing.written_at,
        }
    }
}

/// A base and its counts at a selected backup point.
#[derive(Clone, Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct BackupBase {
    #[ts(type = "string")]
    pub id: BaseId,
    pub name: String,
    pub hidden: bool,
    pub mount: Option<bh_core::Mount>,
    pub notes: usize,
    pub records: usize,
    pub files: usize,
}
impl From<RestorableBase> for BackupBase {
    fn from(base: RestorableBase) -> Self {
        Self {
            id: base.id,
            name: base.name,
            hidden: base.hidden,
            mount: base.mount,
            notes: base.notes,
            records: base.records,
            files: base.files,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoredSignUp {
    pub account: bh_core::AccountSummary,
    pub kit: crate::views::SecretString,
    pub summary: Option<RestoreSummary>,
    pub error: Option<CommandError>,
}

fn missing() -> CommandError {
    bh_core::Error::NotFound.into()
}

fn opened(
    state: &AppState,
    handle: &str,
) -> Result<Arc<tokio::sync::Mutex<bh_core::OpenedBackup>>, CommandError> {
    state
        .open_backups
        .lock()
        .unwrap()
        .get(handle)
        .map(|entry| entry.backup.clone())
        .ok_or_else(missing)
}

pub fn backup_status(state: &AppState, account: AccountId) -> Result<BackupStatus, CommandError> {
    Ok(state.core.account(account)?.backup_status()?)
}
pub fn set_backup(
    state: &AppState,
    account: AccountId,
    location: Option<BackupLocation>,
) -> Result<(), CommandError> {
    Ok(state.core.account(account)?.set_backup(location)?)
}
pub fn acknowledge_backup(state: &AppState, account: AccountId) -> Result<(), CommandError> {
    Ok(state.core.account(account)?.acknowledge_backup()?)
}
pub async fn backup_now(state: &AppState, account: AccountId) -> Result<(), CommandError> {
    state.core.account(account)?.backup_now().await?;
    Ok(())
}
pub fn backup_estimate(state: &AppState, account: AccountId) -> Result<u64, CommandError> {
    Ok(state.core.account(account)?.backup_estimate()?)
}

pub fn restore_list(
    state: &AppState,
    location: &BackupLocation,
) -> Result<Vec<BackupListing>, CommandError> {
    let folder = state.core.open_folder(location)?;
    Ok(bh_core::list_backups(folder.as_ref())?
        .into_iter()
        .map(Into::into)
        .collect())
}
pub async fn restore_open(
    state: &AppState,
    location: &BackupLocation,
    listing: &BackupListing,
    password: SecretString,
    kit: SecretString,
) -> Result<String, CommandError> {
    let source_was_present = state.core.account(listing.account).is_ok();
    let folder = state.core.open_folder(location)?;
    let opened = state
        .core
        .open_backup(folder, &listing.into(), password.into_inner(), &kit)
        .await?;
    state.insert_open_restore(listing.account, source_was_present, opened)
}
pub async fn restore_unlock(
    state: &AppState,
    handle: &str,
    password: SecretString,
) -> Result<usize, CommandError> {
    Ok(opened(state, handle)?
        .lock()
        .await
        .unlock(password.into_inner())
        .await?)
}
pub async fn restore_points(state: &AppState, handle: &str) -> Result<Vec<i64>, CommandError> {
    Ok(opened(state, handle)?.lock().await.points())
}
pub async fn restore_bases(
    state: &AppState,
    handle: &str,
    at: i64,
) -> Result<Vec<BackupBase>, CommandError> {
    Ok(opened(state, handle)?
        .lock()
        .await
        .bases(at)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}
pub async fn restore_check(
    state: &AppState,
    handle: &str,
    at: i64,
) -> Result<CheckReport, CommandError> {
    Ok(opened(state, handle)?.lock().await.check(at).await?)
}
pub async fn restore_into(
    state: &AppState,
    handle: &str,
    account: AccountId,
    at: i64,
    bases: &[BaseId],
    label: &str,
) -> Result<RestoreSummary, CommandError> {
    let backup = opened(state, handle)?;
    let target = state.core.account(account)?;
    if let Some(entry) = state.open_backups.lock().unwrap().get_mut(handle) {
        entry.destinations.insert(account);
    }
    Ok(backup
        .lock()
        .await
        .restore_into(&target, at, bases, label)
        .await?)
}
pub async fn restore_sign_up(
    state: &AppState,
    handle: &str,
    form: SignUpForm,
    at: i64,
    label: &str,
) -> Result<RestoredSignUp, CommandError> {
    // Check the handle and point before creating the new account.
    let backup = opened(state, handle)?;
    let backup = backup.lock().await;
    let bases: Vec<_> = backup
        .bases(at)
        .await?
        .into_iter()
        .map(|base| base.id)
        .collect();
    let SignedUp { account, kit } = super::account::sign_up_without_base(state, form).await?;
    if let Some(entry) = state.open_backups.lock().unwrap().get_mut(handle) {
        entry.destinations.insert(account.id);
    }
    let result = match state.core.account(account.id) {
        Ok(target) => backup
            .restore_into(&target, at, &bases, label)
            .await
            .map_err(CommandError::from),
        Err(error) => Err(error.into()),
    };
    let (summary, error) = match result {
        Ok(summary) => (Some(summary), None),
        Err(error) => (None, Some(error)),
    };
    Ok(RestoredSignUp {
        account,
        kit,
        summary,
        error,
    })
}
pub fn restore_close(state: &AppState, handle: &str) -> Result<(), CommandError> {
    state
        .open_backups
        .lock()
        .unwrap()
        .remove(handle)
        .ok_or_else(missing)?;
    Ok(())
}

pub mod ipc {
    use super::*;
    use crate::state::Startup;
    #[tauri::command]
    pub fn backup_status(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
    ) -> Result<BackupStatus, CommandError> {
        super::backup_status(startup.state()?, account)
    }
    #[tauri::command]
    pub fn set_backup(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        location: Option<BackupLocation>,
    ) -> Result<(), CommandError> {
        super::set_backup(startup.state()?, account, location)
    }
    #[tauri::command]
    pub fn acknowledge_backup(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
    ) -> Result<(), CommandError> {
        super::acknowledge_backup(startup.state()?, account)
    }
    #[tauri::command]
    pub async fn backup_now(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
    ) -> Result<(), CommandError> {
        super::backup_now(startup.state()?, account).await
    }
    #[tauri::command]
    pub fn backup_estimate(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
    ) -> Result<u64, CommandError> {
        super::backup_estimate(startup.state()?, account)
    }
    #[tauri::command]
    pub async fn pick_backup_folder(
        app: tauri::AppHandle,
    ) -> Result<Option<BackupLocation>, CommandError> {
        #[cfg(target_os = "macos")]
        {
            use tauri_plugin_dialog::DialogExt;
            let selected = app.dialog().file().blocking_pick_folder();
            let Some(selected) = selected else {
                return Ok(None);
            };
            let path = selected.into_path().map_err(|error| CommandError {
                kind: "Invalid".into(),
                message: error.to_string(),
            })?;
            Ok(Some(BackupLocation::Path {
                label: crate::backup::label_for(&path),
                path,
            }))
        }
        #[cfg(target_os = "android")]
        {
            Ok(crate::backup::android::pick(&app)
                .await
                .map_err(|message| CommandError {
                    kind: "Storage".into(),
                    message,
                })?
                .map(|(uri, label)| BackupLocation::Document { uri, label }))
        }
        #[cfg(not(any(target_os = "macos", target_os = "android")))]
        {
            let _ = app;
            Err(CommandError {
                kind: "Invalid".into(),
                message: "not available".into(),
            })
        }
    }
    #[tauri::command]
    pub fn restore_list(
        startup: tauri::State<'_, Startup>,
        location: BackupLocation,
    ) -> Result<Vec<BackupListing>, CommandError> {
        super::restore_list(startup.state()?, &location)
    }
    #[tauri::command]
    pub async fn restore_open(
        startup: tauri::State<'_, Startup>,
        location: BackupLocation,
        listing: BackupListing,
        password: SecretString,
        kit: SecretString,
    ) -> Result<String, CommandError> {
        super::restore_open(startup.state()?, &location, &listing, password, kit).await
    }
    #[tauri::command]
    pub async fn restore_unlock(
        startup: tauri::State<'_, Startup>,
        handle: String,
        password: SecretString,
    ) -> Result<usize, CommandError> {
        super::restore_unlock(startup.state()?, &handle, password).await
    }
    #[tauri::command]
    pub async fn restore_points(
        startup: tauri::State<'_, Startup>,
        handle: String,
    ) -> Result<Vec<i64>, CommandError> {
        super::restore_points(startup.state()?, &handle).await
    }
    #[tauri::command]
    pub async fn restore_bases(
        startup: tauri::State<'_, Startup>,
        handle: String,
        at: i64,
    ) -> Result<Vec<BackupBase>, CommandError> {
        super::restore_bases(startup.state()?, &handle, at).await
    }
    #[tauri::command]
    pub async fn restore_check(
        startup: tauri::State<'_, Startup>,
        handle: String,
        at: i64,
    ) -> Result<CheckReport, CommandError> {
        super::restore_check(startup.state()?, &handle, at).await
    }
    #[tauri::command]
    pub async fn restore_into(
        startup: tauri::State<'_, Startup>,
        handle: String,
        account: AccountId,
        at: i64,
        bases: Vec<BaseId>,
        label: String,
    ) -> Result<RestoreSummary, CommandError> {
        super::restore_into(startup.state()?, &handle, account, at, &bases, &label).await
    }
    #[tauri::command]
    pub async fn restore_sign_up(
        startup: tauri::State<'_, Startup>,
        handle: String,
        form: SignUpForm,
        at: i64,
        label: String,
    ) -> Result<RestoredSignUp, CommandError> {
        super::restore_sign_up(startup.state()?, &handle, form, at, &label).await
    }
    #[tauri::command]
    pub fn restore_close(
        startup: tauri::State<'_, Startup>,
        handle: String,
    ) -> Result<(), CommandError> {
        super::restore_close(startup.state()?, &handle)
    }
}
