use crate::error::CommandError;
use crate::state::{ActiveApproval, AppState};
use bh_core::{
    AccountId, AccountSummary, AppChoice, AppOffer, ApprovalId, ApprovalRequest, BaseGrantRequest,
    BaseId, DeviceId, Digits, Mode, ObjectId,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::Ordering};

struct Starting<'a> {
    state: &'a AppState,
    pending: &'a str,
}
impl Drop for Starting<'_> {
    fn drop(&mut self) {
        self.state
            .starting_approvals
            .lock()
            .unwrap()
            .remove(self.pending);
    }
}

fn not_found() -> CommandError {
    CommandError {
        kind: "NotFound".into(),
        message: "Not found".into(),
    }
}
fn current(state: &AppState, pending: &str) -> Result<Arc<ActiveApproval>, CommandError> {
    state
        .approvals
        .lock()
        .unwrap()
        .get(pending)
        .cloned()
        .ok_or_else(not_found)
}
fn summary(state: &AppState, account: AccountId) -> Result<AccountSummary, CommandError> {
    state
        .core
        .accounts()
        .into_iter()
        .find(|a| a.id == account)
        .ok_or_else(not_found)
}
async fn installed(
    state: &AppState,
    account: bh_core::Account,
) -> Result<AccountSummary, CommandError> {
    state.listen(account.id())?;
    if account.bases().is_empty() {
        let _ = account.create_base("Personal").await;
    }
    summary(state, account.id())
}

pub async fn approval_start(state: &AppState, pending: &str) -> Result<ApprovalId, CommandError> {
    let existing = { state.approvals.lock().unwrap().get(pending).cloned() };
    if let Some(entry) = existing {
        return Ok(entry.handle.lock().await.id());
    }
    let sign_in = {
        let active = state.active_pending.lock().unwrap();
        if !active.contains(pending) {
            return Err(not_found());
        }
        let mut starting = state.starting_approvals.lock().unwrap();
        if !starting.insert(pending.to_owned()) {
            return Err(CommandError {
                kind: "Invalid".into(),
                message: "Sign-in is in use".into(),
            });
        }
        state
            .pending
            .lock()
            .unwrap()
            .get(pending)
            .cloned()
            .ok_or_else(not_found)?
    };
    let _starting = Starting { state, pending };
    let result = sign_in.request_approval().await;
    if result.is_err() && !state.active_pending.lock().unwrap().contains(pending) {
        return Err(not_found());
    }
    let approval = result?;
    let id = approval.id();
    let expired = {
        let active = state.active_pending.lock().unwrap();
        if active.contains(pending) {
            state
                .approvals
                .lock()
                .unwrap()
                .insert(pending.to_owned(), Arc::new(ActiveApproval::new(approval)));
            state.pending.lock().unwrap().remove(pending);
            None
        } else {
            Some(approval)
        }
    };
    if let Some(mut approval) = expired {
        let _ = approval.cancel().await;
        return Err(not_found());
    }
    Ok(id)
}

pub async fn approval_digits(state: &AppState, pending: &str) -> Result<String, CommandError> {
    let entry = current(state, pending)?;
    let mut approval = entry.handle.lock().await;
    if entry.interrupted.load(Ordering::Acquire) {
        return Err(not_found());
    }
    tokio::select! {
        biased;
        _ = entry.interrupt.notified() => Err(not_found()),
        result = approval.digits() => Ok(result?.to_string()),
    }
}

pub async fn approval_wait(
    state: &AppState,
    pending: &str,
) -> Result<AccountSummary, CommandError> {
    let entry = current(state, pending)?;
    let mut approval = entry.handle.lock().await;
    if entry.interrupted.load(Ordering::Acquire) {
        return Err(not_found());
    }
    let account = tokio::select! {
        biased;
        _ = entry.interrupt.notified() => return Err(not_found()),
        result = approval.wait() => result?,
    };
    drop(approval);
    state.active_pending.lock().unwrap().remove(pending);
    installed(state, account).await
}

pub async fn approval_cancel(state: &AppState, pending: &str) -> Result<(), CommandError> {
    let entry = state.approvals.lock().unwrap().remove(pending);
    if let Some(entry) = entry {
        entry.stop();
        entry.handle.lock().await.cancel().await?;
    }
    Ok(())
}

pub async fn approval_use_kit(
    state: &AppState,
    pending: &str,
    kit: &str,
) -> Result<AccountSummary, CommandError> {
    // Before the request has posted, the pending sign-in still owns the kit path.
    // Mark it cancelled under the same lock used to install a posted approval.
    let pending_sign_in = {
        let mut active = state.active_pending.lock().unwrap();
        let entry = state.approvals.lock().unwrap().get(pending).cloned();
        if entry.is_some() {
            None
        } else {
            let sign_in = state
                .pending
                .lock()
                .unwrap()
                .get(pending)
                .cloned()
                .ok_or_else(not_found)?;
            active.remove(pending);
            Some(sign_in)
        }
    };
    if let Some(sign_in) = pending_sign_in {
        let account = sign_in.with_kit(kit).await?;
        state.pending.lock().unwrap().remove(pending);
        return installed(state, account).await;
    }
    let entry = current(state, pending)?;
    entry.stop();
    let mut approval = entry.handle.lock().await;
    let account = approval.use_kit(kit).await?;
    drop(approval);
    state.active_pending.lock().unwrap().remove(pending);
    installed(state, account).await
}

pub async fn approval_requests(
    state: &AppState,
    account: AccountId,
) -> Result<Vec<ApprovalRequest>, CommandError> {
    Ok(state.core.account(account)?.approval_requests().await?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedRequest {
    pub id: ApprovalId,
}

pub async fn approval_open(
    state: &AppState,
    account: AccountId,
    id: ApprovalId,
) -> Result<OpenedRequest, CommandError> {
    // Opening answers the relay; listing and events must never do that.
    let request = state.core.account(account)?.open_request(id).await?;
    state
        .open_requests
        .lock()
        .unwrap()
        .insert((account, id), request);
    Ok(OpenedRequest { id })
}

pub async fn approval_approve(
    state: &AppState,
    account: AccountId,
    id: ApprovalId,
    digits: &str,
) -> Result<DeviceId, CommandError> {
    let digits = Digits::parse(digits)?; // Malformed input must leave the request open.
    let request = state
        .open_requests
        .lock()
        .unwrap()
        .remove(&(account, id))
        .ok_or_else(not_found)?;
    Ok(state
        .core
        .account(account)?
        .approve(request, &digits)
        .await?)
}

pub async fn approval_decline(
    state: &AppState,
    account: AccountId,
    id: ApprovalId,
) -> Result<(), CommandError> {
    let request = state.open_requests.lock().unwrap().remove(&(account, id));
    let app_request = state
        .open_app_requests
        .lock()
        .unwrap()
        .remove(&(account, id));
    let result = state.core.account(account)?.decline(id).await;
    drop((request, app_request)); // Drop after decline to avoid racing best-effort cancellation.
    Ok(result?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseChoiceInput {
    pub base: Option<BaseId>,
    pub folder: Option<ObjectId>,
    pub new_name: Option<String>,
    pub mode: Mode,
}

impl BaseChoiceInput {
    pub fn into_grant(self) -> Result<BaseGrantRequest, bh_core::Error> {
        match (self.base, self.folder, self.new_name) {
            (Some(base), None, None) => Ok(BaseGrantRequest::Existing {
                base,
                mode: self.mode,
            }),
            (Some(base), Some(folder), None) => Ok(BaseGrantRequest::Folder {
                base,
                folder,
                mode: self.mode,
            }),
            (None, None, Some(name)) => Ok(BaseGrantRequest::New {
                name,
                mode: self.mode,
            }),
            _ => Err(bh_core::Error::Invalid(
                "Choose a base, a folder or a new base".into(),
            )),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppChoiceInput {
    pub bases: Vec<BaseChoiceInput>,
    pub cap_micro_usd: u64,
    pub replaces: Option<DeviceId>,
}

pub async fn connect_open(
    state: &AppState,
    account: AccountId,
    id: ApprovalId,
) -> Result<OpenedRequest, CommandError> {
    let request = state.core.account(account)?.open_app_request(id).await?;
    state
        .open_app_requests
        .lock()
        .unwrap()
        .insert((account, id), request);
    Ok(OpenedRequest { id })
}

pub async fn connect_check(
    state: &AppState,
    account: AccountId,
    id: ApprovalId,
    digits: &str,
) -> Result<AppOffer, CommandError> {
    let digits = Digits::parse(digits)?;
    let mut request = state
        .open_app_requests
        .lock()
        .unwrap()
        .remove(&(account, id))
        .ok_or_else(not_found)?;
    let result = request.check_digits(&digits).await;
    if result.is_ok() {
        state
            .open_app_requests
            .lock()
            .unwrap()
            .insert((account, id), request);
    }
    Ok(result?)
}

pub async fn connect_approve(
    state: &AppState,
    account: AccountId,
    id: ApprovalId,
    choice: AppChoiceInput,
) -> Result<(DeviceId, bool), CommandError> {
    let bases = choice
        .bases
        .into_iter()
        .map(BaseChoiceInput::into_grant)
        .collect::<Result<Vec<_>, _>>()?;
    let request = state
        .open_app_requests
        .lock()
        .unwrap()
        .remove(&(account, id))
        .ok_or_else(not_found)?;
    Ok(state
        .core
        .account(account)?
        .approve_app(
            request,
            AppChoice {
                bases,
                cap_micro_usd: choice.cap_micro_usd,
                replaces: choice.replaces,
            },
        )
        .await?)
}

pub mod ipc {
    use super::*;
    use crate::state::Startup;
    use tauri::State;
    #[tauri::command]
    pub async fn approval_start(
        state: State<'_, Startup>,
        pending: String,
    ) -> Result<ApprovalId, CommandError> {
        super::approval_start(state.state()?, &pending).await
    }
    #[tauri::command]
    pub async fn approval_digits(
        state: State<'_, Startup>,
        pending: String,
    ) -> Result<String, CommandError> {
        super::approval_digits(state.state()?, &pending).await
    }
    #[tauri::command]
    pub async fn approval_wait(
        state: State<'_, Startup>,
        pending: String,
    ) -> Result<AccountSummary, CommandError> {
        super::approval_wait(state.state()?, &pending).await
    }
    #[tauri::command]
    pub async fn approval_cancel(
        state: State<'_, Startup>,
        pending: String,
    ) -> Result<(), CommandError> {
        super::approval_cancel(state.state()?, &pending).await
    }
    #[tauri::command]
    pub async fn approval_use_kit(
        state: State<'_, Startup>,
        pending: String,
        kit: String,
    ) -> Result<AccountSummary, CommandError> {
        let kit = crate::views::SecretString::from(kit);
        super::approval_use_kit(state.state()?, &pending, &kit).await
    }
    #[tauri::command]
    pub async fn approval_requests(
        state: State<'_, Startup>,
        account: AccountId,
    ) -> Result<Vec<ApprovalRequest>, CommandError> {
        super::approval_requests(state.state()?, account).await
    }
    #[tauri::command]
    pub async fn approval_open(
        state: State<'_, Startup>,
        account: AccountId,
        id: ApprovalId,
    ) -> Result<OpenedRequest, CommandError> {
        super::approval_open(state.state()?, account, id).await
    }
    #[tauri::command]
    pub async fn approval_approve(
        state: State<'_, Startup>,
        account: AccountId,
        id: ApprovalId,
        digits: String,
    ) -> Result<DeviceId, CommandError> {
        let digits = crate::views::SecretString::from(digits);
        super::approval_approve(state.state()?, account, id, &digits).await
    }
    #[tauri::command]
    pub async fn approval_decline(
        state: State<'_, Startup>,
        account: AccountId,
        id: ApprovalId,
    ) -> Result<(), CommandError> {
        super::approval_decline(state.state()?, account, id).await
    }
    #[tauri::command]
    pub async fn connect_open(
        state: State<'_, Startup>,
        account: AccountId,
        id: ApprovalId,
    ) -> Result<OpenedRequest, CommandError> {
        super::connect_open(state.state()?, account, id).await
    }
    #[tauri::command]
    pub async fn connect_check(
        state: State<'_, Startup>,
        account: AccountId,
        id: ApprovalId,
        digits: String,
    ) -> Result<AppOffer, CommandError> {
        let digits = crate::views::SecretString::from(digits);
        super::connect_check(state.state()?, account, id, &digits).await
    }
    #[tauri::command]
    pub async fn connect_approve(
        state: State<'_, Startup>,
        account: AccountId,
        id: ApprovalId,
        choice: AppChoiceInput,
    ) -> Result<(DeviceId, bool), CommandError> {
        super::connect_approve(state.state()?, account, id, choice).await
    }
}
