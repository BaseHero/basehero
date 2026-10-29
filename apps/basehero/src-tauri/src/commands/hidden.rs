use crate::error::CommandError;
use crate::state::AppState;
use crate::views::{AppEvent, BaseRef};
use bh_core::{AccountId, BaseId, BaseSummary, PasswordStrength};
use zeroize::Zeroizing;

pub async fn create_hidden_base(
    state: &AppState,
    account: AccountId,
    name: &str,
    password: Zeroizing<String>,
) -> Result<BaseSummary, CommandError> {
    let base = state
        .core
        .account(account)?
        .create_hidden_base(name, password)
        .await?;
    state.base(&BaseRef {
        account,
        base: base.id(),
    })?;
    crate::state::sync_hidden_recents(&state.core);
    Ok(BaseSummary {
        id: base.id(),
        name: base.name(),
        mode: base.mode(),
        hidden: true,
        mount: None,
    })
}

pub async fn unlock_hidden(
    state: &AppState,
    account: AccountId,
    password: Zeroizing<String>,
) -> Result<Vec<BaseSummary>, CommandError> {
    let bases = state.core.account(account)?.unlock_hidden(password).await?;
    crate::state::sync_hidden_recents(&state.core);
    Ok(bases)
}

pub async fn lock_hidden(
    state: &AppState,
    account: AccountId,
    base: BaseId,
) -> Result<(), CommandError> {
    state.core.account(account)?.lock_hidden(base).await?;
    state.reconcile_bases(account)?;
    crate::state::sync_hidden_recents(&state.core);
    Ok(())
}

pub async fn lock_all_hidden(state: &AppState) {
    futures_util::future::join_all(state.core.accounts().into_iter().map(|account| async move {
        if let Ok(handle) = state.core.account(account.id) {
            handle.lock_all_hidden().await;
            let _ = state.reconcile_bases(account.id);
        }
    }))
    .await;
    crate::state::sync_hidden_recents(&state.core);
}

pub fn password_strength(password: &str, context: &[String]) -> PasswordStrength {
    let words: Vec<&str> = context.iter().map(String::as_str).collect();
    bh_core::password_strength(password, &words)
}

pub async fn refresh_account(state: &AppState, account: AccountId) -> Result<(), CommandError> {
    state.core.account(account)?.refresh().await?;
    (state.sink)(AppEvent::KitChanged { account });
    Ok(())
}

pub mod ipc {
    use super::*;
    use crate::state::Startup;

    #[tauri::command]
    pub async fn create_hidden_base(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        name: String,
        password: String,
    ) -> Result<BaseSummary, CommandError> {
        super::create_hidden_base(startup.state()?, account, &name, Zeroizing::new(password)).await
    }

    #[tauri::command]
    pub async fn unlock_hidden(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        password: String,
    ) -> Result<Vec<BaseSummary>, CommandError> {
        super::unlock_hidden(startup.state()?, account, Zeroizing::new(password)).await
    }

    #[tauri::command]
    pub async fn lock_hidden(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
        base: BaseId,
    ) -> Result<(), CommandError> {
        super::lock_hidden(startup.state()?, account, base).await
    }

    #[tauri::command]
    pub async fn lock_all_hidden(startup: tauri::State<'_, Startup>) -> Result<(), CommandError> {
        super::lock_all_hidden(startup.state()?).await;
        Ok(())
    }

    #[tauri::command]
    pub fn password_strength(password: String, context: Vec<String>) -> PasswordStrength {
        super::password_strength(&Zeroizing::new(password), &context)
    }

    #[tauri::command]
    pub async fn refresh_account(
        startup: tauri::State<'_, Startup>,
        account: AccountId,
    ) -> Result<(), CommandError> {
        super::refresh_account(startup.state()?, account).await
    }
}
