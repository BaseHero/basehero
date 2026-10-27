use crate::error::CommandError;
use crate::state::AppState;
use bh_core::AccountSummary;

pub fn accounts(state: &AppState) -> Result<Vec<AccountSummary>, CommandError> {
    Ok(state.core.accounts())
}
