//! Protected local account projection over a verified, cut-qualified history index.
//!
//! Checkpoints are local DTOs, not remotely authenticated snapshots or proof
//! that the home disclosed its latest head. Before restore the storage adapter
//! must verify the account/source namespace, generation and cut, exact genesis
//! and tail originals, an independently pinned hosting root, and the separate
//! outer opening. The index handle must bind that namespace and generation;
//! lookup failures are `Error::Unavailable`, never absent history. Persist the
//! projection, originals, proof and index changes in one durable transaction
//! before rebasing; this module writes no service state and cannot authenticate
//! arbitrary checkpoint bytes on its own.

use std::sync::Arc;

pub use crate::history::indexed::{HistoryIndex, KeyUse, receiving_hash};
use crate::{AccountId, Error, Head, VerifiedAccount};
pub use bh_storage::account::{AccountDeviceRow, AccountProjectionDelta};

/// Current local authority and live obligations, not a wire checkpoint.
/// The summary uses the existing strict account-summary codec and version.
pub struct Checkpoint {
    pub account: AccountId,
    pub head: Head,
    pub summary: Vec<u8>,
    pub active: Vec<AccountDeviceRow>,
    pub stopped: bool,
}

/// Capture current authority without walking historical originals.
pub fn capture(account: &VerifiedAccount) -> Checkpoint {
    Checkpoint {
        account: account.id(),
        head: account.head(),
        summary: account.summary(),
        active: account.checkpoint_rows(),
        stopped: account.is_stopped(),
    }
}

/// Restore only after the adapter's trusted-local source and opening checks.
pub fn restore(
    checkpoint: Checkpoint,
    epoch: u64,
    index: Arc<dyn HistoryIndex>,
) -> Result<VerifiedAccount, Error> {
    VerifiedAccount::from_checkpoint(
        checkpoint.account,
        checkpoint.head,
        &checkpoint.summary,
        checkpoint.active,
        checkpoint.stopped,
        epoch,
        index,
    )
}

/// Incremental facts since the current indexed cut, including the current summary.
pub fn delta(account: &VerifiedAccount) -> AccountProjectionDelta {
    account.delta()
}

/// Rebase only after the adapter has durably committed this exact head and delta.
/// Refuses a mismatched committed position or hash without changing the input view.
pub fn rebase(
    account: VerifiedAccount,
    committed: Head,
    epoch: u64,
    index: Arc<dyn HistoryIndex>,
) -> Result<VerifiedAccount, Error> {
    if committed != account.head() {
        return Err(Error::WrongPredecessor);
    }
    Ok(account.rebase(epoch, index))
}
