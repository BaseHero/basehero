//! What the person sees about this container's note sync, derived in one
//! place from the store and the client's last pass: receiving, copying and
//! publishing. `pending` counts notes with local updates not yet accepted, whether or
//! not the hosted log acknowledged them. Completing a first device's setup
//! at its account home is shown on its own watch (`HomeStatus`), not here.
use crate::puller::Held;
use bh_account::VerifiedAccount;
use bh_device::{ContainerId, Owner};
use bh_sync::permit::LogKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    /// Saved on this device; not being published (not yet connected, or the
    /// work cannot be sealed as it stands).
    SavedLocal {
        pending: u64,
    },
    Syncing {
        pending: u64,
    },
    /// Every local update is accepted from its verified echo, no account
    /// change waits to be copied, and verified progress has reached every
    /// head known to exist.
    Synced,
    /// Synced, but this base holds content only a newer build can apply (an
    /// unknown content kind, or a Note declaration this build cannot read).
    /// Nothing is paused; the person is told to update.
    UpdateNeeded,
    WaitingNetwork,
    /// Connected, but current authority does not permit the work now: the
    /// service refuses or cannot check it, the base's epoch is closed, or a
    /// control waits for the person's approval.
    WaitingAuthorization,
    /// The log's next event cannot be judged yet (a body, key or local
    /// configuration is missing). Everything verified before it is kept.
    HistoryMissing,
    Unsupported,
    /// The base log, or this device's account, is stopped by a proven
    /// contradiction.
    Stopped,
    /// This device's own key signed other bytes under one of its event ids
    /// (a clone or a local fault): it publishes nothing until resolved.
    PublishingStopped,
    /// Notes or typed items with work the hosted log ordered but did not
    /// accept (refused, rejected or conflicted). It stays on this device.
    NotAccepted {
        notes: u64,
    },
    /// The base log holds other bytes under the id of this device's kept
    /// copy of an account change, or holds the copy without its effect.
    /// The copy stays kept and is neither sent nor signed again.
    ControlNotAccepted,
    /// A removal took effect and the own base's protection is being
    /// renewed: the personal key's rotation is due, or this device accepted
    /// one the base's epoch does not reflect yet (its copy is behind the
    /// rotation, or its new epoch's key is still being delivered), or the
    /// base's epoch is closed until its rekey while the account is still past
    /// its copy.
    Protecting,
}

/// Why the last pass did not finish its work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Condition {
    /// No pass has reached the service yet.
    Starting,
    Working,
    /// Some work cannot be sealed as it stands.
    Held,
    Network,
    Authorization,
    /// The endpoint's policy cannot be used by this build.
    Unsupported,
    /// The account owner stopped on history contradicting its own.
    Stopped,
}

/// The client's state the status is derived from.
pub(crate) struct Inputs {
    pub condition: Condition,
    /// Notes the client holds for a refusal an honest device never causes;
    /// they show as not accepted too.
    pub alarms: u64,
    pub held: Held,
    pub tail_known: bool,
    pub latest: u64,
    /// An account change the base lacks, or a kept copy not yet settled.
    pub unsettled: bool,
    /// The kept copy's id holds other bytes, or the copy without effect.
    pub control_not_accepted: bool,
}

/// `None` when local state cannot be read; the status then stays as it was.
/// `account` is the account at its current verified head, if readable.
pub(crate) fn derive(
    owner: &Owner,
    container: ContainerId,
    account: Option<&VerifiedAccount>,
    inputs: Inputs,
) -> Option<SyncStatus> {
    let database = owner.shared_database(container).ok()?;
    let (progress, summary, publishing_stopped, held_notes, newer_build, sealing, rotated) = {
        let db = database.lock().expect("container writer lock");
        let own = db.own_base().ok().flatten();
        let progress = own
            .as_ref()
            .and_then(|record| db.log_progress(LogKind::Base as u8, record.base).ok())
            .flatten();
        let newer_build = match own.as_ref() {
            Some(record) => db.needs_newer_build(record.base).ok()?,
            None => false,
        };
        let sealing = match own.as_ref() {
            Some(record) => db
                .seal_waits()
                .ok()?
                .iter()
                .any(|wait| wait.base == record.base),
            None => false,
        };
        // The accepted rotation's position, from its one row: never the
        // whole keyring on a status recompute.
        let rotated = db
            .personal_delivery()
            .ok()
            .flatten()
            .map(|(position, _)| position);
        (
            progress,
            db.outbox_summary().ok()?,
            db.publishing_stopped().ok()?,
            db.has_held_notes().ok()?,
            newer_build,
            sealing,
            rotated,
        )
    };
    if progress.is_some_and(|p| p.stopped.is_some()) || inputs.condition == Condition::Stopped {
        return Some(SyncStatus::Stopped);
    }
    if publishing_stopped {
        return Some(SyncStatus::PublishingStopped);
    }
    if inputs.condition == Condition::Unsupported || inputs.held == Held::Unsupported {
        return Some(SyncStatus::Unsupported);
    }
    // Typed work counts like note work: a base is never Synced with unsent or
    // unaccepted typed mutations.
    let pending = summary.unaccepted_notes + summary.unaccepted_typed;
    let not_accepted = summary.not_accepted_notes + summary.not_accepted_typed + inputs.alarms;
    if not_accepted > 0 {
        return Some(SyncStatus::NotAccepted {
            notes: not_accepted,
        });
    }
    if inputs.control_not_accepted {
        return Some(SyncStatus::ControlNotAccepted);
    }
    // A rotation due, or one accepted that the base's copy of the account
    // has not reached, or the own base's epoch closed until its rekey's key
    // installs: the copier may rekey before this device accepts the
    // rotation it follows. Or a new epoch whose key is still being
    // delivered.
    let copied = progress
        .and_then(|p| p.account)
        .map_or(0, |(position, _)| position);
    let closed = closed_epoch_renews(
        progress.is_some_and(|p| p.account.is_some()),
        progress.is_some_and(|p| p.epoch_id.is_some()),
        account.is_some_and(|account| account.head().position > copied),
    );
    let protecting = account.is_some_and(|account| account.rotation_due(0).is_some())
        || rotated.is_some_and(|position| copied < position)
        || closed
        || sealing;
    if protecting && !matches!(inputs.condition, Condition::Network | Condition::Starting) {
        return Some(SyncStatus::Protecting);
    }
    if inputs.held == Held::Missing {
        return Some(SyncStatus::HistoryMissing);
    }
    let caught_up = progress.is_some_and(|p| inputs.tail_known && p.position >= inputs.latest);
    let synced = pending == 0 && !inputs.unsettled && caught_up && !held_notes;
    Some(settled(inputs.condition, pending, synced, newer_build))
}

/// A closed epoch shows a renewal in progress only while the account is past
/// the base's copy: a rotation this device accepted is not copied yet, or its
/// rekey's key is still being delivered. A legacy untimed self-removal closes
/// the epoch with no rotation due and nothing further to copy, so it is not a
/// renewal and must not claim that protection will return.
fn closed_epoch_renews(account_copied: bool, epoch_open: bool, account_behind: bool) -> bool {
    account_copied && !epoch_open && account_behind
}

/// The quiet status, once nothing higher-priority applies. A newer build is
/// needed only where `Synced` would otherwise be shown: every state that
/// already has something to say keeps saying it.
fn settled(condition: Condition, pending: u64, synced: bool, newer_build: bool) -> SyncStatus {
    match condition {
        Condition::Authorization => SyncStatus::WaitingAuthorization,
        Condition::Network => SyncStatus::WaitingNetwork,
        Condition::Starting | Condition::Held => SyncStatus::SavedLocal { pending },
        _ if synced && newer_build => SyncStatus::UpdateNeeded,
        _ if synced => SyncStatus::Synced,
        Condition::Working => SyncStatus::Syncing { pending },
        Condition::Unsupported => SyncStatus::Unsupported,
        Condition::Stopped => SyncStatus::Stopped,
    }
}

#[cfg(test)]
mod tests {
    use super::{Condition, Inputs, SyncStatus, closed_epoch_renews, derive, settled};
    use crate::puller::Held;
    use bh_device::Owner;
    use bh_storage::EpochKeyRow;

    #[test]
    fn an_accepted_rotation_is_read_from_its_one_row_not_the_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Owner::default();
        let container = owner.create_container(dir.path()).unwrap();
        {
            let database = owner.shared_database(container).unwrap();
            let mut db = database.lock().unwrap();
            db.commit_account_verified([7; 32], &[b"genesis"], 1, [8; 32], false)
                .unwrap();
            // A keyring row no keyring read accepts: a status that read the
            // keyring would not see the rotation.
            let row = EpochKeyRow {
                base: [1; 32],
                epoch_id: [2; 32],
                purpose: 300,
                seal: vec![1],
            };
            db.install_epoch_keys(None, &[row], || true).unwrap();
            let snapshot = db.keyring_snapshot().unwrap().unwrap();
            db.accept_personal_delivery(&snapshot, 5, b"rotation", &snapshot.rows, || true)
                .unwrap();
        }
        let inputs = Inputs {
            condition: Condition::Working,
            alarms: 0,
            held: Held::No,
            tail_known: true,
            latest: 0,
            unsettled: false,
            control_not_accepted: false,
        };
        assert_eq!(
            derive(&owner, container, None, inputs),
            Some(SyncStatus::Protecting)
        );
    }

    #[test]
    fn a_closed_epoch_counts_only_while_the_rotation_is_still_to_come() {
        // The rekey round trip: the rotation is accepted here but the base's
        // copy of the account has not reached it yet.
        assert!(closed_epoch_renews(true, false, true));
        // A legacy untimed self-removal closes the epoch with no rotation due
        // and the base's copy already at the account's head.
        assert!(!closed_epoch_renews(true, false, false));
        // An open epoch, or no copied account at all, is never a renewal.
        assert!(!closed_epoch_renews(true, true, true));
        assert!(!closed_epoch_renews(false, false, true));
    }

    #[test]
    fn a_newer_build_is_needed_only_where_synced_would_show() {
        assert_eq!(
            settled(Condition::Working, 0, true, true),
            SyncStatus::UpdateNeeded
        );
        assert_eq!(
            settled(Condition::Working, 0, true, false),
            SyncStatus::Synced
        );
        // Work still to publish, an unreachable service or an approval each
        // keep their own line: none is hidden behind the update notice.
        assert_eq!(
            settled(Condition::Working, 2, false, true),
            SyncStatus::Syncing { pending: 2 }
        );
        assert_eq!(
            settled(Condition::Network, 0, true, true),
            SyncStatus::WaitingNetwork
        );
        assert_eq!(
            settled(Condition::Authorization, 0, true, true),
            SyncStatus::WaitingAuthorization
        );
        assert_eq!(
            settled(Condition::Starting, 0, false, true),
            SyncStatus::SavedLocal { pending: 0 }
        );
    }
}
