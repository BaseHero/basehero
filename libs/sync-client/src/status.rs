//! What the person sees about this container's note sync, derived in one
//! place from the store and the client's last pass: receiving, copying and
//! publishing. `pending` counts notes with local updates not yet accepted, whether or
//! not the hosted log acknowledged them. Completing a first device's setup
//! at its account home is shown on its own watch (`HomeStatus`), not here.
use crate::puller::Held;
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
    /// Notes with work the hosted log ordered but did not accept (refused,
    /// rejected or conflicted). It stays on this device.
    NotAccepted {
        notes: u64,
    },
    /// The base log holds other bytes under the id of this device's kept
    /// copy of an account change, or holds the copy without its effect.
    /// The copy stays kept and is neither sent nor signed again.
    ControlNotAccepted,
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
pub(crate) fn derive(owner: &Owner, container: ContainerId, inputs: Inputs) -> Option<SyncStatus> {
    let database = owner.shared_database(container).ok()?;
    let (progress, summary, publishing_stopped, held_notes) = {
        let db = database.lock().expect("container writer lock");
        let progress = db
            .own_base()
            .ok()
            .flatten()
            .and_then(|record| db.log_progress(LogKind::Base as u8, record.base).ok())
            .flatten();
        (
            progress,
            db.outbox_summary().ok()?,
            db.publishing_stopped().ok()?,
            db.has_held_notes().ok()?,
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
    let pending = summary.unaccepted_notes;
    let not_accepted = summary.not_accepted_notes + inputs.alarms;
    if not_accepted > 0 {
        return Some(SyncStatus::NotAccepted {
            notes: not_accepted,
        });
    }
    if inputs.control_not_accepted {
        return Some(SyncStatus::ControlNotAccepted);
    }
    if inputs.held == Held::Missing {
        return Some(SyncStatus::HistoryMissing);
    }
    let caught_up = progress.is_some_and(|p| inputs.tail_known && p.position >= inputs.latest);
    let synced = pending == 0 && !inputs.unsettled && caught_up && !held_notes;
    Some(match inputs.condition {
        Condition::Authorization => SyncStatus::WaitingAuthorization,
        Condition::Network => SyncStatus::WaitingNetwork,
        Condition::Starting | Condition::Held => SyncStatus::SavedLocal { pending },
        _ if synced => SyncStatus::Synced,
        Condition::Working => SyncStatus::Syncing { pending },
        Condition::Unsupported => SyncStatus::Unsupported,
        Condition::Stopped => SyncStatus::Stopped,
    })
}
