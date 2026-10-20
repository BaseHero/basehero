//! The short owner boundary sync work is decided under. A sync client takes
//! a `SyncFence` before its awaits (signing, authorization, opening a
//! connection, reading); immediately before its synchronous step (persisting
//! a sealed package, enqueueing a request, recording an Ack, committing an
//! incoming batch) it runs that step inside `with_sync_fence`, which checks,
//! under the container session and writer guards, that what it was decided
//! under still holds. Nothing awaits inside it.
//!
//! The capability check is ordered against account lock and history: the
//! account owner advances its generation under the same writer guard
//! (`AccountJournal::fence`, `commit_verified_fenced`). Ordinary content
//! history moving on does not invalidate a fence: an older observation stays
//! a truthful one. A control, a copied account change, a new epoch, a stop or
//! another hosting root does.
use crate::{ContainerId, Owner, OwnerError};
use bh_account::owner::AccountCapability;
use bh_storage::DeviceDatabase;
use bh_sync::permit::{LogId, LogKind};
use std::sync::Arc;

/// What sync work was decided under. Opaque; never leaves native code.
pub struct SyncFence {
    container: ContainerId,
    base: [u8; 32],
    capability: Arc<AccountCapability>,
    root: [u8; 32],
    control: [u8; 32],
    account: Option<(u64, [u8; 32])>,
    epoch: Option<[u8; 32]>,
}

impl std::fmt::Debug for SyncFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncFence(..)")
    }
}

/// How much a fenced step rechecks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recheck {
    /// The capability and the base's control, account copy, epoch and root.
    Everything,
    /// Only the capability: an incoming batch moves the rest itself.
    Authority,
}

impl Owner {
    /// The current authority for `log`, this container's own base, and the
    /// base's control, account copy, epoch and hosting root as verified
    /// history has applied them. `Unbound` without current authority for it.
    pub fn sync_fence(&self, id: ContainerId, log: LogId) -> Result<SyncFence, OwnerError> {
        if log.kind != LogKind::Base {
            return Err(OwnerError::InvalidBatch);
        }
        let session = self.account_session(id)?;
        let guard = session.lock().expect("container session lock");
        let (base, capability) = guard.authority().current().ok_or(OwnerError::Unbound)?;
        if base != log.id {
            return Err(OwnerError::Unbound);
        }
        let database = guard.shared_database();
        let db = database.lock().expect("container writer lock");
        if !capability.is_current() {
            return Err(OwnerError::Unbound);
        }
        let progress = db
            .log_progress(LogKind::Base as u8, base)?
            .ok_or(OwnerError::NotRegistered)?;
        if progress.stopped.is_some() {
            return Err(OwnerError::Stopped);
        }
        Ok(SyncFence {
            container: id,
            base,
            capability,
            root: progress.hosting_root,
            control: progress.control_digest,
            account: progress.account,
            epoch: progress.epoch_id,
        })
    }

    /// Run `step` only while everything `fence` captured still holds, under
    /// the container session and writer guards: `Unbound` once its authority
    /// ended, `Stopped` once the base stopped, `Changed` after a control,
    /// account copy, epoch or root change. `step` must not wait: no await,
    /// no signer call, only a synchronous store call or nonblocking enqueue.
    pub fn with_sync_fence<T>(
        &self,
        fence: &SyncFence,
        step: impl FnOnce(&mut DeviceDatabase) -> Result<T, OwnerError>,
    ) -> Result<T, OwnerError> {
        self.fenced(fence, Recheck::Everything, step)
    }

    pub(crate) fn fenced<T>(
        &self,
        fence: &SyncFence,
        recheck: Recheck,
        step: impl FnOnce(&mut DeviceDatabase) -> Result<T, OwnerError>,
    ) -> Result<T, OwnerError> {
        let session = self.account_session(fence.container)?;
        let guard = session.lock().expect("container session lock");
        let current = guard.authority().current();
        if !current.is_some_and(|(base, capability)| {
            base == fence.base && Arc::ptr_eq(&capability, &fence.capability)
        }) {
            return Err(OwnerError::Unbound);
        }
        let database = guard.shared_database();
        let mut db = database.lock().expect("container writer lock");
        if !fence.capability.is_current() {
            return Err(OwnerError::Unbound);
        }
        if recheck == Recheck::Everything {
            let progress = db
                .log_progress(LogKind::Base as u8, fence.base)?
                .ok_or(OwnerError::NotRegistered)?;
            if progress.stopped.is_some() {
                return Err(OwnerError::Stopped);
            }
            if progress.hosting_root != fence.root
                || progress.control_digest != fence.control
                || progress.account != fence.account
                || progress.epoch_id != fence.epoch
            {
                return Err(OwnerError::Changed);
            }
        }
        step(&mut db)
    }
}
