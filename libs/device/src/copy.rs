//! The base copy of an account change. A device's base history follows the
//! account only through account events copied into the base log as
//! controls, so a paired device can write to a base once its addition is
//! copied there, and a removal closes the base's content epoch once copied.
use crate::{ContainerId, Owner, OwnerError};
use bh_account::{Head as AccountHead, VerifiedAccount};
use bh_crypto::Secret;
use bh_event::{ControlSigningRequest, Seen, key_id, prepare_account_change};
use bh_sync::{BaseId, Digest, Head, permit::LogKind};

impl Owner {
    /// Prepare the control that copies `account_event` into this container's
    /// own base, for this device's control key to sign through the account
    /// owner's confirmation. `anchor` is the account at the head the base
    /// genesis names and `metadata` the base's M. The copy claims the base's
    /// verified head, its receipt and last control, and the base's copy of
    /// the account; only the account event after that copy's head is copied.
    pub fn prepare_account_change_copy(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        metadata: &Secret<32>,
        account_event: &[u8],
    ) -> Result<ControlSigningRequest, OwnerError> {
        let (base, capability) = self
            .account_session(id)?
            .lock()
            .expect("container session lock")
            .authority()
            .current()
            .ok_or(OwnerError::Unbound)?;
        if anchor.id() != capability.account_id() {
            return Err(OwnerError::AnchorMismatch);
        }
        let database = self.shared_database(id)?;
        let (progress, changes) = {
            let db = database.lock().expect("container writer lock");
            let kind = LogKind::Base as u8;
            let progress = db
                .log_progress(kind, base)?
                .ok_or(OwnerError::NotRegistered)?;
            (progress, db.log_account_changes(kind, base)?)
        };
        if progress.stopped.is_some() {
            return Err(OwnerError::Stopped);
        }
        // Before its genesis is verified a base has no head to claim.
        let (Some(receipt), Some((position, hash)), Some(metadata_id)) =
            (progress.receipt, progress.account, progress.metadata_id)
        else {
            return Err(OwnerError::NotRegistered);
        };
        if metadata_id != key_id(metadata) {
            return Err(OwnerError::Unavailable);
        }
        let mut account = anchor.clone();
        for change in &changes {
            account.apply(change).map_err(|_| OwnerError::Unavailable)?;
        }
        if account.head() != (AccountHead { position, hash }) {
            return Err(OwnerError::Unavailable);
        }
        let seen = Seen {
            head: Head {
                position: progress.position,
                hash: Digest(progress.head_hash),
            },
            control: progress.control_digest,
            account: account.head(),
        };
        prepare_account_change(
            BaseId(base),
            &account,
            capability.device_id(),
            metadata,
            seen,
            receipt,
            account_event,
        )
        .map_err(|_| OwnerError::CopyRefused)
    }
}
