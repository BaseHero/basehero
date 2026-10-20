//! This device's note packages. A package claims the base head this
//! device's verified history has applied, with its hosting receipt, the
//! base's last control and its copy of the account, and seals the pending
//! update as `note || writer declaration || update` under the content key.
use crate::{ContainerId, ORDINARY_AUDIENCE, Owner, OwnerError};
use bh_account::{Head as AccountHead, VerifiedAccount};
use bh_crypto::Secret;
use bh_event::{NoteDraft, NoteSigningRequest, Seen, key_id, prepare_note};
use bh_storage::PackageCandidate;
use bh_sync::{BaseId, Digest, Head, permit::LogKind, receipt};

/// Why a pending update cannot be sealed now. Its work stays pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealRefusal {
    /// The base's content epoch is closed: content waits for a new one.
    EpochClosed,
    /// The stored head's receipt does not verify under the pinned root for
    /// that head, so an event claiming it would be refused.
    SeenUnverified,
    /// The update has no writer declaration (old local work), which a
    /// published note event must carry.
    NoDeclaration,
}

impl Owner {
    /// Prepare the note event for `candidate`, a pending update of this
    /// container's own base, for this device's ordinary key to sign outside
    /// every lock. `anchor` is the account at the head the base genesis
    /// names; `hosting_root` comes from the base's authenticated hosting
    /// association and must be the root pinned at registration.
    pub fn prepare_note_seal(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        hosting_root: [u8; 32],
        metadata: &Secret<32>,
        content: &Secret<32>,
        candidate: &PackageCandidate,
    ) -> Result<NoteSigningRequest, OwnerError> {
        let (base, capability) = self
            .account_session(id)?
            .lock()
            .expect("container session lock")
            .authority()
            .current()
            .ok_or(OwnerError::Unbound)?;
        let key = candidate.pending.key;
        if key.base != base || key.audience != ORDINARY_AUDIENCE {
            return Err(OwnerError::Unbound);
        }
        if anchor.id() != capability.account_id() {
            return Err(OwnerError::AnchorMismatch);
        }
        let writer = crate::writers::pending_declaration(&candidate.pending)
            .map_err(|_| OwnerError::WriterUnavailable)?
            .ok_or(OwnerError::SealRefused(SealRefusal::NoDeclaration))?;
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
        if progress.hosting_root != hosting_root {
            return Err(OwnerError::Unavailable);
        }
        // Before its genesis is verified a base has no head to claim.
        let (Some(stored), Some((position, hash)), Some(metadata_id)) =
            (progress.receipt, progress.account, progress.metadata_id)
        else {
            return Err(OwnerError::NotRegistered);
        };
        let epoch = progress
            .epoch_id
            .ok_or(OwnerError::SealRefused(SealRefusal::EpochClosed))?;
        if metadata_id != key_id(metadata) || epoch != key_id(content) {
            return Err(OwnerError::Unavailable);
        }
        let head = Head {
            position: progress.position,
            hash: Digest(progress.head_hash),
        };
        if receipt::verify(&hosting_root, BaseId(base), &stored).map(|r| r.head()) != Ok(head) {
            return Err(OwnerError::SealRefused(SealRefusal::SeenUnverified));
        }
        let mut account = anchor.clone();
        for change in &changes {
            account.apply(change).map_err(|_| OwnerError::Unavailable)?;
        }
        if account.head() != (AccountHead { position, hash }) {
            return Err(OwnerError::Unavailable);
        }
        let seen = Seen {
            head,
            control: progress.control_digest,
            account: account.head(),
        };
        prepare_note(
            BaseId(base),
            &account,
            capability.device_id(),
            seen,
            stored,
            NoteDraft {
                event_id: candidate.event_id,
                note: key.note,
                writer,
                update: &candidate.pending.bytes,
            },
            metadata,
            content,
        )
        .map_err(|_| OwnerError::Unavailable)
    }
}
