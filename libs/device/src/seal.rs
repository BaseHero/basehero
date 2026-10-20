//! This device's content packages: note updates and typed payloads. A package
//! claims the base head this device's verified history has applied, with its
//! hosting receipt, the base's last control and its copy of the account, and
//! seals its exact payload under the content key. A note package carries
//! `note || writer declaration || update`; a typed package carries the
//! `bh-data` payload bytes unchanged, under the shared content kind.
use crate::{ContainerId, ORDINARY_AUDIENCE, Owner, OwnerError};
use bh_account::{Head as AccountHead, VerifiedAccount};
use bh_crypto::Secret;
use bh_event::{
    ContentSigningRequest, NoteDraft, Seen, TypedDraft, key_id, prepare_note, prepare_typed,
};
use bh_storage::{PackageCandidate, TypedPackageCandidate};
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
    /// This base's ordinary content key cannot seal another audience.
    AudienceUnsupported,
}

/// What a content seal claims about verified history, checked once against
/// this container's own base.
struct ContentContext {
    device: bh_account::DeviceId,
    seen: Seen,
    receipt: [u8; receipt::RECEIPT_LEN],
    account: VerifiedAccount,
}

impl Owner {
    /// The verified head, account copy and epoch a content event of `base`
    /// claims, for this device's ordinary key to sign outside every lock.
    /// `anchor` is the account at the head the base genesis names;
    /// `hosting_root` comes from the base's authenticated hosting association
    /// and must be the root pinned at registration.
    fn content_context(
        &self,
        id: ContainerId,
        base: [u8; 32],
        anchor: &VerifiedAccount,
        hosting_root: [u8; 32],
        metadata: &Secret<32>,
        content: &Secret<32>,
    ) -> Result<ContentContext, OwnerError> {
        let (base_now, capability) = self
            .account_session(id)?
            .lock()
            .expect("container session lock")
            .authority()
            .current()
            .ok_or(OwnerError::Unbound)?;
        if base != base_now {
            return Err(OwnerError::Unbound);
        }
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
        Ok(ContentContext {
            device: capability.device_id(),
            seen: Seen {
                head,
                control: progress.control_digest,
                account: account.head(),
            },
            receipt: stored,
            account,
        })
    }

    /// Prepare the note event for `candidate`, a pending update of this
    /// container's own base, for this device's ordinary key to sign outside
    /// every lock.
    pub fn prepare_note_seal(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        hosting_root: [u8; 32],
        metadata: &Secret<32>,
        content: &Secret<32>,
        candidate: &PackageCandidate,
    ) -> Result<ContentSigningRequest, OwnerError> {
        let key = candidate.pending.key;
        let (base, capability) = self
            .account_session(id)?
            .lock()
            .expect("container session lock")
            .authority()
            .current()
            .ok_or(OwnerError::Unbound)?;
        if key.base != base || key.audience != ORDINARY_AUDIENCE {
            return Err(OwnerError::Unbound);
        }
        if anchor.id() != capability.account_id() {
            return Err(OwnerError::AnchorMismatch);
        }
        let writer = crate::writers::pending_declaration(&candidate.pending)
            .map_err(|_| OwnerError::WriterUnavailable)?
            .ok_or(OwnerError::SealRefused(SealRefusal::NoDeclaration))?;
        let context =
            self.content_context(id, key.base, anchor, hosting_root, metadata, content)?;
        prepare_note(
            BaseId(key.base),
            &context.account,
            context.device,
            context.seen,
            context.receipt,
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

    /// Prepare the typed-data event for `candidate`, a pending mutation of this
    /// container's own base, sealing its exact payload bytes. No writer
    /// declaration is manufactured: a typed payload names no note.
    pub fn prepare_typed_seal(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        hosting_root: [u8; 32],
        metadata: &Secret<32>,
        content: &Secret<32>,
        candidate: &TypedPackageCandidate,
    ) -> Result<ContentSigningRequest, OwnerError> {
        if candidate.audience != ORDINARY_AUDIENCE {
            return Err(OwnerError::SealRefused(SealRefusal::AudienceUnsupported));
        }
        let context =
            self.content_context(id, candidate.base, anchor, hosting_root, metadata, content)?;
        prepare_typed(
            BaseId(candidate.base),
            &context.account,
            context.device,
            context.seen,
            context.receipt,
            TypedDraft {
                event_id: candidate.event_id,
                payload: &candidate.payload,
            },
            metadata,
            content,
        )
        .map_err(|_| OwnerError::Unavailable)
    }
}
