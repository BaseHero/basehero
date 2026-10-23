//! The base copy of an account change. A device's base history follows the
//! account only through account events copied into the base log as
//! controls, so a paired device can write to a base once its addition is
//! copied there, and a removal closes the base's content epoch once copied.
//! Confirmed account events are copied as runs, by a device's control key or
//! the current recovery key; a personal-key rotation that takes effect only
//! by the base's rekey. No untimed copy is ever prepared.
use crate::{ContainerId, Owner, OwnerError};
use bh_account::{Head as AccountHead, VerifiedAccount, owner::AccountCapability};
use bh_crypto::Secret;
use bh_event::{
    ControlSigningRequest, Copier, Seen,
    account_run::{AccountCopy, MAX_RUN, apply_copies, base_account, prepare_account_run},
    key_id,
    rekey::rotated_account,
};
use bh_storage::StoreError;
use bh_sync::{
    BaseId, Digest, Head,
    permit::LogKind,
    receipt::{self, RECEIPT_LEN},
};

/// What a control in this container's own base claims: the base, this
/// device, the base's copy of the account, the verified head with its
/// receipt and last control.
pub(crate) struct CopyContext {
    pub base: BaseId,
    pub capability: std::sync::Arc<AccountCapability>,
    pub account: VerifiedAccount,
    pub seen: Seen,
    pub receipt: [u8; RECEIPT_LEN],
    /// The base's pinned hosting root, which its controls' confirmations
    /// verify under.
    pub root: [u8; 32],
}

/// The most run data one control carries. The service takes a base
/// control's body inline in one authorization message of at most 64 KiB, so
/// a run's sealed body stays in the 16 KiB size class: its data and the
/// seal's 46 bytes of framing (kind, length, nonce, tag) within 16 KiB.
/// Today that is about 37 entries of the smallest kind and 8 device
/// additions, below `MAX_RUN`.
pub const RUN_BYTES: usize = 16 * 1024 - 46;

/// How the base's next missing account entries are copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyPlan {
    /// The first entry is a personal-key rotation that takes effect: only
    /// the base's rekey copies it.
    Rekey,
    /// A run of this many of the entries, from the first: it ends before a
    /// rotation that takes effect, before the first entry that does not
    /// apply, and within `RUN_BYTES`.
    Run(usize),
}

impl Owner {
    /// The base's verified state a control by this device claims. `anchor`
    /// is the account at the head the base genesis names and `metadata` the
    /// base's M.
    pub(crate) fn copy_context(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        metadata: &Secret<32>,
    ) -> Result<CopyContext, OwnerError> {
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
        let (progress, changes, ahead) = {
            let db = database.lock().expect("container writer lock");
            let kind = LogKind::Base as u8;
            let progress = db
                .log_progress(kind, base)?
                .ok_or(OwnerError::NotRegistered)?;
            // The control feed may have covered positions content has not
            // reached: a control claims the newest verified control state,
            // at the feed's authenticated endpoint.
            let ahead = match db.control_cursor(base)? {
                Some(cursor) if cursor.covered.position() > progress.position => {
                    let last = db
                        .control_fact_at(base, cursor.position)?
                        .ok_or(StoreError::CorruptSyncState)?;
                    let changes = db.control_account_changes(base, cursor.position)?;
                    Some((cursor, last, changes))
                }
                _ => None,
            };
            (progress, db.log_account_changes(kind, base)?, ahead)
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
        let root = progress.hosting_root;
        let (seen, receipt, account) = match ahead {
            Some((cursor, last, changes)) => {
                let account =
                    base_account(anchor, &changes, &root).map_err(|_| OwnerError::Unavailable)?;
                let head = cursor.covered.head(BaseId(base));
                if account.head().position != last.account.0
                    || account.head().hash != last.account.1
                    || receipt::verify(&root, BaseId(base), &cursor.receipt).map(|r| r.head())
                        != Ok(head)
                {
                    return Err(OwnerError::Unavailable);
                }
                let seen = Seen {
                    head,
                    control: last.control_digest,
                    account: account.head(),
                };
                (seen, cursor.receipt, account)
            }
            None => {
                let account =
                    base_account(anchor, &changes, &root).map_err(|_| OwnerError::Unavailable)?;
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
                (seen, receipt, account)
            }
        };
        Ok(CopyContext {
            base: BaseId(base),
            capability,
            account,
            seen,
            receipt,
            root,
        })
    }

    /// How `entries`, the account events after the base's copy of the
    /// account (at most `MAX_RUN`, each with its ordering confirmation), are
    /// copied into this container's own base from its verified state: each
    /// applied with the time its confirmation proves under the base's
    /// hosting root, as the base will, the run within `RUN_BYTES`.
    /// `CopyRefused` if the first does not apply.
    pub fn plan_account_copy(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        metadata: &Secret<32>,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<CopyPlan, OwnerError> {
        let c = self.copy_context(id, anchor, metadata)?;
        let mut account = c.account;
        // The run's count byte, then each entry's length, original and
        // confirmation.
        let mut bytes = 1;
        for (index, (original, confirmation)) in entries.iter().take(MAX_RUN).enumerate() {
            bytes += 4 + original.len() + confirmation.len();
            if index > 0 && bytes > RUN_BYTES {
                return Ok(CopyPlan::Run(index));
            }
            if rotated_account(&account, original, confirmation, &c.root).is_ok() {
                return Ok(if index == 0 {
                    CopyPlan::Rekey
                } else {
                    CopyPlan::Run(index)
                });
            }
            let copy = AccountCopy {
                original: original.clone(),
                confirmation: Some(confirmation.clone()),
            };
            if apply_copies(&mut account, &[copy], &c.root).is_err() {
                return match index {
                    0 => Err(OwnerError::CopyRefused),
                    _ => Ok(CopyPlan::Run(index)),
                };
            }
        }
        match entries.len().min(MAX_RUN) {
            0 => Err(OwnerError::CopyRefused),
            n => Ok(CopyPlan::Run(n)),
        }
    }

    /// Prepare the control that copies `run`, the account events after the
    /// base's copy of the account with their ordering confirmations, into
    /// this container's own base. `Copier::Device` must name this device,
    /// which signs with its control key through the account owner's
    /// confirmation; `Copier::Recovery` is signed with the current recovery
    /// key, as the request's expected key names.
    pub fn prepare_account_run_copy(
        &self,
        id: ContainerId,
        anchor: &VerifiedAccount,
        metadata: &Secret<32>,
        run: &[(Vec<u8>, Vec<u8>)],
        copier: Copier,
    ) -> Result<ControlSigningRequest, OwnerError> {
        let c = self.copy_context(id, anchor, metadata)?;
        if matches!(copier, Copier::Device(device) if device != c.capability.device_id()) {
            return Err(OwnerError::CopyRefused);
        }
        prepare_account_run(c.base, &c.account, copier, metadata, c.seen, c.receipt, run)
            .map_err(|_| OwnerError::CopyRefused)
    }
}
