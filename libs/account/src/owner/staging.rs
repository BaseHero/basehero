//! Signed trust controls staged before their order, and the account
//! directory read and written under the accepted personal key.
//!
//! A staged control is never authority. It settles only from verified history
//! at its position: its exact bytes there were ordered; anything else there
//! means it lost. A staged rotation's new key exists only inside its seals;
//! the accepted key changes only when `accept_rotation` accepts the ordered
//! rotation.
use super::*;
use crate::directory::{self, DirectoryEntry, EntrySubject, OpenedEntry};
use crate::journal::StagedControl;
use crate::recovery::{PasswordCheck, RecoveryCode, RecoveryKeys, make_password_check};
use crate::trust::{ConfirmedTime, DeviceState, REMOVAL_WAIT_MS};
use crate::{AccountChange, personal::PersonalKey};

/// How a staged control's position was taken in verified history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settled {
    /// Ordered at `position` with these confirmed bounds. A removal
    /// request's wait ends at `bounds.latest_ms + REMOVAL_WAIT_MS` unless it
    /// lapsed; read `device_state`/`request_state` for what to show.
    Accepted {
        position: u64,
        bounds: ConfirmedTime,
    },
    /// An ordered cancel that was confirmed only once its request's deadline
    /// had passed: the removal took effect.
    CancelTookEffect,
    /// Another entry took the position; nothing staged was applied.
    Lost,
}

/// A settled stage, now cleared, with the exact row it settled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub staged: StagedControl,
    pub outcome: Settled,
}

/// Why one directory entry was not opened. Others in the same read still are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryRefused {
    Invalid(Error),
    /// Lower than the version this device already accepted for the entry.
    LowerVersion {
        remembered: u64,
    },
}

const ROTATE_PERSONAL: u8 = 9;
const REPLACE_RECOVERY: u8 = 8;

/// The digest of the device-seal body a rotation signs, if `event` decodes
/// as one. Decoding is not verification.
pub fn rotation_body_digest(event: &[u8]) -> Option<[u8; 32]> {
    match AccountEvent::decode(event).ok()?.control {
        Control::RotatePersonal { publication, .. } => Some(*publication.device_digest()),
        _ => None,
    }
}

/// The device-seal digest of the personal key `event` publishes, at signup
/// or by a rotation, if it does. Decoding is not verification.
pub fn published_device_digest(event: &[u8]) -> Option<[u8; 32]> {
    match AccountEvent::decode(event).ok()?.control {
        Control::PersonalKey(publication) | Control::RotatePersonal { publication, .. } => {
            Some(*publication.device_digest())
        }
        _ => None,
    }
}

/// The digest a publication names for this raw device-seal body.
pub fn device_seals_digest(raw: &[u8]) -> [u8; 32] {
    personal::body_digest(raw)
}

/// Whether `raw` is exactly the device-seal body rotation `event` signs.
pub fn signs_rotation_body(event: &[u8], raw: &[u8]) -> bool {
    rotation_body_digest(event)
        .is_some_and(|signed| crate::crypto::constant_time_eq(&personal::body_digest(raw), &signed))
}

/// Where a signed directory entry's id sits: after its domain, account and
/// personal-key id.
const ENTRY_DOMAIN: &[u8] = b"bh/directory-entry/v1\0";
const ENTRY_ID_AT: usize = ENTRY_DOMAIN.len() + 32 + 32;

/// The id a directory entry is stored under, read from its header without
/// opening it: for paging a directory read. Not verification.
pub fn directory_entry_id(bytes: &[u8]) -> Option<[u8; 32]> {
    if !bytes.starts_with(ENTRY_DOMAIN) || bytes.len() > directory::MAX_ENTRY {
        return None;
    }
    bytes.get(ENTRY_ID_AT..ENTRY_ID_AT + 32)?.try_into().ok()
}

/// The highest version the device database can remember.
const MAX_VERSION: u64 = i64::MAX as u64;

/// The tag of a trust control a device may stage; additions are staged as
/// admissions and setup is never staged.
fn trust_kind(event: &AccountEvent) -> Option<u8> {
    Some(match event.change() {
        AccountChange::DeviceRemovedSelf { .. } => 2,
        AccountChange::RemovalRequested { .. } => 5,
        AccountChange::RemovedNow { .. } => 6,
        AccountChange::RemovalCancelled { .. } => 7,
        AccountChange::RecoveryReplaced { .. } => 8,
        AccountChange::PersonalRotated { .. } => ROTATE_PERSONAL,
        AccountChange::DeviceAdded { .. } | AccountChange::Setup => return None,
    })
}

/// The decoded event, only if it is the exact successor of `head`.
fn next_at(head: Head, bytes: &[u8]) -> Result<AccountEvent, Error> {
    let event = AccountEvent::decode(bytes)?;
    if event.previous_head() != head {
        return Err(Error::WrongPredecessor);
    }
    Ok(event)
}

impl<J, S, P> AccountOwner<J, S, P>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    pub fn staged_control(&self) -> Result<Option<StagedControl>, OwnerError> {
        self.journal.staged_control().map_err(OwnerError::from)
    }

    /// Clear `expected`, the exact staged row read before, after the
    /// service definitively refused those bytes while verified history still
    /// stands at their predecessor. A different row staged meanwhile is
    /// `StagedControlChanged` and is kept; nothing staged is not an error.
    pub fn discard_staged(&mut self, expected: &StagedControl) -> Result<(), OwnerError> {
        self.journal.clear_staged_control(expected)?;
        Ok(())
    }

    /// Stage an already-signed trust control before submitting it. It must
    /// be the exact next event at this device's verified head. The same bytes
    /// again return the stage; a different staged control is never
    /// overwritten. Signatures and timed rules are judged when it is ordered.
    pub fn stage_control(
        &mut self,
        capability: &AccountCapability,
        event: &[u8],
        body: Option<Vec<u8>>,
        attachment: Option<Vec<u8>>,
        sealed_kit: Option<Vec<u8>>,
    ) -> Result<StagedControl, OwnerError> {
        let head = self.verified(capability)?.head();
        let decoded = next_at(head, event).map_err(OwnerError::Invalid)?;
        let kind = trust_kind(&decoded).ok_or(OwnerError::Invalid(Error::NotPermitted))?;
        self.stage(StagedControl {
            kind,
            event: event.to_vec(),
            body,
            attachment,
            sealed_kit,
        })
    }

    fn stage(&mut self, row: StagedControl) -> Result<StagedControl, OwnerError> {
        match self.journal.staged_control()? {
            Some(staged) if staged == row => return Ok(staged),
            Some(_) => return Err(JournalError::StagedControlExists.into()),
            None => {}
        }
        self.journal.stage_control(&row)?;
        Ok(row)
    }

    /// Stage a personal-key rotation for the latest effect due at `at_ms`
    /// (a verified accepted head's `earliest_ms`), so one rotation fulfils
    /// every effect due. A new key is sealed to the devices active at
    /// `at_ms` and the recovery key, and the rotation is signed with this
    /// device's ordinary key: no prompt. The new key is kept only in those
    /// seals. A rotation already staged at this head is returned unchanged.
    pub async fn stage_rotation(
        &mut self,
        capability: &AccountCapability,
        at_ms: u64,
    ) -> Result<StagedControl, OwnerError> {
        let view = self.verified(capability)?.clone();
        if let Some(staged) = self.journal.staged_control()? {
            if staged.kind == ROTATE_PERSONAL && next_at(view.head(), &staged.event).is_ok() {
                return Ok(staged);
            }
            return Err(JournalError::StagedControlExists.into());
        }
        let reason = view
            .rotation_reason(at_ms)
            .ok_or(OwnerError::Invalid(Error::NotPermitted))?;
        let prepared = personal::prepare_rotation(&view.advanced(at_ms), &PersonalKey::generate())
            .map_err(OwnerError::Invalid)?;
        let request = view
            .rotate_personal(
                capability.device_id(),
                reason.position(),
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .map_err(OwnerError::Invalid)?;
        let signature = self
            .sign_content(capability, request.signing_bytes())
            .await?;
        let event = request.finish(signature).map_err(OwnerError::Invalid)?;
        if self.verified(capability)?.head() != view.head() {
            return Err(OwnerError::Invalid(Error::WrongPredecessor));
        }
        self.stage(StagedControl {
            kind: ROTATE_PERSONAL,
            event: event.as_bytes().to_vec(),
            body: Some(prepared.body),
            attachment: Some(prepared.recovery_seal),
            sealed_kit: None,
        })
    }

    /// Once verified history reaches the staged position, say how it was
    /// taken and clear the stage; `None` while it has not (or nothing is
    /// staged), keeping the stage. Needs no capability, so a device's own
    /// removal still settles. The outcome comes from stored history and
    /// confirmations alone, so it is the same after a restart. A concurrent
    /// change to the stage is `StagedControlChanged`: read again and retry.
    pub fn settle_staged(&mut self) -> Result<Option<Settlement>, OwnerError> {
        let Some(staged) = self.journal.staged_control()? else {
            return Ok(None);
        };
        let loaded = self.loaded.as_ref().ok_or(OwnerError::NotActive)?;
        if loaded.stopped {
            return Err(OwnerError::Stopped);
        }
        let view = &loaded.account;
        let event = AccountEvent::decode(&staged.event).map_err(|_| JournalError::Corrupt)?;
        let position = event.head().position;
        if view.head().position < position {
            return Ok(None);
        }
        let outcome = if !view
            .verified_event_at(position, &staged.event)
            .map_err(OwnerError::Invalid)?
        {
            Settled::Lost
        } else {
            let bounds = view
                .confirmed_time(position)
                .map_err(OwnerError::Invalid)?
                .ok_or(JournalError::Corrupt)?;
            match event.control {
                Control::Cancel(request) if self.cancel_too_late(view, request, bounds)? => {
                    Settled::CancelTookEffect
                }
                _ => Settled::Accepted { position, bounds },
            }
        };
        self.journal.clear_staged_control(&staged)?;
        if let Some(sealed) = &staged.sealed_kit {
            self.retire_kit(sealed);
        }
        Ok(Some(Settlement { staged, outcome }))
    }

    /// Whether an ordered cancel came too late: it names a removal request
    /// whose deadline its confirmation reached, and that request's target is
    /// removed.
    fn cancel_too_late(
        &self,
        view: &VerifiedAccount,
        request: u64,
        cancel: ConfirmedTime,
    ) -> Result<bool, OwnerError> {
        let page = self
            .journal
            .history_prefix(
                Some(HistoryCursor {
                    anchor: view.id(),
                    cut: view.head(),
                    next_position: request,
                }),
                1,
            )?
            .ok_or(JournalError::Corrupt)?;
        let original = page.events.first().ok_or(JournalError::Corrupt)?;
        if page.first_position != request
            || !view
                .verified_event_at(request, original)
                .map_err(OwnerError::Invalid)?
        {
            return Err(JournalError::Corrupt.into());
        }
        let decoded = AccountEvent::decode(original).map_err(|_| JournalError::Corrupt)?;
        let Control::RemoveRequest(target) = decoded.control else {
            return Ok(false);
        };
        let Some(requested) = view.confirmed_time(request).map_err(OwnerError::Invalid)? else {
            return Ok(false);
        };
        Ok(
            requested.latest_ms.saturating_add(REMOVAL_WAIT_MS) <= cancel.latest_ms
                && view.device_state(target, cancel.latest_ms) == Ok(DeviceState::Removed),
        )
    }

    /// One directory entry at `version`, sealed to the accepted personal key
    /// and signed with this device's ordinary key at its verified head.
    /// Refused while history publishes a key this device has not accepted.
    pub async fn prepare_directory_entry(
        &mut self,
        capability: &AccountCapability,
        entry: &DirectoryEntry,
        version: u64,
    ) -> Result<Vec<u8>, OwnerError> {
        if version > MAX_VERSION {
            return Err(OwnerError::Invalid(Error::Malformed));
        }
        let personal = self.open_current_personal(capability).await?;
        let request = directory::prepare_entry(
            self.verified(capability)?,
            &personal,
            capability.device_id(),
            entry,
            version,
        )
        .map_err(OwnerError::Invalid)?;
        let signature = self
            .sign_content(capability, request.signing_bytes())
            .await?;
        request.finish(signature).map_err(OwnerError::Invalid)
    }

    /// Open entries read from the directory under the accepted personal key,
    /// in order. Each opened entry raises the version this device remembers
    /// for its id, across restarts; a lower version is refused, an equal one
    /// accepted. A device that remembers none can be shown an older entry.
    pub async fn open_directory_entries(
        &mut self,
        capability: &AccountCapability,
        entries: &[&[u8]],
    ) -> Result<Vec<Result<OpenedEntry, EntryRefused>>, OwnerError> {
        let personal = self.open_current_personal(capability).await?;
        let view = self.verified(capability)?.clone();
        let mut out = Vec::with_capacity(entries.len());
        for bytes in entries {
            let opened = match directory::open_entry(&view, &personal, bytes) {
                Ok(opened) => opened,
                Err(error) => {
                    out.push(Err(EntryRefused::Invalid(error)));
                    continue;
                }
            };
            // A version this device could never remember is skipped, not
            // the whole read.
            if opened.version > MAX_VERSION {
                out.push(Err(EntryRefused::Invalid(Error::Malformed)));
                continue;
            }
            // Raise first, then compare, so a concurrent raise is never lowered.
            if !self
                .journal
                .remember_directory_version(opened.entry_id, opened.version)?
            {
                let remembered = self
                    .journal
                    .directory_version(opened.entry_id)?
                    .ok_or(JournalError::Corrupt)?;
                if opened.version < remembered {
                    out.push(Err(EntryRefused::LowerVersion { remembered }));
                    continue;
                }
            }
            out.push(Ok(opened));
        }
        Ok(out)
    }

    /// This device's own directory entry at `version`, sealed to the
    /// accepted personal key and signed with its ordinary key, with the id
    /// it is stored under; `None` while this device remembers the home
    /// holding that id at `version` or later. A device names only itself.
    /// Ids derive from the personal key, so an entry under a key rotated
    /// away is not remembered for the current one.
    pub async fn prepare_own_entry(
        &mut self,
        capability: &AccountCapability,
        entry: &DirectoryEntry,
        version: u64,
    ) -> Result<Option<([u8; 32], Vec<u8>)>, OwnerError> {
        if version > MAX_VERSION {
            return Err(OwnerError::Invalid(Error::Malformed));
        }
        let subject = match entry {
            DirectoryEntry::DeviceName { device, .. } if *device == capability.device_id() => {
                EntrySubject::DeviceName(*device)
            }
            DirectoryEntry::PasswordCheck { .. } => EntrySubject::PasswordCheck,
            _ => return Err(OwnerError::Invalid(Error::NotPermitted)),
        };
        let personal = self.open_current_personal(capability).await?;
        let id = directory::entry_id(&directory::directory_key(&personal), &subject);
        if self
            .journal
            .directory_version(id)?
            .is_some_and(|held| held >= version)
        {
            return Ok(None);
        }
        let request = directory::prepare_entry(
            self.verified(capability)?,
            &personal,
            capability.device_id(),
            entry,
            version,
        )
        .map_err(OwnerError::Invalid)?;
        let signature = self
            .sign_content(capability, request.signing_bytes())
            .await?;
        let bytes = request.finish(signature).map_err(OwnerError::Invalid)?;
        Ok(Some((id, bytes)))
    }

    /// The home holds this device's entry `entry` at `version` or later:
    /// remembered across restarts, so it is not written again.
    pub fn own_entry_held(&mut self, entry: [u8; 32], version: u64) -> Result<(), OwnerError> {
        if version > MAX_VERSION {
            return Err(OwnerError::Invalid(Error::Malformed));
        }
        self.journal.remember_directory_version(entry, version)?;
        Ok(())
    }

    /// Replace the recovery key: a new code and record under `password`
    /// (the current one or a new one), the accepted personal key sealed to
    /// the new recovery key, and the replacement signed with this device's
    /// second key. It is staged with the record as its `body`, that seal as
    /// its `attachment` and the new code sealed by the pending-setup
    /// protector as its `sealed_kit`, which stays until the person saves the
    /// kit. Returns the new code and a check of `password`. The new recovery
    /// key is dropped here; only its record and seal remain.
    pub async fn stage_recovery_replacement(
        &mut self,
        capability: &AccountCapability,
        password: &Password,
    ) -> Result<(StagedControl, RecoveryCode, PasswordCheck), OwnerError> {
        let view = self.verified(capability)?.clone();
        if self.journal.staged_control()?.is_some() {
            return Err(JournalError::StagedControlExists.into());
        }
        let keys = RecoveryKeys::generate();
        let code = RecoveryCode::generate();
        let record = crate::recovery::prepare_replacement(&view, &keys, password, &code)
            .map_err(OwnerError::Invalid)?;
        let check = make_password_check(password).map_err(OwnerError::Invalid)?;
        let personal = self.open_current_personal(capability).await?;
        let seal = personal::seal_for_new_recovery(&view, &personal, &keys.public())
            .map_err(OwnerError::Invalid)?;
        let request = view
            .replace_recovery(
                capability.device_id(),
                keys.public(),
                record.digest(),
                personal::seal_digest(&seal),
            )
            .map_err(OwnerError::Invalid)?;
        drop(keys);
        let event = self.sign_control(capability, &request).await?;
        if self.verified(capability)?.head() != view.head() {
            return Err(OwnerError::Invalid(Error::WrongPredecessor));
        }
        let sealed_kit = self
            .protector
            .seal(code.expose())
            .map_err(OwnerError::Protector)?;
        let staged = self.stage(StagedControl {
            kind: REPLACE_RECOVERY,
            event: event.as_bytes().to_vec(),
            body: Some(record.as_bytes().to_vec()),
            attachment: Some(seal),
            sealed_kit: Some(sealed_kit),
        })?;
        Ok((staged, code, check))
    }

    /// The code of a staged recovery replacement whose kit the person has
    /// not saved yet; `None` otherwise.
    pub fn staged_kit_code(&mut self) -> Result<Option<RecoveryCode>, OwnerError> {
        let Some(staged) = self.journal.staged_control()? else {
            return Ok(None);
        };
        let Some(sealed) = staged
            .sealed_kit
            .as_ref()
            .filter(|_| staged.kind == REPLACE_RECOVERY)
        else {
            return Ok(None);
        };
        let opened = self.protector.open(sealed).map_err(OwnerError::Protector)?;
        let raw: [u8; 16] = opened
            .expose()
            .try_into()
            .map_err(|_| JournalError::Corrupt)?;
        Ok(Some(RecoveryCode::from_raw(&raw)))
    }

    /// The person saved the staged recovery replacement's kit: clear it from
    /// the stage in one durable step, keeping the replacement staged so it
    /// is sent, then retire the kit's protector key. Returns the account
    /// position the replacement is staged for, its kit cleared now or
    /// before; `None` when no replacement is staged, as when it was lost
    /// while its kit showed.
    pub fn confirm_staged_kit(&mut self) -> Result<Option<u64>, OwnerError> {
        let Some(staged) = self
            .journal
            .staged_control()?
            .filter(|staged| staged.kind == REPLACE_RECOVERY)
        else {
            return Ok(None);
        };
        let position = AccountEvent::decode(&staged.event)
            .map_err(|_| JournalError::Corrupt)?
            .head()
            .position;
        if let Some(sealed) = staged.sealed_kit.clone() {
            self.journal.clear_staged_kit(&staged)?;
            self.retire_kit(&sealed);
        }
        Ok(Some(position))
    }

    /// Retire the protector key of a kit's `sealed` code, once the stage no
    /// longer holds it. Best effort: a key that cannot be retired now
    /// protects only a code the person saved, or one never sent.
    fn retire_kit(&mut self, sealed: &[u8]) {
        if self.protector.retire_key(sealed).is_ok() {
            return;
        }
        // An adapter without direct deletion: retire it as a saved setup
        // kit is, under a no-code key made for that.
        if let Ok(retired) = self.protector.reseal_without_code(sealed, &[]) {
            let _ = self.protector.retire_kit_key(&retired);
        }
    }
}
