//! Durable account state the owner needs, expressed as domain operations.
//!
//! A storage adapter must commit the original signed event bytes, the resulting
//! verified head and the sticky integrity stop in one transaction: a head is
//! never durable without the bytes that produced it. The pending first-device
//! setup blob is opaque here and is protected by the account owner, not the
//! journal. This is deliberately not a generic key-value store.

use crate::crypto::{Secret, SecretBytes};
use crate::history::{AccountId, DevicePublicKeys, Head, VerifiedAccount};
use crate::trust::ConfirmedTime;

/// Exact signed admission and signed recipient-encrypted delivery. The event's
/// one-based position and predecessor are checked by the account layer, never
/// inferred from an untrusted relay response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedAdmission {
    pub position: u64,
    pub previous: [u8; 32],
    pub event: Vec<u8>,
    pub delivery: Vec<u8>,
}

/// One exact signed trust control staged before its order, and what its
/// submission carries. `kind` is the control's tag in `event`. A recovery
/// replacement (kind 8) and a personal rotation (kind 9) both carry the raw
/// recovery seal as `attachment`; `body` is the replacement's recovery
/// record (8) or the rotation's exact raw device-seal frame (9). A
/// replacement's `sealed_kit` is its new code, sealed by the pending-setup
/// protector, until the person saves the kit; it is not sent while present.
/// Other controls carry nothing.
/// Nothing staged is accepted: the owner settles it only from verified history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedControl {
    pub kind: u8,
    pub event: Vec<u8>,
    pub body: Option<Vec<u8>>,
    pub attachment: Option<Vec<u8>>,
    pub sealed_kit: Option<Vec<u8>>,
}

use crate::platform::{ControlKeyPolicy, DeviceKeyStoreKind, KeyHandle};

/// One held base root, sealed locally to the accepted personal key.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyringRow {
    pub base: [u8; 32],
    pub key_id: [u8; 32],
    pub purpose: crate::local_seal::LocalKeyPurpose,
    pub seal: Vec<u8>,
}

/// The durable evidence of the personal key this device accepted, opened
/// again at its own verified position.
#[derive(Clone, PartialEq, Eq)]
pub enum AcceptedPersonal {
    /// The first device's initial seal.
    Initial,
    /// The delivery this device's addition carried.
    Delivered { added_at: u64, frame: Vec<u8> },
    /// An accepted rotation's ordered device-seal body.
    Rotated { position: u64, body: Vec<u8> },
}

/// What accepting a rotation read and compares at commit.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyringState {
    pub head: Head,
    pub accepted: AcceptedPersonal,
    pub rows: Vec<KeyringRow>,
}

/// Framing version of the owner's pending first-device setup blob.
pub const PENDING_SETUP_VERSION: u16 = 1;

/// First-device setup stage. Whether the home has ordered the staged bytes is
/// derived from the journal, not stored here; `kit_saved` is a separate explicit
/// confirmation so it survives a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStage {
    /// Local materials generated and signed; not submitted or ordered yet.
    Prepared,
    /// Submitted to the account home, result unknown. Reconcile the exact signed
    /// bytes before treating it as home ordered.
    HomePending,
    /// Home acknowledged the exact events and all three private objects.
    HomeOrdered,
}

impl SetupStage {
    pub fn code(self) -> u8 {
        match self {
            Self::Prepared => 0,
            Self::HomePending => 1,
            Self::HomeOrdered => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Prepared),
            1 => Some(Self::HomePending),
            2 => Some(Self::HomeOrdered),
            _ => None,
        }
    }
}

/// Opaque, native-protected pending-setup material plus its stage and the
/// person's explicit kit-save confirmation.
#[derive(Clone)]
pub struct PendingSetupRecord {
    pub version: u16,
    pub stage: SetupStage,
    pub kit_saved: bool,
    pub blob: Vec<u8>,
}

/// Recorded local device identity. The owner still checks these keys against
/// verified active history; this record is not authority by itself.
#[derive(Clone)]
pub struct JournaledDevice {
    pub handle: KeyHandle,
    pub keys: DevicePublicKeys,
    pub policy: ControlKeyPolicy,
    pub kind: DeviceKeyStoreKind,
}

/// Durable verified account: trusted anchor, original signed history, head, stop.
#[derive(Clone)]
pub struct JournaledAccount {
    pub anchor: AccountId,
    pub history: Vec<Vec<u8>>,
    pub head: Head,
    pub stopped: bool,
}

/// Local owner-checked projection bound to its trusted anchor and exact head.
/// Never supplied by an account home or a WebView.
pub struct JournaledProjection {
    pub account: VerifiedAccount,
    pub stopped: bool,
    /// Coherently captured current durable target; the view may be a rebuild cut.
    pub target: Head,
}

/// A captured original-history prefix. Appends never change its final cut.
/// This cursor is not authority; native callers must check their generation
/// around a multi-page export.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HistoryCursor {
    pub anchor: AccountId,
    pub cut: Head,
    pub next_position: u64,
}
impl std::fmt::Debug for HistoryCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryCursor")
            .field("cut", &self.cut)
            .field("next_position", &self.next_position)
            .finish_non_exhaustive()
    }
}
pub struct HistoryPage {
    pub anchor: AccountId,
    pub cut: Head,
    pub first_position: u64,
    pub events: Vec<Vec<u8>>,
    /// Each event's confirmed time, where the journal stores one.
    pub times: Vec<Option<ConfirmedTime>>,
    pub next: Option<HistoryCursor>,
}

/// Exact protected-home objects and the original initial account cut. No code,
/// recovery private key, or opened personal seed belongs here.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialBootstrapRecord {
    pub anchor: AccountId,
    pub head: Head,
    pub recovery_record: Vec<u8>,
    pub device_seal: Vec<u8>,
    pub recovery_seal: Vec<u8>,
}

/// Journal failures carry no identity, key or input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// The storage adapter failed; no state change is implied.
    Storage,
    /// Required confirmation is absent; refused before writes, safe to retry.
    MissingTime,
    /// A newly appended confirmed original predates a durable observation.
    TimeRegressed,
    /// Stored account state is internally inconsistent.
    Corrupt,
    /// A previous admission remains unresolved; never overwrite its bytes.
    StagedAdmissionExists,
    /// A stale completion cannot clear a newer row.
    StagedAdmissionChanged,
    /// Another trust control is staged; never overwrite its bytes.
    StagedControlExists,
    /// The staged control changed since it was read; nothing was cleared.
    /// Read it again and retry.
    StagedControlChanged,
    /// The accepted personal key, head or keyring changed since it was read;
    /// nothing was written. Retry from a fresh read.
    KeyringChanged,
    /// A held base has no local keyring rows yet; nothing was written.
    /// Initialize the keyring, then retry.
    KeyringIncomplete,
}

/// Durable state an account owner needs. Implementations commit each mutation
/// atomically, and never let a head outlive its signed bytes.
pub trait AccountJournal {
    /// Load the trusted anchor, original signed history, remembered head and stop.
    fn load(&self) -> Result<Option<JournaledAccount>, JournalError>;
    /// Native journals return current authority or a resumable verified cut.
    /// None permits full replay only for memory/remote journals.
    fn load_projection(&self) -> Result<Option<JournaledProjection>, JournalError> {
        Ok(None)
    }
    fn advance_projection(&mut self, _: &VerifiedAccount) -> Result<(), JournalError> {
        Ok(())
    }
    /// Attach native evidence even after the first memory/genesis commit.
    fn rebase_projection(&self, account: VerifiedAccount) -> Result<VerifiedAccount, JournalError> {
        Ok(account)
    }
    fn has_account(&self) -> Result<bool, JournalError> {
        Ok(self.load()?.is_some())
    }
    /// Limit 1..=256; every page is contiguous and ends at the captured cut,
    /// never a moving current head. A gap, changed cut/account or oversized
    /// original fails the whole page. None is only an absent account.
    fn history_prefix(
        &self,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Option<HistoryPage>, JournalError> {
        if !(1..=256).contains(&limit) {
            return Err(JournalError::Corrupt);
        }
        let Some(record) = self.load()? else {
            return if cursor.is_some() {
                Err(JournalError::Corrupt)
            } else {
                Ok(None)
            };
        };
        let c = cursor.unwrap_or(HistoryCursor {
            anchor: record.anchor,
            cut: record.head,
            next_position: 1,
        });
        if c.anchor != record.anchor
            || c.cut.position == 0
            || c.cut.position > record.head.position
            || (c.cut.position == record.head.position && c.cut.hash != record.head.hash)
            || c.next_position == 0
            || c.next_position > c.cut.position
            || record
                .history
                .get((c.cut.position - 1) as usize)
                .is_none_or(|bytes| crate::crypto::hash(bytes) != c.cut.hash)
        {
            return Err(JournalError::Corrupt);
        }
        let end = c
            .cut
            .position
            .min(c.next_position.saturating_add(limit as u64 - 1));
        let events = record
            .history
            .get((c.next_position - 1) as usize..end as usize)
            .ok_or(JournalError::Corrupt)?;
        if events
            .iter()
            .any(|e| e.len() > crate::history::MAX_EVENT_LEN)
        {
            return Err(JournalError::Corrupt);
        }
        Ok(Some(HistoryPage {
            anchor: c.anchor,
            cut: c.cut,
            first_position: c.next_position,
            events: events.to_vec(),
            times: vec![None; events.len()],
            next: (end < c.cut.position).then_some(HistoryCursor {
                next_position: end + 1,
                ..c
            }),
        }))
    }

    /// Append original signed bytes and set the resulting head and stop flag in
    /// one commit. An empty `events` slice only updates the stop flag; the head
    /// then refers to bytes already stored.
    fn commit_verified(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
    ) -> Result<(), JournalError>;

    /// Order a generation advance against writers using the container guard.
    /// Standalone journals have no external writer to exclude.
    fn fence(&self, action: impl FnOnce()) -> Result<(), JournalError> {
        action();
        Ok(())
    }

    /// Keep the durable commit and its generation advance in the same guard.
    /// `fence` runs even when the durable commit fails.
    fn commit_verified_fenced(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
        fence: impl FnOnce(bool),
    ) -> Result<(), JournalError> {
        let result = self.commit_verified(anchor, events, head, stopped);
        fence(result.is_ok());
        result
    }

    /// Commit signed bytes and checked projection atomically, fencing under the writer guard.
    fn commit_projected_fenced(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
        projection: Option<&VerifiedAccount>,
        fence: impl FnOnce(bool),
    ) -> Result<(), JournalError> {
        let start = head.position.checked_sub(events.len() as u64);
        if projection.is_some_and(|p| {
            start.is_none_or(|start| {
                (start + 1..=head.position)
                    .any(|position| !matches!(p.confirmed_time(position), Ok(None)))
            })
        }) {
            fence(false);
            return Err(JournalError::Corrupt);
        }
        self.commit_verified_fenced(anchor, events, head, stopped, fence)
    }

    /// `commit_projected_fenced` with each original's caller-verified confirmed
    /// bounds and exact proof bytes, stored in the same commit. Journals that
    /// cannot store this evidence refuse timed events. A `MissingTime` refusal
    /// must precede all writes and must not invoke `fence`; authority is unchanged.
    #[allow(clippy::too_many_arguments)]
    fn commit_timed_fenced(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        evidence: &[Option<(ConfirmedTime, Vec<u8>)>],
        head: Head,
        stopped: bool,
        projection: Option<&VerifiedAccount>,
        fence: impl FnOnce(bool),
    ) -> Result<(), JournalError> {
        if evidence.len() != events.len() || evidence.iter().any(Option::is_some) {
            fence(false);
            return Err(JournalError::Storage);
        }
        self.commit_projected_fenced(anchor, events, head, stopped, projection, fence)
    }

    /// Commit verified alert facts with the account originals in one transaction.
    /// Non-device journals have no local notification store. The same no-write,
    /// no-fence rule for `MissingTime` as `commit_timed_fenced` applies.
    #[allow(clippy::too_many_arguments)]
    fn commit_timed_alerted_fenced(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        evidence: &[Option<(ConfirmedTime, Vec<u8>)>],
        head: Head,
        stopped: bool,
        projection: Option<&VerifiedAccount>,
        _alerts: &[bh_storage::NewAlert],
        fence: impl FnOnce(bool),
    ) -> Result<(), JournalError> {
        self.commit_timed_fenced(anchor, events, evidence, head, stopped, projection, fence)
    }

    /// An accepted-head observation can establish a deadline with no new entry.
    /// Only device journals persist local notifications.
    fn record_observed_alerts(
        &mut self,
        _anchor: AccountId,
        _head: Head,
        _observed_earliest_ms: u64,
        _alerts: &[bh_storage::NewAlert],
    ) -> Result<(), JournalError> {
        Ok(())
    }

    /// Local lower bound from an accepted-head observation; replay does not
    /// consume it until the projection has reached the stored account head.
    fn observed_account_floor(&self) -> Result<Option<u64>, JournalError> {
        Ok(None)
    }

    /// Attach the home's caller-verified confirmations of setup positions 2
    /// and 3 to the prefix a kit save committed untimed, with `projection`,
    /// that prefix's fresh timed replay, in one commit. Only while setup is
    /// pending, the head is exactly `setup_head` at position 3 with these
    /// originals at 2 and 3, and no confirmation is stored. Genesis is never
    /// timed, and no other entry is ever retimed. Journals that cannot store
    /// this evidence refuse.
    fn attach_setup_confirmations(
        &mut self,
        _anchor: AccountId,
        _setup_head: Head,
        _originals: [&[u8]; 2],
        _evidence: &[(ConfirmedTime, Vec<u8>); 2],
        _projection: &VerifiedAccount,
    ) -> Result<(), JournalError> {
        Err(JournalError::Storage)
    }

    fn device(&self) -> Result<Option<JournaledDevice>, JournalError>;
    fn commit_device(&mut self, device: &JournaledDevice) -> Result<(), JournalError>;

    /// Unsupported journals fail closed; they cannot silently lose the only
    /// initial-device personal seal while deleting pending setup.
    fn initial_bootstrap(&self) -> Result<Option<InitialBootstrapRecord>, JournalError> {
        Err(JournalError::Storage)
    }
    fn retain_initial_bootstrap(
        &mut self,
        _record: &InitialBootstrapRecord,
        _clear_pending: bool,
    ) -> Result<(), JournalError> {
        Err(JournalError::Storage)
    }

    fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError>;
    fn commit_pending_setup(&mut self, setup: &PendingSetupRecord) -> Result<(), JournalError>;
    /// Delete pending setup material. Called only once the journal holds the
    /// staged bytes (home ordered) and the person confirmed the kit saved.
    fn clear_pending_setup(&mut self) -> Result<(), JournalError>;

    /// Atomic insert; refuse a second row even if its bytes match. No send
    /// until this succeeds. Clearing is permitted only after verified history
    /// resolves the signed position; cancel does not clear it.
    fn staged_admission(&self) -> Result<Option<StagedAdmission>, JournalError>;
    fn insert_staged_admission(&mut self, row: &StagedAdmission) -> Result<(), JournalError>;
    fn clear_staged_admission(&mut self, expected: &StagedAdmission) -> Result<(), JournalError>;

    /// At most one staged trust control. Insert refuses a second row, even
    /// with the same bytes; clearing compares the whole row and clears
    /// nothing (`StagedControlChanged`) if it changed. Clearing an absent row
    /// succeeds. Journals without this store fail closed.
    fn staged_control(&self) -> Result<Option<StagedControl>, JournalError> {
        Err(JournalError::Storage)
    }
    fn stage_control(&mut self, _row: &StagedControl) -> Result<(), JournalError> {
        Err(JournalError::Storage)
    }
    fn clear_staged_control(&mut self, _expected: &StagedControl) -> Result<(), JournalError> {
        Err(JournalError::Storage)
    }
    /// Clear the `sealed_kit` of `expected`, the exact staged row, in one
    /// durable write that keeps the control staged; any other row, or none,
    /// is `StagedControlChanged` and nothing changes.
    fn clear_staged_kit(&mut self, _expected: &StagedControl) -> Result<(), JournalError> {
        Err(JournalError::Storage)
    }

    /// The highest version this device accepted for a directory entry id.
    fn directory_version(&self, _entry: [u8; 32]) -> Result<Option<u64>, JournalError> {
        Err(JournalError::Storage)
    }
    /// Raise the remembered version; returns whether it advanced. A lower or
    /// equal version leaves it unchanged.
    fn remember_directory_version(
        &mut self,
        _entry: [u8; 32],
        _version: u64,
    ) -> Result<bool, JournalError> {
        Err(JournalError::Storage)
    }

    /// The head, accepted personal key and every keyring row, read together.
    /// Journals without a keyring fail closed.
    fn keyring_state(&self) -> Result<KeyringState, JournalError> {
        Err(JournalError::Storage)
    }
    /// Accept the rotation at `position` and replace every row with its
    /// re-sealed form in one commit, only if `expected` is still exactly what
    /// is stored and `current` holds under the writer. A change is
    /// `KeyringChanged`; a held base without rows is `KeyringIncomplete`.
    fn commit_accepted_rotation(
        &mut self,
        _expected: &KeyringState,
        _position: u64,
        _body: &[u8],
        _rows: &[KeyringRow],
        _current: impl Fn() -> bool,
    ) -> Result<(), JournalError> {
        Err(JournalError::Storage)
    }
}

/// Native protection for the pending setup blob. A production adapter seals it
/// with an OS-held key; no software fallback is offered here.
pub trait PendingSetupProtector {
    /// Create a fresh per-setup wrapping key for code-bearing material.
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError>;
    fn open(&mut self, blob: &[u8]) -> Result<SecretBytes, ProtectorError>;
    /// Seal a no-code replacement under a distinct key, retaining the old key
    /// reference for crash-safe retirement after the replacement is durable.
    fn reseal_without_code(
        &mut self,
        _old: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtectorError> {
        // Other platform adapters must explicitly implement safe retirement
        // before first-device setup is enabled; never silently reuse a key.
        Err(ProtectorError::Unavailable)
    }
    /// Idempotently retire the old code-bearing key; call on every restart of
    /// a saved setup and before it may be cleared after home acknowledgement.
    fn retire_kit_key(&mut self, _saved: &[u8]) -> Result<(), ProtectorError> {
        Err(ProtectorError::Unavailable)
    }
    /// Idempotently delete the key `blob` is sealed under, once nothing
    /// durable holds `blob`: a changed kit the person saved, or one whose
    /// replacement was lost. `Unavailable` where the adapter has no such
    /// deletion; the caller then retires it as a saved setup kit is.
    fn retire_key(&mut self, _blob: &[u8]) -> Result<(), ProtectorError> {
        Err(ProtectorError::Unavailable)
    }
}

/// Protector failures carry no secret or handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectorError {
    Unavailable,
    Failed,
}

/// Length of the nonce prefix in the pending-setup seal framing (XChaCha20-Poly1305).
pub const PENDING_SETUP_NONCE_LEN: usize = 24;

/// Associated data for the pending-setup seal. It fixes the purpose and framing
/// version, so a blob sealed here cannot be opened under another domain or
/// version. Keep the trailing version in step with `PENDING_SETUP_VERSION`.
pub const PENDING_SETUP_SEAL_AD: &[u8] = b"BaseHero pending setup v1";

/// Seal pending-setup plaintext under a native-held 32-byte wrapping key.
///
/// Framing is the 24-byte nonce followed by the AEAD ciphertext; open must use
/// the same framing and associated data. This is shared framing, not a protector:
/// a native adapter owns the wrapping key and its storage, and only that adapter
/// decides whether a key exists.
pub fn seal_pending_setup(
    wrapping: &Secret<32>,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtectorError> {
    let (nonce, ciphertext) = crate::crypto::aead_seal(wrapping, PENDING_SETUP_SEAL_AD, plaintext)
        .map_err(|_| ProtectorError::Failed)?;
    let mut out = Vec::with_capacity(PENDING_SETUP_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob produced by [`seal_pending_setup`]. A wrong key, altered bytes,
/// a truncated blob or a future framing are all `Failed`. A missing wrapping key
/// is the adapter's `Unavailable`, never a silent regeneration here.
pub fn open_pending_setup(
    wrapping: &Secret<32>,
    blob: &[u8],
) -> Result<SecretBytes, ProtectorError> {
    if blob.len() < PENDING_SETUP_NONCE_LEN {
        return Err(ProtectorError::Failed);
    }
    let (nonce, ciphertext) = blob.split_at(PENDING_SETUP_NONCE_LEN);
    let nonce: [u8; PENDING_SETUP_NONCE_LEN] =
        nonce.try_into().map_err(|_| ProtectorError::Failed)?;
    crate::crypto::aead_open(wrapping, &nonce, PENDING_SETUP_SEAL_AD, ciphertext)
        .map_err(|_| ProtectorError::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_setup_seal_round_trips_and_rejects_tampering() {
        let wrapping = Secret::<32>::random();
        let plaintext = b"BHPEND01 pending setup material";
        let blob = seal_pending_setup(&wrapping, plaintext).expect("seal");
        assert_eq!(
            blob.len(),
            PENDING_SETUP_NONCE_LEN + plaintext.len() + 16,
            "framing is nonce plus AEAD ciphertext"
        );
        assert_ne!(
            blob.as_slice(),
            plaintext,
            "plaintext is not stored verbatim"
        );
        assert_eq!(
            open_pending_setup(&wrapping, &blob).expect("open").expose(),
            plaintext
        );

        // A different wrapping key and any altered byte are refused.
        let other = Secret::<32>::random();
        assert!(matches!(
            open_pending_setup(&other, &blob),
            Err(ProtectorError::Failed)
        ));
        for index in [0, PENDING_SETUP_NONCE_LEN, blob.len() - 1] {
            let mut tampered = blob.clone();
            tampered[index] ^= 1;
            assert!(matches!(
                open_pending_setup(&wrapping, &tampered),
                Err(ProtectorError::Failed)
            ));
        }
        assert!(matches!(
            open_pending_setup(&wrapping, &blob[..PENDING_SETUP_NONCE_LEN - 1]),
            Err(ProtectorError::Failed)
        ));
        assert!(matches!(
            open_pending_setup(&wrapping, &blob[..PENDING_SETUP_NONCE_LEN]),
            Err(ProtectorError::Failed)
        ));

        // A fresh nonce makes two seals of the same plaintext differ.
        assert_ne!(seal_pending_setup(&wrapping, plaintext).unwrap(), blob);
    }
}
