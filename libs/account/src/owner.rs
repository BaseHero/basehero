//! Account owner: durable verification, a generation-bound capability, and the
//! interrupted first-device setup state machine. Not WebView-visible.
//!
//! The owner is the only component that turns persisted signed bytes into
//! authority. It replays original history against the remembered head, refuses
//! to regenerate identity when the native key is missing, and mints an opaque
//! offline-authority capability only for an active device with ready materials.
//! Reaching a hosted verdict is a separate, unimplemented gate.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::SecretBytes;
use crate::history::{
    AccountId, Control, DeviceId, DevicePublicKeys, Error, Head, SigningRequest, VerifiedAccount,
};
use crate::journal::{
    AcceptedPersonal, AccountJournal, HistoryCursor, JournalError, JournaledDevice,
    JournaledProjection, KeyringRow, PENDING_SETUP_VERSION, PendingSetupProtector,
    PendingSetupRecord, ProtectorError, SetupStage, StagedAdmission,
};
use crate::platform::{DeviceKeyStore, KeyStoreError, StoredDevice};
use crate::recovery::{
    PASSWORD_CHECK_SIZE, Password, PasswordCheck, RecoveryCode, RecoveryKeys, make_password_check,
    prepare_record,
};
use crate::{AccountEvent, device_auth, local_seal, personal};

pub mod staging;

const PENDING_MAGIC: &[u8; 8] = b"BHPEND01";
const MAX_BLOB_PART: usize = 1 << 20;
const MAX_CONTROLS: usize = 64;

/// Shared invalidation counter. Locking, a verified removal, a sticky stop and a
/// native key invalidation advance it; a capability is bound to one value.
#[derive(Clone)]
pub struct AccountGeneration(Arc<AtomicU64>);

impl AccountGeneration {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    pub fn current(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    /// Invalidate every capability minted at the current value.
    pub fn advance(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
    }
}

impl Default for AccountGeneration {
    fn default() -> Self {
        Self::new()
    }
}

/// What a capability authorises. This is the last verified local state, never a
/// current account-home or checker verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    OfflineLastVerified,
}

/// Opaque generation-bound authority. Not `Clone`, not a credential, and not
/// exposed to the WebView. Operations recheck it after every await.
pub struct AccountCapability {
    generation: u64,
    current_generation: AccountGeneration,
    account: AccountId,
    device: DeviceId,
    head: Head,
}

impl AccountCapability {
    pub fn account_id(&self) -> AccountId {
        self.account
    }
    pub fn device_id(&self) -> DeviceId {
        self.device
    }
    pub fn head(&self) -> Head {
        self.head
    }
    pub fn authority(&self) -> Authority {
        Authority::OfflineLastVerified
    }
    /// Check under the shared container writer guard just before COMMIT.
    pub fn is_current(&self) -> bool {
        self.generation == self.current_generation.current()
    }
}

impl std::fmt::Debug for AccountCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountCapability(..)")
    }
}

/// Why a journaled account cannot mint authority. The persisted state is never
/// rewritten and identity is never regenerated. A transient native-store failure
/// (`AuthenticationCancelled`, `StorageFailure`) is returned as
/// `OwnerError::Device` instead, so a cancelled prompt is not treated as a lost key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionReason {
    /// Persisted history failed replay against the remembered head.
    CorruptHistory,
    /// No device identity is recorded for this account.
    NoDevice,
    /// The native key is unavailable, invalidated or no longer matches the
    /// recorded identity (not a transient prompt failure).
    KeyUnavailable,
    /// The recorded device is not active in verified history (verified removal).
    DeviceNotActive,
    /// The record digest and personal publication are not both verified.
    IncompleteMaterials,
}

/// Result of activating over durable state.
#[derive(Debug)]
pub enum AccountLoad {
    Active(AccountCapability),
    /// No account is journaled on this device.
    Uninitialized,
    /// A sticky integrity stop; last verified state is retained.
    Stopped,
    AdmissionRequired(AdmissionReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerError {
    Journal(JournalError),
    /// No loaded account, or a capability bound to a stale identity.
    NotActive,
    Stopped,
    /// A capability was minted for a superseded generation, account or device.
    Stale,
    Device(KeyStoreError),
    Protector(ProtectorError),
    /// From `apply_incoming`: authenticated history contradicting this
    /// owner's, now stopped; or `Unavailable` local evidence, nothing
    /// applied and no stop.
    Invalid(Error),
    /// Incoming bytes that are not this account's next verified history
    /// (malformed, badly signed, not next, or a signed event breaking the
    /// rules). Nothing applied and no stop: a member or server cannot stop
    /// the account with them.
    Refused(Error),
    /// The next incoming event needs a newer build. Nothing applied and no
    /// stop: the account pauses until it can read it.
    Unsupported(Error),
    /// No staged admission exists for reconciliation.
    NoStagedAdmission,
}

impl From<JournalError> for OwnerError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupError {
    Journal(JournalError),
    Protector(ProtectorError),
    Device(KeyStoreError),
    Protocol(Error),
    AlreadyStarted,
    NotStarted,
    Corrupt,
    UnsupportedVersion,
    /// A reported home head does not match the exact signed bytes.
    HomeMismatch,
}

impl From<JournalError> for SetupError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<ProtectorError> for SetupError {
    fn from(error: ProtectorError) -> Self {
        Self::Protector(error)
    }
}

/// Protected-home ciphertext objects. Never serialize these as public account
/// history or WebView output; they contain no opened keys or recovery code.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingHomeObjects {
    pub record: Vec<u8>,
    pub device_seal: Vec<u8>,
    pub recovery_seal: Vec<u8>,
}

/// Resumable first-device setup summary. `submission` is the exact ordered list
/// of signed bytes to submit; `head` is the head those bytes produce.
/// A verified result, or the exact unchanged bytes to retry while the home is
/// unreachable or has not yet ordered an event at the signed position.
#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionResolution {
    Checking { event: Vec<u8> },
    Admitted { delivery: Vec<u8> },
    NotAdded,
}

/// Public signed initial account prefix, separate from protected-home objects.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialAccountPrefix {
    pub anchor: AccountId,
    pub head: Head,
    pub events: Vec<Vec<u8>>,
}

pub struct SetupStatus {
    pub stage: SetupStage,
    pub kit_saved: bool,
    pub anchor: AccountId,
    pub head: Head,
    pub submission: Vec<Vec<u8>>,
}

struct Loaded {
    account: VerifiedAccount,
    device: Option<StoredDevice>,
    stopped: bool,
}

/// Why one loaded projection did not reach its verified target.
enum CatchUp {
    /// A newer generation owns this journal; nothing was adopted.
    Stale,
    /// Local evidence could not answer now; the same view may be retried.
    Unavailable,
    /// The durable target is not the caller's required head.
    Moved,
    /// A candidate for the target was contradicted by verified evidence.
    CorruptHistory,
    /// The journal could not read or record the projection.
    Journal(JournalError),
}

/// How staging reports a projection that could not be refreshed. Only local
/// evidence that could not answer, or a transient journal failure while
/// repairing it, is retryable; a moved head, damaged history or another
/// account would refuse the same bytes again.
fn refresh_error(outcome: CatchUp) -> OwnerError {
    match outcome {
        CatchUp::Stale => OwnerError::Stale,
        CatchUp::Unavailable | CatchUp::Journal(JournalError::Storage) => {
            OwnerError::Invalid(Error::Unavailable)
        }
        CatchUp::Moved => OwnerError::Invalid(Error::WrongPredecessor),
        CatchUp::CorruptHistory => JournalError::Corrupt.into(),
        CatchUp::Journal(error) => error.into(),
    }
}

/// What a device's second key signs as its half of the cosigned event
/// whose unsigned bytes are `unsigned`, as `CosigningRequest` asks it to.
pub fn cosigned_device_message(unsigned: &[u8]) -> Vec<u8> {
    crate::history::cosign_bytes(crate::history::ROLE_DEVICE, unsigned)
}

pub struct AccountOwner<J, S, P> {
    journal: J,
    store: S,
    protector: P,
    generation: AccountGeneration,
    loaded: Option<Loaded>,
}

impl<J, S, P> AccountOwner<J, S, P>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    pub fn new(journal: J, store: S, protector: P, generation: AccountGeneration) -> Self {
        Self {
            journal,
            store,
            protector,
            generation,
            loaded: None,
        }
    }

    pub fn generation(&self) -> AccountGeneration {
        self.generation.clone()
    }

    /// Load durable state and, only for an active key with ready materials, mint
    /// offline authority. A stop, removal, missing key or corrupt history never
    /// regenerates identity or clears the remembered head.
    pub async fn activate(&mut self) -> Result<AccountLoad, OwnerError> {
        // A durable no-code stage may precede the journal commit. Retire the
        // code-bearing key again after a crash, before minting authority.
        if let Some(pending) = self.journal.pending_setup()?
            && pending.kit_saved
        {
            self.protector
                .retire_kit_key(&pending.blob)
                .map_err(OwnerError::Protector)?;
        }
        if !self.journal.has_account()? {
            self.loaded = None;
            return Ok(AccountLoad::Uninitialized);
        }
        let generation = self.generation.current();
        let checked = match self.journal.load_projection() {
            Ok(p) => p,
            Err(JournalError::Corrupt) => {
                self.loaded = None;
                self.fence()?;
                return Ok(AccountLoad::AdmissionRequired(
                    AdmissionReason::CorruptHistory,
                ));
            }
            Err(e) => return Err(e.into()),
        };
        let (mut account, stopped) = if let Some(checked) = checked {
            match self.catch_up_projection(checked, generation, None) {
                Ok(checked) => (checked.account, checked.stopped),
                Err(CatchUp::Stale) => return Err(OwnerError::Stale),
                Err(CatchUp::Unavailable) => {
                    return Err(OwnerError::Invalid(Error::Unavailable));
                }
                Err(CatchUp::Journal(error)) => return Err(error.into()),
                Err(CatchUp::CorruptHistory | CatchUp::Moved) => {
                    self.loaded = None;
                    self.fence()?;
                    return Ok(AccountLoad::AdmissionRequired(
                        AdmissionReason::CorruptHistory,
                    ));
                }
            }
        } else {
            let Some(record) = self.journal.load()? else {
                self.loaded = None;
                return Ok(AccountLoad::Uninitialized);
            };
            let account = match self.view_at(record.anchor, record.head, record.head.position) {
                Ok(account) => account,
                Err(_) => {
                    self.loaded = None;
                    self.fence()?;
                    return Ok(AccountLoad::AdmissionRequired(
                        AdmissionReason::CorruptHistory,
                    ));
                }
            };
            (account, record.stopped)
        };

        // Do not impose an observation made at the target head on older
        // originals while a damaged/stale projection rebuilds its prefix.
        // Bind the floor only after verified replay reaches that head.
        if let Some(floor) = self.journal.observed_account_floor()? {
            account.remember_observation_floor(floor);
        }

        // A persisted stop stays stopped and keeps the last verified state. It is
        // checked before any device or native work.
        if stopped {
            self.loaded = Some(Loaded {
                account,
                device: None,
                stopped: true,
            });
            self.fence()?;
            return Ok(AccountLoad::Stopped);
        }

        let Some(identity) = self.journal.device()? else {
            self.loaded = None;
            self.fence()?;
            return Ok(AccountLoad::AdmissionRequired(AdmissionReason::NoDevice));
        };
        let expected = stored(&identity);
        let device_id = expected.keys.id();

        // The native load may prompt. A lock, stop or invalidation that advances
        // the shared generation while it is in flight must not mint authority.
        if self.generation.current() != generation {
            return Err(OwnerError::Stale);
        }
        match self.store.load_matching(&expected).await {
            Ok(()) => {}
            Err(error) => {
                self.loaded = Some(Loaded {
                    account,
                    device: Some(expected),
                    stopped: false,
                });
                self.fence()?;
                return match error {
                    KeyStoreError::AuthenticationCancelled | KeyStoreError::StorageFailure => {
                        Err(OwnerError::Device(error))
                    }
                    _ => Ok(AccountLoad::AdmissionRequired(
                        AdmissionReason::KeyUnavailable,
                    )),
                };
            }
        }
        if self.generation.current() != generation {
            self.loaded = None;
            return Err(OwnerError::Stale);
        }
        if account.active_device(device_id).is_err() {
            self.loaded = Some(Loaded {
                account,
                device: Some(expected),
                stopped: false,
            });
            self.fence()?;
            return Ok(AccountLoad::AdmissionRequired(
                AdmissionReason::DeviceNotActive,
            ));
        }
        if !account.materials_ready().unwrap_or(false) {
            self.loaded = Some(Loaded {
                account,
                device: Some(expected),
                stopped: false,
            });
            self.fence()?;
            return Ok(AccountLoad::AdmissionRequired(
                AdmissionReason::IncompleteMaterials,
            ));
        }

        let capability = AccountCapability {
            // The generation captured before the native load, never a fresh read:
            // a concurrent advance after the recheck must leave this capability
            // stale, not be absorbed into freshly-minted authority.
            generation,
            current_generation: self.generation.clone(),
            account: account.id(),
            device: device_id,
            head: account.head(),
        };
        self.loaded = Some(Loaded {
            account,
            device: Some(expected),
            stopped: false,
        });
        Ok(AccountLoad::Active(capability))
    }

    /// Drop in-memory authority. Durable state is untouched.
    pub fn lock(&mut self) -> Result<(), OwnerError> {
        self.loaded = None;
        self.fence()
    }

    fn fence(&self) -> Result<(), OwnerError> {
        self.journal.fence(|| {
            self.generation.advance();
        })?;
        Ok(())
    }

    /// Apply incoming ordered history. Valid input commits the original bytes and
    /// the resulting head together. Only authenticated contradiction (a fork)
    /// commits a sticky stop, keeping the last good head and bytes; anything
    /// else invalid or unreadable is refused or paused with nothing applied.
    pub fn apply_incoming(&mut self, events: &[&[u8]]) -> Result<Head, OwnerError> {
        let events: Vec<_> = events.iter().map(|bytes| (*bytes, None)).collect();
        self.apply_incoming_timed(&events)
    }

    /// Apply originals with caller-verified confirmation bounds and exact proof
    /// bytes. The caller verifies confirmation signatures and their binding to
    /// each original; this layer verifies account history and persists evidence.
    #[allow(clippy::type_complexity)] // Keep each original paired with its exact evidence.
    pub fn apply_incoming_timed(
        &mut self,
        events: &[(&[u8], Option<(crate::trust::ConfirmedTime, Vec<u8>)>)],
    ) -> Result<Head, OwnerError> {
        let (anchor, device_id) = {
            let loaded = self.loaded.as_ref().ok_or(OwnerError::NotActive)?;
            if loaded.stopped {
                return Err(OwnerError::Stopped);
            }
            (
                loaded.account.id(),
                loaded.device.as_ref().map(|d| d.keys.id()),
            )
        };
        let last_head = self.loaded.as_ref().expect("checked").account.head();
        // No successor means no projection copy, no SQLite write and no fence.
        if events.is_empty() {
            return Ok(last_head);
        }
        // Setup may still receive the home's times; nothing builds on it first.
        if last_head.position.saturating_add(events.len() as u64) > 3
            && self.journal.pending_setup()?.is_some()
        {
            return Err(OwnerError::Invalid(Error::Unavailable));
        }
        if events
            .iter()
            .any(|(_, evidence)| evidence.as_ref().is_some_and(|(_, proof)| proof.is_empty()))
        {
            return Err(OwnerError::Refused(Error::MissingTime));
        }
        let timed: Vec<_> = events
            .iter()
            .map(|(bytes, evidence)| (*bytes, evidence.as_ref().map(|(time, _)| *time)))
            .collect();
        let originals: Vec<_> = events.iter().map(|(bytes, _)| *bytes).collect();
        let evidence: Vec<_> = events
            .iter()
            .map(|(_, evidence)| evidence.clone())
            .collect();
        let candidate = (|| {
            let mut candidate = self.loaded.as_ref().expect("checked").account.clone();
            let mut alerts = Vec::new();
            for (original, time) in &timed {
                if let Some(own) = device_id {
                    alerts.extend(crate::alerts::apply(&mut candidate, original, *time, own)?);
                } else {
                    candidate.apply_timed(original, *time)?;
                }
            }
            Ok::<_, Error>((candidate, alerts))
        })();
        match candidate {
            Ok((candidate, alerts)) => {
                let head = candidate.head();
                let removed = device_id
                    .map(|id| candidate.active_device(id).is_err())
                    .unwrap_or(false);
                if let Err(error) = self.journal.commit_timed_alerted_fenced(
                    anchor,
                    &originals,
                    &evidence,
                    head,
                    false,
                    Some(&candidate),
                    &alerts,
                    |success| {
                        if !success || removed {
                            self.generation.advance();
                        }
                    },
                ) {
                    if error == JournalError::MissingTime {
                        return Err(OwnerError::Refused(Error::MissingTime));
                    }
                    self.loaded.as_mut().expect("checked").stopped = true;
                    if error == JournalError::TimeRegressed {
                        self.journal.commit_projected_fenced(
                            anchor,
                            &[],
                            last_head,
                            true,
                            None,
                            |_| {
                                self.generation.advance();
                            },
                        )?;
                        return Err(OwnerError::Invalid(Error::TimeRegressed));
                    }
                    return Err(error.into());
                }
                match self.journal.rebase_projection(candidate) {
                    Ok(account) => self.loaded.as_mut().expect("checked").account = account,
                    Err(error) => {
                        // Commit succeeded but this owner cannot publish an indexed
                        // view. Reload before use; never publish a partial overlay.
                        self.loaded = None;
                        return Err(error.into());
                    }
                }
                Ok(head)
            }
            Err(Error::Unavailable) => Err(OwnerError::Invalid(Error::Unavailable)),
            Err(error @ (Error::UnsupportedVersion | Error::UnsupportedControl)) => {
                Err(OwnerError::Unsupported(error))
            }
            Err(error) if !matches!(error, Error::Fork | Error::TimeRegressed) => {
                Err(OwnerError::Refused(error))
            }
            Err(error) => {
                // Stop the session before the durable write: a storage failure
                // must not leave this owner active with usable capabilities.
                if let Some(loaded) = self.loaded.as_mut() {
                    loaded.stopped = true;
                }
                self.journal
                    .commit_projected_fenced(anchor, &[], last_head, true, None, |_| {
                        self.generation.advance();
                    })?;
                Err(OwnerError::Invalid(error))
            }
        }
    }

    /// Record deadlines established by a caller-verified fresh accepted-head
    /// observation, even when no new account entry was ordered. `time` must be
    /// the accepted head's verified lower/upper bounds, never the device clock
    /// or server prose. The matching head prevents stale observations.
    pub fn observe_accepted_alerts(
        &mut self,
        capability: &AccountCapability,
        head: Head,
        time: crate::trust::ConfirmedTime,
    ) -> Result<(), OwnerError> {
        let state = self.verified(capability)?;
        if state.head() != head
            || time.latest_ms < time.earliest_ms
            || state
                .confirmed_time(head.position)
                .map_err(OwnerError::Invalid)?
                .is_some_and(|last| {
                    time.earliest_ms < last.earliest_ms || time.latest_ms < last.latest_ms
                })
        {
            return Err(OwnerError::Invalid(Error::Unavailable));
        }
        let pending = state.pending_removals(0);
        let alerts =
            crate::alerts::deadlines(&pending, state, capability.device_id(), time.earliest_ms)
                .map_err(OwnerError::Invalid)?;
        self.journal
            .record_observed_alerts(state.id(), head, time.earliest_ms, &alerts)?;
        self.loaded
            .as_mut()
            .expect("checked")
            .account
            .remember_observation_floor(time.earliest_ms);
        self.check(capability)?;
        Ok(())
    }

    /// Borrow only checked native identity, never exposing it to the WebView.
    pub fn verified(&self, capability: &AccountCapability) -> Result<&VerifiedAccount, OwnerError> {
        self.check(capability)?;
        Ok(&self.loaded.as_ref().expect("checked").account)
    }

    /// Build a device admission request against the verified, active owner.
    /// The caller must still obtain the exact second-key signature and order it.
    pub fn prepare_add_device(
        &self,
        capability: &AccountCapability,
        keys: DevicePublicKeys,
    ) -> Result<SigningRequest, OwnerError> {
        self.check(capability)?;
        if self.journal.staged_admission()?.is_some() {
            return Err(OwnerError::Journal(JournalError::StagedAdmissionExists));
        }
        let loaded = self.loaded.as_ref().expect("checked");
        loaded
            .account
            .add_device(capability.device, keys)
            .map_err(OwnerError::Invalid)
    }

    /// Sign a private delivery to the device in an exact signed pending add.
    /// The session must remain live through durable staging of add and seal;
    /// this offline operation does not itself prove hosted admission.
    pub async fn seal_personal_for_device(
        &mut self,
        capability: &AccountCapability,
        personal_key: &personal::PersonalKey,
        recipient: &DevicePublicKeys,
        admission: &AccountEvent,
    ) -> Result<Vec<u8>, OwnerError> {
        self.check(capability)?;
        let loaded = self.loaded.as_ref().expect("checked");
        let state = loaded.account.clone();
        let device = loaded.device.clone().ok_or(OwnerError::NotActive)?;
        let result = personal::seal_for_device(
            &state,
            personal_key,
            &device,
            recipient,
            admission,
            &mut self.store,
        )
        .await;
        self.check(capability)?;
        result.map_err(OwnerError::Invalid)
    }

    /// Advance one loaded projection to its durable target, adopting only what
    /// the journal verified. A required `expected` target (staging) also fences
    /// a head that moved while the caller prepared; `activate` follows the
    /// target it reads each round and passes `None`.
    fn catch_up_projection(
        &mut self,
        mut checked: JournaledProjection,
        generation: u64,
        expected: Option<Head>,
    ) -> Result<JournaledProjection, CatchUp> {
        loop {
            if self.generation.current() != generation {
                return Err(CatchUp::Stale);
            }
            if expected.is_some_and(|expected| checked.target != expected) {
                return Err(CatchUp::Moved);
            }
            if checked.account.head() == checked.target {
                return Ok(checked);
            }
            let cursor = HistoryCursor {
                anchor: checked.account.id(),
                cut: checked.target,
                next_position: checked.account.head().position + 1,
            };
            let Some(page) = self
                .journal
                .history_prefix(Some(cursor), 256)
                .map_err(CatchUp::Journal)?
            else {
                return Err(CatchUp::Journal(JournalError::Corrupt));
            };
            if page.times.len() != page.events.len() {
                return Err(CatchUp::Journal(JournalError::Corrupt));
            }
            let timed: Vec<_> = page
                .events
                .iter()
                .zip(&page.times)
                .map(|(bytes, time)| (bytes.as_slice(), *time))
                .collect();
            let candidate = match checked.account.applied_batch_timed(&timed) {
                Ok(candidate) => candidate,
                Err(Error::Unavailable) => return Err(CatchUp::Unavailable),
                Err(_) => return Err(CatchUp::CorruptHistory),
            };
            if self.generation.current() != generation {
                return Err(CatchUp::Stale);
            }
            self.journal
                .advance_projection(&candidate)
                .map_err(CatchUp::Journal)?;
            std::thread::yield_now();
            let Some(next) = self.journal.load_projection().map_err(CatchUp::Journal)? else {
                return Err(CatchUp::Journal(JournalError::Corrupt));
            };
            checked = next;
        }
    }

    /// Re-read the durable projection after the loaded view's local index
    /// stopped answering, or once another process committed history past
    /// it. It replaces the loaded view only when the durable
    /// target is still `expected`, the verified head the request was prepared
    /// at, keeping the accepted-head observation floor. A moved head or another
    /// account refuses without retry; damaged history refuses; a transient
    /// journal failure to complete the repair reports unavailability.
    pub fn re_read_projection(&mut self, expected: Head) -> Result<(), OwnerError> {
        let generation = self.generation.current();
        let (anchor, floor) = {
            let loaded = self.loaded.as_ref().ok_or(OwnerError::NotActive)?;
            (
                loaded.account.id(),
                loaded.account.timeline.observed_earliest_ms,
            )
        };
        let Some(checked) = self
            .journal
            .load_projection()
            .map_err(|error| refresh_error(CatchUp::Journal(error)))?
        else {
            return Err(JournalError::Corrupt.into());
        };
        if checked.account.id() != anchor {
            return Err(OwnerError::Stale);
        }
        let mut checked = self
            .catch_up_projection(checked, generation, Some(expected))
            .map_err(refresh_error)?;
        // A rebuild must not drop an observation made at the target head.
        if let Some(floor) = self
            .journal
            .observed_account_floor()
            .map_err(|error| refresh_error(CatchUp::Journal(error)))?
        {
            checked.account.remember_observation_floor(floor);
        }
        if let Some(floor) = floor {
            checked.account.remember_observation_floor(floor);
        }
        let loaded = self.loaded.as_mut().ok_or(OwnerError::NotActive)?;
        loaded.stopped = checked.stopped;
        loaded.account = checked.account;
        Ok(())
    }

    /// Stage one exact signed add before network submission. This is called by
    /// the live pairing session only after its request and signature match.
    pub fn stage_signed_admission(
        &mut self,
        capability: &AccountCapability,
        recipient: &DevicePublicKeys,
        signed: &[u8],
        delivery: &[u8],
    ) -> Result<(), OwnerError> {
        self.check(capability)?;
        let head = self.loaded.as_ref().expect("checked").account.head();
        let request = match self.prepare_add_device(capability, recipient.clone()) {
            Ok(request) => request,
            // A projection rewrite may leave the loaded view's index at an
            // older epoch over the same verified head while the approval is
            // signed and sealed. Re-read it once: the unchanged head still
            // decides that this request applies; a moved head refuses.
            Err(OwnerError::Invalid(Error::Unavailable)) => {
                self.re_read_projection(head)?;
                self.prepare_add_device(capability, recipient.clone())?
            }
            Err(error) => return Err(error),
        };
        if signed.len() != request.signing_bytes().len() + 64
            || !signed.starts_with(request.signing_bytes())
            || delivery.is_empty()
        {
            return Err(OwnerError::Invalid(Error::Malformed));
        }
        let signature = signed[request.signing_bytes().len()..]
            .try_into()
            .map_err(|_| OwnerError::Invalid(Error::Malformed))?;
        request.finish(signature).map_err(OwnerError::Invalid)?;
        let head = self.loaded.as_ref().expect("checked").account.head();
        let position = head
            .position
            .checked_add(1)
            .ok_or(OwnerError::Invalid(Error::PositionOverflow))?;
        self.journal.insert_staged_admission(&StagedAdmission {
            position,
            previous: head.hash,
            event: signed.to_vec(),
            delivery: delivery.to_vec(),
        })?;
        Ok(())
    }

    /// On restart or an unknown home result, use only verified ordered history.
    /// A missing/unreachable successor keeps the original row and exact bytes;
    /// no control-key signature is requested on this path.
    pub fn reconcile_staged_admission(
        &mut self,
        incoming: Option<&[&[u8]]>,
    ) -> Result<AdmissionResolution, OwnerError> {
        let staged = self
            .journal
            .staged_admission()?
            .ok_or(OwnerError::NoStagedAdmission)?;
        let loaded = self.loaded.as_ref().ok_or(OwnerError::NotActive)?;
        if loaded.stopped {
            return Err(OwnerError::Stopped);
        }
        if staged.position <= 1 {
            return Err(OwnerError::Journal(JournalError::Corrupt));
        }
        let head = loaded.account.head();
        if head.position < staged.position
            && head.position == staged.position - 1
            && head.hash != staged.previous
        {
            return Err(OwnerError::Journal(JournalError::Corrupt));
        }
        // A crash may have landed the verified event but not cleared the row.
        // Do not reapply a duplicate successor from a retried home response.
        if head.position < staged.position
            && let Some(events) = incoming
            && !events.is_empty()
        {
            self.apply_incoming(events)?;
        }
        // The owner verified its prefix on activation and each committed
        // successor afterward. Its per-position signed-event hashes let us
        // compare the staged original bytes without loading or replaying history.
        let verified = &self.loaded.as_ref().expect("checked").account;
        if verified.head().position < staged.position {
            return Ok(AdmissionResolution::Checking {
                event: staged.event,
            });
        }
        let outcome = if verified
            .verified_event_at(staged.position, &staged.event)
            .map_err(OwnerError::Invalid)?
        {
            AdmissionResolution::Admitted {
                delivery: staged.delivery.clone(),
            }
        } else {
            AdmissionResolution::NotAdded
        };
        self.journal.clear_staged_admission(&staged)?;
        Ok(outcome)
    }

    /// Scanner status when this owner has already verified the account history.
    /// A fresh scanner without an owner must use pairing::scanner_status instead.
    pub fn scanner_status(
        &self,
    ) -> Result<crate::pairing::ScannerStatus, crate::pairing::PairError> {
        let loaded = self
            .loaded
            .as_ref()
            .ok_or(crate::pairing::PairError::WrongContext)?;
        if loaded.stopped {
            return Err(crate::pairing::PairError::History);
        }
        let device = loaded
            .device
            .as_ref()
            .ok_or(crate::pairing::PairError::WrongContext)?;
        crate::pairing::scanner_status_verified(&loaded.account, &device.keys)
    }

    pub fn staged_admission(&self) -> Result<Option<StagedAdmission>, OwnerError> {
        self.journal.staged_admission().map_err(OwnerError::from)
    }

    /// Build an immediate self-removal request for this active device. It does
    /// not submit, order or apply anything.
    pub fn prepare_remove_self(
        &self,
        capability: &AccountCapability,
    ) -> Result<SigningRequest, OwnerError> {
        self.check(capability)?;
        let loaded = self.loaded.as_ref().expect("checked");
        loaded
            .account
            .remove_self(capability.device)
            .map_err(OwnerError::Invalid)
    }

    /// Complete a control request through the native store. The generation is
    /// checked before and after the await: a lock, removal, stop or key
    /// invalidation that lands while a prompt is open must discard the result.
    pub async fn sign_control(
        &mut self,
        capability: &AccountCapability,
        request: &SigningRequest,
    ) -> Result<AccountEvent, OwnerError> {
        self.check(capability)?;
        let device = self
            .loaded
            .as_ref()
            .and_then(|loaded| loaded.device.clone())
            .ok_or(OwnerError::NotActive)?;
        let event = request
            .sign_with(&device, &mut self.store)
            .await
            .map_err(OwnerError::Device)?;
        self.check(capability)?;
        Ok(event)
    }

    /// Complete a removal-now through the native store: `recovery` is the
    /// recovery key's half, checked before anything is asked of the person;
    /// this device's second key then signs its half, under the same
    /// confirmation and generation checks as [`Self::sign_control`].
    pub async fn sign_cosigned(
        &mut self,
        capability: &AccountCapability,
        request: &crate::CosigningRequest,
        recovery: [u8; 64],
    ) -> Result<AccountEvent, OwnerError> {
        self.check(capability)?;
        crate::crypto::verify(
            request.recovery_key(),
            &request.recovery_signing_bytes(),
            &recovery,
        )
        .map_err(|_| OwnerError::Invalid(Error::BadSignature))?;
        let device = self
            .loaded
            .as_ref()
            .and_then(|loaded| loaded.device.clone())
            .ok_or(OwnerError::NotActive)?;
        if device.keys.control() != request.device_key() {
            return Err(OwnerError::Device(KeyStoreError::WrongKey));
        }
        self.store
            .load_matching(&device)
            .await
            .map_err(OwnerError::Device)?;
        let signature = self
            .store
            .sign_control(device.handle.clone(), request.device_signing_bytes())
            .await
            .map_err(OwnerError::Device)?;
        self.check(capability)?;
        request
            .finish(signature, recovery)
            .map_err(OwnerError::Invalid)
    }

    /// Complete a base control (such as the base copy of an account change)
    /// with the native second key, under the same confirmation and generation
    /// checks as [`Self::sign_control`]. Only base-event originals are
    /// signed here; account events go through their own request.
    pub async fn sign_base_control(
        &mut self,
        capability: &AccountCapability,
        expected: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64], OwnerError> {
        const BASE_ORIGINAL: &[u8] = b"bh/original-envelope/v1\0";
        self.check(capability)?;
        if !message.starts_with(BASE_ORIGINAL) {
            return Err(OwnerError::Invalid(Error::Malformed));
        }
        self.sign_native(capability, message, Some(expected)).await
    }

    /// Ordinary native device signing, not control approval. No database guard
    /// is held during either native operation; late results are discarded.
    pub async fn sign_content(
        &mut self,
        capability: &AccountCapability,
        message: &[u8],
    ) -> Result<[u8; 64], OwnerError> {
        self.sign_native(capability, message, None).await
    }

    /// `expected` selects control signing and binds it to the producer's key;
    /// ordinary signing has no separate producer key to compare.
    async fn sign_native(
        &mut self,
        capability: &AccountCapability,
        message: &[u8],
        expected: Option<&[u8; 32]>,
    ) -> Result<[u8; 64], OwnerError> {
        self.check(capability)?;
        let device = self
            .loaded
            .as_ref()
            .and_then(|l| l.device.clone())
            .ok_or(OwnerError::NotActive)?;
        let key = match expected {
            Some(expected) if device.keys.control() != expected => {
                return Err(OwnerError::Device(KeyStoreError::WrongKey));
            }
            Some(_) => device.keys.control(),
            None => device.keys.signing(),
        };
        let loaded = self.store.load_matching(&device).await;
        self.check(capability)?;
        loaded.map_err(OwnerError::Device)?;
        let signature = if expected.is_some() {
            self.store
                .sign_control(device.handle, message.to_vec())
                .await
        } else {
            self.store
                .sign_content(device.handle, message.to_vec())
                .await
        };
        self.check(capability)?;
        let signature = signature.map_err(OwnerError::Device)?;
        crate::crypto::verify(key, message, &signature)
            .map_err(|_| OwnerError::Invalid(Error::BadSignature))?;
        Ok(signature)
    }

    /// Prove ordinary device-key possession for a protected session's binding
    /// and fresh challenge. This is not current hosted authority: the caller
    /// must check it independently and consume the challenge in that session.
    pub async fn prove_sync_device(
        &mut self,
        capability: &AccountCapability,
        context: device_auth::Context,
    ) -> Result<device_auth::Proof, OwnerError> {
        let request =
            device_auth::prepare(self.verified(capability)?, capability.device_id(), context)
                .map_err(OwnerError::Invalid)?;
        let signature = self.sign_content(capability, request.message()).await?;
        request.finish(signature).map_err(OwnerError::Invalid)
    }

    /// As [`Self::prove_sync_device`], at an earlier verified head of this
    /// account: one an account home that has not caught up yet still holds.
    /// The view at `position` is replayed from the journal's verified prefix.
    /// A position past the current head, or one this device was not active
    /// at, is refused before anything is signed.
    pub async fn prove_sync_device_at(
        &mut self,
        capability: &AccountCapability,
        position: u64,
        context: device_auth::Context,
    ) -> Result<device_auth::Proof, OwnerError> {
        let current = self.verified(capability)?;
        let head = current.head();
        let view = if position == head.position {
            current.clone()
        } else if position == 0 || position > head.position {
            return Err(OwnerError::Invalid(Error::InvalidCredentials));
        } else {
            self.view_at(current.id(), head, position)?
        };
        let request = device_auth::prepare(&view, capability.device_id(), context)
            .map_err(OwnerError::Invalid)?;
        let signature = self.sign_content(capability, request.message()).await?;
        request.finish(signature).map_err(OwnerError::Invalid)
    }

    /// The account at an earlier verified `position` (or the current head),
    /// replayed from the journal's original history.
    pub fn verified_at(
        &self,
        capability: &AccountCapability,
        position: u64,
    ) -> Result<VerifiedAccount, OwnerError> {
        let current = self.verified(capability)?;
        let head = current.head();
        if position == head.position {
            return Ok(current.clone());
        }
        if position == 0 || position > head.position {
            return Err(OwnerError::Invalid(Error::InvalidCredentials));
        }
        self.view_at(current.id(), head, position)
    }

    /// After activation found this device no longer active in its own
    /// verified history: its id and the newest view of that history in which
    /// it still was. `None` while it is active, if it never was, or if no
    /// such history is loaded. Grants no authority; only a starting point
    /// from which public evidence of the removal can be checked.
    pub fn last_member_view(&self) -> Result<Option<(DeviceId, VerifiedAccount)>, OwnerError> {
        let Some(Loaded {
            account,
            device: Some(device),
            stopped: false,
        }) = self.loaded.as_ref()
        else {
            return Ok(None);
        };
        let id = device.keys.id();
        if account.active_device(id).is_ok() {
            return Ok(None);
        }
        let (anchor, head) = (account.id(), account.head());
        let mut cursor = Some(HistoryCursor {
            anchor,
            cut: head,
            next_position: 1,
        });
        let (mut events, mut times) = (Vec::new(), Vec::new());
        while let Some(next) = cursor {
            let page = self
                .journal
                .history_prefix(Some(next), 256)?
                .ok_or(JournalError::Corrupt)?;
            if page.times.len() != page.events.len() {
                return Err(JournalError::Corrupt.into());
            }
            times.extend(page.times);
            events.extend(page.events);
            cursor = page.next;
        }
        if events.len() as u64 != head.position {
            return Err(JournalError::Corrupt.into());
        }
        let timed: Vec<_> = events
            .iter()
            .zip(times)
            .map(|(bytes, time)| (bytes.as_slice(), time))
            .collect();
        let prefix = |len: usize| {
            VerifiedAccount::replay_timed(
                anchor,
                &timed[..len],
                Head {
                    position: len as u64,
                    hash: crate::crypto::hash(timed[len - 1].0),
                },
            )
            .map_err(OwnerError::Invalid)
        };
        // One replay, entry by entry, to the last entry it was a member at.
        let mut view = prefix(1)?;
        let mut member = view.active_device(id).is_ok().then_some(1);
        for (index, entry) in timed.iter().enumerate().skip(1) {
            view = view
                .applied_batch_timed_with_outcomes(std::slice::from_ref(entry))
                .map_err(OwnerError::Invalid)?
                .0;
            if view.active_device(id).is_ok() {
                member = Some(index + 1);
            }
        }
        if view.head() != head {
            return Err(JournalError::Corrupt.into());
        }
        member
            .map(|len| prefix(len).map(|view| (id, view)))
            .transpose()
    }

    // ---- A device joining by QR ----

    /// Prove possession of this device's journaled ordinary key at `head` of
    /// `account`, the head the showing device reported, before this device
    /// holds any of its history. Nothing here is verified: the service checks
    /// the proof against its own verified history, and admission is only the
    /// history this device then reads and verifies itself. Refused for a
    /// journal that already holds another account.
    pub async fn prove_joining(
        &mut self,
        account: AccountId,
        head: Head,
        context: device_auth::Context,
    ) -> Result<device_auth::Proof, OwnerError> {
        if let Some(stored) = self.journal.load()?
            && stored.anchor != account
        {
            return Err(OwnerError::Stale);
        }
        let identity = self.journal.device()?.ok_or(OwnerError::NotActive)?;
        let device = stored(&identity);
        self.store
            .load_matching(&device)
            .await
            .map_err(OwnerError::Device)?;
        let request = device_auth::prepare_joining(account, &device.keys, head, context);
        let signature = self
            .store
            .sign_content(device.handle.clone(), request.message().to_vec())
            .await
            .map_err(OwnerError::Device)?;
        request.finish(signature).map_err(OwnerError::Invalid)
    }

    /// Commit the account history a joining device read, verified here from
    /// `anchor` (the code's account): original signed bytes from genesis, in
    /// which this device's journaled keys are active exactly. Anything else
    /// is refused and nothing is kept. A journal that already holds this
    /// account (an interrupted earlier admission) is kept as it is.
    pub fn adopt_joined(
        &mut self,
        anchor: AccountId,
        history: &[&[u8]],
    ) -> Result<Head, OwnerError> {
        let identity = self.journal.device()?.ok_or(OwnerError::NotActive)?;
        if let Some(stored) = self.journal.load()? {
            if stored.anchor != anchor {
                return Err(OwnerError::Stale);
            }
            return Ok(stored.head);
        }
        let (genesis, rest) = history
            .split_first()
            .ok_or(OwnerError::Invalid(Error::TruncatedHistory))?;
        let mut view =
            VerifiedAccount::from_genesis(anchor, genesis).map_err(OwnerError::Invalid)?;
        view.apply_batch(rest).map_err(OwnerError::Invalid)?;
        if view
            .active_device(identity.keys.id())
            .map_err(OwnerError::Invalid)?
            != &identity.keys
        {
            return Err(OwnerError::Invalid(Error::NotActive));
        }
        self.journal
            .commit_verified(anchor, history, view.head(), false)?;
        Ok(view.head())
    }

    /// `adopt_joined` for history read from the network: each original after
    /// the genesis carries the caller-verified confirmed time and exact proof
    /// bytes, committed with it from the first commit. A missing proof
    /// refuses with nothing kept. A journal that already holds this account
    /// (an interrupted earlier admission) is kept as it is, only if it holds
    /// these originals with these times; one committed without them, or with
    /// others, is `Stale`, and nothing is overwritten.
    #[allow(clippy::type_complexity)] // Keep each original paired with its exact evidence.
    pub fn adopt_joined_timed(
        &mut self,
        anchor: AccountId,
        history: &[(&[u8], Option<(crate::trust::ConfirmedTime, Vec<u8>)>)],
    ) -> Result<Head, OwnerError> {
        let identity = self.journal.device()?.ok_or(OwnerError::NotActive)?;
        let ((genesis, untimed), rest) = history
            .split_first()
            .ok_or(OwnerError::Invalid(Error::TruncatedHistory))?;
        if untimed.is_some() {
            return Err(OwnerError::Invalid(Error::Malformed));
        }
        if rest
            .iter()
            .any(|(_, evidence)| evidence.as_ref().is_none_or(|(_, proof)| proof.is_empty()))
        {
            return Err(OwnerError::Refused(Error::MissingTime));
        }
        if let Some(stored) = self.journal.load()? {
            if stored.anchor != anchor || !self.holds_timed(&stored, history)? {
                return Err(OwnerError::Stale);
            }
            return Ok(stored.head);
        }
        let mut view =
            VerifiedAccount::from_genesis(anchor, genesis).map_err(OwnerError::Invalid)?;
        for (original, evidence) in rest {
            view.apply_timed(original, evidence.as_ref().map(|(time, _)| *time))
                .map_err(OwnerError::Invalid)?;
        }
        if view
            .active_device(identity.keys.id())
            .map_err(OwnerError::Invalid)?
            != &identity.keys
        {
            return Err(OwnerError::Invalid(Error::NotActive));
        }
        let originals: Vec<_> = history.iter().map(|(original, _)| *original).collect();
        let evidence: Vec<_> = history
            .iter()
            .map(|(_, evidence)| evidence.clone())
            .collect();
        self.journal.commit_timed_fenced(
            anchor,
            &originals,
            &evidence,
            view.head(),
            false,
            Some(&view),
            |_| {},
        )?;
        Ok(view.head())
    }

    /// Whether the journal holds `history`'s originals, each with its time,
    /// as far as both reach.
    #[allow(clippy::type_complexity)]
    fn holds_timed(
        &self,
        stored: &crate::journal::JournaledAccount,
        history: &[(&[u8], Option<(crate::trust::ConfirmedTime, Vec<u8>)>)],
    ) -> Result<bool, OwnerError> {
        let mut cursor = Some(HistoryCursor {
            anchor: stored.anchor,
            cut: stored.head,
            next_position: 1,
        });
        let mut offered = history.iter();
        while let Some(next) = cursor {
            let page = self
                .journal
                .history_prefix(Some(next), 256)?
                .ok_or(JournalError::Corrupt)?;
            for (event, time) in page.events.iter().zip(&page.times) {
                let Some((original, evidence)) = offered.next() else {
                    return Ok(true);
                };
                if event.as_slice() != *original
                    || *time != evidence.as_ref().map(|(time, _)| *time)
                {
                    return Ok(false);
                }
            }
            cursor = page.next;
        }
        Ok(true)
    }

    /// Open the personal key delivered to this device by the addition at
    /// `added_at`: the exact signed delivery frame that addition carried,
    /// checked against the verified account at that position before the
    /// native receiver opens it.
    pub async fn open_delivered_personal(
        &mut self,
        capability: &AccountCapability,
        frame: &[u8],
        added_at: u64,
    ) -> Result<personal::PersonalKey, OwnerError> {
        let view = self.verified_at(capability, added_at)?;
        let device = self
            .loaded
            .as_ref()
            .and_then(|l| l.device.clone())
            .ok_or(OwnerError::NotActive)?;
        let result = personal::open_for_device(&view, frame, &device, &mut self.store).await;
        self.check(capability)?;
        result.map_err(OwnerError::Invalid)
    }

    /// The account at `position`, before `head`, replayed from the journal.
    fn view_at(
        &self,
        anchor: AccountId,
        head: Head,
        position: u64,
    ) -> Result<VerifiedAccount, OwnerError> {
        let mut cursor = Some(HistoryCursor {
            anchor,
            cut: head,
            next_position: 1,
        });
        let mut events = Vec::new();
        let mut times = Vec::new();
        while let Some(next) = cursor
            && (events.len() as u64) < position
        {
            let page = self
                .journal
                .history_prefix(Some(next), 256)?
                .ok_or(JournalError::Corrupt)?;
            if page.times.len() != page.events.len() {
                return Err(JournalError::Corrupt.into());
            }
            times.extend(page.times);
            events.extend(page.events);
            cursor = page.next;
        }
        events.truncate(position as usize);
        let last = events.last().ok_or(JournalError::Corrupt)?;
        let remembered = if position == head.position {
            head
        } else {
            Head {
                position,
                hash: crate::crypto::hash(last),
            }
        };
        let timed: Vec<_> = events
            .iter()
            .zip(times)
            .map(|(bytes, time)| (bytes.as_slice(), time))
            .collect();
        let view = VerifiedAccount::replay_timed(anchor, &timed, remembered)
            .map_err(OwnerError::Invalid)?;
        if view.head().position != position {
            return Err(OwnerError::Journal(JournalError::Corrupt));
        }
        Ok(view)
    }

    /// Read exactly the remembered signup cut, never the current history length.
    /// Public signed originals only; additional controls use a captured journal
    /// cursor, not this bounded initial-prefix interface.
    pub fn initial_prefix(
        &self,
        capability: &AccountCapability,
    ) -> Result<InitialAccountPrefix, OwnerError> {
        self.check(capability)?;
        let retained = self
            .journal
            .initial_bootstrap()?
            .ok_or(JournalError::Corrupt)?;
        let prefix = self.read_initial_prefix(&retained)?;
        self.check(capability)?;
        Ok(prefix)
    }

    fn read_initial_prefix(
        &self,
        retained: &crate::journal::InitialBootstrapRecord,
    ) -> Result<InitialAccountPrefix, OwnerError> {
        if retained.head.position != 3
            || self
                .loaded
                .as_ref()
                .is_none_or(|l| l.account.id() != retained.anchor)
        {
            return Err(OwnerError::Journal(JournalError::Corrupt));
        }
        let page = self
            .journal
            .history_prefix(
                Some(crate::journal::HistoryCursor {
                    anchor: retained.anchor,
                    cut: retained.head,
                    next_position: 1,
                }),
                3,
            )?
            .ok_or(JournalError::Corrupt)?;
        if page.events.len() != 3
            || page.next.is_some()
            || page.cut != retained.head
            || page.anchor != retained.anchor
            || page.first_position != 1
        {
            return Err(OwnerError::Journal(JournalError::Corrupt));
        }
        let prefix = InitialAccountPrefix {
            anchor: page.anchor,
            head: page.cut,
            events: page.events,
        };
        verify_initial_prefix(&prefix).map_err(OwnerError::Invalid)?;
        Ok(prefix)
    }

    /// Native-only authenticated bootstrap. Public signed history and private
    /// encrypted objects remain distinct owned types; neither contains roots.
    pub fn initial_bootstrap(
        &self,
        capability: &AccountCapability,
    ) -> Result<(InitialAccountPrefix, PendingHomeObjects), OwnerError> {
        self.check(capability)?;
        let retained = self
            .journal
            .initial_bootstrap()?
            .ok_or(JournalError::Corrupt)?;
        let prefix = self.read_initial_prefix(&retained)?;
        let account = verify_initial_prefix(&prefix).map_err(OwnerError::Invalid)?;
        authenticate_initial_objects(&account, &retained).map_err(OwnerError::Invalid)?;
        self.check(capability)?;
        Ok((
            prefix,
            PendingHomeObjects {
                record: retained.recovery_record,
                device_seal: retained.device_seal,
                recovery_seal: retained.recovery_seal,
            },
        ))
    }

    /// Initial-device opening only. Pairing has a distinct authenticated delivery
    /// and opener; missing initial material never falls back or regenerates.
    pub async fn open_personal(
        &mut self,
        capability: &AccountCapability,
    ) -> Result<personal::PersonalKey, OwnerError> {
        let (prefix, objects) = self.initial_bootstrap(capability)?;
        let historical = verify_initial_prefix(&prefix).map_err(OwnerError::Invalid)?;
        let device = self
            .loaded
            .as_ref()
            .and_then(|l| l.device.clone())
            .ok_or(OwnerError::NotActive)?;
        self.check(capability)?;
        let result = personal::open_initial_fenced(
            &historical,
            &objects.device_seal,
            &device,
            &mut self.store,
            || capability.is_current(),
        )
        .await;
        self.check(capability)?;
        result.map_err(OwnerError::Invalid)
    }

    /// The personal key this device accepted: its initial seal, the delivery
    /// its addition carried, or its latest accepted rotation, each opened at
    /// its own verified position. A newer publication this device has not
    /// accepted, or a staged proposal, is never returned.
    pub async fn open_current_personal(
        &mut self,
        capability: &AccountCapability,
    ) -> Result<personal::PersonalKey, OwnerError> {
        self.check(capability)?;
        let accepted = self.journal.keyring_state()?.accepted;
        self.open_accepted(capability, &accepted).await
    }

    /// Accept the RotatePersonal at `position`: open this device's seal from
    /// its ordered `body`, then switch the accepted key and re-seal every local
    /// keyring row to it in one commit. Native work holds no database writer;
    /// the commit compares the head, accepted key and rows read before it, so
    /// a concurrent change is `KeyringChanged` (retry), never overwritten.
    /// A held base without keyring rows is `KeyringIncomplete` until its
    /// keyring is initialized. Repeating the accepted rotation is idempotent.
    pub async fn accept_rotation(
        &mut self,
        capability: &AccountCapability,
        position: u64,
        body: &[u8],
    ) -> Result<personal::PersonalKey, OwnerError> {
        let mut head = self.verified(capability)?.head();
        let mut state = self.journal.keyring_state()?;
        if state.head.position > head.position {
            // Another process committed later history: this view lags the
            // durable head. Catch it up to that head before judging, or
            // every retry would find the keyring changed again.
            // A head that moved on again meanwhile is the same retry.
            self.re_read_projection(state.head)
                .map_err(|error| match error {
                    OwnerError::Invalid(Error::WrongPredecessor) => {
                        OwnerError::Journal(JournalError::KeyringChanged)
                    }
                    other => other,
                })?;
            head = self.verified(capability)?.head();
            state = self.journal.keyring_state()?;
        }
        if state.head != head {
            return Err(OwnerError::Journal(JournalError::KeyringChanged));
        }
        match &state.accepted {
            AcceptedPersonal::Rotated {
                position: p,
                body: b,
            } if *p == position => {
                if b.as_slice() != body {
                    return Err(OwnerError::Invalid(Error::InvalidCredentials));
                }
                return self.open_accepted(capability, &state.accepted).await;
            }
            AcceptedPersonal::Rotated { position: p, .. }
            | AcceptedPersonal::Delivered { added_at: p, .. }
                if *p > position =>
            {
                return Err(OwnerError::Invalid(Error::InvalidCredentials));
            }
            _ => {}
        }
        let view = self.rotation_at(capability, position)?;
        let old = self.open_accepted(capability, &state.accepted).await?;
        let new = self.open_rotation(capability, &view, body).await?;
        let account = capability.account_id();
        let rows = state
            .rows
            .iter()
            .map(|row| {
                let context = local_seal::LocalKeyContext {
                    account,
                    base: row.base,
                    purpose: row.purpose,
                    key_id: row.key_id,
                };
                let root = local_seal::open(&context, &old, &row.seal)
                    .map_err(|_| OwnerError::Journal(JournalError::Corrupt))?;
                Ok(KeyringRow {
                    seal: local_seal::seal(&context, &new.public(), &root)
                        .map_err(OwnerError::Invalid)?,
                    ..row.clone()
                })
            })
            .collect::<Result<Vec<_>, OwnerError>>()?;
        self.check(capability)?;
        let committed =
            self.journal
                .commit_accepted_rotation(&state, position, body, &rows, || {
                    capability.is_current()
                });
        self.check(capability)?;
        committed?;
        Ok(new)
    }

    async fn open_accepted(
        &mut self,
        capability: &AccountCapability,
        accepted: &AcceptedPersonal,
    ) -> Result<personal::PersonalKey, OwnerError> {
        match accepted {
            AcceptedPersonal::Initial => self.open_personal(capability).await,
            AcceptedPersonal::Delivered { added_at, frame } => {
                self.open_delivered_personal(capability, frame, *added_at)
                    .await
            }
            AcceptedPersonal::Rotated { position, body } => {
                // An accepted body matching the current verified publication can
                // open against its indexed view, without replaying old history on
                // every reopen. A newer, unaccepted publication needs the old
                // historical view instead; never substitute its key for this one.
                let current = self.verified(capability)?;
                let view = if *current
                    .personal_publication()
                    .map_err(OwnerError::Invalid)?
                    .device_digest()
                    == personal::body_digest(body)
                {
                    current.clone()
                } else {
                    self.rotation_at(capability, *position)?
                };
                self.open_rotation(capability, &view, body).await
            }
        }
    }

    /// The verified account at `position`, only where the original there is a
    /// RotatePersonal whose publication that history holds: a rotation that
    /// took effect, not merely a signed event with the rotation tag.
    fn rotation_at(
        &self,
        capability: &AccountCapability,
        position: u64,
    ) -> Result<VerifiedAccount, OwnerError> {
        let view = self.verified_at(capability, position)?;
        let page = self
            .journal
            .history_prefix(
                Some(HistoryCursor {
                    anchor: view.id(),
                    cut: self.verified(capability)?.head(),
                    next_position: position,
                }),
                1,
            )?
            .ok_or(JournalError::Corrupt)?;
        let original = page.events.first().ok_or(JournalError::Corrupt)?;
        if page.first_position != position || crate::crypto::hash(original) != view.head().hash {
            return Err(JournalError::Corrupt.into());
        }
        let event = AccountEvent::decode(original).map_err(OwnerError::Invalid)?;
        let Control::RotatePersonal { publication, .. } = &event.control else {
            return Err(OwnerError::Invalid(Error::InvalidCredentials));
        };
        let held = view.personal_publication().map_err(OwnerError::Invalid)?;
        if publication.public() != held.public()
            || publication.device_digest() != held.device_digest()
            || publication.recovery_digest() != held.recovery_digest()
        {
            return Err(OwnerError::Invalid(Error::InvalidCredentials));
        }
        Ok(view)
    }

    async fn open_rotation(
        &mut self,
        capability: &AccountCapability,
        view: &VerifiedAccount,
        body: &[u8],
    ) -> Result<personal::PersonalKey, OwnerError> {
        let device = self
            .loaded
            .as_ref()
            .and_then(|l| l.device.clone())
            .ok_or(OwnerError::NotActive)?;
        let result = personal::open_rotation_for_device(view, body, &device, &mut self.store).await;
        self.check(capability)?;
        result.map_err(OwnerError::Invalid)
    }

    fn check(&self, capability: &AccountCapability) -> Result<(), OwnerError> {
        let loaded = self.loaded.as_ref().ok_or(OwnerError::NotActive)?;
        if loaded.stopped {
            return Err(OwnerError::Stopped);
        }
        if capability.generation != self.generation.current() {
            return Err(OwnerError::Stale);
        }
        let device = loaded.device.as_ref().ok_or(OwnerError::NotActive)?;
        if capability.account != loaded.account.id() || capability.device != device.keys.id() {
            return Err(OwnerError::Stale);
        }
        loaded
            .account
            .active_device(device.keys.id())
            .map_err(|_| OwnerError::Stale)?;
        Ok(())
    }

    // ---- Interrupted first-device setup ----

    /// Prepare a first device: generate native keys, genesis, recovery record and
    /// personal publication, and durably stage the exact signed bytes plus the
    /// protected pending material. A retry never regenerates a staged setup.
    pub async fn begin_first_device(
        &mut self,
        policy: crate::platform::ControlKeyPolicy,
        password: &Password,
    ) -> Result<SetupStatus, SetupError> {
        // Never start a second setup over an existing account: it would sign a
        // new genesis and overwrite the working device identity. A crash before
        // `commit_pending_setup` can still leave only an unreferenced device row.
        if self.journal.has_account()? || self.journal.pending_setup()?.is_some() {
            return Err(SetupError::AlreadyStarted);
        }
        // Create the native identity first: SQLite and the OS key store cannot be
        // committed together, so reconcile rather than pretend otherwise.
        let device = self
            .store
            .create(policy)
            .await
            .map_err(SetupError::Device)?;
        let recovery = RecoveryKeys::generate();
        let code = RecoveryCode::generate();

        let genesis = AccountEvent::genesis(device.keys.clone(), recovery.public())
            .sign_with(&device, &mut self.store)
            .await
            .map_err(SetupError::Device)?;
        let anchor = AccountId::of_genesis(&genesis).map_err(SetupError::Protocol)?;
        let account = VerifiedAccount::from_genesis(anchor, genesis.as_bytes())
            .map_err(SetupError::Protocol)?;

        let record =
            prepare_record(&account, &recovery, password, &code).map_err(SetupError::Protocol)?;
        // The device-local check of the chosen password, for a later change
        // of password; kept with the pending setup until it is published.
        let password_check = make_password_check(password).map_err(SetupError::Protocol)?;
        let record_event = account
            .prepare_recovery_record(device.keys.id(), record.digest())
            .map_err(SetupError::Protocol)?
            .sign_with(&device, &mut self.store)
            .await
            .map_err(SetupError::Device)?;
        let mut after_record = account.clone();
        after_record
            .apply(record_event.as_bytes())
            .map_err(SetupError::Protocol)?;

        let personal = personal::PersonalKey::generate();
        let publication = personal::prepare_publication(&after_record, &personal)
            .map_err(SetupError::Protocol)?;
        let publish_event = after_record
            .publish_personal_key(
                device.keys.id(),
                publication.public(),
                publication.device_digest(),
                publication.recovery_digest(),
            )
            .map_err(SetupError::Protocol)?
            .sign_with(&device, &mut self.store)
            .await
            .map_err(SetupError::Device)?;
        let mut complete = after_record.clone();
        complete
            .apply(publish_event.as_bytes())
            .map_err(SetupError::Protocol)?;

        let material = PendingMaterial {
            anchor,
            genesis: genesis.as_bytes().to_vec(),
            controls: vec![
                record_event.as_bytes().to_vec(),
                publish_event.as_bytes().to_vec(),
            ],
            code,
            record: record.as_bytes().to_vec(),
            device_seal: publication.device_seal().to_vec(),
            recovery_seal: publication.recovery_seal().to_vec(),
            password_check: Some(password_check),
        };
        let plaintext = material.encode();
        let blob = self.protector.seal(plaintext.expose())?;

        // Persist the device identity, then the staged setup. A crash between the
        // two leaves an orphan native identity, never a half-written account.
        self.journal.commit_device(&JournaledDevice {
            handle: device.handle.clone(),
            keys: device.keys.clone(),
            policy: device.policy,
            kind: device.kind,
        })?;
        self.journal.commit_pending_setup(&PendingSetupRecord {
            version: PENDING_SETUP_VERSION,
            stage: SetupStage::Prepared,
            kit_saved: false,
            blob,
        })?;
        status_from_material(&material, SetupStage::Prepared, false)
    }

    /// Resume summary, or `None` once setup completed or never started.
    pub fn setup_status(&mut self) -> Result<Option<SetupStatus>, SetupError> {
        let Some(record) = self.journal.pending_setup()? else {
            return Ok(None);
        };
        let material = self.open_material(&record)?;
        status_from_material(&material, record.stage, record.kit_saved).map(Some)
    }

    /// The code the person must keep until the kit is saved. Opened from the
    /// native-protected pending blob; never a new random value.
    pub fn pending_kit_code(&mut self) -> Result<RecoveryCode, SetupError> {
        let record = self
            .journal
            .pending_setup()?
            .ok_or(SetupError::NotStarted)?;
        if record.kit_saved {
            return Err(SetupError::NotStarted);
        }
        let material = self.open_material(&record)?;
        Ok(RecoveryCode::from_raw(material.code.expose()))
    }

    /// The password check signup made, while the pending setup still holds
    /// it, and the digest of the recovery record it belongs with. `None` for
    /// a setup made before signup kept one, or once setup completed.
    pub fn pending_password_check(
        &mut self,
    ) -> Result<Option<(PasswordCheck, [u8; 32])>, SetupError> {
        let Some(record) = self.journal.pending_setup()? else {
            return Ok(None);
        };
        let material = self.open_material(&record)?;
        let digest = crate::recovery::record_checks(&material.record)
            .map_err(SetupError::Protocol)?
            .digest;
        Ok(material.password_check.map(|check| (check, digest)))
    }

    /// Encrypted private objects the account home must receive during setup: the
    /// recovery record and the two personal-key seals. This is not authority and
    /// not a verified head.
    pub fn pending_home_objects(&mut self) -> Result<PendingHomeObjects, SetupError> {
        let record = self
            .journal
            .pending_setup()?
            .ok_or(SetupError::NotStarted)?;
        let material = self.open_material(&record)?;
        Ok(PendingHomeObjects {
            record: material.record,
            device_seal: material.device_seal,
            recovery_seal: material.recovery_seal,
        })
    }

    /// Record that the exact signed bytes were submitted and the result is
    /// unknown. This is never a verified head.
    pub fn mark_home_pending(&mut self) -> Result<(), SetupError> {
        let mut record = self
            .journal
            .pending_setup()?
            .ok_or(SetupError::NotStarted)?;
        if record.stage == SetupStage::Prepared {
            record.stage = SetupStage::HomePending;
            self.journal.commit_pending_setup(&record)?;
        }
        Ok(())
    }

    /// Reconcile a home-ordered response against the exact signed bytes we hold.
    ///
    /// Call this only after the home acknowledged the ordered events **and** the
    /// three private objects from `pending_home_objects`; immutable encrypted
    /// originals survive deletion of the disposable pending blob. Only an exact head
    /// match commits verified history, and bytes already stored are not appended
    /// again, so a retry is idempotent.
    ///
    /// `setup_evidence` is the home's caller-verified confirmations of positions
    /// 2 and 3; `None` only for a verified legacy home head. Setup committed
    /// untimed by an offline kit save receives these times once, so this
    /// device judges maturity exactly as the home does.
    pub fn confirm_home_ordered(
        &mut self,
        reported: Head,
        setup_evidence: Option<[(crate::trust::ConfirmedTime, Vec<u8>); 2]>,
    ) -> Result<(), SetupError> {
        let Some(record) = self.journal.pending_setup()? else {
            return Err(SetupError::NotStarted);
        };
        let material = self.open_material(&record)?;
        let head = expected_head(&material)?;
        if head != reported {
            return Err(SetupError::HomeMismatch);
        }
        match &setup_evidence {
            Some(evidence) => self.commit_setup_times(&material, head, evidence)?,
            None if !self.local_history_committed(&material)? => {
                self.commit_local_history(&material, head)?;
            }
            None => {}
        }
        if record.kit_saved {
            self.protector.retire_kit_key(&record.blob)?;
            self.retain_initial(&material, true)?;
        } else if record.stage != SetupStage::HomeOrdered {
            let mut ordered = record;
            ordered.stage = SetupStage::HomeOrdered;
            self.journal.commit_pending_setup(&ordered)?;
        }
        Ok(())
    }

    /// True when the journal already holds the staged anchor and first events.
    /// This proves only a local commit, never home ordering or private delivery.
    fn local_history_committed(&self, material: &PendingMaterial) -> Result<bool, SetupError> {
        let Some(account) = self
            .journal
            .history_prefix(None, 1 + material.controls.len())?
        else {
            return Ok(false);
        };
        if account.anchor != material.anchor
            || account.events.len() < 1 + material.controls.len()
            || account.events[0] != material.genesis
        {
            return Ok(false);
        }
        Ok(material
            .controls
            .iter()
            .enumerate()
            .all(|(index, control)| account.events[index + 1] == *control))
    }

    /// Explicit saved-kit confirmation. An opened destination is not success.
    /// Commit the verified prefix locally even if the home is not available.
    /// Keep the signed events and encrypted private delivery objects pending,
    /// but replace the recoverable code in the protected blob with zeroes.
    pub fn confirm_kit_saved(&mut self) -> Result<(), SetupError> {
        let Some(mut record) = self.journal.pending_setup()? else {
            return Err(SetupError::NotStarted);
        };
        let mut material = self.open_material(&record)?;
        let head = expected_head(&material)?;
        if !record.kit_saved {
            material.code = RecoveryCode::from_raw(&[0; 16]);
            record.blob = self
                .protector
                .reseal_without_code(&record.blob, material.encode().expose())?;
            record.kit_saved = true;
            // Crash-safe: the no-code blob is durable before the local commit.
            // A retry completes the commit without regenerating an account.
            self.journal.commit_pending_setup(&record)?;
        }
        self.protector.retire_kit_key(&record.blob)?;
        if !self.local_history_committed(&material)? {
            self.commit_local_history(&material, head)?;
        }
        self.retain_initial(&material, record.stage == SetupStage::HomeOrdered)?;
        Ok(())
    }

    fn retain_initial(
        &mut self,
        material: &PendingMaterial,
        clear_pending: bool,
    ) -> Result<(), SetupError> {
        let head = expected_head(material)?;
        if head.position != 3 {
            return Err(SetupError::Corrupt);
        }
        let prefix = InitialAccountPrefix {
            anchor: material.anchor,
            head,
            events: std::iter::once(material.genesis.clone())
                .chain(material.controls.clone())
                .collect(),
        };
        let account = verify_initial_prefix(&prefix).map_err(SetupError::Protocol)?;
        let row = crate::journal::InitialBootstrapRecord {
            anchor: material.anchor,
            head,
            recovery_record: material.record.clone(),
            device_seal: material.device_seal.clone(),
            recovery_seal: material.recovery_seal.clone(),
        };
        authenticate_initial_objects(&account, &row).map_err(SetupError::Protocol)?;
        self.journal.retain_initial_bootstrap(&row, clear_pending)?;
        Ok(())
    }

    /// Commit the setup prefix with the home's times, or attach them to the
    /// prefix an offline kit save committed untimed. Stored times are final.
    fn commit_setup_times(
        &mut self,
        material: &PendingMaterial,
        head: Head,
        evidence: &[(crate::trust::ConfirmedTime, Vec<u8>); 2],
    ) -> Result<(), SetupError> {
        let [record, key] = material.controls.as_slice() else {
            return Err(SetupError::Corrupt);
        };
        if evidence.iter().any(|(_, proof)| proof.is_empty()) {
            return Err(SetupError::Protocol(Error::MissingTime));
        }
        let times = [None, Some(evidence[0].0), Some(evidence[1].0)];
        let events = [material.genesis.as_slice(), record, key];
        let timed: Vec<_> = events.iter().copied().zip(times).collect();
        let account = VerifiedAccount::replay_timed(material.anchor, &timed, head)
            .map_err(SetupError::Protocol)?;
        if !self.local_history_committed(material)? {
            let evidence = [None, Some(evidence[0].clone()), Some(evidence[1].clone())];
            self.journal.commit_timed_fenced(
                material.anchor,
                &events,
                &evidence,
                head,
                false,
                Some(&account),
                |_| {},
            )?;
            return Ok(());
        }
        let stored = self
            .journal
            .history_prefix(None, 3)?
            .ok_or(JournalError::Corrupt)?
            .times;
        if stored == times {
            return Ok(());
        }
        self.journal.attach_setup_confirmations(
            material.anchor,
            head,
            [record, key],
            evidence,
            &account,
        )?;
        // Refresh a loaded untimed view; capabilities stay valid.
        if let Some(loaded) = self.loaded.as_mut() {
            match self.journal.rebase_projection(account) {
                Ok(account) => loaded.account = account,
                Err(error) => {
                    self.loaded = None;
                    return Err(error.into());
                }
            }
        }
        Ok(())
    }

    fn commit_local_history(
        &mut self,
        material: &PendingMaterial,
        head: Head,
    ) -> Result<(), SetupError> {
        let mut events: Vec<&[u8]> = Vec::with_capacity(1 + material.controls.len());
        events.push(&material.genesis);
        events.extend(material.controls.iter().map(Vec::as_slice));
        let account = VerifiedAccount::replay(material.anchor, &events, head)
            .map_err(SetupError::Protocol)?;
        self.journal.commit_projected_fenced(
            material.anchor,
            &events,
            head,
            false,
            Some(&account),
            |_| {},
        )?;
        Ok(())
    }

    fn open_material(
        &mut self,
        record: &PendingSetupRecord,
    ) -> Result<PendingMaterial, SetupError> {
        if record.version != PENDING_SETUP_VERSION {
            return Err(SetupError::UnsupportedVersion);
        }
        let plaintext = self.protector.open(&record.blob)?;
        PendingMaterial::decode(plaintext.expose())
    }
}

fn stored(identity: &JournaledDevice) -> StoredDevice {
    StoredDevice {
        handle: identity.handle.clone(),
        keys: identity.keys.clone(),
        policy: identity.policy,
        kind: identity.kind,
    }
}

fn status_from_material(
    material: &PendingMaterial,
    stage: SetupStage,
    kit_saved: bool,
) -> Result<SetupStatus, SetupError> {
    let mut submission = Vec::with_capacity(1 + material.controls.len());
    submission.push(material.genesis.clone());
    submission.extend(material.controls.iter().cloned());
    Ok(SetupStatus {
        stage,
        kit_saved,
        anchor: material.anchor,
        head: expected_head(material)?,
        submission,
    })
}

fn verify_initial_prefix(prefix: &InitialAccountPrefix) -> Result<VerifiedAccount, Error> {
    if prefix.head.position != 3 || prefix.events.len() != 3 {
        return Err(Error::InvalidSetup);
    }
    VerifiedAccount::replay(
        prefix.anchor,
        &prefix.events.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        prefix.head,
    )
}

fn authenticate_initial_objects(
    account: &VerifiedAccount,
    row: &crate::journal::InitialBootstrapRecord,
) -> Result<(), Error> {
    if row.anchor != account.id() || row.head != account.head() {
        return Err(Error::InvalidCredentials);
    }
    account.verify_initial_objects(&row.recovery_record, &row.device_seal, &row.recovery_seal)
}

fn expected_head(material: &PendingMaterial) -> Result<Head, SetupError> {
    let mut account = VerifiedAccount::from_genesis(material.anchor, &material.genesis)
        .map_err(SetupError::Protocol)?;
    for control in &material.controls {
        account.apply(control).map_err(SetupError::Protocol)?;
    }
    Ok(account.head())
}

/// Pending setup plaintext. Held only in memory and inside the native-protected
/// blob; never written to SQLite columns directly.
struct PendingMaterial {
    anchor: AccountId,
    genesis: Vec<u8>,
    controls: Vec<Vec<u8>>,
    code: RecoveryCode,
    record: Vec<u8>,
    device_seal: Vec<u8>,
    recovery_seal: Vec<u8>,
    /// Absent in a setup sealed before signup made one. Appended last, so
    /// an older reader of a newer blob ignores it.
    password_check: Option<PasswordCheck>,
}

impl PendingMaterial {
    fn encode(&self) -> SecretBytes {
        let mut out = Vec::new();
        out.extend_from_slice(PENDING_MAGIC);
        out.extend_from_slice(&PENDING_SETUP_VERSION.to_be_bytes());
        out.extend_from_slice(&self.anchor.0);
        put(&mut out, &self.genesis);
        out.extend_from_slice(&(self.controls.len() as u32).to_be_bytes());
        for control in &self.controls {
            put(&mut out, control);
        }
        out.extend_from_slice(self.code.expose());
        put(&mut out, &self.record);
        put(&mut out, &self.device_seal);
        put(&mut out, &self.recovery_seal);
        if let Some(check) = &self.password_check {
            out.extend_from_slice(check.encode().expose());
        }
        SecretBytes::from_vec(out)
    }

    fn decode(input: &[u8]) -> Result<Self, SetupError> {
        let mut reader = BlobReader(input);
        if reader.take(PENDING_MAGIC.len())? != PENDING_MAGIC {
            return Err(SetupError::Corrupt);
        }
        if u16::from_be_bytes(reader.array()?) != PENDING_SETUP_VERSION {
            return Err(SetupError::UnsupportedVersion);
        }
        let anchor = AccountId(reader.array()?);
        let genesis = reader.blob()?.to_vec();
        let count = u32::from_be_bytes(reader.array()?) as usize;
        if count > MAX_CONTROLS {
            return Err(SetupError::Corrupt);
        }
        let mut controls = Vec::with_capacity(count);
        for _ in 0..count {
            controls.push(reader.blob()?.to_vec());
        }
        let code = RecoveryCode::from_raw(&reader.array()?);
        let record = reader.blob()?.to_vec();
        let device_seal = reader.blob()?.to_vec();
        let recovery_seal = reader.blob()?.to_vec();
        let password_check = match reader.0.len() {
            0 => None,
            PASSWORD_CHECK_SIZE => {
                Some(PasswordCheck::decode(reader.0).map_err(|_| SetupError::Corrupt)?)
            }
            _ => return Err(SetupError::Corrupt),
        };
        Ok(Self {
            anchor,
            genesis,
            controls,
            code,
            record,
            device_seal,
            recovery_seal,
            password_check,
        })
    }
}

fn put(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

struct BlobReader<'a>(&'a [u8]);

impl<'a> BlobReader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SetupError> {
        if self.0.len() < len {
            return Err(SetupError::Corrupt);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SetupError> {
        self.take(N)?.try_into().map_err(|_| SetupError::Corrupt)
    }

    fn blob(&mut self) -> Result<&'a [u8], SetupError> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        if len > MAX_BLOB_PART || self.0.len() < len {
            return Err(SetupError::Corrupt);
        }
        self.take(len)
    }
}

#[cfg(test)]
mod cost_tests {
    use super::*;
    use crate::crypto::{KemKey, Secret, SigningKey};
    use crate::history::{RecoveryPublicKeys, reset_signature_checks, signature_checks};
    use crate::journal::{JournaledAccount, ProtectorError};
    use crate::platform::{ControlKeyPolicy, DeviceKeyStoreKind, KeyHandle, KeyStoreError};

    struct Journal {
        account: JournaledAccount,
        device: JournaledDevice,
        staged: Option<StagedAdmission>,
    }
    impl AccountJournal for Journal {
        fn load(&self) -> Result<Option<JournaledAccount>, JournalError> {
            Ok(Some(self.account.clone()))
        }
        fn commit_verified(
            &mut self,
            _: AccountId,
            events: &[&[u8]],
            head: Head,
            stopped: bool,
        ) -> Result<(), JournalError> {
            self.account
                .history
                .extend(events.iter().map(|e| e.to_vec()));
            self.account.head = head;
            self.account.stopped = stopped;
            Ok(())
        }
        fn device(&self) -> Result<Option<JournaledDevice>, JournalError> {
            Ok(Some(self.device.clone()))
        }
        fn commit_device(&mut self, _: &JournaledDevice) -> Result<(), JournalError> {
            unreachable!()
        }
        fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError> {
            Ok(None)
        }
        fn commit_pending_setup(&mut self, _: &PendingSetupRecord) -> Result<(), JournalError> {
            unreachable!()
        }
        fn clear_pending_setup(&mut self) -> Result<(), JournalError> {
            unreachable!()
        }
        fn staged_admission(&self) -> Result<Option<StagedAdmission>, JournalError> {
            Ok(self.staged.clone())
        }
        fn insert_staged_admission(&mut self, _: &StagedAdmission) -> Result<(), JournalError> {
            unreachable!()
        }
        fn clear_staged_admission(&mut self, _: &StagedAdmission) -> Result<(), JournalError> {
            self.staged = None;
            Ok(())
        }
    }
    struct NoStore;
    impl DeviceKeyStore for NoStore {
        async fn create(&mut self, _: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
            unreachable!()
        }
        async fn load(&mut self, _: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
            unreachable!()
        }
        async fn sign_control(
            &mut self,
            _: KeyHandle,
            _: Vec<u8>,
        ) -> Result<[u8; 64], KeyStoreError> {
            unreachable!()
        }
        async fn sign_content(
            &mut self,
            _: KeyHandle,
            _: Vec<u8>,
        ) -> Result<[u8; 64], KeyStoreError> {
            unreachable!()
        }
        async fn decapsulate(
            &mut self,
            _: KeyHandle,
            _: [u8; 1120],
        ) -> Result<Secret<32>, KeyStoreError> {
            unreachable!()
        }
    }
    struct NoProtector;
    impl PendingSetupProtector for NoProtector {
        fn seal(&mut self, _: &[u8]) -> Result<Vec<u8>, ProtectorError> {
            unreachable!()
        }
        fn open(&mut self, _: &[u8]) -> Result<crate::crypto::SecretBytes, ProtectorError> {
            unreachable!()
        }
        fn reseal_without_code(&mut self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, ProtectorError> {
            unreachable!()
        }
        fn retire_kit_key(&mut self, _: &[u8]) -> Result<(), ProtectorError> {
            unreachable!()
        }
    }

    #[test]
    fn reconcile_and_scanner_status_verify_only_the_successor() {
        let signer = SigningKey::generate();
        let first = crate::DevicePublicKeys::new(
            SigningKey::generate().public(),
            signer.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let draft = AccountEvent::genesis(
            first.clone(),
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
        );
        let genesis = draft.finish(signer.sign(draft.signing_bytes())).unwrap();
        let anchor = AccountId::of_genesis(&genesis).unwrap();
        let account = VerifiedAccount::from_genesis(anchor, genesis.as_bytes()).unwrap();
        let recipient = crate::DevicePublicKeys::new(
            SigningKey::generate().public(),
            SigningKey::generate().public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let draft = account.add_device(first.id(), recipient).unwrap();
        let add = draft.finish(signer.sign(draft.signing_bytes())).unwrap();
        let staged = StagedAdmission {
            position: 2,
            previous: account.head().hash,
            event: add.as_bytes().to_vec(),
            delivery: vec![1],
        };
        let device = JournaledDevice {
            handle: KeyHandle([3; 32]),
            keys: first,
            policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            kind: DeviceKeyStoreKind::MacLoginKeychainV1,
        };
        let mut owner = AccountOwner::new(
            Journal {
                account: JournaledAccount {
                    anchor,
                    history: vec![genesis.as_bytes().to_vec()],
                    head: account.head(),
                    stopped: false,
                },
                device: device.clone(),
                staged: Some(staged),
            },
            NoStore,
            NoProtector,
            AccountGeneration::new(),
        );
        owner.loaded = Some(Loaded {
            account,
            device: Some(stored(&device)),
            stopped: false,
        });
        reset_signature_checks();
        assert!(matches!(
            owner.reconcile_staged_admission(Some(&[add.as_bytes()])),
            Ok(AdmissionResolution::Admitted { .. })
        ));
        assert_eq!(
            signature_checks(),
            1,
            "one new signature, no genesis replay"
        );
        reset_signature_checks();
        assert_eq!(
            owner.scanner_status(),
            Ok(crate::pairing::ScannerStatus::Added)
        );
        assert_eq!(
            signature_checks(),
            0,
            "status must use the verified projection"
        );
    }
}
