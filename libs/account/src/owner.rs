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
    AccountId, DeviceId, DevicePublicKeys, Error, Head, SigningRequest, VerifiedAccount,
};
use crate::journal::{
    AccountJournal, JournalError, JournaledDevice, PENDING_SETUP_VERSION, PendingSetupProtector,
    PendingSetupRecord, ProtectorError, SetupStage, StagedAdmission,
};
use crate::platform::{DeviceKeyStore, KeyStoreError, StoredDevice};
use crate::recovery::{Password, RecoveryCode, RecoveryKeys, prepare_record};
use crate::{AccountEvent, personal};

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
    Invalid(Error),
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

/// Encrypted setup objects for the home. The journal and base records never
/// carry them.
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
        let Some(record) = self.journal.load()? else {
            self.loaded = None;
            return Ok(AccountLoad::Uninitialized);
        };
        let history: Vec<&[u8]> = record.history.iter().map(Vec::as_slice).collect();
        let account = match VerifiedAccount::replay(record.anchor, &history, record.head) {
            Ok(account) => account,
            Err(_) => {
                self.loaded = None;
                self.fence()?;
                return Ok(AccountLoad::AdmissionRequired(
                    AdmissionReason::CorruptHistory,
                ));
            }
        };

        // A persisted stop stays stopped and keeps the last verified state. It is
        // checked before any device or native work.
        if record.stopped {
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
        let generation = self.generation.current();
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
    /// the resulting head together; invalid input commits a sticky stop while
    /// keeping the last good head and bytes.
    pub fn apply_incoming(&mut self, events: &[&[u8]]) -> Result<Head, OwnerError> {
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
        // apply_batch makes the one transactional copy and advances this owner
        // before the journal commit. A failed/uncertain commit must stop this
        // owner until activation rebuilds from durable signed bytes.
        let result = self
            .loaded
            .as_mut()
            .expect("checked")
            .account
            .apply_batch(events);
        match result {
            Ok(()) => {
                let loaded = self.loaded.as_ref().expect("checked");
                let head = loaded.account.head();
                let removed = device_id
                    .map(|id| loaded.account.active_device(id).is_err())
                    .unwrap_or(false);
                if let Err(error) =
                    self.journal
                        .commit_verified_fenced(anchor, events, head, false, |success| {
                            if !success || removed {
                                self.generation.advance();
                            }
                        })
                {
                    // An uncertain durable result cannot leave a usable owner.
                    self.loaded.as_mut().expect("checked").stopped = true;
                    return Err(error.into());
                }
                Ok(head)
            }
            Err(error) => {
                // Stop the session before the durable write: a storage failure
                // must not leave this owner active with usable capabilities.
                if let Some(loaded) = self.loaded.as_mut() {
                    loaded.stopped = true;
                }
                self.journal
                    .commit_verified_fenced(anchor, &[], last_head, true, |_| {
                        self.generation.advance();
                    })?;
                Err(OwnerError::Invalid(error))
            }
        }
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
        let request = self.prepare_add_device(capability, recipient.clone())?;
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
        let outcome = if verified.verified_event_at(staged.position, &staged.event) {
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
        if self.journal.load()?.is_some() || self.journal.pending_setup()?.is_some() {
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
        let material = self.open_material(&record)?;
        Ok(RecoveryCode::from_raw(material.code.expose()))
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
    /// three private objects from `pending_home_objects`; a later kit
    /// confirmation deletes the local copies of those objects. Only an exact head
    /// match commits verified history, and bytes already stored are not appended
    /// again, so a retry is idempotent.
    pub fn confirm_home_ordered(&mut self, reported: Head) -> Result<(), SetupError> {
        let Some(record) = self.journal.pending_setup()? else {
            return Err(SetupError::NotStarted);
        };
        let material = self.open_material(&record)?;
        let head = expected_head(&material)?;
        if head != reported {
            return Err(SetupError::HomeMismatch);
        }
        if !self.home_ordered(&material)? {
            let mut events: Vec<&[u8]> = Vec::with_capacity(1 + material.controls.len());
            events.push(&material.genesis);
            events.extend(material.controls.iter().map(Vec::as_slice));
            self.journal
                .commit_verified(material.anchor, &events, head, false)?;
        }
        if record.kit_saved {
            self.journal.clear_pending_setup()?;
        }
        Ok(())
    }

    /// True when the journal already holds the staged anchor and first events.
    fn home_ordered(&self, material: &PendingMaterial) -> Result<bool, SetupError> {
        let Some(account) = self.journal.load()? else {
            return Ok(false);
        };
        if account.anchor != material.anchor
            || account.history.len() < 1 + material.controls.len()
            || account.history[0] != material.genesis
        {
            return Ok(false);
        }
        Ok(material
            .controls
            .iter()
            .enumerate()
            .all(|(index, control)| account.history[index + 1] == *control))
    }

    /// Explicit saved-kit confirmation. An opened destination is not success.
    /// The person's answer is kept even before the home orders the staged bytes;
    /// once both hold, the pending code and recovery material are deleted.
    pub fn confirm_kit_saved(&mut self) -> Result<(), SetupError> {
        let Some(mut record) = self.journal.pending_setup()? else {
            return Err(SetupError::NotStarted);
        };
        let material = self.open_material(&record)?;
        if self.home_ordered(&material)? {
            self.journal.clear_pending_setup()?;
        } else {
            record.kit_saved = true;
            self.journal.commit_pending_setup(&record)?;
        }
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
        Ok(Self {
            anchor,
            genesis,
            controls,
            code,
            record: reader.blob()?.to_vec(),
            device_seal: reader.blob()?.to_vec(),
            recovery_seal: reader.blob()?.to_vec(),
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
