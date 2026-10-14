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
use crate::history::{AccountId, DeviceId, Error, Head, SigningRequest, VerifiedAccount};
use crate::journal::{
    AccountJournal, JournalError, JournaledDevice, PENDING_SETUP_VERSION, PendingSetupProtector,
    PendingSetupRecord, ProtectorError, SetupStage,
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
                self.generation.advance();
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
            self.generation.advance();
            return Ok(AccountLoad::Stopped);
        }

        let Some(identity) = self.journal.device()? else {
            self.loaded = None;
            self.generation.advance();
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
                self.generation.advance();
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
            self.generation.advance();
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
            self.generation.advance();
            return Ok(AccountLoad::AdmissionRequired(
                AdmissionReason::IncompleteMaterials,
            ));
        }

        let capability = AccountCapability {
            // The generation captured before the native load, never a fresh read:
            // a concurrent advance after the recheck must leave this capability
            // stale, not be absorbed into freshly-minted authority.
            generation,
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
    pub fn lock(&mut self) {
        self.generation.advance();
        self.loaded = None;
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
        let mut candidate = self.loaded.as_ref().expect("checked").account.clone();
        match candidate.apply_batch(events) {
            Ok(()) => {
                let head = candidate.head();
                self.journal.commit_verified(anchor, events, head, false)?;
                let removed = device_id
                    .map(|id| candidate.active_device(id).is_err())
                    .unwrap_or(false);
                self.loaded = Some(Loaded {
                    account: candidate,
                    device: self.loaded.as_ref().and_then(|l| l.device.clone()),
                    stopped: false,
                });
                if removed {
                    self.generation.advance();
                }
                Ok(head)
            }
            Err(error) => {
                // Stop the session before the durable write: a storage failure
                // must not leave this owner active with usable capabilities.
                if let Some(loaded) = self.loaded.as_mut() {
                    loaded.stopped = true;
                }
                self.generation.advance();
                self.journal.commit_verified(anchor, &[], last_head, true)?;
                Err(OwnerError::Invalid(error))
            }
        }
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
