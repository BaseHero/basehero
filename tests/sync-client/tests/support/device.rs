//! A real signed-up device: its account, own base (not yet registered) and
//! notes in a native container, and a signer holding its ordinary key and
//! base roots as the host's native signer would.
#![allow(dead_code)]

use super::fake::Hosted;
use bh_account::{
    AccountId, ConfirmedTime, DeviceId, DevicePublicKeys, Head as AccountHead, VerifiedAccount,
    device_auth::{self, Context, Proof},
    journal::{AccountJournal, InitialBootstrapRecord, StagedAdmission, StagedControl},
    owner::{
        AccountCapability, AccountGeneration, AccountLoad, AccountOwner, OwnerError, SetupError,
        staging::Settlement,
    },
    pairing,
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_authz::proto::account_log_id;
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_data::{
    Actor, DataError, MutationId, Position, Scope,
    admission::{Confirmation, HostAdmission},
    catalogue::Shipped,
    mutation::ops::Operation,
};
use bh_device::{
    ContainerId, Owner,
    control::{InstallError, SealWait, install_sealed_epoch, open_seal_set},
    own_base::create_or_open,
};
use bh_storage::{
    DeviceDatabase, NoteKey, PackagePreparation, StoredNotePackage, TypedPackagePreparation,
    TypedPackageProgress,
};
use bh_sync::{
    BaseId,
    permit::{LogId, LogKind},
};
use bh_sync_client::{
    AccountApplyError, Appraisal, BaseControlRequest, Client, ControlSignError, Endpoint,
    HomeSetup, Identity, Signer, SignerError, SyncStatus, TimedOriginal, Tuning,
    pairing::Approvals,
};
use futures_util::future::BoxFuture;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{oneshot, watch};

#[path = "../../../../libs/account/tests/support/protector.rs"]
pub mod protector;
#[path = "../../../../libs/account/tests/support/store.rs"]
pub mod store;

pub type Account = AccountOwner<DeviceJournal, store::FakeStore, protector::PlainProtector>;

pub fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(v) => v,
        _ => panic!("unexpected async platform"),
    }
}

/// Changes a retained setup before the client sees it, as a faulty host would.
pub type Tamper = Box<dyn Fn(&mut HomeSetup) + Send + Sync>;

/// The native key seeds a host's key store holds, kept so that a fresh
/// account owner can be loaded for each account operation.
pub struct Seeds {
    pub ordinary: Secret<32>,
    pub control: Secret<32>,
    pub receiver: Secret<32>,
}
impl Clone for Seeds {
    fn clone(&self) -> Self {
        let copy = |s: &Secret<32>| Secret::from_slice(s.expose()).unwrap();
        Self {
            ordinary: copy(&self.ordinary),
            control: copy(&self.control),
            receiver: copy(&self.receiver),
        }
    }
}
impl Seeds {
    pub fn of(store: &store::FakeStore) -> Self {
        let state = store.state();
        Self {
            ordinary: state.ordinary.as_ref().unwrap().export_seed(),
            control: state.control.as_ref().unwrap().export_seed(),
            receiver: state.receiver.as_ref().unwrap().export_seed(),
        }
    }
    /// A key store holding these keys, as the host's native store does.
    pub fn store(&self, generation: &AccountGeneration) -> store::FakeStore {
        let store = store::FakeStore::new(generation.clone());
        {
            let mut state = store.state_mut();
            state.ordinary = Some(SigningKey::from_seed(&self.ordinary));
            state.control = Some(SigningKey::from_seed(&self.control));
            state.receiver = Some(KemKey::from_seed(&self.receiver));
        }
        store
    }
}

pub struct TestSigner {
    ordinary: SigningKey,
    seeds: Seeds,
    /// The account at the head the base genesis names; read again at that
    /// head once setup keeps the home's times, as the host does.
    anchor: Mutex<VerifiedAccount>,
    /// The account at its current verified head.
    current: Mutex<VerifiedAccount>,
    account: AccountId,
    device: DeviceId,
    genesis: Vec<u8>,
    metadata: Secret<32>,
    /// The genesis epoch's content root.
    content: Secret<32>,
    /// Every epoch's content root this device holds, by key id, as the
    /// host's own base keeps them in memory: the genesis one, those in its
    /// keyring when it opened, and each installed since.
    epochs: Mutex<BTreeMap<[u8; 32], Secret<32>>>,
    /// The epoch each `with_epoch_keys` call asked for, in order.
    pub epoch_asks: Mutex<Vec<Option<[u8; 32]>>>,
    /// Seal sets the client asked to install, and those installed.
    pub install_attempts: AtomicUsize,
    pub installs: AtomicUsize,
    /// A wrong content root handed out as this device's, to prove the client
    /// ties the key to the stored epoch.
    content_override: Mutex<Option<Secret<32>>>,
    database: Arc<Mutex<DeviceDatabase>>,
    generation: AccountGeneration,
    base: BaseId,
    /// This device came from `Device::join`, whose fixture copies no
    /// personal-key delivery: its keyring cannot open P.
    fixture_join: bool,
    /// The client asked for another base's keys.
    pub wrong_base: AtomicBool,
    /// The client held the container's writer lock while asking for keys.
    pub owner_lock_held: AtomicBool,
    /// Completed home confirmations: head and authority generation.
    pub home_ordered: Mutex<Vec<(AccountHead, u64)>>,
    /// Confirmations refused for a superseded authority.
    pub stale_confirms: AtomicUsize,
    /// Refuse every confirmation, as a host that stops before recording it.
    pub refuse_confirm: AtomicBool,
    /// Confirmations the client asked for, completed or not.
    pub confirm_attempts: AtomicUsize,
    pub tamper: Mutex<Option<Tamper>>,
    /// Models a later device for which the signer has no original-home obligation.
    pub no_home_obligation: AtomicBool,
    /// Prove possession only while the account owner still holds this
    /// device active, as the host's signer does once its authority ended.
    pub proofs_need_membership: AtomicBool,
    /// The person has approved base controls: without it a control is
    /// `ConfirmationNeeded`, never prompted for, unless `approvals` covers it.
    pub approve_controls: AtomicBool,
    /// Single approvals of one control copy, as pairing grants them.
    pub approvals: Approvals,
    /// Base controls asked for, and those signed.
    pub control_requests: AtomicUsize,
    pub control_signatures: AtomicUsize,
    /// Account heads reached by applying incoming account history.
    pub applied: Mutex<Vec<AccountHead>>,
    /// Incoming account history the client asked to apply, applied or not.
    pub apply_attempts: AtomicUsize,
    /// The next event signature waits for release, as a platform signer
    /// awaiting the person or secure hardware does.
    sign_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    /// Event signatures made.
    pub signed: AtomicUsize,
    /// How long each event signature takes, as the platform signer's.
    pub sign_time: Mutex<Duration>,
    /// When each event signature was asked for: the package's run was
    /// captured just before.
    pub sign_asked: Mutex<Vec<tokio::time::Instant>>,
    /// Rotations the client asked to accept, and those accepted.
    pub accept_attempts: AtomicUsize,
    pub accepts: AtomicUsize,
    /// Rotations staged at the client's request.
    pub rotations_staged: AtomicUsize,
    /// Refuse to stage a rotation, as a signer that cannot act now.
    pub refuse_rotation: AtomicBool,
    /// The account owner is lent elsewhere, as a host's publisher holds it
    /// while it signs: settling or discarding a stage cannot use it now.
    pub owner_lent: AtomicBool,
    /// This device's own directory entries and what its reads found.
    pub own: OwnDirectory,
}

/// This device's name and what directory reads found, as the host keeps
/// them in memory.
#[derive(Default)]
pub struct OwnDirectory {
    /// The model name the host gives this device, if any.
    pub label: Mutex<Option<String>>,
    /// The host asks for a directory read.
    pub wanted: AtomicBool,
    /// The names each read found, in order.
    pub reads: Mutex<Vec<Vec<(DeviceId, String)>>>,
    /// Whether each read found a password check.
    pub checks: Mutex<Vec<bool>>,
    /// Preparing own entries fails, as an owner that cannot open its key.
    pub fail_own: AtomicBool,
    /// Opening a directory read fails.
    pub fail_reads: AtomicBool,
    /// Reads reported failed.
    pub unread: AtomicUsize,
}

/// The content roots `own` holds in memory for its base, by key id: every
/// one in its keyring.
fn held_epochs(
    own: &bh_device::own_base::OwnBase,
    db: &Mutex<DeviceDatabase>,
) -> BTreeMap<[u8; 32], Secret<32>> {
    let rows = db.lock().unwrap().epoch_keys(own.id().0).unwrap();
    rows.iter()
        .filter(|row| row.purpose == bh_account::local_seal::LocalKeyPurpose::Content as i64)
        .filter_map(|row| {
            own.with_epoch_key(Some(row.epoch_id), |_, k| {
                k.map(|k| (row.epoch_id, Secret::from_slice(k.expose()).unwrap()))
            })
            .unwrap()
        })
        .collect()
}
/// Only the genesis epoch's root, as the joining fixture delivers it.
fn genesis_epoch(content: &Secret<32>) -> BTreeMap<[u8; 32], Secret<32>> {
    BTreeMap::from([(
        bh_crypto::committed_key_id(content),
        Secret::from_slice(content.expose()).unwrap(),
    )])
}

/// Public keys of a device that exists only in the account log.
pub fn test_keys(seed: u8) -> DevicePublicKeys {
    DevicePublicKeys::new([seed; 32], [seed + 1; 32], [seed + 2; 1216]).unwrap()
}
impl TestSigner {
    /// Hand out `key` as this device's content root instead of its own.
    pub fn use_content_key(&self, key: Option<Secret<32>>) {
        *self.content_override.lock().unwrap() = key;
    }
    pub fn identity_account(&self) -> AccountId {
        self.account
    }
    pub fn device_id(&self) -> DeviceId {
        self.device
    }
    /// The host's account owner, activated, with its key store.
    pub fn account_owner(&self) -> (Account, AccountCapability, store::FakeStore) {
        let store = self.seeds.store(&self.generation);
        let mut account = Account::new(
            DeviceJournal::from_shared(self.database.clone()),
            store.clone(),
            protector::PlainProtector,
            self.generation.clone(),
        );
        match ready(account.activate()) {
            Ok(AccountLoad::Active(cap)) => (account, cap, store),
            _ => panic!("account not active"),
        }
    }
    /// The account at an earlier head of the journal's verified history.
    fn view_at(&self, head: AccountHead) -> Option<VerifiedAccount> {
        let record = DeviceJournal::from_shared(self.database.clone())
            .load()
            .ok()??;
        let events: Vec<&[u8]> = record
            .history
            .get(..usize::try_from(head.position).ok()?)?
            .iter()
            .map(Vec::as_slice)
            .collect();
        VerifiedAccount::replay(record.anchor, &events, head).ok()
    }
    /// Hold the next event signature until released.
    pub fn hold_next_sign(&self) -> super::fake::HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.sign_hold.lock().unwrap() = Some((arrived, release_rx));
        super::fake::HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    /// Lock and unlock: every authority minted before is superseded.
    pub fn relock(&self) -> u64 {
        self.generation.advance()
    }
    /// The account owner over the device's journal and key store, activated
    /// at the current generation, as the host holds it.
    fn activated(&self) -> Result<(Account, AccountCapability, u64), SignerError> {
        let mut account = self.unloaded_owner();
        let generation = self.generation.current();
        match ready(account.activate()) {
            Ok(AccountLoad::Active(cap)) => Ok((account, cap, generation)),
            _ => Err(SignerError),
        }
    }
    /// Whether this signer may still prove possession (`proofs_need_membership`).
    fn still_member(&self) -> Result<(), SignerError> {
        if self.proofs_need_membership.load(Ordering::SeqCst) {
            self.activated()?;
        }
        Ok(())
    }
    /// `Device::join`'s fixture holds no delivered personal key: the keyring
    /// reads the device as the signup device and opening P fails as
    /// `Corrupt`. Say what is actually wrong instead.
    fn delivered_personal(&self) {
        assert!(
            !self.fixture_join,
            "this device came from Device::join, whose fixture holds no \
             delivered personal key; pair it through the real QR flow \
             (support::pair::paired) before accepting a rotation or opening \
             the personal key"
        );
    }
    /// The account owner as the host loads it, activated over the journal.
    fn owner(&self) -> Option<(Account, AccountCapability)> {
        self.activated()
            .ok()
            .map(|(account, cap, _)| (account, cap))
    }
    /// Cache a freshly read owner view without moving the cache backwards: a
    /// concurrent apply may have committed past the head this read saw. The
    /// host signer needs no such guard, as its read-then-write is serialized
    /// by the owner lend.
    fn cache_current(&self, fresh: VerifiedAccount) {
        let mut current = self.current.lock().unwrap();
        if fresh.head().position >= current.head().position {
            *current = fresh;
        }
    }
    /// Whether this device is active in the account's original three-event
    /// signup prefix, from the journal's verified history.
    fn in_signup(&self) -> Result<bool, SignerError> {
        let record = DeviceJournal::from_shared(self.database.clone())
            .load()
            .map_err(|_| SignerError)?
            .ok_or(SignerError)?;
        let events = record.history.get(..3).ok_or(SignerError)?;
        let mut view =
            VerifiedAccount::from_genesis(record.anchor, &events[0]).map_err(|_| SignerError)?;
        view.apply(&events[1]).map_err(|_| SignerError)?;
        view.apply(&events[2]).map_err(|_| SignerError)?;
        Ok(view.active_device(self.device).is_ok())
    }
    fn apply_now(
        &self,
        after: AccountHead,
        originals: &[TimedOriginal],
    ) -> Result<AccountHead, AccountApplyError> {
        self.apply_attempts.fetch_add(1, Ordering::SeqCst);
        let (mut account, cap) = match self.activated() {
            Ok((account, cap, _)) => (account, cap),
            Err(_) if self.account_stopped() => return Err(AccountApplyError::Stopped),
            Err(_) => return Err(AccountApplyError::Unavailable),
        };
        if account
            .verified(&cap)
            .map_err(|_| AccountApplyError::Unavailable)?
            .head()
            != after
        {
            return Err(AccountApplyError::Unavailable);
        }
        let timed: Vec<_> = originals
            .iter()
            .map(|(original, evidence)| (original.as_slice(), evidence.clone()))
            .collect();
        let head = account
            .apply_incoming_timed(&timed)
            .map_err(|error| match error {
                OwnerError::Refused(_) => AccountApplyError::Refused,
                OwnerError::Unsupported(_) => AccountApplyError::Unsupported,
                OwnerError::Invalid(bh_account::Error::Unavailable) => {
                    AccountApplyError::Unavailable
                }
                OwnerError::Invalid(_) | OwnerError::Stopped => AccountApplyError::Stopped,
                _ => AccountApplyError::Unavailable,
            })?;
        self.cache_current(
            account
                .verified(&cap)
                .map_err(|_| AccountApplyError::Unavailable)?
                .clone(),
        );
        // A staged addition the applied history resolves is settled, as the
        // host's adapter does after each apply; a failure is retried then.
        if account.staged_admission().is_ok_and(|row| row.is_some()) {
            let _ = account.reconcile_staged_admission(None);
        }
        self.applied.lock().unwrap().push(head);
        Ok(head)
    }
    /// Whether the account owner has latched its stop.
    pub fn account_stopped(&self) -> bool {
        let mut account = self.unloaded_owner();
        matches!(ready(account.activate()), Ok(AccountLoad::Stopped))
    }
    /// The account owner over the device's journal and key store, not yet
    /// activated.
    fn unloaded_owner(&self) -> Account {
        let store = self.seeds.store(&self.generation);
        Account::new(
            DeviceJournal::from_shared(self.database.clone()),
            store,
            protector::PlainProtector,
            self.generation.clone(),
        )
    }
    /// A control-key-signed event extending another successor of the head
    /// the base genesis names: given to a device that applied a different
    /// successor there, it is authenticated history contradicting its own.
    pub fn fork_successor(&self) -> Vec<u8> {
        let control = SigningKey::from_seed(&self.seeds.control);
        let sign = |view: &VerifiedAccount, seed: u8| {
            let request = view.add_device(self.device, test_keys(seed)).unwrap();
            request
                .finish(control.sign(request.signing_bytes()))
                .unwrap()
        };
        let mut branch = self.anchor.lock().unwrap().clone();
        let time = ConfirmedTime {
            earliest_ms: u64::MAX / 2,
            latest_ms: u64::MAX / 2,
        };
        branch
            .apply_timed(sign(&branch, 91).as_bytes(), Some(time))
            .unwrap();
        sign(&branch, 101).as_bytes().to_vec()
    }
    fn sign_control_now(
        &self,
        expected: [u8; 32],
        message: &[u8],
        copies: &[u8],
    ) -> Result<[u8; 64], ControlSignError> {
        self.control_requests.fetch_add(1, Ordering::SeqCst);
        if !self.approve_controls.load(Ordering::SeqCst) && !self.approvals.take(copies) {
            return Err(ControlSignError::ConfirmationNeeded);
        }
        let (mut account, cap) = self.owner().ok_or(ControlSignError::Unavailable)?;
        let signature = ready(account.sign_base_control(&cap, &expected, message))
            .map_err(|_| ControlSignError::Unavailable)?;
        self.control_signatures.fetch_add(1, Ordering::SeqCst);
        Ok(signature)
    }
    /// Sign the addition of a device with this device's control key, as
    /// pairing does once the person confirms it. Not applied here: the
    /// account home orders it and this device follows it from the log.
    pub fn add_device(&self, keys: DevicePublicKeys) -> Vec<u8> {
        let (mut account, cap) = self.owner().expect("active account");
        let request = account.prepare_add_device(&cap, keys).unwrap();
        let event = ready(account.sign_control(&cap, &request)).unwrap();
        event.as_bytes().to_vec()
    }
    pub fn request_removal(&self, target: DeviceId) -> Vec<u8> {
        let (mut owner, cap) = self.owner().expect("active account");
        let request = owner
            .verified(&cap)
            .unwrap()
            .request_removal(self.device, target)
            .unwrap();
        ready(owner.sign_control(&cap, &request))
            .unwrap()
            .as_bytes()
            .to_vec()
    }
    /// This device's cancellation of removal request `request`, signed with
    /// its control key: not applied here; the account home orders it.
    pub fn cancel_removal(&self, _target: DeviceId, request: u64) -> Option<Vec<u8>> {
        let (mut account, cap) = self.owner()?;
        let request = account
            .verified(&cap)
            .unwrap()
            .cancel_removal(self.device, request)
            .ok()?;
        Some(
            ready(account.sign_control(&cap, &request))
                .ok()?
                .as_bytes()
                .to_vec(),
        )
    }

    /// Detached signed chain for a full-page hostile-home fixture. Does not
    /// change this owner's durable account or its cached current view.
    pub fn signed_additions(&self, count: u8, at: u64) -> Vec<Vec<u8>> {
        let control = SigningKey::from_seed(&self.seeds.control);
        let mut view = self.current.lock().unwrap().clone();
        (0..count)
            .map(|index| {
                let keys = if index < 81 {
                    test_keys(10 + index * 3)
                } else {
                    // The compact one-byte fixture seeds run out past 81
                    // additions. Keep the long-history keys distinct.
                    let mut signing = [0xa1; 32];
                    signing[0] = index;
                    let mut control = [0xb2; 32];
                    control[0] = index;
                    let mut receiving = [0xc3; 1216];
                    receiving[0] = index;
                    DevicePublicKeys::new(signing, control, receiving).unwrap()
                };
                let request = view.add_device(self.device, keys).unwrap();
                let event = request
                    .finish(control.sign(request.signing_bytes()))
                    .unwrap();
                view.apply_timed(
                    event.as_bytes(),
                    Some(ConfirmedTime {
                        earliest_ms: at,
                        latest_ms: at,
                    }),
                )
                .unwrap();
                event.as_bytes().to_vec()
            })
            .collect()
    }
    /// `signed_additions` followed by this device's removal of itself,
    /// signed on that detached chain: a long history ending in removal.
    pub fn signed_additions_then_removal(&self, count: u8, at: u64) -> Vec<Vec<u8>> {
        let mut chain = self.signed_additions(count, at);
        let control = SigningKey::from_seed(&self.seeds.control);
        let mut view = self.current.lock().unwrap().clone();
        for event in &chain {
            view.apply_timed(
                event,
                Some(ConfirmedTime {
                    earliest_ms: at,
                    latest_ms: at,
                }),
            )
            .unwrap();
        }
        let request = view.remove_self(self.device).unwrap();
        let removal = request
            .finish(control.sign(request.signing_bytes()))
            .unwrap();
        chain.push(removal.as_bytes().to_vec());
        chain
    }
    /// This device's removal of itself, signed with its ordinary key rather
    /// than the control key the account names for it: a wrong signer.
    pub fn remove_self_signed_by_ordinary_key(&self) -> Vec<u8> {
        let view = self.current.lock().unwrap().clone();
        let request = view.remove_self(self.device).unwrap();
        let ordinary = SigningKey::from_seed(&self.seeds.ordinary);
        let mut event = request.signing_bytes().to_vec();
        event.extend(ordinary.sign(request.signing_bytes()));
        event
    }
    /// This device's removal of itself, signed with its control key: not
    /// applied here; the account home orders it.
    pub fn remove_self(&self) -> Vec<u8> {
        let (mut account, cap) = self.owner().expect("active account");
        let request = account.prepare_remove_self(&cap).unwrap();
        let event = ready(account.sign_control(&cap, &request)).unwrap();
        event.as_bytes().to_vec()
    }
    /// This device's rotation of the personal key for the removal at
    /// `removal`, signed with its ordinary key: not applied here; the
    /// account home orders it. Also its prepared seals (each member
    /// device's and the recovery key's) and the new key.
    pub fn rotate_personal(
        &self,
        removal: u64,
        at: u64,
    ) -> (
        Vec<u8>,
        bh_account::personal::PreparedRotation,
        bh_account::personal::PersonalKey,
    ) {
        let (account, cap) = self.owner().expect("active account");
        let view = account.verified(&cap).unwrap().clone();
        let next = bh_account::personal::PersonalKey::generate();
        let prepared = bh_account::personal::prepare_rotation(&view.advanced(at), &next).unwrap();
        let request = view
            .rotate_personal(
                self.device,
                removal,
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .unwrap();
        let signature = self.ordinary.sign(request.signing_bytes());
        let rotation = request.finish(signature).unwrap();
        (rotation.as_bytes().to_vec(), prepared, next)
    }
    /// Accept the rotation at `position` with its ordered `body`, as the
    /// host does once the account history holding it is applied: the
    /// keyring is re-sealed to the new key.
    pub fn accept_rotation(&self, position: u64, body: &[u8]) {
        self.delivered_personal();
        let (mut account, cap) = self.owner().expect("active account");
        let cap = Arc::new(cap);
        ready(bh_device::own_base::ensure_keyring(
            &mut account,
            cap.clone(),
            self.database.clone(),
        ))
        .unwrap();
        ready(account.accept_rotation(&cap, position, body)).unwrap();
    }
    /// `root` sealed as a base content key of `base` to the personal key
    /// `to`, sent by this device at its account's current verified head.
    pub fn seal_content_key(
        &self,
        base: BaseId,
        root: &Secret<32>,
        to: &bh_account::personal::PersonalKey,
    ) -> Vec<u8> {
        use bh_device::base_keys::{BaseKeyPurpose, SealHeader, prepare_seal};
        let (account, cap) = self.owner().expect("active account");
        let history = account.verified(&cap).unwrap().clone();
        let header = SealHeader {
            purpose: BaseKeyPurpose::Content,
            base,
            audience: [0; 32],
            key_id: bh_crypto::committed_key_id(root),
            recipient: bh_crypto::hash(&to.public()),
            sender: history.id(),
            device: self.device,
            head: history.head(),
        };
        let unsigned = prepare_seal(&history, header, &to.public(), root).unwrap();
        let signature = self.ordinary.sign(unsigned.signing_bytes());
        unsigned.finish(signature).unwrap()
    }
    /// `root` sealed as a base content key of `base` to the personal public
    /// key `to`, as `seal_content_key` does for a key this test holds.
    pub fn seal_content_key_to(&self, base: BaseId, root: &Secret<32>, to: &[u8; 1216]) -> Vec<u8> {
        use bh_device::base_keys::{BaseKeyPurpose, SealHeader, prepare_seal};
        let (account, cap) = self.owner().expect("active account");
        let history = account.verified(&cap).unwrap().clone();
        let header = SealHeader {
            purpose: BaseKeyPurpose::Content,
            base,
            audience: [0; 32],
            key_id: bh_crypto::committed_key_id(root),
            recipient: bh_crypto::hash(to),
            sender: history.id(),
            device: self.device,
            head: history.head(),
        };
        let unsigned = prepare_seal(&history, header, to, root).unwrap();
        let signature = self.ordinary.sign(unsigned.signing_bytes());
        unsigned.finish(signature).unwrap()
    }
    /// Stage an already-signed trust control, as the host does once the
    /// person confirms it (`AccountOwner::stage_control`).
    pub fn stage(&self, event: &[u8]) -> StagedControl {
        let (mut account, cap) = self.owner().expect("active account");
        account
            .stage_control(&cap, event, None, None, None)
            .unwrap()
    }
    /// What this device has staged and not yet settled.
    pub fn staged(&self) -> Option<StagedControl> {
        DeviceJournal::from_shared(self.database.clone())
            .staged_control()
            .unwrap()
    }
    /// The personal public key this device holds accepted.
    pub fn accepted_personal(&self) -> [u8; 1216] {
        self.delivered_personal();
        let (mut account, cap) = self.owner().expect("active account");
        ready(account.open_current_personal(&cap)).unwrap().public()
    }
    /// Keep `content` in memory as the epoch key it commits to, as the
    /// host's own base does once a key is installed.
    pub fn hold_epoch(&self, content: Secret<32>) {
        self.epochs
            .lock()
            .unwrap()
            .entry(bh_crypto::committed_key_id(&content))
            .or_insert(content);
    }
    /// Whether this signer holds the key of `epoch` in memory.
    pub fn holds_epoch(&self, epoch: [u8; 32]) -> bool {
        self.epochs.lock().unwrap().contains_key(&epoch)
    }
    /// Refuse another base's keys, and a client that holds the container's
    /// writer lock while it asks for keys.
    fn key_lock_free(&self, base: BaseId) -> Result<(), SignerError> {
        if base != self.base {
            self.wrong_base.store(true, Ordering::SeqCst);
            return Err(SignerError);
        }
        // A host signer may take the container's writer lock to reach its
        // keys. The client must not hold it here: with a plain lock this
        // would deadlock, so it is tried for a while and reported instead.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match self.database.try_lock() {
                Ok(guard) => break drop(guard),
                Err(_) if std::time::Instant::now() < deadline => std::thread::yield_now(),
                Err(_) => {
                    self.owner_lock_held.store(true, Ordering::SeqCst);
                    return Err(SignerError);
                }
            }
        }
        Ok(())
    }
    /// The base roots, as the joining bootstrap will deliver them.
    fn roots(&self) -> (Secret<32>, Secret<32>) {
        (
            Secret::from_slice(self.metadata.expose()).unwrap(),
            Secret::from_slice(self.content.expose()).unwrap(),
        )
    }
}
impl Signer for TestSigner {
    fn identity(&self) -> Result<Identity, SignerError> {
        Ok(Identity {
            account: self.account,
            device: self.device,
            genesis: self.genesis.clone(),
            anchor: self.anchor.lock().unwrap().clone(),
        })
    }
    fn device_proof(&self, context: Context) -> BoxFuture<'_, Result<Proof, SignerError>> {
        let member = self.still_member();
        Box::pin(async move {
            member?;
            let current = self.current.lock().unwrap().clone();
            let request =
                device_auth::prepare(&current, self.device, context).map_err(|_| SignerError)?;
            let signature = self.ordinary.sign(request.message());
            request.finish(signature).map_err(|_| SignerError)
        })
    }
    fn device_proof_at(
        &self,
        head: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        let member = self.still_member();
        Box::pin(async move {
            member?;
            let view = self.view_at(head).ok_or(SignerError)?;
            let request =
                device_auth::prepare(&view, self.device, context).map_err(|_| SignerError)?;
            let signature = self.ordinary.sign(request.message());
            request.finish(signature).map_err(|_| SignerError)
        })
    }
    fn initial_home_setup(&self) -> Result<Option<HomeSetup>, SignerError> {
        if self.no_home_obligation.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let retained = DeviceJournal::from_shared(self.database.clone())
            .initial_bootstrap()
            .map_err(|_| SignerError)?;
        if retained.is_none() {
            // Only a device that joined later has none; a first device's
            // missing record is never treated as no obligation.
            return if self.in_signup()? {
                Err(SignerError)
            } else {
                Ok(None)
            };
        }
        let (account, cap, generation) = self.activated()?;
        let (prefix, objects) = account.initial_bootstrap(&cap).map_err(|_| SignerError)?;
        let mut setup = HomeSetup {
            prefix,
            objects,
            generation,
        };
        if let Some(tamper) = self.tamper.lock().unwrap().as_ref() {
            tamper(&mut setup);
        }
        Ok(Some(setup))
    }
    fn confirm_home_ordered(
        &self,
        setup: &HomeSetup,
        evidence: [(ConfirmedTime, Vec<u8>); 2],
    ) -> Result<(), SignerError> {
        self.confirm_attempts.fetch_add(1, Ordering::SeqCst);
        if self.refuse_confirm.load(Ordering::SeqCst) {
            return Err(SignerError);
        }
        let (mut account, cap, generation) = self.activated()?;
        if generation != setup.generation || cap.account_id() != setup.prefix.anchor {
            self.stale_confirms.fetch_add(1, Ordering::SeqCst);
            return Err(SignerError);
        }
        // A setup whose pending record is already gone (an earlier client
        // cleared it) is complete once its home holds the objects.
        match account.confirm_home_ordered(setup.prefix.head, Some(evidence)) {
            Ok(()) | Err(SetupError::NotStarted) => {}
            Err(_) => return Err(SignerError),
        }
        // Both the current account and the creator anchor now carry the
        // setup's times.
        let head = self.anchor.lock().unwrap().head();
        let anchor = account
            .verified_at(&cap, head.position)
            .map_err(|_| SignerError)?;
        if anchor.head() != head {
            return Err(SignerError);
        }
        self.cache_current(account.verified(&cap).map_err(|_| SignerError)?.clone());
        *self.anchor.lock().unwrap() = anchor;
        self.home_ordered
            .lock()
            .unwrap()
            .push((setup.prefix.head, generation));
        Ok(())
    }
    fn sign_event(&self, message: Vec<u8>) -> BoxFuture<'_, Result<[u8; 64], SignerError>> {
        let hold = self.sign_hold.lock().unwrap().take();
        self.sign_asked
            .lock()
            .unwrap()
            .push(tokio::time::Instant::now());
        let time = *self.sign_time.lock().unwrap();
        Box::pin(async move {
            if let Some((arrived, release)) = hold {
                let _ = arrived.send(());
                let _ = release.await;
            }
            if !time.is_zero() {
                tokio::time::sleep(time).await;
            }
            self.signed.fetch_add(1, Ordering::SeqCst);
            Ok(self.ordinary.sign(&message))
        })
    }
    fn current_account(&self) -> Result<VerifiedAccount, SignerError> {
        Ok(self.current.lock().unwrap().clone())
    }
    fn apply_account_timed(
        &self,
        after: AccountHead,
        originals: Vec<TimedOriginal>,
    ) -> BoxFuture<'_, Result<AccountHead, AccountApplyError>> {
        // The test key store is not Send: the work is done before the future.
        let result = self.apply_now(after, &originals);
        Box::pin(async move { result })
    }
    fn observe_account_accepted(
        &self,
        head: AccountHead,
        time: ConfirmedTime,
    ) -> Result<(), SignerError> {
        let (mut owner, cap, _) = self.activated()?;
        owner
            .observe_accepted_alerts(&cap, head, time)
            .map_err(|_| SignerError)?;
        let current = owner.verified(&cap).map_err(|_| SignerError)?.clone();
        self.cache_current(current.clone());
        let mut anchor = self.anchor.lock().unwrap();
        if anchor.head() == head {
            *anchor = current;
        }
        Ok(())
    }
    fn sign_base_control(
        &self,
        request: BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>> {
        let result = self.sign_control_now(request.expected_key, &request.message, &request.copies);
        Box::pin(async move { result })
    }
    fn staged_addition(&self) -> Result<Option<StagedAdmission>, SignerError> {
        DeviceJournal::from_shared(self.database.clone())
            .staged_admission()
            .map_err(|_| SignerError)
    }
    fn staged_control(&self) -> Result<Option<StagedControl>, SignerError> {
        DeviceJournal::from_shared(self.database.clone())
            .staged_control()
            .map_err(|_| SignerError)
    }
    fn stage_rotation(&self, at_ms: u64) -> BoxFuture<'_, Result<StagedControl, SignerError>> {
        // The test key store is not Send: the work is done before the future.
        let result = (|| {
            if self.refuse_rotation.load(Ordering::SeqCst) {
                return Err(SignerError);
            }
            let (mut account, cap, _) = self.activated()?;
            ready(account.stage_rotation(&cap, at_ms)).map_err(|_| SignerError)
        })();
        if result.is_ok() {
            self.rotations_staged.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(async move { result })
    }
    fn settle_staged(&self) -> Result<Option<Settlement>, SignerError> {
        if self.owner_lent.load(Ordering::SeqCst) {
            return Err(SignerError);
        }
        let (mut account, _, _) = self.activated()?;
        account.settle_staged().map_err(|_| SignerError)
    }
    fn discard_staged(&self, expected: &StagedControl) -> Result<(), SignerError> {
        if self.owner_lent.load(Ordering::SeqCst) {
            return Err(SignerError);
        }
        let (mut account, _, _) = self.activated()?;
        account.discard_staged(expected).map_err(|_| SignerError)
    }
    fn accept_rotation(
        &self,
        position: u64,
        raw: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), SignerError>> {
        // As the host does: the keyring made ready, the rotation accepted,
        // then the current account and creator anchor read again.
        self.delivered_personal();
        self.accept_attempts.fetch_add(1, Ordering::SeqCst);
        let result = (|| {
            let (mut account, cap, _) = self.activated()?;
            let cap = Arc::new(cap);
            ready(bh_device::own_base::ensure_keyring(
                &mut account,
                cap.clone(),
                self.database.clone(),
            ))
            .map_err(|_| SignerError)?;
            ready(account.accept_rotation(&cap, position, &raw)).map_err(|_| SignerError)?;
            self.cache_current(account.verified(&cap).map_err(|_| SignerError)?.clone());
            let head = self.anchor.lock().unwrap().head();
            let anchor = account
                .verified_at(&cap, head.position)
                .map_err(|_| SignerError)?;
            if anchor.head() == head {
                *self.anchor.lock().unwrap() = anchor;
            }
            self.accepts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })();
        Box::pin(async move { result })
    }
    fn prepare_base_entry(
        &self,
        base: BaseId,
        epoch: [u8; 32],
        server: String,
        version: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>, SignerError>> {
        let result = (|| {
            if base != self.base {
                return Err(SignerError);
            }
            let root = self
                .epochs
                .lock()
                .unwrap()
                .get(&epoch)
                .map(|key| Secret::from_slice(key.expose()).unwrap())
                .ok_or(SignerError)?;
            let (mut account, cap, _) = self.activated()?;
            let history = account.verified(&cap).map_err(|_| SignerError)?.clone();
            let recipient = *history.personal_public().map_err(|_| SignerError)?;
            use bh_device::base_keys::{
                BaseKeyPurpose, InitialBaseKeyPackage, SealHeader, prepare_seal,
            };
            // As the host does: the base's original seals while they are this
            // epoch's and sealed to the current personal key, else fresh ones.
            let package = self
                .database
                .lock()
                .unwrap()
                .own_base()
                .unwrap()
                .ok_or(SignerError)?
                .initial_key_package;
            let package = InitialBaseKeyPackage::decode(&package).map_err(|_| SignerError)?;
            let (metadata_seal, current_key_seal) = match SealHeader::decode(package.content_seal())
            {
                Ok(header)
                    if header.key_id == epoch
                        && header.recipient == bh_crypto::hash(&recipient) =>
                {
                    (
                        package.metadata_seal().to_vec(),
                        package.content_seal().to_vec(),
                    )
                }
                _ => {
                    let header = SealHeader {
                        purpose: BaseKeyPurpose::Metadata,
                        base,
                        audience: [0; 32],
                        key_id: bh_event::key_id(&self.metadata),
                        recipient: bh_crypto::hash(&recipient),
                        sender: history.id(),
                        device: self.device,
                        head: history.head(),
                    };
                    let seal = |header: SealHeader, key: &Secret<32>| {
                        let unsigned = prepare_seal(&history, header, &recipient, key)
                            .map_err(|_| SignerError)?;
                        let signature = self.ordinary.sign(unsigned.signing_bytes());
                        unsigned.finish(signature).map_err(|_| SignerError)
                    };
                    (
                        seal(header, &self.metadata)?,
                        seal(
                            SealHeader {
                                purpose: BaseKeyPurpose::Content,
                                key_id: epoch,
                                ..header
                            },
                            &root,
                        )?,
                    )
                }
            };
            let entry = bh_account::directory::DirectoryEntry::Base {
                base: base.0,
                server,
                epoch_id: epoch,
                current_key_seal,
                metadata_seal,
                own: true,
            };
            ready(account.prepare_directory_entry(&cap, &entry, version)).map_err(|_| SignerError)
        })();
        Box::pin(async move { result })
    }
    fn open_directory_entries(
        &self,
        entries: Vec<Vec<u8>>,
    ) -> BoxFuture<'_, Result<bh_sync_client::OpenedEntries, SignerError>> {
        let result = (|| {
            if self.own.fail_reads.load(Ordering::SeqCst) && !entries.is_empty() {
                return Err(SignerError);
            }
            let (mut account, cap, _) = self.activated()?;
            let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
            ready(account.open_directory_entries(&cap, &refs)).map_err(|_| SignerError)
        })();
        Box::pin(async move { result })
    }
    fn directory_state(&self) -> Result<Option<(u64, bool)>, SignerError> {
        self.database
            .lock()
            .unwrap()
            .directory_state()
            .map_err(|_| SignerError)
    }
    fn set_directory_state(&self, version: u64, written: bool) -> Result<(), SignerError> {
        self.database
            .lock()
            .unwrap()
            .set_directory_state(version, written)
            .map_err(|_| SignerError)
    }
    fn own_entries(&self) -> BoxFuture<'_, Result<bh_sync_client::OwnEntries, SignerError>> {
        // As the host does: only the name it was given, once.
        let result = (|| {
            if self.own.fail_own.load(Ordering::SeqCst) {
                return Err(SignerError);
            }
            let Some(name) = self.own.label.lock().unwrap().clone() else {
                return Ok(Vec::new());
            };
            let (mut account, cap, _) = self.activated()?;
            let entry = bh_account::directory::DirectoryEntry::DeviceName {
                device: cap.device_id(),
                name,
            };
            Ok(ready(account.prepare_own_entry(&cap, &entry, 1))
                .map_err(|_| SignerError)?
                .map(|(_, bytes)| (1, bytes))
                .into_iter()
                .collect())
        })();
        Box::pin(async move { result })
    }
    fn own_entry_held(&self, entry: [u8; 32], version: u64) -> Result<(), SignerError> {
        let (mut account, _, _) = self.activated()?;
        account
            .own_entry_held(entry, version)
            .map_err(|_| SignerError)
    }
    fn directory_wanted(&self) -> bool {
        self.own.wanted.swap(false, Ordering::SeqCst)
    }
    fn directory_read(&self, read: bh_sync_client::DirectoryRead) {
        self.own.reads.lock().unwrap().push(read.names);
        self.own
            .checks
            .lock()
            .unwrap()
            .push(read.password_check.is_some());
    }
    fn directory_unread(&self) {
        self.own.unread.fetch_add(1, Ordering::SeqCst);
    }
    fn with_metadata_key(
        &self,
        base: BaseId,
        use_key: &mut dyn FnMut(&Secret<32>),
    ) -> Result<(), SignerError> {
        self.key_lock_free(base)?;
        use_key(&self.metadata);
        Ok(())
    }
    fn with_epoch_keys(
        &self,
        base: BaseId,
        epoch: Option<[u8; 32]>,
        use_keys: &mut dyn FnMut(&Secret<32>, Option<&Secret<32>>),
    ) -> Result<(), SignerError> {
        self.key_lock_free(base)?;
        self.epoch_asks.lock().unwrap().push(epoch);
        // Only roots already in memory, and only the epoch's own; the
        // closure calls into the Owner, which takes its own locks: none of
        // the signer's may be held across it.
        let content = match self.content_override.lock().unwrap().as_ref() {
            Some(key) => Some(Secret::from_slice(key.expose()).expect("32 bytes")),
            None => epoch.and_then(|epoch| {
                self.epochs
                    .lock()
                    .unwrap()
                    .get(&epoch)
                    .map(|key| Secret::from_slice(key.expose()).expect("32 bytes"))
            }),
        };
        use_keys(&self.metadata, content.as_ref());
        Ok(())
    }
    fn install_epoch(
        &self,
        wait: SealWait,
        set: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), InstallError>> {
        // As the host does: the set opened with M, then the account owner
        // opens P and installs this account's seal; the test key store is
        // not Send, so the work is done before the future.
        self.install_attempts.fetch_add(1, Ordering::SeqCst);
        let result = (|| {
            if wait.base != self.base.0 {
                return Err(InstallError::Invalid);
            }
            let opened = open_seal_set(&wait, &self.metadata, &set)?;
            let (mut account, cap, _) = self.activated().map_err(|_| InstallError::Unavailable)?;
            let content = ready(install_sealed_epoch(
                &mut account,
                Arc::new(cap),
                self.database.clone(),
                &wait,
                &opened,
            ))?;
            self.hold_epoch(content);
            self.installs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })();
        Box::pin(async move { result })
    }
}

/// A host that confirms this device's own rule changes: test-only admission,
/// never compiled into a product path.
pub struct Confirmed;
impl HostAdmission for Confirmed {
    fn confirms(&self, request: &Confirmation, _at: Option<Position>) -> Result<bool, DataError> {
        Ok(matches!(request.actor, Actor::Device { .. }))
    }
}

/// One open note this device writes to.
pub struct Writer {
    pub note: [u8; 32],
    window: String,
    generation: u64,
    token: [u8; 32],
    author: Note,
    requests: u8,
}
impl Writer {
    /// The window showing this note.
    pub fn window(&self) -> &str {
        &self.window
    }
}

pub struct Device {
    pub dir: tempfile::TempDir,
    pub owner: Arc<Owner>,
    pub id: ContainerId,
    pub base: BaseId,
    pub signer: Arc<TestSigner>,
    pub account_log: LogId,
    pub originals: Vec<Vec<u8>>,
    /// The recovery kit's code as signup printed it, on the signup device.
    pub kit: Option<String>,
    fixture_join: bool,
    windows: Mutex<u32>,
    /// The label and colour presence uses when this device's client starts.
    presence: Mutex<Option<(String, u8)>>,
}

impl Device {
    /// Sign up and create the own base, as signup leaves a device.
    pub fn new() -> Self {
        Self::new_with_maintenance(true)
    }

    pub fn new_with_maintenance(enabled: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(if enabled {
            Owner::default()
        } else {
            Owner::without_maintenance()
        });
        let id = owner.create_container(dir.path()).unwrap();
        let db = owner.shared_database(id).unwrap();
        let generation = AccountGeneration::new();
        let generation_for_signer = generation.clone();
        let store = store::FakeStore::new(generation.clone());
        let mut account = Account::new(
            DeviceJournal::from_shared(db.clone()),
            store.clone(),
            protector::PlainProtector,
            generation,
        );
        ready(account.begin_first_device(
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            &Password::new("correct horse battery staple").unwrap(),
        ))
        .unwrap();
        let kit = account.pending_kit_code().unwrap().to_kit_text();
        // As the app's signup leaves it: the kit saved, the account home not
        // yet known to have ordered the signup history.
        account.confirm_kit_saved().unwrap();
        let record = DeviceJournal::from_shared(db.clone())
            .load()
            .unwrap()
            .unwrap();
        let history = record.history.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let verified = VerifiedAccount::replay(record.anchor, &history, record.head).unwrap();
        owner.anchor(id, &verified).unwrap();
        let cap = match ready(account.activate()).unwrap() {
            AccountLoad::Active(c) => Arc::new(c),
            _ => panic!("not active"),
        };
        let own = ready(create_or_open(&mut account, cap.clone(), db.clone())).unwrap();
        let base = own.id();
        let (metadata, content) = own
            .with_keys(|m, k| {
                (
                    Secret::from_slice(m.expose()).unwrap(),
                    Secret::from_slice(k.expose()).unwrap(),
                )
            })
            .unwrap();
        let epochs = held_epochs(&own, &db);
        owner.authorize(id, cap.clone(), base.0).unwrap();
        let seeds = Self::seeds(&store);
        let ordinary = SigningKey::from_seed(&seeds.ordinary);
        let genesis = record.history[0].clone();
        let signer = Arc::new(TestSigner {
            ordinary,
            seeds,
            current: Mutex::new(verified.clone()),
            anchor: Mutex::new(verified),
            account: cap.account_id(),
            device: cap.device_id(),
            genesis: genesis.clone(),
            metadata,
            content,
            epochs: Mutex::new(epochs),
            content_override: Mutex::default(),
            epoch_asks: Mutex::default(),
            install_attempts: AtomicUsize::new(0),
            installs: AtomicUsize::new(0),
            database: db.clone(),
            generation: generation_for_signer,
            base,
            fixture_join: false,
            wrong_base: AtomicBool::new(false),
            owner_lock_held: AtomicBool::new(false),
            home_ordered: Mutex::default(),
            stale_confirms: AtomicUsize::new(0),
            refuse_confirm: AtomicBool::new(false),
            confirm_attempts: AtomicUsize::new(0),
            tamper: Mutex::default(),
            no_home_obligation: AtomicBool::new(false),
            proofs_need_membership: AtomicBool::new(false),
            approve_controls: AtomicBool::new(true),
            approvals: Approvals::default(),
            control_requests: AtomicUsize::new(0),
            control_signatures: AtomicUsize::new(0),
            applied: Mutex::default(),
            apply_attempts: AtomicUsize::new(0),
            sign_hold: Mutex::default(),
            signed: AtomicUsize::new(0),
            sign_time: Mutex::default(),
            sign_asked: Mutex::default(),
            accept_attempts: AtomicUsize::new(0),
            accepts: AtomicUsize::new(0),
            rotations_staged: AtomicUsize::new(0),
            refuse_rotation: AtomicBool::new(false),
            owner_lent: AtomicBool::new(false),
            own: OwnDirectory::default(),
        });
        Self {
            dir,
            owner,
            id,
            base,
            signer,
            account_log: LogId {
                kind: LogKind::Account,
                id: account_log_id(&genesis).unwrap(),
            },
            originals: record.history,
            kit: Some(kit),
            fixture_join: false,
            windows: Mutex::new(0),
            presence: Mutex::new(None),
        }
    }

    fn seeds(store: &store::FakeStore) -> Seeds {
        Seeds::of(store)
    }

    /// Another device of `first`'s account, with its own native keys,
    /// joined to `first`'s own base. FIXTURE PROVISIONING until pairing
    /// supplies it: `first`'s control key signs the addition, the fake
    /// account home orders it directly, and this device receives the signed
    /// account history, the base's genesis record and its roots M and K by
    /// copy, as the joining bootstrap will deliver them. The base itself
    /// knows of this device only once `first` copies the addition into it.
    pub async fn join(first: &Device, hosted: &Hosted) -> Self {
        Self::join_with_maintenance(first, hosted, true).await
    }

    pub async fn join_with_maintenance(first: &Device, hosted: &Hosted, enabled: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(if enabled {
            Owner::default()
        } else {
            Owner::without_maintenance()
        });
        let id = owner.create_container(dir.path()).unwrap();
        let db = owner.shared_database(id).unwrap();
        let generation = AccountGeneration::new();
        let store = store::FakeStore::new(generation.clone());
        let mut journal = DeviceJournal::from_shared(db.clone());
        let identity = ready(pairing::scanner_identity(
            &mut journal,
            &mut store.clone(),
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        ))
        .unwrap();
        let addition = first.signer.add_device(identity.keys.clone());
        hosted.edge.order_account(first.account_log, &addition);
        let timed = hosted.confirmed_account(first.account_log).await;
        let refs: Vec<_> = timed
            .iter()
            .map(|(original, evidence)| (original.as_slice(), evidence.clone()))
            .collect();
        let history = timed.iter().map(|(original, _)| original.clone()).collect();
        let anchor_id = first.signer.account;
        let mut account = Account::new(
            DeviceJournal::from_shared(db.clone()),
            store.clone(),
            protector::PlainProtector,
            generation.clone(),
        );
        account.adopt_joined_timed(anchor_id, &refs).unwrap();
        let cap = match ready(account.activate()).unwrap() {
            AccountLoad::Active(c) => Arc::new(c),
            other => panic!("joined device not active: {other:?}"),
        };
        let current = account.verified(&cap).unwrap().clone();
        let anchor_head = first.signer.anchor.lock().unwrap().head();
        let anchor = account.verified_at(&cap, anchor_head.position).unwrap();
        assert_eq!(anchor.head(), anchor_head);
        owner.anchor(id, &current).unwrap();
        let record = first
            .owner
            .shared_database(first.id)
            .unwrap()
            .lock()
            .unwrap()
            .own_base()
            .unwrap()
            .unwrap();
        db.lock()
            .unwrap()
            .create_own_base_if_absent(&record, || cap.is_current())
            .unwrap();
        owner
            .record_registration(id, first.base.0, None, hosted.edge.root())
            .unwrap();
        owner.authorize(id, cap.clone(), first.base.0).unwrap();
        let seeds = Self::seeds(&store);
        let ordinary = store.state_mut().ordinary.take().unwrap();
        let (metadata, content) = first.signer.roots();
        let epochs = genesis_epoch(&content);
        let signer = Arc::new(TestSigner {
            ordinary,
            seeds,
            anchor: Mutex::new(anchor),
            current: Mutex::new(current),
            account: anchor_id,
            device: identity.keys.id(),
            genesis: first.signer.genesis.clone(),
            metadata,
            content,
            epochs: Mutex::new(epochs),
            content_override: Mutex::default(),
            epoch_asks: Mutex::default(),
            install_attempts: AtomicUsize::new(0),
            installs: AtomicUsize::new(0),
            database: db.clone(),
            generation,
            base: first.base,
            fixture_join: true,
            wrong_base: AtomicBool::new(false),
            owner_lock_held: AtomicBool::new(false),
            home_ordered: Mutex::default(),
            stale_confirms: AtomicUsize::new(0),
            refuse_confirm: AtomicBool::new(false),
            confirm_attempts: AtomicUsize::new(0),
            tamper: Mutex::default(),
            no_home_obligation: AtomicBool::new(false),
            proofs_need_membership: AtomicBool::new(false),
            approve_controls: AtomicBool::new(true),
            approvals: Approvals::default(),
            control_requests: AtomicUsize::new(0),
            control_signatures: AtomicUsize::new(0),
            applied: Mutex::default(),
            apply_attempts: AtomicUsize::new(0),
            sign_hold: Mutex::default(),
            signed: AtomicUsize::new(0),
            sign_time: Mutex::default(),
            sign_asked: Mutex::default(),
            accept_attempts: AtomicUsize::new(0),
            accepts: AtomicUsize::new(0),
            rotations_staged: AtomicUsize::new(0),
            refuse_rotation: AtomicBool::new(false),
            owner_lent: AtomicBool::new(false),
            own: OwnDirectory::default(),
        });
        Self {
            dir,
            owner,
            id,
            base: first.base,
            signer,
            account_log: first.account_log,
            originals: history,
            kit: None,
            fixture_join: true,
            windows: Mutex::new(0),
            presence: Mutex::new(None),
        }
    }

    /// A device that joined by pairing, once its admission is committed. Its
    /// signer holds its own keys and the base roots it opened itself, from
    /// the delivery its addition carried and the own base's key package.
    pub fn joined(
        dir: tempfile::TempDir,
        owner: Arc<Owner>,
        id: ContainerId,
        generation: AccountGeneration,
        seeds: Seeds,
    ) -> Self {
        let db = owner.shared_database(id).unwrap();
        let mut account = Account::new(
            DeviceJournal::from_shared(db.clone()),
            seeds.store(&generation),
            protector::PlainProtector,
            generation.clone(),
        );
        let cap = match ready(account.activate()).unwrap() {
            AccountLoad::Active(c) => Arc::new(c),
            other => panic!("joined device not active: {other:?}"),
        };
        let own = ready(create_or_open(&mut account, cap.clone(), db.clone())).unwrap();
        let base = own.id();
        let metadata = own
            .with_metadata_key(|m| Secret::from_slice(m.expose()).unwrap())
            .unwrap();
        // The genesis epoch's root, which the original package names.
        let genesis_id = bh_device::base_keys::SealHeader::decode(
            own.initial_key_package().unwrap().content_seal(),
        )
        .unwrap()
        .key_id;
        let epochs = held_epochs(&own, &db);
        let content = Secret::from_slice(epochs[&genesis_id].expose()).unwrap();
        let current = account.verified(&cap).unwrap().clone();
        let anchor = account.verified_at(&cap, 3).unwrap();
        let record = DeviceJournal::from_shared(db.clone())
            .load()
            .unwrap()
            .unwrap();
        let genesis = record.history[0].clone();
        let signer = Arc::new(TestSigner {
            ordinary: SigningKey::from_seed(&seeds.ordinary),
            seeds,
            anchor: Mutex::new(anchor),
            current: Mutex::new(current),
            account: cap.account_id(),
            device: cap.device_id(),
            genesis: genesis.clone(),
            metadata,
            content,
            epochs: Mutex::new(epochs),
            content_override: Mutex::default(),
            epoch_asks: Mutex::default(),
            install_attempts: AtomicUsize::new(0),
            installs: AtomicUsize::new(0),
            database: db.clone(),
            generation,
            base,
            fixture_join: false,
            wrong_base: AtomicBool::new(false),
            owner_lock_held: AtomicBool::new(false),
            home_ordered: Mutex::default(),
            stale_confirms: AtomicUsize::new(0),
            refuse_confirm: AtomicBool::new(false),
            confirm_attempts: AtomicUsize::new(0),
            tamper: Mutex::default(),
            no_home_obligation: AtomicBool::new(false),
            proofs_need_membership: AtomicBool::new(false),
            approve_controls: AtomicBool::new(false),
            approvals: Approvals::default(),
            control_requests: AtomicUsize::new(0),
            control_signatures: AtomicUsize::new(0),
            applied: Mutex::default(),
            apply_attempts: AtomicUsize::new(0),
            sign_hold: Mutex::default(),
            signed: AtomicUsize::new(0),
            sign_time: Mutex::default(),
            sign_asked: Mutex::default(),
            accept_attempts: AtomicUsize::new(0),
            accepts: AtomicUsize::new(0),
            rotations_staged: AtomicUsize::new(0),
            refuse_rotation: AtomicBool::new(false),
            owner_lent: AtomicBool::new(false),
            own: OwnDirectory::default(),
        });
        Self {
            dir,
            owner,
            id,
            base,
            signer,
            account_log: LogId {
                kind: LogKind::Account,
                id: account_log_id(&genesis).unwrap(),
            },
            originals: record.history,
            kit: None,
            fixture_join: false,
            windows: Mutex::new(0),
            presence: Mutex::new(None),
        }
    }

    /// Whether the container may be used: a joined one only once its
    /// bootstrap activated it.
    /// Order a genuinely signed remote producer's update through the local
    /// hosted fixture, without passing it through this device's authoring gate.
    pub fn remote_note(&self, hosted: &Hosted, note: [u8; 32], delta: &[u8]) -> u64 {
        let progress = self.progress();
        let (position, hash) = progress.account.unwrap();
        let writer = bh_event::writer::DeviceWriterDeclaration {
            account: self.signer.account.0,
            device: self.signer.device.0,
            nonce: [71; 32],
        };
        let binding = bh_event::Binding {
            version: 3,
            highest: 3,
            mode: 0,
            base: self.log().id,
            audience: [0; 32],
            epoch: bh_event::key_id(&self.signer.content),
            event_id: bh_sync::EventId(bh_crypto::random()),
            account: self.signer.account,
            device: self.signer.device,
            account_head: AccountHead { position, hash },
            seen: bh_sync::Head {
                position: progress.position,
                hash: bh_sync::Digest(progress.head_hash),
            },
            seen_control: progress.control_digest,
            class: bh_event::CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: progress.receipt.unwrap(),
        };
        let encoded = bh_event::seal(
            binding,
            bh_event::Payload {
                kind: bh_event::NOTE,
                data: &bh_event::note_payload(note, writer, delta),
            },
            &self.signer.ordinary,
            &self.signer.metadata,
            Some(&self.signer.content),
        )
        .unwrap();
        hosted.edge.order(
            self.log(),
            &encoded.descriptor,
            Some(encoded.body),
            bh_sync::Route::Content,
        )
    }

    /// This device's `ACCOUNT_REKEY` installing `root` as its base's new
    /// content key, carrying `rotation` with its ordering `confirmation`,
    /// signed with its ordinary key, and the seal set it commits to.
    pub fn prepare_rekey(
        &self,
        rotation: &[u8],
        confirmation: &[u8],
        root: &Secret<32>,
        seals: Vec<Vec<u8>>,
    ) -> (bh_event::Encoded, bh_sync::BodyObject) {
        let anchor = self.signer.anchor.lock().unwrap().clone();
        let prepared = self
            .owner
            .prepare_rekey(
                self.id,
                &anchor,
                &self.signer.metadata,
                rotation,
                confirmation,
                root,
                seals,
            )
            .unwrap();
        let signature = self.signer.ordinary.sign(prepared.control.signing_bytes());
        let control = prepared.control.finish(signature).unwrap();
        (control, prepared.seal_set)
    }
    /// This device's base metadata root, as the client hands it to the
    /// service for a base control.
    pub fn metadata_key(&self) -> bh_authz::proto::MetadataKey {
        bh_authz::proto::MetadataKey::new(&self.signer.metadata)
    }
    /// As `remote_note`, a first paragraph `text` sealed under `root`, the
    /// content key of the epoch this device's verified history is in.
    pub fn remote_note_under(
        &self,
        hosted: &Hosted,
        root: &Secret<32>,
        note: [u8; 32],
        text: &str,
    ) -> u64 {
        let progress = self.progress();
        let (position, hash) = progress.account.unwrap();
        let writer = bh_event::writer::DeviceWriterDeclaration {
            account: self.signer.account.0,
            device: self.signer.device.0,
            nonce: [72; 32],
        };
        let delta = Note::with_writer(writer.client_id(bh_event::writer::WriterScope {
            base: self.log().id,
            audience: [0; 32],
            note,
        }))
        .unwrap()
        .try_append_paragraph(text)
        .unwrap();
        let binding = bh_event::Binding {
            version: 3,
            highest: 3,
            mode: 0,
            base: self.log().id,
            audience: [0; 32],
            epoch: bh_event::key_id(root),
            event_id: bh_sync::EventId(bh_crypto::random()),
            account: self.signer.account,
            device: self.signer.device,
            account_head: AccountHead { position, hash },
            seen: bh_sync::Head {
                position: progress.position,
                hash: bh_sync::Digest(progress.head_hash),
            },
            seen_control: progress.control_digest,
            class: bh_event::CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: progress.receipt.unwrap(),
        };
        let encoded = bh_event::seal(
            binding,
            bh_event::Payload {
                kind: bh_event::NOTE,
                data: &bh_event::note_payload(note, writer, &delta),
            },
            &self.signer.ordinary,
            &self.signer.metadata,
            Some(root),
        )
        .unwrap();
        hosted.edge.order(
            self.log(),
            &encoded.descriptor,
            Some(encoded.body),
            bh_sync::Route::Content,
        )
    }

    pub fn usable(&self) -> bool {
        self.owner
            .joined(self.id)
            .unwrap()
            .is_none_or(|joined| joined.activated)
    }
    /// Install note authority for the own base, as the host does on open.
    pub fn authorize(&self) -> Result<(), bh_device::OwnerError> {
        let (_, cap, _) = self.signer.account_owner();
        self.owner.authorize(self.id, Arc::new(cap), self.base.0)
    }
    /// The own base's exact initial key package.
    pub fn own_base_package(&self) -> Vec<u8> {
        let db = self.owner.shared_database(self.id).unwrap();
        let record = db.lock().unwrap().own_base().unwrap().unwrap();
        record.initial_key_package
    }

    /// This note's working state, rebuilt from SQLite as a reopened note is.
    pub fn reopened(&self, note: [u8; 32]) -> Note {
        let db = self.owner.shared_database(self.id).unwrap();
        let ordered = db.lock().unwrap().note_ordered(self.key(note)).unwrap();
        Note::from_ordered(&ordered).unwrap()
    }
    /// How many times `text` was inserted into the reopened note: each
    /// inserted run is encoded once in its state, so applying the same
    /// update twice under another writer would show twice.
    pub fn inserted(&self, note: [u8; 32], text: &str) -> usize {
        let state = self.reopened(note).state().unwrap();
        state
            .windows(text.len())
            .filter(|w| *w == text.as_bytes())
            .count()
    }

    /// Open a note this device received, to write to it.
    pub fn writer(&self, note: [u8; 32]) -> Writer {
        let window = {
            let mut n = self.windows.lock().unwrap();
            *n += 1;
            format!("w{n}")
        };
        self.owner.show_note(&window, self.id, note).unwrap();
        let opened = self.owner.open_leased(&window, note).unwrap();
        let lease = opened.writer.unwrap();
        let author = Owner::core_author(&opened).unwrap();
        Writer {
            note,
            window,
            generation: opened.generation,
            token: lease.token,
            author,
            requests: 0,
        }
    }

    /// Local updates not yet accepted.
    pub fn pending(&self) -> usize {
        let db = self.owner.shared_database(self.id).unwrap();
        let db = db.lock().unwrap();
        db.pending_note_updates().unwrap().len()
    }

    /// The signup's retained prefix and private objects, as the device
    /// database holds them.
    pub fn retained(&self) -> InitialBootstrapRecord {
        let db = self.owner.shared_database(self.id).unwrap();
        DeviceJournal::from_shared(db)
            .initial_bootstrap()
            .unwrap()
            .unwrap()
    }
    /// The canonical bundle of the retained objects, as the home stores it.
    pub fn retained_bundle(&self) -> Vec<u8> {
        let r = self.retained();
        bh_sync::home_objects::encode(&r.recovery_record, &r.device_seal, &r.recovery_seal).unwrap()
    }
    /// Complete setup locally from public ordering alone, as an earlier
    /// client did, leaving only the retained initial bootstrap.
    pub fn clear_pending_as_earlier_client(&self) {
        let (mut account, _, _) = self.signer.activated().unwrap();
        account
            .confirm_home_ordered(self.retained().head, None)
            .unwrap();
    }
    /// Whether the first-device setup still waits for the account home.
    pub fn home_pending(&self) -> bool {
        let db = self.owner.shared_database(self.id).unwrap();
        DeviceJournal::from_shared(db)
            .pending_setup()
            .unwrap()
            .is_some()
    }

    pub fn log(&self) -> LogId {
        LogId {
            kind: LogKind::Base,
            id: self.base.0,
        }
    }
    /// Record the presence label and colour a later `start` applies.
    pub fn label_presence(&self, label: &str, colour: u8) {
        *self.presence.lock().unwrap() = Some((label.to_owned(), colour));
    }
    /// This device's genesis epoch content root.
    pub fn content_key(&self) -> Secret<32> {
        Secret::from_slice(self.signer.content.expose()).unwrap()
    }
    /// Type `text` in a fresh window on `note` and return that writer's
    /// client id with a relative position naming its inserted text.
    pub fn type_with_position(&self, note: [u8; 32], text: &str) -> (u64, Vec<u8>) {
        let mut typist = self.typist(note);
        self.type_text(&mut typist, text);
        let position = typist.position();
        (typist.client, position)
    }
    /// Whether an accepted writer binding exists for this note and writer.
    pub fn has_binding(&self, note: [u8; 32], client: u64) -> bool {
        let db = self.owner.shared_database(self.id).unwrap();
        db.lock()
            .unwrap()
            .accepted_binding(self.key(note), client)
            .unwrap()
            .is_some()
    }
    pub fn key(&self, note: [u8; 32]) -> NoteKey {
        NoteKey {
            base: self.base.0,
            audience: [0; 32],
            note,
        }
    }

    pub fn endpoint(&self, hosted: &Hosted) -> Endpoint {
        Endpoint {
            edge_url: "http://edge.invalid".into(),
            hosting_root: hosted.edge.root(),
            app_root: hosted.policy_root.public(),
            policy: Vec::new(),
            policy_signature: Vec::new(),
            limits: bh_confidential_policy::Limits {
                max_lifetime_secs: 86_400,
                max_uncertainty_secs: 0,
            },
            build_floor: 1,
            appraisal: Appraisal::Synthetic,
            device_clock: hosted.edge.clock.clone(),
            recovery_key: hosted.edge.recovery_certificate(),
        }
    }

    /// Start a client over the fake edge, with its status channel. It pays
    /// the edge's current signer and commit costs, at its current pacing.
    pub fn start(&self, hosted: &Arc<Hosted>) -> (Client, watch::Receiver<SyncStatus>) {
        self.start_at(hosted, self.endpoint(hosted))
    }
    /// As `start`, its sockets named `who` in the edge's marks.
    pub fn start_named(
        &self,
        hosted: &Arc<Hosted>,
        who: &'static str,
    ) -> (Client, watch::Receiver<SyncStatus>) {
        self.start_over(hosted, self.endpoint(hosted), hosted.connector_for(who))
    }
    /// Start a client over the real transport to `endpoint`'s edge.
    pub fn start_on(&self, endpoint: Endpoint) -> (Client, watch::Receiver<SyncStatus>) {
        let (status, watch) = watch::channel(SyncStatus::SavedLocal { pending: 0 });
        let client = Client::start(
            endpoint,
            self.owner.clone(),
            self.id,
            self.signer.clone(),
            status,
        );
        (client, watch)
    }
    pub fn start_at(
        &self,
        hosted: &Arc<Hosted>,
        endpoint: Endpoint,
    ) -> (Client, watch::Receiver<SyncStatus>) {
        self.start_over(hosted, endpoint, hosted.connector())
    }
    fn start_over(
        &self,
        hosted: &Arc<Hosted>,
        endpoint: Endpoint,
        connector: Arc<dyn bh_sync_client::transport::Connector>,
    ) -> (Client, watch::Receiver<SyncStatus>) {
        let (status, watch) = watch::channel(SyncStatus::SavedLocal { pending: 0 });
        let costs = hosted.edge.costs();
        *self.signer.sign_time.lock().unwrap() = costs.signer;
        let client = Client::start_tuned(
            endpoint,
            connector,
            self.owner.clone(),
            self.id,
            self.signer.clone(),
            status,
            Tuning {
                pacing: hosted.edge.pacing(),
                commit_delay: costs.commit,
                seen_window: *hosted.edge.seen_window.lock().unwrap(),
                ..Tuning::default()
            },
        );
        if let Some((label, colour)) = self.presence.lock().unwrap().clone() {
            let presence = client.presence();
            presence.configure(&label, colour);
            presence.foreground(true);
        }
        (client, watch)
    }

    /// A new note with its first paragraph committed. Returns the writer
    /// and the update's id.
    pub fn new_note(&self, text: &str) -> (Writer, i64) {
        let note = self.owner.create_note(self.id).unwrap();
        let window = {
            let mut n = self.windows.lock().unwrap();
            *n += 1;
            format!("w{n}")
        };
        self.owner.show_note(&window, self.id, note).unwrap();
        let opened = self.owner.open_leased(&window, note).unwrap();
        let lease = opened.writer.unwrap();
        let author = Owner::core_author(&opened).unwrap();
        let mut writer = Writer {
            note,
            window,
            generation: opened.generation,
            token: lease.token,
            author,
            requests: 0,
        };
        let id = self.append(&mut writer, text);
        (writer, id)
    }

    /// Commit one more paragraph to the writer's note.
    pub fn append(&self, writer: &mut Writer, text: &str) -> i64 {
        let delta = writer.author.try_append_paragraph(text).unwrap();
        writer.requests += 1;
        self.owner
            .commit_leased(
                &writer.window,
                writer.generation,
                writer.token,
                [writer.requests; 16],
                &delta,
            )
            .unwrap();
        let db = self.owner.shared_database(self.id).unwrap();
        let db = db.lock().unwrap();
        db.pending_note_updates()
            .unwrap()
            .iter()
            .map(|p| p.update_id)
            .max()
            .unwrap()
    }

    /// Save one typed mutation in this base's ordinary scope and queue it for
    /// publishing, through the same submit path a host uses.
    pub fn typed_submit(&self, op: Operation) -> (MutationId, i64) {
        self.typed_submit_scoped([0; 32], op)
    }
    pub fn typed_submit_scoped(&self, audience: [u8; 32], op: Operation) -> (MutationId, i64) {
        let scope = Scope {
            base: self.base.0,
            audience,
        };
        if audience != [0; 32] {
            let mut raw = self.raw();
            let tx = raw.transaction().unwrap();
            let sid = bh_data::store::records::scope_id(&tx, scope, &Shipped).unwrap();
            tx.execute("INSERT INTO data_coverage(scope,through,complete) VALUES(?1,0,1) ON CONFLICT(scope) DO UPDATE SET complete=1", [sid]).unwrap();
            tx.commit().unwrap();
        }
        let db = self.owner.shared_database(self.id).unwrap();
        let mut db = db.lock().unwrap();
        let actor = Actor::Device {
            account: self.signer.account.0,
            device: self.signer.device.0,
        };
        let queued = db
            .submit_typed(&Shipped, scope, &actor, op, &Confirmed)
            .unwrap();
        (queued.saved.mutation, queued.package)
    }
    /// This typed work's sealed package, if it has one.
    pub fn typed_package(&self, package: i64) -> Option<bh_storage::StoredTypedPackage> {
        let db = self.owner.shared_database(self.id).unwrap();
        let db = db.lock().unwrap();
        match db.prepare_typed_package(package) {
            Ok(TypedPackagePreparation::Existing(stored)) => Some(stored),
            _ => None,
        }
    }
    pub fn typed_progress(&self, package: i64) -> Option<TypedPackageProgress> {
        let db = self.owner.shared_database(self.id).unwrap();
        let db = db.lock().unwrap();
        db.typed_package_progress(package).unwrap()
    }
    /// The position this typed package's verified Ack recorded.
    pub fn typed_acked(&self, package: i64) -> Option<u64> {
        self.typed_progress(package)?.payload_position
    }
    /// `bh-data`'s own state for a saved typed mutation, if it is still saved.
    pub fn typed_state(&self, mutation: MutationId) -> Option<String> {
        let raw = self.raw();
        raw.query_row(
            "SELECT state FROM data_pending WHERE mutation=?1",
            [mutation.0.as_slice()],
            |r| r.get(0),
        )
        .ok()
    }
    /// This update's sealed package, if it has one.
    pub fn package(&self, update_id: i64) -> Option<StoredNotePackage> {
        let db = self.owner.shared_database(self.id).unwrap();
        let db = db.lock().unwrap();
        db.package_progress(update_id).unwrap()?;
        match db.prepare_note_package(update_id).unwrap() {
            PackagePreparation::Existing(stored) => Some(stored),
            PackagePreparation::Candidate(_) => None,
        }
    }
    /// The position this update's verified Ack recorded.
    pub fn acked(&self, update_id: i64) -> Option<u64> {
        let db = self.owner.shared_database(self.id).unwrap();
        let db = db.lock().unwrap();
        db.package_progress(update_id).unwrap()?.position
    }
    pub fn registered(&self) -> bool {
        let db = self.owner.shared_database(self.id).unwrap();
        let db = db.lock().unwrap();
        db.registration(self.base.0)
            .unwrap()
            .is_some_and(|r| r.registered)
    }
    pub fn progress(&self) -> bh_storage::sync_state::LogProgress {
        let db = self.owner.shared_database(self.id).unwrap();
        let progress = db.lock().unwrap().log_progress(1, self.base.0).unwrap();
        progress.unwrap()
    }
    pub fn raw(&self) -> rusqlite::Connection {
        let path = std::fs::read_dir(self.dir.path().join("accounts"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
            .unwrap();
        rusqlite::Connection::open(path).unwrap()
    }
}

impl Typist {
    /// The content writer this typist is using.
    pub fn client(&self) -> u64 {
        self.client
    }
    /// A relative position at the end of this typist's text, naming its writer.
    pub fn position(&self) -> Vec<u8> {
        use yrs::{Assoc, StickyIndex, Transact, updates::encoder::Encode};
        let txn = self.doc.transact();
        match &self.text {
            Some(text) => StickyIndex::from_type(&txn, text, Assoc::After).encode_v1(),
            None => Vec::new(),
        }
    }
}

/// Types into one note a keystroke at a time, as the editor saves: each
/// keystroke is one committed update inserting a character at the end of
/// this typist's own paragraph, made by its first keystroke. It keeps its
/// document across keystrokes; when the note moved or its writer lease was
/// taken (a remote apply), it reopens, takes in the working state and types
/// on.
pub struct Typist {
    pub note: [u8; 32],
    window: String,
    generation: u64,
    token: [u8; 32],
    client: u64,
    doc: yrs::Doc,
    text: Option<yrs::XmlTextRef>,
    salt: [u8; 8],
    requests: u64,
}

impl Device {
    /// Drop all owners and connections and reopen the actual container.
    /// Call only after stopping/dropping clients and other database handles.
    pub fn restart(self) -> Self {
        assert_eq!(Arc::strong_count(&self.owner), 1, "clients released owner");
        assert_eq!(
            Arc::strong_count(&self.signer),
            1,
            "clients released signer"
        );
        let lock_path = std::fs::read_dir(self.dir.path().join("accounts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "lock"))
            .unwrap();
        let seeds = self.signer.seeds.clone();
        // The Device::join fixture provisions a second identity without
        // pairing's delivered-personal-key row. Rebuild its test signer from
        // its saved native seeds and base roots after opening the database.
        let fixture = if self.fixture_join {
            Some((
                self.signer.anchor.lock().unwrap().clone(),
                self.signer.current.lock().unwrap().clone(),
                self.signer.account,
                self.signer.device,
                self.signer.genesis.clone(),
                self.signer.roots(),
            ))
        } else {
            None
        };
        let account_log = self.account_log;
        let originals = self.originals;
        let dir = self.dir;
        drop(self.owner);
        drop(self.signer);
        // A real process exit also ends its native checkpoint workers. Here
        // a worker may still be destroying its last DB reference (even once
        // Arc's strong count is zero). Synchronize on release of its actual
        // container lock, not a timer, polling interval or assumed delay.
        let lock = std::fs::File::open(lock_path).unwrap();
        lock.lock().unwrap();
        drop(lock);
        let owner = Arc::new(Owner::default());
        let id = owner
            .open_containers(dir.path())
            .unwrap()
            .pop()
            .unwrap()
            .1
            .unwrap();
        if let Some((anchor, current, account, identity, genesis, (metadata, content))) = fixture {
            let epochs = genesis_epoch(&content);
            let generation = AccountGeneration::new();
            let db = owner.shared_database(id).unwrap();
            let signer = Arc::new(TestSigner {
                ordinary: SigningKey::from_seed(&seeds.ordinary),
                seeds,
                anchor: Mutex::new(anchor),
                current: Mutex::new(current),
                account,
                device: identity,
                genesis,
                metadata,
                content,
                epochs: Mutex::new(epochs),
                content_override: Mutex::default(),
                epoch_asks: Mutex::default(),
                install_attempts: AtomicUsize::new(0),
                installs: AtomicUsize::new(0),
                database: db,
                generation,
                base: BaseId(self.base.0),
                fixture_join: true,
                wrong_base: AtomicBool::new(false),
                owner_lock_held: AtomicBool::new(false),
                home_ordered: Mutex::default(),
                stale_confirms: AtomicUsize::new(0),
                refuse_confirm: AtomicBool::new(false),
                confirm_attempts: AtomicUsize::new(0),
                tamper: Mutex::default(),
                no_home_obligation: AtomicBool::new(false),
                proofs_need_membership: AtomicBool::new(false),
                approve_controls: AtomicBool::new(true),
                approvals: Approvals::default(),
                control_requests: AtomicUsize::new(0),
                control_signatures: AtomicUsize::new(0),
                applied: Mutex::default(),
                apply_attempts: AtomicUsize::new(0),
                sign_hold: Mutex::default(),
                signed: AtomicUsize::new(0),
                sign_time: Mutex::default(),
                sign_asked: Mutex::default(),
                accept_attempts: AtomicUsize::new(0),
                accepts: AtomicUsize::new(0),
                rotations_staged: AtomicUsize::new(0),
                refuse_rotation: AtomicBool::new(false),
                owner_lent: AtomicBool::new(false),
                own: OwnDirectory::default(),
            });
            let device = Self {
                dir,
                owner,
                id,
                base: self.base,
                signer,
                account_log,
                originals,
                kit: None,
                fixture_join: true,
                windows: Mutex::new(0),
                presence: Mutex::new(None),
            };
            // The account as the reopened owner verifies it, with its times.
            let (account, cap, _) = device.signer.account_owner();
            let current = account.verified(&cap).unwrap().clone();
            let at = device.signer.anchor.lock().unwrap().head().position;
            *device.signer.anchor.lock().unwrap() = account.verified_at(&cap, at).unwrap();
            *device.signer.current.lock().unwrap() = current.clone();
            device.owner.anchor(id, &current).unwrap();
            device.authorize().unwrap();
            device
        } else {
            let device = Self::joined(dir, owner, id, AccountGeneration::new(), seeds);
            device
                .owner
                .anchor(id, &device.signer.current.lock().unwrap())
                .unwrap();
            device.authorize().unwrap();
            device
        }
    }

    /// A new, empty note and a typist for it.
    pub fn new_typist(&self) -> Typist {
        let note = self.owner.create_note(self.id).unwrap();
        self.typist(note)
    }
    /// A typist for a note this device has.
    pub fn typist(&self, note: [u8; 32]) -> Typist {
        let window = {
            let mut n = self.windows.lock().unwrap();
            *n += 1;
            format!("w{n}")
        };
        self.owner.show_note(&window, self.id, note).unwrap();
        let mut typist = Typist {
            note,
            window,
            generation: 0,
            token: [0; 32],
            client: 0,
            doc: yrs::Doc::new(),
            text: None,
            salt: bh_crypto::random(),
            requests: 0,
        };
        self.reopen(&mut typist);
        typist
    }
    fn reopen(&self, typist: &mut Typist) {
        use yrs::{Transact, Update, updates::decoder::Decode};
        let opened = self.owner.open_leased(&typist.window, typist.note).unwrap();
        let lease = opened.writer.unwrap();
        if typist.text.is_none() {
            typist.client = lease.client_id;
            typist.doc = yrs::Doc::with_options(yrs::Options {
                offset_kind: yrs::OffsetKind::Utf16,
                cleanup_formatting: false,
                ..yrs::Options::with_client_id(yrs::ClientID::new(lease.client_id))
            });
        }
        assert_eq!(lease.client_id, typist.client, "typist kept its writer");
        let mut txn = typist.doc.transact_mut();
        for segment in opened.state.segments() {
            txn.apply_update(Update::decode_v1(segment).unwrap())
                .unwrap();
        }
        typist.generation = opened.generation;
        typist.token = lease.token;
    }
    /// Type `c` and commit it, as one keystroke. Returns its update's id.
    pub fn type_key(&self, typist: &mut Typist, c: char) -> i64 {
        self.type_text(typist, &c.to_string())
    }
    /// Insert `text` at once and commit it, as one paste. Returns its
    /// update's id.
    pub fn type_text(&self, typist: &mut Typist, text: &str) -> i64 {
        use yrs::{Text, Transact, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};
        let inserted = text;
        let delta = {
            let mut txn = typist.doc.transact_mut();
            let text = match &typist.text {
                Some(text) => text.clone(),
                None => {
                    let fragment = txn.get_or_insert_xml_fragment(bh_core::note::FRAGMENT);
                    let len = fragment.len(&txn);
                    let paragraph =
                        fragment.insert(&mut txn, len, XmlElementPrelim::empty("paragraph"));
                    let text = paragraph.insert(&mut txn, 0, XmlTextPrelim::new(""));
                    typist.text = Some(text.clone());
                    text
                }
            };
            let end = text.len(&txn);
            text.insert(&mut txn, end, inserted);
            txn.encode_update_v1()
        };
        typist.requests += 1;
        let mut request = [0; 16];
        request[..8].copy_from_slice(&typist.salt);
        request[8..].copy_from_slice(&typist.requests.to_be_bytes());
        for _ in 0..5 {
            match self.owner.commit_leased(
                &typist.window,
                typist.generation,
                typist.token,
                request,
                &delta,
            ) {
                Ok(_) => {
                    let db = self.owner.shared_database(self.id).unwrap();
                    return db
                        .lock()
                        .unwrap()
                        .local_frontier(self.key(typist.note))
                        .unwrap();
                }
                // The keystroke is already in the typist's document: take in
                // what the note gained, and retry the same bytes/request.
                Err(
                    bh_device::OwnerError::WriterUnavailable
                    | bh_device::OwnerError::Store(bh_storage::StoreError::StaleNote),
                ) => self.reopen(typist),
                Err(error) => panic!("keystroke not saved: {error:?}"),
            }
        }
        panic!("keystroke not saved after reopening");
    }
    /// The note's top-level paragraphs as this device shows them: its
    /// working state, reopened from SQLite.
    pub fn paragraphs(&self, note: [u8; 32]) -> Vec<String> {
        use yrs::{
            GetString, ReadTxn, Transact, Update, XmlFragment, XmlOut, updates::decoder::Decode,
        };
        let db = self.owner.shared_database(self.id).unwrap();
        let ordered = db.lock().unwrap().note_ordered(self.key(note)).unwrap();
        let doc = yrs::Doc::new();
        {
            let mut txn = doc.transact_mut();
            for segment in ordered.segments() {
                txn.apply_update(Update::decode_v1(segment).unwrap())
                    .unwrap();
            }
        }
        let txn = doc.transact();
        let Some(fragment) = txn.get_xml_fragment(bh_core::note::FRAGMENT) else {
            return Vec::new();
        };
        fragment
            .children(&txn)
            .filter_map(|child| match child {
                XmlOut::Element(element) => Some(
                    element
                        .children(&txn)
                        .filter_map(|inner| match inner {
                            XmlOut::Text(text) => Some(text.get_string(&txn)),
                            _ => None,
                        })
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect()
    }
}

/// Wait until `done` holds, failing after `seconds`.
pub async fn until(seconds: u64, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
