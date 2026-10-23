//! The native sync client: one per anchored container, started and stopped
//! by its host. It keeps an attested authorization session through the edge,
//! registers the container's own base, then runs two independent lanes
//! (`scheduler`): a receiver that verifies the base's log (other devices'
//! notes and this device's own echoes), follows the account, orders a device
//! addition the person approved and copies account changes into the base;
//! and a publisher of this device's sealed note packages, one in flight per
//! note in local commit order: a note's next package starts after 300 ms
//! without an edit on it (at most 1 s after its first unsent edit) and no
//! sooner than 500 ms after its previous start.
//! Neither waits for the other's round. `pairing` shows and scans the QR
//! code; `bootstrap` reads a joined device's base before it is usable.
//!
//! Every package's exact bytes are persisted before they are first sent, and
//! a retry sends those bytes; nothing reseals automatically, except a package
//! under an epoch the base replaced at a control position content has already
//! passed, which can never be ordered and is resealed under the current
//! epoch. No local work is discarded. No network wait happens while a
//! database guard or note work lock is held: sealing and acknowledgement are
//! short store calls between network steps.
//!
//! Synthetic appraisal exists only with the `synthetic-attestation` feature,
//! which no release build enables:
#![cfg_attr(
    not(feature = "synthetic-attestation"),
    doc = "```compile_fail\nlet _ = bh_sync_client::Appraisal::Synthetic;\n```"
)]
#![forbid(unsafe_code)]

mod account_evidence;
mod authz;
mod backoff;
pub mod bootstrap;
mod controls;
mod copier;
pub mod data;
mod directory;
mod home;
mod notices;
mod outbox;
pub mod pairing;
mod presence;
mod puller;
mod recover;
mod register;
mod rekey;
mod relay;
mod removal;
mod scheduler;
mod status;
pub mod transport;
mod trust;
mod tuning;

pub use authz::AuthzSession;
pub use presence::{
    MAX_LABEL, MAX_LOCAL_NOTES, MAX_REMOTE, Presence, RemotePresence, RemoteState, SEND_INTERVAL,
};
pub use recover::{RecoverError, RecoverStage, recover, recover_reporting};
pub use rekey::EpochInstalled;
pub use status::SyncStatus;
pub use trust::{Ordered, OrderedControl};

/// Directory entries as opened, in the order read: each one's content, or
/// why it was refused.
pub type OpenedEntries = Vec<Result<OpenedEntry, EntryRefused>>;

// Pacing knobs are for tests (`Client::start_tuned`); a release build keeps
// them out of the public API.
#[cfg(feature = "test-support")]
pub use tuning::{Pacing, Quiet, Tuning};
#[cfg(not(feature = "test-support"))]
pub(crate) use tuning::{Pacing, Tuning};

/// Progress of this client's first-device home check, independent of note sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeStatus {
    /// The signer identifies this as a later device with no original-home obligation.
    NotNeeded,
    /// An attempt is in progress or awaiting its storage answer.
    Pending,
    /// The home check will retry; note publication proceeds separately.
    Retrying(HomeRetryReason),
    /// An exact storage answer was confirmed under the original authority.
    Done,
}

/// Fixed, content-free reason why the home check is retrying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeRetryReason {
    Unavailable,
    Refused,
    /// The signer is locked or its retained setup failed local checks.
    SetupNotReady,
    Other,
}

use bh_account::{
    AccountId, ConfirmedTime, DeviceId, Head as AccountHead, VerifiedAccount, device_auth,
    directory::OpenedEntry,
    journal::{StagedAdmission, StagedControl},
    owner::{
        InitialAccountPrefix, PendingHomeObjects,
        staging::{EntryRefused, Settlement},
    },
};
use bh_authz_proto::Refusal;
use bh_confidential_policy::Limits;
use bh_crypto::Secret;
use bh_device::{
    ContainerId, Owner,
    control::{InstallError, SealWait},
};
use bh_sync::{BaseId, evidence::RecoveryKeyCertificate};
use futures_util::future::BoxFuture;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::{Notify, watch};

/// The device's own clock is independent of the home's qualified bounds.
pub trait DeviceClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// POSIX clock used outside tests. A removal deadline must have passed both
/// this clock and the home's independently signed lower bound.
pub struct SystemDeviceClock;
impl DeviceClock for SystemDeviceClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_millis() as u64)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RemovalVerdict {
    Active,
    Pending {
        deadline_ms: u64,
        by: Option<DeviceId>,
    },
    /// A pre-handoff snapshot of locally unsent work for the banner. It is
    /// not the frozen count the destructive step reports; a host must not
    /// display it as final.
    Removed {
        unsent: u64,
    },
    Refused,
}
impl std::fmt::Debug for RemovalVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => f.write_str("Active"),
            Self::Pending { deadline_ms, by } => f
                .debug_struct("Pending")
                .field("deadline_ms", deadline_ms)
                .field("has_requester", &by.is_some())
                .finish(),
            Self::Removed { unsent } => f.debug_struct("Removed").field("unsent", unsent).finish(),
            Self::Refused => f.write_str("Refused"),
        }
    }
}
use transport::{Connector, WsConnector};

/// Which appraisal the device applies to the authorization service's proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appraisal {
    /// Hardware attestation under the signed policy.
    Hardware,
    /// The labelled synthetic quote of a local service. Local builds only.
    #[cfg(feature = "synthetic-attestation")]
    Synthetic,
}

/// One hosting association: the edge and the roots this device pins for it.
/// `hosting_root` must come from the authenticated hosting association; it is
/// never invented and has no default.
#[derive(Clone)]
pub struct Endpoint {
    /// The edge's base URL, `https://…` (or `http://…` locally).
    pub edge_url: String,
    pub hosting_root: [u8; 32],
    /// The root that signs the confidential-service policy.
    pub app_root: [u8; 32],
    /// A signed policy delivered before the first handshake, so the service
    /// cannot present an older one. Empty for none.
    pub policy: Vec<u8>,
    pub policy_signature: Vec<u8>,
    /// Policy lifetime and clock bounds for this deployment.
    pub limits: Limits,
    /// The signed app build date at UTC midnight, in POSIX seconds.
    pub build_floor: u64,
    pub appraisal: Appraisal,
    /// Independent local clock, never replaced by the service's bounds.
    pub device_clock: Arc<dyn DeviceClock>,
    /// The home's recovery key, which a recovering device seals its claim
    /// to, certified under `hosting_root`.
    pub recovery_key: RecoveryKeyCertificate,
}

/// Who this device is in its account, and the account at the head its own
/// base's genesis names.
pub struct Identity {
    pub account: AccountId,
    pub device: DeviceId,
    /// The account's original genesis event: it names the account log.
    pub genesis: Vec<u8>,
    pub anchor: VerifiedAccount,
}

/// A first device's signup, as kept for its account home: the original
/// signed prefix and the three private objects (recovery record, device seal,
/// recovery seal) it commits to, read from the account owner's retained
/// initial bootstrap. Ciphertext only; it never leaves native code except to
/// the account home.
pub struct HomeSetup {
    pub prefix: InitialAccountPrefix,
    pub objects: PendingHomeObjects,
    /// The generation of the native authority that read it. The signer
    /// refuses to complete setup once that authority is superseded.
    pub generation: u64,
}

/// The host's native authority for this container. It holds no lock across
/// its futures that the client could also need.
///
/// Lock order: the client calls the signer holding no lock of the Owner's
/// (container session or writer), and the closure it passes to
/// `with_metadata_key` or `with_epoch_keys` takes those locks itself. So the signer must not hold,
/// while it runs that closure, any lock the Owner takes, nor any lock that
/// code holding an Owner lock may wait for.
pub trait Signer: Send + Sync {
    fn identity(&self) -> Result<Identity, SignerError>;
    /// Possession of this device's ordinary key over a channel's binding and
    /// the service's challenge, at the device's current verified head.
    fn device_proof(
        &self,
        context: device_auth::Context,
    ) -> BoxFuture<'_, Result<device_auth::Proof, SignerError>>;
    /// As `device_proof`, at an earlier verified head of the account: the
    /// head an account home that has not caught up yet still holds.
    fn device_proof_at(
        &self,
        head: AccountHead,
        context: device_auth::Context,
    ) -> BoxFuture<'_, Result<device_auth::Proof, SignerError>>;
    /// This device's retained signup for its account home, exactly as
    /// signup kept it: never regenerated, and read whether or not the
    /// pending setup record still exists. `None` only for a device that
    /// never held one, a device added later; a first device whose retained
    /// signup is missing or does not verify is an error.
    fn initial_home_setup(&self) -> Result<Option<HomeSetup>, SignerError>;
    /// Complete first-device setup at `setup.prefix.head`. The client calls
    /// this only after a verified read of the account log holds exactly that
    /// prefix, with `evidence` the home's verified confirmations of its
    /// positions 2 and 3 (exact bytes), and the service answered that its
    /// home durably stored exactly these objects. The owner keeps those
    /// times with the prefix (`AccountOwner::confirm_home_ordered`), and the
    /// host then reads both its current account and its creator anchor
    /// again. Refused if the authority `setup.generation` names is no longer
    /// current, or `setup` is not this account's; the client then reads the
    /// setup again and retries with the same bytes.
    fn confirm_home_ordered(
        &self,
        setup: &HomeSetup,
        evidence: [(ConfirmedTime, Vec<u8>); 2],
    ) -> Result<(), SignerError>;
    /// An ordinary-key signature over a prepared event's signing bytes.
    fn sign_event(&self, message: Vec<u8>) -> BoxFuture<'_, Result<[u8; 64], SignerError>>;
    /// The account at its current verified head, from the account owner.
    /// `Identity::anchor` stays the account the base genesis names.
    fn current_account(&self) -> Result<VerifiedAccount, SignerError>;
    /// The newest account view this signer verified while the device was a
    /// member, still available after its authority ended. Only a starting
    /// point the removal check verifies the public evidence forward from.
    fn last_verified_account(&self) -> Result<VerifiedAccount, SignerError> {
        self.current_account()
    }
    /// Apply account originals the account log ordered after `after`, each
    /// with the confirmed time and exact confirmation bytes the client
    /// verified under the hosting root (`None` only for the genesis),
    /// through the account owner (`AccountOwner::apply_incoming_timed`): it
    /// verifies them as the next signed history and commits them with
    /// their evidence and head. Then the host reacquires current authority
    /// for this container. `Unavailable`, with nothing applied, unless the
    /// owner's verified head is exactly `after`.
    fn apply_account_timed(
        &self,
        after: AccountHead,
        originals: Vec<TimedOriginal>,
    ) -> BoxFuture<'_, Result<AccountHead, AccountApplyError>>;
    /// Persist an independently authenticated accepted-head observation at
    /// precisely the owner's current original head. The caller first checks
    /// its confirmation commitment, including on empty follow reads.
    fn observe_account_accepted(
        &self,
        head: AccountHead,
        time: ConfirmedTime,
    ) -> Result<(), SignerError>;
    /// A control-key signature over a base control's original
    /// (`AccountOwner::sign_base_control`), only within an action the
    /// person approved: today the copy of exactly the account event a
    /// pairing approval names (`pairing::Approvals::take(&request.copies)`).
    /// The client asks from the background: without such an approval this
    /// must return `ConfirmationNeeded` at once, never prompt. The client
    /// keeps its work and waits for authorization.
    fn sign_base_control(
        &self,
        request: BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>>;
    /// The device addition this device staged and verified history has
    /// not settled yet (`AccountOwner::staged_admission`). The client orders
    /// its exact bytes, carrying its delivery, and never asks for it to be
    /// signed again. Once applied history holds its position, the host's
    /// `apply_account_timed` settles the row
    /// (`AccountOwner::reconcile_staged_admission`).
    fn staged_addition(&self) -> Result<Option<StagedAdmission>, SignerError> {
        Ok(None)
    }
    /// The signed trust control this device staged and verified history has
    /// not settled yet (`AccountOwner::staged_control`). The client orders
    /// its exact bytes and never asks for it to be signed again.
    fn staged_control(&self) -> Result<Option<StagedControl>, SignerError>;
    /// Stage a personal-key rotation for the latest effect due at `at_ms`,
    /// a verified accepted head's `earliest_ms`, never the device clock
    /// (`AccountOwner::stage_rotation`): a new key sealed to the devices
    /// active then and the recovery key, signed with the ordinary key, no
    /// prompt. The accepted key and the keyring are untouched.
    fn stage_rotation(&self, at_ms: u64) -> BoxFuture<'_, Result<StagedControl, SignerError>>;
    /// Once verified history holds the staged control's position, how it was
    /// taken, and the stage cleared (`AccountOwner::settle_staged`). `None`
    /// while it has not, or nothing is staged.
    fn settle_staged(&self) -> Result<Option<Settlement>, SignerError>;
    /// Clear exactly `expected`, after the service definitively refused its
    /// bytes while verified history still stands at their predecessor
    /// (`AccountOwner::discard_staged`). Another row staged meanwhile stays.
    fn discard_staged(&self, expected: &StagedControl) -> Result<(), SignerError>;
    /// Accept the personal-key rotation ordered at `position` from its exact
    /// raw device-seal body, never its padded transport object: the keyring
    /// is ready (`ensure_keyring`), then `AccountOwner::accept_rotation`
    /// re-seals it to the new key; the host then reads its current account
    /// and creator anchor again. On any error nothing is accepted.
    fn accept_rotation(
        &self,
        position: u64,
        raw: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), SignerError>>;
    /// The account-directory entry for base `base` at `version`: its key
    /// package for `epoch` only (that epoch's content key, from memory,
    /// sealed to the current personal key and signed with the ordinary
    /// key), under `server`, sealed and signed
    /// (`AccountOwner::prepare_directory_entry`). Refused while the epoch's
    /// key is not held or history publishes a key this device has not
    /// accepted.
    fn prepare_base_entry(
        &self,
        base: BaseId,
        epoch: [u8; 32],
        server: String,
        version: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>, SignerError>>;
    /// Open directory entries read from the home under the accepted personal
    /// key, in order, each raising the version this device remembers for its
    /// id (`AccountOwner::open_directory_entries`). An empty read only checks
    /// that this device can open the directory.
    fn open_directory_entries(
        &self,
        entries: Vec<Vec<u8>>,
    ) -> BoxFuture<'_, Result<OpenedEntries, SignerError>>;
    /// The version of this device's own-base directory entry, and whether the
    /// home is known to hold it.
    fn directory_state(&self) -> Result<Option<(u64, bool)>, SignerError>;
    fn set_directory_state(&self, version: u64, written: bool) -> Result<(), SignerError>;
    // ---- This device's own directory entries, and what it reads back ----
    /// This device's own directory entries the home is not known to hold,
    /// each sealed to the accepted personal key and signed at the version it
    /// is written at, `(version, bytes)` (`AccountOwner::prepare_own_entry`):
    /// its name, once the host has one, and a password check it holds
    /// unpublished, bound to the current recovery record. Empty once the
    /// home holds each.
    fn own_entries(&self) -> BoxFuture<'_, Result<OwnEntries, SignerError>>;
    /// The home holds this device's entry `entry` at `version` or later
    /// (`AccountOwner::own_entry_held`): it is not written again.
    fn own_entry_held(&self, entry: [u8; 32], version: u64) -> Result<(), SignerError>;
    /// Whether the host asked for the directory to be read now (its devices
    /// view opened, or a password change needs the account's check). Asking
    /// is cleared by this call.
    fn directory_wanted(&self) -> bool;
    /// What a directory read found, every entry opened under the accepted
    /// personal key.
    fn directory_read(&self, read: DirectoryRead);
    /// A security alert was durably written outside account-history apply;
    /// let the host deliver it to its existing alert subscribers. Called
    /// only after releasing the database lock.
    fn alerts_written(&self) {}
    /// A read the host asked for, or one after an addition, failed: it is
    /// tried again on its own backoff, and the host need not wait for it.
    fn directory_unread(&self) {}
    /// Use base `base`'s metadata root M (today only the own base's). Never
    /// waits on a content key: M is given while the base's current epoch's
    /// key is missing or its epoch is closed. Keys are never copied out,
    /// logged or stored by the client. See the lock order above.
    fn with_metadata_key(
        &self,
        base: BaseId,
        use_key: &mut dyn FnMut(&Secret<32>),
    ) -> Result<(), SignerError>;
    /// Use M and the content root of `epoch`, only from keys the host
    /// already opened in memory: `None` for a closed epoch (`None`) or one
    /// whose key it does not hold, never another epoch's key. No native key
    /// work happens here, so it holds no lock across any.
    fn with_epoch_keys(
        &self,
        base: BaseId,
        epoch: Option<[u8; 32]>,
        use_keys: &mut dyn FnMut(&Secret<32>, Option<&Secret<32>>),
    ) -> Result<(), SignerError>;
    /// Install the content key a rekey's seal set carries for this account:
    /// `set` opened with M as exactly the set `wait` names, this account's
    /// seal in it authenticated against verified history and opened with
    /// the accepted personal key (`AccountOwner::open_current_personal`),
    /// kept in the local keyring (`install_epoch_keys`) and the wait ended;
    /// then the key is used from memory. On any error nothing is installed
    /// and the wait stays.
    fn install_epoch(
        &self,
        wait: SealWait,
        set: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), InstallError>>;
}

/// This device's own directory entries to write: `(version, bytes)` each.
pub type OwnEntries = Vec<(u64, Vec<u8>)>;

/// What one read of the account directory found: each active device's name
/// as that device signed it, and the password check bound to the current
/// recovery record, if the directory holds one.
pub struct DirectoryRead {
    pub names: Vec<(DeviceId, String)>,
    pub password_check: Option<bh_account::recovery::PasswordCheck>,
}

/// An account original with the confirmed time and exact confirmation
/// bytes verified for it; `None` only for the genesis.
pub type TimedOriginal = (Vec<u8>, Option<(ConfirmedTime, Vec<u8>)>);

/// One base control for the control key: its exact signing bytes, the key
/// that must sign them, and the original account event it copies into the
/// base, byte for byte. The signer judges approval by `copies`.
pub struct BaseControlRequest {
    pub expected_key: [u8; 32],
    pub message: Vec<u8>,
    pub copies: Vec<u8>,
}

/// The signer cannot act now (locked, stale or removed authority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignerError;

/// Why incoming account history was not applied, as the account owner
/// judged it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountApplyError {
    /// Not the account's next verified history (`OwnerError::Refused`):
    /// nothing applied, no stop. The log is read again later.
    Refused,
    /// The next event needs a newer build (`OwnerError::Unsupported`):
    /// nothing applied, no stop.
    Unsupported,
    /// The owner is stopped: authenticated history contradicts its own
    /// (`OwnerError::Invalid`, other than `Unavailable`, or `Stopped`).
    Stopped,
    /// The owner cannot act now: locked, stale or removed authority, local
    /// evidence unavailable, or its head is no longer `after`.
    Unavailable,
}

/// Why a base control was not signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlSignError {
    /// No action the person approved covers it now.
    ConfirmationNeeded,
    /// The account owner cannot sign (locked, stale or removed authority).
    Unavailable,
}

/// Windows with committed remote changes queued for delivery
/// (`Owner::drain_surface`), for the host to wake. It holds window labels
/// only, at most one entry per window. The generation is a nondestructive
/// signal of the same events, for lanes that only need "something committed".
#[derive(Clone, Default)]
pub struct WindowWakes(Arc<WindowWakesInner>);
#[derive(Default)]
struct WindowWakesInner {
    windows: std::sync::Mutex<BTreeSet<String>>,
    notify: Notify,
    generation: watch::Sender<u64>,
}
impl WindowWakes {
    /// The windows woken since the last call, waiting until there is one.
    pub async fn next(&self) -> Vec<String> {
        loop {
            let woken = self.take();
            if !woken.is_empty() {
                return woken;
            }
            self.0.notify.notified().await;
        }
    }
    /// The windows woken since the last call, without waiting.
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.windows.lock().expect("window wakes"))
            .into_iter()
            .collect()
    }
    /// Every accepted-history wake, without taking the host's queue: each
    /// change means something this device's notes were waiting for committed.
    pub(crate) fn generation(&self) -> watch::Receiver<u64> {
        self.0.generation.subscribe()
    }
    pub(crate) fn wake(&self, windows: Vec<String>) {
        self.0
            .generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        if windows.is_empty() {
            return;
        }
        self.0.windows.lock().expect("window wakes").extend(windows);
        self.0.notify.notify_one();
    }
}

/// Fixed, content-free failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The edge could not be reached, or a connection ended.
    Network,
    /// The service refused the request.
    Refused(Refusal),
    /// The service could not establish current authority.
    Unavailable,
    /// The attested channel failed or the service's answer was not valid.
    Channel,
    /// The endpoint's confidential-service policy does not load or verify:
    /// this build cannot appraise the service.
    Unsupported,
    /// The signer could not act.
    Signer,
    /// Local state could not be read or written.
    Local,
    /// The client has stopped.
    Stopped,
}

pub(crate) struct Shared {
    endpoint: Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    signer: Arc<dyn Signer>,
    authz: authz::Authz,
    home_authz: authz::Authz,
    /// Raised on every wake: each lane watches it and looks at durable work
    /// before it sleeps, so wakes that come together are never lost.
    wake: watch::Sender<u64>,
    home_wake: Notify,
    removal_wake: Notify,
    /// Set once, when the client stops: both lanes end and close their links.
    halt: watch::Sender<bool>,
    status: watch::Sender<SyncStatus>,
    windows: WindowWakes,
    home_status: watch::Sender<HomeStatus>,
    /// The last new content epoch installed on this device.
    installed: watch::Sender<Option<EpochInstalled>>,
    removal_verdict: watch::Sender<RemovalVerdict>,
    /// The last trust control this device ordered, as verified history
    /// settled it.
    ordered: watch::Sender<Option<OrderedControl>>,
    presence: presence::Presence,
    tuning: Tuning,
}

impl Shared {
    /// Wait out `commits` durable commits' time, if a test set one.
    pub(crate) async fn commit_time(&self, commits: usize) {
        let delay = self.tuning.commit_delay;
        if !delay.is_zero() && commits > 0 {
            tokio::time::sleep(delay * commits as u32).await;
        }
    }
    /// Raise the wake generation.
    pub(crate) fn wake(&self) {
        self.wake
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
    /// The client has been told to stop for good.
    pub(crate) fn is_halted(&self) -> bool {
        *self.halt.borrow()
    }
    /// Ends when the client stops.
    pub(crate) async fn halted(&self) {
        let _ = self.halt.subscribe().wait_for(|halted| *halted).await;
    }
    pub(crate) fn new(
        endpoint: Endpoint,
        connector: Arc<dyn Connector>,
        owner: Arc<Owner>,
        container: ContainerId,
        signer: Arc<dyn Signer>,
        status: watch::Sender<SyncStatus>,
        tuning: Tuning,
    ) -> Arc<Self> {
        let authz = authz::Authz::new(&endpoint);
        let home_authz = authz::Authz::new(&endpoint);
        let (home_status, _) = watch::channel(HomeStatus::Pending);
        Arc::new(Shared {
            endpoint,
            connector,
            owner,
            container,
            signer,
            authz,
            home_authz,
            wake: watch::Sender::new(0),
            home_wake: Notify::new(),
            removal_wake: Notify::new(),
            halt: watch::Sender::new(false),
            status,
            windows: WindowWakes::default(),
            home_status,
            installed: watch::Sender::new(None),
            removal_verdict: watch::Sender::new(RemovalVerdict::Active),
            ordered: watch::Sender::new(None),
            presence: presence::Presence::new(),
            tuning,
        })
    }
}

/// Check once, with no running client, whether this device's removal took
/// effect, for a device whose own verified history no longer holds it
/// active, so it can no longer authenticate. `last` is the newest view of
/// that history in which `device` was a member; the public account evidence
/// is verified forward from it, as a running client's check does. `None` if
/// it could not be checked now. Only `Removed` is proof of removal.
pub async fn check_removal(
    endpoint: Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    device: DeviceId,
    genesis: Vec<u8>,
    last: VerifiedAccount,
) -> Option<RemovalVerdict> {
    removal::once(endpoint, connector, owner, container, device, genesis, last).await
}

/// The sync client of one anchored container.
///
/// Any holder may stop it (`shutdown`), however many others still hold it:
/// from then on it opens no session and runs no loop. Dropping the last
/// holder stops its loops too.
pub struct Client {
    shared: Arc<Shared>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    shutdown_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// True once a stop has ended the loops and closed the sessions.
    stopped: watch::Sender<bool>,
}

impl Client {
    /// Start syncing `container` with the edge named by `endpoint`. Must be
    /// called inside a Tokio runtime.
    pub fn start(
        endpoint: Endpoint,
        owner: Arc<Owner>,
        container: ContainerId,
        signer: Arc<dyn Signer>,
        status: watch::Sender<SyncStatus>,
    ) -> Self {
        let connector = WsConnector::new(&endpoint.edge_url);
        Self::start_with(endpoint, connector, owner, container, signer, status)
    }

    /// As `start`, over another transport to the same edge routes.
    pub fn start_with(
        endpoint: Endpoint,
        connector: Arc<dyn Connector>,
        owner: Arc<Owner>,
        container: ContainerId,
        signer: Arc<dyn Signer>,
        status: watch::Sender<SyncStatus>,
    ) -> Self {
        Self::spawn(Shared::new(
            endpoint,
            connector,
            owner,
            container,
            signer,
            status,
            Tuning::default(),
        ))
    }

    /// As `start_with`, with another pacing or a commit time: for tests.
    #[cfg(feature = "test-support")]
    pub fn start_tuned(
        endpoint: Endpoint,
        connector: Arc<dyn Connector>,
        owner: Arc<Owner>,
        container: ContainerId,
        signer: Arc<dyn Signer>,
        status: watch::Sender<SyncStatus>,
        tuning: Tuning,
    ) -> Self {
        Self::spawn(Shared::new(
            endpoint, connector, owner, container, signer, status, tuning,
        ))
    }

    fn spawn(shared: Arc<Shared>) -> Self {
        let task = tokio::spawn(scheduler::run(shared.clone()));
        let home_task = tokio::spawn(home::run(shared.clone()));
        let presence_task = tokio::spawn(presence::run(shared.clone()));
        let removal_task = tokio::spawn(removal::run(shared.clone()));
        Self {
            shared,
            tasks: std::sync::Mutex::new(vec![task, home_task, presence_task, removal_task]),
            shutdown_task: std::sync::Mutex::new(None),
            stopped: watch::Sender::new(false),
        }
    }

    /// This device's own-device presence. Dormant until configured and used;
    /// a client that never touches it opens no presence socket.
    pub fn presence(&self) -> Presence {
        self.shared.presence.clone()
    }

    /// Each new content epoch of the own base once this device installed
    /// its key: the snapshot writer's signal. It names the base, the key id
    /// and the rekey's ordered head, never a key.
    pub fn epoch_installed(&self) -> watch::Receiver<Option<EpochInstalled>> {
        self.shared.installed.subscribe()
    }

    /// Each trust control this device staged, once verified history settled
    /// it: ordered (with its confirmed time), a cancel that came too late,
    /// lost to another entry, or refused.
    pub fn trust(&self) -> watch::Receiver<Option<OrderedControl>> {
        self.shared.ordered.subscribe()
    }

    /// Observe the home check without changing the note sync status.
    pub fn home_status(&self) -> watch::Receiver<HomeStatus> {
        self.shared.home_status.subscribe()
    }

    /// The verified removal result. A host must quiesce and erase before it
    /// presents the final erased screen.
    pub fn removal_verdict(&self) -> watch::Receiver<RemovalVerdict> {
        self.shared.removal_verdict.subscribe()
    }

    /// Check this device's removal against the public evidence now. The
    /// answer is published on `removal_verdict`; a check already under way
    /// when asked is superseded rather than published.
    pub fn check_removal(&self) {
        self.shared.removal_wake.notify_one();
    }

    /// Windows to wake after remote changes commit. Every clone sees the
    /// same wakes; take them from one place.
    pub fn window_wakes(&self) -> WindowWakes {
        self.shared.windows.clone()
    }

    /// Look for new local work now rather than at the next poll: also after
    /// the person approved a base control (`ControlSignError`).
    pub fn wake(&self) {
        self.shared.wake();
        self.shared.home_wake.notify_one();
    }

    /// Stop syncing for good. Work in flight is abandoned at its next wait;
    /// its exact bytes are already persisted and a later start resends
    /// them. Returns once the loops have ended and the sessions closed; a
    /// second or concurrent call waits for the same.
    pub async fn shutdown(&self) {
        self.shared.halt.send_replace(true);
        self.shared.authz.stop();
        self.shared.home_authz.stop();
        {
            let mut supervisor = self
                .shutdown_task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if supervisor.is_none() {
                let tasks = std::mem::take(
                    &mut *self
                        .tasks
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
                let shared = self.shared.clone();
                let stopped = self.stopped.clone();
                *supervisor = Some(tokio::spawn(async move {
                    // The scheduler ends its lanes on halt: each closes and
                    // joins its own data link. Home is aborted; its link's
                    // drop cancels its tasks.
                    let mut tasks = tasks.into_iter();
                    let scheduler = tasks.next();
                    // Home is aborted; presence observes the stop, sends its
                    // best-effort clears and joins its own socket.
                    let home = tasks.next();
                    let presence = tasks.next();
                    let removal = tasks.next();
                    if let Some(removal) = removal {
                        removal.abort();
                        let _ = removal.await;
                    }
                    if let Some(home) = home {
                        home.abort();
                        let _ = home.await;
                    }
                    if let Some(scheduler) = scheduler {
                        let _ = scheduler.await;
                    }
                    if let Some(presence) = presence {
                        let _ = presence.await;
                    }
                    shared.authz.close().await;
                    shared.home_authz.close().await;
                    // No completion-on-Drop: cancelling a waiter cannot publish
                    // completion before the actual owned tasks have joined.
                    stopped.send_replace(true);
                }));
            }
        }
        let _ = self.stopped.subscribe().wait_for(|stopped| *stopped).await;
    }

    /// The authenticated authorization session, opened if needed. Holding it
    /// excludes this client's own requests; drop it promptly. `Stopped`
    /// once the client stopped.
    pub async fn authz(&self) -> Result<AuthzSession<'_>, ClientError> {
        self.shared.authz.session(&self.shared).await
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shared.halt.send_replace(true);
        self.shared.authz.stop();
        self.shared.home_authz.stop();
        let tasks = self
            .tasks
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in tasks.drain(..) {
            task.abort();
        }
        // A started shutdown supervisor finishes joining independently. It owns
        // Shared, never Client; no reference cycle. Without shutdown, stop above
        // wakes session tasks and Authz's last Drop aborts as a fallback.
    }
}
