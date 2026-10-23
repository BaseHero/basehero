//! Authentication, current authority and permit issuance.
//!
//! Every request first reads the account's log from the edge past the last
//! verified position, under a permit the service issues itself: that read is
//! the head lookup, and its start time is the issued time of every permit the
//! request yields. Stored history only saves rereading; nothing is issued
//! from it alone. One account's concurrent requests share that lookup: a
//! request arriving while it is in flight awaits its result instead of
//! reading again, and a ReadBatch runs its currentness reads and its
//! selection side by side. The account's lock guards memory and local
//! storage only, never a network wait; other accounts never wait for it.
//!
//! Each own base has a control record: the base's controls as
//! `ControlSpine` follows them, and the base's copy of the account. The
//! service verifies a base control with M before permitting it, keeps it
//! pending until it reads it back from the log, and confirms it then by its
//! exact bytes, without M. A control it cannot account for means its record
//! is stale: the device sends `RegisterBase` with M, and the record is
//! rebuilt from the log.
//!
//! Base controls are read sparsely, against one endpoint whose receipt
//! verifies under the pinned hosting root; every page of a scan names that
//! same endpoint. Nothing a scan builds is saved or used until every raw
//! control links to it and the endpoint is covered, and a save is
//! conditional on the durable projection it began from. A base's genesis
//! is provisional until it is read back ordered.
use crate::{
    Clock, EdgeReader, PermitKeys, RecoveryHomeKey, ServiceError,
    store::{
        Activation, Attachment, ConfirmedPage, ControlConflict, Pending, Prior, Record,
        RecoveryDigests, Saved, Status, Store, StoredEvent, VerifiedBase,
        candidate::{BaseWrite, Candidate},
        projection::{
            AppliedBody, HistoricalEntry, HistoricalSnapshot, Pin, ProjectionHeader,
            ProjectionWrite, Source, SourceKey,
        },
    },
};
use bh_account::{
    AccountEvent, AccountId, DeviceId, Error as AccountError, Head as AccountHead, VerifiedAccount,
    device_auth::{self, Context, PROOF_LEN},
    personal, projection as account_projection,
};
use bh_authz_proto::{
    ACCOUNT_EPOCH, Delivery, FromService, LogId, LogKind, MetadataKey, ReadBatchResult,
    RecoverPurpose, RecoveryAnswer, RecoveryAttachment, Refusal, ToService, Want, account_log_id,
    account_log_unwrap, account_log_wrap, delivery_body, rotation_body, rotation_frame,
};
use bh_crypto::Secret;
use bh_event::{ControlSpine, Outcome, SeenReceiptConflict, account_run::apply_copies, key_id};
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, Head, OpaqueEvent, OrderState, RawControlHead, Route,
    permit::{self, MAX_PERMIT_WINDOW_MS, Permit, Scope},
    receipt, referenced_body,
};
use futures_util::future::{BoxFuture, FutureExt, WeakShared};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

/// Accounts whose verified view stays in memory between requests.
const CACHED_ACCOUNTS: usize = 4096;
/// Positions per self-issued account-log read, and controls per base
/// controls read.
const READ_BATCH: u64 = 64;
/// How long after its permits' deadline a pending control may still appear
/// in its log: the margin between this service's clock and the log's.
const PENDING_GRACE_MS: u64 = 60_000;
/// Kit-use notices in one answer.
const NOTICES_READ: usize = 64;
/// Registration replays outside the account lock. If the durable record
/// changed meanwhile, it replays again from the new state, up to this many
/// attempts; then it issues nothing.
const REGISTER_REPLAY_ATTEMPTS: usize = 3;

/// The service's verified view of one account at its account-log head, the
/// bodies its ordered events carry (the only account bodies it permits
/// reading), and the control records of its bases this process has used.
struct Account {
    log: LogId,
    verified: VerifiedAccount,
    head: Head,
    /// The canonical opening at `head`.
    opening: OrderState,
    pin: Option<Pin>,
    /// Only the uncommitted current <=64-original page, discarded on commit.
    page: Option<PendingHomePage>,
    bases: HashMap<[u8; 32], BaseRecord>,
}

struct PendingHomePage {
    start: VerifiedAccount,
    before: OrderState,
    entries: Vec<HistoricalEntry>,
}

/// One base's control record in memory.
struct BaseRecord {
    spine: ControlSpine,
    /// The base's copy of the account, at the spine's account head: restored
    /// from its own indexed checkpoint and kept as controls apply, never
    /// rebuilt per permit or replayed from its anchor.
    view: VerifiedAccount,
    pending: Option<Pending>,
    status: Status,
    /// Its controls were read from the log and covered since it was loaded.
    /// Never for a provisional record.
    current: bool,
    /// The BASE copy's selected generation and cut, and the one HOME prefix
    /// (the head the genesis names) it extends.
    pin: Pin,
    anchor: Pin,
}
impl BaseRecord {
    fn controls(&self) -> Controls {
        let state = self.spine.state();
        Controls {
            control_head: state.control_head,
            control_digest: state.control_digest,
            account: state.account,
            epoch: state.epoch,
            floor: state.floor,
            metadata_id: state.metadata_id,
            pending: self
                .pending
                .as_ref()
                .map(|p| (p.event_id, p.after, p.deadline_ms)),
        }
    }
}

/// The parts of a base's control record a ReadBatch or control rests on.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Controls {
    control_head: Head,
    control_digest: [u8; 32],
    account: AccountHead,
    epoch: Option<[u8; 32]>,
    floor: u16,
    metadata_id: [u8; 32],
    pending: Option<([u8; 32], Head, u64)>,
}

/// What an account refresh verified: when its lookup started, and the
/// heads it left.
#[derive(Clone, Copy)]
struct Current {
    issued: u64,
    outer: Head,
    original: AccountHead,
}

/// What a base's control confirmation verified: when it started, and the
/// record it left.
#[derive(Clone, Copy)]
struct Confirmed {
    start: u64,
    controls: Controls,
}

type Read<T> = BoxFuture<'static, Result<T, Failure>>;

/// A read in flight that later requests may join. The slot keeps it weakly:
/// once every request awaiting it is gone, so is the read.
struct Flight<T> {
    number: u64,
    read: WeakShared<Read<T>>,
}

/// One account's verified view and its currentness reads in flight.
#[derive(Default)]
struct SlotState {
    account: Option<Account>,
    refresh: Option<Flight<Current>>,
    confirms: HashMap<[u8; 32], Option<Flight<Confirmed>>>,
    /// Flights started so far: a request can tell which began after it.
    started: u64,
}
impl SlotState {
    /// The account at exactly the heads `current` verified.
    fn at(&self, current: &Current) -> Result<&Account, Failure> {
        match &self.account {
            Some(a) if a.head == current.outer && a.verified.head() == current.original => Ok(a),
            _ => Err(Unavailable),
        }
    }
    fn base(&mut self, base: &[u8; 32]) -> Result<&mut BaseRecord, Failure> {
        self.account
            .as_mut()
            .and_then(|a| a.bases.get_mut(base))
            .ok_or(Unavailable)
    }
    fn at_mut(&mut self, current: &Current) -> Result<&mut Account, Failure> {
        match &mut self.account {
            Some(a) if a.head == current.outer && a.verified.head() == current.original => Ok(a),
            _ => Err(Unavailable),
        }
    }
}
type Slot = Arc<tokio::sync::Mutex<SlotState>>;

/// Await the flight `entry` names, or start one with `start`. A `fresh`
/// request joins only a flight begun after it arrived, waiting out an older
/// one first. Sets `older` when the result rests on a flight begun before
/// the request: a refusal must not.
async fn join_or_start<T, F>(
    slot: &Slot,
    fresh: bool,
    older: &mut bool,
    entry: impl Fn(&mut SlotState) -> &mut Option<Flight<T>>,
    start: F,
) -> Result<T, Failure>
where
    T: Clone + Send + Sync + 'static,
    F: FnOnce(u64) -> Read<T>,
{
    let mut start = Some(start);
    let mut arrived = None;
    loop {
        let mut state = slot.lock().await;
        let arrived = *arrived.get_or_insert(state.started);
        let live = entry(&mut state)
            .as_ref()
            .and_then(|f| Some((f.number, f.read.upgrade()?)));
        let read = match live {
            Some((number, read)) if !fresh || number >= arrived => {
                *older |= number < arrived;
                read
            }
            Some((_, read)) => {
                drop(state);
                let _ = read.await;
                continue;
            }
            None => {
                let number = state.started;
                state.started += 1;
                let read = start.take().ok_or(Unavailable)?(number).shared();
                let weak = read.downgrade().ok_or(Unavailable)?;
                *entry(&mut state) = Some(Flight { number, read: weak });
                read
            }
        };
        drop(state);
        return read.await;
    }
}

/// One page of a base's controls and the endpoint it was read against:
/// its opening and the head its receipt authenticated.
struct ControlPage {
    items: Vec<(Commitment, OpaqueEvent)>,
    endpoint: (OrderState, Head),
    receipt: Option<[u8; 300]>,
}

/// A sparse read of a base's controls after `after`, up to the endpoint its
/// first page names.
struct Scan {
    log: LogId,
    root: [u8; 32],
    after: u64,
    endpoint: Option<(OrderState, Head)>,
    receipt: Option<[u8; 300]>,
    required: Option<(OrderState, Head, Digest)>,
    full: bool,
}
impl Scan {
    fn new(
        log: LogId,
        root: [u8; 32],
        after: u64,
        required: Option<(OrderState, Head, Digest)>,
    ) -> Self {
        Self {
            log,
            root,
            after,
            endpoint: None,
            receipt: None,
            required,
            full: false,
        }
    }
    /// Whether to read another page once a follower at `raw` took this
    /// one: none once it reached the endpoint's raw control, which a full
    /// page may end at. A short page before it withheld controls.
    fn more(&self, raw: RawControlHead) -> Result<bool, Failure> {
        let (endpoint, _) = self.endpoint.ok_or(Unavailable)?;
        if endpoint.raw_control() == raw {
            Ok(false)
        } else if self.full {
            Ok(true)
        } else {
            Err(Unavailable)
        }
    }
}

/// A base's controls replayed from its genesis to a covered endpoint. The
/// raw path, first uses and copies are the candidate's staged rows.
struct Replayed {
    spine: ControlSpine,
    view: VerifiedAccount,
    /// It passed through the remembered raw checkpoint.
    passed: bool,
}

/// The checkpoint and delta of a BASE copy `view` at `pin`'s generation over
/// `anchor`, with the spine's raw opening.
fn base_write(
    view: &VerifiedAccount,
    pin: Pin,
    anchor: Pin,
    root: [u8; 32],
    opening: OrderState,
) -> ProjectionWrite {
    ProjectionWrite {
        header: ProjectionHeader {
            pin: Pin {
                cut: view.head(),
                ..pin
            },
            root,
            opening,
            prefix: Some(anchor),
        },
        checkpoint: account_projection::capture(view),
        delta: account_projection::delta(view),
        snapshots: Vec::new(),
    }
}

struct Inner {
    store: Arc<Store>,
    keys: PermitKeys,
    recovery: Option<RecoveryHomeKey>,
    clock: Arc<dyn Clock>,
    edge: Arc<dyn EdgeReader>,
    accounts: Mutex<HashMap<[u8; 32], Slot>>,
    /// Generation cleanups still running off the async workers.
    cleaning: tokio::sync::watch::Sender<usize>,
    #[cfg(feature = "synthetic-attestation")]
    observer: Mutex<Option<Observer>>,
    #[cfg(feature = "synthetic-attestation")]
    before_base_publish: Mutex<Option<PublicationHold>>,
}

/// Test-only: called with each decoded request a connection handles.
#[cfg(feature = "synthetic-attestation")]
pub type Observer = Arc<dyn Fn(&ToService) + Send + Sync>;

#[cfg(feature = "synthetic-attestation")]
pub type PublicationHold = Arc<dyn Fn(LogId) -> BoxFuture<'static, ()> + Send + Sync>;

#[derive(Clone)]
pub struct Service {
    inner: Arc<Inner>,
}

#[derive(Clone, Copy)]
enum Failure {
    Refused(Refusal),
    Unavailable,
}
use Failure::{Refused, Unavailable};

fn account_failure(error: AccountError, refusal: Refusal) -> Failure {
    if matches!(error, AccountError::Unavailable) {
        Unavailable
    } else {
        Refused(refusal)
    }
}

impl Service {
    /// A service without a recovery key: it refuses recovery claims.
    pub fn open(
        path: &Path,
        keys: PermitKeys,
        clock: Arc<dyn Clock>,
        edge: Arc<dyn EdgeReader>,
    ) -> Result<Self, ServiceError> {
        Self::open_inner(path, keys, None, clock, edge)
    }

    /// A service that checks recovery claims sealed to `recovery`.
    pub fn open_with_recovery(
        path: &Path,
        keys: PermitKeys,
        recovery: RecoveryHomeKey,
        clock: Arc<dyn Clock>,
        edge: Arc<dyn EdgeReader>,
    ) -> Result<Self, ServiceError> {
        Self::open_inner(path, keys, Some(recovery), clock, edge)
    }

    fn open_inner(
        path: &Path,
        keys: PermitKeys,
        recovery: Option<RecoveryHomeKey>,
        clock: Arc<dyn Clock>,
        edge: Arc<dyn EdgeReader>,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            inner: Arc::new(Inner {
                store: Arc::new(Store::open(path)?),
                keys,
                recovery,
                clock,
                edge,
                accounts: Mutex::new(HashMap::new()),
                cleaning: tokio::sync::watch::Sender::new(0),
                #[cfg(feature = "synthetic-attestation")]
                observer: Mutex::new(None),
                #[cfg(feature = "synthetic-attestation")]
                before_base_publish: Mutex::new(None),
            }),
        })
    }

    /// Test-only: show every decoded request to `observer`, before it is
    /// handled.
    #[cfg(feature = "synthetic-attestation")]
    pub fn observe(&self, observer: Observer) {
        *self.inner.observer.lock().expect("observer") = Some(observer);
    }

    /// Synthetic interleaving after raw coverage verification, before any
    /// candidate save or new authority is published.
    #[cfg(feature = "synthetic-attestation")]
    pub fn hold_base_publication(&self, hold: PublicationHold) {
        *self.inner.before_base_publish.lock().expect("hold") = Some(hold);
    }

    /// Test-only: wait until no generation cleanup is running.
    #[cfg(feature = "synthetic-attestation")]
    pub async fn staging_cleaned(&self) {
        let mut running = self.inner.cleaning.subscribe();
        running.wait_for(|n| *n == 0).await.expect("cleaning");
    }

    pub(crate) fn response_current(&self, answer: &FromService) -> bool {
        match answer {
            FromService::ReadBatch { deadline_ms, .. } => self
                .inner
                .clock
                .now_ms()
                .is_ok_and(|now| now < *deadline_ms),
            _ => true,
        }
    }

    /// The application session over an established channel. `channel_binding`
    /// must be that channel's binding; the first message is the challenge.
    pub fn connect(&self, channel_binding: [u8; 32]) -> (Connection, FromService) {
        let challenge = bh_crypto::random();
        (
            Connection {
                inner: self.inner.clone(),
                binding: channel_binding,
                challenge: Some(challenge),
                nonce: Some(challenge),
                session: None,
                recovery: None,
            },
            FromService::Challenge { challenge },
        )
    }
}

/// The authenticated device of one connection.
struct Session {
    account: AccountId,
    device: DeviceId,
    log: LogId,
    genesis: Vec<u8>,
}

/// The account a connection's released recovery claim was for, and whether
/// its one recovery-signed device addition has been used.
struct RecoverySession {
    account: AccountId,
    log: LogId,
    genesis: Vec<u8>,
    event: Option<Digest>,
}

/// One device connection's application protocol.
pub struct Connection {
    inner: Arc<Inner>,
    binding: [u8; 32],
    /// Spent by the first authentication attempt.
    challenge: Option<[u8; 32]>,
    /// The same challenge as the home nonce of one recovery claim, spent by
    /// the first `Recover` independently of authentication.
    nonce: Option<[u8; 32]>,
    session: Option<Session>,
    recovery: Option<RecoverySession>,
}
impl Connection {
    /// Whether a device has authenticated on this connection.
    pub fn authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// The account this unauthenticated connection recovered, while its one
    /// recovery-signed device addition is unused.
    pub fn recovering(&self) -> Option<AccountId> {
        self.recovery
            .as_ref()
            .filter(|r| r.event.is_none())
            .map(|r| r.account)
    }

    pub async fn handle(&mut self, message: ToService) -> FromService {
        #[cfg(feature = "synthetic-attestation")]
        if let Some(observer) = self.inner.observer.lock().expect("observer").clone() {
            observer(&message);
        }
        if self.recovery.is_some()
            && !matches!(
                message,
                ToService::SubmitControl {
                    attachment: None,
                    ..
                } | ToService::ConfirmControl { .. }
            )
        {
            return FromService::Refused {
                reason: Refusal::Unauthenticated,
            };
        }
        let result = match message {
            ToService::Authenticate {
                proof,
                account,
                device,
                genesis,
            } => self.authenticate(&proof, account, device, genesis).await,
            // A request that joined reads begun before it arrived is refused
            // only on reads of its own: it asks again, fresh.
            ToService::Permits { items } => {
                let mut older = false;
                match self.permits(&items, false, &mut older).await {
                    Ok(FromService::Permits { items: answers })
                        if older && answers.iter().any(Result::is_err) =>
                    {
                        self.permits(&items, true, &mut older).await
                    }
                    Err(Refused(_)) if older => self.permits(&items, true, &mut older).await,
                    answer => answer,
                }
            }
            ToService::ReadBatch {
                want:
                    Want::ReadBatch {
                        log,
                        after,
                        max_events,
                    },
            } => {
                let mut older = false;
                match self
                    .read_batch(log, after, max_events, false, &mut older)
                    .await
                {
                    Err(Refused(_)) if older => {
                        self.read_batch(log, after, max_events, true, &mut older)
                            .await
                    }
                    answer => answer,
                }
            }
            ToService::ReadBatch { .. } => Err(Refused(Refusal::Malformed)),
            ToService::StoreHomeObjects {
                prefix,
                record,
                device_seal,
                recovery_seal,
            } => {
                self.store_home_objects(prefix, record, device_seal, recovery_seal)
                    .await
            }
            ToService::SubmitControl {
                log,
                event,
                delivery,
                attachment,
            } => self.submit_control(log, event, delivery, attachment).await,
            ToService::Recover { sealed, purpose } => self.recover(&sealed, purpose).await,
            ToService::ReadNotices { after_ms } => self.read_notices(after_ms).await,
            ToService::ConfirmControl {
                log,
                event,
                challenge,
            } => self.confirm_control(log, event, challenge).await,
            ToService::ReadAccountEvidence {
                genesis,
                first,
                last,
                challenge,
            } => {
                self.read_account_evidence(genesis, first, last, challenge)
                    .await
            }
            ToService::RegisterBase {
                descriptor,
                body,
                creator_head,
                metadata,
            } => {
                self.register_base(descriptor, body, creator_head, metadata)
                    .await
            }
            ToService::SubmitBaseControl {
                log,
                descriptor,
                body,
                metadata,
            } => {
                self.submit_base_control(log, descriptor, body, metadata)
                    .await
            }
        };
        match result {
            Ok(answer) => answer,
            Err(Refused(reason)) => FromService::Refused { reason },
            Err(Unavailable) => FromService::Unavailable,
        }
    }

    async fn confirm_control(
        &self,
        log: LogId,
        event: Digest,
        challenge: [u8; 32],
    ) -> Result<FromService, Failure> {
        let (id, own_log, genesis) = if let Some(session) = &self.session {
            (session.account, session.log, &session.genesis)
        } else if let Some(recovery) = &self.recovery {
            if recovery.event != Some(event) {
                return Err(Refused(Refusal::Unauthenticated));
            }
            (recovery.account, recovery.log, &recovery.genesis)
        } else {
            return Err(Refused(Refusal::Unauthenticated));
        };
        if log != own_log {
            return Err(Refused(Refusal::Unauthenticated));
        }
        let slot = self.inner.slot(id)?;
        let current = self
            .inner
            .refresh(&slot, id, log, genesis, true, &mut false)
            .await?;
        let state = slot.lock().await;
        let account = state.at(&current)?;
        let confirmation = self
            .inner
            .store
            .confirmed_event(&id.0, event)
            .map_err(|_| Unavailable)?
            .ok_or(Refused(Refusal::NotOrdered))?;
        let head = self.inner.accepted(account, challenge)?;
        Ok(FromService::Confirmed { confirmation, head })
    }

    async fn read_account_evidence(
        &self,
        genesis: Vec<u8>,
        first: u64,
        last: u64,
        challenge: [u8; 32],
    ) -> Result<FromService, Failure> {
        if first == 0
            || last < first
            || last > bh_authz_proto::MAX_SAFE_POSITION
            || last - first >= READ_BATCH
        {
            return Err(Refused(Refusal::Malformed));
        }
        let event = AccountEvent::decode(&genesis).map_err(|_| Refused(Refusal::Malformed))?;
        let id = AccountId::of_genesis(&event).map_err(|_| Refused(Refusal::Malformed))?;
        let log = LogId {
            kind: LogKind::Account,
            id: account_log_id(&genesis).map_err(|_| Refused(Refusal::Malformed))?,
        };
        let slot = self.inner.slot(id)?;
        let current = self
            .inner
            .refresh(&slot, id, log, &genesis, true, &mut false)
            .await?;
        let state = slot.lock().await;
        let account = state.at(&current)?;
        let mut confirmations = Vec::new();
        for position in first..=last {
            if let Some(bytes) = self
                .inner
                .store
                .confirmation(&id.0, position)
                .map_err(|_| Unavailable)?
            {
                confirmations.push(bytes);
            }
        }
        self.inner.before_deadline(current.issued)?;
        Ok(FromService::AccountEvidence {
            events_permit: self.inner.sign_uncapped(
                Scope::ReadEvents { log, first, last },
                current.issued,
                bh_crypto::random(),
            ),
            confirmations,
            head: self.inner.accepted(account, challenge)?,
        })
    }

    async fn authenticate(
        &mut self,
        proof: &[u8; PROOF_LEN],
        account: AccountId,
        device: DeviceId,
        genesis: Vec<u8>,
    ) -> Result<FromService, Failure> {
        // Spent by any attempt: one challenge per connection.
        let challenge = self
            .challenge
            .take()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        let event =
            AccountEvent::decode(&genesis).map_err(|_| Refused(Refusal::Unauthenticated))?;
        if AccountId::of_genesis(&event).ok() != Some(account) {
            return Err(Refused(Refusal::Unauthenticated));
        }
        let log = LogId {
            kind: LogKind::Account,
            id: account_log_id(&genesis).map_err(|_| Refused(Refusal::Unauthenticated))?,
        };
        let slot = self.inner.slot(account)?;
        let current = self
            .inner
            .refresh(&slot, account, log, &genesis, true, &mut false)
            .await?;
        let state = slot.lock().await;
        let current = state.at(&current)?;
        // The proof names the head it was made at: the current one, or an
        // earlier verified head of a device that has not caught up yet.
        let position = u64::from_be_bytes(proof[66..74].try_into().expect("fixed width"));
        let view = self
            .inner
            .view_at(current, account, &genesis, position)?
            .ok_or(Refused(Refusal::Unauthenticated))?;
        let context = Context {
            channel_binding: self.binding,
            challenge,
        };
        match device_auth::verify_at(&view, context, proof) {
            Ok(possession) if possession.device() == device => {}
            Err(AccountError::NotActive) => return Err(Refused(Refusal::NotActive)),
            Err(AccountError::Unavailable) => return Err(Unavailable),
            _ => return Err(Refused(Refusal::Unauthenticated)),
        }
        active_now(
            &current.verified,
            device,
            self.inner.clock.bounds_ms().map_err(|_| Unavailable)?,
        )?;
        let account_head = current.verified.head();
        self.session = Some(Session {
            account,
            device,
            log,
            genesis,
        });
        Ok(FromService::Authenticated { account_head })
    }

    async fn store_home_objects(
        &self,
        prefix: AccountHead,
        record: Vec<u8>,
        device_seal: Vec<u8>,
        recovery_seal: Vec<u8>,
    ) -> Result<FromService, Failure> {
        let session = self
            .session
            .as_ref()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        let slot = self.inner.slot(session.account)?;
        let current = self.inner.current(&slot, session, true, &mut false).await?;
        let issued = current.issued;
        let state = slot.lock().await;
        let current = state.at(&current)?;
        let cap = active_now(
            &current.verified,
            session.device,
            self.inner.clock.bounds_ms().map_err(|_| Unavailable)?,
        )?;
        self.inner.before_deadline(issued)?;
        // Only the three-event signup prefix, already ordered at this home.
        // Later account changes do not change the retained original commitments.
        if prefix.position != 3 || current.head.position < prefix.position {
            return Err(Refused(Refusal::Invalid));
        }
        let historical = self
            .inner
            .view_at(current, session.account, &session.genesis, prefix.position)?
            .ok_or(Refused(Refusal::Invalid))?;
        if historical.head() != prefix {
            return Err(Refused(Refusal::Invalid));
        }
        historical
            .verify_initial_objects(&record, &device_seal, &recovery_seal)
            .map_err(|_| Refused(Refusal::Invalid))?;
        let current_record = bh_account::recovery::record_checks(&record)
            .ok()
            .zip(current.verified.record_digest().ok())
            .is_some_and(|(checks, digest)| checks.digest == digest)
            && current
                .verified
                .personal_publication()
                .is_ok_and(|p| p.recovery_digest() == &personal::seal_digest(&recovery_seal));
        let bundle = bh_sync::home_objects::encode(&record, &device_seal, &recovery_seal)
            .map_err(|_| Refused(Refusal::Invalid))?;
        let bundle_digest = bh_sync::home_objects::digest(&bundle).map_err(|_| Unavailable)?;
        // The signed account-chain head commits the prefix; it is not the
        // different, outer account-log ordering head.
        let prefix_digest = Digest(historical.head().hash);
        let permit = self.inner.sign(
            Scope::StoreHomeObjects {
                log: session.log,
                prefix_digest,
                bundle_digest,
            },
            issued,
            bh_crypto::random(),
            cap,
        );
        // Neither the device seal nor a success marker enters Store. The
        // immutable write uses the fixed permission outside this account's
        // lock.
        drop(state);
        let stored = self
            .inner
            .edge
            .store_home_objects(permit, bundle)
            .await
            .map_err(|_| Unavailable)?;
        if stored.prefix_digest != prefix_digest
            || stored.bundle_digest != bundle_digest
            || self.inner.clock.now_ms().map_err(|_| Unavailable)? >= issued + MAX_PERMIT_WINDOW_MS
        {
            return Err(Unavailable);
        }
        // Stored at the home, the record can be released: indexed by its
        // proof check while it is the account's current record. A record a
        // replacement has superseded is never indexed again.
        let state = slot.lock().await;
        let account = state.account.as_ref().ok_or(Unavailable)?;
        active_now(
            &account.verified,
            session.device,
            self.inner.clock.bounds_ms().map_err(|_| Unavailable)?,
        )?;
        if current_record
            && account.verified.record_digest().ok()
                == bh_account::recovery::record_checks(&record)
                    .ok()
                    .map(|checks| checks.digest)
            && account
                .verified
                .personal_publication()
                .is_ok_and(|p| p.recovery_digest() == &personal::seal_digest(&recovery_seal))
        {
            self.inner
                .store
                .put_recovery(&session.account.0, &record, &recovery_seal, None)
                .map_err(|_| Unavailable)?;
        }
        Ok(FromService::HomeObjectsStored {
            prefix,
            digest: bundle_digest.0,
        })
    }

    /// Judge a recovery claim sealed for this connection's nonce, which any
    /// claim spends. `AddDevice` is for a device with no session: a release
    /// opens this connection's recovery session for the account. `Sign` is
    /// for an authenticated device checking its own account's password and
    /// kit: a claim for any other account is not recognised.
    async fn recover(
        &mut self,
        sealed: &[u8],
        purpose: RecoverPurpose,
    ) -> Result<FromService, Failure> {
        let nonce = self.nonce.take().ok_or(Refused(Refusal::Unauthenticated))?;
        let key = self
            .inner
            .recovery
            .as_ref()
            .ok_or(Refused(Refusal::Unsupported))?;
        let own = match purpose {
            RecoverPurpose::AddDevice => None,
            RecoverPurpose::Sign => Some(
                self.session
                    .as_ref()
                    .ok_or(Refused(Refusal::Unauthenticated))?,
            ),
        };
        let not_recognised = Ok(FromService::Recovery(RecoveryAnswer::NotRecognised));
        // The purpose is sealed with the claim; the request's must match it.
        let claim = match bh_account::recovery::open_claim(&key.key, sealed, &nonce) {
            Ok((claim, sealed_for)) if sealed_for == purpose as u8 => claim,
            Ok(_) | Err(AccountError::InvalidCredentials) => return not_recognised,
            Err(_) => return Err(Refused(Refusal::Malformed)),
        };
        let Some(entry) = self
            .inner
            .store
            .recovery_by_proof(&claim.proof_check())
            .map_err(|_| Unavailable)?
        else {
            return not_recognised;
        };
        let account = AccountId(entry.account);
        let slot = self.inner.slot(account)?;
        let current = if let Some(session) = own {
            if session.account != account {
                return not_recognised;
            }
            self.inner.current(&slot, session, true, &mut false).await?
        } else {
            let genesis = self
                .inner
                .store
                .account_event(&account.0, 1)
                .map_err(|_| Unavailable)?
                .ok_or(Unavailable)?;
            let log = LogId {
                kind: LogKind::Account,
                id: account_log_id(&genesis).map_err(|_| Unavailable)?,
            };
            self.inner
                .refresh(&slot, account, log, &genesis, true, &mut false)
                .await?
        };
        // Re-read and validate the indexed material under the account lock:
        // refresh may have activated a replacement, retiring this proof.
        let guard = slot.lock().await;
        let view = &guard.at(&current)?.verified;
        let Some(entry) = self
            .inner
            .store
            .recovery_by_proof(&claim.proof_check())
            .map_err(|_| Unavailable)?
        else {
            return not_recognised;
        };
        if entry.account != account.0
            || view.record_digest().map_err(|_| Unavailable)? != entry.record_digest
            || bh_account::recovery::record_checks(&entry.record)
                .map_err(|_| Unavailable)?
                .digest
                != entry.record_digest
            || view
                .personal_publication()
                .map_err(|_| Unavailable)?
                .recovery_digest()
                != &bh_account::personal::seal_digest(&entry.recovery_seal)
        {
            return Err(Unavailable);
        }
        let bounds = self.inner.clock.bounds_ms().map_err(|_| Unavailable)?;
        let judged =
            crate::recovery::check(&self.inner.store, &claim, bounds).map_err(|_| Unavailable)?;
        drop(guard);
        let Some((judged_account, answer)) = judged else {
            return not_recognised;
        };
        if judged_account != account {
            return Err(Unavailable);
        }
        if matches!(answer, RecoveryAnswer::Released { .. })
            && purpose == RecoverPurpose::AddDevice
            && self.session.is_none()
        {
            let RecoveryAnswer::Released { ref genesis, .. } = answer else {
                return Err(Unavailable);
            };
            self.recovery = Some(RecoverySession {
                account,
                log: LogId {
                    kind: LogKind::Account,
                    id: account_log_id(genesis).map_err(|_| Unavailable)?,
                },
                genesis: genesis.clone(),
                event: None,
            });
        }
        Ok(FromService::Recovery(answer))
    }

    /// When the session's account's kit was used, after `after_ms`.
    async fn read_notices(&self, after_ms: u64) -> Result<FromService, Failure> {
        let session = self
            .session
            .as_ref()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        let slot = self.inner.slot(session.account)?;
        self.inner.current(&slot, session, true, &mut false).await?;
        let kit_used_ms = self
            .inner
            .store
            .notices_after(&session.account.0, after_ms, NOTICES_READ)
            .map_err(|_| Unavailable)?;
        Ok(FromService::Notices { kit_used_ms })
    }

    /// One read-only immutable selection. Its currentness reads (the account
    /// refresh and, for a base, the control confirmation) and the selection
    /// run side by side; the selection is discarded unless both succeed and
    /// what they verified is unchanged at the grant. The account lock guards
    /// only the small authority snapshot, never a read or the body stream.
    async fn read_batch(
        &self,
        log: LogId,
        after: Head,
        max_events: u16,
        fresh: bool,
        older: &mut bool,
    ) -> Result<FromService, Failure> {
        if !(1..=64).contains(&max_events)
            || after
                .position
                .checked_add(u64::from(max_events))
                .is_none_or(|n| n > bh_authz_proto::MAX_SAFE_POSITION)
            || (after.position == 0 && after != Head::EMPTY)
        {
            return Err(Refused(Refusal::Malformed));
        }
        let session = self
            .session
            .as_ref()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        let own_account = log == session.log;
        if !own_account && !self.inner.owns(session, &log)? {
            return Err(Refused(Refusal::Unknown));
        }
        let slot = self.inner.slot(session.account)?;
        let first = after.position + 1;
        let last = after.position + u64::from(max_events);
        let select = async {
            let start = self.inner.clock.now_ms().map_err(|_| Unavailable)?;
            let read = self.inner.sign_uncapped(
                Scope::ReadEvents { log, first, last },
                start,
                bh_crypto::random(),
            );
            let fetched = self.inner.edge.read_log_with_receipt(read).await;
            Ok::<_, Failure>((start, fetched))
        };
        // The only supported base policy is this verified, registered sole-account
        // control protocol. A registry match alone is not a membership rule.
        let (mut refreshed_older, mut confirmed_older) = (false, false);
        let confirm = async {
            if own_account {
                return Ok(None);
            }
            self.inner
                .confirm_base(&slot, session, log, true, fresh, &mut confirmed_older)
                .await
        };
        let (current, confirmed, selected) = tokio::join!(
            self.inner
                .current(&slot, session, fresh, &mut refreshed_older),
            confirm,
            select
        );
        *older |= refreshed_older || confirmed_older;
        let current = current?;
        let confirmed = confirmed?;
        let (selected_at, fetched) = selected?;
        // The earliest start of every read the answer rests on.
        let issued = confirmed
            .map_or(current.issued, |c| current.issued.min(c.start))
            .min(selected_at);
        let outer_head = current.outer;
        let original_head = current.original;
        let control = confirmed.map(|c| c.controls);
        {
            let state = slot.lock().await;
            let account = state.at(&current)?;
            if account.verified.active_device(session.device).is_err() {
                return Err(Refused(Refusal::NotActive));
            }
            if let Some(control) = control {
                // Refused only on the record this request's confirmation left.
                let record = account
                    .bases
                    .get(&log.id)
                    .filter(|r| r.current && r.controls() == control)
                    .ok_or(Unavailable)?;
                let state = record.spine.state();
                if state.creator != session.account
                    || state.base != BaseId(log.id)
                    || state.hosting_root != self.inner.keys.root()
                    || record.view.id() != session.account
                {
                    return Err(Refused(Refusal::Unsupported));
                }
                if record.view.active_device(session.device).is_err() {
                    return Err(Refused(Refusal::NotActive));
                }
                if state.account != original_head {
                    return Err(Refused(Refusal::AccountChangePending));
                }
            }
        }
        if own_account
            && (after.position > outer_head.position
                || (after.position == outer_head.position && after != outer_head))
        {
            return Err(Unavailable);
        }
        self.inner.before_deadline(issued)?;
        let fetched = fetched.map_err(|_| Unavailable)?;
        // Ordering failures go through the legacy verifier, not an empty result.
        // Missing receipt evidence cannot be made into a verified tail.
        let mut chain = after;
        let mut bodies = Vec::with_capacity(fetched.items.len().min(usize::from(max_events)));
        let mut invalid =
            fetched.items.len() > usize::from(max_events) || fetched.coverage.is_some();
        for (ordered, bytes) in fetched.items.iter().take(usize::from(max_events)) {
            let parsed = (|| {
                let c = Commitment::decode(ordered).ok()?;
                let event = OpaqueEvent::decode(bytes).ok()?;
                chain = c.verify_next(BaseId(log.id), chain).ok()?;
                c.verify_body(&event).ok()?;
                let body = if own_account {
                    if c.route() != Route::Control {
                        return None;
                    }
                    account_log_unwrap(&event).ok()?.1
                } else {
                    Some(referenced_body(&event).ok()?)
                };
                Some(body)
            })();
            match parsed {
                Some(Some(body)) => bodies.push(body),
                Some(None) => {}
                None => {
                    invalid = true;
                    break;
                }
            }
        }
        if own_account {
            if !invalid
                && (chain.position > outer_head.position
                    || (chain.position < outer_head.position
                        && fetched.items.len() < usize::from(max_events)))
            {
                return Err(Unavailable);
            }
            if chain.position == outer_head.position && chain != outer_head {
                invalid = true;
            }
        }
        if !own_account
            && !invalid
            && control.is_some_and(|known| {
                chain.position < known.control_head.position
                    && fetched.items.len() < usize::from(max_events)
            })
        {
            return Err(Unavailable);
        }
        if !own_account && !fetched.items.is_empty() {
            match fetched.receipt.as_ref() {
                None => return Err(Unavailable),
                Some(bytes)
                    if receipt::verify(&self.inner.keys.root(), BaseId(log.id), bytes)
                        .map(|r| r.head() != chain)
                        .unwrap_or(true) =>
                {
                    invalid = true
                }
                _ => {}
            }
        } else if fetched.receipt.is_some() {
            invalid = true;
        }
        let guard = slot.lock().await;
        // Compare guarded evidence, not another network freshness lookup. This
        // cannot detect withheld outside changes; the first check's deadline stands.
        self.inner.before_deadline(issued)?;
        let account = guard.at(&current)?;
        let cap = active_now(
            &account.verified,
            session.device,
            self.inner.clock.bounds_ms().map_err(|_| Unavailable)?,
        )?;
        if own_account {
            // Lapsed originals still advance the public log. Do not stall
            // following that log, or grant their inactive delivery bodies.
            let pin = account.pin.ok_or(Unavailable)?;
            let mut applied = Vec::with_capacity(bodies.len());
            for body in bodies {
                if self
                    .inner
                    .store
                    .body_applied(pin, body)
                    .map_err(|_| Unavailable)?
                {
                    applied.push(body);
                }
            }
            bodies = applied;
        } else {
            let record = account.bases.get(&log.id).ok_or(Unavailable)?;
            let state = record.spine.state();
            if state.creator != session.account
                || state.base != BaseId(log.id)
                || state.hosting_root != self.inner.keys.root()
                || Some(record.controls()) != control
                || state.account != account.verified.head()
                || record.view.id() != session.account
                || !record.current
                || record.view.active_device(session.device).is_err()
            {
                return Err(Unavailable);
            }
        }
        let deadline_ms = issued
            .checked_add(MAX_PERMIT_WINDOW_MS)
            .ok_or(Unavailable)?
            .min(cap.unwrap_or(u64::MAX));
        let repair = || FromService::ReadBatch {
            log,
            after,
            issued_ms: issued,
            deadline_ms,
            result: ReadBatchResult::Repair {
                events_permit: self.inner.sign(
                    Scope::ReadEvents { log, first, last },
                    issued,
                    bh_crypto::random(),
                    cap,
                ),
            },
        };
        if invalid {
            let answer = repair();
            self.inner.before_deadline(issued)?;
            if !own_account {
                self.inner.running(&log.id)?;
            }
            return Ok(answer);
        }
        let body_permit = (!bodies.is_empty()).then(|| {
            self.inner.sign(
                Scope::ReadBodies { log, bodies },
                issued,
                bh_crypto::random(),
                cap,
            )
        });
        let reply = FromService::ReadBatch {
            log,
            after,
            issued_ms: issued,
            deadline_ms,
            result: ReadBatchResult::Selected {
                possibly_more: fetched.items.len() == usize::from(max_events),
                items: fetched.items,
                receipt: fetched.receipt,
                body_permit,
            },
        };
        // A full page cannot be cut short: its receipt names its exact tail.
        let answer = match reply.encode() {
            Ok(_) => reply,
            Err(_) => repair(),
        };
        self.inner.before_deadline(issued)?;
        if !own_account {
            self.inner.running(&log.id)?;
        }
        Ok(answer)
    }

    async fn permits(
        &self,
        items: &[Want],
        fresh: bool,
        older: &mut bool,
    ) -> Result<FromService, Failure> {
        let session = self
            .session
            .as_ref()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        let slot = self.inner.slot(session.account)?;
        let current = self.inner.current(&slot, session, fresh, older).await?;
        let mut issued = current.issued;
        // A content append needs its base's control record current: made so
        // once per base in a request.
        let mut bases: HashMap<[u8; 32], Option<Refusal>> = HashMap::new();
        let mut control_heads: HashMap<[u8; 32], Result<u64, Refusal>> = HashMap::new();
        // Any other base item needs only an accepted record: a provisional
        // one is promoted first, by reading its genesis back.
        let mut accepted: HashMap<[u8; 32], Option<Refusal>> = HashMap::new();
        for item in items {
            if let Want::ReadEvents { log, .. }
            | Want::ReadBodies { log, .. }
            | Want::Stage { log, .. }
            | Want::Subscribe { log } = item
                && *log != session.log
                && !accepted.contains_key(&log.id)
                && self.inner.owns(session, log)?
            {
                let refused = match self
                    .inner
                    .accepted_base(&slot, session, *log, fresh, older)
                    .await
                {
                    Ok(confirmed) => {
                        if let Some(confirmed) = confirmed {
                            issued = issued.min(confirmed.start);
                        }
                        None
                    }
                    Err(Refused(reason)) => Some(reason),
                    Err(Unavailable) => return Err(Unavailable),
                };
                accepted.insert(log.id, refused);
            }
            if let Want::ReadControls { log, .. } = item
                && *log != session.log
                && !control_heads.contains_key(&log.id)
                && self.inner.owns(session, log)?
            {
                let head = match self
                    .inner
                    .confirm_base(&slot, session, *log, true, fresh, older)
                    .await
                {
                    Ok(Some(confirmed)) => {
                        issued = issued.min(confirmed.start);
                        Ok(confirmed.controls.control_head.position)
                    }
                    Ok(None) => return Err(Unavailable),
                    Err(Refused(reason)) => Err(reason),
                    Err(Unavailable) => return Err(Unavailable),
                };
                control_heads.insert(log.id, head);
            }
            if let Want::Append { log, .. } | Want::Presence { log, .. } = item
                && !bases.contains_key(&log.id)
                && self.inner.owns(session, log)?
            {
                let refused = match self
                    .inner
                    .confirm_base(&slot, session, *log, false, fresh, older)
                    .await
                {
                    Ok(confirmed) => {
                        if let Some(confirmed) = confirmed {
                            issued = issued.min(confirmed.start);
                        }
                        None
                    }
                    Err(Refused(reason)) => Some(reason),
                    Err(Unavailable) => return Err(Unavailable),
                };
                bases.insert(log.id, refused);
            }
        }
        let state = slot.lock().await;
        let account = state.at(&current)?;
        let bounds = self.inner.clock.bounds_ms().map_err(|_| Unavailable)?;
        let cap = active_now(&account.verified, session.device, bounds)?;
        self.inner.before_deadline(issued)?;
        // A record evicted or reloaded since it was made current grants nothing.
        if bases.iter().any(|(base, refused)| {
            refused.is_none() && account.bases.get(base).is_none_or(|r| !r.current)
        }) {
            return Err(Unavailable);
        }
        let batch = bh_crypto::random();
        let mut answers = Vec::with_capacity(items.len());
        for item in items {
            let refused = match item {
                Want::Append { log, .. } | Want::Presence { log, .. } => {
                    bases.get(&log.id).copied().flatten()
                }
                Want::ReadEvents { log, .. }
                | Want::ReadBodies { log, .. }
                | Want::Stage { log, .. }
                | Want::Subscribe { log } => accepted.get(&log.id).copied().flatten(),
                _ => None,
            };
            let answer = match refused {
                Some(reason) => Err(reason),
                None => match item {
                    Want::ReadControls { log, after } => {
                        let through = if *log == session.log {
                            Some(Ok(current.outer.position))
                        } else {
                            control_heads.get(&log.id).copied()
                        };
                        match through {
                            Some(Ok(through)) if *after <= through => {
                                if *log != session.log {
                                    let record = account.bases.get(&log.id).ok_or(Unavailable)?;
                                    let state = record.spine.state();
                                    // Confirmation made this record current; a different
                                    // hosting root cannot issue under our permit key.
                                    if !record.current
                                        || state.hosting_root != self.inner.keys.root()
                                    {
                                        return Err(Unavailable);
                                    }
                                }
                                Ok(Scope::ReadControlRange {
                                    log: *log,
                                    after: *after,
                                    through,
                                })
                            }
                            Some(Ok(_)) => Err(Refusal::Malformed),
                            Some(Err(reason)) => Err(reason),
                            None => Err(Refusal::Unknown),
                        }
                    }
                    _ => self.scope(session, account, item)?,
                },
            };
            answers.push(answer.map(|scope| self.inner.sign(scope, issued, batch, cap)));
        }
        let affected = items
            .iter()
            .filter_map(|item| {
                let log = match item {
                    Want::ReadEvents { log, .. }
                    | Want::ReadControls { log, .. }
                    | Want::ReadBodies { log, .. }
                    | Want::Stage { log, .. }
                    | Want::Append { log, .. }
                    | Want::Subscribe { log }
                    | Want::Presence { log, .. }
                    | Want::ReadDirectory { log }
                    | Want::StoreDirectoryEntry { log, .. }
                    | Want::ReadBatch { log, .. } => log,
                };
                (log.kind == LogKind::Base).then_some(log.id)
            })
            .collect::<Vec<_>>();
        self.inner
            .store
            .while_running(&affected, || ())
            .map_err(|_| Unavailable)?
            .ok_or(Refused(Refusal::Conflict))?;
        Ok(FromService::Permits { items: answers })
    }

    /// One requested permit's scope, or its refusal. An item's own refusal is
    /// `Ok(Err(..))`; a storage failure fails the whole request.
    fn scope(
        &self,
        session: &Session,
        account: &Account,
        item: &Want,
    ) -> Result<Result<Scope, Refusal>, Failure> {
        let log = match item {
            Want::ReadEvents { log, .. }
            | Want::ReadControls { log, .. }
            | Want::ReadBodies { log, .. }
            | Want::Stage { log, .. }
            | Want::Append { log, .. }
            | Want::Subscribe { log }
            | Want::Presence { log, .. }
            | Want::ReadDirectory { log }
            | Want::StoreDirectoryEntry { log, .. }
            | Want::ReadBatch { log, .. } => *log,
        };
        if log == session.log {
            // The account log is read and watched; it changes only through
            // verified controls. Its only readable bodies are those its
            // ordered, verified events carry. A rotation's body is staged
            // before the rotation names it, and is read back only by the service.
            return Ok(match item {
                &Want::ReadEvents { first, last, .. } => Ok(Scope::ReadEvents { log, first, last }),
                &Want::Stage { body, len, .. } => Ok(Scope::Stage { log, body, len }),
                Want::Subscribe { .. } => Ok(Scope::Subscribe { log }),
                Want::ReadDirectory { .. } => Ok(Scope::ReadDirectory { log }),
                &Want::StoreDirectoryEntry {
                    entry,
                    version,
                    body,
                    len,
                    ..
                } => Ok(Scope::StoreDirectoryEntry {
                    log,
                    entry,
                    version,
                    body,
                    len,
                }),
                Want::ReadBodies { bodies, .. } => {
                    let mut all_applied = true;
                    for body in bodies {
                        let applied = match account.pin {
                            Some(pin) => self
                                .inner
                                .store
                                .body_applied(pin, *body)
                                .map_err(|_| Unavailable)?,
                            None => false,
                        };
                        all_applied &= applied;
                    }
                    if all_applied {
                        Ok(Scope::ReadBodies {
                            log,
                            bodies: bodies.clone(),
                        })
                    } else {
                        Err(Refusal::Unknown)
                    }
                }
                _ => Err(Refusal::Unsupported),
            });
        }
        if !self.inner.owns(session, &log)? {
            return Ok(Err(Refusal::Unknown));
        }
        Ok(match *item {
            Want::ReadEvents { first, last, .. } => Ok(Scope::ReadEvents { log, first, last }),
            Want::ReadBodies { ref bodies, .. } => Ok(Scope::ReadBodies {
                log,
                bodies: bodies.clone(),
            }),
            Want::Stage { body, len, .. } => Ok(Scope::Stage { log, body, len }),
            Want::Subscribe { .. } => Ok(Scope::Subscribe { log }),
            Want::ReadBatch { .. }
            | Want::ReadControls { .. }
            | Want::ReadDirectory { .. }
            | Want::StoreDirectoryEntry { .. } => Err(Refusal::Unsupported),
            Want::Presence { epoch, .. } => content_membership(session, account, log, epoch)
                .map(|()| Scope::Presence { log, epoch }),
            Want::Append {
                ref event, epoch, ..
            } => (|| {
                let event = OpaqueEvent::decode(event).map_err(|_| Refusal::Malformed)?;
                content_membership(session, account, log, epoch)?;
                // Every base event commits to its detached body in its first
                // 32 envelope bytes: the permit requires exactly that body.
                let body = referenced_body(&event).map_err(|_| Refusal::Malformed)?;
                Ok(Scope::Append {
                    log,
                    event: event.digest(),
                    body: Some(body),
                    epoch,
                    after: None,
                    attached: None,
                })
            })(),
        })
    }

    async fn submit_control(
        &mut self,
        log: LogId,
        event: Vec<u8>,
        delivery: Option<Box<Delivery>>,
        attachment: Option<Box<RecoveryAttachment>>,
    ) -> Result<FromService, Failure> {
        let (id, own_log, genesis, device) = if let Some(session) = &self.session {
            (
                session.account,
                session.log,
                &session.genesis,
                Some(session.device),
            )
        } else if let Some(recovery) = &self.recovery {
            if recovery.event.is_some() || log != recovery.log || delivery.is_none() {
                return Err(Refused(Refusal::Unauthenticated));
            }
            let decoded =
                AccountEvent::decode(&event).map_err(|_| Refused(Refusal::Unauthenticated))?;
            if !matches!(
                decoded.change(),
                bh_account::AccountChange::DeviceAdded {
                    by_recovery: true,
                    ..
                }
            ) {
                return Err(Refused(Refusal::Unauthenticated));
            }
            (recovery.account, recovery.log, &recovery.genesis, None)
        } else {
            return Err(Refused(Refusal::Unauthenticated));
        };
        if log.kind == LogKind::Base {
            return Err(Refused(Refusal::Unsupported));
        }
        if log != own_log {
            return Err(Refused(Refusal::Unknown));
        }
        // Only a device's own control carries an attachment.
        if attachment.is_some() && (delivery.is_some() || device.is_none()) {
            return Err(Refused(Refusal::Invalid));
        }
        // A rotation names the body it staged: read it back before any lock.
        let attachment = match attachment {
            Some(attachment) => Some(self.inner.read_attachment(log, &event, *attachment).await?),
            None => None,
        };
        let slot = self.inner.slot(id)?;
        let current = self
            .inner
            .refresh(&slot, id, log, genesis, true, &mut false)
            .await?;
        let issued = current.issued;
        let state = slot.lock().await;
        let current = state.at(&current)?;
        let cap = device
            .map(|device| {
                active_now(
                    &current.verified,
                    device,
                    self.inner.clock.bounds_ms().map_err(|_| Unavailable)?,
                )
            })
            .transpose()?
            .flatten();
        self.inner.before_deadline(issued)?;
        let body = if current.head == Head::EMPTY {
            // A new account's log starts with its genesis, which carries nothing.
            if event != *genesis || delivery.is_some() || attachment.is_some() {
                return Err(Refused(Refusal::Invalid));
            }
            None
        } else {
            let mut candidate = current.verified.clone();
            let bounds = self.inner.confirmation_bounds(id, current.head.position)?;
            let decoded = AccountEvent::decode(&event).map_err(|_| Refused(Refusal::Invalid))?;
            if let bh_account::AccountChange::RemovalCancelled { request, .. } = decoded.change()
                && current.verified.pending_removals(0).iter().any(|pending| {
                    pending.request == request && bounds.latest_ms >= pending.deadline_ms
                })
            {
                return Err(Refused(Refusal::Lapsed));
            }
            candidate
                .apply_timed(&event, Some(crate::confirm::time(bounds)))
                .map_err(|error| account_failure(error, Refusal::Invalid))?;
            if device.is_none() {
                let delivery = delivery.as_ref().ok_or(Refused(Refusal::Unauthenticated))?;
                let sender = personal::verify_device_delivery(
                    &candidate,
                    &delivery.frame,
                    &delivery.recipient,
                )
                .map_err(|_| Refused(Refusal::Invalid))?;
                if sender
                    != current
                        .verified
                        .recovery_author()
                        .map_err(|_| Refused(Refusal::Invalid))?
                {
                    return Err(Refused(Refusal::Unauthenticated));
                }
            }
            let delivery_body = delivery
                .map(|delivery| admit_delivery(&current.verified, &candidate, &delivery))
                .transpose()
                .map_err(|_| Refused(Refusal::Invalid))?;
            let attached_body = admit_attachment(
                &current.verified,
                &candidate,
                &decoded,
                attachment.as_ref(),
                bounds,
            )
            .map_err(|_| Refused(Refusal::Invalid))?;
            // A replacement carries a complete new record, but a rotation
            // carries only its seals. Refuse before permitting an append if
            // the initial record has not been indexed, or if the durable row
            // no longer matches this verified predecessor publication.
            if matches!(
                decoded.change(),
                bh_account::AccountChange::PersonalRotated { .. }
            ) {
                let required = RecoveryDigests {
                    record: current
                        .verified
                        .record_digest()
                        .map_err(|_| Refused(Refusal::Invalid))?,
                    seal: *current
                        .verified
                        .personal_publication()
                        .map_err(|_| Refused(Refusal::Invalid))?
                        .recovery_digest(),
                };
                if self
                    .inner
                    .store
                    .recovery_digests(&id.0)
                    .map_err(|_| Unavailable)?
                    != Some(required)
                {
                    return Err(Refused(Refusal::Invalid));
                }
            }
            delivery_body.or(attached_body)
        };
        let commitment = body.as_ref().map(BodyObject::commitment);
        let wrapped =
            account_log_wrap(&event, commitment).map_err(|_| Refused(Refusal::Invalid))?;
        if let Some(attachment) = &attachment
            && !self
                .inner
                .store
                .stage_attachment(&id.0, wrapped.digest(), attachment)
                .map_err(|_| Unavailable)?
        {
            return Err(Refused(Refusal::Invalid));
        }
        let batch = bh_crypto::random();
        let mut items = Vec::with_capacity(2);
        // A delivery body is staged under this permit; an attachment's
        // rotation body was staged before it was named.
        if let Some(body) = body.as_ref().filter(|_| attachment.is_none()) {
            let stage = Scope::Stage {
                log,
                body: body.commitment(),
                len: body.bytes().len() as u32,
            };
            items.push(Ok(self.inner.sign(stage, issued, batch, cap)));
        }
        let append = Scope::Append {
            log,
            event: wrapped.digest(),
            body: commitment,
            epoch: ACCOUNT_EPOCH,
            after: Some(current.head),
            attached: None,
        };
        items.push(Ok(self.inner.sign(append, issued, batch, cap)));
        if device.is_none() {
            self.recovery.as_mut().ok_or(Unavailable)?.event = Some(wrapped.digest());
        }
        Ok(FromService::Permits { items })
    }

    /// Verify the base genesis against the session account's history at the
    /// head it names, with M, before recording anything. The epoch content
    /// appends must carry is the genesis's content key id. Any controls the
    /// base's log already holds are replayed with M: this rebuilds a record
    /// the service lost.
    async fn register_base(
        &mut self,
        descriptor: Vec<u8>,
        body: Vec<u8>,
        creator_head: AccountHead,
        metadata: MetadataKey,
    ) -> Result<FromService, Failure> {
        let session = self
            .session
            .as_ref()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        let slot = self.inner.slot(session.account)?;
        let current = self.inner.current(&slot, session, true, &mut false).await?;
        let issued = current.issued;
        let descriptor =
            OpaqueEvent::decode(&descriptor).map_err(|_| Refused(Refusal::Malformed))?;
        let body = BodyObject::new(body).map_err(|_| Refused(Refusal::Malformed))?;
        // The creator's view at the head the request names, rebuilt from the
        // history this service verified; a head it never had chooses nothing.
        // That exact HOME pin is the BASE copy's one prefix.
        let (creator, home) = {
            let state = slot.lock().await;
            let account = state.at(&current)?;
            let creator = self
                .inner
                .view_at(
                    account,
                    session.account,
                    &session.genesis,
                    creator_head.position,
                )?
                .filter(|view| view.head() == creator_head)
                .ok_or(Refused(Refusal::Invalid))?;
            (creator, account.pin.ok_or(Unavailable)?)
        };
        let anchor = Pin {
            cut: creator_head,
            ..home
        };
        let base = BaseId::from_genesis(&descriptor);
        let genesis = Commitment::order(
            base,
            bh_sync::OrderState::EMPTY,
            &descriptor,
            Route::Control,
        )
        .map_err(|_| Refused(Refusal::Invalid))?;
        let (spine, verified) = ControlSpine::from_genesis(
            &creator,
            &descriptor,
            body.bytes(),
            metadata.expose(),
            self.inner.keys.root(),
            &genesis,
        )
        .map_err(|_| Refused(Refusal::Invalid))?;
        if verified.creator != session.account
            || verified.account_head != creator_head
            || referenced_body(&descriptor).ok() != Some(body.commitment())
        {
            return Err(Refused(Refusal::Invalid));
        }
        let log = LogId {
            kind: LogKind::Base,
            id: verified.base.0,
        };
        let start = spine.state().clone();
        let wanted = VerifiedBase {
            account: session.account.0,
            epoch: verified.content_key_id,
        };
        // Replay outside the lock into a fresh candidate generation. A replay
        // that does not pass through the durable checkpoint it began from, or
        // a durable projection changed while it ran, publishes nothing: it
        // replays again from the new state, bounded. The comparison,
        // conditional save and publication are one short locked section.
        let root = self.inner.keys.root();
        let mut attempts = 0;
        let cap = loop {
            self.inner.running(&log.id)?;
            let stored = match self
                .inner
                .store
                .base_snapshot(base)
                .map_err(|_| Unavailable)?
            {
                Some(Record::Legacy) => return Err(Refused(Refusal::Unsupported)),
                Some(Record::Canonical(stored)) => Some(stored),
                None => None,
            };
            let expected = stored.as_ref().map(|s| {
                let p = &s.projection;
                Prior::of(p.status, &p.state, p.pending.as_ref())
            });
            let previous = stored.as_ref().map(|s| s.pin);
            let accepted = stored
                .as_ref()
                .map(|s| &s.projection)
                .filter(|p| p.status == Status::Accepted)
                .map(|p| {
                    (
                        p.state.order,
                        p.state.control,
                        Digest(p.state.control_digest),
                    )
                });
            let mut candidate = self
                .inner
                .store
                .begin_candidate(
                    base,
                    anchor,
                    root,
                    &genesis,
                    &account_projection::capture(&creator),
                )
                .map_err(|_| Unavailable)?;
            // Cleaned however this attempt ends, its request cancelled too.
            let mut leftover = Leftover {
                inner: self.inner.clone(),
                pin: Some(candidate.pin),
            };
            let outcome = self
                .inner
                .publish_registration(
                    &slot,
                    &current,
                    session,
                    issued,
                    &mut candidate,
                    Registration {
                        log,
                        genesis: &genesis,
                        start: &start,
                        creator: &creator,
                        metadata: metadata.expose(),
                        wanted,
                        anchor,
                    },
                    stored.and_then(|s| s.projection.pending),
                    expected,
                    previous,
                    accepted,
                )
                .await;
            if matches!(outcome, Ok(Some(_))) {
                // Published: the generation it replaced is left instead.
                leftover.pin = previous;
            }
            leftover.clean().await;
            if let Some(cap) = outcome? {
                break cap;
            }
            attempts += 1;
            if attempts >= REGISTER_REPLAY_ATTEMPTS {
                return Err(Unavailable);
            }
        };
        drop(metadata);
        let batch = bh_crypto::random();
        let stage = Scope::Stage {
            log,
            body: body.commitment(),
            len: body.bytes().len() as u32,
        };
        let append = Scope::Append {
            log,
            event: descriptor.digest(),
            body: Some(body.commitment()),
            epoch: wanted.epoch,
            after: Some(Head::EMPTY),
            attached: None,
        };
        let answer = FromService::Permits {
            items: vec![
                Ok(self.inner.sign(stage, issued, batch, cap)),
                Ok(self.inner.sign(append, issued, batch, cap)),
            ],
        };
        self.inner.running(&log.id)?;
        Ok(answer)
    }

    /// Permit a base control after verifying it with M against the base's
    /// current control record: one pending control per base, ordered after
    /// the base's control head.
    async fn submit_base_control(
        &mut self,
        log: LogId,
        descriptor: Vec<u8>,
        body: Vec<u8>,
        metadata: MetadataKey,
    ) -> Result<FromService, Failure> {
        let session = self
            .session
            .as_ref()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        if !self.inner.owns(session, &log)? {
            return Err(Refused(Refusal::Unknown));
        }
        let slot = self.inner.slot(session.account)?;
        let current = self.inner.current(&slot, session, true, &mut false).await?;
        let confirmed = self
            .inner
            .confirm_base(&slot, session, log, true, true, &mut false)
            .await?
            .ok_or(Unavailable)?;
        let issued = current.issued.min(confirmed.start);
        let descriptor =
            OpaqueEvent::decode(&descriptor).map_err(|_| Refused(Refusal::Malformed))?;
        let body = BodyObject::new(body).map_err(|_| Refused(Refusal::Malformed))?;
        let mut guard = slot.lock().await;
        let account = guard.at_mut(&current)?;
        let cap = active_now(
            &account.verified,
            session.device,
            self.inner.clock.bounds_ms().map_err(|_| Unavailable)?,
        )?;
        self.inner.before_deadline(issued)?;
        let home = account.pin.ok_or(Unavailable)?;
        let record = account.bases.get_mut(&log.id).ok_or(Unavailable)?;
        if !record.current
            || record.status != Status::Accepted
            || record.controls() != confirmed.controls
        {
            return Err(Unavailable);
        }
        let state = record.spine.state();
        if referenced_body(&descriptor).ok() != Some(body.commitment())
            || key_id(metadata.expose()) != state.metadata_id
        {
            return Err(Refused(Refusal::Invalid));
        }
        let store = &self.inner.store;
        let pin = record.pin;
        let used = |id| {
            store
                .base_id_used(pin, id)
                .map_err(|_| Outcome::UnavailablePause)
        };
        let effect = match record.spine.check_submission(
            &record.view,
            &descriptor,
            body.bytes(),
            metadata.expose(),
            &used,
        ) {
            Ok(effect) => effect,
            Err(Outcome::IntegrityStop) => {
                if let Some(witness) = record.spine.seen_receipt_conflict(
                    &record.view,
                    &descriptor,
                    body.bytes(),
                    metadata.expose(),
                    None,
                    &used,
                ) {
                    store.stop_seen(witness, None).map_err(|_| Unavailable)?;
                    return Err(Refused(Refusal::Conflict));
                }
                return Err(Unavailable);
            }
            Err(Outcome::Rejected) => return Err(Refused(Refusal::Invalid)),
            Err(Outcome::UnsupportedPause) => return Err(Refused(Refusal::Unsupported)),
            Err(_) => return Err(Unavailable),
        };
        drop(metadata);
        // A copy carries the account's own ordered events after the base's
        // copy of the account, byte for byte.
        for (i, copy) in effect.account_copies.iter().enumerate() {
            let ordered = self
                .inner
                .store
                .account_event(&session.account.0, state.account.position + 1 + i as u64)
                .map_err(|_| Unavailable)?;
            if ordered.as_deref() != Some(copy.original.as_slice()) {
                return Err(Refused(Refusal::Invalid));
            }
        }
        if record
            .pending
            .as_ref()
            .is_some_and(|p| p.effect.digest != effect.digest)
        {
            return Err(Refused(Refusal::Conflict));
        }
        let after = state.control_head;
        let [stage, append] = control_permits(log, &descriptor, &body, &effect, after);
        let pending = Pending {
            event_id: descriptor.publication_id(Route::Control).0,
            after,
            deadline_ms: (issued + MAX_PERMIT_WINDOW_MS).min(cap.unwrap_or(u64::MAX)),
            effect,
        };
        // Durable before any permit exists, so a restart can confirm it, and
        // only over the record this check judged against.
        let prior = Prior::of(record.status, state, record.pending.as_ref());
        // A pending-only save: the BASE copy is unchanged, its pin rechecked.
        let write = base_write(
            &record.view,
            record.pin,
            record.anchor,
            state.hosting_root,
            state.order,
        );
        match self
            .inner
            .store
            .save_controls_if(
                None,
                record.status,
                state,
                Some(&pending),
                &[],
                Some(prior),
                &BaseWrite {
                    candidate: None,
                    previous: Some(record.pin),
                    projection: &write,
                    copies: &[],
                    anchor: record.anchor,
                    expected_home: home,
                },
            )
            .map_err(|_| Unavailable)?
        {
            Saved::Written => {}
            Saved::Stopped => return Err(Refused(Refusal::Conflict)),
            Saved::Changed | Saved::Conflict => return Err(Unavailable),
        }
        record.pending = Some(pending);
        let batch = bh_crypto::random();
        self.inner.running(&log.id)?;
        Ok(FromService::Permits {
            items: vec![
                Ok(self.inner.sign(stage, issued, batch, cap)),
                Ok(self.inner.sign(append, issued, batch, cap)),
            ],
        })
    }
}

/// The stage and append scopes for a checked base control ordered after
/// `after`: the append carries the epoch in effect once it is ordered (all
/// zero once closed) and, for a rekey, attaches the seal set its body
/// commits to, so the log keeps that set as long as the control's own body.
fn control_permits(
    log: LogId,
    descriptor: &OpaqueEvent,
    body: &BodyObject,
    effect: &bh_event::ControlEffect,
    after: Head,
) -> [Scope; 2] {
    [
        Scope::Stage {
            log,
            body: body.commitment(),
            len: body.bytes().len() as u32,
        },
        Scope::Append {
            log,
            event: descriptor.digest(),
            body: Some(body.commitment()),
            epoch: effect.epoch_after.unwrap_or([0; 32]),
            after: Some(after),
            attached: effect.seal_set,
        },
    ]
}

/// Effective membership is a time projection; it does not need a rotation
/// or a base-copy transaction to cut off a device at its deadline.
fn active_now(
    account: &VerifiedAccount,
    device: DeviceId,
    bounds: crate::Bounds,
) -> Result<Option<u64>, Failure> {
    match account
        .device_state(device, bounds.earliest_ms)
        .map_err(|error| account_failure(error, Refusal::NotActive))?
    {
        bh_account::DeviceState::Active => Ok(None),
        bh_account::DeviceState::RemovalPending { deadline_ms, .. } => Ok(Some(deadline_ms)),
        bh_account::DeviceState::Removed => Err(Refused(Refusal::NotActive)),
    }
}

/// The content-append membership rule, also used for event-free presence.
fn content_membership(
    session: &Session,
    account: &Account,
    log: LogId,
    epoch: [u8; 32],
) -> Result<(), Refusal> {
    let record = account.bases.get(&log.id).ok_or(Refusal::Resync)?;
    let state = record.spine.state();
    // The author writes as a member of the base's copy of the account,
    // under its open epoch, and only once the base has every account change:
    // a removal must close the epoch first.
    if record.view.active_device(session.device).is_err() {
        return Err(Refusal::NotActive);
    }
    if state.epoch != Some(epoch) {
        return Err(Refusal::Epoch);
    }
    if account.verified.head() != state.account {
        return Err(Refusal::AccountChangePending);
    }
    Ok(())
}

/// The padded body for a personal-key delivery on a device addition, once it
/// verifies: `candidate` is `predecessor` with the addition applied, and the
/// recipient must be exactly the device it introduces. The frame must be
/// signed by a device active before and after, sealed to that recipient under
/// the account's current publication. Nothing is opened.
fn admit_delivery(
    predecessor: &VerifiedAccount,
    candidate: &VerifiedAccount,
    delivery: &Delivery,
) -> Result<BodyObject, ()> {
    let recipient = &delivery.recipient;
    if predecessor.active_device(recipient.id()).is_ok()
        || candidate.active_device(recipient.id()).ok() != Some(recipient)
    {
        return Err(());
    }
    let sender =
        personal::verify_device_delivery(candidate, &delivery.frame, recipient).map_err(|_| ())?;
    match (
        predecessor.active_device(sender),
        candidate.active_device(sender),
    ) {
        (Ok(before), Ok(after)) if before == after => {}
        _ if predecessor.recovery_author().ok() == Some(sender)
            && candidate.recovery_author().ok() == Some(sender) => {}
        _ => return Err(()),
    }
    delivery_body(&delivery.frame).map_err(|_| ())
}

/// Judge attachment bytes against the authenticated transition, not an edge
/// claim. Raw rotation digests and padded transport commitments are separate.
fn admit_attachment(
    predecessor: &VerifiedAccount,
    candidate: &VerifiedAccount,
    event: &AccountEvent,
    attachment: Option<&Attachment>,
    bounds: bh_sync::evidence::TimeBounds,
) -> Result<Option<BodyObject>, ()> {
    match (event.change(), attachment) {
        (bh_account::AccountChange::RecoveryReplaced { .. }, Some(a))
            if a.rotation_body.is_none() && a.record.is_some() =>
        {
            let checks = bh_account::recovery::record_checks(a.record.as_ref().ok_or(())?)
                .map_err(|_| ())?;
            if checks.account != predecessor.id()
                || candidate.record_digest().map_err(|_| ())? != checks.digest
                || candidate
                    .personal_publication()
                    .map_err(|_| ())?
                    .recovery_digest()
                    != &personal::seal_digest(&a.recovery_seal)
            {
                return Err(());
            }
            Ok(None)
        }
        (bh_account::AccountChange::PersonalRotated { .. }, Some(a))
            if a.record.is_none() && a.rotation_body.is_some() =>
        {
            if candidate
                .personal_publication()
                .map_err(|_| ())?
                .recovery_digest()
                != &personal::seal_digest(&a.recovery_seal)
            {
                return Err(());
            }
            let raw = a.rotation_body.as_deref().ok_or(())?;
            personal::verify_rotation_body(&predecessor.advanced(bounds.earliest_ms), event, raw)
                .map_err(|_| ())?;
            rotation_body(raw).map(Some).map_err(|_| ())
        }
        (
            bh_account::AccountChange::RecoveryReplaced { .. }
            | bh_account::AccountChange::PersonalRotated { .. },
            _,
        ) => Err(()),
        (_, None) => Ok(None),
        (_, Some(_)) => Err(()),
    }
}

impl Inner {
    fn confirmation_bounds(
        &self,
        id: AccountId,
        position: u64,
    ) -> Result<bh_sync::evidence::TimeBounds, Failure> {
        let now = self.clock.bounds_ms().map_err(|_| Unavailable)?;
        let mut bounds =
            crate::confirm::clamp(now, self.store.time_floor(&id.0).map_err(|_| Unavailable)?);
        if let Some(bytes) = self
            .store
            .confirmation(&id.0, position)
            .map_err(|_| Unavailable)?
        {
            let confirmation =
                bh_sync::evidence::OrderingConfirmation::decode(&bytes).map_err(|_| Unavailable)?;
            let last = confirmation
                .verify(&self.keys.root())
                .map_err(|_| Unavailable)?
                .bounds;
            bounds.earliest_ms = bounds.earliest_ms.max(last.earliest_ms);
            bounds.latest_ms = bounds.latest_ms.max(last.latest_ms);
        }
        Ok(bounds)
    }

    // Called under the account lock: persist the observed floor before exposing it.
    fn accepted(&self, account: &Account, challenge: [u8; 32]) -> Result<Vec<u8>, Failure> {
        let id = account.verified.id();
        let bounds = self.confirmation_bounds(id, account.head.position)?;
        let confirmation = self
            .store
            .confirmation(&id.0, account.head.position)
            .map_err(|_| Unavailable)?;
        self.store
            .remember_time(&id.0, bounds)
            .map_err(|_| Unavailable)?;
        Ok(crate::confirm::accepted(
            &self.keys,
            account.log,
            challenge,
            &account.verified,
            confirmation.as_deref(),
            bounds,
        ))
    }

    fn running(&self, base: &[u8; 32]) -> Result<(), Failure> {
        self.store
            .while_running(&[*base], || ())
            .map_err(|_| Unavailable)?
            .ok_or(Refused(Refusal::Conflict))
    }

    fn stop_conflict(
        &self,
        log: LogId,
        root: [u8; 32],
        remembered: OrderState,
        observed: OrderState,
        receipt: Option<&[u8; 300]>,
        remembered_receipt: Option<&[u8; 300]>,
    ) -> Result<(), Failure> {
        let receipt = receipt.ok_or(Unavailable)?;
        self.store
            .stop(
                &log.id,
                root,
                remembered,
                observed,
                receipt,
                remembered_receipt,
            )
            .map_err(|_| Unavailable)?;
        Err(Refused(Refusal::Conflict))
    }

    /// A signed endpoint at a required control's GLOBAL position is a
    /// direct contradiction, irrespective of its raw-control position.
    /// This check runs immediately after receipt verification, before a
    /// missing forward raw path can be mistaken for the whole result.
    fn stop_at_control_position(
        &self,
        log: LogId,
        root: [u8; 32],
        raw: OrderState,
        accepted: (Head, Digest),
        endpoint: OrderState,
        receipt: Option<&[u8; 300]>,
    ) -> Result<(), Failure> {
        let observed = endpoint.head(BaseId(log.id));
        for (known, known_digest, known_order) in [
            (raw.head(BaseId(log.id)), None, Some(raw)),
            (accepted.0, Some(accepted.1), None),
        ] {
            if observed.position == known.position && observed != known {
                self.store
                    .stop_control(
                        BaseId(log.id),
                        root,
                        raw,
                        ControlConflict {
                            known,
                            observed,
                            known_digest,
                            observed_digest: None,
                            known_order,
                            observed_order: None,
                        },
                        endpoint,
                        receipt.ok_or(Unavailable)?,
                        None,
                    )
                    .map_err(|_| Unavailable)?;
                return Err(Refused(Refusal::Conflict));
            }
        }
        Ok(())
    }

    fn before_deadline(&self, issued: u64) -> Result<(), Failure> {
        let now = self.clock.now_ms().map_err(|_| Unavailable)?;
        if now
            >= issued
                .checked_add(MAX_PERMIT_WINDOW_MS)
                .ok_or(Unavailable)?
        {
            return Err(Unavailable);
        }
        Ok(())
    }

    /// This account's lock, from a bounded map: idle entries are dropped
    /// when it is full.
    fn slot(&self, account: AccountId) -> Result<Slot, Failure> {
        let mut map = self.accounts.lock().map_err(|_| Unavailable)?;
        if let Some(slot) = map.get(&account.0) {
            return Ok(slot.clone());
        }
        if map.len() >= CACHED_ACCOUNTS {
            map.retain(|_, slot| Arc::strong_count(slot) > 1);
            if map.len() >= CACHED_ACCOUNTS {
                return Err(Unavailable);
            }
        }
        let slot = Slot::default();
        map.insert(account.0, slot.clone());
        Ok(slot)
    }

    /// An attachment as the service judges it: a rotation's exact raw
    /// frame, read back from the account log by the commitment it names.
    /// Only a rotation names a body.
    async fn read_attachment(
        &self,
        log: LogId,
        event: &[u8],
        attachment: RecoveryAttachment,
    ) -> Result<Attachment, Failure> {
        let RecoveryAttachment {
            record,
            recovery_seal,
            rotation_body,
        } = attachment;
        let rotation_body = match rotation_body {
            None => None,
            Some(commitment)
                if AccountEvent::decode(event).is_ok_and(|event| {
                    matches!(
                        event.change(),
                        bh_account::AccountChange::PersonalRotated { .. }
                    )
                }) =>
            {
                Some(self.staged_rotation(log, commitment).await?)
            }
            Some(_) => return Err(Refused(Refusal::Invalid)),
        };
        Ok(Attachment {
            record,
            recovery_seal,
            rotation_body,
        })
    }

    /// The raw frame inside the one body staged on the account log under
    /// `commitment`, if it is a canonical rotation transport. Bytes the edge
    /// cannot serve, or that are not those the commitment names, are
    /// `Unavailable`: the device stages them again.
    async fn staged_rotation(&self, log: LogId, commitment: Digest) -> Result<Vec<u8>, Failure> {
        let now = self.clock.now_ms().map_err(|_| Unavailable)?;
        let permit = self.sign_uncapped(
            Scope::ReadBodies {
                log,
                bodies: vec![commitment],
            },
            now,
            bh_crypto::random(),
        );
        let read = self
            .edge
            .read_bodies(permit)
            .await
            .map_err(|_| Unavailable)?;
        let [bytes] = <[_; 1]>::try_from(read).map_err(|_| Unavailable)?;
        let body = BodyObject::new(bytes).map_err(|_| Unavailable)?;
        if body.commitment() != commitment {
            return Err(Unavailable);
        }
        rotation_frame(body.bytes())
            .map(<[u8]>::to_vec)
            .map_err(|_| Refused(Refusal::Invalid))
    }

    fn sign_uncapped(&self, scope: Scope, issued_ms: u64, batch: [u8; 16]) -> Vec<u8> {
        self.sign(scope, issued_ms, batch, None)
    }

    fn sign(&self, scope: Scope, issued_ms: u64, batch: [u8; 16], cap: Option<u64>) -> Vec<u8> {
        permit::sign(
            &self.keys.key,
            &self.keys.certificate,
            &Permit {
                scope,
                issued_ms,
                deadline_ms: (issued_ms + MAX_PERMIT_WINDOW_MS).min(cap.unwrap_or(u64::MAX)),
                batch,
            },
        )
    }

    /// Refresh, then require the session's device to be active now. Returns
    /// what the refresh verified; `older` as for `join_or_start`.
    async fn current(
        self: &Arc<Self>,
        slot: &Slot,
        session: &Session,
        fresh: bool,
        older: &mut bool,
    ) -> Result<Current, Failure> {
        let current = self
            .refresh(
                slot,
                session.account,
                session.log,
                &session.genesis,
                fresh,
                older,
            )
            .await?;
        let state = slot.lock().await;
        active_now(
            &state.at(&current)?.verified,
            session.device,
            self.clock.bounds_ms().map_err(|_| Unavailable)?,
        )?;
        Ok(current)
    }

    /// The account's head lookup, shared by its concurrent requests: one in
    /// flight is joined, never repeated. A failed one fails every request
    /// awaiting it.
    async fn refresh(
        self: &Arc<Self>,
        slot: &Slot,
        id: AccountId,
        log: LogId,
        genesis: &[u8],
        fresh: bool,
        older: &mut bool,
    ) -> Result<Current, Failure> {
        join_or_start(
            slot,
            fresh,
            older,
            |state| &mut state.refresh,
            |number| {
                let (inner, slot, genesis) = (self.clone(), slot.clone(), genesis.to_vec());
                async move {
                    let result = inner.read_account(&slot, id, log, &genesis).await;
                    let mut state = slot.lock().await;
                    if state.refresh.as_ref().is_some_and(|f| f.number == number) {
                        state.refresh = None;
                    }
                    result
                }
                .boxed()
            },
        )
        .await
    }

    /// The cached account, loaded if absent.
    fn loaded<'a>(
        &self,
        state: &'a mut SlotState,
        id: AccountId,
        log: LogId,
        genesis: &[u8],
    ) -> Result<&'a mut Account, Failure> {
        if state.account.is_none() {
            state.account = Some(self.load(id, log, genesis)?);
        }
        let account = state.account.as_mut().ok_or(Unavailable)?;
        if account.log != log {
            return Err(Refused(Refusal::Unauthenticated));
        }
        Ok(account)
    }

    /// Bring the account's verified view to the edge's head. Returns the time
    /// the lookup started and the heads it left. Verified bounded prefixes
    /// commit atomically. Failure issues nothing; a consumed failed candidate
    /// evicts only the cache, so the next request reloads the last durable
    /// verified prefix.
    async fn read_account(
        &self,
        slot: &Slot,
        id: AccountId,
        log: LogId,
        genesis: &[u8],
    ) -> Result<Current, Failure> {
        self.loaded(&mut *slot.lock().await, id, log, genesis)?;
        let issued = self.clock.now_ms().map_err(|_| Unavailable)?;
        loop {
            let (previous, opening) = {
                let state = slot.lock().await;
                let account = state.account.as_ref().ok_or(Unavailable)?;
                (account.head, account.opening)
            };
            let first = previous.position + 1;
            let now = self.clock.now_ms().map_err(|_| Unavailable)?;
            let read = self.sign_uncapped(
                Scope::ReadEvents {
                    log,
                    first,
                    last: first + READ_BATCH - 1,
                },
                now,
                bh_crypto::random(),
            );
            let items = self.edge.read_log(read).await.map_err(|_| Unavailable)?;
            if items.len() as u64 > READ_BATCH {
                return Err(Unavailable);
            }
            // The ordinary warm path never takes or clones the verified history.
            if items.is_empty() {
                break;
            }
            let full = items.len() as u64 == READ_BATCH;
            let mut head = previous;
            let mut order = opening;
            let mut events = Vec::with_capacity(items.len());
            let mut ordered = Vec::with_capacity(items.len());
            let mut ordered_states = Vec::with_capacity(items.len());
            for (commitment, event) in items {
                let commitment = Commitment::decode(&commitment).map_err(|_| Unavailable)?;
                let event = OpaqueEvent::decode(&event).map_err(|_| Unavailable)?;
                // Each entry continues the exact opening verified so far.
                if commitment.before() != order {
                    return Err(Unavailable);
                }
                head = commitment
                    .verify_next(BaseId(log.id), head)
                    .map_err(|_| Unavailable)?;
                order = commitment.after();
                commitment.verify_body(&event).map_err(|_| Unavailable)?;
                let (original, body) = account_log_unwrap(&event).map_err(|_| Unavailable)?;
                if head.position == 1 && original != genesis {
                    return Err(Unavailable);
                }
                ordered.push(head);
                ordered_states.push(order);
                events.push(StoredEvent {
                    original: original.to_vec(),
                    body,
                });
            }
            // Fetch attached rotation bodies before entering the account's
            // locked verification/transaction section. The edge's bytes are
            // checked against both the transport commitment and signed raw
            // publication below.
            let rotation_digests: Vec<_> = events
                .iter()
                .filter_map(|event| {
                    let decoded = AccountEvent::decode(&event.original).ok()?;
                    matches!(
                        decoded.change(),
                        bh_account::AccountChange::PersonalRotated { .. }
                    )
                    .then_some(event.body)
                    .flatten()
                })
                .collect();
            let rotation_bodies = if rotation_digests.is_empty() {
                Vec::new()
            } else {
                let now = self.clock.now_ms().map_err(|_| Unavailable)?;
                let permit = self.sign_uncapped(
                    Scope::ReadBodies {
                        log,
                        bodies: rotation_digests.clone(),
                    },
                    now,
                    bh_crypto::random(),
                );
                let read = self
                    .edge
                    .read_bodies(permit)
                    .await
                    .map_err(|_| Unavailable)?;
                if read.len() != rotation_digests.len() {
                    return Err(Unavailable);
                }
                read
            };
            // Move, do not clone, the account (including its base records).
            // No await between taking it and the atomic durable commit/publication.
            // Verification/storage failure drops the candidate, leaving None.
            let mut state = slot.lock().await;
            if state.account.as_ref().map(|a| (a.head, a.opening)) != Some((previous, opening)) {
                return Err(Unavailable);
            }
            let mut candidate = state.account.take().ok_or(Unavailable)?;
            let page_before = if previous == Head::EMPTY {
                ordered_states[0]
            } else {
                opening
            };
            candidate.page = Some(PendingHomePage {
                start: candidate.verified.clone(),
                before: page_before,
                entries: Vec::with_capacity(events.len()),
            });
            let mut snapshots = Vec::new();
            if previous == Head::EMPTY {
                snapshots.push(HistoricalSnapshot {
                    checkpoint: account_projection::capture(&candidate.verified),
                    opening: ordered_states[0],
                });
            }
            let mut applied = Vec::new();
            // Sample only after the edge has returned the original bytes. Never
            // re-sign stored entries, including those written by older versions.
            let bounds = self.confirmation_bounds(id, previous.position)?;
            let mut confirmations = Vec::new();
            let mut activations = Vec::new();
            let mut rotation_body_index = 0;
            for (event, ordered) in events
                .iter()
                .zip(&ordered)
                .skip(usize::from(previous == Head::EMPTY))
            {
                let decoded = AccountEvent::decode(&event.original).map_err(|_| Unavailable)?;
                let change = decoded.change();
                let attached_change = matches!(
                    change,
                    bh_account::AccountChange::RecoveryReplaced { .. }
                        | bh_account::AccountChange::PersonalRotated { .. }
                );
                let predecessor = attached_change.then(|| candidate.verified.clone());
                let prefix = if matches!(change, bh_account::AccountChange::RecoveryReplaced { .. })
                {
                    Some(
                        self.view_at(&candidate, id, genesis, 3)?
                            .ok_or(Unavailable)?
                            .head(),
                    )
                } else {
                    None
                };
                let (verified, bytes, outcome) = crate::confirm::apply(
                    &self.keys,
                    candidate.verified,
                    log,
                    event,
                    *ordered,
                    bounds,
                )
                .map_err(|_| Unavailable)?;
                let rotation_read =
                    if matches!(change, bh_account::AccountChange::PersonalRotated { .. })
                        && event.body.is_some()
                    {
                        let body = rotation_bodies
                            .get(rotation_body_index)
                            .ok_or(Unavailable)?;
                        rotation_body_index += 1;
                        Some(body.as_slice())
                    } else {
                        None
                    };
                if matches!(
                    change,
                    bh_account::AccountChange::RecoveryReplaced { .. }
                        | bh_account::AccountChange::PersonalRotated { .. }
                ) {
                    let wrapped =
                        account_log_wrap(&event.original, event.body).map_err(|_| Unavailable)?;
                    let attached = self
                        .store
                        .attachment(&id.0, wrapped.digest())
                        .map_err(|_| Unavailable)?
                        .ok_or(Unavailable)?;
                    let effect = if outcome == bh_account::ControlOutcome::Applied {
                        let predecessor = predecessor.as_ref().ok_or(Unavailable)?;
                        let body = admit_attachment(
                            predecessor,
                            &verified,
                            &decoded,
                            Some(&attached),
                            bounds,
                        )
                        .map_err(|_| Unavailable)?;
                        match change {
                            bh_account::AccountChange::RecoveryReplaced { .. } => {
                                Some(Activation::Replace {
                                    old: predecessor.record_digest().map_err(|_| Unavailable)?,
                                    record: attached.record.ok_or(Unavailable)?,
                                    seal: attached.recovery_seal,
                                    prefix: Digest(prefix.ok_or(Unavailable)?.hash),
                                })
                            }
                            bh_account::AccountChange::PersonalRotated { .. } => {
                                let actual = rotation_read.ok_or(Unavailable)?;
                                if body.as_ref().map(BodyObject::commitment) != event.body
                                    || bh_authz_proto::rotation_frame(actual)
                                        .map_err(|_| Unavailable)?
                                        != attached.rotation_body.as_deref().ok_or(Unavailable)?
                                    || BodyObject::new(actual.to_vec())
                                        .map_err(|_| Unavailable)?
                                        .commitment()
                                        != event.body.ok_or(Unavailable)?
                                {
                                    return Err(Unavailable);
                                }
                                Some(Activation::Rotate {
                                    seal: attached.recovery_seal,
                                })
                            }
                            _ => return Err(Unavailable),
                        }
                    } else {
                        None
                    };
                    activations.push((ordered.position, effect));
                }
                candidate.verified = verified;
                if outcome == bh_account::ControlOutcome::Applied
                    && let Some(digest) = event.body
                {
                    applied.push(AppliedBody {
                        position: ordered.position,
                        digest,
                    });
                }
                let event_index = (ordered.position - previous.position - 1) as usize;
                if ordered.position % 64 == 0 {
                    snapshots.push(HistoricalSnapshot {
                        checkpoint: account_projection::capture(&candidate.verified),
                        opening: ordered_states[event_index],
                    });
                }
                candidate
                    .page
                    .as_mut()
                    .ok_or(Unavailable)?
                    .entries
                    .push(HistoricalEntry {
                        position: ordered.position,
                        event: StoredEvent {
                            original: event.original.clone(),
                            body: event.body,
                        },
                        confirmation: Some(bytes.clone()),
                    });
                confirmations.push((ordered.position, bytes));
            }
            let generation = candidate.pin.map_or(1, |pin| pin.generation);
            let committed = candidate.verified.head();
            let write = ProjectionWrite {
                header: ProjectionHeader {
                    pin: Pin {
                        key: SourceKey {
                            account: id,
                            source: Source::Home(log),
                        },
                        generation,
                        cut: committed,
                    },
                    root: self.keys.root(),
                    opening: order,
                    prefix: None,
                },
                checkpoint: account_projection::capture(&candidate.verified),
                delta: account_projection::delta(&candidate.verified),
                snapshots,
            };
            let pin = self
                .store
                .extend_projected(
                    &id.0,
                    &log.id,
                    opening,
                    order,
                    &events,
                    ConfirmedPage {
                        confirmations: &confirmations,
                        activations: &activations,
                    },
                    &write,
                    &applied,
                )
                .map_err(|_| Unavailable)?;
            candidate.verified = account_projection::rebase(
                candidate.verified,
                committed,
                generation,
                self.store.history_index(pin),
            )
            .map_err(|_| Unavailable)?;
            let delta = account_projection::delta(&candidate.verified);
            if delta.expected != delta.through
                || !delta.added.is_empty()
                || !delta.removed.is_empty()
                || !delta.keys.is_empty()
            {
                return Err(Unavailable);
            }
            candidate.pin = Some(pin);
            candidate.page = None;
            candidate.head = head;
            candidate.opening = order;
            state.account = Some(candidate);
            if !full {
                break;
            }
        }
        // Retirement is best effort after the durable confirmation; a failed
        // network acknowledgement leaves its row for the next refresh.
        if let Some(prefix_digest) = self.store.retire_pending(&id.0).map_err(|_| Unavailable)? {
            let now = self.clock.now_ms().map_err(|_| Unavailable)?;
            let permit = self.sign_uncapped(
                Scope::RetireHomeObjects { log, prefix_digest },
                now,
                bh_crypto::random(),
            );
            if self.edge.retire_home_objects(permit).await.is_ok() {
                self.store
                    .retire_done(&id.0, prefix_digest)
                    .map_err(|_| Unavailable)?;
            }
        }
        let state = slot.lock().await;
        let account = state.account.as_ref().ok_or(Unavailable)?;
        Ok(Current {
            issued,
            outer: account.head,
            original: account.verified.head(),
        })
    }

    /// The stored view, or the genesis alone for an account the service has
    /// not yet seen on the edge.
    fn load(&self, id: AccountId, log: LogId, genesis: &[u8]) -> Result<Account, Failure> {
        let key = SourceKey {
            account: id,
            source: Source::Home(log),
        };
        let stored = self
            .store
            .current_projection(key)
            .map_err(|_| Unavailable)?;
        let Some(stored) = stored else {
            return Ok(Account {
                log,
                verified: VerifiedAccount::from_genesis(id, genesis)
                    .map_err(|_| Refused(Refusal::Unauthenticated))?,
                head: Head::EMPTY,
                opening: OrderState::EMPTY,
                pin: None,
                page: None,
                bases: HashMap::new(),
            });
        };
        let Record::Canonical(stored) = stored else {
            // Pre-projection canonical rows and older legacy scopes remain
            // intact but unsupported; never replay/backfill on open.
            return Err(Refused(Refusal::Unsupported));
        };
        let pin = stored.header.pin;
        let opening = stored.header.opening;
        let verified = self
            .store
            .restore_projection(stored, key, self.keys.root(), genesis)
            .map_err(|_| Unavailable)?;
        Ok(Account {
            log,
            verified,
            head: opening.head(BaseId(log.id)),
            opening,
            pin: Some(pin),
            page: None,
            bases: HashMap::new(),
        })
    }

    /// The verified view at `position`: the current one, or one rebuilt from
    /// the stored history before it. `None` for a position the account's
    /// verified history does not have.
    fn view_at(
        &self,
        current: &Account,
        id: AccountId,
        genesis: &[u8],
        position: u64,
    ) -> Result<Option<VerifiedAccount>, Failure> {
        let head = current.verified.head().position;
        if position == head {
            return Ok(Some(current.verified.clone()));
        }
        if position == 0 || position > head {
            return Ok(None);
        }
        // A caller examining the current uncommitted HOME page (notably a
        // replacement checking its signup prefix) uses only that bounded
        // candidate, never fabricated disk history.
        if let Some(page) = &current.page
            && position >= page.start.head().position
        {
            if position == page.start.head().position {
                return Ok(Some(page.start.clone()));
            }
            let entries: Vec<_> = page
                .entries
                .iter()
                .take_while(|e| e.position <= position)
                .map(|e| HistoricalEntry {
                    position: e.position,
                    event: StoredEvent {
                        original: e.event.original.clone(),
                        body: e.event.body,
                    },
                    confirmation: e.confirmation.clone(),
                })
                .collect();
            if entries.last().map(|e| e.position) != Some(position) {
                return Err(Unavailable);
            }
            let (view, _) = crate::confirm::replay_suffix(
                page.start.clone(),
                current.log,
                page.before,
                &entries,
                &self.keys.root(),
            )
            .map_err(|_| Unavailable)?;
            return Ok(Some(view));
        }
        let pin = current.pin.ok_or(Unavailable)?;
        if pin.key.account != id || pin.key.source != Source::Home(current.log) {
            return Err(Unavailable);
        }
        let snapshot = self
            .store
            .projection_at(pin, position)
            .map_err(|_| Unavailable)?;
        let before = snapshot.header.opening;
        let first = snapshot.header.pin.cut.position;
        let view = self
            .store
            .restore_projection(snapshot, pin.key, self.keys.root(), genesis)
            .map_err(|_| Unavailable)?;
        if first == position {
            return Ok(Some(view));
        }
        let entries = self
            .store
            .history_range(pin, first + 1, position)
            .map_err(|_| Unavailable)?;
        let (view, _) =
            crate::confirm::replay_suffix(view, current.log, before, &entries, &self.keys.root())
                .map_err(|_| Unavailable)?;
        Ok(Some(view))
    }
}

/// The BASE generation a registration attempt leaves: its own candidate
/// until that is published, then the generation it replaced. It is cleaned
/// in bounded batches on a blocking thread, under no lock: awaited before
/// the attempt returns, or left running when its request is cancelled. A
/// selected or stop-referenced one is kept; a failure leaves unreachable
/// rows.
struct Leftover {
    inner: Arc<Inner>,
    pin: Option<Pin>,
}

impl Leftover {
    /// Clean it before this request goes on, off the async worker.
    async fn clean(mut self) {
        if let Some(cleaning) = self.start() {
            let _ = cleaning.await;
        }
    }

    fn start(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        let pin = self.pin.take()?;
        let inner = self.inner.clone();
        inner.cleaning.send_modify(|n| *n += 1);
        let clean = move || {
            while let Ok(true) = inner.store.discard_generation(pin, 256) {}
            inner.cleaning.send_modify(|n| *n -= 1);
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => Some(runtime.spawn_blocking(clean)),
            Err(_) => {
                clean();
                None
            }
        }
    }
}

impl Drop for Leftover {
    fn drop(&mut self) {
        self.start();
    }
}

/// What one registration attempt replays and publishes.
struct Registration<'a> {
    log: LogId,
    genesis: &'a Commitment,
    /// The spine at the verified genesis.
    start: &'a bh_event::ControlState,
    /// The creator's exact HOME view at the head the genesis names.
    creator: &'a VerifiedAccount,
    metadata: &'a Secret<32>,
    wanted: VerifiedBase,
    anchor: Pin,
}

impl Inner {
    /// One registration attempt: replay the base's log into `candidate`, then
    /// publish that whole generation in the final conditional save.
    /// `Ok(None)`: the durable record moved meanwhile (or the replay did not
    /// pass through it); retry. Staging alone authorizes nothing.
    #[allow(clippy::too_many_arguments)]
    async fn publish_registration(
        &self,
        slot: &Slot,
        current: &Current,
        session: &Session,
        issued: u64,
        candidate: &mut Candidate,
        reg: Registration<'_>,
        pending: Option<Pending>,
        expected: Option<Prior>,
        previous: Option<Pin>,
        accepted: Option<(OrderState, Head, Digest)>,
    ) -> Result<Option<Option<u64>>, Failure> {
        let root = reg.start.hosting_root;
        let view = account_projection::rebase(
            reg.creator.clone(),
            reg.anchor.cut,
            candidate.pin.generation,
            self.store.history_index(candidate.pin),
        )
        .map_err(|_| Unavailable)?;
        let replayed = self
            .replay(
                reg.log,
                reg.genesis,
                ControlSpine::resume(reg.start.clone()),
                view.clone(),
                reg.metadata,
                accepted,
                candidate,
            )
            .await?;
        let mut state = slot.lock().await;
        let account = state.at_mut(current)?;
        let cap = active_now(
            &account.verified,
            session.device,
            self.clock.bounds_ms().map_err(|_| Unavailable)?,
        )?;
        self.before_deadline(issued)?;
        let home = account.pin.ok_or(Unavailable)?;
        let (status, spine, view) = match replayed {
            // Not ordered yet: the exact verified genesis stays provisional.
            // An accepted record is never demoted.
            None if accepted.is_some() => return Err(Unavailable),
            None => (
                Status::Provisional,
                ControlSpine::resume(reg.start.clone()),
                view,
            ),
            Some(replayed) if replayed.passed => (Status::Accepted, replayed.spine, replayed.view),
            // A delayed answer that does not pass through the durable
            // checkpoint would regress or contradict it.
            Some(_) => return Ok(None),
        };
        // A control this service permitted that can still follow the rebuilt
        // record stays pending, to be confirmed once ordered.
        let pending =
            pending.filter(|p| status == Status::Accepted && p.after == spine.state().control_head);
        let write = base_write(&view, candidate.pin, reg.anchor, root, spine.state().order);
        match self
            .store
            .save_controls_if(
                Some(reg.wanted),
                status,
                spine.state(),
                pending.as_ref(),
                &[],
                expected,
                &BaseWrite {
                    candidate: Some(candidate),
                    previous,
                    projection: &write,
                    copies: &[],
                    anchor: reg.anchor,
                    expected_home: home,
                },
            )
            .map_err(|_| Unavailable)?
        {
            Saved::Conflict | Saved::Stopped => Err(Refused(Refusal::Conflict)),
            Saved::Changed => Ok(None),
            Saved::Written => {
                account.bases.insert(
                    reg.log.id,
                    BaseRecord {
                        spine,
                        view,
                        pending,
                        status,
                        current: status == Status::Accepted,
                        pin: candidate.pin,
                        anchor: reg.anchor,
                    },
                );
                Ok(Some(cap))
            }
        }
    }

    /// Whether `log` is a base registered to the session's account.
    fn owns(&self, session: &Session, log: &LogId) -> Result<bool, Failure> {
        if log.kind != LogKind::Base {
            return Ok(false);
        }
        let owner = self.store.base(&log.id).map_err(|_| Unavailable)?;
        Ok(owner.is_some_and(|o| o.account == session.account.0))
    }

    /// Bring the base's control record up to its log, shared like the
    /// account's refresh: read its controls after the control head, confirm
    /// the pending one by its exact bytes, and drop a pending one that can no
    /// longer be ordered. A record read since it was loaded, with nothing
    /// pending, is current unless `force`: then `None`, with no read. A
    /// control the record cannot account for is `Resync`.
    async fn confirm_base(
        self: &Arc<Self>,
        slot: &Slot,
        session: &Session,
        log: LogId,
        force: bool,
        fresh: bool,
        older: &mut bool,
    ) -> Result<Option<Confirmed>, Failure> {
        {
            let mut state = slot.lock().await;
            let account =
                self.loaded(&mut state, session.account, session.log, &session.genesis)?;
            if let std::collections::hash_map::Entry::Vacant(entry) = account.bases.entry(log.id) {
                entry.insert(self.load_base(session, &log.id)?);
            }
            let record = account.bases.get(&log.id).ok_or(Unavailable)?;
            self.running(&log.id)?;
            if record.current && record.pending.is_none() && !force {
                return Ok(None);
            }
        }
        let base = log.id;
        join_or_start(
            slot,
            fresh,
            older,
            |state| state.confirms.entry(base).or_default(),
            |number| {
                let (inner, slot) = (self.clone(), slot.clone());
                async move {
                    let result = inner.confirm(&slot, log).await;
                    let mut state = slot.lock().await;
                    if state
                        .confirms
                        .get(&base)
                        .and_then(Option::as_ref)
                        .is_some_and(|f| f.number == number)
                    {
                        state.confirms.remove(&base);
                    }
                    result
                }
                .boxed()
            },
        )
        .await
        .map(Some)
    }

    /// A confirmation that fails leaves no record in memory: the next
    /// request reloads the durable one, which it never changed.
    /// Load the base's record, promoting a provisional one. An accepted one
    /// is not read: these grants rest on the base's registration alone.
    async fn accepted_base(
        self: &Arc<Self>,
        slot: &Slot,
        session: &Session,
        log: LogId,
        fresh: bool,
        older: &mut bool,
    ) -> Result<Option<Confirmed>, Failure> {
        {
            let mut state = slot.lock().await;
            let account =
                self.loaded(&mut state, session.account, session.log, &session.genesis)?;
            if let std::collections::hash_map::Entry::Vacant(entry) = account.bases.entry(log.id) {
                entry.insert(self.load_base(session, &log.id)?);
            }
            if account
                .bases
                .get(&log.id)
                .is_some_and(|r| r.status == Status::Accepted)
            {
                self.running(&log.id)?;
                return Ok(None);
            }
        }
        self.confirm_base(slot, session, log, false, fresh, older)
            .await
    }

    async fn confirm(&self, slot: &Slot, log: LogId) -> Result<Confirmed, Failure> {
        let result = self.confirm_covered(slot, log).await;
        if result.is_err()
            && let Some(account) = slot.lock().await.account.as_mut()
        {
            account.bases.remove(&log.id);
        }
        result
    }

    /// Read the base's controls after its raw checkpoint, up to one covered
    /// endpoint: the pending control's exact bytes are its only expected
    /// change. A provisional record reads from its genesis and is promoted
    /// once that exact genesis is covered. Saved conditionally on the record
    /// it began from, and only then published.
    async fn confirm_covered(&self, slot: &Slot, log: LogId) -> Result<Confirmed, Failure> {
        // A pending control is judged by a time before the read.
        let start = self.clock.now_ms().map_err(|_| Unavailable)?;
        self.running(&log.id)?;
        let (prior, root, accepted) = {
            let mut state = slot.lock().await;
            let record = state.base(&log.id)?;
            let spine = record.spine.state();
            (
                Prior::of(record.status, spine, record.pending.as_ref()),
                spine.hosting_root,
                (spine.control, Digest(spine.control_digest)),
            )
        };
        let provisional = prior.status == Status::Provisional;
        let after = if provisional {
            0
        } else {
            prior.order.raw_control().position
        };
        let mut scan = Scan::new(
            log,
            root,
            after,
            (!provisional).then_some((prior.order, accepted.0, accepted.1)),
        );
        // The record this confirmation builds, once a control changes it.
        let mut candidate: Option<(ControlSpine, VerifiedAccount)> = None;
        // The consumed effect's exact copies: the BASE copy's new suffix.
        let mut copies = Vec::new();
        let mut consumed = false;
        let mut observed_genesis = false;
        let mut ids = Vec::new();
        loop {
            let items = self.page(&mut scan).await?;
            if !provisional
                && let Some((endpoint, _)) = scan.endpoint
                && endpoint.raw_control().position == prior.order.raw_control().position
                && endpoint.raw_control() != prior.order.raw_control()
            {
                self.stop_conflict(
                    log,
                    root,
                    prior.order,
                    endpoint,
                    scan.receipt.as_ref(),
                    None,
                )?;
            }
            let mut state = slot.lock().await;
            let record = state.base(&log.id)?;
            if Prior::of(record.status, record.spine.state(), record.pending.as_ref()) != prior {
                return Err(Unavailable);
            }
            for (ordered, event) in items {
                if provisional {
                    // Its exact genesis, and nothing a re-registration has
                    // not judged with M.
                    if ordered.after() != prior.order {
                        return Err(Refused(Refusal::Resync));
                    }
                    observed_genesis = true;
                    ids.push((ordered.event_id().0, ordered.head().position));
                    continue;
                }
                let pending = record
                    .pending
                    .as_ref()
                    .filter(|p| {
                        !consumed
                            && p.event_id == event.publication_id(Route::Control).0
                            && p.effect.digest == event.digest()
                    })
                    .ok_or(Refused(Refusal::Resync))?;
                let (spine, view) =
                    candidate.get_or_insert_with(|| (record.spine.clone(), record.view.clone()));
                apply_copies(view, &pending.effect.account_copies, &root).map_err(|e| match e {
                    Outcome::UnavailablePause => Unavailable,
                    _ => Refused(Refusal::Resync),
                })?;
                spine
                    .apply(pending.effect.clone(), &ordered)
                    .map_err(|_| Refused(Refusal::Resync))?;
                copies.clone_from(&pending.effect.account_copies);
                consumed = true;
                ids.push((ordered.event_id().0, ordered.head().position));
            }
            let raw = candidate
                .as_ref()
                .map_or(prior.order, |(spine, _)| spine.state().order)
                .raw_control();
            drop(state);
            if !scan.more(raw)? {
                break;
            }
        }
        if provisional && !observed_genesis {
            return Err(Unavailable);
        }
        let (endpoint, authenticated) = scan.endpoint.ok_or(Unavailable)?;
        let mut state = slot.lock().await;
        let record = state.base(&log.id)?;
        if Prior::of(record.status, record.spine.state(), record.pending.as_ref()) != prior {
            return Err(Unavailable);
        }
        candidate
            .as_ref()
            .map_or(&record.spine, |(spine, _)| spine)
            .finish_coverage(endpoint, authenticated)
            .map_err(|_| Unavailable)?;
        #[cfg(feature = "synthetic-attestation")]
        let hold = self
            .before_base_publish
            .lock()
            .map_err(|_| Unavailable)?
            .clone();
        #[cfg(feature = "synthetic-attestation")]
        if let Some(hold) = hold {
            drop(state);
            hold(log).await;
            state = slot.lock().await;
            let record = state.base(&log.id)?;
            if Prior::of(record.status, record.spine.state(), record.pending.as_ref()) != prior {
                return Err(Unavailable);
            }
        }
        let home = state
            .account
            .as_ref()
            .and_then(|a| a.pin)
            .ok_or(Unavailable)?;
        let record = state.base(&log.id)?;
        let expired = record
            .pending
            .as_ref()
            .is_some_and(|p| start > p.deadline_ms + PENDING_GRACE_MS);
        let pending = if consumed || expired {
            None
        } else {
            record.pending.clone()
        };
        if candidate.is_some() || provisional || pending.is_none() != record.pending.is_none() {
            let (spine, view) = candidate
                .as_ref()
                .map_or((&record.spine, &record.view), |(spine, view)| (spine, view));
            let write = base_write(
                view,
                record.pin,
                record.anchor,
                spine.state().hosting_root,
                spine.state().order,
            );
            match self
                .store
                .save_controls_if(
                    None,
                    Status::Accepted,
                    spine.state(),
                    pending.as_ref(),
                    &ids,
                    Some(prior),
                    &BaseWrite {
                        candidate: None,
                        previous: Some(record.pin),
                        projection: &write,
                        copies: &copies,
                        anchor: record.anchor,
                        expected_home: home,
                    },
                )
                .map_err(|_| Unavailable)?
            {
                Saved::Written => {}
                Saved::Stopped => return Err(Refused(Refusal::Conflict)),
                Saved::Changed | Saved::Conflict => return Err(Unavailable),
            }
            // Committed: rebase onto the new cut before publishing it.
            let pin = write.header.pin;
            if let Some((spine, view)) = candidate {
                record.view = account_projection::rebase(
                    view,
                    pin.cut,
                    pin.generation,
                    self.store.history_index(pin),
                )
                .map_err(|_| Unavailable)?;
                record.spine = spine;
            }
            record.pin = pin;
            record.pending = pending;
            record.status = Status::Accepted;
        }
        self.running(&log.id)?;
        record.current = true;
        Ok(Confirmed {
            start,
            controls: record.controls(),
        })
    }

    /// The next page of `scan`'s controls. Its first page fixes the
    /// endpoint; every later one is bounded by and must name it.
    async fn page(&self, scan: &mut Scan) -> Result<Vec<(Commitment, OpaqueEvent)>, Failure> {
        let through = scan.endpoint.map(|(endpoint, _)| endpoint.position());
        let page = self
            .read_controls(
                scan.log,
                scan.root,
                scan.after,
                through,
                scan.endpoint,
                scan.receipt.as_ref(),
                scan.required,
            )
            .await?;
        match scan.endpoint {
            None => {
                scan.endpoint = Some(page.endpoint);
                scan.receipt = page.receipt;
            }
            Some(frozen) if frozen != page.endpoint => return Err(Unavailable),
            Some(_) => {}
        }
        scan.full = page.items.len() as u64 == READ_BATCH;
        if let Some((last, _)) = page.items.last() {
            scan.after = last.head().position;
        }
        Ok(page.items)
    }

    /// Up to `READ_BATCH` control-route events after `after`, each checked
    /// against its commitment, and the endpoint they were read against:
    /// the current one, or exactly `through`. Its receipt must verify under
    /// `root`, the base's pinned hosting root, for the head its opening
    /// derives; only an empty log has none.
    #[allow(clippy::too_many_arguments)] // The scan's pinned root, endpoint and remembered facts.
    async fn read_controls(
        &self,
        log: LogId,
        root: [u8; 32],
        after: u64,
        through: Option<u64>,
        frozen: Option<(OrderState, Head)>,
        old_receipt: Option<&[u8; 300]>,
        required: Option<(OrderState, Head, Digest)>,
    ) -> Result<ControlPage, Failure> {
        let now = self.clock.now_ms().map_err(|_| Unavailable)?;
        let scope = match through {
            None => Scope::ReadControls { log, after },
            Some(through) => Scope::ReadControlRange {
                log,
                after,
                through,
            },
        };
        let read = self.sign_uncapped(scope, now, bh_crypto::random());
        let read = self
            .edge
            .read_log_with_receipt(read)
            .await
            .map_err(|_| Unavailable)?;
        let coverage = read.coverage.ok_or(Unavailable)?;
        let base = BaseId(log.id);
        let authenticated = match coverage.receipt.as_ref() {
            Some(bytes) => receipt::verify(&root, base, bytes)
                .map_err(|_| Unavailable)?
                .head(),
            None => Head::EMPTY,
        };
        let endpoint = coverage.order;
        if endpoint.head(base) != authenticated
            || through.is_some_and(|through| through != endpoint.position())
        {
            return Err(Unavailable);
        }
        if let Some((raw, accepted, digest)) = required {
            self.stop_at_control_position(
                log,
                root,
                raw,
                (accepted, digest),
                endpoint,
                coverage.receipt.as_ref(),
            )?;
        }
        if read.items.len() as u64 > READ_BATCH || read.receipt.is_some() {
            return Err(Unavailable);
        }
        // The two rooted endpoint statements conflict regardless of whether
        // untrusted raw item bytes in this page can be decoded.
        if let Some((prior, _)) = frozen
            && endpoint.position() == prior.position()
            && endpoint != prior
        {
            self.stop_conflict(
                log,
                root,
                prior,
                endpoint,
                coverage.receipt.as_ref(),
                old_receipt,
            )?;
        }
        let items = read
            .items
            .iter()
            .map(|(commitment, event)| {
                let commitment = Commitment::decode(commitment).map_err(|_| Unavailable)?;
                let event = OpaqueEvent::decode(event).map_err(|_| Unavailable)?;
                commitment.verify_body(&event).map_err(|_| Unavailable)?;
                let position = commitment.head().position;
                if commitment.base() != base
                    || commitment.route() != Route::Control
                    || position <= after
                    || position > endpoint.position()
                {
                    return Err(Unavailable);
                }
                Ok((commitment, event))
            })
            .collect::<Result<_, _>>()?;
        Ok(ControlPage {
            items,
            endpoint: (endpoint, authenticated),
            receipt: coverage.receipt,
        })
    }

    /// The stored record, with the base's copy of the account restored from
    /// its own indexed checkpoint over its one pinned HOME prefix: no copy is
    /// read or replayed, and nothing of HOME's history before it. Without a
    /// usable record the device must resync; one recorded before canonical
    /// order, or before BASE copies, pauses this base alone.
    fn load_base(&self, session: &Session, base: &[u8; 32]) -> Result<BaseRecord, Failure> {
        let resync = Refused(Refusal::Resync);
        self.running(base)?;
        let snapshot = match self
            .store
            .base_snapshot(BaseId(*base))
            .map_err(|_| Unavailable)?
        {
            None => return Err(resync),
            Some(Record::Legacy) => return Err(Refused(Refusal::Unsupported)),
            Some(Record::Canonical(snapshot)) => snapshot,
        };
        let state = snapshot.projection.state;
        if state.creator != session.account {
            return Err(resync);
        }
        let key = snapshot.pin.key;
        let stored = match self
            .store
            .current_projection(key)
            .map_err(|_| Unavailable)?
        {
            Some(Record::Canonical(stored))
                if stored.header.pin == snapshot.pin
                    && stored.header.prefix == Some(snapshot.anchor) =>
            {
                stored
            }
            _ => return Err(Unavailable),
        };
        let view = self
            .store
            .restore_projection(stored, key, state.hosting_root, &session.genesis)
            .map_err(|_| Unavailable)?;
        if view.head() != state.account {
            return Err(Unavailable);
        }
        Ok(BaseRecord {
            spine: ControlSpine::resume(state),
            view,
            pending: snapshot.projection.pending,
            status: snapshot.projection.status,
            current: false,
            pin: snapshot.pin,
            anchor: snapshot.anchor,
        })
    }

    /// Follow the base's ordered controls from its genesis with M, judging
    /// each as devices do, to one covered endpoint, staging every raw
    /// control, its routed first use and each effect's copies into
    /// `candidate` as it goes. None while the log is empty. Holds one network
    /// page and one effect's copies, never the base's history. Returns the
    /// spine, the base's copy of the account after them (rebased onto the
    /// candidate), and whether the replay passed through `through`, a
    /// remembered raw checkpoint (always when none).
    #[allow(clippy::too_many_arguments)] // The replay's inputs plus its candidate.
    async fn replay(
        &self,
        log: LogId,
        genesis: &Commitment,
        mut spine: ControlSpine,
        mut view: VerifiedAccount,
        metadata: &Secret<32>,
        through: Option<(OrderState, Head, Digest)>,
        candidate: &mut Candidate,
    ) -> Result<Option<Replayed>, Failure> {
        let root = spine.state().hosting_root;
        let mut scan = Scan::new(log, root, 0, through);
        let mut passed = through.is_none_or(|(order, _, _)| order == spine.state().order);
        let mut conflict: Option<ControlConflict> = None;
        let mut seen_witness: Option<SeenReceiptConflict> = None;
        let mut first = true;
        // Verified raw controls not yet staged: at most this page's.
        let mut batch: Vec<Commitment> = Vec::new();
        loop {
            let items = self.page(&mut scan).await?;
            let mut items = items.iter();
            if std::mem::take(&mut first) {
                // The log's first control is this genesis, or it is empty.
                match items.next() {
                    None if scan.endpoint == Some((OrderState::EMPTY, Head::EMPTY)) => {
                        return Ok(None);
                    }
                    Some((ordered, _)) if ordered == genesis => batch.push(*genesis),
                    _ => return Err(Unavailable),
                }
            }
            let later: Vec<_> = items.collect();
            // Normal replay fetches one batch. If it is incomplete, a
            // bounded per-item fallback can still verify an early rooted
            // witness without requiring bodies *after* that witness.
            let bodies = if seen_witness.is_none() {
                self.read_bodies(log, &later).await.ok()
            } else {
                None
            };
            for (index, item) in later.into_iter().enumerate() {
                let (ordered, event) = item;
                if seen_witness.is_some() {
                    spine.apply_rejected(ordered).map_err(|_| Unavailable)?;
                    batch.push(*ordered);
                    continue;
                }
                let fallback;
                let body = if let Some(body) = bodies.as_ref().and_then(|all| all.get(index)) {
                    body
                } else {
                    fallback = self
                        .read_bodies(log, &[item])
                        .await?
                        .into_iter()
                        .next()
                        .ok_or(Unavailable)?;
                    &fallback
                };
                // First uses before this control: the candidate's staged
                // prefix, then this page's unstaged ones.
                let unstaged = &batch;
                let stage = &*candidate;
                let store = &self.store;
                let position = ordered.head().position;
                let used_before = |id: bh_sync::EventId| {
                    if unstaged.iter().any(|c| c.event_id() == id) {
                        return Ok(true);
                    }
                    store
                        .candidate_id_used(stage, position, id)
                        .map_err(|_| Outcome::UnavailablePause)
                };
                let checked = spine.check(&view, event, body, metadata, ordered, &used_before);
                match checked {
                    Ok(mut effect) => {
                        let copies = std::mem::take(&mut effect.account_copies);
                        apply_copies(&mut view, &copies, &root).map_err(|_| Unavailable)?;
                        spine.apply(effect, ordered).map_err(|_| Unavailable)?;
                        batch.push(*ordered);
                        // One effect's copies with the raw controls before it,
                        // then the view rebases: its suffix stays one effect.
                        let write = base_write(
                            &view,
                            candidate.pin,
                            candidate.prefix,
                            root,
                            spine.state().order,
                        );
                        candidate.pin = self
                            .store
                            .stage_candidate(candidate, spine.state(), &copies, &write, &batch)
                            .map_err(|_| Unavailable)?;
                        batch.clear();
                        view = account_projection::rebase(
                            view,
                            candidate.pin.cut,
                            candidate.pin.generation,
                            self.store.history_index(candidate.pin),
                        )
                        .map_err(|_| Unavailable)?;
                    }
                    Err(Outcome::Rejected) => {
                        spine.apply_rejected(ordered).map_err(|_| Unavailable)?;
                        batch.push(*ordered);
                    }
                    Err(Outcome::IntegrityStop) => {
                        let Some(witness) = spine.seen_receipt_conflict(
                            &view,
                            event,
                            body,
                            metadata,
                            Some(ordered),
                            &used_before,
                        ) else {
                            return Err(Unavailable);
                        };
                        seen_witness = Some(witness);
                        spine.apply_rejected(ordered).map_err(|_| Unavailable)?;
                        batch.push(*ordered);
                    }
                    Err(Outcome::UnsupportedPause) => {
                        return Err(Refused(Refusal::Unsupported));
                    }
                    Err(_) => return Err(Unavailable),
                }
                if let Some((order, accepted, digest)) = through {
                    if ordered.head().position == accepted.position
                        && (ordered.head() != accepted || ordered.event_digest() != digest)
                    {
                        conflict.get_or_insert(ControlConflict {
                            known: accepted,
                            observed: ordered.head(),
                            known_digest: Some(digest),
                            observed_digest: Some(ordered.event_digest()),
                            known_order: None,
                            observed_order: None,
                        });
                    }
                    if ordered.head().position == order.position() && ordered.after() != order {
                        conflict.get_or_insert(ControlConflict {
                            known: order.head(BaseId(log.id)),
                            observed: ordered.head(),
                            known_digest: None,
                            observed_digest: None,
                            known_order: Some(order),
                            observed_order: Some(ordered.after()),
                        });
                    }
                    passed |= order == spine.state().order;
                }
            }
            // The page's remaining raw controls (rejected, or streamed after
            // a rooted witness) hold their place in the candidate.
            if !batch.is_empty() {
                let write = base_write(
                    &view,
                    candidate.pin,
                    candidate.prefix,
                    root,
                    spine.state().order,
                );
                candidate.pin = self
                    .store
                    .stage_candidate(candidate, spine.state(), &[], &write, &batch)
                    .map_err(|_| Unavailable)?;
                batch.clear();
            }
            if !scan.more(spine.state().order.raw_control())? {
                break;
            }
        }
        let (endpoint, authenticated) = scan.endpoint.ok_or(Unavailable)?;
        spine
            .finish_coverage(endpoint, authenticated)
            .map_err(|_| Unavailable)?;
        if let Some(witness) = seen_witness {
            let proof = scan.receipt.as_ref().ok_or(Unavailable)?;
            self.store
                .stop_seen(witness, Some((endpoint, proof, &*candidate)))
                .map_err(|_| Unavailable)?;
            return Err(Refused(Refusal::Conflict));
        }
        if let Some((prior, _, _)) = through {
            if let Some(conflict) = conflict {
                self.store
                    .stop_control(
                        BaseId(log.id),
                        root,
                        prior,
                        conflict,
                        endpoint,
                        scan.receipt.as_ref().ok_or(Unavailable)?,
                        Some(&*candidate),
                    )
                    .map_err(|_| Unavailable)?;
                return Err(Refused(Refusal::Conflict));
            }
            if endpoint.raw_control().position == prior.raw_control().position
                && endpoint.raw_control() != prior.raw_control()
            {
                self.stop_conflict(log, root, prior, endpoint, scan.receipt.as_ref(), None)?;
            }
        }
        #[cfg(feature = "synthetic-attestation")]
        let hold = self
            .before_base_publish
            .lock()
            .map_err(|_| Unavailable)?
            .clone();
        #[cfg(feature = "synthetic-attestation")]
        if let Some(hold) = hold {
            hold(log).await;
        }
        Ok(Some(Replayed {
            spine,
            view,
            passed,
        }))
    }

    /// The bodies the events reference, in order.
    async fn read_bodies(
        &self,
        log: LogId,
        events: &[&(Commitment, OpaqueEvent)],
    ) -> Result<Vec<Vec<u8>>, Failure> {
        if events.is_empty() {
            return Ok(vec![]);
        }
        let bodies = events
            .iter()
            .map(|(_, event)| referenced_body(event))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Unavailable)?;
        let now = self.clock.now_ms().map_err(|_| Unavailable)?;
        let read = self.sign_uncapped(
            Scope::ReadBodies {
                log,
                bodies: bodies.clone(),
            },
            now,
            bh_crypto::random(),
        );
        let read = self.edge.read_bodies(read).await.map_err(|_| Unavailable)?;
        if read.len() != bodies.len() {
            return Err(Unavailable);
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::{DevicePublicKeys, RecoveryPublicKeys};
    use bh_crypto::{KemKey, SigningKey};
    use bh_event::{ControlChange, ControlEffect, ControlState};

    fn effect(
        change: ControlChange,
        epoch: Option<[u8; 32]>,
        seal_set: Option<Digest>,
    ) -> ControlEffect {
        ControlEffect {
            digest: Digest([1; 32]),
            epoch_after: epoch,
            account_head_after: AccountHead {
                position: 5,
                hash: [2; 32],
            },
            change,
            account_copies: vec![],
            seal_set,
            floor_after: 2,
            seen_position: 3,
            judged_control_digest: [4; 32],
            judged_account_head: AccountHead {
                position: 4,
                hash: [5; 32],
            },
        }
    }

    fn base_control() -> (LogId, OpaqueEvent, BodyObject, Head) {
        let body = BodyObject::new(vec![6; 1024]).unwrap();
        let mut envelope = body.commitment().0.to_vec();
        envelope.resize(1024, 7);
        let descriptor = OpaqueEvent::new(bh_sync::EventId([8; 32]), envelope).unwrap();
        let log = LogId {
            kind: LogKind::Base,
            id: [9; 32],
        };
        let after = Head {
            position: 10,
            hash: Digest([11; 32]),
        };
        (log, descriptor, body, after)
    }

    #[test]
    fn rekey_permit_opens_the_new_epoch() {
        let (log, descriptor, body, after) = base_control();
        let set = Digest([12; 32]);
        let [stage, append] = control_permits(
            log,
            &descriptor,
            &body,
            &effect(ControlChange::Rekey, Some([13; 32]), Some(set)),
            after,
        );
        assert!(
            stage
                == Scope::Stage {
                    log,
                    body: body.commitment(),
                    len: 1024,
                }
        );
        // The append reopens the log under the new key and orders the seal
        // set the rekey's body commits to with it.
        assert!(
            append
                == Scope::Append {
                    log,
                    event: descriptor.digest(),
                    body: Some(body.commitment()),
                    epoch: [13; 32],
                    after: Some(after),
                    attached: Some(set),
                }
        );
        // Any other control attaches nothing; a removal closes the epoch.
        let [_, append] = control_permits(
            log,
            &descriptor,
            &body,
            &effect(ControlChange::AccountRun, None, None),
            after,
        );
        let Scope::Append {
            epoch, attached, ..
        } = append
        else {
            panic!("append")
        };
        assert_eq!((epoch, attached), ([0; 32], None));
    }

    #[test]
    fn content_under_the_old_epoch_is_refused_after_rekey() {
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let device = keys.id();
        let request = AccountEvent::genesis(
            keys,
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
        );
        let genesis = request
            .finish(control.sign(request.signing_bytes()))
            .unwrap();
        let id = AccountId::of_genesis(&genesis).unwrap();
        let verified = VerifiedAccount::from_genesis(id, genesis.as_bytes()).unwrap();
        let (log, ..) = base_control();
        let (old, new) = ([14; 32], [15; 32]);
        let mut state = ControlState {
            base: BaseId(log.id),
            creator: id,
            hosting_root: [16; 32],
            metadata_id: [17; 32],
            epoch: Some(old),
            floor: 2,
            control: Head::EMPTY,
            control_digest: [0; 32],
            control_head: Head::EMPTY,
            order: OrderState::EMPTY,
            account: verified.head(),
        };
        let account = |state: &ControlState| Account {
            log: LogId {
                kind: LogKind::Account,
                id: [18; 32],
            },
            verified: verified.clone(),
            head: Head::EMPTY,
            opening: OrderState::EMPTY,
            pin: None,
            page: None,
            bases: HashMap::from([(
                log.id,
                BaseRecord {
                    spine: ControlSpine::resume(state.clone()),
                    view: verified.clone(),
                    pending: None,
                    status: Status::Accepted,
                    current: true,
                    pin: Pin {
                        key: SourceKey {
                            account: id,
                            source: Source::Base(BaseId(log.id)),
                        },
                        generation: 1,
                        cut: verified.head(),
                    },
                    anchor: Pin {
                        key: SourceKey {
                            account: id,
                            source: Source::Home(LogId {
                                kind: LogKind::Account,
                                id: [18; 32],
                            }),
                        },
                        generation: 1,
                        cut: verified.head(),
                    },
                },
            )]),
        };
        let session = Session {
            account: id,
            device,
            log: LogId {
                kind: LogKind::Account,
                id: [18; 32],
            },
            genesis: genesis.as_bytes().to_vec(),
        };
        assert_eq!(
            content_membership(&session, &account(&state), log, old),
            Ok(())
        );
        // A rekey's effect applied: the old epoch is refused, the new taken.
        state.epoch = Some(new);
        let after = account(&state);
        assert_eq!(
            content_membership(&session, &after, log, old),
            Err(Refusal::Epoch)
        );
        assert_eq!(content_membership(&session, &after, log, new), Ok(()));
    }
}
