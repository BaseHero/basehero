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
use crate::{
    Clock, EdgeReader, PermitKeys, ServiceError,
    store::{Pending, Store, StoredEvent, VerifiedBase},
};
use bh_account::{
    AccountEvent, AccountId, DeviceId, Error as AccountError, Head as AccountHead, VerifiedAccount,
    device_auth::{self, Context, PROOF_LEN},
    personal,
};
use bh_authz_proto::{
    ACCOUNT_EPOCH, Delivery, FromService, LogId, LogKind, MetadataKey, ReadBatchResult, Refusal,
    ToService, Want, account_log_id, account_log_unwrap, account_log_wrap, delivery_body,
};
use bh_crypto::Secret;
use bh_event::{ControlSpine, Outcome, key_id};
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, Head, OpaqueEvent, Route,
    permit::{self, MAX_PERMIT_WINDOW_MS, Permit, Scope},
    receipt, referenced_body,
};
use futures_util::future::{BoxFuture, FutureExt, WeakShared};
use std::{
    collections::{HashMap, HashSet},
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
    bodies: HashSet<Digest>,
    bases: HashMap<[u8; 32], BaseRecord>,
}

/// One base's control record in memory.
struct BaseRecord {
    spine: ControlSpine,
    /// The base's copy of the account, at the spine's account head. Kept as
    /// controls apply, never rebuilt per permit.
    view: VerifiedAccount,
    pending: Option<Pending>,
    /// Its controls were read from the log since it was loaded.
    current: bool,
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

struct Inner {
    store: Store,
    keys: PermitKeys,
    clock: Arc<dyn Clock>,
    edge: Arc<dyn EdgeReader>,
    accounts: Mutex<HashMap<[u8; 32], Slot>>,
    #[cfg(feature = "synthetic-attestation")]
    observer: Mutex<Option<Observer>>,
}

/// Test-only: called with each decoded request a connection handles.
#[cfg(feature = "synthetic-attestation")]
pub type Observer = Arc<dyn Fn(&ToService) + Send + Sync>;

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

impl Service {
    pub fn open(
        path: &Path,
        keys: PermitKeys,
        clock: Arc<dyn Clock>,
        edge: Arc<dyn EdgeReader>,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            inner: Arc::new(Inner {
                store: Store::open(path)?,
                keys,
                clock,
                edge,
                accounts: Mutex::new(HashMap::new()),
                #[cfg(feature = "synthetic-attestation")]
                observer: Mutex::new(None),
            }),
        })
    }

    /// Test-only: show every decoded request to `observer`, before it is
    /// handled.
    #[cfg(feature = "synthetic-attestation")]
    pub fn observe(&self, observer: Observer) {
        *self.inner.observer.lock().expect("observer") = Some(observer);
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
                session: None,
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

/// One device connection's application protocol.
pub struct Connection {
    inner: Arc<Inner>,
    binding: [u8; 32],
    challenge: Option<[u8; 32]>,
    session: Option<Session>,
}
impl Connection {
    /// Whether a device has authenticated on this connection.
    pub fn authenticated(&self) -> bool {
        self.session.is_some()
    }

    pub async fn handle(&mut self, message: ToService) -> FromService {
        #[cfg(feature = "synthetic-attestation")]
        if let Some(observer) = self.inner.observer.lock().expect("observer").clone() {
            observer(&message);
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
            } => self.submit_control(log, event, delivery).await,
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
            _ => return Err(Refused(Refusal::Unauthenticated)),
        }
        if current.verified.active_device(device).is_err() {
            return Err(Refused(Refusal::NotActive));
        }
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
        );
        // No private bytes or success marker enter Store. The immutable write
        // uses the fixed permission outside this account's lock.
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
        Ok(FromService::HomeObjectsStored {
            prefix,
            digest: bundle_digest.0,
        })
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
            let read = self.inner.sign(
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
        let mut invalid = fetched.items.len() > usize::from(max_events);
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
        if account.verified.active_device(session.device).is_err() {
            return Err(Refused(Refusal::NotActive));
        }
        if own_account {
            if bodies.iter().any(|body| !account.bodies.contains(body)) {
                return Err(Unavailable);
            }
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
            .ok_or(Unavailable)?;
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
                ),
            },
        };
        if invalid {
            let answer = repair();
            self.inner.before_deadline(issued)?;
            return Ok(answer);
        }
        let body_permit = (!bodies.is_empty()).then(|| {
            self.inner.sign(
                Scope::ReadBodies { log, bodies },
                issued,
                bh_crypto::random(),
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
        for item in items {
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
        if account.verified.active_device(session.device).is_err() {
            return Err(Refused(Refusal::NotActive));
        }
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
                _ => None,
            };
            let answer = match refused {
                Some(reason) => Err(reason),
                None => self.scope(session, account, item)?,
            };
            answers.push(answer.map(|scope| self.inner.sign(scope, issued, batch)));
        }
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
            | Want::ReadBodies { log, .. }
            | Want::Stage { log, .. }
            | Want::Append { log, .. }
            | Want::Subscribe { log }
            | Want::Presence { log, .. }
            | Want::ReadBatch { log, .. } => *log,
        };
        if log == session.log {
            // The account log is read and watched; it changes only through
            // verified controls. Its only readable bodies are those its
            // ordered, verified events carry.
            return Ok(match item {
                &Want::ReadEvents { first, last, .. } => Ok(Scope::ReadEvents { log, first, last }),
                Want::Subscribe { .. } => Ok(Scope::Subscribe { log }),
                Want::ReadBodies { bodies, .. }
                    if bodies.iter().all(|b| account.bodies.contains(b)) =>
                {
                    Ok(Scope::ReadBodies {
                        log,
                        bodies: bodies.clone(),
                    })
                }
                Want::ReadBodies { .. } => Err(Refusal::Unknown),
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
            Want::ReadBatch { .. } => Err(Refusal::Unsupported),
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
                })
            })(),
        })
    }

    async fn submit_control(
        &mut self,
        log: LogId,
        event: Vec<u8>,
        delivery: Option<Box<Delivery>>,
    ) -> Result<FromService, Failure> {
        let session = self
            .session
            .as_ref()
            .ok_or(Refused(Refusal::Unauthenticated))?;
        // Base controls (epoch closure, members) are not supported yet; they
        // are never taken for content.
        if log.kind == LogKind::Base {
            return Err(Refused(Refusal::Unsupported));
        }
        if log != session.log {
            return Err(Refused(Refusal::Unknown));
        }
        let slot = self.inner.slot(session.account)?;
        let current = self.inner.current(&slot, session, true, &mut false).await?;
        let issued = current.issued;
        let state = slot.lock().await;
        let current = state.at(&current)?;
        let body = if current.head == Head::EMPTY {
            // A new account's log starts with its genesis, which carries nothing.
            if event != session.genesis || delivery.is_some() {
                return Err(Refused(Refusal::Invalid));
            }
            None
        } else {
            let mut candidate = current.verified.clone();
            candidate
                .apply(&event)
                .map_err(|_| Refused(Refusal::Invalid))?;
            delivery
                .map(|delivery| admit_delivery(&current.verified, &candidate, &delivery))
                .transpose()
                .map_err(|_| Refused(Refusal::Invalid))?
        };
        let commitment = body.as_ref().map(BodyObject::commitment);
        let wrapped =
            account_log_wrap(&event, commitment).map_err(|_| Refused(Refusal::Invalid))?;
        let batch = bh_crypto::random();
        let mut items = Vec::with_capacity(2);
        if let Some(body) = &body {
            let stage = Scope::Stage {
                log,
                body: body.commitment(),
                len: body.bytes().len() as u32,
            };
            items.push(Ok(self.inner.sign(stage, issued, batch)));
        }
        let append = Scope::Append {
            log,
            event: wrapped.digest(),
            body: commitment,
            epoch: ACCOUNT_EPOCH,
            after: Some(current.head),
        };
        items.push(Ok(self.inner.sign(append, issued, batch)));
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
        let creator = self
            .inner
            .view_at(
                slot.lock().await.at(&current)?,
                session.account,
                &session.genesis,
                creator_head.position,
            )?
            .filter(|view| view.head() == creator_head)
            .ok_or(Refused(Refusal::Invalid))?;
        let base = BaseId::from_genesis(&descriptor);
        let genesis = Commitment::order(base, Head::EMPTY, &descriptor, Route::Control)
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
        // Replay outside the lock. If the durable record changed while it
        // ran, its answer may predate that change: replay again from the new
        // state, bounded. The comparison, conditional save and publication
        // are one short locked section.
        let mut attempts = 0;
        loop {
            let expected = self.inner.store.prior(&log.id).map_err(|_| Unavailable)?;
            let (spine, view, extends) = self
                .inner
                .replay(
                    log,
                    &genesis,
                    ControlSpine::resume(start.clone()),
                    creator.clone(),
                    metadata.expose(),
                    expected.map(|p| p.control_head),
                )
                .await?;
            let head = spine.state().control_head;
            // A delayed answer that does not pass through the durable control
            // head it began from would regress it.
            let stale = !extends;
            let mut state = slot.lock().await;
            let account = state.at_mut(&current)?;
            // Verified registrations of one base agree; repeating one is idempotent.
            let recorded = self
                .inner
                .store
                .bind_base(&log.id, wanted)
                .map_err(|_| Unavailable)?;
            if recorded != wanted {
                return Err(Refused(Refusal::Conflict));
            }
            // A control this service permitted that can still follow the rebuilt
            // record stays pending, to be confirmed once it is ordered.
            let pending = self
                .inner
                .store
                .controls(&log.id)
                .map_err(|_| Unavailable)?
                .and_then(|(_, pending)| pending)
                .filter(|p| p.after == head);
            if !stale
                && self
                    .inner
                    .store
                    .save_controls_if(spine.state(), pending.as_ref(), expected)
                    .map_err(|_| Unavailable)?
            {
                account.bases.insert(
                    log.id,
                    BaseRecord {
                        spine,
                        view,
                        pending,
                        current: true,
                    },
                );
                break;
            }
            attempts += 1;
            if attempts >= REGISTER_REPLAY_ATTEMPTS {
                return Err(Unavailable);
            }
            drop(state);
        }
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
        };
        Ok(FromService::Permits {
            items: vec![
                Ok(self.inner.sign(stage, issued, batch)),
                Ok(self.inner.sign(append, issued, batch)),
            ],
        })
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
        let record = account.bases.get_mut(&log.id).ok_or(Unavailable)?;
        if !record.current || record.controls() != confirmed.controls {
            return Err(Unavailable);
        }
        let state = record.spine.state();
        if referenced_body(&descriptor).ok() != Some(body.commitment())
            || key_id(metadata.expose()) != state.metadata_id
        {
            return Err(Refused(Refusal::Invalid));
        }
        let effect = record
            .spine
            .check_submission(&record.view, &descriptor, body.bytes(), metadata.expose())
            .map_err(|outcome| match outcome {
                Outcome::Rejected => Refused(Refusal::Invalid),
                Outcome::UnsupportedPause => Refused(Refusal::Unsupported),
                _ => Unavailable,
            })?;
        drop(metadata);
        // A copy carries the account's own ordered event after the base's
        // copy of the account, byte for byte.
        let ordered = self
            .inner
            .store
            .account_event(&session.account.0, state.account.position + 1)
            .map_err(|_| Unavailable)?;
        if ordered.as_deref() != Some(effect.account_event.as_slice()) {
            return Err(Refused(Refusal::Invalid));
        }
        if record
            .pending
            .as_ref()
            .is_some_and(|p| p.effect.digest != effect.digest)
        {
            return Err(Refused(Refusal::Conflict));
        }
        let after = state.control_head;
        let epoch = effect.epoch_after.unwrap_or([0; 32]);
        let pending = Pending {
            event_id: descriptor.id().0,
            after,
            deadline_ms: issued + MAX_PERMIT_WINDOW_MS,
            effect,
        };
        // Durable before any permit exists, so a restart can confirm it.
        self.inner
            .store
            .save_controls(state, Some(&pending))
            .map_err(|_| Unavailable)?;
        record.pending = Some(pending);
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
            epoch,
            after: Some(after),
        };
        Ok(FromService::Permits {
            items: vec![
                Ok(self.inner.sign(stage, issued, batch)),
                Ok(self.inner.sign(append, issued, batch)),
            ],
        })
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
        _ => return Err(()),
    }
    delivery_body(&delivery.frame).map_err(|_| ())
}

impl Inner {
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

    fn sign(&self, scope: Scope, issued_ms: u64, batch: [u8; 16]) -> Vec<u8> {
        permit::sign(
            &self.keys.key,
            &self.keys.certificate,
            &Permit {
                scope,
                issued_ms,
                deadline_ms: issued_ms + MAX_PERMIT_WINDOW_MS,
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
        if state
            .at(&current)?
            .verified
            .active_device(session.device)
            .is_err()
        {
            return Err(Refused(Refusal::NotActive));
        }
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
            let previous = slot.lock().await.account.as_ref().ok_or(Unavailable)?.head;
            let first = previous.position + 1;
            let now = self.clock.now_ms().map_err(|_| Unavailable)?;
            let read = self.sign(
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
            let mut events = Vec::with_capacity(items.len());
            for (commitment, event) in items {
                let commitment = Commitment::decode(&commitment).map_err(|_| Unavailable)?;
                let event = OpaqueEvent::decode(&event).map_err(|_| Unavailable)?;
                head = commitment
                    .verify_next(BaseId(log.id), head)
                    .map_err(|_| Unavailable)?;
                commitment.verify_body(&event).map_err(|_| Unavailable)?;
                let (original, body) = account_log_unwrap(&event).map_err(|_| Unavailable)?;
                if head.position == 1 && original != genesis {
                    return Err(Unavailable);
                }
                events.push(StoredEvent {
                    original: original.to_vec(),
                    body,
                });
            }
            // Move, do not clone, the account (including its base records).
            // No await between taking it and the atomic durable commit/publication.
            // Verification/storage failure drops the candidate, leaving None.
            let mut state = slot.lock().await;
            if state.account.as_ref().map(|a| a.head) != Some(previous) {
                return Err(Unavailable);
            }
            let mut candidate = state.account.take().ok_or(Unavailable)?;
            let originals: Vec<_> = events
                .iter()
                .skip(usize::from(previous == Head::EMPTY))
                .map(|e| e.original.as_slice())
                .collect();
            candidate.verified = candidate
                .verified
                .applied_batch(&originals)
                .map_err(|_| Unavailable)?;
            self.store
                .extend(&id.0, &log.id, previous, head, &events)
                .map_err(|_| Unavailable)?;
            candidate
                .bodies
                .extend(events.iter().filter_map(|e| e.body));
            candidate.head = head;
            state.account = Some(candidate);
            if !full {
                break;
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
        let stored = self.store.account(&id.0).map_err(|_| Unavailable)?;
        let Some(stored) = stored else {
            return Ok(Account {
                log,
                verified: VerifiedAccount::from_genesis(id, genesis)
                    .map_err(|_| Refused(Refusal::Unauthenticated))?,
                head: Head::EMPTY,
                bodies: HashSet::new(),
                bases: HashMap::new(),
            });
        };
        if stored.log != log.id {
            return Err(Refused(Refusal::Unauthenticated));
        }
        Ok(Account {
            log,
            verified: replay(id, &stored.events).ok_or(Unavailable)?,
            head: stored.head,
            bodies: stored.events.iter().filter_map(|e| e.body).collect(),
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
        let stored = self
            .store
            .account(&id.0)
            .map_err(|_| Unavailable)?
            .ok_or(Unavailable)?;
        let events = stored.events.get(..position as usize).ok_or(Unavailable)?;
        if events.first().map(|e| e.original.as_slice()) != Some(genesis) {
            return Err(Unavailable);
        }
        replay(id, events).map(Some).ok_or(Unavailable)
    }
}

impl Inner {
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
            if !account.bases.contains_key(&log.id) {
                let record = self.load_base(account, session, &log.id)?;
                account.bases.insert(log.id, record);
            }
            let record = account.bases.get(&log.id).ok_or(Unavailable)?;
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

    async fn confirm(&self, slot: &Slot, log: LogId) -> Result<Confirmed, Failure> {
        // A pending control is judged by a time before the read.
        let start = self.clock.now_ms().map_err(|_| Unavailable)?;
        loop {
            let after = slot.lock().await.base(&log.id)?.spine.state().control_head;
            let items = self.read_controls(log, after.position).await?;
            let full = items.len() as u64 == READ_BATCH;
            let mut state = slot.lock().await;
            let account = state.account.as_mut().ok_or(Unavailable)?;
            // Removal is cache eviction, never deletion of durable
            // controls/pending: a failure reloads them on the next request.
            let mut taken = account.bases.remove(&log.id).ok_or(Unavailable)?;
            if taken.spine.state().control_head != after {
                return Err(Unavailable);
            }
            for (ordered, event) in items {
                let pending = taken
                    .pending
                    .take()
                    .filter(|p| p.event_id == event.id().0 && p.effect.digest == event.digest())
                    .ok_or(Refused(Refusal::Resync))?;
                taken.view = taken
                    .view
                    .applied_batch(&[&pending.effect.account_event])
                    .map_err(|_| Refused(Refusal::Resync))?;
                taken
                    .spine
                    .apply(pending.effect, &ordered)
                    .map_err(|_| Refused(Refusal::Resync))?;
                // Commit only a fully verified prefix before publication or await.
                self.store
                    .save_controls(taken.spine.state(), None)
                    .map_err(|_| Unavailable)?;
            }
            account.bases.insert(log.id, taken);
            if !full {
                break;
            }
        }
        let mut state = slot.lock().await;
        let record = state.base(&log.id)?;
        if record
            .pending
            .as_ref()
            .is_some_and(|p| start > p.deadline_ms + PENDING_GRACE_MS)
        {
            self.store
                .save_controls(record.spine.state(), None)
                .map_err(|_| Unavailable)?;
            record.pending = None;
        }
        record.current = true;
        Ok(Confirmed {
            start,
            controls: record.controls(),
        })
    }

    /// Up to `READ_BATCH` control-route events after `after`, each checked
    /// against its commitment.
    async fn read_controls(
        &self,
        log: LogId,
        after: u64,
    ) -> Result<Vec<(Commitment, OpaqueEvent)>, Failure> {
        let now = self.clock.now_ms().map_err(|_| Unavailable)?;
        let read = self.sign(Scope::ReadControls { log, after }, now, bh_crypto::random());
        let items = self.edge.read_log(read).await.map_err(|_| Unavailable)?;
        if items.len() as u64 > READ_BATCH {
            return Err(Unavailable);
        }
        items
            .iter()
            .map(|(commitment, event)| {
                let commitment = Commitment::decode(commitment).map_err(|_| Unavailable)?;
                let event = OpaqueEvent::decode(event).map_err(|_| Unavailable)?;
                commitment.verify_body(&event).map_err(|_| Unavailable)?;
                if commitment.route() != Route::Control || commitment.head().position <= after {
                    return Err(Unavailable);
                }
                Ok((commitment, event))
            })
            .collect()
    }

    /// The stored record, with the base's copy of the account rebuilt from
    /// the account's verified history at the genesis's head and the copied
    /// account events. Without a usable record the device must resync.
    fn load_base(
        &self,
        account: &Account,
        session: &Session,
        base: &[u8; 32],
    ) -> Result<BaseRecord, Failure> {
        let resync = Refused(Refusal::Resync);
        let (state, pending) = self
            .store
            .controls(base)
            .map_err(|_| Unavailable)?
            .ok_or(resync)?;
        let anchor = state
            .account
            .position
            .checked_sub(state.account_changes.len() as u64)
            .ok_or(resync)?;
        let mut view = self
            .view_at(account, session.account, &session.genesis, anchor)?
            .ok_or(resync)?;
        for change in &state.account_changes {
            view.apply(change).map_err(|_| resync)?;
        }
        if state.creator != session.account || view.head() != state.account {
            return Err(resync);
        }
        Ok(BaseRecord {
            spine: ControlSpine::resume(state),
            view,
            pending,
            current: false,
        })
    }

    /// Follow the base's ordered controls from its genesis with M, judging
    /// each as devices do. Returns the spine and the base's copy of the
    /// account after them, and whether the replay passed through
    /// `through`'s control head (always true when there is none).
    async fn replay(
        &self,
        log: LogId,
        genesis: &Commitment,
        mut spine: ControlSpine,
        mut view: VerifiedAccount,
        metadata: &Secret<32>,
        through: Option<Head>,
    ) -> Result<(ControlSpine, VerifiedAccount, bool), Failure> {
        let mut after = 0;
        let mut passed = through.is_none_or(|head| head == spine.state().control_head);
        loop {
            let items = self.read_controls(log, after).await?;
            let full = items.len() as u64 == READ_BATCH;
            // The log's first control is this genesis, or there is none yet.
            if after == 0 && items.first().is_some_and(|(ordered, _)| ordered != genesis) {
                return Err(Unavailable);
            }
            let later: Vec<_> = items
                .iter()
                .filter(|(ordered, _)| ordered != genesis)
                .collect();
            let bodies = self.read_bodies(log, &later).await?;
            for ((ordered, event), body) in later.into_iter().zip(bodies) {
                match spine.check(&view, event, &body, metadata, ordered) {
                    Ok(effect) => {
                        view.apply(&effect.account_event).map_err(|_| Unavailable)?;
                        spine.apply(effect, ordered).map_err(|_| Unavailable)?;
                    }
                    Err(Outcome::Rejected) => {
                        spine.apply_rejected(ordered).map_err(|_| Unavailable)?;
                    }
                    Err(Outcome::UnsupportedPause) => {
                        return Err(Refused(Refusal::Unsupported));
                    }
                    Err(_) => return Err(Unavailable),
                }
                if through == Some(spine.state().control_head) {
                    passed = true;
                }
            }
            match items.last() {
                Some((ordered, _)) if full => after = ordered.head().position,
                _ => return Ok((spine, view, passed)),
            }
        }
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
        let read = self.sign(
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

fn replay(id: AccountId, events: &[StoredEvent]) -> Option<VerifiedAccount> {
    let (genesis, rest) = events.split_first()?;
    let mut verified = VerifiedAccount::from_genesis(id, &genesis.original).ok()?;
    let rest: Vec<&[u8]> = rest.iter().map(|e| e.original.as_slice()).collect();
    verified.apply_batch(&rest).ok()?;
    Some(verified)
}
