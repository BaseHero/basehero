//! An in-memory hosted environment. The authorization service is the real
//! `bh_authz::Service`, in process, behind the real attested channel with the
//! labelled synthetic attestation. The data edge and its log objects are a
//! fake that behaves as the Worker and log object do: permits verified at use
//! against the pinned root and the edge's clock, a deadline checked before
//! each data frame (a late frame is withheld and its request refused
//! `Expired`), a send window the device must grant back, staged bodies,
//! exact retry by event id and route, the control head as a control's
//! predecessor, and a closed epoch refusing content.
//!
//! The service and the edge share one clock that moves with the runtime's
//! (paused) clock, so permits expire as time passes. Real costs the fake
//! would otherwise make free are injected as delays at their seams
//! (`Costs`): the service's reads through the edge, the edge's calls to its
//! log objects and body store, and, through the device fixture, the
//! signer and durable commits.
#![allow(dead_code)]

use bh_authz::{
    ChannelConfig, Clock, ClockError, EdgeError, EdgeReader, PermitKeys, Service,
    SyntheticAttestation, proto::ToService, proto::Want,
};
use bh_confidential_attestation::synthetic;
use bh_confidential_policy::{Policy, Role};
use bh_crypto::SigningKey;
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, EventId, Head, OpaqueEvent, Route,
    permit::{self, AppendAck, LogId, LogKind, Permit, PermitError, Scope},
    receipt::{self, CertifiedReceiptKey},
    referenced_body,
    wire::{MAX_FRAME_LEN, Refusal, Request, Response},
};
use bh_sync_client::{
    pairing::{Got, Put, Relay, Side},
    transport::{Connector, Route as Path, Socket, TransportError},
};
use futures_util::{SinkExt, StreamExt, future::BoxFuture};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Error as WsError, Message, protocol::Role as WsRole},
};

pub const TIME_START: u64 = 1_900_000_000_000;

/// The service's and the edge's trusted time: `TIME_START` plus the runtime's
/// elapsed time since the fixture began, plus any explicit `advance`. Under
/// a paused runtime it moves exactly as the client's timers do.
pub struct TestClock {
    start: tokio::time::Instant,
    offset: AtomicU64,
    /// Standing still at this time, for a test of a client-side wait that
    /// must not depend on permit lives.
    still: Mutex<Option<u64>>,
}
impl TestClock {
    fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
            offset: AtomicU64::new(0),
            still: Mutex::new(None),
        }
    }
    pub fn now(&self) -> u64 {
        if let Some(still) = *self.still.lock().unwrap() {
            return still;
        }
        TIME_START + self.offset.load(Ordering::SeqCst) + self.start.elapsed().as_millis() as u64
    }
    /// Stop the clock where it is: no permit expires from now on.
    pub fn stand_still(&self) {
        let now = self.now();
        *self.still.lock().unwrap() = Some(now);
    }
    /// Jump forward by `ms`, as a clock passing a deadline at once.
    pub fn advance(&self, ms: u64) {
        self.offset.fetch_add(ms, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        Ok(self.now())
    }
}

/// Costs the in-memory fixture would otherwise make free, each a delay of
/// the runtime's clock at its own seam.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Costs {
    /// One event signature by the platform signer.
    pub signer: Duration,
    /// One durable local commit on the typing path: a keystroke's save, a
    /// seal, an Ack, received history.
    pub commit: Duration,
    /// One way between the authorization service and the edge, for each
    /// read the service makes through the edge.
    pub checker_edge: Duration,
    /// One way between the edge and a log object or the body store, for
    /// each call the edge makes to either.
    pub edge_object: Duration,
}
impl Costs {
    pub const FREE: Self = Self {
        signer: Duration::ZERO,
        commit: Duration::ZERO,
        checker_edge: Duration::ZERO,
        edge_object: Duration::ZERO,
    };
    pub const DEFAULT: Self = Self {
        signer: Duration::from_millis(30),
        commit: Duration::from_millis(5),
        checker_edge: Duration::from_millis(20),
        edge_object: Duration::from_millis(20),
    };
    /// The default signer and commit, with the service, edge and log
    /// object 5 ms apart: how much the hop assumption matters.
    pub const NEAR: Self = Self {
        signer: Duration::from_millis(30),
        commit: Duration::from_millis(5),
        checker_edge: Duration::from_millis(5),
        edge_object: Duration::from_millis(5),
    };
    pub const SLOW: Self = Self {
        signer: Duration::from_millis(120),
        commit: Duration::from_millis(30),
        checker_edge: Duration::from_millis(60),
        edge_object: Duration::from_millis(60),
    };
}

/// What crossed the fixture's sockets and the service, counted as it
/// happened. `Sub` gives what one interval cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Encrypted authorization records devices sent, and their bytes.
    pub authz_up: usize,
    pub authz_up_bytes: usize,
    /// Encrypted authorization records devices received, and their bytes.
    pub authz_down: usize,
    pub authz_down_bytes: usize,
    /// Encoded DATA frames devices sent, and their bytes, credit grants
    /// among them.
    pub data_up: usize,
    pub data_up_bytes: usize,
    pub credits: usize,
    /// Encoded DATA frames devices received, and their bytes.
    pub data_down: usize,
    pub data_down_bytes: usize,
    /// Body bytes the edge sent in Body frames.
    pub body_bytes_down: usize,
    /// Decoded permit items in the service's requests, by kind.
    pub want_stage: usize,
    pub want_append: usize,
    pub want_read_events: usize,
    pub want_read_bodies: usize,
    pub want_subscribe: usize,
    /// Decoded requests by kind: `Permits` messages, `ReadBatch` requests
    /// and everything else (authentication, registration, controls, home).
    pub permits_messages: usize,
    pub read_batches: usize,
    pub other_requests: usize,
    /// DATA requests by kind.
    pub publish: usize,
    pub read_events: usize,
    pub read_bodies: usize,
    pub subscribe: usize,
    pub stage: usize,
    pub append: usize,
    /// Reads the service made through the edge.
    pub edge_reads: usize,
}
impl std::ops::Sub for Counts {
    type Output = Self;
    fn sub(self, before: Self) -> Self {
        macro_rules! minus {
            ($($field:ident),*) => {
                Self { $($field: self.$field - before.$field),* }
            };
        }
        minus!(
            authz_up,
            authz_up_bytes,
            authz_down,
            authz_down_bytes,
            data_up,
            data_up_bytes,
            credits,
            data_down,
            data_down_bytes,
            body_bytes_down,
            want_stage,
            want_append,
            want_read_events,
            want_read_bodies,
            want_subscribe,
            permits_messages,
            read_batches,
            other_requests,
            publish,
            read_events,
            read_bodies,
            subscribe,
            stage,
            append,
            edge_reads
        )
    }
}

/// Live counters behind `Counts`.
#[derive(Default)]
struct Counters([AtomicUsize; 26]);
#[derive(Clone, Copy)]
enum Count {
    AuthzUp,
    AuthzUpBytes,
    AuthzDown,
    AuthzDownBytes,
    DataUp,
    DataUpBytes,
    Credits,
    DataDown,
    DataDownBytes,
    BodyBytesDown,
    WantStage,
    WantAppend,
    WantReadEvents,
    WantReadBodies,
    WantSubscribe,
    WantPresence,
    PermitsMessages,
    ReadBatches,
    OtherRequests,
    Publish,
    ReadEvents,
    ReadBodies,
    Subscribe,
    Stage,
    Append,
    EdgeReads,
}
impl Counters {
    fn add(&self, count: Count, n: usize) {
        self.0[count as usize].fetch_add(n, Ordering::SeqCst);
    }
    fn snapshot(&self) -> Counts {
        let v = |c: Count| self.0[c as usize].load(Ordering::SeqCst);
        Counts {
            authz_up: v(Count::AuthzUp),
            authz_up_bytes: v(Count::AuthzUpBytes),
            authz_down: v(Count::AuthzDown),
            authz_down_bytes: v(Count::AuthzDownBytes),
            data_up: v(Count::DataUp),
            data_up_bytes: v(Count::DataUpBytes),
            credits: v(Count::Credits),
            data_down: v(Count::DataDown),
            data_down_bytes: v(Count::DataDownBytes),
            body_bytes_down: v(Count::BodyBytesDown),
            want_stage: v(Count::WantStage),
            want_append: v(Count::WantAppend),
            want_read_events: v(Count::WantReadEvents),
            want_read_bodies: v(Count::WantReadBodies),
            want_subscribe: v(Count::WantSubscribe),
            permits_messages: v(Count::PermitsMessages),
            read_batches: v(Count::ReadBatches),
            other_requests: v(Count::OtherRequests),
            publish: v(Count::Publish),
            read_events: v(Count::ReadEvents),
            read_bodies: v(Count::ReadBodies),
            subscribe: v(Count::Subscribe),
            stage: v(Count::Stage),
            append: v(Count::Append),
            edge_reads: v(Count::EdgeReads),
        }
    }
    /// Count one decoded request the service is about to handle.
    fn request(&self, message: &ToService) {
        match message {
            ToService::Permits { items } => {
                self.add(Count::PermitsMessages, 1);
                for item in items {
                    self.add(
                        match item {
                            Want::Stage { .. } => Count::WantStage,
                            Want::Append { .. } => Count::WantAppend,
                            Want::ReadEvents { .. } => Count::WantReadEvents,
                            Want::ReadBodies { .. } => Count::WantReadBodies,
                            Want::Subscribe { .. } => Count::WantSubscribe,
                            Want::Presence { .. } => Count::WantPresence,
                            Want::ReadBatch { .. } => Count::ReadBatches,
                        },
                        1,
                    );
                }
            }
            ToService::ReadBatch { .. } => self.add(Count::ReadBatches, 1),
            _ => self.add(Count::OtherRequests, 1),
        }
    }
}
/// The edge's initial send window: one largest frame plus 4 MiB.
pub const INITIAL_WINDOW: usize = MAX_FRAME_LEN + 4 * 1024 * 1024;

/// One thing a device did at the edge, or the edge did for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Stage {
        log: [u8; 32],
        body: Vec<u8>,
    },
    Publish {
        event: Vec<u8>,
        body: Vec<u8>,
    },
    BadProof(ProofFault),
    Append {
        log: [u8; 32],
        event: Vec<u8>,
    },
    Read {
        log: [u8; 32],
        first: u64,
        last: u64,
    },
    /// An append for this event reached the socket, before it is handled.
    Arrived {
        event: EventId,
    },
    /// The Ack for this event left the edge.
    Acked {
        event: EventId,
        position: u64,
    },
    Refused {
        reason: Refusal,
    },
    /// A subscription to this log started on a data socket, replacing any
    /// earlier one for the log on that socket.
    Subscribed {
        log: [u8; 32],
    },
    /// A permitted private-home store reached the log object.
    HomeStore {
        bundle: Vec<u8>,
    },
}

/// One held private-home store: `arrived` fires once the bundle is stored,
/// and its answer waits for `release` (or for it to be dropped).
pub struct HomeHold {
    pub arrived: oneshot::Receiver<()>,
    pub release: oneshot::Sender<()>,
}

/// A one-shot fault on the next matching base-log request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofFault {
    RequestId,
    Log,
    Event,
    Descriptor,
    Receipt,
    Root,
    Route,
    Commitment,
    Head,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    BadPublished(ProofFault),
    /// The clock passes the stage permit's deadline before it is checked.
    ExpireStage,
    /// The append commits, then the socket drops without its Ack; with
    /// `then_down`, the edge also stops accepting connections.
    DropAfterAppend {
        then_down: bool,
    },
    /// The append commits, then the clock passes its deadline, so its Ack
    /// is withheld and the request refused `Expired`.
    WithholdAck,
    /// The staged body is reclaimed before the append is handled.
    ReclaimBeforeAppend,
    /// An account-log append commits, then the socket drops without its Ack;
    /// with `then_down`, the edge also stops accepting connections.
    DropAfterAccountAppend {
        then_down: bool,
    },
    /// The append is not ordered. Its Ack names the log's current head, with
    /// a genuine receipt for that head, and the next read of that position
    /// returns a commitment forged to name this event at that head.
    ForgeAck,
}

struct Log {
    entries: Vec<(Commitment, OpaqueEvent)>,
    epoch: [u8; 32],
    control: Head,
    staged: HashMap<Digest, Vec<u8>>,
    bodies: HashMap<Digest, Vec<u8>>,
    ids: HashMap<EventId, (Digest, usize)>,
    /// A forged commitment served once for its position.
    forged: Option<(Commitment, OpaqueEvent)>,
    /// Data reads serve these from a position on instead of the entries.
    served: Option<(u64, Vec<(Commitment, OpaqueEvent)>)>,
    home_objects: HashMap<Digest, (Digest, Vec<u8>)>,
}
impl Default for Log {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            epoch: [0; 32],
            control: Head::EMPTY,
            staged: HashMap::new(),
            bodies: HashMap::new(),
            ids: HashMap::new(),
            forged: None,
            served: None,
            home_objects: HashMap::new(),
        }
    }
}
impl Log {
    fn head(&self) -> Head {
        self.entries.last().map_or(Head::EMPTY, |(c, _)| c.head())
    }
}
fn key(log: LogId) -> (u8, [u8; 32]) {
    (log.kind as u8, log.id)
}

pub struct Edge {
    root: SigningKey,
    permit_key: SigningKey,
    permit_certificate: [u8; receipt::CERTIFICATE_LEN],
    receipt_certificate: CertifiedReceiptKey,
    receipt_key: SigningKey,
    pub clock: Arc<TestClock>,
    costs: Mutex<Costs>,
    pacing: Mutex<bh_sync_client::Pacing>,
    /// Bytes per second each DATA socket carries from a device, if limited.
    uplink: Mutex<Option<u64>>,
    counters: Counters,
    /// Steps of the hosted path, each with when it happened: for tracing
    /// one change's way from one device to another.
    marks: Mutex<Vec<(tokio::time::Instant, String)>>,
    logs: Mutex<HashMap<(u8, [u8; 32]), Log>>,
    hooks: Mutex<VecDeque<Hook>>,
    pub seen: Mutex<Vec<Seen>>,
    /// Production checker descriptor selections, distinct from DATA reads.
    selected_reads: Mutex<Vec<(LogId, u64, u64)>>,
    /// What `seen` holds, each with the runtime's time it happened.
    timed: Mutex<Vec<(tokio::time::Instant, Seen)>>,
    /// The round trip injected on every socket: each message travels half
    /// of it each way, in order, without holding the ones behind it.
    latency: Mutex<Duration>,
    /// Messages devices sent on the authorization route (permit requests,
    /// among others), counted as they leave the device.
    pub authz_messages: std::sync::atomic::AtomicUsize,
    /// Count refused ReadBatch exchanges by the authenticated record sizes
    /// (79+60 request bytes, 4+60 refusal bytes) in this isolated fixture.
    pub refused_read_batches: std::sync::atomic::AtomicUsize,
    read_batch_inflight: AtomicBool,
    /// Withhold account subscription hints while exercising receiver-led follow.
    pub suppress_account_notices: AtomicBool,
    pub down: AtomicBool,
    pub changed: Notify,
    /// Connections attempted to the authorization route, up or down.
    pub authz_connects: std::sync::atomic::AtomicUsize,
    /// Data sockets opened.
    pub data_connects: std::sync::atomic::AtomicUsize,
    /// The next new base event is refused with this, and so is every later
    /// append of it.
    refuse_next: Mutex<Option<Refusal>>,
    refusing: Mutex<HashMap<EventId, Refusal>>,
    /// Server-side socket tasks, aborted when the edge goes down.
    sockets: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Reads serve nothing past this position, as a lagging read path.
    frozen: Mutex<Option<u64>>,
    /// Base reads starting past this position go unanswered.
    held: Mutex<Option<u64>>,
    /// Private-home storage is unreachable: nothing is stored.
    pub home_down: AtomicBool,
    /// Serve a wrongly marked final body on DATA without changing the
    /// production authorization selection.
    pub wrong_body_last: AtomicBool,
    /// Corrupt each DATA BODY ordinal without changing its signed grant or bytes.
    pub wrong_body_index: AtomicBool,
    /// Private-home stores succeed, but their answer names another bundle.
    pub forge_home: AtomicBool,
    home_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    stage_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    valid_publish_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    body_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    batch_reply_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    authz_reply_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    data_connect_hold: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    /// Presence joins admitted, attempts (including refusals), and nonempty
    /// presence frames relayed.
    presence_joins: std::sync::atomic::AtomicUsize,
    presence_attempts: std::sync::atomic::AtomicUsize,
    presence_frames: std::sync::atomic::AtomicUsize,
    /// Presence frames delivered to a joiner before its roster snapshot.
    presence_before_peers: std::sync::atomic::AtomicUsize,
    presence: Mutex<PresenceRoom>,
}

enum Step {
    Frames(Vec<Response>, u64),
    Drop,
    HeldPublish(PendingPublish, oneshot::Receiver<()>),
    HeldReply(Vec<Response>, u64, oneshot::Receiver<()>),
}
struct PendingPublish {
    id: u32,
    log: LogId,
    stage_deadline: u64,
    append_deadline: u64,
    append_permit: Vec<u8>,
    event: Vec<u8>,
}

impl Edge {
    fn new() -> Arc<Self> {
        let root = SigningKey::generate();
        let receipt_key = SigningKey::generate();
        let receipt_certificate = receipt::verify_certificate(
            &root.public(),
            &receipt::certify(&root, receipt_key.public()),
        )
        .unwrap();
        let permit_key = SigningKey::generate();
        let permit_certificate = permit::certify(&root, permit_key.public());
        Arc::new(Self {
            root,
            permit_key,
            permit_certificate,
            receipt_certificate,
            receipt_key,
            clock: Arc::new(TestClock::new()),
            costs: Mutex::new(Costs::FREE),
            pacing: Mutex::default(),
            uplink: Mutex::default(),
            counters: Counters::default(),
            marks: Mutex::default(),
            logs: Mutex::default(),
            hooks: Mutex::default(),
            seen: Mutex::default(),
            timed: Mutex::default(),
            latency: Mutex::default(),
            selected_reads: Default::default(),
            authz_messages: Default::default(),
            refused_read_batches: Default::default(),
            read_batch_inflight: AtomicBool::new(false),
            suppress_account_notices: AtomicBool::new(false),
            down: AtomicBool::new(false),
            changed: Notify::new(),
            authz_connects: Default::default(),
            data_connects: Default::default(),
            refuse_next: Mutex::default(),
            refusing: Mutex::default(),
            sockets: Mutex::default(),
            frozen: Mutex::default(),
            held: Mutex::default(),
            home_down: AtomicBool::new(false),
            wrong_body_last: AtomicBool::new(false),
            wrong_body_index: AtomicBool::new(false),
            forge_home: AtomicBool::new(false),
            home_hold: Mutex::default(),
            stage_hold: Mutex::default(),
            valid_publish_hold: Mutex::default(),
            body_hold: Mutex::default(),
            batch_reply_hold: Mutex::default(),
            authz_reply_hold: Mutex::default(),
            data_connect_hold: Mutex::default(),
            presence_joins: Default::default(),
            presence_attempts: Default::default(),
            presence_frames: Default::default(),
            presence_before_peers: Default::default(),
            presence: Mutex::default(),
        })
    }
    pub fn root(&self) -> [u8; 32] {
        self.root.public()
    }
    pub fn selected_reads(&self, log: LogId) -> Vec<(u64, u64)> {
        self.selected_reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _, _)| *id == log)
            .map(|(_, first, last)| (*first, *last))
            .collect()
    }

    /// A permit for `scope`, issued now, as the service would sign it.
    pub fn permit(&self, scope: Scope) -> Vec<u8> {
        let now = self.clock.now();
        permit::sign(
            &self.permit_key,
            &self.permit_certificate,
            &Permit {
                scope,
                issued_ms: now,
                deadline_ms: now + permit::MAX_PERMIT_WINDOW_MS,
                batch: [0; 16],
            },
        )
    }
    pub fn hook(&self, hook: Hook) {
        self.hooks.lock().unwrap().push_back(hook);
    }
    fn take_hook(&self, matches: impl Fn(&Hook) -> bool) -> Option<Hook> {
        let mut hooks = self.hooks.lock().unwrap();
        let index = hooks.iter().position(matches)?;
        hooks.remove(index)
    }
    /// Refuse every append of the next new base event with `reason`.
    pub fn refuse_next_event(&self, reason: Refusal) {
        *self.refuse_next.lock().unwrap() = Some(reason);
    }
    /// Hold the answer of the next private-home store after storing it.
    pub fn hold_next_stage(&self) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.stage_hold.lock().unwrap() = Some((arrived, release_rx));
        HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    /// Hold the next unmodified compound proof after durable ordering,
    /// without holding the injected malformed reply preceding it.
    pub fn hold_next_valid_publish_reply(&self) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.valid_publish_hold.lock().unwrap() = Some((arrived, release_rx));
        HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    /// Hold the answer of the next DATA body read, and every later request
    /// on that socket, as a slow body stream does.
    pub fn hold_next_body_read(&self) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.body_hold.lock().unwrap() = Some((arrived, release_rx));
        HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    /// Hold the reply to the next ReadBatch on its way to the device, and
    /// every reply behind it on that authorization socket.
    pub fn hold_next_batch_reply(&self) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.batch_reply_hold.lock().unwrap() = Some((arrived, release_rx));
        HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    /// Hold the next reply of any kind on its way to a device over an
    /// authorization socket, and every reply behind it on that socket.
    pub fn hold_next_authz_reply(&self) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.authz_reply_hold.lock().unwrap() = Some((arrived, release_rx));
        HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    /// Hold the next data connection open until released.
    pub fn hold_next_data_connect(&self) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.data_connect_hold.lock().unwrap() = Some((arrived, release_rx));
        HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    pub fn hold_next_home_store(&self) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.home_hold.lock().unwrap() = Some((arrived, release_rx));
        HomeHold {
            arrived: arrived_rx,
            release,
        }
    }
    /// Each stored private-home bundle: (prefix digest, bundle digest, bytes).
    pub fn home_objects(&self, log: LogId) -> Vec<(Digest, Digest, Vec<u8>)> {
        self.logs
            .lock()
            .unwrap()
            .get(&key(log))
            .map_or(Vec::new(), |l| {
                l.home_objects
                    .iter()
                    .map(|(prefix, (digest, bytes))| (*prefix, *digest, bytes.clone()))
                    .collect()
            })
    }
    /// The bundles of every permitted private-home store, in order.
    pub fn home_stores(&self) -> Vec<Vec<u8>> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::HomeStore { bundle } => Some(bundle),
                _ => None,
            })
            .collect()
    }
    pub fn hooks_left(&self) -> usize {
        self.hooks.lock().unwrap().len()
    }
    fn note(&self, seen: Seen) {
        self.timed
            .lock()
            .unwrap()
            .push((tokio::time::Instant::now(), seen.clone()));
        self.seen.lock().unwrap().push(seen);
        self.changed.notify_waiters();
    }
    fn mark(&self, what: impl Into<String>) {
        self.marks
            .lock()
            .unwrap()
            .push((tokio::time::Instant::now(), what.into()));
    }
    /// The hosted path's steps so far, each with when it happened.
    pub fn marks(&self) -> Vec<(tokio::time::Instant, String)> {
        self.marks.lock().unwrap().clone()
    }
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    /// What the edge saw, each with when it saw it.
    pub fn timed(&self) -> Vec<(tokio::time::Instant, Seen)> {
        self.timed.lock().unwrap().clone()
    }
    /// Inject this round trip on every socket opened from now on.
    pub fn set_latency(&self, round_trip: Duration) {
        *self.latency.lock().unwrap() = round_trip;
    }
    /// Charge these costs from now on; clients started later use its
    /// signer and commit times.
    pub fn set_costs(&self, costs: Costs) {
        *self.costs.lock().unwrap() = costs;
    }
    pub fn costs(&self) -> Costs {
        *self.costs.lock().unwrap()
    }
    /// The pacing clients started from now on use.
    pub fn set_pacing(&self, pacing: bh_sync_client::Pacing) {
        *self.pacing.lock().unwrap() = pacing;
    }
    pub fn pacing(&self) -> bh_sync_client::Pacing {
        *self.pacing.lock().unwrap()
    }
    /// Limit each DATA socket opened from now on to `bytes_per_second` from
    /// the device to the edge, as a constrained uplink.
    pub fn set_uplink(&self, bytes_per_second: Option<u64>) {
        *self.uplink.lock().unwrap() = bytes_per_second;
    }
    /// What has crossed the sockets and the service so far.
    pub fn counts(&self) -> Counts {
        self.counters.snapshot()
    }
    /// One read the service makes through the edge: to the edge and on to
    /// the log object, and back. `then` runs at the object.
    async fn through_edge<T>(&self, then: impl FnOnce() -> T) -> T {
        self.counters.add(Count::EdgeReads, 1);
        let costs = self.costs();
        let one_way = costs.checker_edge + costs.edge_object;
        if one_way.is_zero() {
            return then();
        }
        tokio::time::sleep(one_way).await;
        self.mark("service's read at object");
        let result = then();
        tokio::time::sleep(one_way).await;
        result
    }
    pub fn appends(&self, log: [u8; 32]) -> Vec<Vec<u8>> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Append { log: l, event } if l == log => Some(event),
                _ => None,
            })
            .collect()
    }
    pub fn stages(&self, log: [u8; 32]) -> Vec<Vec<u8>> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Stage { log: l, body } if l == log => Some(body),
                _ => None,
            })
            .collect()
    }
    pub fn entries(&self, log: LogId) -> Vec<(Commitment, OpaqueEvent)> {
        self.logs
            .lock()
            .unwrap()
            .get(&key(log))
            .map_or(Vec::new(), |l| l.entries.clone())
    }
    /// Close the base's content epoch, as an ordered removal copy does.
    pub fn close_epoch(&self, log: LogId) {
        self.logs.lock().unwrap().entry(key(log)).or_default().epoch = [0; 32];
    }
    /// Move the base's content epoch on, as an ordered rotation does.
    pub fn rotate_epoch(&self, log: LogId, epoch: [u8; 32]) {
        self.logs.lock().unwrap().entry(key(log)).or_default().epoch = epoch;
    }
    /// An ordered body, as another device's event would carry.
    pub fn insert_body(&self, log: LogId, bytes: Vec<u8>) -> Digest {
        let commitment = BodyObject::new(bytes.clone()).unwrap().commitment();
        self.logs
            .lock()
            .unwrap()
            .entry(key(log))
            .or_default()
            .bodies
            .insert(commitment, bytes);
        commitment
    }
    /// Batch reads (more than one position) serve nothing past `position`
    /// until thawed with `None`, as a lagging read path; single-position
    /// reads, appends, Acks and head notices go on.
    pub fn freeze_reads(&self, position: Option<u64>) {
        *self.frozen.lock().unwrap() = position;
        self.changed.notify_waiters();
    }
    /// Leave base reads that start past `position` unanswered until released
    /// with `None`, as a device losing its connection mid-read sees.
    pub fn hold_reads_after(&self, position: Option<u64>) {
        *self.held.lock().unwrap() = position;
    }
    /// Forget a log's ordered events, as a base whose log the service has
    /// not ordered anything into yet serves it.
    pub fn forget_log(&self, log: LogId) {
        self.logs.lock().unwrap().remove(&key(log));
        self.changed.notify_waiters();
    }
    /// The base-log reads of events, as `(first, last)` asked for.
    pub fn reads(&self, log: LogId) -> Vec<(u64, u64)> {
        self.seen()
            .into_iter()
            .filter_map(|s| match s {
                Seen::Read {
                    log: l,
                    first,
                    last,
                } if l == log.id => Some((first, last)),
                _ => None,
            })
            .collect()
    }
    /// Remove an ordered body, as a lost object leaves the log; returns it.
    pub fn take_body(&self, log: LogId, body: Digest) -> Option<Vec<u8>> {
        self.logs
            .lock()
            .unwrap()
            .get_mut(&key(log))?
            .bodies
            .remove(&body)
    }
    /// Order an event and its body directly, as a member's submission the
    /// service let through would be. Returns its position.
    pub fn order(
        &self,
        log: LogId,
        event: &OpaqueEvent,
        body: Option<Vec<u8>>,
        route: Route,
    ) -> u64 {
        let head = {
            let mut logs = self.logs.lock().unwrap();
            let entry = logs.entry(key(log)).or_default();
            if let Some(body) = body {
                let commitment = BodyObject::new(body.clone()).unwrap().commitment();
                entry.bodies.insert(commitment, body);
            }
            let ordered = Commitment::order(BaseId(log.id), entry.head(), event, route).unwrap();
            if route == Route::Control {
                entry.control = ordered.head();
            }
            entry
                .ids
                .insert(event.id(), (event.digest(), entry.entries.len()));
            entry.entries.push((ordered, event.clone()));
            ordered.head()
        };
        self.changed.notify_waiters();
        head.position
    }
    /// Order an original account event in the account log, as the account
    /// home orders a submitted control.
    pub fn order_account(&self, log: LogId, original: &[u8]) -> u64 {
        let event = bh_authz::proto::account_log_wrap(original, None).unwrap();
        self.order(log, &event, None, Route::Control)
    }
    /// Until `serve_ordered`, data reads of an account log serve `originals`
    /// from `position` on, chained after what is ordered before it, instead
    /// of what the account home ordered there: an edge serving other bytes.
    /// The service's own reads still see the ordered log.
    pub fn serve_account(&self, log: LogId, position: u64, originals: &[Vec<u8>]) {
        {
            let mut logs = self.logs.lock().unwrap();
            let entry = logs.get_mut(&key(log)).unwrap();
            let mut head = entry
                .entries
                .iter()
                .map(|(c, _)| c.head())
                .take_while(|h| h.position < position)
                .last()
                .unwrap_or(Head::EMPTY);
            let mut served = Vec::new();
            for original in originals {
                let event = bh_authz::proto::account_log_wrap(original, None).unwrap();
                let ordered =
                    Commitment::order(BaseId(log.id), head, &event, Route::Control).unwrap();
                head = ordered.head();
                served.push((ordered, event));
            }
            entry.served = Some((position, served));
        }
        self.changed.notify_waiters();
    }
    /// Data reads serve the ordered log again.
    pub fn serve_ordered(&self, log: LogId) {
        self.logs.lock().unwrap().get_mut(&key(log)).unwrap().served = None;
        self.changed.notify_waiters();
    }
    /// Rewrite the log's last position with other history and extend it:
    /// what a hosting service that forked the log after this device read it
    /// would serve. Every head it serves has a genuine receipt.
    pub fn fork(&self, log: LogId) {
        {
            let mut logs = self.logs.lock().unwrap();
            let entry = logs.get_mut(&key(log)).unwrap();
            let (last, event) = entry.entries.pop().unwrap();
            let route = match last.route() {
                Route::Content => Route::Control,
                Route::Control => Route::Content,
            };
            let previous = entry.head();
            let other = Commitment::order(BaseId(log.id), previous, &event, route).unwrap();
            entry.entries.push((other, event.clone()));
            let next =
                Commitment::order(BaseId(log.id), other.head(), &event, last.route()).unwrap();
            entry.entries.push((next, event));
        }
        self.changed.notify_waiters();
    }
    pub fn head(&self, log: LogId) -> Head {
        self.logs
            .lock()
            .unwrap()
            .get(&key(log))
            .map_or(Head::EMPTY, Log::head)
    }
    /// Subscriptions started for this log.
    pub fn subscriptions(&self, log: LogId) -> usize {
        self.seen()
            .iter()
            .filter(|s| **s == Seen::Subscribed { log: log.id })
            .count()
    }
    fn verify(&self, signed: &[u8]) -> Result<Permit, Refusal> {
        permit::verify(self.root.public(), signed, self.clock.now()).map_err(|e| match e {
            PermitError::Expired => Refusal::Expired,
            _ => Refusal::Malformed,
        })
    }
    fn receipt(&self, log: LogId, head: Head) -> Option<[u8; receipt::RECEIPT_LEN]> {
        (log.kind == LogKind::Base).then(|| {
            receipt::sign(
                &self.receipt_certificate,
                &self.receipt_key,
                BaseId(log.id),
                head,
            )
            .unwrap()
        })
    }

    /// Handle one request as the edge and its log object do.
    fn handle(&self, request: Request) -> Step {
        let refuse = |id, reason| Step::Frames(vec![Response::Refused { id, reason }], u64::MAX);
        match request {
            Request::Read { id, permit } => {
                let permit = match self.verify(&permit) {
                    Ok(p) => p,
                    Err(reason) => return refuse(id, reason),
                };
                let deadline = permit.deadline_ms;
                match permit.scope {
                    Scope::ReadEvents { log, first, last } => {
                        if log.kind == LogKind::Base
                            && self.held.lock().unwrap().is_some_and(|at| first > at)
                        {
                            return Step::Frames(Vec::new(), deadline);
                        }
                        self.note(Seen::Read {
                            log: log.id,
                            first,
                            last,
                        });
                        let frozen = *self.frozen.lock().unwrap();
                        let last = match frozen {
                            Some(at) if last > first => last.min(at),
                            _ => last,
                        };
                        let mut logs = self.logs.lock().unwrap();
                        let forged = logs.get_mut(&key(log)).and_then(|l| {
                            l.forged
                                .take_if(|(c, _)| (first..=last).contains(&c.head().position))
                        });
                        let items: Vec<(Vec<u8>, Vec<u8>)> =
                            logs.get(&key(log)).map_or(Vec::new(), |l| {
                                let served = l
                                    .served
                                    .as_ref()
                                    .map_or((u64::MAX, &[][..]), |(from, served)| {
                                        (*from, served.as_slice())
                                    });
                                l.entries
                                    .iter()
                                    .filter(|(c, _)| c.head().position < served.0)
                                    .chain(served.1)
                                    .map(|entry| match &forged {
                                        Some(f)
                                            if f.0.head().position == entry.0.head().position =>
                                        {
                                            f
                                        }
                                        _ => entry,
                                    })
                                    .filter(|(c, _)| (first..=last).contains(&c.head().position))
                                    .map(|(c, e)| (c.encode(), e.encode()))
                                    .collect()
                            });
                        let receipt = items.last().and_then(|(c, _)| {
                            self.receipt(log, Commitment::decode(c).unwrap().head())
                        });
                        Step::Frames(vec![Response::Events { id, items, receipt }], deadline)
                    }
                    Scope::ReadBodies { log, bodies } => {
                        self.mark("body read at object");
                        let hold = self.body_hold.lock().unwrap().take();
                        let logs = self.logs.lock().unwrap();
                        let mut frames = Vec::new();
                        let count = bodies.len();
                        for (index, body) in bodies.iter().enumerate() {
                            match logs.get(&key(log)).and_then(|l| l.bodies.get(body)) {
                                Some(bytes) => frames.push(Response::Body {
                                    id,
                                    index: (index
                                        + usize::from(self.wrong_body_index.load(Ordering::SeqCst)))
                                        as u8,
                                    last: (index + 1 == count)
                                        && !self.wrong_body_last.load(Ordering::SeqCst),
                                    bytes: bytes.clone(),
                                }),
                                None => {
                                    frames.push(Response::Refused {
                                        id,
                                        reason: Refusal::Missing,
                                    });
                                    break;
                                }
                            }
                        }
                        if let Some((arrived, release)) = hold {
                            let _ = arrived.send(());
                            return Step::HeldReply(frames, deadline, release);
                        }
                        Step::Frames(frames, deadline)
                    }
                    _ => refuse(id, Refusal::Scope),
                }
            }
            Request::Stage { id, permit, body } => {
                if let Some(Hook::ExpireStage) = self.take_hook(|h| *h == Hook::ExpireStage) {
                    self.clock.advance(31_000);
                }
                let permit = match self.verify(&permit) {
                    Ok(p) => p,
                    Err(reason) => {
                        self.note(Seen::Refused { reason });
                        return refuse(id, reason);
                    }
                };
                let Scope::Stage {
                    log,
                    body: commitment,
                    len,
                } = permit.scope
                else {
                    return refuse(id, Refusal::Scope);
                };
                self.note(Seen::Stage {
                    log: log.id,
                    body: body.clone(),
                });
                let Ok(object) = BodyObject::new(body.clone()) else {
                    return refuse(id, Refusal::Malformed);
                };
                if object.commitment() != commitment || body.len() != len as usize {
                    return refuse(id, Refusal::Malformed);
                }
                let mut logs = self.logs.lock().unwrap();
                let entry = logs.entry(key(log)).or_default();
                // Restaging an ordered body is simply ok; it stays ordered.
                if !entry.bodies.contains_key(&commitment) {
                    entry.staged.insert(commitment, body);
                }
                Step::Frames(vec![Response::Staged { id }], permit.deadline_ms)
            }
            Request::Publish {
                id,
                stage_permit,
                append_permit,
                event,
                body,
            } => {
                self.note(Seen::Publish {
                    event: event.clone(),
                    body: body.clone(),
                });
                // Prevalidate BOTH signed, exact-byte grants before staging.
                // The reused stage/append handlers then perform their normal
                // staging, epoch, predecessor, retry and hook checks without
                // another socket turn or intermediate response to the client.
                let stage = match self.verify(&stage_permit) {
                    Ok(p) => p,
                    Err(reason) => return refuse(id, reason),
                };
                let append = match self.verify(&append_permit) {
                    Ok(p) => p,
                    Err(reason) => return refuse(id, reason),
                };
                let (
                    Scope::Stage {
                        log: stage_log,
                        body: stage_body,
                        len,
                    },
                    Scope::Append {
                        log,
                        event: digest,
                        body: append_body,
                        after: None,
                        ..
                    },
                ) = (&stage.scope, &append.scope)
                else {
                    return refuse(id, Refusal::Scope);
                };
                if *log != *stage_log
                    || log.kind != LogKind::Base
                    || *append_body != Some(*stage_body)
                    || *len as usize != body.len()
                    || BodyObject::new(body.clone()).map(|b| b.commitment()).ok()
                        != Some(*stage_body)
                    || OpaqueEvent::decode(&event).ok().is_none_or(|e| {
                        e.digest() != *digest || referenced_body(&e).ok() != Some(*stage_body)
                    })
                {
                    return refuse(id, Refusal::Scope);
                }
                match self.handle(Request::Stage {
                    id,
                    permit: stage_permit,
                    body,
                }) {
                    Step::Frames(frames, _)
                        if matches!(frames.as_slice(), [Response::Staged { .. }]) => {}
                    other => return other,
                }
                let pending = PendingPublish {
                    id,
                    log: *log,
                    stage_deadline: stage.deadline_ms,
                    append_deadline: append.deadline_ms,
                    append_permit,
                    event,
                };
                if let Some((arrived, release)) = self.stage_hold.lock().unwrap().take() {
                    let _ = arrived.send(());
                    return Step::HeldPublish(pending, release);
                }
                self.finish_publish(pending)
            }
            Request::Append { id, permit, event } => {
                let permit = match self.verify(&permit) {
                    Ok(p) => p,
                    Err(reason) => {
                        self.note(Seen::Refused { reason });
                        return refuse(id, reason);
                    }
                };
                let Scope::Append {
                    log,
                    event: digest,
                    body,
                    epoch,
                    after,
                } = permit.scope
                else {
                    return refuse(id, Refusal::Scope);
                };
                self.note(Seen::Append {
                    log: log.id,
                    event: event.clone(),
                });
                let Ok(event) = OpaqueEvent::decode(&event) else {
                    return refuse(id, Refusal::Malformed);
                };
                if event.digest() != digest {
                    return refuse(id, Refusal::Malformed);
                }
                if log.kind == LogKind::Base {
                    let mut refusing = self.refusing.lock().unwrap();
                    if !refusing.contains_key(&event.id())
                        && let Some(reason) = self.refuse_next.lock().unwrap().take()
                    {
                        refusing.insert(event.id(), reason);
                    }
                    if let Some(reason) = refusing.get(&event.id()) {
                        return refuse(id, *reason);
                    }
                }
                let hook = match log.kind {
                    LogKind::Base => self.take_hook(|h| {
                        matches!(
                            h,
                            Hook::DropAfterAppend { .. }
                                | Hook::WithholdAck
                                | Hook::ReclaimBeforeAppend
                                | Hook::ForgeAck
                        )
                    }),
                    LogKind::Account => {
                        self.take_hook(|h| matches!(h, Hook::DropAfterAccountAppend { .. }))
                    }
                };
                let route = if after.is_some() {
                    Route::Control
                } else {
                    Route::Content
                };
                let head = {
                    let mut logs = self.logs.lock().unwrap();
                    let entry = logs.entry(key(log)).or_default();
                    if hook == Some(Hook::ReclaimBeforeAppend)
                        && let Some(body) = body
                    {
                        entry.staged.remove(&body);
                    }
                    if hook == Some(Hook::ForgeAck) {
                        // The forgery chains from the genuine predecessor of
                        // the head it claims; only its hash is not its own.
                        let head = entry.head();
                        let previous = entry.entries[entry.entries.len() - 2].0.head();
                        let mut bytes = Commitment::order(BaseId(log.id), previous, &event, route)
                            .unwrap()
                            .encode();
                        bytes[Commitment::LEN - 32..].copy_from_slice(&head.hash.0);
                        entry.forged = Some((Commitment::decode(&bytes).unwrap(), event.clone()));
                        let ack = AppendAck {
                            log,
                            event: event.id(),
                            head,
                            receipt: self.receipt(log, head),
                        };
                        return Step::Frames(
                            vec![Response::Acked {
                                id,
                                ack: ack.encode(),
                            }],
                            permit.deadline_ms,
                        );
                    }
                    // An exact retry gets the original result before any
                    // predecessor or epoch check.
                    if let Some((original, index)) = entry.ids.get(&event.id()).copied() {
                        let (ordered, _) = &entry.entries[index];
                        if original != digest || ordered.route() != route {
                            return refuse(id, Refusal::Conflict);
                        }
                        ordered.head()
                    } else {
                        match after {
                            Some(after) if after != entry.control => {
                                return refuse(id, Refusal::Predecessor);
                            }
                            None if epoch == [0; 32] || epoch != entry.epoch => {
                                return refuse(id, Refusal::Epoch);
                            }
                            _ => {}
                        }
                        // Only a staging body can be ordered: an ordered one
                        // never belongs to a second event.
                        if let Some(body) = body {
                            let Some(bytes) = entry.staged.remove(&body) else {
                                return refuse(id, Refusal::NotStaged);
                            };
                            entry.bodies.insert(body, bytes);
                        }
                        let ordered =
                            Commitment::order(BaseId(log.id), entry.head(), &event, route).unwrap();
                        if after.is_some() {
                            entry.control = ordered.head();
                            entry.epoch = epoch;
                        }
                        entry.ids.insert(event.id(), (digest, entry.entries.len()));
                        entry.entries.push((ordered, event.clone()));
                        ordered.head()
                    }
                };
                self.changed.notify_waiters();
                match hook {
                    Some(
                        Hook::DropAfterAppend { then_down }
                        | Hook::DropAfterAccountAppend { then_down },
                    ) => {
                        if then_down {
                            self.down.store(true, Ordering::SeqCst);
                        }
                        return Step::Drop;
                    }
                    Some(Hook::WithholdAck) => self.clock.advance(31_000),
                    _ => {}
                }
                let ack = AppendAck {
                    log,
                    event: event.id(),
                    head,
                    receipt: self.receipt(log, head),
                };
                Step::Frames(
                    vec![Response::Acked {
                        id,
                        ack: ack.encode(),
                    }],
                    permit.deadline_ms,
                )
            }
            Request::StoreHomeObjects { id, permit, bundle } => {
                let permit = match self.verify(&permit) {
                    Ok(p) => p,
                    Err(reason) => return refuse(id, reason),
                };
                let Scope::StoreHomeObjects {
                    log,
                    prefix_digest,
                    bundle_digest,
                } = permit.scope
                else {
                    return refuse(id, Refusal::Scope);
                };
                if log.kind != LogKind::Account
                    || bh_sync::home_objects::digest(&bundle) != Ok(bundle_digest)
                {
                    return refuse(id, Refusal::Malformed);
                }
                self.note(Seen::HomeStore {
                    bundle: bundle.clone(),
                });
                let mut logs = self.logs.lock().unwrap();
                let entry = logs.entry(key(log)).or_default();
                if let Some((digest, bytes)) = entry.home_objects.get(&prefix_digest) {
                    if *digest != bundle_digest || *bytes != bundle {
                        return refuse(id, Refusal::Conflict);
                    }
                } else {
                    entry
                        .home_objects
                        .insert(prefix_digest, (bundle_digest, bundle));
                }
                Step::Frames(
                    vec![Response::HomeObjectsStored {
                        id,
                        prefix_digest,
                        bundle_digest,
                    }],
                    permit.deadline_ms,
                )
            }
            // Served by `serve_data`, which keeps it running.
            Request::Subscribe { id, .. } => refuse(id, Refusal::Unavailable),
            Request::PresenceJoin { id, .. } | Request::Presence { id, .. } => {
                refuse(id, Refusal::Unavailable)
            }
            Request::Credit { .. } => Step::Frames(Vec::new(), u64::MAX),
        }
    }

    fn finish_publish(&self, pending: PendingPublish) -> Step {
        let PendingPublish {
            id,
            log,
            stage_deadline,
            append_deadline,
            append_permit,
            event,
        } = pending;
        let refuse = |reason| Step::Frames(vec![Response::Refused { id, reason }], u64::MAX);
        if self.clock.now() >= append_deadline.min(stage_deadline) {
            return refuse(Refusal::Expired);
        }
        let ack = match self.handle(Request::Append {
            id,
            permit: append_permit,
            event,
        }) {
            Step::Frames(frames, _) => match frames.as_slice() {
                [Response::Acked { ack, .. }] => ack.clone(),
                _ => return Step::Frames(frames, append_deadline.min(stage_deadline)),
            },
            Step::Drop => return Step::Drop,
            Step::HeldPublish(..) | Step::HeldReply(..) => {
                unreachable!("append cannot hold publication")
            }
        };
        let decoded = AppendAck::decode(&ack).unwrap();
        let commitment = self
            .logs
            .lock()
            .unwrap()
            .get(&key(log))
            .and_then(|l| {
                l.ids
                    .get(&decoded.event)
                    .and_then(|(_, index)| l.entries.get(*index))
            })
            .map(|(c, _)| c.encode());
        let Some(mut commitment) = commitment else {
            return refuse(Refusal::Unavailable);
        };
        let event = self
            .logs
            .lock()
            .unwrap()
            .get(&key(log))
            .and_then(|l| {
                l.ids
                    .get(&decoded.event)
                    .and_then(|(_, index)| l.entries.get(*index))
            })
            .map(|(_, e)| e.clone())
            .unwrap();
        if permit::verify_published_ordering(&self.root.public(), log, &event, &ack, &commitment)
            .is_err()
        {
            return refuse(Refusal::Unavailable);
        }
        let mut ack = decoded;
        let mut reply_id = id;
        let bad = self.take_hook(|h| matches!(h, Hook::BadPublished(_)));
        if let Some(Hook::BadPublished(fault)) = bad {
            self.note(Seen::BadProof(fault));
            match fault {
                ProofFault::RequestId => reply_id = id.wrapping_add(999),
                ProofFault::Log => ack.log.id[0] ^= 1,
                ProofFault::Event => ack.event.0[0] ^= 1,
                ProofFault::Receipt => ack.receipt.as_mut().unwrap()[0] ^= 1,
                ProofFault::Root => {
                    let wrong_root = SigningKey::generate();
                    let wrong_key = SigningKey::generate();
                    let cert = receipt::verify_certificate(
                        &wrong_root.public(),
                        &receipt::certify(&wrong_root, wrong_key.public()),
                    )
                    .unwrap();
                    ack.receipt =
                        Some(receipt::sign(&cert, &wrong_key, BaseId(log.id), ack.head).unwrap());
                }
                ProofFault::Descriptor | ProofFault::Route => {
                    let original = Commitment::decode(&commitment).unwrap();
                    let changed = if fault == ProofFault::Descriptor {
                        let mut envelope = event.envelope().to_vec();
                        envelope[40] ^= 1;
                        OpaqueEvent::new(event.id(), envelope).unwrap()
                    } else {
                        event.clone()
                    };
                    let route = if fault == ProofFault::Route {
                        Route::Control
                    } else {
                        Route::Content
                    };
                    let forged =
                        Commitment::order(BaseId(log.id), original.previous(), &changed, route)
                            .unwrap();
                    commitment = forged.encode();
                    ack.head = forged.head();
                    ack.receipt = self.receipt(log, forged.head());
                }
                ProofFault::Commitment => commitment[Commitment::LEN - 1] ^= 1,
                ProofFault::Head => ack.head.hash.0[0] ^= 1,
            }
        }
        let frames = vec![Response::Published {
            id: reply_id,
            ack: ack.encode(),
            commitment,
        }];
        let deadline = append_deadline.min(stage_deadline);
        if bad.is_none()
            && let Some((arrived, release)) = self.valid_publish_hold.lock().unwrap().take()
        {
            let _ = arrived.send(());
            return Step::HeldReply(frames, deadline, release);
        }
        Step::Frames(frames, deadline)
    }

    /// One data frame, once the window covers it and before its deadline;
    /// past the deadline it is withheld and its request refused `Expired`.
    async fn gate(&self, window: &Window, deadline: u64, frame: Response) -> Response {
        if matches!(frame, Response::Refused { .. }) {
            return frame;
        }
        let len = frame.encode().unwrap().len() as i64;
        loop {
            if self.clock.now() >= deadline {
                return Response::Refused {
                    id: id_of(&frame),
                    reason: Refusal::Expired,
                };
            }
            {
                let mut available = window.0.lock().unwrap();
                if *available >= len {
                    *available -= len;
                    return frame;
                }
            }
            let _ = tokio::time::timeout(Duration::from_millis(20), window.1.notified()).await;
        }
    }

    /// A subscription: the log's head after `after`, then each new head,
    /// each with its receipt for a base log, until the permit's deadline
    /// ends it with `Refused{Expired}`.
    async fn subscription(
        self: Arc<Self>,
        window: Arc<Window>,
        out: mpsc::UnboundedSender<(tokio::time::Instant, Response)>,
        id: u32,
        log: LogId,
        after: u64,
        deadline: u64,
    ) {
        let mut sent = after;
        loop {
            let head = self.head(log);
            if head.position > sent
                && !(log.kind == LogKind::Account
                    && self.suppress_account_notices.load(Ordering::SeqCst))
            {
                let frame = Response::Head {
                    id,
                    head,
                    receipt: self.receipt(log, head).map(|r| r.to_vec()),
                };
                let frame = self.gate(&window, deadline, frame).await;
                let ended = matches!(frame, Response::Refused { .. });
                // From the log object to the edge.
                self.mark("head notice leaves object");
                let at = tokio::time::Instant::now() + self.costs().edge_object;
                if out.send((at, frame)).is_err() || ended {
                    return;
                }
                sent = head.position;
            }
            if self.clock.now() >= deadline {
                let _ = out.send((
                    tokio::time::Instant::now(),
                    Response::Refused {
                        id,
                        reason: Refusal::Expired,
                    },
                ));
                return;
            }
            // Appends notify; the poll catches a clock moved past the deadline.
            let _ = tokio::time::timeout(Duration::from_millis(250), self.changed.notified()).await;
        }
    }

    /// One data socket: credit is read alongside requests; requests are
    /// answered in order, each data frame waiting for window and checked
    /// against its permit's deadline. Subscriptions run beside them, one per
    /// log; a newer one for the same log replaces the older silently.
    async fn serve_data<S>(self: Arc<Self>, ws: WebSocketStream<S>, who: &'static str)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sink, mut stream) = ws.split();
        let presence_socket = self.presence_socket();
        let window: Arc<Window> = Arc::new((Mutex::new(INITIAL_WINDOW as i64), Notify::new()));
        let (requests, mut queue) = mpsc::unbounded_channel::<(tokio::time::Instant, Request)>();
        // Each frame leaves the edge at its instant, in order.
        let (out, mut outgoing) = mpsc::unbounded_channel::<(tokio::time::Instant, Response)>();
        // Ends with this task, even when it is aborted, so the socket closes.
        let reader = AbortOnDrop({
            let window = window.clone();
            let edge = self.clone();
            tokio::spawn(async move {
                while let Some(Ok(Message::Binary(bytes))) = stream.next().await {
                    edge.counters.add(Count::DataUp, 1);
                    edge.counters.add(Count::DataUpBytes, bytes.len());
                    let Ok(request) = Request::decode(&bytes) else {
                        break;
                    };
                    match &request {
                        Request::Credit { .. } => {}
                        Request::Read { permit, .. } => {
                            let scope = permit::verify(
                                edge.root.public(),
                                permit,
                                permit::issued_ms(permit).unwrap_or(0),
                            )
                            .map(|p| p.scope);
                            edge.mark(match scope {
                                Ok(Scope::ReadEvents { log, first, last }) => format!(
                                    "{who}: DATA Read of {} events {first}..={last} arrives at edge",
                                    if log.kind == LogKind::Base { "base" } else { "account" }
                                ),
                                Ok(Scope::ReadBodies { bodies, .. }) => format!(
                                    "{who}: DATA Read of {} bodies arrives at edge",
                                    bodies.len()
                                ),
                                _ => format!("{who}: DATA Read arrives at edge"),
                            });
                        }
                        other => edge.mark(format!("{who}: DATA {} arrives at edge", kind(other))),
                    }
                    edge.counters.add(
                        match &request {
                            Request::Publish { .. } => Count::Publish,
                            Request::Stage { .. } => Count::Stage,
                            Request::Append { .. } => Count::Append,
                            Request::Subscribe { .. } => Count::Subscribe,
                            Request::Credit { .. } => Count::Credits,
                            Request::Read { permit, .. } => match permit::verify(
                                edge.root.public(),
                                permit,
                                permit::issued_ms(permit).unwrap_or(0),
                            )
                            .map(|p| p.scope)
                            {
                                Ok(Scope::ReadBodies { .. }) => Count::ReadBodies,
                                _ => Count::ReadEvents,
                            },
                            _ => Count::OtherRequests,
                        },
                        usize::from(!matches!(request, Request::StoreHomeObjects { .. })),
                    );
                    if let Request::Append { event, .. } | Request::Publish { event, .. } = &request
                        && let Ok(event) = OpaqueEvent::decode(event)
                    {
                        edge.note(Seen::Arrived { event: event.id() });
                    }
                    if let Request::Credit { bytes } = request {
                        *window.0.lock().unwrap() += i64::from(bytes);
                        window.1.notify_waiters();
                    } else if requests
                        .send((tokio::time::Instant::now(), request))
                        .is_err()
                    {
                        break;
                    }
                }
            })
        });
        let writer = AbortOnDrop({
            let edge = self.clone();
            tokio::spawn(async move {
                while let Some((at, frame)) = outgoing.recv().await {
                    if at > tokio::time::Instant::now() {
                        tokio::time::sleep_until(at).await;
                    }
                    let encoded = frame.encode().unwrap();
                    edge.counters.add(Count::DataDown, 1);
                    edge.counters.add(Count::DataDownBytes, encoded.len());
                    if let Response::Body { bytes, .. } = &frame {
                        edge.counters.add(Count::BodyBytesDown, bytes.len());
                    }
                    edge.mark(format!("{who}: DATA {} leaves edge", answer(&frame)));
                    match &frame {
                        Response::Acked { ack, .. } | Response::Published { ack, .. } => {
                            let ack = AppendAck::decode(ack).unwrap();
                            edge.note(Seen::Acked {
                                event: ack.event,
                                position: ack.head.position,
                            });
                        }
                        Response::Refused { reason, .. } => {
                            edge.note(Seen::Refused { reason: *reason })
                        }
                        _ => {}
                    }
                    if sink.send(Message::Binary(encoded.into())).await.is_err() {
                        break;
                    }
                }
                let _ = sink.close().await;
            })
        });
        let mut subscriptions: HashMap<(u8, [u8; 32]), AbortOnDrop> = HashMap::new();
        'requests: while let Some((arrived, request)) = queue.recv().await {
            // The edge's calls to its log object (and body store): a
            // compound publication stages, then appends; a subscription
            // opens a socket to the object; others make one call. Each
            // answer comes back one way from the object.
            let one_way = self.costs().edge_object;
            let ahead = match &request {
                Request::Credit { .. } => Duration::ZERO,
                Request::Subscribe { .. } => one_way * 2,
                Request::Publish { .. } => one_way * 3,
                _ => one_way,
            };
            if !ahead.is_zero() {
                tokio::time::sleep_until(arrived + ahead).await;
            }
            let back = match &request {
                Request::Credit { .. } | Request::Subscribe { .. } => Duration::ZERO,
                _ => one_way,
            };
            let now = tokio::time::Instant::now();
            if let Request::PresenceJoin { id, permit } = &request {
                match self.verify(permit) {
                    Ok(Permit {
                        scope: Scope::Presence { log, .. },
                        deadline_ms,
                        ..
                    }) if log.kind == LogKind::Base => {
                        self.presence_join(
                            presence_socket,
                            log,
                            *id,
                            deadline_ms,
                            now + back,
                            &out,
                        );
                    }
                    Ok(_) => {
                        let _ = out.send((
                            now,
                            Response::Refused {
                                id: *id,
                                reason: Refusal::Scope,
                            },
                        ));
                    }
                    Err(reason) => {
                        let _ = out.send((now, Response::Refused { id: *id, reason }));
                    }
                }
                continue;
            }
            if let Request::Presence { id, sealed } = &request {
                self.presence_frame(presence_socket, *id, sealed, now + back);
                continue;
            }
            if let Request::Subscribe { id, permit, after } = &request {
                match self.verify(permit) {
                    Ok(Permit {
                        scope: Scope::Subscribe { log },
                        deadline_ms,
                        ..
                    }) => {
                        self.note(Seen::Subscribed { log: log.id });
                        let task = tokio::spawn(self.clone().subscription(
                            window.clone(),
                            out.clone(),
                            *id,
                            log,
                            *after,
                            deadline_ms,
                        ));
                        subscriptions.insert(key(log), AbortOnDrop(task));
                    }
                    Ok(_) => {
                        let _ = out.send((
                            tokio::time::Instant::now(),
                            Response::Refused {
                                id: *id,
                                reason: Refusal::Scope,
                            },
                        ));
                    }
                    Err(reason) => {
                        let _ = out.send((
                            tokio::time::Instant::now(),
                            Response::Refused { id: *id, reason },
                        ));
                    }
                }
                continue;
            }
            let step = match self.handle(request) {
                Step::HeldPublish(pending, release) => {
                    // Stage has completed; only the durable barrier holds
                    // ordering and its proof response.
                    if release.await.is_err() {
                        break;
                    }
                    self.finish_publish(pending)
                }
                step => step,
            };
            let (frames, deadline) = match step {
                Step::Drop => break,
                Step::Frames(frames, deadline) => (frames, deadline),
                Step::HeldReply(frames, deadline, release) => {
                    if release.await.is_err() {
                        break;
                    }
                    (frames, deadline)
                }
                Step::HeldPublish(..) => unreachable!("one publication barrier"),
            };
            let mut at = tokio::time::Instant::now() + back;
            for frame in frames {
                // Each body is fetched from the body store in turn.
                if matches!(frame, Response::Body { .. }) {
                    at += one_way * 2;
                }
                let frame = self.gate(&window, deadline, frame).await;
                let expired = matches!(frame, Response::Refused { .. });
                if out
                    .send((at.max(tokio::time::Instant::now()), frame))
                    .is_err()
                {
                    break 'requests;
                }
                if expired {
                    break;
                }
            }
        }
        self.presence_leave(presence_socket);
        drop(subscriptions);
        drop(reader);
        drop(out);
        // Let the writer flush what was queued before the socket closes.
        let _ = tokio::time::timeout(Duration::from_millis(200), async {
            let mut writer = writer;
            let _ = (&mut writer.0).await;
        })
        .await;
    }
}

type Window = (Mutex<i64>, Notify);

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn kind(request: &Request) -> &'static str {
    match request {
        Request::Read { .. } => "Read",
        Request::Stage { .. } => "Stage",
        Request::Append { .. } => "Append",
        Request::Publish { .. } => "Publish",
        Request::Subscribe { .. } => "Subscribe",
        Request::StoreHomeObjects { .. } => "StoreHomeObjects",
        Request::Credit { .. } => "Credit",
        Request::PresenceJoin { .. } => "PresenceJoin",
        Request::Presence { .. } => "Presence",
    }
}
fn answer(response: &Response) -> &'static str {
    match response {
        Response::Events { .. } => "Events",
        Response::Body { .. } => "Body",
        Response::Staged { .. } => "Staged",
        Response::Acked { .. } => "Acked",
        Response::Published { .. } => "Published",
        Response::HomeObjectsStored { .. } => "HomeObjectsStored",
        Response::Head { .. } => "Head notice",
        Response::Refused { .. } => "Refused",
        Response::Presence { .. } => "Presence",
        Response::Peers { .. } => "Peers",
    }
}

fn id_of(response: &Response) -> u32 {
    match response {
        Response::Events { id, .. }
        | Response::Body { id, .. }
        | Response::Staged { id }
        | Response::Acked { id, .. }
        | Response::Published { id, .. }
        | Response::HomeObjectsStored { id, .. }
        | Response::Head { id, .. }
        | Response::Refused { id, .. }
        | Response::Presence { id, .. }
        | Response::Peers { id, .. } => *id,
    }
}

/// Presence membership the fake edge keeps for live data sockets, as the log
/// object's attachments do: epoch, random slot, the join's deadline, and a
/// sink to that socket. Nothing is stored or logged.
#[derive(Default)]
struct PresenceRoom {
    next_socket: u64,
    next_slot: u32,
    sockets: std::collections::BTreeMap<u64, PresenceSocket>,
    /// Sealed frames seen with their sender slot and arrival time, for
    /// canary, slot and pacing checks.
    wire: Vec<([u8; 32], u32, Vec<u8>, tokio::time::Instant)>,
    /// Drop every presence join and frame, as a silent network path.
    silence: bool,
    /// Refuse every presence join `Unavailable`, as a deploy or full place does.
    refuse_unavailable: bool,
    /// Drop frames from these slots while their joins keep renewing.
    silent_from: std::collections::BTreeSet<u32>,
    /// Deliver a presence frame before the roster snapshot.
    frame_before_peers: bool,
    /// Refuse this many joins `Epoch`, as a DO closed after a control.
    refuse_epoch: usize,
}
struct PresenceSocket {
    base: [u8; 32],
    log: LogId,
    slot: u32,
    join_id: u32,
    /// Edge-clock deadline of the current join permit.
    deadline: u64,
    sender: mpsc::UnboundedSender<(tokio::time::Instant, Response)>,
    /// The roster snapshot, held until the first presence frame arrives.
    pending_snapshot: bool,
}

impl Edge {
    pub fn presence_joins(&self) -> usize {
        self.presence_joins.load(Ordering::SeqCst)
    }
    /// Every presence join attempt, refused or admitted.
    pub fn presence_attempts(&self) -> usize {
        self.presence_attempts.load(Ordering::SeqCst)
    }
    pub fn presence_frames(&self) -> usize {
        self.presence_frames.load(Ordering::SeqCst)
    }
    pub fn presence_before_peers(&self) -> usize {
        self.presence_before_peers.load(Ordering::SeqCst)
    }
    /// Drop every presence join and frame from now on, as a silent loss does.
    pub fn silence(&self) {
        self.presence.lock().unwrap().silence = true;
    }
    /// Refuse every presence join `Unavailable`, as a deploy or full place does.
    pub fn refuse_presence_unavailable(&self) {
        self.presence.lock().unwrap().refuse_unavailable = true;
    }
    /// Refuse every presence join `Epoch`, as a closed DO does.
    pub fn refuse_presence_epochs(&self) {
        self.presence.lock().unwrap().refuse_epoch = usize::MAX;
    }
    /// Admit presence joins again after either blanket refusal.
    pub fn admit_presence(&self) {
        let mut room = self.presence.lock().unwrap();
        room.refuse_unavailable = false;
        room.refuse_epoch = 0;
    }
    /// Drop frames from `slot` while that join stays live, so a graceful
    /// close's best-effort clears are lost and only its `left` remains.
    pub fn silence_presence_frames_from(&self, slot: u32) {
        self.presence.lock().unwrap().silent_from.insert(slot);
    }
    /// End `slot`'s join as its permit deadline would, telling the others it
    /// left without answering the lost device.
    pub fn presence_expire_slot(&self, base: [u8; 32], slot: u32) {
        let one_way = self.costs().edge_object;
        let mut room = self.presence.lock().unwrap();
        let found = room
            .sockets
            .iter()
            .find(|(_, socket)| socket.base == base && socket.slot == slot)
            .map(|(id, _)| *id);
        if let Some(id) = found
            && let Some(gone) = room.sockets.remove(&id)
        {
            Self::presence_left(&mut room, gone, one_way);
        }
    }
    /// Deliver the next presence frame to a joiner before its roster snapshot.
    pub fn frames_before_peers(&self) {
        self.presence.lock().unwrap().frame_before_peers = true;
    }
    /// Refuse the next join or renewal `Epoch`, as a DO closes with 4409.
    pub fn refuse_next_presence_epoch(&self) {
        self.presence.lock().unwrap().refuse_epoch += 1;
    }
    /// Deliver a frame to every presence socket of `base`, as another device.
    pub fn inject_presence(&self, base: [u8; 32], frame: Vec<u8>) {
        self.inject_presence_from(base, u32::MAX, frame);
    }
    /// Deliver a frame to every presence socket of `base` from `slot`.
    pub fn inject_presence_from(&self, base: [u8; 32], from: u32, frame: Vec<u8>) {
        let room = self.presence.lock().unwrap();
        let at = tokio::time::Instant::now();
        for socket in room.sockets.values().filter(|s| s.base == base) {
            let _ = socket.sender.send((
                at,
                Response::Presence {
                    id: socket.join_id,
                    from,
                    sealed: frame.clone(),
                },
            ));
        }
    }
    /// Attach a bare presence socket to `base`, as another device that stays
    /// live but never sends. Its slot makes a departure leave `others > 0`,
    /// so only the named `left` can remove that sender's caret.
    pub fn attach_presence_peer(
        &self,
        base: [u8; 32],
    ) -> mpsc::UnboundedReceiver<(tokio::time::Instant, Response)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut room = self.presence.lock().unwrap();
        room.next_socket += 1;
        let socket = room.next_socket;
        room.next_slot = room.next_slot.wrapping_add(1).max(1);
        let slot = room.next_slot;
        let at = tokio::time::Instant::now();
        let others = room
            .sockets
            .values()
            .filter(|other| other.base == base)
            .count() as u16
            + 1;
        for other in room.sockets.values().filter(|other| other.base == base) {
            let _ = other.sender.send((
                at,
                Response::Peers {
                    id: other.join_id,
                    others,
                    event: 1,
                    slot,
                },
            ));
        }
        room.sockets.insert(
            socket,
            PresenceSocket {
                base,
                log: LogId {
                    kind: LogKind::Base,
                    id: base,
                },
                slot,
                join_id: 0,
                deadline: u64::MAX,
                sender,
                pending_snapshot: false,
            },
        );
        receiver
    }
    /// Tell every presence socket of `base` that `slot` left, as the log
    /// object does when a socket closes.
    pub fn presence_left_slot(&self, base: [u8; 32], slot: u32) {
        let room = self.presence.lock().unwrap();
        let others = room
            .sockets
            .values()
            .filter(|socket| socket.base == base)
            .count()
            .saturating_sub(1) as u16;
        let at = tokio::time::Instant::now();
        for socket in room.sockets.values().filter(|s| s.base == base) {
            let _ = socket.sender.send((
                at,
                Response::Peers {
                    id: socket.join_id,
                    others,
                    event: 2,
                    slot,
                },
            ));
        }
    }
    /// Sealed presence bytes seen on the wire.
    pub fn presence_wire(&self, base: [u8; 32]) -> Vec<Vec<u8>> {
        self.presence
            .lock()
            .unwrap()
            .wire
            .iter()
            .filter(|(b, _, _, _)| *b == base)
            .map(|(_, _, frame, _)| frame.clone())
            .collect()
    }
    /// Sealed presence bytes and the slot each came from.
    pub fn presence_wire_from(&self, base: [u8; 32]) -> Vec<(u32, Vec<u8>)> {
        self.presence
            .lock()
            .unwrap()
            .wire
            .iter()
            .filter(|(b, _, _, _)| *b == base)
            .map(|(_, from, frame, _)| (*from, frame.clone()))
            .collect()
    }
    /// Sealed presence bytes and when the edge saw each, for pacing checks.
    pub fn presence_wire_at(&self, base: [u8; 32]) -> Vec<(tokio::time::Instant, Vec<u8>)> {
        self.presence
            .lock()
            .unwrap()
            .wire
            .iter()
            .filter(|(b, _, _, _)| *b == base)
            .map(|(_, _, frame, at)| (*at, frame.clone()))
            .collect()
    }
    fn all_stored(&self) -> Vec<Vec<u8>> {
        let logs = self.logs.lock().unwrap();
        let mut all = Vec::new();
        for log in logs.values() {
            all.extend(log.entries.iter().map(|(c, _)| c.encode()));
            all.extend(log.staged.values().cloned());
            all.extend(log.bodies.values().cloned());
            all.extend(log.home_objects.values().map(|(_, b)| b.clone()));
        }
        all
    }
    pub fn wire_contains(&self, needles: &[&[u8]]) -> bool {
        let mut all = self.all_stored();
        all.extend(
            self.presence
                .lock()
                .unwrap()
                .wire
                .iter()
                .map(|(_, _, frame, _)| frame.clone()),
        );
        all.iter().any(|bytes| {
            needles
                .iter()
                .any(|n| bytes.windows(n.len()).any(|w| w == *n))
        })
    }
    pub fn storage_contains(&self, needles: &[&[u8]]) -> bool {
        self.all_stored().iter().any(|bytes| {
            needles
                .iter()
                .any(|n| bytes.windows(n.len()).any(|w| w == *n))
        })
    }
    fn presence_socket(&self) -> u64 {
        let mut room = self.presence.lock().unwrap();
        room.next_socket += 1;
        room.next_socket
    }
    /// A join or same-epoch renewal: a new socket gets a slot and a snapshot,
    /// the others a `joined`; the same socket keeps its slot.
    fn presence_join(
        &self,
        socket: u64,
        log: LogId,
        id: u32,
        deadline: u64,
        at: tokio::time::Instant,
        sender: &mpsc::UnboundedSender<(tokio::time::Instant, Response)>,
    ) {
        let one_way = self.costs().edge_object;
        let now = tokio::time::Instant::now();
        let mut room = self.presence.lock().unwrap();
        if room.silence {
            return;
        }
        self.presence_attempts.fetch_add(1, Ordering::SeqCst);
        if room.refuse_unavailable {
            let _ = sender.send((
                now,
                Response::Refused {
                    id,
                    reason: Refusal::Unavailable,
                },
            ));
            if let Some(gone) = room.sockets.remove(&socket) {
                Self::presence_left(&mut room, gone, one_way);
            }
            return;
        }
        if room.refuse_epoch > 0 {
            room.refuse_epoch -= 1;
            let _ = sender.send((
                now,
                Response::Refused {
                    id,
                    reason: Refusal::Epoch,
                },
            ));
            if let Some(gone) = room.sockets.remove(&socket) {
                Self::presence_left(&mut room, gone, one_way);
            }
            return;
        }
        self.presence_joins.fetch_add(1, Ordering::SeqCst);
        if let Some(existing) = room.sockets.get_mut(&socket) {
            existing.join_id = id;
            existing.deadline = deadline;
            return;
        }
        room.next_slot = room.next_slot.wrapping_add(1).max(1);
        let slot = room.next_slot;
        let pending_snapshot = room.frame_before_peers;
        let others = room
            .sockets
            .values()
            .filter(|s| s.base == log.id && s.log.kind == log.kind)
            .count() as u16;
        let snapshot = Response::Peers {
            id,
            others,
            event: 0,
            slot,
        };
        if others == 0 || !room.frame_before_peers {
            let _ = sender.send((at, snapshot));
        }
        for other in room.sockets.values() {
            if other.base == log.id && other.log.kind == log.kind {
                let _ = other.sender.send((
                    at,
                    Response::Peers {
                        id: other.join_id,
                        others,
                        event: 1,
                        slot,
                    },
                ));
            }
        }
        room.sockets.insert(
            socket,
            PresenceSocket {
                base: log.id,
                log,
                slot,
                join_id: id,
                deadline,
                sender: sender.clone(),
                pending_snapshot: others > 0 && pending_snapshot,
            },
        );
    }
    /// A nonempty frame: kept for canary checks, relayed to every other socket
    /// of the base whose join is live.
    fn presence_frame(&self, socket: u64, id: u32, sealed: &[u8], at: tokio::time::Instant) {
        let mut room = self.presence.lock().unwrap();
        if room.silence {
            return;
        }
        let Some((base, slot, current_id)) = room
            .sockets
            .get(&socket)
            .map(|from| (from.base, from.slot, from.join_id))
        else {
            return;
        };
        if current_id != id || room.silent_from.contains(&slot) {
            return;
        }
        room.wire
            .push((base, slot, sealed.to_vec(), tokio::time::Instant::now()));
        // A test fixture keeps a bounded sample; production stores nothing.
        if room.wire.len() > 4096 {
            room.wire.remove(0);
        }
        self.presence_frames.fetch_add(1, Ordering::SeqCst);
        let recipients: Vec<u64> = room
            .sockets
            .iter()
            .filter(|(s, other)| **s != socket && other.base == base)
            .map(|(s, _)| *s)
            .collect();
        for recipient in recipients {
            let Some((id, own_slot, pending, sender)) = room.sockets.get(&recipient).map(|other| {
                (
                    other.join_id,
                    other.slot,
                    other.pending_snapshot,
                    other.sender.clone(),
                )
            }) else {
                continue;
            };
            let _ = sender.send((
                at,
                Response::Presence {
                    id,
                    from: slot,
                    sealed: sealed.to_vec(),
                },
            ));
            if pending {
                if let Some(other) = room.sockets.get_mut(&recipient) {
                    other.pending_snapshot = false;
                }
                let others = room
                    .sockets
                    .values()
                    .filter(|s| s.base == base && s.slot != own_slot)
                    .count() as u16;
                let _ = sender.send((
                    at,
                    Response::Peers {
                        id,
                        others,
                        event: 0,
                        slot: own_slot,
                    },
                ));
                self.presence_before_peers.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    fn presence_leave(&self, socket: u64) {
        let one_way = self.costs().edge_object;
        let mut room = self.presence.lock().unwrap();
        if let Some(gone) = room.sockets.remove(&socket) {
            Self::presence_left(&mut room, gone, one_way);
        }
    }
    fn presence_left(room: &mut PresenceRoom, gone: PresenceSocket, one_way: Duration) {
        let others = room
            .sockets
            .values()
            .filter(|s| s.base == gone.base)
            .count() as u16;
        let at = tokio::time::Instant::now() + one_way;
        for other in room.sockets.values() {
            if other.base == gone.base {
                let _ = other.sender.send((
                    at,
                    Response::Peers {
                        id: other.join_id,
                        others: others.saturating_sub(1),
                        event: 2,
                        slot: gone.slot,
                    },
                ));
            }
        }
    }
    /// End joins whose permit deadline passed, as the edge and DO do.
    fn sweep_presence(self: &Arc<Self>) {
        let now = self.clock.now();
        let one_way = self.costs().edge_object;
        let mut room = self.presence.lock().unwrap();
        let expired: Vec<u64> = room
            .sockets
            .iter()
            .filter(|(_, s)| s.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(gone) = room.sockets.remove(&id) {
                let _ = gone.sender.send((
                    tokio::time::Instant::now(),
                    Response::Refused {
                        id: gone.join_id,
                        reason: Refusal::Expired,
                    },
                ));
                Self::presence_left(&mut room, gone, one_way);
            }
        }
    }
    async fn presence_sweeper(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            self.sweep_presence();
        }
    }
}

impl EdgeReader for Edge {
    fn read_log_with_receipt(
        &self,
        signed: Vec<u8>,
    ) -> BoxFuture<'_, Result<bh_authz::LogRead, EdgeError>> {
        Box::pin(self.through_edge(move || {
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            let Scope::ReadEvents { log, first, last } = permit.scope else {
                return Err(EdgeError::Refused);
            };
            self.selected_reads.lock().unwrap().push((log, first, last));
            if log.kind == LogKind::Base {
                self.mark("checker selects base events");
            }
            let items = self.read_log_now(signed)?;
            let receipt = if let Some((last, _)) = items.last() {
                let tail = Commitment::decode(last)
                    .map_err(|_| EdgeError::Malformed)?
                    .head();
                self.receipt(log, tail)
            } else {
                None
            };
            Ok(bh_authz::LogRead { items, receipt })
        }))
    }
    fn store_home_objects(
        &self,
        permit: Vec<u8>,
        bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<bh_authz::HomeObjectsAck, EdgeError>> {
        Box::pin(async move {
            self.counters.add(Count::EdgeReads, 1);
            let costs = self.costs();
            // There and back before the store is answered.
            let trip = (costs.checker_edge + costs.edge_object) * 2;
            if !trip.is_zero() {
                tokio::time::sleep(trip).await;
            }
            if self.home_down.load(Ordering::SeqCst) {
                return Err(EdgeError::Unavailable);
            }
            let step = self.handle(Request::StoreHomeObjects {
                id: 1,
                permit,
                bundle,
            });
            let hold = self.home_hold.lock().unwrap().take();
            if let Some((arrived, release)) = hold {
                let _ = arrived.send(());
                let _ = release.await;
            }
            match step {
                Step::Frames(frames, deadline) if self.clock.now() < deadline => {
                    match frames.as_slice() {
                        [
                            Response::HomeObjectsStored {
                                prefix_digest,
                                bundle_digest,
                                ..
                            },
                        ] => {
                            let mut bundle_digest = *bundle_digest;
                            if self.forge_home.load(Ordering::SeqCst) {
                                bundle_digest.0[0] ^= 1;
                            }
                            Ok(bh_authz::HomeObjectsAck {
                                prefix_digest: *prefix_digest,
                                bundle_digest,
                            })
                        }
                        _ => Err(EdgeError::Refused),
                    }
                }
                _ => Err(EdgeError::Unavailable),
            }
        })
    }
    fn read_log(
        &self,
        signed: Vec<u8>,
    ) -> BoxFuture<'_, Result<Vec<(Vec<u8>, Vec<u8>)>, EdgeError>> {
        Box::pin(self.through_edge(move || self.read_log_now(signed)))
    }
    fn read_bodies(&self, signed: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        Box::pin(self.through_edge(move || {
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            let Scope::ReadBodies { log, bodies } = permit.scope else {
                return Err(EdgeError::Refused);
            };
            let logs = self.logs.lock().unwrap();
            let ordered = logs.get(&key(log)).ok_or(EdgeError::Refused)?;
            bodies
                .iter()
                .map(|b| ordered.bodies.get(b).cloned().ok_or(EdgeError::Refused))
                .collect()
        }))
    }
}

impl Edge {
    /// A log read as the log object answers it.
    fn read_log_now(&self, signed: Vec<u8>) -> Result<bh_authz::LogItems, EdgeError> {
        {
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            // Up to 64 control-route events after a control read's position.
            let (log, controls, first, last) = match permit.scope {
                Scope::ReadEvents { log, first, last } => (log, false, first, last),
                Scope::ReadControls { log, after } => (log, true, after + 1, u64::MAX),
                _ => return Err(EdgeError::Refused),
            };
            let frozen = *self.frozen.lock().unwrap();
            let logs = self.logs.lock().unwrap();
            Ok(logs.get(&key(log)).map_or(Vec::new(), |l| {
                l.entries
                    .iter()
                    .filter(|(c, _)| {
                        (!controls || c.route() == Route::Control)
                            && (first..=last).contains(&c.head().position)
                            && (log.kind != LogKind::Base
                                || frozen.is_none_or(|at| c.head().position <= at))
                    })
                    .take(64)
                    .map(|(c, e)| (c.encode(), e.encode()))
                    .collect()
            }))
        }
    }
}

fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The edge, the real authorization service and its attested channel.
pub struct Hosted {
    pub edge: Arc<Edge>,
    relay: Arc<FakeRelay>,
    service: Mutex<Service>,
    pub policy_root: SigningKey,
    config: ChannelConfig,
    dir: tempfile::TempDir,
}
impl Hosted {
    pub fn new() -> Arc<Self> {
        let edge = Edge::new();
        let dir = tempfile::tempdir().unwrap();
        let service = Self::service(&edge, &dir.path().join("authz-0.sqlite"));
        let policy_root = SigningKey::generate();
        let policy = serde_json::to_vec(&Policy {
            version: 1,
            generation: 1,
            issued_at: seconds() - 60,
            expires_at: seconds() + 3600,
            builds: vec![synthetic::build(Role::Checker)],
            machines: vec![synthetic::machine()],
        })
        .unwrap();
        let policy_signature =
            policy_root.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &policy].concat());
        let config = ChannelConfig {
            app_root: policy_root.public(),
            policy,
            policy_signature,
        };
        tokio::spawn(edge.clone().presence_sweeper());
        Arc::new(Self {
            edge,
            relay: Arc::default(),
            service: Mutex::new(service),
            policy_root,
            config,
            dir,
        })
    }
    fn service(edge: &Arc<Edge>, path: &std::path::Path) -> Service {
        let permit_key = SigningKey::generate();
        let certificate = permit::certify(&edge.root, permit_key.public());
        let service = Service::open(
            path,
            PermitKeys::new(permit_key, certificate).unwrap(),
            edge.clock.clone(),
            edge.clone(),
        )
        .unwrap();
        let counted = edge.clone();
        service.observe(Arc::new(move |message| {
            counted.counters.request(message);
            counted.mark(match message {
                ToService::Permits { .. } => "service: Permits request begins",
                ToService::ReadBatch { .. } => "service: ReadBatch request begins",
                _ => "service: other request begins",
            });
        }));
        service
    }
    /// Replace the authorization service with one on an empty disk, as a
    /// restore that lost its base registry leaves it, and end every open
    /// connection.
    pub fn restart_service_empty(&self) {
        let path = self
            .dir
            .path()
            .join(format!("authz-{}.sqlite", bh_crypto::random::<8>()[0]));
        *self.service.lock().unwrap() = Self::service(&self.edge, &path);
        for task in self.edge.sockets.lock().unwrap().drain(..) {
            task.abort();
        }
        // Every presence socket lived only in that service's log object.
        self.edge.presence.lock().unwrap().sockets.clear();
    }
    /// Stop accepting connections and end every open one.
    pub fn go_down(&self) {
        self.edge.down.store(true, Ordering::SeqCst);
        for task in self.edge.sockets.lock().unwrap().drain(..) {
            task.abort();
        }
        // A DO restart or deploy closes every internal presence socket.
        self.edge.presence.lock().unwrap().sockets.clear();
    }
    pub fn come_up(&self) {
        self.edge.down.store(false, Ordering::SeqCst);
    }
    pub fn connector(self: &Arc<Self>) -> Arc<dyn Connector> {
        self.connector_for("device")
    }
    /// A connector whose sockets are named `who` in the edge's marks.
    pub fn connector_for(self: &Arc<Self>, who: &'static str) -> Arc<dyn Connector> {
        Arc::new(Connect(self.clone(), who))
    }
    /// The edge's pairing relay routes.
    pub fn relay(&self) -> Arc<dyn Relay> {
        self.relay.clone()
    }
    /// Serve every message on `side` changed by `tamper`, as a relay that
    /// alters what it holds would.
    pub fn tamper_relay(&self, side: Side, tamper: Tamper) {
        *self.relay.tamper.lock().unwrap() = Some((side, tamper));
    }
    /// The exact messages stored on `side`, across every pairing.
    pub fn relay_held(&self, side: Side) -> Vec<Vec<u8>> {
        self.relay
            .pairings
            .lock()
            .unwrap()
            .values()
            .flat_map(|p| p.side(side).clone())
            .collect()
    }
    /// Messages stored on `side`, across every pairing.
    pub fn relay_messages(&self, side: Side) -> usize {
        self.relay
            .pairings
            .lock()
            .unwrap()
            .values()
            .map(|p| p.side(side).len())
            .sum()
    }
    /// Store a message directly, as anyone holding the code could.
    pub fn put_relay(
        &self,
        code: &bh_account::pairing::QrCode,
        side: Side,
        index: u8,
        bytes: Vec<u8>,
    ) {
        let name = code.relay().name();
        let put = futures_util::FutureExt::now_or_never(self.relay.put(name, side, index, bytes));
        assert_eq!(put, Some(Ok(Put::Stored)));
    }
}

/// The pairing relay as the Worker's `PairingRelay` behaves: up to four
/// messages of at most 8 KiB per side, in order without gaps, an exact
/// resend accepted again, deleted five minutes after its first message.
#[derive(Default)]
pub struct FakeRelay {
    pairings: Mutex<HashMap<[u8; 32], Pairing>>,
    tamper: Mutex<Option<(Side, Tamper)>>,
}
/// How a relay alters a message it serves.
pub type Tamper = Box<dyn Fn(&mut Vec<u8>) + Send + Sync>;
struct Pairing {
    created: tokio::time::Instant,
    show: Vec<Vec<u8>>,
    join: Vec<Vec<u8>>,
}
impl Pairing {
    fn side(&self, side: Side) -> &Vec<Vec<u8>> {
        match side {
            Side::Show => &self.show,
            Side::Join => &self.join,
        }
    }
}
const RELAY_TTL: Duration = Duration::from_secs(300);
impl FakeRelay {
    /// The pairing named `name`, unless it expired (then it is deleted).
    fn live<'a>(
        pairings: &'a mut HashMap<[u8; 32], Pairing>,
        name: &[u8; 32],
    ) -> Result<Option<&'a mut Pairing>, ()> {
        if pairings
            .get(name)
            .is_some_and(|p| p.created.elapsed() >= RELAY_TTL)
        {
            pairings.remove(name);
            return Err(());
        }
        Ok(pairings.get_mut(name))
    }
}
impl Relay for FakeRelay {
    fn put(
        &self,
        name: [u8; 32],
        side: Side,
        index: u8,
        message: Vec<u8>,
    ) -> BoxFuture<'_, Result<Put, TransportError>> {
        let result = (|| {
            if index >= 4 {
                return Put::Full;
            }
            if message.is_empty() || message.len() > 8192 {
                return Put::Refused;
            }
            let mut pairings = self.pairings.lock().unwrap();
            let pairing = match Self::live(&mut pairings, &name) {
                Err(()) => return Put::Expired,
                Ok(Some(p)) => p,
                Ok(None) => pairings.entry(name).or_insert(Pairing {
                    created: tokio::time::Instant::now(),
                    show: Vec::new(),
                    join: Vec::new(),
                }),
            };
            let held = match side {
                Side::Show => &mut pairing.show,
                Side::Join => &mut pairing.join,
            };
            match held.get(index as usize) {
                Some(existing) if *existing == message => Put::Stored,
                Some(_) => Put::Taken,
                None if index as usize != held.len() => Put::Taken,
                None => {
                    held.push(message);
                    Put::Stored
                }
            }
        })();
        Box::pin(async move { Ok(result) })
    }
    fn get(
        &self,
        name: [u8; 32],
        side: Side,
        index: u8,
    ) -> BoxFuture<'_, Result<Got, TransportError>> {
        let result = (|| {
            let mut pairings = self.pairings.lock().unwrap();
            let pairing = match Self::live(&mut pairings, &name) {
                Err(()) => return Got::Expired,
                Ok(None) => return Got::Empty,
                Ok(Some(p)) => p,
            };
            let Some(message) = pairing.side(side).get(index as usize) else {
                return Got::Empty;
            };
            let mut message = message.clone();
            if let Some((tampered, tamper)) = self.tamper.lock().unwrap().as_ref()
                && *tampered == side
            {
                tamper(&mut message);
            }
            Got::Message(message)
        })();
        Box::pin(async move { Ok(result) })
    }
}

struct Connect(Arc<Hosted>, &'static str);
impl Connector for Connect {
    fn connect(&self, route: Path) -> BoxFuture<'_, Result<Socket, TransportError>> {
        Box::pin(async move {
            match route {
                Path::Authz => self.0.edge.authz_connects.fetch_add(1, Ordering::SeqCst),
                Path::Data => self.0.edge.data_connects.fetch_add(1, Ordering::SeqCst),
            };
            if self.0.edge.down.load(Ordering::SeqCst) {
                return Err(TransportError);
            }
            if route == Path::Data {
                let hold = self.0.edge.data_connect_hold.lock().unwrap().take();
                if let Some((arrived, release)) = hold {
                    let _ = arrived.send(());
                    let _ = release.await;
                }
            }
            let (client, server) = tokio::io::duplex(1 << 16);
            let config = bh_sync_client::transport::socket_config();
            let server =
                WebSocketStream::from_raw_socket(server, WsRole::Server, Some(config)).await;
            let task = match route {
                Path::Data => tokio::spawn(self.0.edge.clone().serve_data(server, self.1)),
                Path::Authz => {
                    let hosted = self.0.clone();
                    let service = hosted.service.lock().unwrap().clone();
                    tokio::spawn(async move {
                        let _ = service
                            .serve_connection(server, &hosted.config, &SyntheticAttestation)
                            .await;
                    })
                }
            };
            self.0.edge.sockets.lock().unwrap().push(task);
            let client =
                WebSocketStream::from_raw_socket(client, WsRole::Client, Some(config)).await;
            let latency = *self.0.edge.latency.lock().unwrap();
            let authz = (route == Path::Authz).then(|| self.0.edge.clone());
            let uplink = match route {
                Path::Data => *self.0.edge.uplink.lock().unwrap(),
                Path::Authz => None,
            };
            if latency.is_zero() && authz.is_none() && uplink.is_none() {
                return Ok(Box::pin(client) as Socket);
            }
            Ok(delayed(
                Box::pin(client),
                latency / 2,
                authz,
                uplink,
                self.1,
            ))
        })
    }
}

/// A socket over channels, so messages can be delayed on their way.
struct Channel {
    incoming: mpsc::UnboundedReceiver<Result<Message, WsError>>,
    outgoing: mpsc::UnboundedSender<Message>,
}
impl futures_util::Stream for Channel {
    type Item = Result<Message, WsError>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}
impl futures_util::Sink<Message> for Channel {
    type Error = WsError;
    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), WsError>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), WsError> {
        self.outgoing
            .send(item)
            .map_err(|_| WsError::ConnectionClosed)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), WsError>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), WsError>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Carry each message `one_way` later than it was sent, in order, each on
/// its own clock: a message is never held back by the delay of the one
/// before it, unless `uplink` (bytes per second from the device) is still
/// carrying the ones before it. Counts the encrypted records a device sends
/// and receives on the authorization route.
fn delayed(
    real: Socket,
    one_way: Duration,
    authz: Option<Arc<Edge>>,
    uplink: Option<u64>,
    who: &'static str,
) -> Socket {
    let (to_device, incoming) = mpsc::unbounded_channel();
    let (outgoing, mut from_device) = mpsc::unbounded_channel::<Message>();
    let (mut sink, mut stream) = real.split();
    let (up, mut up_line) = mpsc::unbounded_channel();
    let reply_counter = authz.clone();
    tokio::spawn(async move {
        // When the uplink has carried everything sent so far.
        let mut free = tokio::time::Instant::now();
        while let Some(message) = from_device.recv().await {
            if let Some(edge) = &authz {
                edge.authz_messages.fetch_add(1, Ordering::SeqCst);
                if let Message::Binary(bytes) = &message {
                    edge.counters.add(Count::AuthzUp, 1);
                    edge.counters.add(Count::AuthzUpBytes, bytes.len());
                    edge.mark(format!("{who}: authz record sent ({} B)", bytes.len()));
                }
                if matches!(&message, Message::Binary(bytes) if bytes.len() == 139) {
                    edge.read_batch_inflight.store(true, Ordering::SeqCst);
                }
            }
            let mut sent = tokio::time::Instant::now();
            if let (Some(rate), Message::Binary(bytes)) = (uplink, &message) {
                let carry = Duration::from_micros(bytes.len() as u64 * 1_000_000 / rate);
                free = free.max(sent) + carry;
                sent = free;
            }
            if up.send((sent + one_way, message)).is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((at, message)) = up_line.recv().await {
            tokio::time::sleep_until(at).await;
            if sink.send(message).await.is_err() {
                return;
            }
        }
        let _ = sink.close().await;
    });
    let (down, mut down_line) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(message) = stream.next().await {
            if let Some(edge) = &reply_counter
                && let Ok(Message::Binary(bytes)) = &message
                && edge.read_batch_inflight.swap(false, Ordering::SeqCst)
            {
                if bytes.len() == 64 {
                    edge.refused_read_batches.fetch_add(1, Ordering::SeqCst);
                }
                let hold = edge.batch_reply_hold.lock().unwrap().take();
                if let Some((arrived, release)) = hold {
                    let _ = arrived.send(());
                    let _ = release.await;
                }
            }
            if let Some(edge) = &reply_counter
                && let Ok(Message::Binary(bytes)) = &message
            {
                edge.counters.add(Count::AuthzDown, 1);
                edge.counters.add(Count::AuthzDownBytes, bytes.len());
                edge.mark(format!(
                    "{who}: authz reply leaves service ({} B)",
                    bytes.len()
                ));
                let hold = edge.authz_reply_hold.lock().unwrap().take();
                if let Some((arrived, release)) = hold {
                    let _ = arrived.send(());
                    let _ = release.await;
                }
            }
            let end = message.is_err();
            if down
                .send((tokio::time::Instant::now() + one_way, message))
                .is_err()
                || end
            {
                return;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((at, message)) = down_line.recv().await {
            tokio::time::sleep_until(at).await;
            if to_device.send(message).is_err() {
                return;
            }
        }
    });
    Box::pin(Channel { incoming, outgoing })
}
