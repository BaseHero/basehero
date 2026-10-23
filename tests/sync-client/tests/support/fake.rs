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
    Attestation, ChannelConfig, Clock, ClockError, EdgeError, EdgeReader, PermitKeys, Service,
    SyntheticAttestation,
    proto::{FromService, ToService, Want},
};
use bh_confidential_attestation::synthetic;
use bh_confidential_channel::{
    appraisal::{PolicyStore, Sample, StoredState},
    handshake::ServerPending,
    record::Opened,
};
use bh_confidential_policy::{Policy, Role, Snapshot};
use bh_crypto::{SecretBytes, SigningKey};
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, EventId, Head, OpaqueEvent, Route,
    evidence::{
        AcceptedHead, ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest,
    },
    permit::{self, AppendAck, LogId, LogKind, Permit, PermitError, Scope},
    receipt::{self, CertifiedReceiptKey},
    referenced_body,
    wire::{CoverageEndpoint, MAX_FRAME_LEN, Refusal, Request, Response},
};
use bh_sync_client::{
    pairing::{Got, Put, Relay, Side},
    transport::{Connector, Route as Path, Socket, TransportError},
};
use futures_util::{SinkExt, StreamExt, future::BoxFuture};
use std::{
    collections::{HashMap, HashSet, VecDeque},
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
    /// Resume the fixture's runtime-driven home clock after holding its
    /// confirmed bound behind a device's deadline.
    pub fn resume(&self) {
        *self.still.lock().unwrap() = None;
    }
    /// Jump forward by `ms`, as a clock passing a deadline at once.
    pub fn advance(&self, ms: u64) {
        self.offset.fetch_add(ms, Ordering::SeqCst);
    }
}
impl bh_sync_client::DeviceClock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now()
    }
}
impl Clock for TestClock {
    fn now_ms(&self) -> Result<u64, ClockError> {
        Ok(self.now())
    }
    fn bounds_ms(&self) -> Result<bh_authz::Bounds, ClockError> {
        let now = self.now();
        Ok(bh_authz::Bounds {
            earliest_ms: now,
            latest_ms: now,
        })
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
    /// Device DATA reads of a base's controls, apart from event reads.
    pub read_controls: usize,
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
            edge_reads,
            read_controls
        )
    }
}

/// Live counters behind `Counts`.
#[derive(Default)]
struct Counters([AtomicUsize; 27]);
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
    ReadControls,
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
            read_controls: v(Count::ReadControls),
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
                            Want::ReadControls { .. }
                            | Want::ReadDirectory { .. }
                            | Want::StoreDirectoryEntry { .. } => Count::OtherRequests,
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

/// How `Hosted::tamper_confirmations` alters an ordering confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmTamper {
    Root,
    Challenge,
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

/// A held base read: past which position, its arrival and its release.
type ReadHold = (u64, oneshot::Sender<()>, oneshot::Receiver<()>);

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
    /// An account-log append is lost before it is ordered: the socket drops.
    DropBeforeAccountAppend,
    /// An account-log append commits, then the clock moves on by `ms`
    /// before its Ack: the home confirms it later than its permit.
    AdvanceAfterAccountAppend {
        ms: u64,
    },
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
    served_full_only: bool,
    home_objects: HashMap<Digest, (Digest, Vec<u8>)>,
    /// The account directory, as the Worker's log object keeps it: each
    /// entry id's version, body digest and exact bytes.
    directory: std::collections::BTreeMap<[u8; 32], (u64, Digest, Vec<u8>)>,
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
            served_full_only: false,
            home_objects: HashMap::new(),
            directory: std::collections::BTreeMap::new(),
        }
    }
}
impl Log {
    fn head(&self) -> Head {
        self.entries.last().map_or(Head::EMPTY, |(c, _)| c.head())
    }
    fn order(&self) -> bh_sync::OrderState {
        self.entries
            .last()
            .map_or(bh_sync::OrderState::EMPTY, |(c, _)| c.after())
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
    /// On signup account appends, fork only DATA wrappers while checker reads stay honest.
    pub alter_account_second_on_append: AtomicBool,
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
    /// A device's metadata-only control reads are refused as unavailable;
    /// the service's own checker reads are not.
    pub refuse_control_reads: AtomicBool,
    /// A device's next control read answers as of this position: a control
    /// after it was appended after the read.
    pub lag_next_control_read: Mutex<Option<u64>>,
    /// DATA reads that asked for each body, answered or not.
    body_asks: Mutex<HashMap<Digest, usize>>,
    /// Each DATA request for a body: its commitment, the socket that sent it
    /// and the connector's name, so a test can follow one client's link.
    body_requests: Mutex<Vec<(Digest, usize, &'static str)>>,
    /// DATA sockets served, each with a stable id for `body_requests`.
    data_sockets: AtomicUsize,
    /// The DATA sockets the edge serves now, by id.
    data_sockets_live: Mutex<HashSet<usize>>,
    /// Each DATA socket served: its connector's name, how many requests it
    /// made, and how many of those were not account-evidence reads. One that
    /// has only read account evidence is a single check's own link.
    data_requests: Mutex<HashMap<usize, (&'static str, usize, usize)>>,
    /// Refuse the next account-evidence DATA read as one the log object
    /// cannot serve, and how many were refused.
    refuse_evidence: AtomicBool,
    evidence_refused: AtomicUsize,
    /// Each device control read's log and the position it reads after.
    pub control_reads: Mutex<Vec<(LogId, u64)>>,
    /// The seen window clients started from now on keep their staged
    /// controls within, if not the services' own.
    pub seen_window: Mutex<Option<u64>>,
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
    read_hold: Mutex<Option<ReadHold>>,
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
    /// Directory pages read and entries stored by devices.
    pub directory_reads: AtomicUsize,
    pub directory_writes: AtomicUsize,
    /// Every trust control's exact original a device submitted, and how many
    /// times a device asked whether one was ordered.
    pub submitted: Mutex<Vec<Vec<u8>>>,
    pub confirm_asks: AtomicUsize,
    /// How many times a device asked the home for its kit-used notices.
    pub notice_reads: AtomicUsize,
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
            alter_account_second_on_append: AtomicBool::new(false),
            down: AtomicBool::new(false),
            changed: Notify::new(),
            authz_connects: Default::default(),
            data_connects: Default::default(),
            refuse_next: Mutex::default(),
            refusing: Mutex::default(),
            sockets: Mutex::default(),
            frozen: Mutex::default(),
            held: Mutex::default(),
            refuse_control_reads: AtomicBool::new(false),
            lag_next_control_read: Mutex::default(),
            body_asks: Mutex::default(),
            body_requests: Mutex::default(),
            data_sockets: Default::default(),
            data_sockets_live: Mutex::default(),
            data_requests: Mutex::default(),
            refuse_evidence: AtomicBool::new(false),
            evidence_refused: Default::default(),
            control_reads: Mutex::default(),
            seen_window: Mutex::default(),
            home_down: AtomicBool::new(false),
            wrong_body_last: AtomicBool::new(false),
            wrong_body_index: AtomicBool::new(false),
            forge_home: AtomicBool::new(false),
            home_hold: Mutex::default(),
            stage_hold: Mutex::default(),
            valid_publish_hold: Mutex::default(),
            body_hold: Mutex::default(),
            read_hold: Mutex::default(),
            batch_reply_hold: Mutex::default(),
            authz_reply_hold: Mutex::default(),
            data_connect_hold: Mutex::default(),
            presence_joins: Default::default(),
            presence_attempts: Default::default(),
            presence_frames: Default::default(),
            presence_before_peers: Default::default(),
            presence: Mutex::default(),
            directory_reads: Default::default(),
            directory_writes: Default::default(),
            submitted: Mutex::default(),
            confirm_asks: Default::default(),
            notice_reads: Default::default(),
        })
    }
    pub fn root(&self) -> [u8; 32] {
        self.root.public()
    }
    /// The home's recovery key: derived from the hosting root's seed, so a
    /// restarted service holds the same one.
    pub fn recovery_key(&self) -> bh_crypto::KemKey {
        let seed = bh_crypto::hash(
            &[
                b"fixture recovery key\0".as_slice(),
                self.root.export_seed().expose(),
            ]
            .concat(),
        );
        bh_crypto::KemKey::from_seed(&bh_crypto::Secret::from_slice(&seed).unwrap())
    }
    /// The recovery key's certificate under the hosting root, as an app
    /// build carries it.
    pub fn recovery_certificate(&self) -> bh_sync::evidence::RecoveryKeyCertificate {
        bh_sync::evidence::certify_recovery_key(&self.root, &self.recovery_key().public())
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
    /// Hold the answer of the next base read that starts past `position`,
    /// and every later request on that socket, until released.
    pub fn hold_next_read_after(&self, position: u64) -> HomeHold {
        let (arrived, arrived_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        *self.read_hold.lock().unwrap() = Some((position, arrived, release_rx));
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
    /// How many DATA reads asked for the body `commitment` names.
    pub fn body_asks(&self, commitment: Digest) -> usize {
        self.body_asks
            .lock()
            .unwrap()
            .get(&commitment)
            .copied()
            .unwrap_or(0)
    }
    /// How many DATA reads named `who` asked for the body `commitment` names.
    pub fn body_asks_by(&self, commitment: Digest, who: &str) -> usize {
        self.body_requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(body, _, name)| *body == commitment && *name == who)
            .count()
    }
    /// The distinct DATA sockets named `who` that asked for the body
    /// `commitment` names: one while that client reuses its link, more once
    /// it dropped and reopened it.
    pub fn body_links_by(&self, commitment: Digest, who: &str) -> usize {
        let mut sockets: Vec<usize> = Vec::new();
        for (body, socket, name) in self.body_requests.lock().unwrap().iter() {
            if *body == commitment && *name == who && !sockets.contains(socket) {
                sockets.push(*socket);
            }
        }
        sockets.len()
    }
    /// The distinct DATA sockets named `who` that asked for any of `bodies`:
    /// one while that client read everything over the same link.
    pub fn body_links_across(&self, bodies: &[Digest], who: &str) -> usize {
        let requests = self.body_requests.lock().unwrap();
        let mut sockets: Vec<usize> = Vec::new();
        for (body, socket, name) in requests.iter() {
            if *name == who && bodies.contains(body) && !sockets.contains(socket) {
                sockets.push(*socket);
            }
        }
        sockets.len()
    }
    /// The DATA sockets named `who` that have only ever read account
    /// evidence: each is one check's own link, opened and released by it.
    pub fn evidence_links(&self, who: &str) -> Vec<usize> {
        let sockets = self.data_requests.lock().unwrap();
        let mut links: Vec<usize> = sockets
            .iter()
            .filter(|(_, (name, requests, other))| *name == who && *requests > 0 && *other == 0)
            .map(|(socket, _)| *socket)
            .collect();
        links.sort_unstable();
        links
    }
    /// How many of those the edge is serving now.
    pub fn live_evidence_links(&self, who: &str) -> usize {
        let sockets = self.evidence_links(who);
        let live = self.data_sockets_live.lock().unwrap();
        sockets
            .iter()
            .filter(|socket| live.contains(socket))
            .count()
    }
    /// Refuse the next account-evidence DATA read as unservable, so the
    /// reading lane sees a network failure while its socket stays open.
    pub fn refuse_next_evidence_read(&self) {
        self.refuse_evidence.store(true, Ordering::SeqCst);
    }
    /// Account-evidence DATA reads refused as unservable.
    pub fn evidence_refused(&self) -> usize {
        self.evidence_refused.load(Ordering::SeqCst)
    }
    /// Serve `bytes` for the body `commitment` names, as an edge handing out
    /// other bytes under an ordered body's commitment would.
    pub fn serve_body_as(&self, log: LogId, commitment: Digest, bytes: Vec<u8>) {
        self.logs
            .lock()
            .unwrap()
            .entry(key(log))
            .or_default()
            .bodies
            .insert(commitment, bytes);
    }
    /// Freeze only BASE-log event reads at `position`, not account history:
    /// multi-position DATA reads are cut there, as is the service's base
    /// checker read. Single-position DATA reads, appends, Acks and notices
    /// continue. `None` thaws the base.
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
    /// The account directory as the home holds it: each entry id's version
    /// and exact bytes.
    pub fn directory(&self, log: LogId) -> Vec<([u8; 32], u64, Vec<u8>)> {
        self.logs
            .lock()
            .unwrap()
            .get(&key(log))
            .map(|held| {
                held.directory
                    .iter()
                    .map(|(entry, (version, _, bytes))| (*entry, *version, bytes.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    /// Hold `bytes` under `entry` at `version` whatever was there, as a home
    /// that rolled its directory back or was written by a test would.
    pub fn put_directory_entry(&self, log: LogId, entry: [u8; 32], version: u64, bytes: Vec<u8>) {
        let digest = Digest(bh_crypto::hash(&bytes));
        self.logs
            .lock()
            .unwrap()
            .entry(key(log))
            .or_default()
            .directory
            .insert(entry, (version, digest, bytes));
    }
    /// Drop `entry` from the directory, as a home that lost it would.
    pub fn remove_directory_entry(&self, log: LogId, entry: [u8; 32]) {
        if let Some(held) = self.logs.lock().unwrap().get_mut(&key(log)) {
            held.directory.remove(&entry);
        }
    }
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
            let ordered = Commitment::order(BaseId(log.id), entry.order(), event, route).unwrap();
            if route == Route::Control {
                entry.control = ordered.head();
            }
            entry.ids.insert(
                event.publication_id(route),
                (event.digest(), entry.entries.len()),
            );
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
    /// A confirmation of the account original ordered at `position`, signed
    /// now by a key certified under the hosting root, as a confirming
    /// hosting service would sign it: for a test that stands in for a
    /// device's own verified read. Its time and exact bytes, as the device
    /// keeps them.
    pub fn account_confirmation(
        &self,
        log: LogId,
        position: u64,
    ) -> (bh_account::ConfirmedTime, Vec<u8>) {
        let logs = self.logs.lock().unwrap();
        let entries = &logs.get(&key(log)).unwrap().entries;
        let original = |at: u64| {
            let (_, event) = &entries[at as usize - 1];
            let (original, body) = bh_authz::proto::account_log_unwrap(event).unwrap();
            (original.to_vec(), body)
        };
        let inner = |at: u64| Head {
            position: at,
            hash: Digest(bh_crypto::hash(&original(at).0)),
        };
        let (bytes, body) = original(position);
        let now = self.clock.now();
        let bounds = bh_sync::evidence::TimeBounds {
            earliest_ms: now,
            latest_ms: now,
        };
        let proof = bh_sync::evidence::OrderingConfirmation::sign(
            &self.permit_key,
            &self.permit_certificate,
            bh_sync::evidence::ConfirmationClaim {
                log,
                original: bh_sync::evidence::original_digest(&bytes),
                original_previous: inner(position - 1),
                original_head: inner(position),
                body,
                ordered: entries[position as usize - 1].0.head(),
                bounds,
            },
        );
        let time = bh_account::ConfirmedTime {
            earliest_ms: now,
            latest_ms: now,
        };
        (time, proof.encode().to_vec())
    }
    /// Another independently certified statement of the exact same claim:
    /// valid evidence on a retry must not overwrite the original proof bytes.
    pub fn resign_account_confirmation(&self, bytes: &[u8]) -> Vec<u8> {
        use bh_sync::evidence::OrderingConfirmation;
        let old = OrderingConfirmation::decode(bytes).unwrap();
        old.verify(&self.root.public()).unwrap();
        let key = SigningKey::generate();
        let certificate = permit::certify(&self.root, key.public());
        OrderingConfirmation::sign(&key, &certificate, *old.claim())
            .encode()
            .to_vec()
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
                .map(|(c, _)| c.after())
                .take_while(|state| state.position() < position)
                .last()
                .unwrap_or(bh_sync::OrderState::EMPTY);
            let mut served = Vec::new();
            for original in originals {
                let event = bh_authz::proto::account_log_wrap(original, None).unwrap();
                let ordered =
                    Commitment::order(BaseId(log.id), head, &event, Route::Control).unwrap();
                head = ordered.after();
                served.push((ordered, event));
            }
            entry.served = Some((position, served));
            entry.served_full_only = false;
        }
        self.changed.notify_waiters();
    }
    /// Serve a page at a real position whose first canonical predecessor is
    /// another (same-position) outer opening, as a forked home might.
    pub fn serve_account_after(
        &self,
        log: LogId,
        position: u64,
        mut before: bh_sync::OrderState,
        originals: &[Vec<u8>],
    ) {
        assert_eq!(before.position() + 1, position);
        let mut served = Vec::new();
        for original in originals {
            let event = bh_authz::proto::account_log_wrap(original, None).unwrap();
            let ordered =
                Commitment::order(BaseId(log.id), before, &event, Route::Control).unwrap();
            before = ordered.after();
            served.push((ordered, event));
        }
        let mut logs = self.logs.lock().unwrap();
        let entry = logs.get_mut(&key(log)).unwrap();
        entry.served = Some((position, served));
        entry.served_full_only = false;
        drop(logs);
        self.changed.notify_waiters();
    }
    /// Serve genuine account originals, but replace the second wrapper's body
    /// and recalculate its and later canonical openings at the data edge.
    pub fn serve_account_with_altered_second_body(&self, log: LogId) {
        let mut logs = self.logs.lock().unwrap();
        let entry = logs.get_mut(&key(log)).unwrap();
        let mut before = entry.entries[0].0.after();
        let served = entry.entries[1..]
            .iter()
            .enumerate()
            .map(|(index, (_, event))| {
                let (original, _) = bh_authz::proto::account_log_unwrap(event).unwrap();
                let wrapped = bh_authz::proto::account_log_wrap(
                    original,
                    if index == 0 {
                        Some(Digest([99; 32]))
                    } else {
                        None
                    },
                )
                .unwrap();
                let commitment =
                    Commitment::order(BaseId(log.id), before, &wrapped, Route::Control).unwrap();
                before = commitment.after();
                (commitment, wrapped)
            })
            .collect();
        entry.served = Some((2, served));
        entry.served_full_only = true;
        drop(logs);
        self.changed.notify_waiters();
    }
    /// Data reads serve the ordered log again.
    pub fn serve_ordered(&self, log: LogId) {
        let mut logs = self.logs.lock().unwrap();
        let entry = logs.get_mut(&key(log)).unwrap();
        entry.served = None;
        entry.served_full_only = false;
        drop(logs);
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
            let previous = entry.order();
            let other = Commitment::order(BaseId(log.id), previous, &event, route).unwrap();
            entry.entries.push((other, event.clone()));
            let next =
                Commitment::order(BaseId(log.id), other.after(), &event, last.route()).unwrap();
            entry.entries.push((next, event));
        }
        self.changed.notify_waiters();
    }
    /// Order the event at `position` on the other route and every later
    /// event again after it: other history from there on, each head served
    /// with a genuine receipt.
    pub fn flip_route(&self, log: LogId, position: u64) {
        {
            let mut logs = self.logs.lock().unwrap();
            let entry = logs.get_mut(&key(log)).unwrap();
            let later = entry.entries.split_off(position as usize - 1);
            for (index, (ordered, event)) in later.into_iter().enumerate() {
                let route = match (index, ordered.route()) {
                    (0, Route::Content) => Route::Control,
                    (0, Route::Control) => Route::Content,
                    (_, route) => route,
                };
                let next = Commitment::order(BaseId(log.id), entry.order(), &event, route).unwrap();
                entry.entries.push((next, event));
            }
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
    /// One log-object capture: select sparse controls and the full-order
    /// endpoint under the same log lock. `through` fixes an earlier endpoint;
    /// without it the captured log's current last entry is the endpoint.
    fn sparse_control_snapshot(
        &self,
        log: LogId,
        after: u64,
        through: Option<u64>,
    ) -> Result<(bh_authz::LogItems, CoverageEndpoint), EdgeError> {
        if log.kind != LogKind::Base {
            return Err(EdgeError::Refused);
        }
        let frozen = *self.frozen.lock().unwrap();
        let logs = self.logs.lock().unwrap();
        let entries = logs
            .get(&key(log))
            .map(|entry| entry.entries.as_slice())
            .unwrap_or(&[]);
        let target = through.unwrap_or(entries.len() as u64);
        let opening = if target == 0 {
            bh_sync::OrderState::EMPTY
        } else {
            entries
                .get(usize::try_from(target - 1).map_err(|_| EdgeError::Unavailable)?)
                .ok_or(EdgeError::Unavailable)?
                .0
                .after()
        };
        let items = entries
            .iter()
            .filter(|(c, _)| {
                c.route() == Route::Control
                    && c.head().position > after
                    && c.head().position <= target
                    && frozen.is_none_or(|at| c.head().position <= at)
            })
            .take(64)
            .map(|(c, e)| (c.encode(), e.encode()))
            .collect();
        Ok((
            items,
            CoverageEndpoint {
                order: opening,
                receipt: (target > 0)
                    .then(|| self.receipt(log, opening.head(BaseId(log.id))))
                    .flatten(),
            },
        ))
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
                            Some(at) if log.kind == LogKind::Base && last > first => last.min(at),
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
                                    .filter(|_| !l.served_full_only || last - first == 63)
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
                        let frames = vec![Response::Events {
                            id,
                            items,
                            receipt,
                            coverage: None,
                        }];
                        if log.kind == LogKind::Base
                            && let Some((_, arrived, release)) = self
                                .read_hold
                                .lock()
                                .unwrap()
                                .take_if(|(at, ..)| first > *at)
                        {
                            let _ = arrived.send(());
                            return Step::HeldReply(frames, deadline, release);
                        }
                        Step::Frames(frames, deadline)
                    }
                    scope @ (Scope::ReadControls { .. } | Scope::ReadControlRange { .. }) => {
                        if self.refuse_control_reads.load(Ordering::SeqCst) {
                            return refuse(id, Refusal::Unavailable);
                        }
                        let (log, after, through) = match scope {
                            Scope::ReadControls { log, after } => (log, after, None),
                            Scope::ReadControlRange {
                                log,
                                after,
                                through,
                            } => (log, after, Some(through)),
                            _ => unreachable!(),
                        };
                        self.control_reads.lock().unwrap().push((log, after));
                        let through = match self.lag_next_control_read.lock().unwrap().take() {
                            Some(at) => Some(through.map_or(at, |t| t.min(at))),
                            None => through,
                        };
                        let (items, coverage) =
                            match self.sparse_control_snapshot(log, after, through) {
                                Ok(snapshot) => snapshot,
                                Err(_) => return refuse(id, Refusal::Unavailable),
                            };
                        Step::Frames(
                            vec![Response::Events {
                                id,
                                items,
                                receipt: None,
                                coverage: Some(coverage),
                            }],
                            deadline,
                        )
                    }
                    Scope::ReadBodies { log, bodies } => {
                        self.mark("body read at object");
                        let hold = self.body_hold.lock().unwrap().take();
                        let logs = self.logs.lock().unwrap();
                        let mut frames = Vec::new();
                        let count = bodies.len();
                        for (index, body) in bodies.iter().enumerate() {
                            *self.body_asks.lock().unwrap().entry(*body).or_default() += 1;
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
                    attached,
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
                let route = if after.is_some() {
                    Route::Control
                } else {
                    Route::Content
                };
                if log.kind == LogKind::Base {
                    let mut refusing = self.refusing.lock().unwrap();
                    if !refusing.contains_key(&event.publication_id(route))
                        && let Some(reason) = self.refuse_next.lock().unwrap().take()
                    {
                        refusing.insert(event.publication_id(route), reason);
                    }
                    if let Some(reason) = refusing.get(&event.publication_id(route)) {
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
                    LogKind::Account => self.take_hook(|h| {
                        matches!(
                            h,
                            Hook::DropAfterAccountAppend { .. }
                                | Hook::DropBeforeAccountAppend
                                | Hook::AdvanceAfterAccountAppend { .. }
                        )
                    }),
                };
                if hook == Some(Hook::DropBeforeAccountAppend) {
                    return Step::Drop;
                }
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
                        let previous = entry.entries[entry.entries.len() - 2].0.after();
                        let mut bytes = Commitment::order(BaseId(log.id), previous, &event, route)
                            .unwrap()
                            .encode();
                        bytes[Commitment::LEN - 32..].copy_from_slice(&head.hash.0);
                        entry.forged = Some((Commitment::decode(&bytes).unwrap(), event.clone()));
                        let ack = AppendAck {
                            log,
                            event: event.publication_id(route),
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
                    if let Some((original, index)) =
                        entry.ids.get(&event.publication_id(route)).copied()
                    {
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
                        // never belongs to a second event. A control's
                        // attached body is ordered with its own.
                        let bodies: Vec<_> = body.into_iter().chain(attached).collect();
                        if bodies.iter().any(|b| !entry.staged.contains_key(b)) {
                            return refuse(id, Refusal::NotStaged);
                        }
                        for body in bodies {
                            let bytes = entry.staged.remove(&body).expect("checked staged");
                            entry.bodies.insert(body, bytes);
                        }
                        let ordered =
                            Commitment::order(BaseId(log.id), entry.order(), &event, route)
                                .unwrap();
                        if after.is_some() {
                            entry.control = ordered.head();
                            entry.epoch = epoch;
                        }
                        entry
                            .ids
                            .insert(event.publication_id(route), (digest, entry.entries.len()));
                        entry.entries.push((ordered, event.clone()));
                        ordered.head()
                    }
                };
                if log.kind == LogKind::Account
                    && self.alter_account_second_on_append.load(Ordering::SeqCst)
                    && self.entries(log).len() >= 2
                {
                    self.serve_account_with_altered_second_body(log);
                }
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
                    Some(Hook::AdvanceAfterAccountAppend { ms }) => self.clock.advance(ms),
                    _ => {}
                }
                let ack = AppendAck {
                    log,
                    event: event.publication_id(route),
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
            Request::StoreDirectoryEntry { id, permit, body } => {
                let permit = match self.verify(&permit) {
                    Ok(p) => p,
                    Err(reason) => return refuse(id, reason),
                };
                let Scope::StoreDirectoryEntry {
                    log,
                    entry,
                    version,
                    body: digest,
                    len,
                } = permit.scope
                else {
                    return refuse(id, Refusal::Scope);
                };
                if body.is_empty() || body.len() != len as usize || body.len() > 65_536 {
                    return refuse(id, Refusal::Malformed);
                }
                if Digest(bh_crypto::hash(&body)) != digest {
                    return refuse(id, Refusal::Scope);
                }
                self.directory_writes.fetch_add(1, Ordering::SeqCst);
                let mut logs = self.logs.lock().unwrap();
                let held = logs.entry(key(log)).or_default();
                // As the Worker: a higher version replaces, the same version
                // with the same body is ok, anything else conflicts.
                match held.directory.get(&entry) {
                    Some((current, held_digest, _))
                        if *current > version
                            || (*current == version && *held_digest != digest) =>
                    {
                        return refuse(id, Refusal::Conflict);
                    }
                    Some((current, _, _)) if *current == version => {}
                    _ => {
                        held.directory.insert(entry, (version, digest, body));
                    }
                }
                Step::Frames(
                    vec![Response::DirectoryEntryStored { id }],
                    permit.deadline_ms,
                )
            }
            Request::ReadDirectory { id, permit, after } => {
                let permit = match self.verify(&permit) {
                    Ok(p) => p,
                    Err(reason) => return refuse(id, reason),
                };
                let Scope::ReadDirectory { log } = permit.scope else {
                    return refuse(id, Refusal::Scope);
                };
                self.directory_reads.fetch_add(1, Ordering::SeqCst);
                let logs = self.logs.lock().unwrap();
                let rows: Vec<Vec<u8>> = logs
                    .get(&key(log))
                    .map(|held| {
                        held.directory
                            .iter()
                            .filter(|(entry, _)| after.is_none_or(|after| **entry > after))
                            .take(65)
                            .map(|(_, (_, _, bytes))| bytes.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                let more = rows.len() > 64;
                Step::Frames(
                    vec![Response::Directory {
                        id,
                        entries: rows.into_iter().take(64).collect(),
                        more,
                    }],
                    permit.deadline_ms,
                )
            }
            Request::RetireHomeObjects { id, .. } => refuse(id, Refusal::Unavailable),
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
                        OpaqueEvent::new(event.nonce(), envelope).unwrap()
                    } else {
                        event.clone()
                    };
                    let route = if fault == ProofFault::Route {
                        Route::Control
                    } else {
                        Route::Content
                    };
                    let forged =
                        Commitment::order(BaseId(log.id), original.before(), &changed, route)
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
        let socket = self.data_sockets.fetch_add(1, Ordering::SeqCst) + 1;
        self.data_sockets_live.lock().unwrap().insert(socket);
        self.data_requests
            .lock()
            .unwrap()
            .insert(socket, (who, 0, 0));
        let _live = LiveData(self.clone(), socket);
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
                                Ok(Scope::ReadControls { .. } | Scope::ReadControlRange { .. }) => {
                                    Count::ReadControls
                                }
                                _ => Count::ReadEvents,
                            },
                            _ => Count::OtherRequests,
                        },
                        usize::from(!matches!(request, Request::StoreHomeObjects { .. })),
                    );
                    let arriving = match &request {
                        Request::Append { event, permit, .. } => Some((event, permit)),
                        Request::Publish {
                            event,
                            append_permit,
                            ..
                        } => Some((event, append_permit)),
                        _ => None,
                    };
                    if let Some((event, signed)) = arriving
                        && let Ok(event) = OpaqueEvent::decode(event)
                        && let Ok(permit) = edge.verify(signed)
                        && let Scope::Append { after, .. } = permit.scope
                    {
                        let route = if after.is_some() {
                            Route::Control
                        } else {
                            Route::Content
                        };
                        edge.note(Seen::Arrived {
                            event: event.publication_id(route),
                        });
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
            // A lane that opens a socket for one piece of work is named by
            // its requests: one that only reads account evidence is the
            // removal lane's link, used by one check at a time.
            let evidence = match &request {
                Request::Read { permit, .. } => self.verify(permit).is_ok_and(|permit| {
                    matches!(
                        permit.scope,
                        Scope::ReadEvents { log, .. } if log.kind == LogKind::Account
                    )
                }),
                _ => false,
            };
            {
                let mut sockets = self.data_requests.lock().unwrap();
                let entry = sockets.entry(socket).or_insert((who, 0, 0));
                entry.1 += 1;
                entry.2 += usize::from(!evidence);
            }
            if evidence && self.refuse_evidence.swap(false, Ordering::SeqCst) {
                self.evidence_refused.fetch_add(1, Ordering::SeqCst);
                let Request::Read { id, .. } = &request else {
                    unreachable!("only a read carries evidence")
                };
                let _ = out.send((
                    now,
                    Response::Refused {
                        id: *id,
                        reason: Refusal::Unavailable,
                    },
                ));
                continue;
            }
            // Bodies name the content link that read them; an account-evidence
            // socket asks for events only, so no evidence lane joins this.
            if let Request::Read { permit, .. } = &request
                && let Ok(permit) = self.verify(permit)
                && let Scope::ReadBodies { bodies, .. } = permit.scope
            {
                let mut requests = self.body_requests.lock().unwrap();
                for body in bodies {
                    requests.push((body, socket, who));
                }
            }
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

/// A DATA socket the edge is serving: its live entry ends with the socket,
/// including when the task that serves it is aborted.
struct LiveData(Arc<Edge>, usize);
impl Drop for LiveData {
    fn drop(&mut self) {
        self.0.data_sockets_live.lock().unwrap().remove(&self.1);
    }
}

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
        Request::ReadDirectory { .. } => "ReadDirectory",
        Request::StoreDirectoryEntry { .. } => "StoreDirectoryEntry",
        Request::RetireHomeObjects { .. } => "RetireHomeObjects",
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
        Response::Directory { .. } => "Directory",
        Response::DirectoryEntryStored { .. } => "DirectoryEntryStored",
        Response::HomeObjectsRetired { .. } => "HomeObjectsRetired",
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
        | Response::Directory { id, .. }
        | Response::DirectoryEntryStored { id }
        | Response::HomeObjectsRetired { id }
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
            let (log, first, last, sparse) = match permit.scope {
                Scope::ReadEvents { log, first, last } => (log, first, last, None),
                Scope::ReadControls { log, after } => {
                    (log, after.saturating_add(1), u64::MAX, Some((after, None)))
                }
                Scope::ReadControlRange {
                    log,
                    after,
                    through,
                } => (
                    log,
                    after.saturating_add(1),
                    through,
                    Some((after, Some(through))),
                ),
                _ => return Err(EdgeError::Refused),
            };
            // The selected-read trace measures finite read windows used by
            // cursor/resume tests; an unbounded control probe is not one.
            if !matches!(sparse, Some((_, None))) {
                self.selected_reads.lock().unwrap().push((log, first, last));
            }
            if log.kind == LogKind::Base {
                self.mark("checker selects base events");
            }
            if let Some((after, through)) = sparse {
                let (items, coverage) = self.sparse_control_snapshot(log, after, through)?;
                return Ok(bh_authz::LogRead {
                    items,
                    receipt: None,
                    coverage: Some(coverage),
                });
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
            Ok(bh_authz::LogRead {
                items,
                receipt,
                coverage: None,
            })
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
            let entry = logs.get(&key(log)).ok_or(EdgeError::Refused)?;
            // Ordered bodies, and an account log's staging ones, which only
            // the service's own permits can read.
            bodies
                .iter()
                .map(|b| {
                    entry
                        .bodies
                        .get(b)
                        .or_else(|| {
                            (log.kind == LogKind::Account)
                                .then(|| entry.staged.get(b))
                                .flatten()
                        })
                        .cloned()
                        .ok_or(EdgeError::Refused)
                })
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
                Scope::ReadControls { log, after } => {
                    (log, true, after.saturating_add(1), u64::MAX)
                }
                Scope::ReadControlRange {
                    log,
                    after,
                    through,
                } => (log, true, after.saturating_add(1), through),
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
struct FixtureNoPolicy;
impl PolicyStore for FixtureNoPolicy {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, ()> {
        Err(())
    }
    fn save(&mut self, _: &Snapshot) -> Result<(), ()> {
        Err(())
    }
}

pub struct Hosted {
    pub edge: Arc<Edge>,
    relay: Arc<FakeRelay>,
    service: Mutex<Service>,
    /// Held by a restart from the moment it retires the current service until
    /// its replacement is in place, and by a connecting client while it binds
    /// and registers one, so no connection binds the instance being retired.
    restart: tokio::sync::Mutex<()>,
    /// Only this account receives test-root-certified alternate answers.
    hostile_account: Mutex<Option<LogId>>,
    /// Keep claiming the same served alternate head on later empty pages.
    consistent_served: AtomicBool,
    omit_account: Mutex<Option<(LogId, u64, u64)>>,
    corrupt_accepted: Mutex<Option<(LogId, bool)>>,
    refuse_permits: AtomicBool,
    refuse_authenticate: AtomicBool,
    forced_not_active: AtomicUsize,
    /// Conceal ordinary NotActive replies while leaving public evidence intact,
    /// to exercise the removal lane's deadline timer without a refusal wake.
    mask_not_active: AtomicBool,
    wrong_predecessor: Mutex<Option<(LogId, u64)>>,
    ahead_corruption: Mutex<Option<(LogId, u64, bool)>>,
    first_page_claim: Mutex<Option<(LogId, u64, Vec<u8>)>>,
    matched_page_claim: Mutex<Option<(LogId, u64, Vec<u8>)>>,
    foreign_root: Mutex<Option<LogId>>,
    other_challenge: Mutex<Option<LogId>>,
    /// Answers to `ConfirmControl` still to be lost after the service
    /// handled them, and how the next ones are altered.
    lose_confirm_answers: AtomicUsize,
    /// Answers to `SubmitControl` still to be lost after the service
    /// handled them.
    lose_submit_answers: AtomicUsize,
    /// Answers to `Recover` still to be lost after the service judged
    /// them.
    lose_recover_answers: AtomicUsize,
    /// A full notice page is answered; every subsequent notice read loses
    /// its connection before an answer, including retries.
    drop_notices_after_first: AtomicBool,
    notice_requests: AtomicUsize,
    confirm_tamper: Mutex<Option<ConfirmTamper>>,
    /// Refuse every `SubmitControl` for this reason, unhandled.
    refuse_submits: Mutex<Option<bh_authz::proto::Refusal>>,
    /// How a released recovery answer is altered before a device sees it.
    recovery_tamper: Mutex<Option<RecoveryTamper>>,
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
            restart: tokio::sync::Mutex::new(()),
            hostile_account: Mutex::new(None),
            consistent_served: AtomicBool::new(false),
            omit_account: Mutex::new(None),
            corrupt_accepted: Mutex::new(None),
            refuse_permits: AtomicBool::new(false),
            refuse_authenticate: AtomicBool::new(false),
            forced_not_active: AtomicUsize::new(0),
            mask_not_active: AtomicBool::new(false),
            wrong_predecessor: Mutex::new(None),
            ahead_corruption: Mutex::new(None),
            first_page_claim: Mutex::new(None),
            matched_page_claim: Mutex::new(None),
            foreign_root: Mutex::new(None),
            other_challenge: Mutex::new(None),
            lose_confirm_answers: AtomicUsize::new(0),
            lose_submit_answers: AtomicUsize::new(0),
            lose_recover_answers: AtomicUsize::new(0),
            drop_notices_after_first: AtomicBool::new(false),
            notice_requests: AtomicUsize::new(0),
            confirm_tamper: Mutex::new(None),
            refuse_submits: Mutex::new(None),
            recovery_tamper: Mutex::new(None),
            policy_root,
            config,
            dir,
        })
    }
    pub fn omit_account_confirmation(&self, log: LogId, position: u64) {
        assert_eq!(log.kind, LogKind::Account);
        self.omit_account_proof_range(log, position, position);
    }
    pub fn omit_account_proof_range(&self, log: LogId, first: u64, last: u64) {
        assert_eq!(log.kind, LogKind::Account);
        assert!(first >= 2 && first <= last);
        *self.omit_account.lock().unwrap() = Some((log, first, last));
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    pub fn refuse_permits_not_active(&self, refuse: bool) {
        self.refuse_permits.store(refuse, Ordering::SeqCst);
    }
    pub fn refuse_authenticate_not_active(&self, refuse: bool) {
        self.refuse_authenticate.store(refuse, Ordering::SeqCst);
    }
    pub fn forced_not_active_count(&self) -> usize {
        self.forced_not_active.load(Ordering::SeqCst)
    }
    pub fn mask_not_active(&self) {
        self.mask_not_active.store(true, Ordering::SeqCst);
        self.close_fixture_connections();
    }
    pub fn corrupt_accepted_account(&self, log: LogId, bad_hash: bool) {
        assert_eq!(log.kind, LogKind::Account);
        *self.corrupt_accepted.lock().unwrap() = Some((log, bad_hash));
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    pub fn wrong_account_predecessor(&self, log: LogId, position: u64) {
        *self.wrong_predecessor.lock().unwrap() = Some((log, position));
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    pub fn corrupt_ahead_account_claim(&self, log: LogId, position: u64, bad_hash: bool) {
        *self.ahead_corruption.lock().unwrap() = Some((log, position, bad_hash));
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    pub fn corrupt_terminal_account_claim(&self, log: LogId, position: u64, bad_hash: bool) {
        *self.ahead_corruption.lock().unwrap() = Some((log, position, bad_hash));
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    pub fn first_account_page_claim(&self, log: LogId, position: u64, proof: Vec<u8>) {
        *self.first_page_claim.lock().unwrap() = Some((log, position, proof));
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    pub fn matched_account_page_claim(&self, log: LogId, position: u64, proof: Vec<u8>) {
        *self.matched_page_claim.lock().unwrap() = Some((log, position, proof));
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    /// Account confirmations re-signed by a key certified under another
    /// hosting root, claims unchanged.
    pub fn foreign_root_account_confirmations(&self, log: LogId) {
        *self.foreign_root.lock().unwrap() = Some(log);
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    /// The honest accepted head, signed for a challenge the reader never sent.
    pub fn accepted_account_head_for_other_challenge(&self, log: LogId) {
        *self.other_challenge.lock().unwrap() = Some(log);
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    /// The service's next `ConfirmControl` answer is lost on its way back:
    /// the socket drops once the service has handled it.
    pub fn lose_next_confirm_answer(&self) {
        self.lose_confirm_answers.fetch_add(1, Ordering::SeqCst);
        self.close_fixture_connections();
    }
    /// The service's next `SubmitControl` answer is lost on its way back:
    /// the socket drops once the service has handled it.
    pub fn lose_next_submit_answer(&self) {
        self.lose_submit_answers.fetch_add(1, Ordering::SeqCst);
        self.close_fixture_connections();
    }
    /// The service's next `Recover` answer is lost on its way back: the
    /// socket drops once the service has judged the claim.
    /// Seed successive home notices for a test of a full read page. No
    /// device or account change is ordered by this fixture operation.
    pub fn seed_notices(&self, account: bh_account::AccountId, from_ms: u64, count: u64) {
        let mut db = rusqlite::Connection::open(self.dir.path().join("authz-0.sqlite")).unwrap();
        let tx = db.transaction().unwrap();
        for offset in 0..count {
            tx.execute(
                "INSERT INTO recovery_notices(account,time_ms) VALUES(?1,?2)",
                rusqlite::params![account.0.as_slice(), (from_ms + offset) as i64],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    pub fn drop_notices_after_first(&self) {
        self.notice_requests.store(0, Ordering::SeqCst);
        self.drop_notices_after_first.store(true, Ordering::SeqCst);
        self.close_fixture_connections();
    }
    pub fn notice_attempts(&self) -> usize {
        self.notice_requests.load(Ordering::SeqCst)
    }
    pub fn lose_next_recover_answer(&self) {
        self.lose_recover_answers.fetch_add(1, Ordering::SeqCst);
        self.close_fixture_connections();
    }
    /// Alter every `ConfirmControl` answer from now on, or stop altering.
    pub fn tamper_confirmations(&self, tamper: Option<ConfirmTamper>) {
        *self.confirm_tamper.lock().unwrap() = tamper;
        self.close_fixture_connections();
    }
    /// Alter every released recovery answer, as a home that lies about the
    /// account's objects would.
    pub fn tamper_recovery(&self, tamper: Option<RecoveryTamper>) {
        *self.recovery_tamper.lock().unwrap() = tamper;
        self.close_fixture_connections();
    }
    /// Refuse every trust control submitted from now on for `reason`, as a
    /// home that will not order them, or stop refusing.
    pub fn refuse_submits(&self, reason: Option<bh_authz::proto::Refusal>) {
        *self.refuse_submits.lock().unwrap() = reason;
        self.close_fixture_connections();
    }
    fn intercepting(&self) -> bool {
        self.mask_not_active.load(Ordering::SeqCst)
            || self.hostile_account.lock().unwrap().is_some()
            || self.lose_confirm_answers.load(Ordering::SeqCst) > 0
            || self.lose_submit_answers.load(Ordering::SeqCst) > 0
            || self.lose_recover_answers.load(Ordering::SeqCst) > 0
            || self.drop_notices_after_first.load(Ordering::SeqCst)
            || self.confirm_tamper.lock().unwrap().is_some()
            || self.refuse_submits.lock().unwrap().is_some()
            || self.recovery_tamper.lock().unwrap().is_some()
    }
    pub fn restore_account_confirmations(&self) {
        *self.omit_account.lock().unwrap() = None;
        *self.corrupt_accepted.lock().unwrap() = None;
        *self.wrong_predecessor.lock().unwrap() = None;
        *self.ahead_corruption.lock().unwrap() = None;
        *self.first_page_claim.lock().unwrap() = None;
        *self.matched_page_claim.lock().unwrap() = None;
        *self.foreign_root.lock().unwrap() = None;
        *self.other_challenge.lock().unwrap() = None;
        *self.hostile_account.lock().unwrap() = None;
        self.close_fixture_connections();
    }
    /// The hostile home certifies the edge's served alternate account bytes
    /// for this log only. Normal traffic still uses the real Service.
    pub fn confirm_served_account(&self, log: LogId) {
        assert_eq!(log.kind, LogKind::Account);
        *self.hostile_account.lock().unwrap() = Some(log);
        self.close_fixture_connections();
    }
    pub fn keep_served_account_head(&self) {
        self.consistent_served.store(true, Ordering::SeqCst);
    }
    pub fn confirm_ordered_account(&self) {
        *self.hostile_account.lock().unwrap() = None;
        self.close_fixture_connections();
    }
    fn close_fixture_connections(&self) {
        for task in self.edge.sockets.lock().unwrap().drain(..) {
            task.abort();
        }
    }
    /// A scoped test-only attested channel: the real Connection handles all
    /// requests; only its selected account evidence is replaced by coherent
    /// evidence of the alternate DATA bytes, certified by this fixture root.
    async fn serve_hostile_connection(
        &self,
        mut ws: WebSocketStream<tokio::io::DuplexStream>,
        service: Service,
    ) -> Result<(), ()> {
        let start = std::time::Instant::now();
        let now = move || start.elapsed().as_millis() as u64;
        let hello = ws.next().await.ok_or(())?.map_err(|_| ())?.into_data();
        let pending =
            ServerPending::<FixtureNoPolicy>::accept_hello(&hello, self.config.app_root, now())
                .map_err(|_| ())?;
        let evidence = SyntheticAttestation
            .evidence(pending.report_data())
            .await
            .map_err(|_| ())?;
        let (proof, pending) = pending
            .attach_evidence(
                &self.config.policy,
                &self.config.policy_signature,
                &evidence.quote,
                &evidence.collateral,
                &evidence.event_log,
                now(),
            )
            .map_err(|_| ())?;
        ws.send(Message::Binary(proof.into()))
            .await
            .map_err(|_| ())?;
        let encapsulation = ws.next().await.ok_or(())?.map_err(|_| ())?.into_data();
        let (finish, pending) = pending
            .accept_encapsulation(&encapsulation, now())
            .map_err(|_| ())?;
        ws.send(Message::Binary(finish.into()))
            .await
            .map_err(|_| ())?;
        let confirm = ws.next().await.ok_or(())?.map_err(|_| ())?.into_data();
        let mut session = pending
            .accept_finish(&confirm, move || Sample {
                system_seconds: None,
                monotonic_ms: now(),
            })
            .map_err(|_| ())?;
        let (mut connection, challenge) = service.connect(session.binding().map_err(|_| ())?);
        ws.send(Message::Binary(
            session
                .seal(SecretBytes::from_vec(challenge.encode().map_err(|_| ())?))
                .map_err(|_| ())?
                .into(),
        ))
        .await
        .map_err(|_| ())?;
        while let Some(frame) = ws.next().await {
            let frame = frame.map_err(|_| ())?;
            if matches!(frame, Message::Close(_)) {
                break;
            }
            let Message::Binary(bytes) = frame else {
                continue;
            };
            let Opened::Data(plain) = session.open(&bytes).map_err(|_| ())? else {
                break;
            };
            let request = ToService::decode(plain.expose()).map_err(|_| ())?;
            if matches!(request, ToService::ReadNotices { .. })
                && self.drop_notices_after_first.load(Ordering::SeqCst)
                && self.notice_requests.fetch_add(1, Ordering::SeqCst) > 0
            {
                return Err(());
            }
            let answer = if (matches!(request, ToService::Permits { .. })
                && self.refuse_permits.load(Ordering::SeqCst))
                || (matches!(request, ToService::Authenticate { .. })
                    && self.refuse_authenticate.load(Ordering::SeqCst))
            {
                self.forced_not_active.fetch_add(1, Ordering::SeqCst);
                FromService::Refused {
                    reason: bh_authz::proto::Refusal::NotActive,
                }
            } else if let (ToService::SubmitControl { event, .. }, Some(reason)) =
                (&request, *self.refuse_submits.lock().unwrap())
            {
                self.edge.submitted.lock().unwrap().push(event.clone());
                FromService::Refused { reason }
            } else {
                connection.handle(request.clone()).await
            };
            let answer = self.hostile_answer(&request, answer);
            // Keep ordinary sessions from sending the NotActive signal in
            // the timer-only removal test. Unauthenticated is still a
            // refusal, and does not falsify the public account evidence.
            let answer = if self.mask_not_active.load(Ordering::SeqCst)
                && matches!(
                    answer,
                    FromService::Refused {
                        reason: bh_authz::proto::Refusal::NotActive
                    }
                ) {
                FromService::Refused {
                    reason: bh_authz::proto::Refusal::Unauthenticated,
                }
            } else {
                answer
            };
            let lost = match request {
                ToService::ConfirmControl { .. } => Some(&self.lose_confirm_answers),
                ToService::SubmitControl { .. } => Some(&self.lose_submit_answers),
                ToService::Recover { .. } => Some(&self.lose_recover_answers),
                _ => None,
            };
            if lost.is_some_and(|lost| {
                lost.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok()
            }) {
                return Err(());
            }
            let sealed = session
                .seal(SecretBytes::from_vec(answer.encode().map_err(|_| ())?))
                .map_err(|_| ())?;
            ws.send(Message::Binary(sealed.into()))
                .await
                .map_err(|_| ())?;
        }
        Ok(())
    }
    fn hostile_answer(&self, request: &ToService, honest: FromService) -> FromService {
        if let (ToService::Recover { .. }, FromService::Recovery(answer)) = (request, &honest)
            && let Some(tamper) = self.recovery_tamper.lock().unwrap().as_ref()
        {
            let mut answer = answer.clone();
            tamper(&mut answer);
            return FromService::Recovery(answer);
        }
        if let ToService::ConfirmControl { log, challenge, .. } = request {
            return self.tampered_confirmation(*log, challenge, honest);
        }
        let ToService::ReadAccountEvidence {
            genesis,
            first,
            last,
            challenge,
        } = request
        else {
            return honest;
        };
        let Some(log) = *self.hostile_account.lock().unwrap() else {
            return honest;
        };
        if bh_authz::proto::account_log_id(genesis).ok() != Some(log.id) {
            return honest;
        }
        let FromService::AccountEvidence {
            events_permit,
            mut confirmations,
            head: honest_head,
        } = honest
        else {
            return honest;
        };
        if let Some((selected, position)) = *self.wrong_predecessor.lock().unwrap()
            && selected == log
            && *first <= position
            && position <= *last
        {
            let index = confirmations
                .iter()
                .position(|p| {
                    OrderingConfirmation::decode(p)
                        .unwrap()
                        .claim()
                        .original_head
                        .position
                        == position
                })
                .unwrap();
            let old = OrderingConfirmation::decode(&confirmations[index]).unwrap();
            let mut claim = *old.claim();
            claim.original_previous.hash.0[0] ^= 1;
            let proof = OrderingConfirmation::sign(
                &self.edge.permit_key,
                &self.edge.permit_certificate,
                claim,
            );
            confirmations[index] = proof.encode().to_vec();
            let head = AcceptedHead::sign(
                &self.edge.permit_key,
                &self.edge.permit_certificate,
                log,
                *challenge,
                claim.original_head,
                proof.commitment(),
                claim.bounds,
            );
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head,
            };
        }
        if let Some((selected, position, bad_hash)) = *self.ahead_corruption.lock().unwrap()
            && selected == log
            && (*last < position || *first > position)
        {
            let claim =
                AcceptedHead::verify(&honest_head, &self.edge.root(), log, challenge).unwrap();
            assert_eq!(claim.original_head.position, position);
            let mut original_head = claim.original_head;
            let mut evidence = claim.evidence;
            if bad_hash {
                original_head.hash.0[0] ^= 1;
            } else {
                evidence[0] ^= 1;
            }
            let head = AcceptedHead::sign(
                &self.edge.permit_key,
                &self.edge.permit_certificate,
                log,
                *challenge,
                original_head,
                evidence,
                claim.bounds,
            );
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head,
            };
        }
        if let Some((selected, position, ref bytes)) = *self.first_page_claim.lock().unwrap()
            && selected == log
            && *last < position
        {
            let proof = OrderingConfirmation::decode(bytes).unwrap();
            proof.verify(&self.edge.root()).unwrap();
            assert_eq!(proof.claim().original_head.position, position);
            let head = AcceptedHead::sign(
                &self.edge.permit_key,
                &self.edge.permit_certificate,
                log,
                *challenge,
                proof.claim().original_head,
                proof.commitment(),
                proof.claim().bounds,
            );
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head,
            };
        }
        if let Some((selected, position, ref bytes)) = *self.matched_page_claim.lock().unwrap()
            && selected == log
            && *first <= position
            && position <= *last
        {
            let proof = OrderingConfirmation::decode(bytes).unwrap();
            proof.verify(&self.edge.root()).unwrap();
            assert_eq!(proof.claim().original_head.position, position);
            let head = AcceptedHead::sign(
                &self.edge.permit_key,
                &self.edge.permit_certificate,
                log,
                *challenge,
                proof.claim().original_head,
                proof.commitment(),
                proof.claim().bounds,
            );
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head,
            };
        }
        if *self.foreign_root.lock().unwrap() == Some(log) {
            let root = SigningKey::generate();
            let key = SigningKey::generate();
            let certificate = permit::certify(&root, key.public());
            let confirmations = confirmations
                .iter()
                .map(|bytes| {
                    let old = OrderingConfirmation::decode(bytes).unwrap();
                    OrderingConfirmation::sign(&key, &certificate, *old.claim())
                        .encode()
                        .to_vec()
                })
                .collect();
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head: honest_head,
            };
        }
        if *self.other_challenge.lock().unwrap() == Some(log) {
            let claim =
                AcceptedHead::verify(&honest_head, &self.edge.root(), log, challenge).unwrap();
            let mut other = *challenge;
            other[0] ^= 1;
            let head = AcceptedHead::sign(
                &self.edge.permit_key,
                &self.edge.permit_certificate,
                log,
                other,
                claim.original_head,
                claim.evidence,
                claim.bounds,
            );
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head,
            };
        }
        if let Some((selected, bad_hash)) = *self.corrupt_accepted.lock().unwrap()
            && selected == log
        {
            let claim =
                AcceptedHead::verify(&honest_head, &self.edge.root(), log, challenge).unwrap();
            let mut original_head = claim.original_head;
            let mut evidence = claim.evidence;
            if bad_hash {
                original_head.hash.0[0] ^= 1;
            } else {
                evidence[0] ^= 1;
            }
            let head = AcceptedHead::sign(
                &self.edge.permit_key,
                &self.edge.permit_certificate,
                log,
                *challenge,
                original_head,
                evidence,
                claim.bounds,
            );
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head,
            };
        }
        if let Some((selected, withheld_first, withheld_last)) = *self.omit_account.lock().unwrap()
            && selected == log
            && *first <= withheld_last
            && *last >= withheld_first
        {
            confirmations.retain(|bytes| {
                !(withheld_first..=withheld_last).contains(
                    &OrderingConfirmation::decode(bytes)
                        .unwrap()
                        .claim()
                        .original_head
                        .position,
                )
            });
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head: honest_head,
            };
        }
        let (from, served) = {
            let logs = self.edge.logs.lock().unwrap();
            let Some((from, served)) = logs.get(&key(log)).and_then(|state| state.served.as_ref())
            else {
                return FromService::AccountEvidence {
                    events_permit,
                    confirmations,
                    head: honest_head,
                };
            };
            (*from, served.clone())
        };
        let follow_served = self.consistent_served.load(Ordering::SeqCst) && *first > from;
        if !(*first <= from && from <= *last) && !follow_served {
            // Non-targeted reads are ordinary real-service responses.
            return FromService::AccountEvidence {
                events_permit,
                confirmations,
                head: honest_head,
            };
        }
        assert_eq!(
            served.len(),
            1,
            "scoped hostile fixture serves exactly one successor"
        );
        let (outer, wrapper) = &served[0];
        let (original, body) = bh_authz::proto::account_log_unwrap(wrapper).unwrap();
        let position = outer.head().position;
        assert_eq!(position, from);
        // Even the deliberately unsupported version has the fixed signed
        // header: 23-byte domain, two 2-byte versions, position, predecessor.
        let previous = Head {
            position: position - 1,
            hash: Digest(original[35..67].try_into().expect("signed predecessor")),
        };
        let inner = Head {
            position,
            hash: Digest(bh_crypto::hash(original)),
        };
        let at = self.edge.clock.now();
        let bounds = TimeBounds {
            earliest_ms: at,
            latest_ms: at,
        };
        let confirmation = OrderingConfirmation::sign(
            &self.edge.permit_key,
            &self.edge.permit_certificate,
            ConfirmationClaim {
                log,
                original: original_digest(original),
                original_previous: previous,
                original_head: inner,
                body,
                ordered: outer.head(),
                bounds,
            },
        );
        if follow_served {
            // This is an empty later page. Re-sign the same alternate head
            // instead of switching back to the honest account at this seam.
            confirmations.clear();
        } else {
            confirmations.retain(|p| {
                OrderingConfirmation::decode(p)
                    .unwrap()
                    .claim()
                    .original_head
                    .position
                    != position
            });
            confirmations.push(confirmation.encode().to_vec());
        }
        let head = AcceptedHead::sign(
            &self.edge.permit_key,
            &self.edge.permit_certificate,
            log,
            *challenge,
            inner,
            confirmation.commitment(),
            bounds,
        );
        FromService::AccountEvidence {
            events_permit,
            confirmations,
            head,
        }
    }
    /// A `ConfirmControl` answer as `tamper_confirmations` alters it: the
    /// confirmation re-signed under another hosting root, or the accepted
    /// head signed for a challenge the device never sent.
    fn tampered_confirmation(
        &self,
        log: LogId,
        challenge: &[u8; 32],
        honest: FromService,
    ) -> FromService {
        let tamper = *self.confirm_tamper.lock().unwrap();
        let (Some(tamper), FromService::Confirmed { confirmation, head }) = (tamper, &honest)
        else {
            return honest;
        };
        match tamper {
            ConfirmTamper::Root => {
                let old = OrderingConfirmation::decode(confirmation).unwrap();
                let root = SigningKey::generate();
                let key = SigningKey::generate();
                let certificate = permit::certify(&root, key.public());
                FromService::Confirmed {
                    confirmation: OrderingConfirmation::sign(&key, &certificate, *old.claim())
                        .encode()
                        .to_vec(),
                    head: head.clone(),
                }
            }
            ConfirmTamper::Challenge => {
                let claim = AcceptedHead::verify(head, &self.edge.root(), log, challenge).unwrap();
                let mut other = *challenge;
                other[0] ^= 1;
                FromService::Confirmed {
                    confirmation: confirmation.clone(),
                    head: AcceptedHead::sign(
                        &self.edge.permit_key,
                        &self.edge.permit_certificate,
                        log,
                        other,
                        claim.original_head,
                        claim.evidence,
                        claim.bounds,
                    ),
                }
            }
        }
    }
    /// Provision a fixture device from the real service's confirmed account
    /// history. Production admission uses the bounded network reader instead.
    pub async fn confirmed_account(&self, log: LogId) -> Vec<bh_sync_client::TimedOriginal> {
        use bh_authz::proto::FromService;
        use bh_sync::evidence::{AcceptedHead, OrderingConfirmation};
        let entries = self.edge.entries(log);
        let genesis = bh_authz::proto::account_log_unwrap(&entries[0].1)
            .unwrap()
            .0
            .to_vec();
        let service = self.service.lock().unwrap().clone();
        let (mut connection, _) = service.connect([0; 32]);
        let mut history = Vec::new();
        for chunk in entries.chunks(64) {
            let first = chunk[0].0.head().position;
            let last = chunk.last().unwrap().0.head().position;
            let challenge = bh_crypto::random();
            let answer = connection
                .handle(ToService::ReadAccountEvidence {
                    genesis: genesis.clone(),
                    first,
                    last,
                    challenge,
                })
                .await;
            let FromService::AccountEvidence {
                confirmations,
                head,
                ..
            } = answer
            else {
                panic!("fixture account evidence refused: {answer:?}");
            };
            AcceptedHead::verify(&head, &self.edge.root(), log, &challenge).unwrap();
            let mut proofs = confirmations.into_iter();
            for (commitment, wrapper) in chunk {
                let (original, body) = bh_authz::proto::account_log_unwrap(wrapper).unwrap();
                let evidence = if commitment.head().position == 1 {
                    None
                } else {
                    let bytes = proofs.next().expect("every original confirmed");
                    let proof = OrderingConfirmation::decode(&bytes).unwrap();
                    let claim = proof.verify_for(&self.edge.root(), original, body).unwrap();
                    assert_eq!(claim.log, log);
                    assert_eq!(claim.ordered, commitment.head());
                    Some((
                        bh_account::ConfirmedTime {
                            earliest_ms: claim.bounds.earliest_ms,
                            latest_ms: claim.bounds.latest_ms,
                        },
                        bytes,
                    ))
                };
                history.push((original.to_vec(), evidence));
            }
            assert!(proofs.next().is_none());
        }
        history
    }

    fn service(edge: &Arc<Edge>, path: &std::path::Path) -> Service {
        let permit_key = SigningKey::generate();
        let certificate = permit::certify(&edge.root, permit_key.public());
        let service = Service::open_with_recovery(
            path,
            PermitKeys::new(permit_key, certificate).unwrap(),
            bh_authz::RecoveryHomeKey::new(
                edge.recovery_key(),
                edge.recovery_certificate(),
                &edge.root(),
            )
            .unwrap(),
            edge.clock.clone(),
            edge.clone(),
        )
        .unwrap();
        let counted = edge.clone();
        service.observe(Arc::new(move |message| {
            counted.counters.request(message);
            match message {
                ToService::SubmitControl { event, .. } => {
                    counted.submitted.lock().unwrap().push(event.clone())
                }
                ToService::ConfirmControl { .. } => {
                    counted.confirm_asks.fetch_add(1, Ordering::SeqCst);
                }
                ToService::ReadNotices { .. } => {
                    counted.notice_reads.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
            counted.mark(match message {
                ToService::Permits { .. } => "service: Permits request begins",
                ToService::ReadBatch { .. } => "service: ReadBatch request begins",
                _ => "service: other request begins",
            });
        }));
        service
    }
    /// Restart the authorization service on its current protected disk,
    /// preserving recovery tries and acknowledged account history.
    pub async fn restart_service(&self) {
        let _restart = self.restart.lock().await;
        let tasks: Vec<_> = self.edge.sockets.lock().unwrap().drain(..).collect();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        let path = self.dir.path().join("authz-0.sqlite");
        assert!(path.exists());
        *self.service.lock().unwrap() = Self::service(&self.edge, &path);
        self.edge.presence.lock().unwrap().sockets.clear();
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
    /// Lose the base registry only, preserving acknowledged account history
    /// and its exact confirmations. An empty account disk would re-confirm
    /// old entries at new times, a different failure from a missing base.
    pub async fn restart_service_without_bases(&self) {
        // A client reconnecting during the restart waits here and binds the
        // replacement, as it would from a process that stopped accepting
        // connections before it exited.
        let _restart = self.restart.lock().await;
        let tasks: Vec<_> = self.edge.sockets.lock().unwrap().drain(..).collect();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        let path = self.dir.path().join("authz-0.sqlite");
        assert!(path.exists());
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(
            "BEGIN IMMEDIATE;
             DELETE FROM base_pending;
             DELETE FROM base_account_changes;
             DELETE FROM base_controls;
             DELETE FROM bases;
             COMMIT;",
        )
        .unwrap();
        *self.service.lock().unwrap() = Self::service(&self.edge, &path);
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
/// How a home alters a recovery answer it serves.
pub type RecoveryTamper = Box<dyn Fn(&mut bh_authz::proto::RecoveryAnswer) + Send + Sync>;
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
            // Binding is atomic with respect to a restart, including being
            // registered for the restart's drain, so a client that connects
            // while the service is retired takes its replacement instead.
            let restart = match route {
                Path::Authz => Some(self.0.restart.lock().await),
                Path::Data => None,
            };
            let task = match route {
                Path::Data => tokio::spawn(self.0.edge.clone().serve_data(server, self.1)),
                Path::Authz => {
                    let hosted = self.0.clone();
                    let service = hosted.service.lock().unwrap().clone();
                    tokio::spawn(async move {
                        if hosted.intercepting() {
                            let _ = hosted.serve_hostile_connection(server, service).await;
                        } else {
                            let _ = service
                                .serve_connection(server, &hosted.config, &SyntheticAttestation)
                                .await;
                        }
                    })
                }
            };
            self.0.edge.sockets.lock().unwrap().push(task);
            drop(restart);
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
