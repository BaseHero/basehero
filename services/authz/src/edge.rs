//! Reading account-home logs and base controls through the edge's data
//! socket, under permits the service issues itself.
use bh_sync::{
    Digest,
    receipt::RECEIPT_LEN,
    wire::{CoverageEndpoint, MAX_FRAME_LEN, Request, Response},
};
use futures_util::{SinkExt, StreamExt, future::BoxFuture};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_tungstenite::{
    Connector, connect_async_tls_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeError {
    /// The edge could not be reached or did not answer in time.
    Unavailable,
    /// The edge refused the read.
    Refused,
    /// The answer was not a well-formed answer to the read.
    Malformed,
}
impl std::fmt::Display for EdgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "edge: {self:?}")
    }
}
impl std::error::Error for EdgeError {}

/// `(commitment, event)` encodings in log order.
pub type LogItems = Vec<(Vec<u8>, Vec<u8>)>;

/// Exact committed rows and the edge's original authenticated tail statement.
pub struct LogRead {
    pub items: LogItems,
    pub receipt: Option<[u8; RECEIPT_LEN]>,
    pub coverage: Option<CoverageEndpoint>,
}

/// Durable immutable private-object acknowledgement, with no append position.
/// The caller must match both digests against its verified prefix and bundle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HomeObjectsAck {
    pub prefix_digest: Digest,
    pub bundle_digest: Digest,
}
impl std::fmt::Debug for HomeObjectsAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HomeObjectsAck")
    }
}

/// Ordered-log reads and immutable private-object storage. No append positions.
pub trait EdgeReader: Send + Sync {
    /// The `(commitment, event)` encodings a ReadEvents or ReadControls permit
    /// selects, in log order; fewer than requested means the rest are past
    /// the head.
    fn read_log(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<LogItems, EdgeError>>;
    /// Adapters without receipt support must not manufacture an authenticated tail.
    fn read_log_with_receipt(&self, _permit: Vec<u8>) -> BoxFuture<'_, Result<LogRead, EdgeError>> {
        Box::pin(async { Err(EdgeError::Unavailable) })
    }
    /// The ordered bodies a ReadBodies permit names, in its order.
    fn read_bodies(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>>;
    /// Exact immutable write. An adapter without this capability fails closed.
    /// Resolve only after the account home's durable acknowledgement.
    fn store_home_objects(
        &self,
        _permit: Vec<u8>,
        _bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<HomeObjectsAck, EdgeError>> {
        Box::pin(async { Err(EdgeError::Unavailable) })
    }
    /// Idempotently retire the initial immutable home bundle after durable replacement.
    fn retire_home_objects(&self, _permit: Vec<u8>) -> BoxFuture<'_, Result<(), EdgeError>> {
        Box::pin(async { Err(EdgeError::Unavailable) })
    }
}

/// Sockets one client keeps open to the edge.
const MAX_SOCKETS: usize = 4;
/// Reads in flight on one socket: the edge's own per-socket bound.
const IN_FLIGHT: usize = 8;
/// Attempts when a socket closes before the answer. Reads and exact immutable
/// object writes are retry-safe; no append or general mutating request is sent.
const ATTEMPTS: usize = 2;
/// Longest wait for one socket's TCP, TLS and WebSocket upgrade.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The edge's `/v1/data` socket. Independent reads share a few sockets, up to
/// eight in flight on each, matched to their answers by request id; each
/// Events frame's length is granted back as credit once it is taken. No lock
/// is held across a network wait, so one slow read delays only itself.
pub struct EdgeClient {
    url: String,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
    pool: Mutex<Pool>,
    /// Woken when a slot frees, a socket opens or closes, or a connect ends.
    changed: Arc<Notify>,
}

#[derive(Default)]
struct Pool {
    sockets: Vec<Arc<Conn>>,
    connecting: usize,
}

/// A read's answer: one Events frame, or one Body frame per named body.
// Keep the exact fixed receipt inline with its Events answer, not behind an
// additional allocation for every read.
#[allow(clippy::large_enum_variant)]
enum Data {
    HomeObjects(HomeObjectsAck),
    Retired,
    Events(LogRead),
    Bodies(Vec<Vec<u8>>),
}
type Answer = Result<Data, EdgeError>;

/// A read waiting for its answer. Its slot stays taken until the answer
/// arrives or the socket closes, as the edge still counts it until then.
struct Pending {
    reply: Option<oneshot::Sender<Answer>>,
    /// The Body frames received so far, in index order.
    bodies: Vec<Vec<u8>>,
    _slot: Slot,
}

/// One socket's in-flight slot; freeing it wakes reads waiting for one.
struct Slot {
    _permit: OwnedSemaphorePermit,
    changed: Arc<Notify>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.changed.notify_waiters();
    }
}

struct Conn {
    slots: Arc<Semaphore>,
    next_id: AtomicU32,
    /// Frames for the writer task. The reader holds only a weak sender, so the
    /// socket closes once the pool and every read have let go of it.
    out: mpsc::UnboundedSender<Message>,
    shared: Arc<Shared>,
}

/// What a socket's reader task shares with the reads on it.
struct Shared {
    closed: AtomicBool,
    pending: Mutex<HashMap<u32, Pending>>,
    changed: Arc<Notify>,
}
impl Shared {
    /// No further reads; every pending read fails as Unavailable.
    fn close(&self) {
        let drained: Vec<Pending> = match self.pending.lock() {
            Ok(mut pending) => {
                self.closed.store(true, Ordering::SeqCst);
                pending.drain().map(|(_, p)| p).collect()
            }
            Err(_) => {
                self.closed.store(true, Ordering::SeqCst);
                vec![]
            }
        };
        for mut read in drained {
            if let Some(reply) = read.reply.take() {
                let _ = reply.send(Err(EdgeError::Unavailable));
            }
        }
        self.changed.notify_waiters();
    }
    fn answer(&self, id: u32, answer: Answer) {
        let read = self.pending.lock().ok().and_then(|mut p| p.remove(&id));
        if let Some(mut read) = read
            && let Some(reply) = read.reply.take()
        {
            let _ = reply.send(answer);
        }
    }
    /// Take one Body frame of a body read; the last one, or one out of
    /// order, answers it.
    fn body(&self, id: u32, index: u8, last: bool, bytes: Vec<u8>) {
        let answer = {
            let Ok(mut pending) = self.pending.lock() else {
                return;
            };
            let Some(read) = pending.get_mut(&id) else {
                return;
            };
            if usize::from(index) != read.bodies.len() {
                Some(Err(EdgeError::Malformed))
            } else {
                read.bodies.push(bytes);
                last.then(|| Ok(Data::Bodies(std::mem::take(&mut read.bodies))))
            }
        };
        if let Some(answer) = answer {
            self.answer(id, answer);
        }
    }
}

impl Conn {
    fn closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }
    /// Stop using this socket and close it; reads on it fail.
    fn retire(&self) {
        let _ = self.out.send(Message::Close(None));
        self.shared.close();
    }
}

/// A read sent on a socket. Dropped before its answer (the read timed out),
/// it retires the socket: the edge may still be working on it, and a stalled
/// socket takes no more reads.
struct InFlight {
    conn: Arc<Conn>,
    id: u32,
    done: bool,
}
impl Drop for InFlight {
    fn drop(&mut self) {
        if !self.done {
            self.conn.retire();
        }
    }
}

/// A socket being opened, counted against `MAX_SOCKETS` until the connect
/// ends or its read is dropped, as when the read times out.
struct Connecting<'a>(&'a EdgeClient);
impl Drop for Connecting<'_> {
    fn drop(&mut self) {
        if let Ok(mut pool) = self.0.pool.lock() {
            pool.connecting -= 1;
        }
        self.0.changed.notify_waiters();
    }
}

impl EdgeClient {
    /// `url` is the edge's data socket, `wss://…/v1/data` (or `ws://` locally).
    pub fn new(url: String, timeout: Duration) -> Result<Self, EdgeError> {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| EdgeError::Unavailable)?
        .with_root_certificates(bh_tls_roots::browser_roots())
        .with_no_client_auth();
        Ok(Self {
            url,
            tls: Arc::new(tls),
            timeout,
            pool: Mutex::new(Pool::default()),
            changed: Arc::new(Notify::new()),
        })
    }

    async fn connect(&self) -> Result<Arc<Conn>, EdgeError> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME_LEN))
            .max_frame_size(Some(MAX_FRAME_LEN));
        let (socket, _) = connect_async_tls_with_config(
            self.url.as_str(),
            Some(config),
            true,
            Some(Connector::Rustls(self.tls.clone())),
        )
        .await
        .map_err(|_| EdgeError::Unavailable)?;
        let (mut sink, mut stream) = socket.split();
        let (out, mut outgoing) = mpsc::unbounded_channel::<Message>();
        let shared = Arc::new(Shared {
            closed: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            changed: self.changed.clone(),
        });
        // Writer: sends queued frames in order; ends when every sender is gone.
        let writing = shared.clone();
        tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
            writing.close();
        });
        // Reader: matches each answer to its read, then grants its frame back.
        let reading = shared.clone();
        let credit = out.downgrade();
        tokio::spawn(async move {
            while let Some(Ok(message)) = stream.next().await {
                let bytes = match message {
                    Message::Binary(bytes) => bytes,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => break,
                };
                let Ok(response) = Response::decode(&bytes) else {
                    break;
                };
                match response {
                    Response::Events {
                        id,
                        items,
                        receipt,
                        coverage,
                    } => {
                        reading.answer(
                            id,
                            Ok(Data::Events(LogRead {
                                items,
                                receipt,
                                coverage,
                            })),
                        );
                    }
                    Response::Body {
                        id,
                        index,
                        last,
                        bytes: body,
                    } => reading.body(id, index, last, body),
                    Response::HomeObjectsRetired { id } => {
                        reading.answer(id, Ok(Data::Retired));
                    }
                    Response::HomeObjectsStored {
                        id,
                        prefix_digest,
                        bundle_digest,
                    } => {
                        reading.answer(
                            id,
                            Ok(Data::HomeObjects(HomeObjectsAck {
                                prefix_digest,
                                bundle_digest,
                            })),
                        );
                    }
                    Response::Refused { id, .. } => {
                        reading.answer(id, Err(EdgeError::Refused));
                        continue;
                    }
                    // No stage, append or subscription requests are sent.
                    _ => break,
                }
                // Credit is owed for every data frame, answered or late.
                let Ok(len) = u32::try_from(bytes.len()) else {
                    break;
                };
                let Ok(frame) = (Request::Credit { bytes: len }).encode() else {
                    break;
                };
                if let Some(out) = credit.upgrade() {
                    let _ = out.send(Message::Binary(frame.into()));
                }
            }
            reading.close();
        });
        Ok(Arc::new(Conn {
            slots: Arc::new(Semaphore::new(IN_FLIGHT)),
            next_id: AtomicU32::new(1),
            out,
            shared,
        }))
    }

    /// A socket with a free slot: an open one, else a new one while fewer
    /// than `MAX_SOCKETS` are open or opening, else wait for a change.
    async fn acquire(&self) -> Result<(Arc<Conn>, Slot), EdgeError> {
        loop {
            // Created before looking, so no change after the look is missed.
            let changed = self.changed.notified();
            let open = {
                let mut pool = self.pool.lock().map_err(|_| EdgeError::Unavailable)?;
                pool.sockets.retain(|conn| !conn.closed());
                let free = pool.sockets.iter().find_map(|conn| {
                    let permit = conn.slots.clone().try_acquire_owned().ok()?;
                    Some((conn.clone(), permit))
                });
                if let Some((conn, permit)) = free {
                    let slot = Slot {
                        _permit: permit,
                        changed: self.changed.clone(),
                    };
                    return Ok((conn, slot));
                }
                let open = pool.sockets.len() + pool.connecting < MAX_SOCKETS;
                if open {
                    pool.connecting += 1;
                }
                open
            };
            if !open {
                changed.await;
                continue;
            }
            let connecting = Connecting(self);
            let opened = tokio::time::timeout(CONNECT_TIMEOUT, self.connect())
                .await
                .unwrap_or(Err(EdgeError::Unavailable));
            if let Ok(conn) = &opened
                && let Ok(mut pool) = self.pool.lock()
            {
                pool.sockets.push(conn.clone());
            }
            drop(connecting);
            opened?;
        }
    }

    async fn request_once(&self, permit: &[u8], bundle: Option<&[u8]>, retire: bool) -> Answer {
        let (conn, slot) = self.acquire().await?;
        let id = conn.next_id.fetch_add(1, Ordering::SeqCst);
        let request = match bundle {
            Some(bundle) => Request::StoreHomeObjects {
                id,
                permit: permit.to_vec(),
                bundle: bundle.to_vec(),
            },
            None if retire => Request::RetireHomeObjects {
                id,
                permit: permit.to_vec(),
            },
            None => Request::Read {
                id,
                permit: permit.to_vec(),
            },
        };
        let frame = request.encode().map_err(|_| EdgeError::Malformed)?;
        let (reply, answer) = oneshot::channel();
        // Under the lock the reader closes with, so a closing socket either
        // fails this read or never takes it.
        let taken = conn.shared.pending.lock().ok().and_then(|mut pending| {
            if conn.closed() {
                return None;
            }
            pending.insert(
                id,
                Pending {
                    reply: Some(reply),
                    bodies: Vec::new(),
                    _slot: slot,
                },
            );
            Some(())
        });
        taken.ok_or(EdgeError::Unavailable)?;
        let mut sent = InFlight {
            conn: conn.clone(),
            id,
            done: false,
        };
        if conn.out.send(Message::Binary(frame.into())).is_err() {
            conn.shared.answer(sent.id, Err(EdgeError::Unavailable));
        }
        let result = answer.await.unwrap_or(Err(EdgeError::Unavailable));
        sent.done = true;
        result
    }

    async fn request(&self, permit: &[u8], bundle: Option<&[u8]>, retire: bool) -> Answer {
        tokio::time::timeout(self.timeout, async {
            let mut result = Err(EdgeError::Unavailable);
            for _ in 0..ATTEMPTS {
                result = self.request_once(permit, bundle, retire).await;
                if !matches!(result, Err(EdgeError::Unavailable)) {
                    break;
                }
            }
            result
        })
        .await
        .map_err(|_| EdgeError::Unavailable)?
    }
}
impl EdgeReader for EdgeClient {
    fn retire_home_objects(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<(), EdgeError>> {
        Box::pin(async move {
            match self.request(&permit, None, true).await? {
                Data::Retired => Ok(()),
                _ => Err(EdgeError::Malformed),
            }
        })
    }
    fn store_home_objects(
        &self,
        permit: Vec<u8>,
        bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<HomeObjectsAck, EdgeError>> {
        Box::pin(async move {
            match self.request(&permit, Some(&bundle), false).await? {
                Data::HomeObjects(stored) => Ok(stored),
                _ => Err(EdgeError::Malformed),
            }
        })
    }
    fn read_log(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<LogItems, EdgeError>> {
        Box::pin(async move {
            match self.request(&permit, None, false).await? {
                Data::Events(read) => Ok(read.items),
                _ => Err(EdgeError::Malformed),
            }
        })
    }
    fn read_log_with_receipt(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<LogRead, EdgeError>> {
        Box::pin(async move {
            match self.request(&permit, None, false).await? {
                Data::Events(read) => Ok(read),
                _ => Err(EdgeError::Malformed),
            }
        })
    }
    fn read_bodies(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        Box::pin(async move {
            match self.request(&permit, None, false).await? {
                Data::Bodies(bodies) => Ok(bodies),
                _ => Err(EdgeError::Malformed),
            }
        })
    }
}
