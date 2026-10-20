//! Nonblocking multiplexed data replies. Credit acknowledges bounded handoff
//! or deliberate discard, never verification, acceptance or durable storage.
//!
//! Queues retain encoded bytes: at most MAX_FRAME_LEN per request and
//! 2 * MAX_FRAME_LEN + 64 KiB per socket (8,585,216 bytes). Body frames and
//! large replies cannot spend the 64 KiB reserve, so stalled large readers
//! cannot prevent an independent small control/metadata response completing.
//! Exhausting either budget ends only that request; already queued frames
//! remain charged until consumed/dropped, even after its map entry is gone.
//!
//! This is a queued-byte bound, not process RSS. The reader additionally
//! holds at most one bounded wire frame and one decoded copy (each <=
//! MAX_FRAME_LEN, plus <=64 event-pair headers); the wire frame is copied
//! into a charged, exact-length boxed slice after the decoded copy is dropped.
//! Each Answers::next decodes its charged frame, then releases that charge;
//! responses retained by callers, transport buffers and queue/guard metadata
//! are outside the queue budget. Each request also has a 65-frame slot cap.
//!
//! Outbound, at most OUT_REQUESTS requests and OUT_BYTES encoded bytes are
//! queued or being written; `send` refuses a request past either at once.
//! Credit is not queued behind requests: the reader adds each frame's length
//! to one checked counter and the writer sends what it owes, first, as one
//! Credit frame. Receiving therefore never waits for outbound space.
use crate::transport::{Connector, Route, TransportError};
use bh_sync::wire::{MAX_FRAME_LEN, Request, Response};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;

/// How long a request that expects an answer waits for its next frame
/// before the socket is treated as lost. A subscription waits as long as
/// its socket is open: no head may move for a long time.
const FRAME_WAIT: Duration = Duration::from_secs(60);
/// Secondary slot bound for small frames, not the body memory bound.
const BUFFERED: usize = 65;
/// One small metadata page/ack can proceed even behind two full body queues.
/// Bodies of any size and replies larger than this cannot use the reserve.
const CONTROL_RESERVE: usize = 64 * 1024;
const BULK_BUDGET: usize = 2 * MAX_FRAME_LEN;
const SOCKET_BUDGET: usize = BULK_BUDGET + CONTROL_RESERVE;
/// Requests queued or being written, per socket.
const OUT_REQUESTS: usize = 32;
/// Encoded request bytes queued or being written, per socket: sixteen
/// largest frames plus a reserve for small requests.
const OUT_BYTES: usize = 16 * MAX_FRAME_LEN + CONTROL_RESERVE;

#[derive(Default)]
struct Budget {
    total: usize,
    bulk: usize,
}
struct Charge {
    budget: Arc<Mutex<Budget>>,
    request: Arc<AtomicUsize>,
    bytes: usize,
    bulk: bool,
}
impl Charge {
    fn reserve(
        budget: &Arc<Mutex<Budget>>,
        request: &Arc<AtomicUsize>,
        bytes: usize,
        small_control: bool,
    ) -> Option<Self> {
        let mut used = budget.lock().expect("data budget");
        let per_id = request.load(Ordering::Relaxed);
        let bulk = !small_control;
        if per_id + bytes > MAX_FRAME_LEN
            || used.total + bytes > SOCKET_BUDGET
            || (bulk && used.bulk + bytes > BULK_BUDGET)
        {
            return None;
        }
        used.total += bytes;
        if bulk {
            used.bulk += bytes;
        }
        request.store(per_id + bytes, Ordering::Relaxed);
        Some(Self {
            budget: budget.clone(),
            request: request.clone(),
            bytes,
            bulk,
        })
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        let mut used = self.budget.lock().expect("data budget");
        used.total -= self.bytes;
        if self.bulk {
            used.bulk -= self.bytes;
        }
        self.request.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}
struct Queued {
    bytes: Box<[u8]>,
    _charge: Charge,
}
#[derive(Clone)]
struct Waiter {
    sender: mpsc::Sender<Queued>,
    queued: Arc<AtomicUsize>,
}

/// The requests waiting for frames, or `None` once the socket has closed:
/// a request is added only while it is open, under the same lock.
type Waiters = Arc<Mutex<Option<HashMap<u32, Waiter>>>>;

/// Requests and encoded bytes queued or being written.
#[derive(Default)]
struct Out {
    requests: usize,
    bytes: usize,
}
/// One admitted request frame; its admission ends once it is written.
struct Outbound {
    frame: Vec<u8>,
    _slot: OutSlot,
}
struct OutSlot {
    out: Arc<Mutex<Out>>,
    bytes: usize,
}
impl OutSlot {
    fn reserve(out: &Arc<Mutex<Out>>, bytes: usize) -> Option<Self> {
        let mut used = out.lock().expect("data out");
        if used.requests + 1 > OUT_REQUESTS || used.bytes + bytes > OUT_BYTES {
            return None;
        }
        used.requests += 1;
        used.bytes += bytes;
        Some(Self {
            out: out.clone(),
            bytes,
        })
    }
}
impl Drop for OutSlot {
    fn drop(&mut self) {
        let mut used = self.out.lock().expect("data out");
        used.requests -= 1;
        used.bytes -= self.bytes;
    }
}
/// Received data bytes not yet granted back, and the writer's wake for them.
#[derive(Default)]
struct Owed {
    bytes: AtomicU32,
    wake: Notify,
}
impl Owed {
    /// Owe `bytes` more. The edge never has more than its window unanswered,
    /// so an overflow is a protocol fault: the socket closes.
    fn add(&self, bytes: usize) -> bool {
        let Ok(bytes) = u32::try_from(bytes) else {
            return false;
        };
        let added = self
            .bytes
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |owed| {
                owed.checked_add(bytes)
            })
            .is_ok();
        self.wake.notify_one();
        added
    }
}

fn close(closed: &AtomicBool, waiters: &Waiters) {
    *waiters.lock().expect("data waiters") = None;
    closed.store(true, Ordering::SeqCst);
}

pub struct DataSocket {
    out: mpsc::Sender<Outbound>,
    admitted: Arc<Mutex<Out>>,
    waiters: Waiters,
    #[cfg(test)]
    budget: Arc<Mutex<Budget>>,
    next: AtomicU32,
    closed: Arc<AtomicBool>,
    tasks: [tokio::task::JoinHandle<()>; 2],
}

/// The frames answering one request, in order. Dropping it forgets the
/// request: later frames for it are credited and discarded.
pub struct Answers {
    frames: mpsc::Receiver<Queued>,
    /// How long to wait for each frame; none for a subscription.
    wait: Option<Duration>,
    id: u32,
    waiters: Waiters,
}
impl Drop for Answers {
    fn drop(&mut self) {
        if let Some(waiting) = self.waiters.lock().expect("data waiters").as_mut() {
            waiting.remove(&self.id);
        }
    }
}
impl Answers {
    /// This request's wire id, for a fire-and-forget send on the same id.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The next frame, or `None` when the socket closed, the request fell
    /// too far behind, or (expecting an answer) the socket went silent.
    pub async fn next(&mut self) -> Option<Response> {
        let frame = match self.wait {
            Some(wait) => tokio::time::timeout(wait, self.frames.recv())
                .await
                .ok()
                .flatten(),
            None => self.frames.recv().await,
        }?;
        // Decoding succeeded before enqueueing. The guard releases only
        // when this owned queue entry actually leaves the receiver.
        Response::decode(&frame.bytes).ok()
    }
}

fn request_id(response: &Response) -> u32 {
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
/// Whether no more frames follow for this request.
fn last(response: &Response) -> bool {
    match response {
        Response::Body { last, .. } => *last,
        Response::Head { .. } | Response::Presence { .. } | Response::Peers { .. } => false,
        _ => true,
    }
}

impl DataSocket {
    pub async fn open(connector: &dyn Connector) -> Result<Self, TransportError> {
        let socket = connector.connect(Route::Data).await?;
        let (mut sink, mut stream) = socket.split();
        // The admission bound is stricter than the channel's, so an admitted
        // request always fits.
        let (out, mut outgoing) = mpsc::channel::<Outbound>(OUT_REQUESTS);
        let closed = Arc::new(AtomicBool::new(false));
        let waiters: Waiters = Arc::new(Mutex::new(Some(HashMap::new())));
        let budget = Arc::new(Mutex::new(Budget::default()));
        let owed = Arc::new(Owed::default());
        let writer = {
            let closed = closed.clone();
            let waiters = waiters.clone();
            let owed = owed.clone();
            tokio::spawn(async move {
                loop {
                    let credit = owed.bytes.swap(0, Ordering::SeqCst);
                    let message = if credit > 0 {
                        let Ok(frame) = (Request::Credit { bytes: credit }).encode() else {
                            break;
                        };
                        frame
                    } else {
                        tokio::select! {
                            biased;
                            _ = owed.wake.notified() => continue,
                            next = outgoing.recv() => match next {
                                // The slot is released once the frame is written.
                                Some(Outbound { frame, _slot }) => {
                                    let sent = sink.send(Message::Binary(frame.into())).await;
                                    drop(_slot);
                                    if sent.is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                None => break,
                            },
                        }
                    };
                    if sink.send(Message::Binary(message.into())).await.is_err() {
                        break;
                    }
                }
                close(&closed, &waiters);
                let _ = sink.close().await;
            })
        };
        let reader = {
            let budget = budget.clone();
            let closed = closed.clone();
            let waiters = waiters.clone();
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
                    let data = !matches!(response, Response::Refused { .. });
                    let id = request_id(&response);
                    let done = last(&response);
                    let small_control = !matches!(response, Response::Body { .. })
                        && bytes.len() <= CONTROL_RESERVE;
                    drop(response);
                    // Hand the frame over, without waiting, before granting
                    // its window back. A frame for a request nobody waits
                    // for, or one too far behind, is consumed here.
                    {
                        let mut waiters = waiters.lock().expect("data waiters");
                        let Some(waiting) = waiters.as_mut() else {
                            break;
                        };
                        let waiter = if done {
                            waiting.remove(&id)
                        } else {
                            waiting.get(&id).cloned()
                        };
                        if let Some(waiter) = waiter {
                            let sent = Charge::reserve(
                                &budget,
                                &waiter.queued,
                                bytes.len(),
                                small_control,
                            )
                            .is_some_and(|charge| {
                                waiter
                                    .sender
                                    .try_send(Queued {
                                        bytes: bytes.as_ref().into(),
                                        _charge: charge,
                                    })
                                    .is_ok()
                            });
                            if !sent {
                                waiting.remove(&id);
                            }
                        }
                    }
                    if data && !owed.add(bytes.len()) {
                        break;
                    }
                }
                close(&closed, &waiters);
            })
        };
        Ok(Self {
            out,
            admitted: Arc::default(),
            waiters,
            #[cfg(test)]
            budget,
            next: AtomicU32::new(1),
            closed,
            tasks: [writer, reader],
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Send one request built for its id; its frames arrive on the answer.
    /// On a socket that is closed or closing, or with no room for it among
    /// the requests not yet written, this fails at once.
    pub fn send(&self, request: impl FnOnce(u32) -> Request) -> Result<Answers, TransportError> {
        let id = self.next.fetch_add(1, Ordering::SeqCst).max(1);
        let request = request(id);
        let wait = (!matches!(
            request,
            Request::Subscribe { .. } | Request::PresenceJoin { .. }
        ))
        .then_some(FRAME_WAIT);
        let frame = request.encode().map_err(|_| TransportError)?;
        let slot = OutSlot::reserve(&self.admitted, frame.len()).ok_or(TransportError)?;
        let (sender, frames) = mpsc::channel(BUFFERED);
        {
            let mut waiters = self.waiters.lock().expect("data waiters");
            let waiting = waiters.as_mut().ok_or(TransportError)?;
            waiting.insert(
                id,
                Waiter {
                    sender,
                    queued: Arc::new(AtomicUsize::new(0)),
                },
            );
            if self.out.try_send(Outbound { frame, _slot: slot }).is_err() {
                waiting.remove(&id);
                return Err(TransportError);
            }
        }
        Ok(Answers {
            frames,
            wait,
            id,
            waiters: self.waiters.clone(),
        })
    }

    /// Send a request on an id the caller already owns, without a waiter:
    /// nothing is queued or retained for an answer. Used for presence frames
    /// on their join's id, which the edge never answers. On a closed socket,
    /// or with no room among requests not yet written, this fails at once.
    pub fn send_quiet(&self, request: Request) -> Result<(), TransportError> {
        let frame = request.encode().map_err(|_| TransportError)?;
        let slot = OutSlot::reserve(&self.admitted, frame.len()).ok_or(TransportError)?;
        {
            let waiters = self.waiters.lock().expect("data waiters");
            if waiters.is_none() {
                return Err(TransportError);
            }
            if self.out.try_send(Outbound { frame, _slot: slot }).is_err() {
                return Err(TransportError);
            }
        }
        Ok(())
    }

    /// One request answered by a single frame.
    pub async fn ask(
        &self,
        request: impl FnOnce(u32) -> Request,
    ) -> Result<Response, TransportError> {
        self.send(request)?.next().await.ok_or(TransportError)
    }

    /// Close the socket: cancel both of its tasks and wait until they have
    /// ended. Unwritten requests are dropped; answers end. Dropping the
    /// socket without this still cancels them, without waiting.
    pub async fn shutdown(&mut self) {
        close(&self.closed, &self.waiters);
        for task in &mut self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests;

impl Drop for DataSocket {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
