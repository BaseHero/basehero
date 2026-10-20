//! One crypto owner and one ciphertext-only writer per authenticated generation.
//! Neither task owns Shared. Cancellation after sealing is a FIFO tombstone.
use super::*;
use futures_util::stream::SplitSink;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{
    OwnedRwLockReadGuard, OwnedRwLockWriteGuard, OwnedSemaphorePermit, Semaphore, mpsc, oneshot,
    watch,
};
use tokio::task::JoinHandle;

pub(super) const CAPACITY: usize = 8;
const MAX_PLAIN: usize = bh_authz_proto::MAX_MESSAGE;
// Five encoded submissions leave three record-sized buffers for receive,
// decoded reply and ReadBatch's temporary OpaqueEvent validation copy.
// Sealing releases the plaintext permit, so eight admissions can be in flight.
// Answer ownership transfers to the caller's oneshot; caller-retained results
// are outside the dispatcher bound. The scratch lock serializes the codec's
// temporary allocations with StoreHomeObjects' encoding scratch.
const PAYLOADS: usize = CAPACITY - 3;
const MAX_RECORD: usize = MAX_PLAIN + 60;

/// What the generation's owner is told. Ordered: a later signal never
/// gives way to an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Signal {
    Running,
    /// Rotation: no new requests; sealed ones drain.
    Drain,
    /// `Authz::close` retires this generation now. Its callers see a
    /// transient `Network`: the client may still be running.
    Retire,
    /// The client stopped for good.
    Stop,
}
impl Signal {
    fn error(self) -> ClientError {
        if self == Self::Stop {
            ClientError::Stopped
        } else {
            ClientError::Network
        }
    }
}

pub(super) enum Lease {
    Normal(#[allow(dead_code)] OwnedRwLockReadGuard<()>),
    Exclusive(#[allow(dead_code)] Arc<OwnedRwLockWriteGuard<()>>),
}
struct Request {
    plain: SecretBytes,
    expected: Family,
    answer: oneshot::Sender<Result<FromService, ClientError>>,
    _admission: OwnedSemaphorePermit,
    payload: OwnedSemaphorePermit,
    _lease: Lease,
}
struct Pending {
    expected: Family,
    answer: oneshot::Sender<Result<FromService, ClientError>>,
    deadline: Clock,
    _admission: OwnedSemaphorePermit,
    _lease: Lease,
}
#[derive(Clone, Copy)]
enum Family {
    Authenticate,
    Permits,
    Home,
    ReadBatch,
}
impl Family {
    fn for_request(message: &ToService) -> Self {
        match message {
            ToService::Authenticate { .. } => Self::Authenticate,
            ToService::StoreHomeObjects { .. } => Self::Home,
            ToService::ReadBatch { .. } => Self::ReadBatch,
            ToService::Permits { .. }
            | ToService::SubmitControl { .. }
            | ToService::RegisterBase { .. }
            | ToService::SubmitBaseControl { .. } => Self::Permits,
        }
    }
    fn accepts(self, message: &FromService) -> bool {
        matches!(
            (self, message),
            (_, FromService::Refused { .. } | FromService::Unavailable)
                | (Self::Authenticate, FromService::Authenticated { .. })
                | (Self::Permits, FromService::Permits { .. })
                | (Self::Home, FromService::HomeObjectsStored { .. })
                | (Self::ReadBatch, FromService::ReadBatch { .. })
        )
    }
}

pub(super) struct Handle {
    pub head: AccountHead,
    pub at: Option<AccountHead>,
    opened: Clock,
    requests: mpsc::Sender<Request>,
    payloads: Arc<Semaphore>,
    scratch: Arc<std::sync::Mutex<()>>,
    signal: watch::Sender<Signal>,
    ended: watch::Receiver<Option<ClientError>>,
    task: Mutex<Option<JoinHandle<()>>>,
    abort: tokio::task::AbortHandle,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.raise(Signal::Stop);
        self.abort.abort();
    }
}
impl Handle {
    pub fn start(live: Live) -> Arc<Self> {
        let (requests, rx) = mpsc::channel(CAPACITY);
        let (signal, stop) = watch::channel(Signal::Running);
        let (ended, end) = watch::channel(None);
        let head = live.head;
        let at = live.at;
        let opened = live.opened;
        let scratch = Arc::new(std::sync::Mutex::new(()));
        let task = tokio::spawn(run(live, rx, stop, ended, scratch.clone()));
        let abort = task.abort_handle();
        Arc::new(Self {
            head,
            at,
            opened,
            requests,
            payloads: Arc::new(Semaphore::new(PAYLOADS)),
            scratch,
            signal,
            ended: end,
            task: Mutex::new(Some(task)),
            abort,
        })
    }
    pub fn usable_at(&self, at: Option<AccountHead>) -> bool {
        self.at == at
            && self.opened.elapsed() < SESSION_LIFE
            && self.error().is_none()
            && *self.signal.borrow() == Signal::Running
    }
    fn raise(&self, to: Signal) {
        self.signal.send_if_modified(|value| {
            let raised = *value < to;
            *value = (*value).max(to);
            raised
        });
    }
    fn error(&self) -> Option<ClientError> {
        *self.ended.borrow()
    }
    /// Permanent: the client stopped.
    pub fn stop(&self) {
        self.raise(Signal::Stop);
        self.payloads.close();
    }
    /// End this generation now, without stopping the client.
    pub fn close(&self) {
        self.raise(Signal::Retire);
        self.payloads.close();
    }
    pub async fn join(&self) {
        // Cancellation drops only the guard, not the owned JoinHandle.
        let mut task = self.task.lock().await;
        if let Some(join) = task.as_mut() {
            let _ = join.await;
        }
        *task = None;
    }
    pub async fn retire(&self) {
        self.raise(Signal::Drain);
        self.join().await;
    }
    pub async fn ask(
        &self,
        message: ToService,
        admission: OwnedSemaphorePermit,
        lease: Lease,
    ) -> Result<FromService, ClientError> {
        let mut end = self.ended.clone();
        let mut stop = self.signal.subscribe();
        if let Some(error) = self.error() {
            return Err(error);
        }
        if *stop.borrow() != Signal::Running {
            return Err(ClientError::Network);
        }
        let work = async {
            let payload = self
                .payloads
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| self.signal.borrow().error())?;
            let expected = Family::for_request(&message);
            // Input remains caller-owned until here. Reject oversized payloads
            // before the codec can allocate a larger-than-record scratch buffer.
            check_size(&message)?;
            let plain = {
                let _scratch = self.scratch.lock().expect("codec scratch");
                SecretBytes::from_vec(message.encode().map_err(|_| ClientError::Channel)?)
            };
            drop(message);
            let (answer, result) = oneshot::channel();
            self.requests
                .send(Request {
                    plain,
                    expected,
                    answer,
                    _admission: admission,
                    payload,
                    _lease: lease,
                })
                .await
                .map_err(|_| self.error().unwrap_or(ClientError::Network))?;
            result
                .await
                .map_err(|_| self.error().unwrap_or(ClientError::Network))?
        };
        tokio::select! {
            biased;
            signal = stop.wait_for(|value| *value >= Signal::Retire) => {
                Err(signal.map_or(ClientError::Stopped, |signal| signal.error()))
            }
            _ = end.wait_for(|value| value.is_some()) => Err(self.error().unwrap_or(ClientError::Network)),
            result = work => result,
        }
    }
}

// Exact encoded length, without copying any payload. This is a local allocation
// bound only; the production codec remains the authority on validity.
pub(super) fn check_size(message: &ToService) -> Result<usize, ClientError> {
    use bh_authz_proto::Want;
    let size: usize = match message {
        ToService::ReadBatch {
            want: Want::ReadBatch { .. },
        } => 3 + 1 + 33 + 40 + 2,
        ToService::ReadBatch { .. } => return Err(ClientError::Channel),
        ToService::Authenticate { proof, genesis, .. } => 3 + proof.len() + 64 + 4 + genesis.len(),
        ToService::StoreHomeObjects {
            record,
            device_seal,
            recovery_seal,
            ..
        } => 3 + 40 + 4 + 14 + record.len() + device_seal.len() + recovery_seal.len(),
        ToService::Permits { items } => {
            if items.len() > bh_authz_proto::MAX_ITEMS {
                return Err(ClientError::Channel);
            }
            let mut size = 5;
            for item in items {
                size += 34
                    + match item {
                        Want::ReadEvents { .. } => 16,
                        Want::ReadBodies { bodies, .. } => 2 + bodies.len().saturating_mul(32),
                        Want::Stage { .. } => 36,
                        Want::Append { event, .. } => 36 + event.len(),
                        Want::Subscribe { .. } => 0,
                        Want::Presence { .. } => 32,
                        Want::ReadBatch { .. } => return Err(ClientError::Channel),
                    };
                if size > MAX_PLAIN {
                    return Err(ClientError::Channel);
                }
            }
            size
        }
        ToService::SubmitControl {
            event, delivery, ..
        } => {
            3 + 33
                + 4
                + event.len()
                + 1
                + delivery.as_ref().map_or(0, |d| {
                    32 + 32 + d.recipient.receiving().len() + 4 + d.frame.len()
                })
        }
        ToService::RegisterBase {
            descriptor, body, ..
        } => 3 + 8 + descriptor.len() + body.len() + 40 + 32,
        ToService::SubmitBaseControl {
            descriptor, body, ..
        } => 3 + 33 + 8 + descriptor.len() + body.len() + 32,
    };
    if size > MAX_PLAIN {
        Err(ClientError::Channel)
    } else {
        Ok(size)
    }
}

struct Record {
    bytes: Vec<u8>,
    _capacity: OwnedSemaphorePermit,
}
struct OwnedTask(JoinHandle<()>);
impl Drop for OwnedTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn write(mut sink: SplitSink<Socket, Message>, mut records: mpsc::Receiver<Record>) {
    while let Some(record) = records.recv().await {
        if sink
            .send(Message::Binary(record.bytes.into()))
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = sink.close().await;
}
async fn run(
    live: Live,
    mut requests: mpsc::Receiver<Request>,
    mut stop: watch::Receiver<Signal>,
    ended: watch::Sender<Option<ClientError>>,
    scratch: Arc<std::sync::Mutex<()>>,
) {
    let Live {
        socket,
        mut session,
        opened,
        ..
    } = live;
    let (sink, mut stream) = socket.split();
    let (records, rx) = mpsc::channel::<Record>(CAPACITY);
    let capacity = Arc::new(Semaphore::new(CAPACITY));
    let mut writer = OwnedTask(tokio::spawn(write(sink, rx)));
    let mut pending = VecDeque::<Pending>::new();
    let mut next: Option<Request> = None;
    let mut draining = false;
    let error = loop {
        // Check every transition, not only a test's final sample. Caller-side
        // encoders also hold admission/payload permits before allocating.
        let queued = requests.len() + usize::from(next.is_some());
        debug_assert!(pending.len() + queued <= CAPACITY);
        debug_assert!(queued <= PAYLOADS);
        if draining && pending.is_empty() {
            break ClientError::Network;
        }
        let deadline = pending
            .front()
            .map_or(opened + SESSION_LIFE + ANSWER_WAIT, |p| p.deadline);
        tokio::select! {
            biased;
            signal = stop.wait_for(|s| *s >= Signal::Retire || (*s == Signal::Drain && !draining)) => {
                let signal = signal.map_or(Signal::Stop, |s| *s);
                if signal >= Signal::Retire { break signal.error(); }
                draining = true; requests.close(); next = None;
                while requests.try_recv().is_ok() {}
            }
            _ = &mut writer.0 => break ClientError::Network,
            _ = tokio::time::sleep_until(deadline), if !pending.is_empty() => break ClientError::Network,
            frame = stream.next() => {
                let frame = match frame {
                    Some(Ok(Message::Binary(frame))) if frame.len() <= MAX_RECORD => frame,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    _ => break ClientError::Network,
                };
                let Some(request) = pending.pop_front() else { break ClientError::Channel; };
                let decoded = {
                    let _scratch = scratch.lock().expect("codec scratch");
                    match session.open(&frame) {
                        Ok(Opened::Data(plain)) => FromService::decode(plain.expose()).map_err(|_| ClientError::Channel),
                        _ => Err(ClientError::Channel),
                    }
                };
                match decoded {
                    Ok(value) if request.expected.accepts(&value) => {
                        let _ = request.answer.send(Ok(value));
                    }
                    _ => { let _ = request.answer.send(Err(ClientError::Channel)); break ClientError::Channel; }
                }
            }
            _ = tokio::time::sleep_until(opened + SESSION_LIFE), if !draining => {
                draining = true; requests.close(); next = None;
                while requests.try_recv().is_ok() {}
            }
            _ = async { if let Some(r) = next.as_mut() { r.answer.closed().await; } }, if next.is_some() => { next = None; }
            permit = capacity.clone().acquire_owned(), if next.is_some() && !draining => {
                let request = next.take().expect("next request");
                if request.answer.is_closed() { continue; }
                let Ok(permit) = permit else { break ClientError::Network; };
                let sealed = match session.seal(request.plain) { Ok(frame) => frame, Err(_) => break ClientError::Channel };
                debug_assert!(sealed.len() <= MAX_RECORD);
                // The permit counts queued AND active records; reserve before seal.
                if records.try_send(Record { bytes: sealed, _capacity: permit }).is_err() { break ClientError::Network; }
                drop(request.payload);
                pending.push_back(Pending { expected: request.expected, answer: request.answer, deadline: Clock::now() + ANSWER_WAIT, _admission: request._admission, _lease: request._lease });
            }
            request = requests.recv(), if next.is_none() && !draining => {
                match request { Some(request) => next = Some(request), None => break ClientError::Network }
            }
        }
    };
    requests.close();
    drop(next);
    while let Ok(request) = requests.try_recv() {
        let _ = request.answer.send(Err(error));
    }
    for request in pending {
        let _ = request.answer.send(Err(error));
    }
    // Best effort authenticated Close, never behind a full writer indefinitely.
    // Stop still destroys traffic keys even if no capacity is available.
    if let Ok(permit) = capacity.try_acquire_owned()
        && let Ok(bytes) = session.close()
    {
        let _ = records.try_send(Record {
            bytes,
            _capacity: permit,
        });
    }
    session.abort();
    drop(records);
    if !writer.0.is_finished()
        && tokio::time::timeout(Duration::from_millis(100), &mut writer.0)
            .await
            .is_err()
    {
        writer.0.abort();
        let _ = (&mut writer.0).await;
    }
    ended.send_replace(Some(error));
}
