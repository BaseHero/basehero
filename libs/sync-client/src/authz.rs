//! The authorization session: an attested channel through the edge, a fresh
//! appraisal and authentication on every connection, one message per record.
//! A session is replaced before the channel's ten-minute life ends.
use crate::{
    Appraisal, ClientError, Endpoint, Shared, backoff::Backoff, transport::Route, transport::Socket,
};
use bh_account::{Head as AccountHead, device_auth::Context};
use bh_authz_proto::{FromService, ToService};
use bh_confidential_channel::{
    appraisal::{PolicyContext, PolicyStore, Sample, StoredState},
    handshake::ClientHello,
    record::{Opened, Session},
};
use bh_confidential_policy::Snapshot;
use bh_crypto::SecretBytes;
use futures_util::{SinkExt, StreamExt};
use std::{
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OwnedRwLockWriteGuard, RwLock, Semaphore, watch};
mod dispatcher;
use tokio::time::Instant as Clock;
use tokio_tungstenite::tungstenite::Message;

/// A session is replaced this long after it opened, before the channel's
/// own 600 s limit.
const SESSION_LIFE: Duration = Duration::from_secs(540);
/// The handshake and authentication, and then each answer, must arrive
/// within this.
const ANSWER_WAIT: Duration = Duration::from_secs(30);

#[cfg(all(test, feature = "synthetic-attestation"))]
mod dispatcher_tests;
#[cfg(all(test, feature = "synthetic-attestation"))]
mod test_support;

/// The accepted policy, kept for this client's life so a later connection
/// cannot present an older one.
pub(crate) struct MemoryPolicy(Option<Snapshot>);
impl PolicyStore for MemoryPolicy {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, ()> {
        Ok(self
            .0
            .clone()
            .map_or(StoredState::Fresh, StoredState::Committed))
    }
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), ()> {
        self.0 = Some(snapshot.clone());
        Ok(())
    }
}

static START: LazyLock<Instant> = LazyLock::new(Instant::now);
fn device_clock() -> Sample {
    Sample {
        system_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs()),
        monotonic_ms: START.elapsed().as_millis() as u64,
    }
}

pub(crate) struct Live {
    socket: Socket,
    session: Session<MemoryPolicy>,
    opened: Clock,
    head: AccountHead,
    /// The earlier head this session's proof was made at, if not the
    /// device's current one.
    at: Option<AccountHead>,
}

pub(crate) struct Authz {
    policy: Option<PolicyContext<MemoryPolicy>>,
    appraisal: Appraisal,
    slot: std::sync::Mutex<Slot>,
    opening: Mutex<()>,
    gate: Arc<RwLock<()>>,
    admission: Arc<Semaphore>,
    stop_signal: watch::Sender<bool>,
    not_active: watch::Sender<u64>,
    /// Set for good when the client stops: no session opens after it.
    stopped: AtomicBool,
}

/// The session, and when the next connection may be tried after one failed.
/// Every user of the session (the client and its host) shares this backoff.
#[derive(Default)]
struct Slot {
    live: Option<Arc<dispatcher::Handle>>,
    backoff: Backoff,
    retry: Option<(Clock, ClientError)>,
}

/// An authenticated session, held exclusively while in use.
pub struct AuthzSession<'a> {
    authz: &'a Authz,
    lease: Arc<OwnedRwLockWriteGuard<()>>,
    live: Arc<dispatcher::Handle>,
}

impl AuthzSession<'_> {
    /// The account head the service verified when this session authenticated.
    pub fn account_head(&self) -> AccountHead {
        self.live.head
    }
    /// One request and its answer. A transport or channel failure ends the
    /// session; the next use opens a new one.
    pub async fn ask(&mut self, message: ToService) -> Result<FromService, ClientError> {
        let result = self
            .authz
            .until_stopped(async {
                let admission = self
                    .authz
                    .admission
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| ClientError::Stopped)?;
                self.live
                    .ask(
                        message,
                        admission,
                        dispatcher::Lease::Exclusive(self.lease.clone()),
                    )
                    .await
            })
            .await;
        self.authz.observe_not_active(&result);
        result
    }
}

async fn receive(socket: &mut Socket) -> Result<Vec<u8>, ClientError> {
    loop {
        match tokio::time::timeout(ANSWER_WAIT, socket.next()).await {
            Ok(Some(Ok(Message::Binary(bytes)))) => return Ok(bytes.to_vec()),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            _ => return Err(ClientError::Network),
        }
    }
}
async fn send(socket: &mut Socket, bytes: Vec<u8>) -> Result<(), ClientError> {
    socket
        .send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| ClientError::Network)
}

impl Live {
    async fn receive(&mut self) -> Result<FromService, ClientError> {
        let frame = receive(&mut self.socket).await?;
        match self.session.open(&frame) {
            Ok(Opened::Data(plain)) => {
                FromService::decode(plain.expose()).map_err(|_| ClientError::Channel)
            }
            _ => Err(ClientError::Channel),
        }
    }
    async fn ask(&mut self, message: ToService) -> Result<FromService, ClientError> {
        // The encoded message may carry M: it moves straight into a wiped owner.
        let plain = SecretBytes::from_vec(message.encode().map_err(|_| ClientError::Channel)?);
        drop(message);
        let sealed = self.session.seal(plain).map_err(|_| ClientError::Channel)?;
        send(&mut self.socket, sealed).await?;
        self.receive().await
    }
}

impl Authz {
    pub(crate) fn new(endpoint: &Endpoint) -> Self {
        let policy = PolicyContext::new(
            endpoint.app_root,
            endpoint.limits,
            endpoint.build_floor,
            MemoryPolicy(None),
            device_clock,
        )
        .ok()
        .filter(|context| {
            endpoint.policy.is_empty()
                || context
                    .deliver_policy(&endpoint.policy, &endpoint.policy_signature)
                    .is_ok()
        });
        Self {
            policy,
            appraisal: endpoint.appraisal,
            slot: std::sync::Mutex::default(),
            opening: Mutex::new(()),
            gate: Arc::new(RwLock::new(())),
            admission: Arc::new(Semaphore::new(dispatcher::CAPACITY)),
            stop_signal: watch::Sender::new(false),
            not_active: watch::Sender::new(0),
            stopped: AtomicBool::new(false),
        }
    }

    pub(crate) fn not_active(&self) -> watch::Receiver<u64> {
        self.not_active.subscribe()
    }
    fn observe_not_active(&self, result: &Result<FromService, ClientError>) {
        if matches!(
            result,
            Ok(FromService::Refused {
                reason: bh_authz_proto::Refusal::NotActive
            }) | Err(ClientError::Refused(bh_authz_proto::Refusal::NotActive))
        ) {
            self.not_active.send_modify(|n| *n = n.wrapping_add(1));
        }
    }

    /// No session opens from now on; the open one closes with `close`.
    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.admission.close();
        self.stop_signal.send_replace(true);
        if let Some(live) = &self.slot.lock().expect("authz slot").live {
            live.stop();
        }
    }
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    pub(crate) async fn close(&self) {
        // Retire only this generation: signup also uses close before fresh
        // current-context authentication. Permanent shutdown calls stop first.
        // Opening borrows Shared and is cancellation-selected; no detached opener.
        let _opening = self.opening.lock().await;
        let live = self.slot.lock().expect("authz slot").live.clone();
        if let Some(live) = live {
            // A retire, not a stop: concurrent callers see a transient error.
            live.close();
            live.join().await;
        }
        self.slot.lock().expect("authz slot").live = None;
    }

    async fn until_stopped<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, ClientError>>,
    ) -> Result<T, ClientError> {
        let mut stop = self.stop_signal.subscribe();
        tokio::select! {
            biased;
            _ = stop.wait_for(|stopped| *stopped) => Err(ClientError::Stopped),
            result = work => result,
        }
    }

    /// One ordinary current-context request, pipelined with others on the
    /// shared dispatcher: permits, subscriptions, ReadBatch. Registration,
    /// controls, home and pairing hold an exclusive `session` instead.
    pub(crate) async fn request(
        &self,
        shared: &Shared,
        message: ToService,
    ) -> Result<FromService, ClientError> {
        let result = self
            .until_stopped(async {
                // Wait at the fair gate before reserving queue capacity: readers
                // behind a public writer must not consume the capacity it needs.
                let lease = self.gate.clone().read_owned().await;
                let admission = self
                    .admission
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| ClientError::Stopped)?;
                let live = self.generation(shared, None).await?;
                live.ask(message, admission, dispatcher::Lease::Normal(lease))
                    .await
            })
            .await;
        self.observe_not_active(&result);
        result
    }

    pub(crate) async fn session<'a>(
        &'a self,
        shared: &Shared,
    ) -> Result<AuthzSession<'a>, ClientError> {
        self.session_at(shared, None).await
    }

    /// A session authenticated at `at`, an earlier verified head of the
    /// account, or at the device's current head for `None`. One older than
    /// its life is replaced as it is taken. After a connection fails, none
    /// is tried again before its backoff ends; until then this fails with
    /// that connection's error.
    pub(crate) async fn session_at<'a>(
        &'a self,
        shared: &Shared,
        at: Option<AccountHead>,
    ) -> Result<AuthzSession<'a>, ClientError> {
        self.until_stopped(async {
            let lease = Arc::new(self.gate.clone().write_owned().await);
            let live = self.generation(shared, at).await?;
            Ok(AuthzSession {
                authz: self,
                lease,
                live,
            })
        })
        .await
    }

    async fn generation(
        &self,
        shared: &Shared,
        at: Option<AccountHead>,
    ) -> Result<Arc<dispatcher::Handle>, ClientError> {
        // One opener, outside the short publication lock. Cancellation drops
        // the borrowed handshake and socket, and releases this mutex.
        let _opening = self.opening.lock().await;
        if self.is_stopped() {
            return Err(ClientError::Stopped);
        }
        let old = self.slot.lock().expect("authz slot").live.clone();
        if let Some(old) = old {
            if old.usable_at(at) {
                return Ok(old);
            }
            old.retire().await;
        }
        {
            let mut slot = self.slot.lock().expect("authz slot");
            slot.live = None;
            if let Some((until, error)) = slot.retry
                && Clock::now() < until
            {
                return Err(error);
            }
        }
        let opened = self
            .until_stopped(async {
                tokio::time::timeout(ANSWER_WAIT, self.open(shared, at))
                    .await
                    .map_err(|_| ClientError::Network)?
            })
            .await;
        // Signal outside the slot lock: the public-evidence task must open a
        // separate channel rather than recurse through this generation.
        if matches!(
            opened,
            Err(ClientError::Refused(bh_authz_proto::Refusal::NotActive))
        ) {
            self.not_active.send_modify(|n| *n = n.wrapping_add(1));
        }
        let mut slot = self.slot.lock().expect("authz slot");
        match opened {
            Ok(_) if self.is_stopped() => Err(ClientError::Stopped),
            Ok(live) => {
                let live = dispatcher::Handle::start(live);
                slot.live = Some(live.clone());
                slot.backoff.reset();
                slot.retry = None;
                Ok(live)
            }
            Err(error) => {
                let wait = slot.backoff.next();
                slot.retry = Some((Clock::now() + wait, error));
                Err(error)
            }
        }
    }

    /// A fresh attested connection for the public account-evidence route.
    /// It never borrows the refused authenticated generation, its fair gate
    /// or its dispatcher capacity. The service permits this route before
    /// Authenticate, and the usual hosting-root checks still apply to data.
    pub(crate) async fn public_evidence(
        &self,
        shared: &Shared,
        request: ToService,
    ) -> Result<FromService, ClientError> {
        self.until_stopped(async {
            let mut live = tokio::time::timeout(ANSWER_WAIT, self.open_channel(shared, None))
                .await
                .map_err(|_| ClientError::Network)??;
            self.challenge(&mut live).await?;
            live.ask(request).await
        })
        .await
    }

    async fn open(&self, shared: &Shared, at: Option<AccountHead>) -> Result<Live, ClientError> {
        let mut live = self.open_channel(shared, at).await?;
        let identity = shared.signer.identity().map_err(|_| ClientError::Signer)?;
        let context = Context {
            channel_binding: live.session.binding().map_err(|_| ClientError::Channel)?,
            challenge: self.challenge(&mut live).await?,
        };
        let proof = match at {
            None => shared.signer.device_proof(context).await,
            Some(head) => shared.signer.device_proof_at(head, context).await,
        }
        .map_err(|_| ClientError::Signer)?;
        let answer = live
            .ask(ToService::Authenticate {
                proof: Box::new(*proof.as_bytes()),
                account: identity.account,
                device: identity.device,
                genesis: identity.genesis,
            })
            .await?;
        match answer {
            FromService::Authenticated { account_head } => {
                live.head = account_head;
                Ok(live)
            }
            FromService::Refused { reason } => Err(ClientError::Refused(reason)),
            FromService::Unavailable => Err(ClientError::Unavailable),
            _ => Err(ClientError::Channel),
        }
    }

    async fn challenge(&self, live: &mut Live) -> Result<[u8; 32], ClientError> {
        match live.receive().await? {
            FromService::Challenge { challenge } => Ok(challenge),
            _ => Err(ClientError::Channel),
        }
    }

    async fn open_channel(
        &self,
        shared: &Shared,
        at: Option<AccountHead>,
    ) -> Result<Live, ClientError> {
        let policy = self.policy.clone().ok_or(ClientError::Unsupported)?;
        let mut socket = shared
            .connector
            .connect(Route::Authz)
            .await
            .map_err(|_| ClientError::Network)?;
        let channel = |_| ClientError::Channel;
        let hello = ClientHello::new(policy).map_err(channel)?;
        send(&mut socket, hello.frame().to_vec()).await?;
        let proof = receive(&mut socket).await?;
        let checked = match self.appraisal {
            Appraisal::Hardware => hello.accept_proof(&proof),
            #[cfg(feature = "synthetic-attestation")]
            Appraisal::Synthetic => hello.accept_synthetic_proof(&proof),
        }
        .map_err(channel)?;
        let (encapsulation, pending) = checked.encapsulate().map_err(channel)?;
        send(&mut socket, encapsulation).await?;
        let finish = receive(&mut socket).await?;
        let (confirm, session) = pending.accept_finish(&finish).map_err(channel)?;
        send(&mut socket, confirm).await?;
        let live = Live {
            socket,
            session,
            opened: Clock::now(),
            head: AccountHead {
                position: 0,
                hash: [0; 32],
            },
            at,
        };
        Ok(live)
    }
}
