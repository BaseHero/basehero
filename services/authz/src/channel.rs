//! One device connection: the attested channel's server handshake over the
//! WebSocket the edge proxies, then one application message per record.
use crate::{Attestation, Service, ServiceError};
use bh_authz_proto::{FromService, Refusal, ToService};
use bh_confidential_channel::{
    appraisal::{PolicyStore, Sample, StoredState},
    handshake::ServerPending,
    record::{Opened, Session},
};
use bh_confidential_policy::Snapshot;
use bh_crypto::SecretBytes;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// From the connection to an authenticated device: the whole channel
/// handshake, including the attestation, and a successful `Authenticate`.
/// Requests before then do not extend it.
const AUTHENTICATE_WITHIN: Duration = Duration::from_secs(30);
/// A channel session lives at most ten minutes, so no wait outlasts it.
const IDLE_WAIT: Duration = Duration::from_secs(600);

/// What the server presents in its proof: the signed policy devices check
/// the evidence against, and the root they pin for it.
#[derive(Clone)]
pub struct ChannelConfig {
    pub app_root: [u8; 32],
    pub policy: Vec<u8>,
    pub policy_signature: [u8; 64],
}

/// The server side keeps no policy: devices appraise, the service attests.
struct NoPolicy;
impl PolicyStore for NoPolicy {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, ()> {
        Err(())
    }
    fn save(&mut self, _: &Snapshot) -> Result<(), ()> {
        Err(())
    }
}

async fn receive<W>(ws: &mut W, by: Instant) -> Result<Option<Vec<u8>>, ServiceError>
where
    W: Stream<Item = Result<Message, WsError>> + Unpin,
{
    loop {
        let message = tokio::time::timeout_at(by, ws.next())
            .await
            .map_err(|_| ServiceError::Transport)?;
        match message {
            None | Some(Ok(Message::Close(_))) => return Ok(None),
            Some(Ok(Message::Binary(bytes))) => return Ok(Some(bytes.to_vec())),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(_) => return Err(ServiceError::Transport),
        }
    }
}
async fn expect<W>(ws: &mut W, by: Instant) -> Result<Vec<u8>, ServiceError>
where
    W: Stream<Item = Result<Message, WsError>> + Unpin,
{
    receive(ws, by).await?.ok_or(ServiceError::Transport)
}
async fn send<W>(ws: &mut W, bytes: Vec<u8>) -> Result<(), ServiceError>
where
    W: Sink<Message, Error = WsError> + Unpin,
{
    ws.send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| ServiceError::Transport)
}
fn seal(session: &mut Session<NoPolicy>, message: &FromService) -> Result<Vec<u8>, ServiceError> {
    let plain = message.encode().map_err(|_| ServiceError::Channel)?;
    session
        .seal(SecretBytes::from_vec(plain))
        .map_err(|_| ServiceError::Channel)
}

/// One active application request plus at most seven parked plaintext records.
/// Only this task opens/seals crypto records. Close wins a ready-handler race.
fn admit(
    frame: Option<Vec<u8>>,
    session: &mut Session<NoPolicy>,
    queue: &mut VecDeque<SecretBytes>,
) -> Result<bool, ServiceError> {
    let Some(frame) = frame else { return Ok(false) };
    // Ordinary crypto framing is 60 bytes. Bound before opening/queueing.
    if frame.len() > bh_authz_proto::MAX_MESSAGE + 60 {
        return Err(ServiceError::Channel);
    }
    match session.open(&frame).map_err(|_| ServiceError::Channel)? {
        Opened::Closed => Ok(false),
        Opened::Data(plain) => {
            if plain.expose().len() > bh_authz_proto::MAX_MESSAGE || queue.len() >= 7 {
                return Err(ServiceError::Channel);
            }
            queue.push_back(plain);
            Ok(true)
        }
    }
}

/// Observe transport/authenticated closure while one operation awaits. Dropping
/// this future drops the unfinished handler; already durable effects remain
/// uncertain to the peer and must never be automatically replayed.
async fn while_open<W, F>(
    ws: &mut W,
    session: &mut Session<NoPolicy>,
    queue: &mut VecDeque<SecretBytes>,
    by: Instant,
    work: F,
) -> Result<Option<F::Output>, ServiceError>
where
    W: Stream<Item = Result<Message, WsError>> + Unpin,
    F: Future,
{
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            frame = receive(ws, by) => {
                if !admit(frame?, session, queue)? { return Ok(None); }
            }
            result = &mut work => return Ok(Some(result)),
        }
    }
}

/// Poll the actual transport, not SplitSink's intermediate one-record buffer:
/// readiness is the last await before sealing/admitting a response.
async fn while_writable<W>(
    ws: &mut W,
    session: &mut Session<NoPolicy>,
    queue: &mut VecDeque<SecretBytes>,
    by: Instant,
    valid: impl Fn() -> bool,
    mut work: impl FnMut(&mut W, &mut Context<'_>) -> Poll<Result<(), WsError>>,
) -> Result<bool, ServiceError>
where
    W: Stream<Item = Result<Message, WsError>> + Sink<Message, Error = WsError> + Unpin,
{
    tokio::time::timeout_at(
        by,
        futures_util::future::poll_fn(|cx| {
            loop {
                // WebSocket reads may flush queued Pong/Close responses, taking
                // buffered application bytes with them. Check before ANY I/O.
                if !valid() {
                    return Poll::Ready(Err(ServiceError::Transport));
                }
                match Pin::new(&mut *ws).poll_next(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None | Some(Ok(Message::Close(_)))) => {
                        return Poll::Ready(Ok(false));
                    }
                    Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                        match admit(Some(bytes.to_vec()), session, queue) {
                            Ok(true) => {}
                            other => return Poll::Ready(other),
                        }
                    }
                    Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                    Poll::Ready(Some(_)) => return Poll::Ready(Err(ServiceError::Transport)),
                }
            }
            if !valid() {
                return Poll::Ready(Err(ServiceError::Transport));
            }
            work(ws, cx).map(|r| r.map(|()| true).map_err(|_| ServiceError::Transport))
        }),
    )
    .await
    .map_err(|_| ServiceError::Transport)?
}

impl Service {
    /// Serve one device until it closes, the channel ends or a frame fails.
    pub async fn serve_connection<W>(
        &self,
        mut ws: W,
        config: &ChannelConfig,
        attestation: &dyn Attestation,
    ) -> Result<(), ServiceError>
    where
        W: Stream<Item = Result<Message, WsError>> + Sink<Message, Error = WsError> + Unpin,
    {
        let start = std::time::Instant::now();
        let now = move || start.elapsed().as_millis() as u64;
        let deadline = Instant::now() + AUTHENTICATE_WITHIN;
        let channel = |_| ServiceError::Channel;
        let hello = expect(&mut ws, deadline).await?;
        let pending = ServerPending::<NoPolicy>::accept_hello(&hello, config.app_root, now())
            .map_err(channel)?;
        let evidence =
            tokio::time::timeout_at(deadline, attestation.evidence(pending.report_data()))
                .await
                .map_err(|_| ServiceError::Transport)?
                .map_err(|_| ServiceError::Attestation)?;
        let (proof, pending) = pending
            .attach_evidence(
                &config.policy,
                &config.policy_signature,
                &evidence.quote,
                &evidence.collateral,
                &evidence.event_log,
                now(),
            )
            .map_err(channel)?;
        send(&mut ws, proof).await?;
        let encapsulation = expect(&mut ws, deadline).await?;
        let (finish, pending) = pending
            .accept_encapsulation(&encapsulation, now())
            .map_err(channel)?;
        send(&mut ws, finish).await?;
        let confirm = expect(&mut ws, deadline).await?;
        let mut session = pending
            .accept_finish(&confirm, move || Sample {
                system_seconds: None,
                monotonic_ms: now(),
            })
            .map_err(channel)?;
        let (mut connection, challenge) = self.connect(session.binding().map_err(channel)?);
        send(&mut ws, seal(&mut session, &challenge)?).await?;
        let mut queue = VecDeque::new();
        loop {
            let by = if connection.authenticated() {
                Instant::now() + IDLE_WAIT
            } else {
                deadline
            };
            if queue.is_empty() && !admit(receive(&mut ws, by).await?, &mut session, &mut queue)? {
                break;
            }
            let plain = queue.pop_front().ok_or(ServiceError::Channel)?;
            let work = async {
                match ToService::decode(plain.expose()) {
                    Ok(message) => connection.handle(message).await,
                    Err(_) => FromService::Refused {
                        reason: Refusal::Malformed,
                    },
                }
            };
            let Some(mut answer) = while_open(&mut ws, &mut session, &mut queue, by, work).await?
            else {
                break;
            };
            // No Selected data may enter the sink after expiry, even when the
            // sink was backpressured after selection. Check after readiness,
            // immediately before the synchronous seal/start_send boundary.
            if !while_writable(
                &mut ws,
                &mut session,
                &mut queue,
                by,
                || true,
                |ws, cx| Pin::new(ws).poll_ready(cx),
            )
            .await?
            {
                break;
            }
            if !self.response_current(&answer) {
                answer = FromService::Unavailable;
            }
            let frame = seal(&mut session, &answer)?;
            if !self.response_current(&answer) {
                return Err(ServiceError::Transport);
            }
            Pin::new(&mut ws)
                .start_send(Message::Binary(frame.into()))
                .map_err(|_| ServiceError::Transport)?;
            // Once start_send accepted a record it cannot be replaced safely:
            // expiry discards the transport, never flushes buffered bytes.
            if !while_writable(
                &mut ws,
                &mut session,
                &mut queue,
                by,
                || self.response_current(&answer),
                |ws, cx| Pin::new(ws).poll_flush(cx),
            )
            .await?
            {
                break;
            }
        }
        // Do not flush (including via Sink::close) after observing closure:
        // transport buffers could still contain a selected result. Drop them.
        Ok(())
    }
}
