//! Native, boot-local Roughtime UDP sampling. Configuration, oscillator and
//! deadlines must be supplied by trusted caller code; this is not a host clock.
use bh_qualified_time::{Bounds, Config, Counter, QualifiedClock, Sample, ServerRoot, Unavailable};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Mutex,
    time::Duration,
};
use tokio::net::UdpSocket;

const MAX_REPLY: usize = 4096;

/// No endpoint, packet, nonce, parser text or OS/library error escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeError;
impl std::fmt::Display for TimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("qualified time unavailable")
    }
}
impl std::error::Error for TimeError {}

/// A shared clock with two fixed pinned UDP endpoints. Unequal keys do not
/// establish that operators are independent; the caller must do so.
pub struct TimeSampler {
    endpoints: [SocketAddr; 2],
    roots: [ServerRoot; 2],
    clock: Mutex<QualifiedClock>,
    refresh_gate: tokio::sync::Mutex<()>,
    timeout: Duration,
}
// A dropped refresh, including cancellation at an await, invalidates the old
// anchor. Declared after the refresh gate, so it drops before the gate unlocks.
struct InvalidateOnDrop<'a> {
    clock: &'a Mutex<QualifiedClock>,
    armed: bool,
}
impl Drop for InvalidateOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.clock
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .mark_unavailable();
        }
    }
}
impl TimeSampler {
    pub fn new(
        servers: [(SocketAddr, ServerRoot); 2],
        config: Config,
        timeout: Duration,
    ) -> Result<Self, TimeError> {
        if servers[0].0 == servers[1].0
            || timeout.is_zero()
            || tokio::time::Instant::now().checked_add(timeout).is_none()
        {
            return Err(TimeError);
        }
        let roots = [servers[0].1, servers[1].1];
        let clock = QualifiedClock::new(roots, config).map_err(|_| TimeError)?;
        Ok(Self {
            endpoints: [servers[0].0, servers[1].0],
            roots,
            clock: Mutex::new(clock),
            refresh_gate: tokio::sync::Mutex::new(()),
            timeout,
        })
    }

    /// One total deadline for concurrent requests, including bind/connect,
    /// sends, receives and verification. No retry, discovery or fallback.
    /// A second concurrent refresh returns TimeError instead of waiting.
    /// Readers retain only the old anchor's original qualification during I/O.
    pub async fn refresh(&self, counter: &impl Counter) -> Result<Bounds, TimeError> {
        let _refresh = self.refresh_gate.try_lock().map_err(|_| TimeError)?;
        let mut invalidation = InvalidateOnDrop {
            clock: &self.clock,
            armed: true,
        };
        let deadline = tokio::time::Instant::now()
            .checked_add(self.timeout)
            .ok_or(TimeError)?;
        let (first, second) = tokio::time::timeout_at(deadline, async {
            tokio::try_join!(
                request(self.endpoints[0], counter),
                request(self.endpoints[1], counter)
            )
        })
        .await
        .map_err(|_| TimeError)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(TimeError);
        }
        // Counter reads in update/now are serialized with each other. The
        // update and its post-deadline check publish (or clear) as one operation.
        let mut clock = self.clock.lock().unwrap_or_else(|e| e.into_inner());
        let result = clock
            .update(
                &[
                    Sample {
                        server: self.roots[0],
                        nonce: &first.nonce,
                        reply: &first.reply,
                        sent: first.sent,
                        received: first.received,
                    },
                    Sample {
                        server: self.roots[1],
                        nonce: &second.nonce,
                        reply: &second.reply,
                        sent: second.sent,
                        received: second.received,
                    },
                ],
                counter,
            )
            .map_err(|_| TimeError);
        // timeout_at cannot preempt synchronous verification. A late success
        // must never become visible to another reader even briefly.
        if tokio::time::Instant::now() >= deadline {
            clock.mark_unavailable();
            return Err(TimeError);
        }
        if result.is_ok() {
            invalidation.armed = false;
        }
        result
    }

    /// Only the existing pure clock's rollback, age and width rules grant bounds.
    pub fn now(&self, counter: &impl Counter) -> Result<Bounds, Unavailable> {
        self.clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .now(counter)
    }
}

struct Response {
    nonce: [u8; 64],
    reply: Vec<u8>,
    sent: u64,
    received: u64,
}
fn request_bytes(nonce: &[u8; 64]) -> [u8; 1024] {
    let mut request = [0; 1024];
    for (i, word) in [
        2u32,
        64,
        u32::from_le_bytes(*b"NONC"),
        u32::from_le_bytes(*b"PAD\xff"),
    ]
    .iter()
    .enumerate()
    {
        request[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    request[16..80].copy_from_slice(nonce);
    request
}
async fn request(endpoint: SocketAddr, counter: &impl Counter) -> Result<Response, TimeError> {
    let nonce = bh_crypto::random::<64>();
    let bind = SocketAddr::new(
        match endpoint.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    );
    let socket = UdpSocket::bind(bind).await.map_err(|_| TimeError)?;
    socket.connect(endpoint).await.map_err(|_| TimeError)?;
    let sent = counter.ticks();
    if socket
        .send(&request_bytes(&nonce))
        .await
        .map_err(|_| TimeError)?
        != 1024
    {
        return Err(TimeError);
    }
    // One extra byte detects a too-long UDP datagram instead of accepting a
    // truncated 4096-byte prefix. No retry or response from a different peer.
    let mut buf = [0; MAX_REPLY + 1];
    let n = socket.recv(&mut buf).await.map_err(|_| TimeError)?;
    let received = counter.ticks();
    if n > MAX_REPLY {
        return Err(TimeError);
    }
    Ok(Response {
        nonce,
        reply: buf[..n].to_vec(),
        sent,
        received,
    })
}
