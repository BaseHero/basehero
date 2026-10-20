//! The device side of the attested channel, appraising synthetic attestation.
#![allow(dead_code)]

use bh_authz::{
    ChannelConfig,
    proto::{FromService, ToService},
};
use bh_confidential_attestation::synthetic;
use bh_confidential_channel::{
    appraisal::{PolicyContext, PolicyStore, Sample, StoredState},
    handshake::ClientHello,
    record::{Opened, Session},
};
use bh_confidential_policy::{Limits, Policy, Role, Snapshot};
use bh_crypto::{SecretBytes, SigningKey};
use futures_util::{SinkExt, StreamExt};
use std::{
    sync::LazyLock,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

pub type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub struct Memory(Option<Snapshot>);
impl PolicyStore for Memory {
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
pub fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn device_clock() -> Sample {
    Sample {
        system_seconds: Some(seconds()),
        monotonic_ms: START.elapsed().as_millis() as u64,
    }
}
/// A signed policy admitting the synthetic checker build.
pub fn channel_config(policy_root: &SigningKey) -> ChannelConfig {
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
    ChannelConfig {
        app_root: policy_root.public(),
        policy,
        policy_signature,
    }
}
pub async fn next_binary<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
) -> Vec<u8> {
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Binary(bytes) => return bytes.to_vec(),
            Message::Close(_) => panic!("closed"),
            _ => {}
        }
    }
}
pub async fn send<S: AsyncRead + AsyncWrite + Unpin>(ws: &mut WebSocketStream<S>, bytes: Vec<u8>) {
    ws.send(Message::Binary(bytes.into())).await.unwrap();
}
/// The device side: the attested handshake with synthetic appraisal.
pub async fn open(url: &str, policy_root: &SigningKey) -> (Socket, Session<Memory>) {
    open_with_snapshot(url, policy_root, None).await
}
/// The same device-side channel, starting with a previously accepted policy.
pub async fn open_with_snapshot(
    url: &str,
    policy_root: &SigningKey,
    previous: Option<Snapshot>,
) -> (Socket, Session<Memory>) {
    let (ws, _) = connect_async(url).await.unwrap();
    handshake_with_snapshot(ws, policy_root, previous).await
}
/// The device side's handshake over an open WebSocket.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    ws: WebSocketStream<S>,
    policy_root: &SigningKey,
) -> (WebSocketStream<S>, Session<Memory>) {
    handshake_with_snapshot(ws, policy_root, None).await
}
pub async fn handshake_with_snapshot<S: AsyncRead + AsyncWrite + Unpin>(
    mut ws: WebSocketStream<S>,
    policy_root: &SigningKey,
    previous: Option<Snapshot>,
) -> (WebSocketStream<S>, Session<Memory>) {
    let limits = Limits {
        max_lifetime_secs: 86_400,
        max_uncertainty_secs: 0,
    };
    let context = PolicyContext::new(
        policy_root.public(),
        limits,
        1,
        Memory(previous),
        device_clock,
    )
    .unwrap();
    let hello = ClientHello::new(context).unwrap();
    send(&mut ws, hello.frame().to_vec()).await;
    let proof = next_binary(&mut ws).await;
    let (encapsulation, pending) = hello
        .accept_synthetic_proof(&proof)
        .unwrap()
        .encapsulate()
        .unwrap();
    send(&mut ws, encapsulation).await;
    let finish = next_binary(&mut ws).await;
    let (confirm, session) = pending.accept_finish(&finish).unwrap();
    send(&mut ws, confirm).await;
    (ws, session)
}
pub async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    session: &mut Session<Memory>,
) -> FromService {
    let frame = next_binary(ws).await;
    let Opened::Data(plain) = session.open(&frame).unwrap() else {
        panic!("data")
    };
    FromService::decode(plain.expose()).unwrap()
}
pub async fn ask<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    session: &mut Session<Memory>,
    message: ToService,
) -> FromService {
    let sealed = session
        .seal(SecretBytes::from_vec(message.encode().unwrap()))
        .unwrap();
    send(ws, sealed).await;
    receive(ws, session).await
}
