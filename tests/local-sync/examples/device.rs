//! Test-only device process for the local sync tests: one device's account
//! registry, container owner, sync and pairing hosts (`bh-host`), the same
//! production operations an app window reaches through its commands, driven
//! by one JSON request per line on stdin. Never an app, CLI or service.
//!
//! Labelled substitutes: a software test key store kept in a local file so
//! a restarted process reloads its exact identity (a platform key store
//! does this natively), a protector that seals nothing, and a connector
//! that can drop, hold or cut this device's own traffic for a test. The
//! account verifier, durable stores, authorization, receipts and apply are
//! the production ones.
//!
//! Usage: `local_sync_device DIR ENDPOINT_FILE gated|plain`.
use bh_account::{
    crypto::{KemKey, Secret, SigningKey},
    platform::{ControlKeyPolicy, DeviceKeyStore, KeyHandle, KeyStoreError, StoredDevice},
};
use bh_data::{MutationId, RecordId, mutation::ops::Operation, query::Query};
use bh_device::ContainerId;
use bh_host::{
    accounts::{AccountOperation, HostKeyStore, Screen, SharedAccountHost, fresh_test_host},
    pairing::{PairingHost, Scope},
    sync::{Configured, StatusView, StatusWindows, SyncHost},
    test_support::{FakeStore, PlainProtector},
};
use bh_storage::NoteKey;
use bh_sync::{
    permit::{self, LogKind, Scope as PermitScope},
    wire::{Request, Response},
};
use bh_sync_client::transport::{Connector, Route, Socket, TransportError, WsConnector};
use futures_util::{SinkExt, StreamExt, future::BoxFuture};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

type Host = SharedAccountHost<FileKeys, PlainProtector>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}
fn sha(bytes: &[u8]) -> String {
    hex(&bh_crypto::sha256(bytes))
}

/// One line to the test, whole. Replies and barrier events share stdout.
fn emit(value: Value) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{value}").expect("stdout");
    out.flush().expect("stdout");
}

// ---------------------------------------------------------------------------
// The software test key store, persisted beside the device's container.

/// `FakeStore` (bh-host's labelled software store) whose keys are also kept
/// in this device's private test directory, so a killed process reloads its
/// exact identity. Not a platform store: tests only.
#[derive(Clone)]
struct FileKeys {
    inner: FakeStore,
    file: PathBuf,
}
impl FileKeys {
    fn open(file: PathBuf, gated: bool) -> Self {
        let inner = if gated {
            FakeStore::gated()
        } else {
            FakeStore::default()
        };
        if let Ok(text) = std::fs::read_to_string(&file) {
            let saved: Value = serde_json::from_str(&text).expect("saved test keys");
            let mut keys = inner.keys.lock().unwrap();
            for (handle, seeds) in saved.as_object().expect("keys") {
                let seed = |i: usize| {
                    Secret::from_slice(&unhex::<32>(seeds[i].as_str().unwrap())).unwrap()
                };
                keys.insert(
                    unhex(handle),
                    (
                        SigningKey::from_seed(&seed(0)),
                        SigningKey::from_seed(&seed(1)),
                        KemKey::from_seed(&seed(2)),
                    ),
                );
            }
        }
        Self { inner, file }
    }
    fn persist(&self) {
        let keys = self.inner.keys.lock().unwrap();
        let saved: serde_json::Map<String, Value> = keys
            .iter()
            .map(|(handle, (ordinary, control, receiver))| {
                (
                    hex(handle),
                    json!([
                        hex(ordinary.export_seed().expose()),
                        hex(control.export_seed().expose()),
                        hex(receiver.export_seed().expose()),
                    ]),
                )
            })
            .collect();
        let next = self.file.with_extension("next");
        std::fs::write(&next, Value::Object(saved).to_string()).expect("write test keys");
        let file = std::fs::File::open(&next).unwrap();
        file.sync_all().unwrap();
        std::fs::rename(&next, &self.file).expect("keep test keys");
    }
}
impl DeviceKeyStore for FileKeys {
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        let created = self.inner.create(policy).await?;
        self.persist();
        Ok(created)
    }
    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        self.inner.load(handle).await
    }
    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        self.inner.sign_control(handle, message).await
    }
    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        self.inner.sign_content(handle, message).await
    }
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        self.inner.decapsulate(handle, ciphertext).await
    }
}
impl HostKeyStore for FileKeys {
    const JOIN_POLICY: ControlKeyPolicy = ControlKeyPolicy::AppEnforcedOwnerConfirmation;
    fn action_gate(&self) -> Option<bh_host::confirm::ActionGate> {
        self.inner.action_gate()
    }
    fn confirm_owner(&mut self) -> impl std::future::Future<Output = Result<(), KeyStoreError>> {
        self.inner.confirm_owner()
    }
}

// ---------------------------------------------------------------------------
// This device's traffic, with test-only faults.

/// What the test asked the connector to do to this device's own traffic.
#[derive(Default)]
struct Plan {
    /// Refuse new connections and end open ones.
    offline: bool,
    /// Swallow the Ack of the next content append, then cut that socket.
    drop_next_ack: bool,
    /// Keep content appends back (the body is staged; the order waits)
    /// until released, then send them as they were. A compound publication
    /// sends its own stage part, with its exact permit and body, at once.
    hold_appends: bool,
    /// Forward content appends but never their Acks, and answer base-log
    /// reads `Unavailable`: the device learns of the order neither from its
    /// Ack nor from its echo, as if it had crashed once it sent.
    hold_acks: bool,
    /// Once an Ack is dropped, answer base-log reads `Unavailable` (as a
    /// failing edge would) until the device sends that event again, so the
    /// outbox resends before the receiver can settle the package from its
    /// echo.
    refuse_read_after_drop: bool,
    refuse_reads_until_resent: Option<String>,
    /// Held appends of these events go now, the others stay held.
    release: Vec<String>,
}

struct Faults {
    root: [u8; 32],
    plan: Mutex<Plan>,
    offline: watch::Sender<bool>,
    /// Bumped when the plan changes, so held frames are looked at again.
    released: watch::Sender<u64>,
    journal: Mutex<std::fs::File>,
    /// Request ids for the stage parts this connector sends itself, far
    /// above any the device's socket uses.
    stages: std::sync::atomic::AtomicU32,
}
impl Faults {
    fn record(&self, mut entry: Value) {
        entry["ms"] = json!(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        );
        let mut journal = self.journal.lock().unwrap();
        writeln!(journal, "{entry}").unwrap();
        journal.flush().unwrap();
    }
    fn barrier(&self, name: &str, detail: Value) {
        self.record(json!({"barrier": name, "detail": detail.clone()}));
        emit(json!({"event": "barrier", "name": name, "detail": detail}));
    }
}

/// The request a data socket sent under an id, as the edge will answer it.
#[derive(Clone)]
struct Sent {
    kind: &'static str,
    log: String,
    content: bool,
    /// Sent by this connector, not the device: its answer is not forwarded.
    own: bool,
}

struct FaultConnector {
    inner: Arc<WsConnector>,
    faults: Arc<Faults>,
}
impl Connector for FaultConnector {
    fn connect(&self, route: Route) -> BoxFuture<'_, Result<Socket, TransportError>> {
        Box::pin(async move {
            if self.faults.plan.lock().unwrap().offline {
                return Err(TransportError);
            }
            let real = self.inner.connect(route).await?;
            Ok(pump(real, route, self.faults.clone()))
        })
    }
}

/// A socket over channels, so a pump between it and the real socket can
/// observe frames and apply the plan.
struct Channel {
    incoming: mpsc::UnboundedReceiver<Result<Message, WsError>>,
    outgoing: mpsc::UnboundedSender<Message>,
}
impl futures_util::Stream for Channel {
    type Item = Result<Message, WsError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}
impl futures_util::Sink<Message> for Channel {
    type Error = WsError;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), WsError> {
        self.outgoing
            .send(item)
            .map_err(|_| WsError::ConnectionClosed)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Poll::Ready(Ok(()))
    }
}

fn pump(real: Socket, route: Route, faults: Arc<Faults>) -> Socket {
    let (to_device, incoming) = mpsc::unbounded_channel();
    let (outgoing, mut from_device) = mpsc::unbounded_channel::<Message>();
    let mut offline = faults.offline.subscribe();
    let mut released = faults.released.subscribe();
    tokio::spawn(async move {
        let (mut sink, mut stream) = real.split();
        let mut sent: HashMap<u32, Sent> = HashMap::new();
        let mut held: Vec<(String, Message)> = Vec::new();
        loop {
            tokio::select! {
                message = from_device.recv() => {
                    let Some(message) = message else {
                        let _ = sink.close().await;
                        return;
                    };
                    if route == Route::Data {
                        match outbound(&faults, &mut sent, &message) {
                            Outbound::Forward => {}
                            Outbound::Hold(event) => {
                                held.push((event, message));
                                continue;
                            }
                            Outbound::StageAndHold(event, stage) => {
                                held.push((event, message));
                                if sink.send(stage).await.is_err() {
                                    return;
                                }
                                continue;
                            }
                            Outbound::Refuse(id) => {
                                let refused = Response::Refused {
                                    id,
                                    reason: bh_sync::wire::Refusal::Unavailable,
                                };
                                let _ = to_device.send(Ok(Message::Binary(
                                    refused.encode().unwrap().into(),
                                )));
                                continue;
                            }
                        }
                    }
                    if sink.send(message).await.is_err() {
                        return;
                    }
                }
                _ = released.changed() => {
                    let go: Vec<_> = {
                        let plan = faults.plan.lock().unwrap();
                        let (go, keep) = held
                            .drain(..)
                            .partition(|(event, _)| !plan.hold_appends || plan.release.contains(event));
                        held = keep;
                        go
                    };
                    for (event, message) in go {
                        faults.record(json!({"released": event}));
                        if sink.send(message).await.is_err() {
                            return;
                        }
                    }
                }
                message = stream.next() => {
                    let Some(message) = message else { return };
                    let Ok(message) = message else {
                        let _ = to_device.send(message);
                        return;
                    };
                    if route == Route::Data {
                        match inbound(&faults, &mut sent, &message) {
                            Inbound::Forward => {}
                            Inbound::Swallow => continue,
                            Inbound::SwallowAndCut => {
                                let _ = sink.close().await;
                                return;
                            }
                        }
                    }
                    if to_device.send(Ok(message)).is_err() {
                        return;
                    }
                }
                _ = async { let _ = offline.wait_for(|offline| *offline).await; } => {
                    let _ = sink.close().await;
                    return;
                }
            }
        }
    });
    Box::pin(Channel { incoming, outgoing })
}

enum Outbound {
    Forward,
    Hold(String),
    /// Hold a compound publication's order; send its stage part now.
    StageAndHold(String, Message),
    Refuse(u32),
}

/// Record a device frame; what to do with it.
fn outbound(faults: &Faults, sent: &mut HashMap<u32, Sent>, message: &Message) -> Outbound {
    let Message::Binary(bytes) = message else {
        return Outbound::Forward;
    };
    let Ok(request) = Request::decode(bytes) else {
        return Outbound::Forward;
    };
    let scope = |signed: &[u8]| {
        permit::issued_ms(signed)
            .ok()
            .and_then(|at| permit::verify(faults.root, signed, at).ok())
            .map(|p| p.scope)
    };
    let log_hex = |log: permit::LogId| {
        format!(
            "{}{}",
            if log.kind == LogKind::Base {
                "01"
            } else {
                "02"
            },
            hex(&log.id)
        )
    };
    match request {
        // The receiver reads its events from the service's read batches or
        // here, and every body here: refusing these keeps the echo away.
        Request::Read { id, permit } => {
            let (kind, log, detail) = match scope(&permit) {
                Some(PermitScope::ReadEvents { log, first, last }) => {
                    ("read", log, json!({"first": first, "last": last}))
                }
                Some(PermitScope::ReadBodies { log, bodies }) => {
                    ("read-bodies", log, json!({"bodies": bodies.len()}))
                }
                _ => return Outbound::Forward,
            };
            let refuse = {
                let plan = faults.plan.lock().unwrap();
                log.kind == LogKind::Base
                    && (plan.hold_acks || plan.refuse_reads_until_resent.is_some())
            };
            if refuse {
                faults.record(json!({"fault": "read-refused", "id": id, "kind": kind,
                    "read": detail}));
                return Outbound::Refuse(id);
            }
            sent.insert(
                id,
                Sent {
                    kind,
                    log: log_hex(log),
                    content: log.kind == LogKind::Base,
                    own: false,
                },
            );
            Outbound::Forward
        }
        Request::Stage { id, permit, body } => {
            let Some(PermitScope::Stage {
                log,
                body: commitment,
                ..
            }) = scope(&permit)
            else {
                return Outbound::Forward;
            };
            let content = log.kind == LogKind::Base;
            faults.record(json!({"out": "stage", "id": id, "log": log_hex(log),
                "body": sha(&body), "commitment": hex(&commitment.0), "len": body.len(),
                "issued_ms": permit::issued_ms(&permit).ok()}));
            sent.insert(
                id,
                Sent {
                    kind: "stage",
                    log: log_hex(log),
                    content,
                    own: false,
                },
            );
            Outbound::Forward
        }
        // A content event's one request: its stage and its append, each
        // under its own permit, journaled as the two parts they are.
        Request::Publish {
            id,
            stage_permit,
            append_permit,
            event,
            body,
        } => {
            let (
                Some(PermitScope::Stage {
                    log,
                    body: commitment,
                    ..
                }),
                Some(PermitScope::Append {
                    event: digest,
                    after,
                    ..
                }),
            ) = (scope(&stage_permit), scope(&append_permit))
            else {
                return Outbound::Forward;
            };
            let content = log.kind == LogKind::Base && after.is_none();
            let event_id = bh_sync::OpaqueEvent::decode(&event)
                .map(|e| {
                    hex(&e
                        .publication_id(if after.is_some() {
                            bh_sync::Route::Control
                        } else {
                            bh_sync::Route::Content
                        })
                        .0)
                })
                .unwrap_or_default();
            resending(faults, &event_id);
            faults.record(json!({"out": "stage", "id": id, "log": log_hex(log),
                "body": sha(&body), "commitment": hex(&commitment.0), "len": body.len(),
                "issued_ms": permit::issued_ms(&stage_permit).ok(), "via": "publish"}));
            faults.record(json!({"out": "append", "id": id, "log": log_hex(log),
                "content": content, "event_id": event_id, "digest": hex(&digest.0),
                "bytes": sha(&event), "issued_ms": permit::issued_ms(&append_permit).ok(),
                "via": "publish"}));
            sent.insert(
                id,
                Sent {
                    kind: "append",
                    log: log_hex(log),
                    content,
                    own: false,
                },
            );
            let held = {
                let plan = faults.plan.lock().unwrap();
                content && plan.hold_appends && !plan.release.contains(&event_id)
            };
            if !held {
                return Outbound::Forward;
            }
            // As an edge that staged the body and then lost the order: the
            // stage part goes alone, with the device's exact permit and body.
            let stage_id = faults
                .stages
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            faults.record(json!({"out": "stage", "id": stage_id, "log": log_hex(log),
                "body": sha(&body), "commitment": hex(&commitment.0), "len": body.len(),
                "issued_ms": permit::issued_ms(&stage_permit).ok(), "held_publish": id}));
            let stage = Request::Stage {
                id: stage_id,
                permit: stage_permit,
                body,
            };
            sent.insert(
                stage_id,
                Sent {
                    kind: "stage",
                    log: log_hex(log),
                    content,
                    own: true,
                },
            );
            faults.barrier(
                "append-held",
                json!({"event_id": event_id, "bytes": sha(&event)}),
            );
            Outbound::StageAndHold(event_id, Message::Binary(stage.encode().unwrap().into()))
        }
        Request::Append { id, permit, event } => {
            let Some(PermitScope::Append {
                log,
                event: digest,
                after,
                ..
            }) = scope(&permit)
            else {
                return Outbound::Forward;
            };
            let content = log.kind == LogKind::Base && after.is_none();
            let event_id = bh_sync::OpaqueEvent::decode(&event)
                .map(|e| {
                    hex(&e
                        .publication_id(if after.is_some() {
                            bh_sync::Route::Control
                        } else {
                            bh_sync::Route::Content
                        })
                        .0)
                })
                .unwrap_or_default();
            resending(faults, &event_id);
            faults.record(json!({"out": "append", "id": id, "log": log_hex(log),
                "content": content, "event_id": event_id, "digest": hex(&digest.0),
                "bytes": sha(&event), "issued_ms": permit::issued_ms(&permit).ok()}));
            sent.insert(
                id,
                Sent {
                    kind: "append",
                    log: log_hex(log),
                    content,
                    own: false,
                },
            );
            let held = {
                let plan = faults.plan.lock().unwrap();
                content && plan.hold_appends && !plan.release.contains(&event_id)
            };
            if held {
                faults.barrier(
                    "append-held",
                    json!({"event_id": event_id, "bytes": sha(&event)}),
                );
                return Outbound::Hold(event_id);
            }
            Outbound::Forward
        }
        Request::PresenceJoin { id, permit } => {
            let epoch = match scope(&permit) {
                Some(PermitScope::Presence { log, epoch }) => {
                    Some(json!({"log": log_hex(log), "epoch": hex(&epoch)}))
                }
                _ => None,
            };
            faults.record(json!({"out": "presence-join", "id": id, "permit": epoch}));
            Outbound::Forward
        }
        Request::Presence { id, sealed } => {
            faults.record(json!({"out": "presence", "id": id, "len": sealed.len(),
                "bytes": sha(&sealed)}));
            Outbound::Forward
        }
        _ => Outbound::Forward,
    }
}

/// The device sends `event` again: reads refused until then may go.
fn resending(faults: &Faults, event: &str) {
    let mut plan = faults.plan.lock().unwrap();
    if plan.refuse_reads_until_resent.as_deref() == Some(event) {
        plan.refuse_reads_until_resent = None;
    }
}

enum Inbound {
    Forward,
    Swallow,
    SwallowAndCut,
}

fn inbound(faults: &Faults, sent: &mut HashMap<u32, Sent>, message: &Message) -> Inbound {
    let Message::Binary(bytes) = message else {
        return Inbound::Forward;
    };
    let Ok(response) = Response::decode(bytes) else {
        return Inbound::Forward;
    };
    match response {
        Response::Staged { id } => match sent.remove(&id) {
            Some(request) => {
                faults.record(json!({"in": "staged", "id": id, "log": request.log}));
                if request.own {
                    Inbound::Swallow
                } else {
                    Inbound::Forward
                }
            }
            None => Inbound::Forward,
        },
        Response::Acked { id, ack } => {
            let Some(request) = sent.remove(&id) else {
                return Inbound::Forward;
            };
            acked(faults, id, &request, &ack, None)
        }
        // A compound publication's Ack, with the commitment it ordered.
        Response::Published { id, ack, .. } => {
            let Some(request) = sent.remove(&id) else {
                return Inbound::Forward;
            };
            acked(faults, id, &request, &ack, Some("publish"))
        }
        Response::Events {
            id, items, receipt, ..
        } => {
            if let Some(request) = sent.remove(&id).filter(|r| r.kind == "read" && r.content) {
                let heads: Vec<Value> = items
                    .iter()
                    .filter_map(|(commitment, _)| bh_sync::Commitment::decode(commitment).ok())
                    .map(|c| {
                        json!({"position": c.head().position, "hash": hex(&c.head().hash.0),
                            "previous": hex(&c.previous().hash.0), "event_id": hex(&c.event_id().0)})
                    })
                    .collect();
                faults.record(json!({"in": "events", "id": id, "log": request.log,
                    "commitments": heads, "receipt": receipt.map(|r| hex(&r))}));
            }
            Inbound::Forward
        }
        Response::Refused { id, reason } => match sent.remove(&id) {
            Some(request) => {
                faults.record(json!({"in": "refused", "id": id, "kind": request.kind,
                    "log": request.log, "content": request.content,
                    "reason": format!("{reason:?}")}));
                if request.own {
                    Inbound::Swallow
                } else {
                    Inbound::Forward
                }
            }
            None => Inbound::Forward,
        },
        Response::Presence { id, from, sealed } => {
            faults.record(json!({"in": "presence", "id": id, "from": from,
                "len": sealed.len(), "bytes": sha(&sealed)}));
            Inbound::Forward
        }
        Response::Peers {
            id,
            others,
            event,
            slot,
        } => {
            faults.record(json!({"in": "peers", "id": id, "others": others,
                "event": event, "slot": slot}));
            Inbound::Forward
        }
        _ => Inbound::Forward,
    }
}

/// Record an Ack (of an append or a compound publication); a content Ack
/// may be held or dropped by the plan.
fn acked(faults: &Faults, id: u32, request: &Sent, ack: &[u8], via: Option<&str>) -> Inbound {
    let ack = permit::AppendAck::decode(ack).ok();
    let position = ack.as_ref().map(|a| a.head.position);
    let event = ack.as_ref().map(|a| hex(&a.event.0));
    faults.record(json!({"in": "acked", "id": id, "log": request.log,
        "content": request.content, "position": position, "event_id": event, "via": via}));
    if !request.content {
        return Inbound::Forward;
    }
    let mut plan = faults.plan.lock().unwrap();
    if plan.hold_acks {
        drop(plan);
        faults.barrier("ack-held", json!({"position": position, "event_id": event}));
        return Inbound::Swallow;
    }
    if plan.drop_next_ack {
        plan.drop_next_ack = false;
        if plan.refuse_read_after_drop {
            plan.refuse_reads_until_resent = event.clone();
        }
        drop(plan);
        faults.barrier(
            "ack-dropped",
            json!({"position": position, "event_id": event}),
        );
        return Inbound::SwallowAndCut;
    }
    Inbound::Forward
}

// ---------------------------------------------------------------------------
// The device.

#[derive(Default)]
struct Seen {
    last: Mutex<Option<StatusView>>,
    states: Mutex<Vec<&'static str>>,
    wakes: Mutex<Vec<String>>,
    ended: Mutex<Vec<String>>,
}
impl StatusWindows for Seen {
    fn post_status(&self, _: ContainerId, view: &StatusView) {
        let mut states = self.states.lock().unwrap();
        if states.last() != Some(&view.state) {
            states.push(view.state);
        }
        *self.last.lock().unwrap() = Some(view.clone());
    }
    fn wake_delivery(&self, window: String) {
        self.wakes.lock().unwrap().push(window);
    }
    fn authority_ended(&self, _: ContainerId, windows: Vec<String>) {
        self.ended.lock().unwrap().extend(windows);
    }
}

struct Device {
    owner: Arc<bh_device::Owner>,
    host: Host,
    sync: SyncHost,
    pairing: PairingHost,
    seen: Arc<Seen>,
    faults: Arc<Faults>,
    connector: Arc<FaultConnector>,
    requests: u64,
}

fn ok(value: Value) -> Result<Value, String> {
    Ok(value)
}

impl Device {
    fn id(&self) -> Result<ContainerId, String> {
        self.host
            .ready_authority()
            .map(|(id, _)| id)
            .ok_or_else(|| "no ready account".to_owned())
    }
    fn scope(&self, page: u64) -> Result<Scope, String> {
        Ok(Scope {
            window: "main".into(),
            page: Some(page),
            container: Some(self.id()?),
        })
    }
    fn key(&self, note: [u8; 32]) -> Result<NoteKey, String> {
        let id = self.id()?;
        let base = self
            .host
            .ready_parts(id)
            .ok_or("no ready parts")?
            .own_base
            .id()
            .0;
        Ok(NoteKey {
            base,
            audience: [0; 32],
            note,
        })
    }
    async fn screen(&self, operation: AccountOperation) -> Result<Screen, String> {
        self.pairing
            .setup_screen("main", &self.host, &self.sync, operation)
            .await
            .map_err(str::to_owned)
    }
    /// As the app's `account_open_note`: authorize notes, show the home
    /// note in `main` and start this account's sync.
    async fn open(&self) -> Result<Value, String> {
        let (id, capability, base) = self.host.note_authority().ok_or("no verified account")?;
        let device = capability.device_id();
        let account = capability.account_id();
        self.owner
            .authorize(id, capability, base)
            .map_err(|e| format!("{e:?}"))?;
        let home = self
            .owner
            .open_home("main", id)
            .map_err(|e| format!("{e:?}"))?;
        self.sync
            .ensure_started(&self.host, id, self.seen.clone())
            .await;
        ok(
            json!({"home": hex(&home), "container": hex(&id.0), "base": hex(&base),
            "device": hex(&device.0), "account": hex(&account.0)}),
        )
    }
    /// Save one paragraph in `note`, shown in `window`, as the editor does:
    /// a save that lost its writer to a concurrent accepted apply reopens
    /// and saves again. Returns this device's local commit receipt.
    fn save(&mut self, window: &str, note: [u8; 32], text: &str) -> Result<Value, String> {
        self.edit_text(window, note, text, false)
    }
    fn edit_text(
        &mut self,
        window: &str,
        note: [u8; 32],
        text: &str,
        typing: bool,
    ) -> Result<Value, String> {
        let id = self.id()?;
        self.owner
            .show_note(window, id, note)
            .map_err(|e| format!("{e:?}"))?;
        for attempt in 0..5 {
            self.requests += 1;
            let mut request = [0; 16];
            request[..8].copy_from_slice(&self.requests.to_be_bytes());
            request[8..12].copy_from_slice(&std::process::id().to_be_bytes());
            let opened = self
                .owner
                .open_leased(window, note)
                .map_err(|e| format!("{e:?}"))?;
            let lease = opened.writer.ok_or("no writer")?;
            let delta = if typing {
                typed_delta(&opened.state, lease.client_id, text)
            } else {
                bh_device::Owner::core_author(&opened)
                    .map_err(|e| format!("{e:?}"))?
                    .try_append_paragraph(text)
                    .map_err(|e| format!("{e:?}"))?
            };
            match self
                .owner
                .commit_leased(window, opened.generation, lease.token, request, &delta)
            {
                Ok((ack, _)) => {
                    self.sync.wake(id);
                    return ok(json!({"request": hex(&ack.request_id),
                        "replayed": ack.replayed, "attempt": attempt}));
                }
                // Only a lost writer or a moved note is saved again; any
                // other error fails the save as it is.
                Err(
                    bh_device::OwnerError::WriterUnavailable
                    | bh_device::OwnerError::Store(bh_storage::StoreError::StaleNote),
                ) if attempt < 4 => {}
                Err(error) => {
                    return Err(format!("save failed on attempt {attempt}: {error:?}"));
                }
            }
        }
        unreachable!()
    }
    /// This device's position among the account's active devices: the hue
    /// every screen uses for it, as the app computes it.
    fn device_colour(&self) -> Result<u8, String> {
        let (_, capability, _) = self.host.note_authority().ok_or("no verified account")?;
        let device = capability.device_id();
        let signer = self.sync.signer(self.id()?).ok_or("no signer")?;
        let account = signer.current_account().map_err(|e| format!("{e:?}"))?;
        let index = account
            .active_devices()
            .map_err(|e| format!("{e:?}"))?
            .position(|keys| keys.id() == device)
            .ok_or("device not active")?;
        Ok((index % 6) as u8)
    }
    /// A Yjs v1 relative position for a UTF-16 offset in one paragraph of
    /// this device's working state, as the editor encodes a selection.
    fn relative(
        &self,
        window: &str,
        note: [u8; 32],
        paragraph: usize,
        offset: u32,
        assoc: yrs::Assoc,
    ) -> Result<Value, String> {
        use yrs::{
            IndexedSequence, ReadTxn, Text, Transact, Update, XmlFragment, XmlOut,
            updates::{decoder::Decode, encoder::Encode},
        };
        let id = self.id()?;
        self.owner
            .show_note(window, id, note)
            .map_err(|e| format!("{e:?}"))?;
        let opened = self
            .owner
            .open(window, note)
            .map_err(|e| format!("{e:?}"))?;
        let doc = yrs::Doc::with_options(yrs::Options {
            offset_kind: yrs::OffsetKind::Utf16,
            cleanup_formatting: false,
            ..yrs::Options::default()
        });
        {
            let mut txn = doc.transact_mut();
            for segment in opened.state.segments() {
                txn.apply_update(Update::decode_v1(segment).map_err(|e| format!("{e:?}"))?)
                    .map_err(|e| format!("{e:?}"))?;
            }
        }
        let txn = doc.transact();
        let fragment = txn
            .get_xml_fragment(bh_core::note::FRAGMENT)
            .ok_or("no fragment")?;
        let element = fragment
            .children(&txn)
            .filter_map(|child| match child {
                XmlOut::Element(element) => Some(element),
                _ => None,
            })
            .nth(paragraph)
            .ok_or("no paragraph")?;
        let text = element.children(&txn).find_map(|child| match child {
            XmlOut::Text(text) => Some(text),
            _ => None,
        });
        // An empty paragraph has no text: the editor names a caret there by
        // the paragraph's own start.
        let Some(text) = text else {
            let sticky = element
                .sticky_index(&txn, 0, yrs::Assoc::Before)
                .ok_or("no position")?;
            return ok(json!({"hex": hex(&sticky.encode_v1()), "len": 0}));
        };
        let len = text.len(&txn);
        let sticky = text
            .sticky_index(&txn, offset.min(len), assoc)
            .ok_or("no position")?;
        ok(json!({"hex": hex(&sticky.encode_v1()), "len": len}))
    }
    /// As the app's `note_selection`: relay nothing locally, but report the
    /// window's relative selection to this account's other devices.
    fn select(
        &self,
        window: &str,
        note: [u8; 32],
        anchor: Vec<u8>,
        head: Vec<u8>,
        label: &str,
    ) -> Result<Value, String> {
        let id = self.id()?;
        self.owner
            .show_note(window, id, note)
            .map_err(|e| format!("{e:?}"))?;
        let presence = self.sync.presence(id).ok_or("presence unavailable")?;
        presence.configure(label, self.device_colour()?);
        presence.foreground(true);
        if !presence.set(window, note, anchor, head) {
            return Err("invalid selection".into());
        }
        ok(json!({}))
    }
    /// As the app's pause or quit: announce nothing to show and close the join.
    fn clear(&self) -> Result<Value, String> {
        self.sync.leave_presence();
        ok(json!({}))
    }
    /// The remote carets this device currently shows.
    fn remote(&self) -> Result<Value, String> {
        let id = self.id()?;
        let receiver = self
            .sync
            .remote_presence(id)
            .ok_or("presence unavailable")?;
        let state = receiver.borrow().clone();
        let entries: Vec<Value> = state
            .entries()
            .iter()
            .map(|peer| {
                json!({
                    "handle": hex(&peer.handle),
                    "note": hex(&peer.note),
                    "label": peer.label,
                    "colour": peer.colour,
                    "anchor": hex(&peer.anchor),
                    "head": hex(&peer.head),
                })
            })
            .collect();
        ok(json!({"entries": entries}))
    }
    fn note(&self, window: &str, note: [u8; 32]) -> Result<Value, String> {
        let id = self.id()?;
        self.owner
            .show_note(window, id, note)
            .map_err(|e| format!("{e:?}"))?;
        let opened = self
            .owner
            .open(window, note)
            .map_err(|e| format!("{e:?}"))?;
        let working =
            bh_core::note::Note::from_ordered(&opened.state).map_err(|e| format!("{e:?}"))?;
        let key = self.key(note)?;
        let database = self
            .owner
            .shared_database(id)
            .map_err(|e| format!("{e:?}"))?;
        let accepted = database
            .lock()
            .unwrap()
            .accepted_note(key)
            .map_err(|e| format!("{e:?}"))?
            .ordered();
        let accepted_note =
            bh_core::note::Note::from_ordered(&accepted).map_err(|e| format!("{e:?}"))?;
        ok(json!({
            "paragraphs": paragraphs(&opened.state),
            "digest": hex(&working.digest().map_err(|e| format!("{e:?}"))?),
            "accepted_paragraphs": paragraphs(&accepted),
            "accepted_digest": hex(&accepted_note.digest().map_err(|e| format!("{e:?}"))?),
        }))
    }
    /// Native records boundary: the handle fixes authority and scope; signing
    /// happens after the approval request, outside its Owner/database locks.
    async fn records(&self, request: &Value) -> Result<Value, String> {
        let id = self.id()?;
        let records = self.owner.records(id).map_err(|e| format!("{e:?}"))?;
        let record = || -> Result<RecordId, String> {
            serde_json::from_value(request["record"].clone()).map_err(|e| e.to_string())
        };
        let operation = || -> Result<Operation, String> {
            serde_json::from_value(request["operation"].clone()).map_err(|e| e.to_string())
        };
        let saved = |saved: bh_data::mutation::pending::LocalSaved| json!({"mutation": saved.mutation, "content_rev": saved.content_rev, "skipped": saved.skipped});
        match request["op"].as_str().unwrap_or("") {
            "records-query" => {
                let query: Query =
                    serde_json::from_value(request["query"].clone()).map_err(|e| e.to_string())?;
                ok(serde_json::to_value(
                    records
                        .session()
                        .query(records.scope(), &query)
                        .map_err(|e| format!("{e:?}"))?,
                )
                .unwrap())
            }
            "records-submit" => ok(saved(
                records.submit(operation()?).map_err(|e| format!("{e:?}"))?,
            )),
            "records-approve" => {
                let op = operation()?;
                let approval = match &op {
                    Operation::DefineType { bytes } => {
                        let proposal = records
                            .prepare_change(bytes)
                            .map_err(|e| format!("{e:?}"))?;
                        records
                            .approval_request(&proposal)
                            .map_err(|e| format!("{e:?}"))?
                    }
                    _ => records
                        .approval_request_operation(op)
                        .map_err(|e| format!("{e:?}"))?,
                };
                let signer = self.sync.signer(id).ok_or("no native signer")?;
                let signature = signer
                    .sign_event(approval.message().to_vec())
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                ok(saved(
                    records
                        .approve(approval, signature)
                        .map_err(|e| format!("{e:?}"))?,
                ))
            }
            "records-undo" => {
                let target: MutationId = serde_json::from_value(request["mutation"].clone())
                    .map_err(|e| e.to_string())?;
                ok(saved(records.undo(target).map_err(|e| format!("{e:?}"))?))
            }
            "records-get" => {
                let row = records
                    .session()
                    .get(records.scope(), record()?)
                    .map_err(|e| format!("{e:?}"))?;
                ok(match row {
                    Some(row) => json!({"record":row.record,"type_id":row.type_id,
                        "revision":row.revision,"accepted":row.accepted,"doc":row.doc,
                        "view":row.view(),"pending":row.pending,"changed_at":row.changed_at.map(|p| p.0)}),
                    None => Value::Null,
                })
            }
            "records-history" => {
                let entries = records
                    .session()
                    .history(records.scope(), record()?, None, 100)
                    .map_err(|e| format!("{e:?}"))?;
                ok(json!({"entries": entries.iter().map(|entry| json!({
                    "position": entry.position.0, "mutation": entry.mutation,
                    "actor": entry.actor, "path": entry.path, "old": entry.old, "new": entry.new
                })).collect::<Vec<_>>() }))
            }
            _ => Err("unknown records command".into()),
        }
    }
    fn status(&self) -> Value {
        json!({
            "view": self.seen.last.lock().unwrap().clone(),
            "states": *self.seen.states.lock().unwrap(),
            "wakes": *self.seen.wakes.lock().unwrap(),
            "ended": *self.seen.ended.lock().unwrap(),
            "running": self.id().ok().is_some_and(|id| self.sync.running(id)),
        })
    }
    /// This device removes itself: the RemoveSelf is signed natively by its
    /// account owner and verified, permitted and ordered by the real
    /// authorization service and log. Only the submission request is made
    /// here, as no product submitter for a removal exists yet.
    ///
    /// The device's own authenticated session also asks for one ordinary
    /// read permit of its base just before the removal and again once the
    /// removal is ordered, and returns both answers. The session is held
    /// throughout, so this device's background sync can neither use it nor
    /// end it first.
    async fn remove_self(&self) -> Result<Value, String> {
        use bh_authz_proto::{FromService, ToService, Want, account_log_id, account_log_wrap};
        let id = self.id()?;
        let (_, capability) = self.host.ready_authority().ok_or("no authority")?;
        let removal = self
            .host
            .run_lent(id, &capability, |owner, cap| {
                Box::pin(async move {
                    let request = owner
                        .prepare_remove_self(&cap)
                        .map_err(|e| format!("{e:?}"))?;
                    owner
                        .sign_control(&cap, &request)
                        .await
                        .map(|event| event.as_bytes().to_vec())
                        .map_err(|e| format!("{e:?}"))
                })
            })
            .await
            .map_err(|_| "owner unavailable".to_owned())??;
        let signer = self.sync.signer(id).ok_or("no signer")?;
        let genesis = signer.identity().map_err(|e| format!("{e:?}"))?.genesis;
        let log = permit::LogId {
            kind: LogKind::Account,
            id: account_log_id(&genesis).map_err(|e| format!("{e:?}"))?,
        };
        let base = permit::LogId {
            kind: LogKind::Base,
            id: self
                .host
                .ready_parts(id)
                .ok_or("no ready parts")?
                .own_base
                .id()
                .0,
        };
        let read = || ToService::Permits {
            items: vec![Want::ReadEvents {
                log: base,
                first: 1,
                last: 1,
            }],
        };
        let client = self.sync.client(id).ok_or("no client")?;
        let mut session = client.authz().await.map_err(|e| format!("{e:?}"))?;
        let head = session.account_head();
        let before = verdict(session.ask(read()).await);
        let answer = session
            .ask(ToService::SubmitControl {
                log,
                event: removal.clone(),
                delivery: None,
                attachment: None,
            })
            .await
            .map_err(|e| format!("{e:?}"))?;
        let FromService::Permits { items } = answer else {
            return Err(format!("removal refused: {answer:?}"));
        };
        let [Ok(append)] = items.as_slice() else {
            return Err("removal permits".into());
        };
        let wrapped = account_log_wrap(&removal, None).map_err(|e| format!("{e:?}"))?;
        let data = bh_sync_client::data::DataSocket::open(self.connector.as_ref())
            .await
            .map_err(|_| "data socket".to_owned())?;
        let permit = append.clone();
        let response = data
            .ask(|id| Request::Append {
                id,
                permit,
                event: wrapped.encode(),
            })
            .await
            .map_err(|_| "removal append".to_owned())?;
        let ack = match response {
            Response::Acked { ack, .. } => {
                permit::AppendAck::decode(&ack).map_err(|e| format!("{e:?}"))?
            }
            other => return Err(format!("removal not ordered: {other:?}")),
        };
        // Asked only now, after the removal's Ack.
        let asked_ms = now_ms();
        let after = verdict(session.ask(read()).await);
        drop(session);
        ok(json!({
            "position": ack.head.position,
            "event": sha(&removal),
            "probe": {
                "want": "ReadEvents", "log": format!("01{}", hex(&base.id)), "first": 1, "last": 1,
                "session_head": {"position": head.position, "hash": hex(&head.hash)},
                "before": before, "asked_ms": asked_ms, "after": after,
            },
        }))
    }
    async fn reconfirm(&self) -> Result<Value, String> {
        let id = self.id()?;
        let handle = self.sync.handle(id).ok_or("no handle")?;
        handle.ops.reconfirm().await.map_err(|e| format!("{e:?}"))?;
        ok(json!({}))
    }
    /// The K2 shape (an honest paragraph, then three crafted inserts with
    /// non-adjacent anchors) committed through this device's own leased
    /// writers in `windows` w1..wN, choosing roles whose log-order text
    /// differs from a single merged state's. Every update goes through the
    /// real local commit, then this device's outbox, signer and the log.
    fn k2(&mut self, note: [u8; 32]) -> Result<Value, String> {
        let id = self.id()?;
        let mut leases = Vec::new();
        for n in 0..8 {
            let window = format!("k2-{n}");
            self.owner
                .show_note(&window, id, note)
                .map_err(|e| format!("{e:?}"))?;
            let opened = self
                .owner
                .open_leased(&window, note)
                .map_err(|e| format!("{e:?}"))?;
            leases.push((window, opened.writer.ok_or("no writer")?.client_id));
        }
        let ids: Vec<u64> = leases.iter().map(|(_, c)| *c).collect();
        let mut chosen = None;
        'search: for s in 0..ids.len() {
            for p in 0..ids.len() {
                for h in 0..ids.len() {
                    for l in 0..ids.len() {
                        let roles = [s, p, h, l];
                        if (0..4).any(|i| (0..i).any(|j| roles[i] == roles[j])) {
                            continue;
                        }
                        let updates = k2_updates(ids[s], ids[p], ids[h], ids[l]);
                        if k2_diverges(&updates).map_err(|e| format!("{e:?}"))? {
                            chosen = Some((roles, updates));
                            break 'search;
                        }
                    }
                }
            }
        }
        let (roles, updates) = chosen.ok_or("no divergent K2 role assignment")?;
        let mut committed = Vec::new();
        for (role, update) in roles.iter().zip(&updates) {
            let window = &leases[*role].0;
            let opened = self
                .owner
                .open_leased(window, note)
                .map_err(|e| format!("{e:?}"))?;
            let lease = opened.writer.ok_or("no writer")?;
            if lease.client_id != leases[*role].1 {
                return Err("lease changed".into());
            }
            self.requests += 1;
            let mut request = [0; 16];
            request[..8].copy_from_slice(&self.requests.to_be_bytes());
            let (ack, _) = self
                .owner
                .commit_leased(window, opened.generation, lease.token, request, update)
                .map_err(|e| format!("K2 commit: {e:?}"))?;
            committed.push(hex(&ack.request_id));
        }
        self.sync.wake(id);
        let refs: Vec<&[u8]> = updates.iter().map(Vec::as_slice).collect();
        let mut live = bh_core::note::Note::new().map_err(|e| format!("{e:?}"))?;
        for u in &refs {
            live.apply_update(u).map_err(|e| format!("{e:?}"))?;
        }
        // An insertion that cannot attach (its anchor is missing) is never
        // committed by a real writer.
        let window = &leases[roles[3]].0;
        let opened = self
            .owner
            .open_leased(window, note)
            .map_err(|e| format!("{e:?}"))?;
        let lease = opened.writer.ok_or("no writer")?;
        let end = bh_device::Owner::core_author(&opened)
            .map_err(|e| format!("{e:?}"))?
            .writer_end(lease.client_id)
            .map_err(|e| format!("{e:?}"))?
            .unwrap_or(0);
        let orphan = item(
            lease.client_id,
            end,
            (ids[roles[0]] ^ 1, 900),
            None,
            "orphan",
        );
        self.requests += 1;
        let mut request = [0; 16];
        request[..8].copy_from_slice(&self.requests.to_be_bytes());
        let orphan =
            self.owner
                .commit_leased(window, opened.generation, lease.token, request, &orphan);
        let orphan = match orphan {
            Ok(_) => "committed",
            Err(bh_device::OwnerError::Store(bh_storage::StoreError::InvalidUpdate)) => "refused",
            Err(error) => return Err(format!("orphan commit: {error:?}")),
        };
        ok(
            json!({"committed": committed, "live_digest": hex(&live.digest().map_err(|e| format!("{e:?}"))?),
            "live_title": live.title_preview().map_err(|e| format!("{e:?}"))?, "unattachable": orphan}),
        )
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The service's answer to one permit request, by kind only.
fn verdict(answer: Result<bh_authz_proto::FromService, bh_sync_client::ClientError>) -> String {
    use bh_authz_proto::FromService;
    match answer {
        Ok(FromService::Permits { items }) if items.iter().all(Result::is_ok) => "permitted".into(),
        Ok(FromService::Permits { items }) => {
            let refused: Vec<_> = items.iter().filter_map(|i| i.as_ref().err()).collect();
            format!("item refused: {refused:?}")
        }
        Ok(FromService::Refused { reason }) => format!("refused: {reason:?}"),
        Ok(other) => format!("answered: {other:?}"),
        Err(error) => format!("failed: {error:?}"),
    }
}

/// Fixture editor: one delta appending text to the final paragraph, under
/// the actual leased writer, hydrated from the current working state.
fn typed_delta(state: &bh_core::note::OrderedState, client: u64, value: &str) -> Vec<u8> {
    use yrs::{
        Text, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment, XmlOut, XmlTextPrelim,
        updates::decoder::Decode,
    };
    let doc = yrs::Doc::with_options(yrs::Options {
        offset_kind: yrs::OffsetKind::Utf16,
        cleanup_formatting: false,
        ..yrs::Options::with_client_id(yrs::ClientID::new(client))
    });
    {
        let mut txn = doc.transact_mut();
        for segment in state.segments() {
            txn.apply_update(Update::decode_v1(segment).unwrap())
                .unwrap();
        }
    }
    let mut txn = doc.transact_mut();
    let fragment = txn.get_or_insert_xml_fragment(bh_core::note::FRAGMENT);
    let paragraph = fragment
        .children(&txn)
        .filter_map(|v| match v {
            XmlOut::Element(e) => Some(e),
            _ => None,
        })
        .last();
    let paragraph = paragraph.unwrap_or_else(|| {
        let len = fragment.len(&txn);
        fragment.insert(&mut txn, len, XmlElementPrelim::empty("paragraph"))
    });
    let text = paragraph.children(&txn).find_map(|v| match v {
        XmlOut::Text(t) => Some(t),
        _ => None,
    });
    let text = text.unwrap_or_else(|| paragraph.insert(&mut txn, 0, XmlTextPrelim::new("")));
    let end = text.len(&txn);
    text.insert(&mut txn, end, value);
    txn.encode_update_v1()
}

/// Every top-level paragraph's text, in document order.
fn paragraphs(state: &bh_core::note::OrderedState) -> Vec<String> {
    use yrs::{
        GetString, ReadTxn, Transact, Update, XmlFragment, XmlOut, updates::decoder::Decode,
    };
    let doc = yrs::Doc::new();
    {
        let mut txn = doc.transact_mut();
        for segment in state.segments() {
            txn.apply_update(Update::decode_v1(segment).expect("segment"))
                .expect("apply");
        }
    }
    let txn = doc.transact();
    let Some(fragment) = txn.get_xml_fragment(bh_core::note::FRAGMENT) else {
        return Vec::new();
    };
    fragment
        .children(&txn)
        .filter_map(|child| match child {
            XmlOut::Element(element) => Some(
                element
                    .children(&txn)
                    .filter_map(|inner| match inner {
                        XmlOut::Text(text) => Some(text.get_string(&txn)),
                        _ => None,
                    })
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect()
}

fn var(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}
/// One crafted Yjs v1 text insert by `client` at `clock`.
fn item(
    client: u64,
    clock: u32,
    origin: (u64, u32),
    right: Option<(u64, u32)>,
    text: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, 1);
    var(&mut out, 1);
    var(&mut out, client);
    var(&mut out, clock as u64);
    out.push(0x84 | if right.is_some() { 0x40 } else { 0 });
    var(&mut out, origin.0);
    var(&mut out, origin.1 as u64);
    if let Some((c, k)) = right {
        var(&mut out, c);
        var(&mut out, k as u64);
    }
    var(&mut out, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
    var(&mut out, 0);
    out
}
fn k2_updates(s: u64, p: u64, h: u64, l: u64) -> [Vec<u8>; 4] {
    let mut seed = bh_core::note::Note::with_writer(s).unwrap();
    [
        seed.append_paragraph("hello").unwrap(),
        item(p, 0, (s, 6), None, "HL"),
        item(h, 0, (s, 4), Some((p, 1)), "abcd"),
        item(l, 0, (s, 6), None, " world"),
    ]
}
fn k2_diverges(updates: &[Vec<u8>; 4]) -> Result<bool, bh_core::note::NoteError> {
    use bh_core::note::NoteError;
    let mut live = bh_core::note::Note::new()?;
    for u in updates {
        match live.apply_update(u) {
            Ok(()) => (),
            Err(NoteError::Unavailable) => return Err(NoteError::Unavailable),
            Err(_) => return Ok(false),
        }
    }
    let mut merged = bh_core::note::Note::new()?;
    match merged.apply_update(&live.state()?) {
        Ok(()) => Ok(merged.title_preview()? != live.title_preview()?),
        Err(NoteError::Unavailable) => Err(NoteError::Unavailable),
        Err(_) => Ok(false),
    }
}

fn arg_note(request: &Value) -> Result<[u8; 32], String> {
    request["note"]
        .as_str()
        .filter(|n| n.len() == 64)
        .map(unhex)
        .ok_or_else(|| "note".to_owned())
}

/// A Yjs v1 relative position sent as hex: the editor's own encoding.
fn arg_bytes(request: &Value, key: &str) -> Result<Vec<u8>, String> {
    let encoded = request[key].as_str().ok_or_else(|| format!("{key} hex"))?;
    if !encoded.is_ascii() || !encoded.len().is_multiple_of(2) {
        return Err(format!("{key} hex"));
    }
    (0..encoded.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("{key} hex"))
}

async fn handle(device: &mut Device, request: &Value) -> Result<Value, String> {
    let text = |key: &str| request[key].as_str().unwrap_or_default().to_owned();
    match request["op"].as_str().unwrap_or_default() {
        "startup" => {
            let screen = device.screen(AccountOperation::Startup).await?;
            ok(json!({"screen": screen}))
        }
        "signup" => {
            let welcome = device.screen(AccountOperation::Startup).await?;
            if welcome != Screen::Welcome {
                return Err(format!("not a new device: {welcome:?}"));
            }
            let kit = device
                .screen(AccountOperation::Create(text("password")))
                .await?;
            if !matches!(kit, Screen::Kit { .. }) {
                return Err(format!("no kit: {kit:?}"));
            }
            let ready = device.screen(AccountOperation::ConfirmKit).await?;
            ok(json!({"screen": ready}))
        }
        "open" => device.open().await,
        "show" => {
            let shown = device
                .pairing
                .show(device.scope(1)?, &device.sync)
                .map_err(|e| format!("{e:?}"))?;
            ok(json!({"session": shown.session, "qr": shown.qr_text, "svg": shown.qr_svg}))
        }
        "pair-status" => {
            let status = device
                .pairing
                .status(&device.scope(1)?, &text("session"))
                .map_err(|e| format!("{e:?}"))?;
            ok(serde_json::to_value(status).unwrap())
        }
        "approve" => {
            let status = device
                .pairing
                .approve(&device.scope(1)?, &text("session"))
                .map_err(|e| format!("{e:?}"))?;
            ok(serde_json::to_value(status).unwrap())
        }
        "join" => {
            let ticket = device
                .pairing
                .join(
                    "main",
                    &device.host,
                    &device.sync,
                    &text("qr"),
                    text("label").into_bytes(),
                )
                .map_err(|e| format!("{e:?}"))?;
            ok(json!({"ticket": ticket.ticket}))
        }
        "join-status" => {
            let status = device
                .pairing
                .join_status("main", &text("ticket"))
                .map_err(|e| format!("{e:?}"))?;
            ok(serde_json::to_value(status).unwrap())
        }
        "save" => {
            let note = arg_note(request)?;
            device.save(&text("window"), note, &text("text"))
        }
        // One caller-controlled keystroke per call; no driver timer.
        "type" => device.edit_text(&text("window"), arg_note(request)?, &text("text"), true),
        "note" => device.note(&text("window"), arg_note(request)?),
        "records-query" | "records-submit" | "records-approve" | "records-undo" | "records-get"
        | "records-history" => device.records(request).await,
        // A Yjs v1 relative position at a paragraph offset in the working
        // note, as the editor's own encoder produces for a selection.
        "relative" => {
            let assoc = if request["assoc"].as_str() == Some("before") {
                yrs::Assoc::Before
            } else {
                yrs::Assoc::After
            };
            device.relative(
                &text("window"),
                arg_note(request)?,
                request["paragraph"].as_u64().unwrap_or(0) as usize,
                request["offset"].as_u64().unwrap_or(0) as u32,
                assoc,
            )
        }
        // Report this device's caret in a note, as the app's note_selection
        // does: the bytes are Yjs v1 relative positions, never PM integers.
        "select" => {
            let label = if request["label"].is_string() {
                text("label")
            } else {
                "Peer".to_owned()
            };
            device.select(
                &text("window"),
                arg_note(request)?,
                arg_bytes(request, "anchor")?,
                arg_bytes(request, "head")?,
                &label,
            )
        }
        // Announce nothing to show, as an app pause or quit would.
        "clear" => device.clear(),
        // The remote carets this device currently shows.
        "remote-presence" => device.remote(),
        "create-note" => {
            let note = device
                .owner
                .create_note(device.id()?)
                .map_err(|e| format!("{e:?}"))?;
            ok(json!({"note": hex(&note)}))
        }
        "verify-receipt" => {
            let encoded = text("receipt");
            if !encoded.is_ascii() || !encoded.len().is_multiple_of(2) {
                return Err("receipt hex".into());
            }
            let bytes = (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "receipt hex")?;
            // A stored receipt names its own log; default to the home base.
            let base = match request["log"].as_str() {
                Some(log) if log.len() == 64 && log.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    unhex(log)
                }
                Some(_) => return Err("log hex".into()),
                None => device.key([0; 32])?.base,
            };
            let receipt =
                bh_sync::receipt::verify(&device.faults.root, bh_sync::BaseId(base), &bytes)
                    .map_err(|e| format!("{e:?}"))?;
            ok(json!({"position": receipt.head().position,
                "hash": hex(&receipt.head().hash.0)}))
        }
        "admission" => {
            let signer = device.sync.signer(device.id()?).ok_or("no signer")?;
            let account = signer.current_account().map_err(|e| format!("{e:?}"))?;
            let devices: Vec<String> = account
                .active_devices()
                .map_err(|e| format!("{e:?}"))?
                .map(|keys| hex(&keys.id().0))
                .collect();
            ok(json!({"account": hex(&account.id().0),
                "position": account.head().position, "devices": devices}))
        }
        "status" => ok(device.status()),
        "wake" => {
            device.sync.wake(device.id()?);
            ok(json!({}))
        }
        "faults" => {
            let mut plan = device.faults.plan.lock().unwrap();
            let flag = |key: &str, current: bool| request[key].as_bool().unwrap_or(current);
            plan.offline = flag("offline", plan.offline);
            plan.drop_next_ack = flag("drop_next_ack", plan.drop_next_ack);
            plan.hold_appends = flag("hold_appends", plan.hold_appends);
            plan.hold_acks = flag("hold_acks", plan.hold_acks);
            plan.refuse_read_after_drop =
                flag("refuse_read_after_drop", plan.refuse_read_after_drop);
            if let Some(event) = request["release"].as_str() {
                plan.release.push(event.to_owned());
            }
            device.faults.offline.send_replace(plan.offline);
            device.faults.released.send_modify(|n| *n += 1);
            device.faults.record(json!({"plan": request.clone()}));
            ok(json!({}))
        }
        "remove-self" => device.remove_self().await,
        "reconfirm" => device.reconfirm().await,
        "k2" => device.k2(arg_note(request)?),
        "quit" => {
            device.sync.leave_presence();
            device.sync.shutdown_all().await;
            ok(json!({}))
        }
        other => Err(format!("unknown op {other:?}")),
    }
}

fn endpoint_root(text: &str) -> [u8; 32] {
    let value: Value = serde_json::from_str(text).expect("endpoint file");
    unhex(value["hosting_root"].as_str().expect("hosting root"))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, dir, endpoint, keys] = args.as_slice() else {
        panic!("usage: local_sync_device DIR ENDPOINT_FILE gated|plain");
    };
    let dir = Path::new(dir);
    std::fs::create_dir_all(dir).unwrap();
    let text = std::fs::read_to_string(endpoint).expect("endpoint file");
    let configured = Configured::from_text(&text);
    let Configured::Ready(ready) = &configured else {
        panic!("a configured endpoint file (local stack or deployed hardware endpoint)");
    };
    let faults = Arc::new(Faults {
        root: endpoint_root(&text),
        plan: Mutex::default(),
        offline: watch::Sender::new(false),
        released: watch::Sender::new(0),
        journal: Mutex::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("frames.jsonl"))
                .unwrap(),
        ),
        stages: std::sync::atomic::AtomicU32::new(0xF000_0000),
    });
    faults.record(json!({"process": std::process::id(), "started": true}));
    let connector = Arc::new(FaultConnector {
        inner: WsConnector::new(&ready.edge_url),
        faults: faults.clone(),
    });
    let relay = bh_sync_client::pairing::HttpRelay::new(&ready.edge_url);
    let store = FileKeys::open(dir.join("software-test-keys.json"), keys == "gated");
    let owner = Arc::new(bh_device::Owner::default());
    let (host, _) = fresh_test_host(&owner, dir, store).await;
    let sync =
        SyncHost::with_transport(configured.clone(), owner.clone(), connector.clone(), relay);
    let mut device = Device {
        owner,
        host,
        sync,
        pairing: PairingHost::default(),
        seen: Arc::default(),
        faults,
        connector,
        requests: 0,
    };
    let (lines, mut requests) = mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    emit(json!({"event": "ready", "pid": std::process::id()}));
    while let Some(line) = requests.recv().await {
        let request: Value = serde_json::from_str(&line).expect("request");
        let quit = request["op"] == "quit";
        let reply =
            match tokio::time::timeout(Duration::from_secs(300), handle(&mut device, &request))
                .await
            {
                Ok(Ok(value)) => json!({"reply": request["seq"], "ok": value}),
                Ok(Err(error)) => json!({"reply": request["seq"], "err": error}),
                Err(_) => json!({"reply": request["seq"], "err": "timed out"}),
            };
        emit(reply);
        if quit {
            break;
        }
    }
}
