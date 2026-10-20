#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_authz::proto::{FromService, ToService, Want};
use bh_authz::{EdgeError, EdgeReader, LogItems, LogRead, Service, SyntheticAttestation};
use bh_crypto::{SecretBytes, SigningKey};
use bh_sync::Head;
use futures_util::{Sink, SinkExt, Stream, StreamExt, future::BoxFuture};
use std::{
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::{device::*, *};
use tokio::sync::{Notify, Semaphore};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};

struct Pause {
    edge: Arc<FakeEdge>,
    enabled: AtomicBool,
    entered: Notify,
    release: Semaphore,
    held: AtomicUsize,
}
struct Held<'a>(&'a AtomicUsize);
impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl EdgeReader for Pause {
    fn read_log(&self, p: Vec<u8>) -> BoxFuture<'_, Result<LogItems, EdgeError>> {
        self.edge.read_log(p)
    }
    fn read_bodies(&self, p: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        self.edge.read_bodies(p)
    }
    fn read_log_with_receipt(&self, p: Vec<u8>) -> BoxFuture<'_, Result<LogRead, EdgeError>> {
        Box::pin(async move {
            let result = self.edge.read_log_with_receipt(p).await;
            if self.enabled.swap(false, Ordering::SeqCst) {
                self.held.fetch_add(1, Ordering::SeqCst);
                let _held = Held(&self.held);
                self.entered.notify_one();
                self.release.acquire().await.unwrap().forget();
            }
            result
        })
    }
}
type Socket = WebSocketStream<tokio::io::DuplexStream>;
type Session = bh_confidential_channel::record::Session<Memory>;
#[derive(Default)]
struct SendGate {
    blocked: AtomicBool,
    flush_blocked: AtomicBool,
    entered: Notify,
    waker: Mutex<Option<Waker>>,
}
struct Gated {
    ws: Socket,
    gate: Arc<SendGate>,
}
impl Stream for Gated {
    type Item = Result<Message, WsError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.ws).poll_next(cx)
    }
}
impl Sink<Message> for Gated {
    type Error = WsError;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        if self.gate.blocked.load(Ordering::SeqCst) {
            *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
            self.gate.entered.notify_one();
            Poll::Pending
        } else {
            Pin::new(&mut self.ws).poll_ready(cx)
        }
    }
    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), WsError> {
        Pin::new(&mut self.ws).start_send(item)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        if self.gate.flush_blocked.load(Ordering::SeqCst) {
            *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
            self.gate.entered.notify_one();
            Poll::Pending
        } else {
            Pin::new(&mut self.ws).poll_flush(cx)
        }
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
        Pin::new(&mut self.ws).poll_close(cx)
    }
}
struct Fixture {
    gate: Arc<SendGate>,
    h: Harness,
    edge: Arc<Pause>,
    ws: Socket,
    session: Session,
    serving: tokio::task::JoinHandle<Result<(), bh_authz::ServiceError>>,
    log: bh_authz::proto::LogId,
}
impl Fixture {
    async fn new() -> Self {
        let h = Harness::new();
        let device = Device::new();
        let account = Account::create_full(&device);
        h.publish(&account);
        let edge = Arc::new(Pause {
            edge: h.edge.clone(),
            enabled: AtomicBool::new(true),
            entered: Notify::new(),
            release: Semaphore::new(0),
            held: AtomicUsize::new(0),
        });
        let service = Service::open(
            &h.dir.path().join("channel.sqlite"),
            h.keys(),
            h.clock.clone(),
            edge.clone(),
        )
        .unwrap();
        let root = SigningKey::generate();
        let config = channel_config(&root);
        let (device_socket, server) = tokio::io::duplex(1 << 20);
        let gate = Arc::new(SendGate::default());
        let send_gate = gate.clone();
        let serving = tokio::spawn(async move {
            let ws = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
            service
                .serve_connection(
                    Gated {
                        ws,
                        gate: send_gate,
                    },
                    &config,
                    &SyntheticAttestation,
                )
                .await
        });
        let ws = WebSocketStream::from_raw_socket(device_socket, Role::Client, None).await;
        let (mut ws, mut session) = handshake(ws, &root).await;
        let FromService::Challenge { challenge } = receive(&mut ws, &mut session).await else {
            panic!()
        };
        let binding = session.binding().unwrap();
        assert!(matches!(
            ask(
                &mut ws,
                &mut session,
                authenticate_message(&account, &device, binding, challenge)
            )
            .await,
            FromService::Authenticated { .. }
        ));
        Self {
            h,
            edge,
            ws,
            session,
            serving,
            log: account.log,
            gate,
        }
    }
    async fn request(&mut self, max_events: u16) {
        let request = ToService::ReadBatch {
            want: Want::ReadBatch {
                log: self.log,
                after: Head::EMPTY,
                max_events,
            },
        };
        let bytes = self
            .session
            .seal(SecretBytes::from_vec(request.encode().unwrap()))
            .unwrap();
        send(&mut self.ws, bytes).await;
    }
    async fn start(&mut self) {
        self.request(1).await;
        self.edge.entered.notified().await;
    }
}

#[tokio::test(start_paused = true)]
async fn authenticated_close_cancels_selection_before_barrier_release() {
    let mut f = Fixture::new().await;
    f.start().await;
    let close = f.session.close().unwrap();
    send(&mut f.ws, close).await;
    tokio::time::timeout(Duration::from_millis(100), &mut f.serving)
        .await
        .expect("Close must be observed without releasing selection")
        .unwrap()
        .unwrap();
    assert_eq!(f.edge.held.load(Ordering::SeqCst), 0);
    assert!(matches!(
        f.ws.next().await,
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
}
#[tokio::test(start_paused = true)]
async fn transport_end_cancels_selection_before_barrier_release() {
    let mut f = Fixture::new().await;
    f.start().await;
    drop(f.ws);
    let _ = tokio::time::timeout(Duration::from_millis(100), f.serving)
        .await
        .expect("transport termination must cancel selection")
        .unwrap();
    assert_eq!(f.edge.held.load(Ordering::SeqCst), 0);
}
#[tokio::test(start_paused = true)]
async fn ninth_admitted_request_closes_without_a_selected_reply() {
    let mut f = Fixture::new().await;
    f.start().await;
    for _ in 0..8 {
        f.request(2).await;
    }
    let _ = tokio::time::timeout(Duration::from_millis(100), &mut f.serving)
        .await
        .expect("queue overflow must close rather than wait for selection")
        .unwrap();
    assert_eq!(f.edge.held.load(Ordering::SeqCst), 0);
    assert!(!matches!(f.ws.next().await, Some(Ok(Message::Binary(_)))));
}
#[tokio::test(start_paused = true)]
async fn eight_admitted_requests_reply_in_fifo_order() {
    let mut f = Fixture::new().await;
    f.start().await;
    for n in [2, 3, 1, 2, 3, 1, 2] {
        f.request(n).await;
    }
    f.edge.release.add_permits(1);
    for count in [1, 2, 3, 1, 2, 3, 1, 2] {
        let FromService::ReadBatch {
            result: bh_authz::proto::ReadBatchResult::Selected { items, .. },
            ..
        } = receive(&mut f.ws, &mut f.session).await
        else {
            panic!("FIFO Selected")
        };
        assert_eq!(items.len(), count);
    }
    let close = f.session.close().unwrap();
    send(&mut f.ws, close).await;
    f.serving.await.unwrap().unwrap();
}
#[tokio::test(start_paused = true)]
async fn expiry_while_sink_not_ready_never_emits_selected() {
    let mut f = Fixture::new().await;
    f.start().await;
    f.gate.blocked.store(true, Ordering::SeqCst);
    f.edge.release.add_permits(1);
    f.gate.entered.notified().await;
    f.h.clock.advance(30_001);
    f.gate.blocked.store(false, Ordering::SeqCst);
    f.gate.waker.lock().unwrap().take().unwrap().wake();
    assert!(matches!(
        receive(&mut f.ws, &mut f.session).await,
        FromService::Unavailable
    ));
    let close = f.session.close().unwrap();
    send(&mut f.ws, close).await;
    f.serving.await.unwrap().unwrap();
}
#[tokio::test(start_paused = true)]
async fn expiry_while_flush_pending_drops_buffer_instead_of_sending() {
    let mut f = Fixture::new().await;
    f.start().await;
    f.gate.flush_blocked.store(true, Ordering::SeqCst);
    f.edge.release.add_permits(1);
    f.gate.entered.notified().await;
    f.h.clock.advance(30_001);
    f.gate.flush_blocked.store(false, Ordering::SeqCst);
    f.gate.waker.lock().unwrap().take().unwrap().wake();
    assert!(!matches!(f.ws.next().await, Some(Ok(Message::Binary(_)))));
    assert!(f.serving.await.unwrap().is_err());
}
#[tokio::test(start_paused = true)]
async fn expired_buffer_is_not_flushed_by_a_websocket_ping() {
    let mut f = Fixture::new().await;
    f.start().await;
    f.gate.flush_blocked.store(true, Ordering::SeqCst);
    f.edge.release.add_permits(1);
    f.gate.entered.notified().await;
    f.h.clock.advance(30_001);
    f.ws.send(Message::Ping(vec![1].into())).await.unwrap();
    assert!(!matches!(f.ws.next().await, Some(Ok(Message::Binary(_)))));
    assert!(f.serving.await.unwrap().is_err());
}
#[tokio::test(start_paused = true)]
async fn close_while_sink_not_ready_drops_without_flushing() {
    let mut f = Fixture::new().await;
    f.start().await;
    f.gate.blocked.store(true, Ordering::SeqCst);
    f.edge.release.add_permits(1);
    f.gate.entered.notified().await;
    let close = f.session.close().unwrap();
    send(&mut f.ws, close).await;
    tokio::time::timeout(Duration::from_millis(100), &mut f.serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!matches!(f.ws.next().await, Some(Ok(Message::Binary(_)))));
}
#[tokio::test(start_paused = true)]
async fn original_deadline_survives_selection_barrier() {
    let mut f = Fixture::new().await;
    f.start().await;
    f.h.clock.advance(30_001);
    f.edge.release.add_permits(1);
    assert!(matches!(
        receive(&mut f.ws, &mut f.session).await,
        FromService::Unavailable
    ));
    let close = f.session.close().unwrap();
    send(&mut f.ws, close).await;
    f.serving.await.unwrap().unwrap();
}
