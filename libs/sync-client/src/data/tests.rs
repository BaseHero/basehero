use super::*;
use crate::transport::{Socket, socket_config};
use bh_sync::wire::{MAX_FRAME_LEN, Refusal};
use futures_util::future::BoxFuture;
use tokio::io::DuplexStream;
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

type Peer = WebSocketStream<DuplexStream>;
struct Once(Mutex<Option<Socket>>);
impl Connector for Once {
    fn connect(&self, _: Route) -> BoxFuture<'_, Result<Socket, TransportError>> {
        Box::pin(async { self.0.lock().unwrap().take().ok_or(TransportError) })
    }
}
async fn pair() -> (DataSocket, Peer) {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let client = WebSocketStream::from_raw_socket(a, Role::Client, Some(socket_config())).await;
    let peer = WebSocketStream::from_raw_socket(b, Role::Server, Some(socket_config())).await;
    let data = DataSocket::open(&Once(Mutex::new(Some(Box::pin(client)))))
        .await
        .unwrap();
    (data, peer)
}
async fn request(data: &DataSocket, peer: &mut Peer) -> (u32, Answers) {
    let answers = data
        .send(|id| Request::Read { id, permit: vec![] })
        .unwrap();
    let frame = peer.next().await.unwrap().unwrap();
    let Request::Read { id, .. } = Request::decode(&frame.into_data()).unwrap() else {
        panic!("read")
    };
    (id, answers)
}
// Credit is a reader barrier: the handoff or deliberate discard has happened.
async fn deliver(peer: &mut Peer, response: Response) {
    let frame = response.encode().unwrap();
    let length = frame.len();
    peer.send(Message::Binary(frame.into())).await.unwrap();
    let credit = tokio::time::timeout(Duration::from_secs(2), peer.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        Request::decode(&credit.into_data()).unwrap(),
        Request::Credit {
            bytes: length as u32
        }
    );
}
fn body(id: u32, last: bool) -> Response {
    Response::Body {
        id,
        index: 0,
        last,
        bytes: vec![42; MAX_FRAME_LEN - 13],
    }
}
async fn ended(answers: &mut Answers) {
    assert!(
        tokio::time::timeout(Duration::from_secs(2), answers.next())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn presence_join_receives_multiple_nonterminal_frames() {
    let (data, mut peer) = pair().await;
    let mut answers = data
        .send(|id| Request::PresenceJoin {
            id,
            permit: vec![8],
        })
        .unwrap();
    let frame = peer.next().await.unwrap().unwrap();
    let Request::PresenceJoin { id, .. } = Request::decode(&frame.into_data()).unwrap() else {
        panic!("presence join");
    };
    let first = Response::Peers {
        id,
        others: 1,
        event: 0,
        slot: 7,
    };
    let second = Response::Presence {
        id,
        from: 7,
        sealed: vec![4],
    };
    deliver(&mut peer, first.clone()).await;
    deliver(&mut peer, second.clone()).await;
    assert_eq!(answers.next().await, Some(first));
    assert_eq!(answers.next().await, Some(second));
    assert!(
        data.waiters
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains_key(&id)
    );
}

#[tokio::test]
async fn maximum_events_receipt_returns_exact_frame_credit() {
    let (data, mut peer) = pair().await;
    let (id, mut answers) = request(&data, &mut peer).await;
    let response = Response::Events {
        id,
        items: vec![(vec![0; bh_sync::Commitment::LEN], vec![0; 65574]); 64],
        receipt: Some([0x5a; 300]),
        coverage: None,
    };
    // deliver asserts Credit equals this frame's exact encoded byte count.
    deliver(&mut peer, response.clone()).await;
    assert_eq!(data.budget.lock().unwrap().total, 4_207_095);
    assert_eq!(answers.next().await, Some(response));
    assert_eq!(data.budget.lock().unwrap().total, 0);
}

#[tokio::test]
async fn home_storage_answer_is_charged_credited_and_terminal() {
    let (data, mut peer) = pair().await;
    let (id, mut answers) = request(&data, &mut peer).await;
    let response = Response::HomeObjectsStored {
        id,
        prefix_digest: bh_sync::Digest([3; 32]),
        bundle_digest: bh_sync::Digest([4; 32]),
    };
    deliver(&mut peer, response.clone()).await;
    assert_eq!(data.budget.lock().unwrap().total, 71);
    assert!(data.waiters.lock().unwrap().as_ref().unwrap().is_empty());
    assert_eq!(answers.next().await, Some(response));
    assert_eq!(data.budget.lock().unwrap().total, 0);
    ended(&mut answers).await;
}

#[tokio::test]
async fn maximum_unread_body_overflows_only_its_id() {
    let (data, mut peer) = pair().await;
    let (id, mut stalled) = request(&data, &mut peer).await;
    deliver(&mut peer, body(id, false)).await;
    deliver(&mut peer, body(id, false)).await; // per-id overflow, deliberately discarded
    let (other, mut healthy) = request(&data, &mut peer).await;
    deliver(&mut peer, Response::Staged { id: other }).await;
    assert!(matches!(
        healthy.next().await,
        Some(Response::Staged { .. })
    ));
    assert!(matches!(stalled.next().await, Some(Response::Body { .. })));
    ended(&mut stalled).await; // never a forged last=true or successful status
}

#[tokio::test]
async fn aggregate_cap_includes_removed_ids_and_reserves_small_answers() {
    let (data, mut peer) = pair().await;
    let (a, mut first) = request(&data, &mut peer).await;
    let (b, second) = request(&data, &mut peer).await;
    deliver(&mut peer, body(a, true)).await;
    deliver(&mut peer, body(b, true)).await;
    assert!(data.waiters.lock().unwrap().as_ref().unwrap().is_empty());
    assert_eq!(data.budget.lock().unwrap().total, 8_519_680);
    let (c, mut overflow) = request(&data, &mut peer).await;
    deliver(&mut peer, body(c, true)).await;
    ended(&mut overflow).await;
    assert_eq!(data.budget.lock().unwrap().total, 8_519_680);
    let (d, mut small) = request(&data, &mut peer).await;
    deliver(
        &mut peer,
        Response::Events {
            id: d,
            items: vec![],
            receipt: None,
            coverage: None,
        },
    )
    .await;
    assert_eq!(data.budget.lock().unwrap().total, 8_519_691);
    assert!(matches!(small.next().await, Some(Response::Events { .. })));
    assert_eq!(data.budget.lock().unwrap().total, 8_519_680);
    assert!(matches!(first.next().await, Some(Response::Body { .. })));
    assert_eq!(data.budget.lock().unwrap().total, 4_259_840);
    drop(second);
    assert_eq!(data.budget.lock().unwrap().total, 0);
    let (e, mut reclaimed) = request(&data, &mut peer).await;
    deliver(&mut peer, body(e, true)).await;
    assert!(matches!(
        reclaimed.next().await,
        Some(Response::Body { .. })
    ));
    assert_eq!(data.budget.lock().unwrap().total, 0);
}

#[tokio::test]
async fn consuming_a_frame_reclaims_the_same_live_request_budget() {
    let (data, mut peer) = pair().await;
    let (id, mut answers) = request(&data, &mut peer).await;
    deliver(&mut peer, body(id, false)).await;
    let queued = data.waiters.lock().unwrap().as_ref().unwrap()[&id]
        .queued
        .clone();
    assert_eq!(queued.load(Ordering::Relaxed), 4_259_840);
    assert!(matches!(
        answers.next().await,
        Some(Response::Body { last: false, .. })
    ));
    assert_eq!(queued.load(Ordering::Relaxed), 0);
    deliver(&mut peer, body(id, true)).await;
    assert_eq!(queued.load(Ordering::Relaxed), 4_259_840);
    assert!(matches!(
        answers.next().await,
        Some(Response::Body { last: true, .. })
    ));
    assert_eq!(queued.load(Ordering::Relaxed), 0);
    ended(&mut answers).await;
}

#[tokio::test]
async fn a_full_slot_queue_releases_the_failed_handoff_charge() {
    let (data, mut peer) = pair().await;
    let (id, mut answers) = request(&data, &mut peer).await;
    // Small Body frames fit the byte bound, so hit the separate slot bound.
    for _ in 0..66 {
        deliver(
            &mut peer,
            Response::Body {
                id,
                index: 0,
                last: false,
                bytes: vec![1],
            },
        )
        .await;
    }
    assert!(data.waiters.lock().unwrap().as_ref().unwrap().is_empty());
    assert_eq!(data.budget.lock().unwrap().total, 65 * 14);
    for _ in 0..65 {
        assert!(matches!(
            answers.next().await,
            Some(Response::Body { last: false, .. })
        ));
    }
    ended(&mut answers).await;
    assert_eq!(data.budget.lock().unwrap().total, 0);
}

#[tokio::test]
async fn reserve_is_bounded_and_body_frames_cannot_use_it() {
    let (data, mut peer) = pair().await;
    let (a, first) = request(&data, &mut peer).await;
    let (b, second) = request(&data, &mut peer).await;
    deliver(&mut peer, body(a, true)).await;
    deliver(&mut peer, body(b, true)).await;
    let (c, mut body_answer) = request(&data, &mut peer).await;
    deliver(
        &mut peer,
        Response::Body {
            id: c,
            index: 0,
            last: true,
            bytes: vec![1],
        },
    )
    .await;
    ended(&mut body_answer).await;
    let (d, reserve) = request(&data, &mut peer).await;
    deliver(
        &mut peer,
        Response::Acked {
            id: d,
            ack: vec![0; 65_536 - 11],
        },
    )
    .await;
    assert_eq!(data.budget.lock().unwrap().total, 8_585_216);
    let (e, mut overflow) = request(&data, &mut peer).await;
    deliver(&mut peer, Response::Staged { id: e }).await;
    ended(&mut overflow).await;
    drop((first, second, reserve));
    assert_eq!(data.budget.lock().unwrap().total, 0);
}

#[tokio::test]
async fn abandoned_frames_get_credit_but_refusals_do_not() {
    let (data, mut peer) = pair().await;
    let (a, abandoned) = request(&data, &mut peer).await;
    drop(abandoned);
    deliver(&mut peer, body(a, false)).await;
    deliver(&mut peer, body(a, true)).await; // no map entry either
    assert_eq!(data.budget.lock().unwrap().total, 0);
    let (b, mut refused) = request(&data, &mut peer).await;
    peer.send(Message::Binary(
        Response::Refused {
            id: b,
            reason: Refusal::Missing,
        }
        .encode()
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    assert!(matches!(
        refused.next().await,
        Some(Response::Refused { .. })
    ));
    // If a refusal granted credit, deliver would observe 8 rather than 7.
    let (c, mut healthy) = request(&data, &mut peer).await;
    deliver(&mut peer, Response::Staged { id: c }).await;
    assert!(healthy.next().await.is_some());
    assert_eq!(data.budget.lock().unwrap().total, 0);
}

#[tokio::test]
async fn a_replaced_subscription_forgets_its_answers_and_later_frames_are_credited() {
    let (data, mut peer) = pair().await;
    let first = data
        .send(|id| Request::Subscribe {
            id,
            permit: vec![],
            after: 0,
        })
        .unwrap();
    let frame = peer.next().await.unwrap().unwrap();
    let Request::Subscribe { id, .. } = Request::decode(&frame.into_data()).unwrap() else {
        panic!("subscribe")
    };
    assert!(
        data.waiters
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains_key(&id)
    );
    // A renewal replaces the stream silently at the edge: dropping its
    // answers must not leave a waiter that no terminal frame will ever end.
    drop(first);
    assert!(data.waiters.lock().unwrap().as_ref().unwrap().is_empty());
    let late = Response::Head {
        id,
        head: bh_sync::Head::EMPTY,
        receipt: None,
    };
    // Still granted back, though nobody waits for it.
    deliver(&mut peer, late).await;
    assert_eq!(data.budget.lock().unwrap().total, 0);
}

fn stage(len: usize) -> impl FnOnce(u32) -> Request {
    move |id| Request::Stage {
        id,
        permit: vec![],
        body: vec![7; len],
    }
}
/// Every request frame the peer has received so far, credit separately.
async fn drain(peer: &mut Peer, want: usize) -> (Vec<Request>, Vec<u32>) {
    let (mut requests, mut credit) = (Vec::new(), Vec::new());
    while requests.len() < want {
        let frame = tokio::time::timeout(Duration::from_secs(5), peer.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match Request::decode(&frame.into_data()).unwrap() {
            Request::Credit { bytes } => credit.push(bytes),
            other => requests.push(other),
        }
    }
    (requests, credit)
}

#[tokio::test]
async fn outbound_requests_are_bounded_and_admission_fails_synchronously() {
    let (data, mut peer) = pair().await;
    // The peer reads nothing: the writer's first frame fills the duplex.
    let mut held = Vec::new();
    for _ in 0..OUT_REQUESTS {
        held.push(data.send(stage(1024)).expect("within the request bound"));
    }
    assert!(data.send(stage(1)).is_err(), "33rd request admitted");
    assert!(!data.is_closed(), "refused admission is local, not a fault");
    let (requests, _) = drain(&mut peer, OUT_REQUESTS).await;
    assert_eq!(requests.len(), OUT_REQUESTS);
    // Written frames release their admission.
    let mut later = None;
    for _ in 0..100 {
        if let Ok(answers) = data.send(stage(1)) {
            later = Some(answers);
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(later.is_some(), "capacity returned after the frames left");
}

#[tokio::test]
async fn outbound_bytes_are_bounded_with_a_small_request_reserve() {
    let (data, mut peer) = pair().await;
    let big = MAX_FRAME_LEN - 64;
    let mut held = Vec::new();
    for n in 0..16 {
        held.push(data.send(stage(big)).unwrap_or_else(|_| panic!("big {n}")));
    }
    assert!(data.send(stage(big)).is_err(), "byte bound exceeded");
    assert!(
        data.send(stage(1024)).is_ok(),
        "a small request still fits the reserve"
    );
    assert!(data.admitted.lock().unwrap().bytes <= OUT_BYTES);
    drain(&mut peer, 17).await;
}

#[tokio::test]
async fn reading_never_waits_for_outbound_space_and_credit_coalesces() {
    let (data, mut peer) = pair().await;
    let (id, mut answers) = request(&data, &mut peer).await;
    // A large frame the peer does not read blocks the client's writer.
    let _blocked = data.send(stage(1024 * 1024)).unwrap();
    let mut sizes = 0u32;
    for n in 0..3 {
        let frame = Response::Body {
            id,
            index: n,
            last: n == 2,
            bytes: vec![n; 100],
        }
        .encode()
        .unwrap();
        sizes += frame.len() as u32;
        peer.send(Message::Binary(frame.into())).await.unwrap();
    }
    for n in 0..3 {
        let next = tokio::time::timeout(Duration::from_secs(2), answers.next())
            .await
            .expect("received while the writer is blocked");
        assert!(matches!(next, Some(Response::Body { index, .. }) if index == n));
    }
    let (requests, credit) = drain(&mut peer, 1).await;
    assert!(matches!(requests[0], Request::Stage { .. }));
    // The blocked writer then grants all three frames back at once.
    let credit = if credit.is_empty() {
        let frame = tokio::time::timeout(Duration::from_secs(2), peer.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Request::Credit { bytes } = Request::decode(&frame.into_data()).unwrap() else {
            panic!("credit")
        };
        vec![bytes]
    } else {
        credit
    };
    assert_eq!(credit, vec![sizes], "one coalesced, exact credit");
}

#[tokio::test]
async fn shutdown_cancels_and_joins_both_tasks() {
    let (mut data, _peer) = pair().await;
    let _waiting = data.send(stage(8)).unwrap();
    data.shutdown().await;
    assert!(data.tasks.iter().all(|t| t.is_finished()));
    assert!(data.is_closed());
    assert!(data.send(stage(8)).is_err());
}
