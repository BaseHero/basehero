//! Isolated in-memory sockets; real handshake, records and authorization codec.
use super::*;
use bh_confidential_attestation::synthetic;
use bh_confidential_channel::handshake::ServerPending;
use bh_confidential_policy::{Limits, Policy, Role};
use bh_crypto::SigningKey;
use std::sync::Arc;
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role as WsRole};

fn clock(start: Clock) -> impl Fn() -> Sample + Send + Sync + 'static {
    move || Sample {
        system_seconds: Some(1_900_000_000),
        monotonic_ms: start.elapsed().as_millis() as u64,
    }
}
async fn fixture() -> (Arc<Authz>, Socket, Session<MemoryPolicy>) {
    let (authz, peer, service, _) = fixture_with_root().await;
    (authz, peer, service)
}
async fn fixture_with_root() -> (Arc<Authz>, Socket, Session<MemoryPolicy>, SigningKey) {
    let start = Clock::now();
    let root = SigningKey::generate();
    let policy = serde_json::to_vec(&Policy {
        version: 1,
        generation: 1,
        issued_at: 1_899_999_900,
        expires_at: 1_900_003_600,
        builds: vec![synthetic::build(Role::Checker)],
        machines: vec![synthetic::machine()],
    })
    .unwrap();
    let signature = root.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &policy].concat());
    let context = PolicyContext::new(
        root.public(),
        Limits {
            max_lifetime_secs: 86_400,
            max_uncertainty_secs: 0,
        },
        1,
        MemoryPolicy(None),
        clock(start),
    )
    .unwrap();
    let hello = ClientHello::new(context.clone()).unwrap();
    let server =
        ServerPending::<MemoryPolicy>::accept_hello(hello.frame(), root.public(), 0).unwrap();
    let quote = synthetic::quote(&server.report_data());
    let (proof, server) = server
        .attach_evidence(&policy, &signature, &quote, b"synthetic", b"synthetic", 0)
        .unwrap();
    let (encapsulation, client) = hello
        .accept_synthetic_proof(&proof)
        .unwrap()
        .encapsulate()
        .unwrap();
    let (finish, server) = server.accept_encapsulation(&encapsulation, 0).unwrap();
    let (confirm, session) = client.accept_finish(&finish).unwrap();
    let service = server.accept_finish(&confirm, clock(start)).unwrap();
    let (a, b) = tokio::io::duplex(1024);
    let socket =
        Box::pin(WebSocketStream::from_raw_socket(a, WsRole::Client, None).await) as Socket;
    let peer = Box::pin(WebSocketStream::from_raw_socket(b, WsRole::Server, None).await) as Socket;
    let authz = Arc::new(Authz {
        policy: Some(context),
        appraisal: Appraisal::Synthetic,
        slot: std::sync::Mutex::new(Slot {
            live: Some(dispatcher::Handle::start(Live {
                socket,
                session,
                opened: start,
                head: AccountHead {
                    position: 42,
                    hash: [42; 32],
                },
                at: None,
            })),
            ..Slot::default()
        }),
        opening: Mutex::new(()),
        gate: Arc::new(RwLock::new(())),
        admission: Arc::new(Semaphore::new(8)),
        stop_signal: watch::Sender::new(false),
        stopped: AtomicBool::new(false),
    });
    (authz, peer, service, root)
}
fn message() -> ToService {
    ToService::Permits {
        items: vec![bh_authz_proto::Want::Subscribe {
            log: bh_authz_proto::LogId {
                kind: bh_authz_proto::LogKind::Base,
                id: [1; 32],
            },
        }],
    }
}
async fn normal(authz: &Authz) -> Result<FromService, ClientError> {
    authz
        .until_stopped(async {
            let lease = authz.gate.clone().read_owned().await;
            let admission = authz.admission.clone().acquire_owned().await.unwrap();
            let live = authz.slot.lock().unwrap().live.clone().unwrap();
            live.ask(message(), admission, dispatcher::Lease::Normal(lease))
                .await
        })
        .await
}
async fn next(peer: &mut Socket, service: &mut Session<MemoryPolicy>) -> ToService {
    let frame = tokio::time::timeout(Duration::from_secs(1), receive(peer))
        .await
        .expect("request must arrive before earlier reply")
        .unwrap();
    let Opened::Data(plain) = service.open(&frame).unwrap() else {
        panic!("data")
    };
    ToService::decode(plain.expose()).unwrap()
}
async fn reply(peer: &mut Socket, service: &mut Session<MemoryPolicy>, marker: u8) {
    let bytes = FromService::Permits {
        items: vec![Ok(vec![marker])],
    }
    .encode()
    .unwrap();
    send(peer, service.seal(SecretBytes::from_vec(bytes)).unwrap())
        .await
        .unwrap();
}
#[tokio::test(start_paused = true)]
async fn normal_requests_pipeline_real_records() {
    let (authz, mut peer, mut service) = fixture().await;
    let a = authz.clone();
    let first = tokio::spawn(async move { normal(&a).await });
    next(&mut peer, &mut service).await;
    let a = authz.clone();
    let second = tokio::spawn(async move { normal(&a).await });
    next(&mut peer, &mut service).await;
    reply(&mut peer, &mut service, 1).await;
    reply(&mut peer, &mut service, 2).await;
    assert_eq!(
        first.await.unwrap().unwrap(),
        FromService::Permits {
            items: vec![Ok(vec![1])]
        }
    );
    assert_eq!(
        second.await.unwrap().unwrap(),
        FromService::Permits {
            items: vec![Ok(vec![2])]
        }
    );
    authz.stop();
    authz.close().await;
}
fn read_batch() -> ToService {
    ToService::ReadBatch {
        want: bh_authz_proto::Want::ReadBatch {
            log: bh_authz_proto::LogId {
                kind: bh_authz_proto::LogKind::Base,
                id: [1; 32],
            },
            after: bh_sync::Head::EMPTY,
            max_events: 48,
        },
    }
}
fn batch_answer() -> FromService {
    FromService::ReadBatch {
        log: bh_authz_proto::LogId {
            kind: bh_authz_proto::LogKind::Base,
            id: [1; 32],
        },
        after: bh_sync::Head::EMPTY,
        issued_ms: 1,
        deadline_ms: 30_001,
        result: bh_authz_proto::ReadBatchResult::Selected {
            items: vec![],
            receipt: None,
            body_permit: None,
            possibly_more: false,
        },
    }
}
#[tokio::test(start_paused = true)]
async fn read_batch_pipelines_with_legacy_permits_on_one_generation() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, connector) = test_support::shared(authz);
    let s = shared.clone();
    let batch = tokio::spawn(async move { s.authz.request(&s, read_batch()).await });
    assert_eq!(next(&mut peer, &mut service).await, read_batch());
    let s = shared.clone();
    let permits = tokio::spawn(async move { s.authz.request(&s, message()).await });
    assert_eq!(next(&mut peer, &mut service).await, message());
    let bytes = batch_answer().encode().unwrap();
    assert_eq!(&bytes[..3], &[0, 2, 33]);
    send(
        &mut peer,
        service.seal(SecretBytes::from_vec(bytes)).unwrap(),
    )
    .await
    .unwrap();
    reply(&mut peer, &mut service, 9).await;
    assert_eq!(batch.await.unwrap().unwrap(), batch_answer());
    assert_eq!(
        permits.await.unwrap().unwrap(),
        FromService::Permits {
            items: vec![Ok(vec![9])]
        }
    );
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    shared.authz.close().await;
}
#[tokio::test(start_paused = true)]
async fn read_batch_and_permits_replies_are_not_interchangeable() {
    for batch_first in [true, false] {
        let (authz, mut peer, mut service) = fixture().await;
        let (_dir, shared, _) = test_support::shared(authz);
        let s = shared.clone();
        let first = tokio::spawn(async move {
            s.authz
                .request(&s, if batch_first { read_batch() } else { message() })
                .await
        });
        next(&mut peer, &mut service).await;
        if batch_first {
            reply(&mut peer, &mut service, 1).await;
        } else {
            send(
                &mut peer,
                service
                    .seal(SecretBytes::from_vec(batch_answer().encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        }
        assert_eq!(first.await.unwrap(), Err(ClientError::Channel));
        shared.authz.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn stop_bypasses_held_public_lease() {
    let (authz, _peer, _service) = fixture().await;
    let lease = AuthzSession {
        authz: &authz,
        lease: Arc::new(authz.gate.clone().write_owned().await),
        live: authz.slot.lock().unwrap().live.clone().unwrap(),
    };
    assert_eq!(lease.account_head().position, 42);
    authz.stop();
    tokio::time::timeout(Duration::from_secs(1), authz.close())
        .await
        .expect("close must not wait for a public lease");
    drop(lease);
}

#[tokio::test(start_paused = true)]
async fn fifo_cancellation_keeps_slot_and_all_eight_can_be_sent() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            shared.authz.request(&shared, message()).await
        }));
        next(&mut peer, &mut service).await;
    }
    assert_eq!(shared.authz.admission.available_permits(), 0);
    tasks[0].abort();
    tokio::task::yield_now().await;
    assert_eq!(
        shared.authz.admission.available_permits(),
        0,
        "sealed cancellation is a tombstone"
    );
    let ninth = shared.authz.request(&shared, message());
    tokio::pin!(ninth);
    test_support::pending(ninth.as_mut()).await;
    reply(&mut peer, &mut service, 0).await;
    tokio::task::yield_now().await;
    test_support::pending(ninth.as_mut()).await;
    tokio::task::yield_now().await;
    next(&mut peer, &mut service).await;
    for marker in 1..=8 {
        reply(&mut peer, &mut service, marker).await;
    }
    for (i, task) in tasks.into_iter().enumerate() {
        if i == 0 {
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                task.await.unwrap().unwrap(),
                FromService::Permits {
                    items: vec![Ok(vec![i as u8])]
                }
            );
        }
    }
    assert_eq!(
        ninth.await.unwrap(),
        FromService::Permits {
            items: vec![Ok(vec![8])]
        }
    );
    shared.authz.close().await;
}

#[tokio::test(start_paused = true)]
async fn exclusive_lease_drains_and_blocks_normal() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let s = shared.clone();
    let first = tokio::spawn(async move { s.authz.request(&s, message()).await });
    next(&mut peer, &mut service).await;
    let exclusive = shared.authz.session(&shared);
    tokio::pin!(exclusive);
    test_support::pending(exclusive.as_mut()).await;
    let normal = shared.authz.request(&shared, message());
    tokio::pin!(normal);
    test_support::pending(normal.as_mut()).await;
    reply(&mut peer, &mut service, 1).await;
    first.await.unwrap().unwrap();
    let mut exclusive = exclusive.await.unwrap();
    assert_eq!(
        exclusive.account_head(),
        AccountHead {
            position: 42,
            hash: [42; 32]
        }
    );
    test_support::pending(normal.as_mut()).await;
    // Even eight waiting readers cannot consume the writer's admission.
    let mut readers = Vec::new();
    for _ in 0..8 {
        let s = shared.clone();
        readers.push(tokio::spawn(
            async move { s.authz.request(&s, message()).await },
        ));
    }
    tokio::task::yield_now().await;
    assert_eq!(shared.authz.admission.available_permits(), 8);
    let ask = exclusive.ask(message());
    tokio::pin!(ask);
    test_support::pending(ask.as_mut()).await;
    next(&mut peer, &mut service).await;
    reply(&mut peer, &mut service, 2).await;
    ask.await.unwrap();
    shared.authz.stop();
    shared.authz.close().await;
    assert_eq!(normal.await, Err(ClientError::Stopped));
    for reader in readers {
        assert_eq!(reader.await.unwrap(), Err(ClientError::Stopped));
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_public_ask_keeps_exclusive_tombstone() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    {
        let mut exclusive = shared.authz.session(&shared).await.unwrap();
        let ask = exclusive.ask(message());
        tokio::pin!(ask);
        test_support::pending(ask.as_mut()).await;
        next(&mut peer, &mut service).await;
    }
    let next_lease = shared.authz.session(&shared);
    tokio::pin!(next_lease);
    test_support::pending(next_lease.as_mut()).await;
    reply(&mut peer, &mut service, 1).await;
    let lease = next_lease.await.unwrap();
    assert_eq!(lease.account_head().position, 42);
    shared.authz.close().await;
}

#[tokio::test(start_paused = true)]
async fn cancelled_gate_and_unsent_admission_waiters_leave_no_orphan() {
    let (authz, _peer, _service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let read = shared.authz.gate.read().await;
    {
        let lease = shared.authz.session(&shared);
        tokio::pin!(lease);
        test_support::pending(lease.as_mut()).await;
    }
    drop(read);
    let all = shared
        .authz
        .admission
        .clone()
        .acquire_many_owned(8)
        .await
        .unwrap();
    {
        let normal = shared.authz.request(&shared, message());
        tokio::pin!(normal);
        test_support::pending(normal.as_mut()).await;
    }
    drop(all);
    assert_eq!(shared.authz.admission.available_permits(), 8);
    assert!(shared.authz.gate.try_write().is_ok());
    shared.authz.close().await;
}

#[tokio::test(start_paused = true)]
async fn unsent_cancellation_releases_admission_without_a_record() {
    let (authz, mut peer, _service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    // Poll only the caller: the actor has not had a turn to seal the command.
    {
        let request = shared.authz.request(&shared, message());
        tokio::pin!(request);
        test_support::pending(request.as_mut()).await;
        assert_eq!(shared.authz.admission.available_permits(), 7);
    }
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(shared.authz.admission.available_permits(), 8);
    assert!(shared.authz.gate.try_write().is_ok());
    let receive = peer.next();
    tokio::pin!(receive);
    test_support::pending(receive.as_mut()).await;
    shared.authz.close().await;
}

#[tokio::test(start_paused = true)]
async fn last_drop_releases_actor_writer_and_socket() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let weak = Arc::downgrade(&shared);
    let loops_shared = shared.clone();
    let task = tokio::spawn(async move {
        let _keep = loops_shared;
        std::future::pending::<()>().await;
    });
    let client = crate::Client {
        shared: shared.clone(),
        tasks: std::sync::Mutex::new(vec![task]),
        shutdown_task: std::sync::Mutex::new(None),
        stopped: watch::Sender::new(false),
    };
    drop(shared);
    drop(client);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        weak.upgrade().is_none(),
        "no actor -> Shared ownership cycle"
    );
    // A socket kept by a detached writer would never reach EOF.
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(Ok(frame)) = peer.next().await {
            if let Message::Binary(bytes) = frame {
                assert!(matches!(service.open(&bytes), Ok(Opened::Closed)));
            }
        }
    })
    .await
    .unwrap();
}

#[test]
fn presence_size_preflight_matches_the_real_permits_encoder() {
    let log = bh_authz_proto::LogId {
        kind: bh_authz_proto::LogKind::Base,
        id: [7; 32],
    };
    let presence = bh_authz_proto::Want::Presence {
        log,
        epoch: [8; 32],
    };
    for items in [
        vec![presence.clone()],
        vec![bh_authz_proto::Want::Subscribe { log }, presence.clone()],
        vec![presence; bh_authz_proto::MAX_ITEMS],
    ] {
        let request = ToService::Permits { items };
        let encoded = request.encode().unwrap();
        assert_eq!(dispatcher::check_size(&request), Ok(encoded.len()));
    }
    let single = ToService::Permits {
        items: vec![bh_authz_proto::Want::Presence {
            log,
            epoch: [8; 32],
        }],
    };
    assert_eq!(single.encode().unwrap().len(), 71);
}

#[tokio::test(start_paused = true)]
async fn oversized_request_is_local_and_does_not_invalidate_live_generation() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let too_big = ToService::SubmitControl {
        log: bh_authz_proto::LogId {
            kind: bh_authz_proto::LogKind::Base,
            id: [1; 32],
        },
        event: vec![0; 65_536],
        delivery: None,
    };
    assert_eq!(
        shared.authz.request(&shared, too_big).await,
        Err(ClientError::Channel)
    );
    assert_eq!(shared.authz.admission.available_permits(), 8);
    let s = shared.clone();
    let request = tokio::spawn(async move { s.authz.request(&s, message()).await });
    next(&mut peer, &mut service).await;
    reply(&mut peer, &mut service, 1).await;
    request.await.unwrap().unwrap();
    shared.authz.close().await;
}

#[tokio::test(start_paused = true)]
async fn eight_maximum_records_and_replies_stay_bounded() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let mut tasks = Vec::new();
    for marker in 0..8 {
        let s = shared.clone();
        tasks.push(tokio::spawn(async move {
            s.authz
                .request(
                    &s,
                    ToService::SubmitControl {
                        log: bh_authz_proto::LogId {
                            kind: bh_authz_proto::LogKind::Base,
                            id: [1; 32],
                        },
                        event: vec![marker; 65_536 - 41],
                        delivery: None,
                    },
                )
                .await
        }));
        let frame = receive(&mut peer).await.unwrap();
        assert_eq!(frame.len(), 65_596);
        let Opened::Data(plain) = service.open(&frame).unwrap() else {
            panic!("data")
        };
        assert_eq!(plain.expose().len(), 65_536);
        assert!(
            matches!(ToService::decode(plain.expose()).unwrap(), ToService::SubmitControl { event, .. } if event == vec![marker;65_536-41])
        );
        assert_eq!(
            shared.authz.admission.available_permits(),
            7 - usize::from(marker)
        );
    }
    for marker in 0..8 {
        let plain = FromService::Permits {
            items: vec![Ok(vec![marker; 65_536 - 10])],
        }
        .encode()
        .unwrap();
        assert_eq!(plain.len(), 65_536);
        let frame = service.seal(SecretBytes::from_vec(plain)).unwrap();
        assert_eq!(frame.len(), 65_596);
        send(&mut peer, frame).await.unwrap();
    }
    for (marker, task) in tasks.into_iter().enumerate() {
        assert_eq!(
            task.await.unwrap().unwrap(),
            FromService::Permits {
                items: vec![Ok(vec![marker as u8; 65_536 - 10])]
            }
        );
    }
    assert_eq!(shared.authz.admission.available_permits(), 8);
    shared.authz.close().await;
}

#[tokio::test(start_paused = true)]
async fn one_paused_opener_cancellation_and_stop_wake_all_waiters() {
    let (authz, _peer, _service) = fixture().await;
    let (_dir, shared, connector) = test_support::shared(authz);
    shared.authz.close().await;
    connector.pause.store(true, Ordering::SeqCst);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let s = shared.clone();
        tasks.push(tokio::spawn(
            async move { s.authz.request(&s, message()).await },
        ));
    }
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    shared.authz.stop();
    tokio::time::timeout(Duration::from_secs(1), shared.authz.close())
        .await
        .unwrap();
    for task in tasks {
        assert_eq!(task.await.unwrap(), Err(ClientError::Stopped));
    }
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn malformed_unexpected_timeout_and_loss_fail_uncertain_work() {
    for mode in 0..4 {
        let (authz, mut peer, mut service) = fixture().await;
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let a = authz.clone();
            tasks.push(tokio::spawn(async move { normal(&a).await }));
            next(&mut peer, &mut service).await;
        }
        let expected = if mode < 2 {
            ClientError::Channel
        } else {
            ClientError::Network
        };
        match mode {
            0 => {
                send(
                    &mut peer,
                    service.seal(SecretBytes::from_vec(vec![1, 2, 3])).unwrap(),
                )
                .await
                .unwrap();
            }
            1 => {
                let bytes = FromService::Challenge { challenge: [0; 32] }
                    .encode()
                    .unwrap();
                send(
                    &mut peer,
                    service.seal(SecretBytes::from_vec(bytes)).unwrap(),
                )
                .await
                .unwrap();
            }
            2 => tokio::time::advance(ANSWER_WAIT).await,
            _ => drop(peer),
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), Err(expected));
        }
        assert_eq!(normal(&authz).await, Err(expected));
        authz.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn backpressured_writer_still_drains_reply_and_stop_bypasses_full_queue() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let s = shared.clone();
    let first = tokio::spawn(async move { s.authz.request(&s, message()).await });
    next(&mut peer, &mut service).await;
    // The peer never reads these large records; the duplex write buffer is 1KiB.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let s = shared.clone();
        tasks.push(tokio::spawn(async move {
            s.authz
                .request(
                    &s,
                    ToService::SubmitControl {
                        log: bh_authz_proto::LogId {
                            kind: bh_authz_proto::LogKind::Base,
                            id: [1; 32],
                        },
                        event: vec![3; 60_000],
                        delivery: None,
                    },
                )
                .await
        }));
    }
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(shared.authz.admission.available_permits(), 0);
    reply(&mut peer, &mut service, 17).await;
    assert_eq!(
        first.await.unwrap().unwrap(),
        FromService::Permits {
            items: vec![Ok(vec![17])]
        }
    );
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(shared.authz.admission.available_permits(), 0);
    shared.authz.stop();
    tokio::time::timeout(Duration::from_secs(1), shared.authz.close())
        .await
        .unwrap();
    for task in tasks {
        assert_eq!(task.await.unwrap(), Err(ClientError::Stopped));
    }
}

#[tokio::test(start_paused = true)]
async fn close_retires_generation_without_stopping_signup_reauthentication() {
    let (authz, _peer, _service) = fixture().await;
    let (_dir, shared, connector) = test_support::shared(authz);
    shared.authz.close().await;
    assert!(
        !shared.authz.is_stopped(),
        "catch_up closes historical auth before current authentication"
    );
    assert!(matches!(
        shared.authz.session(&shared).await,
        Err(ClientError::Network)
    ));
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn retiring_close_is_transient_for_concurrent_callers_but_stop_is_permanent() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    // A sealed normal request and a pinned public lease, as two lanes hold.
    let s = shared.clone();
    let sent = tokio::spawn(async move { s.authz.request(&s, message()).await });
    next(&mut peer, &mut service).await;
    shared.authz.close().await;
    assert_eq!(sent.await.unwrap(), Err(ClientError::Network));
    let s = shared.clone();
    let unsent = tokio::spawn(async move { s.authz.request(&s, message()).await });
    assert_eq!(unsent.await.unwrap(), Err(ClientError::Network));
    assert!(!shared.authz.is_stopped());
    // Permanent stop is still Stopped for every caller.
    shared.authz.stop();
    assert_eq!(
        shared.authz.request(&shared, message()).await,
        Err(ClientError::Stopped)
    );
}

#[tokio::test(start_paused = true)]
async fn retiring_close_reports_network_to_a_pinned_generation() {
    let (authz, mut peer, mut service) = fixture().await;
    let live = authz.slot.lock().unwrap().live.clone().unwrap();
    let a = authz.clone();
    let pinned = tokio::spawn(async move {
        let lease = a.gate.clone().read_owned().await;
        let admission = a.admission.clone().acquire_owned().await.unwrap();
        live.ask(message(), admission, dispatcher::Lease::Normal(lease))
            .await
    });
    next(&mut peer, &mut service).await;
    authz.close().await;
    assert_eq!(pinned.await.unwrap(), Err(ClientError::Network));
}

#[tokio::test(start_paused = true)]
async fn rotation_failure_preserves_policy_backoff_and_never_replays_control() {
    let (authz, mut peer, mut service, root) = fixture_with_root().await;
    let (_dir, shared, connector) = test_support::shared(authz);
    let mut policy = Policy {
        version: 1,
        generation: 2,
        issued_at: 1_899_999_900,
        expires_at: 1_900_003_600,
        builds: vec![synthetic::build(Role::Checker)],
        machines: vec![synthetic::machine()],
    };
    let payload = serde_json::to_vec(&policy).unwrap();
    let signature =
        root.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &payload].concat());
    shared
        .authz
        .policy
        .as_ref()
        .unwrap()
        .deliver_policy(&payload, &signature)
        .unwrap();
    let mut lease = shared.authz.session(&shared).await.unwrap();
    tokio::time::advance(SESSION_LIFE - Duration::from_secs(5)).await;
    {
        let control = ToService::SubmitControl {
            log: bh_authz_proto::LogId {
                kind: bh_authz_proto::LogKind::Base,
                id: [1; 32],
            },
            event: vec![77],
            delivery: None,
        };
        let ask = lease.ask(control.clone());
        tokio::pin!(ask);
        test_support::pending(ask.as_mut()).await;
        assert_eq!(next(&mut peer, &mut service).await, control);
        // Rotation drains already sealed work for at most its answer deadline.
        tokio::time::advance(Duration::from_secs(5)).await;
        test_support::pending(ask.as_mut()).await;
        assert_eq!(
            tokio::time::timeout(ANSWER_WAIT, ask).await.unwrap(),
            Err(ClientError::Network)
        );
    }
    drop(lease);
    assert!(shared.authz.session(&shared).await.is_err());
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    assert!(shared.authz.session(&shared).await.is_err());
    assert_eq!(
        connector.calls.load(Ordering::SeqCst),
        1,
        "failed reopen shares backoff"
    );
    // The old generation emits Close, not a replayed request.
    let frame = receive(&mut peer).await.unwrap();
    assert!(matches!(service.open(&frame), Ok(Opened::Closed)));
    // A genuine older signed policy still fails after failed replacement.
    policy.generation = 1;
    let payload = serde_json::to_vec(&policy).unwrap();
    let signature =
        root.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &payload].concat());
    assert!(
        shared
            .authz
            .policy
            .as_ref()
            .unwrap()
            .deliver_policy(&payload, &signature)
            .is_err()
    );
    shared.authz.close().await;
}

#[tokio::test(start_paused = true)]
async fn historical_context_waits_for_drain_and_cancelled_open_can_stop() {
    let (authz, mut peer, mut service) = fixture().await;
    let (_dir, shared, connector) = test_support::shared(authz);
    let s = shared.clone();
    let first = tokio::spawn(async move { s.authz.request(&s, message()).await });
    next(&mut peer, &mut service).await;
    connector.pause.store(true, Ordering::SeqCst);
    let historical = shared.authz.session_at(
        &shared,
        Some(AccountHead {
            position: 1,
            hash: [1; 32],
        }),
    );
    tokio::pin!(historical);
    test_support::pending(historical.as_mut()).await;
    assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
    reply(&mut peer, &mut service, 1).await;
    first.await.unwrap().unwrap();
    test_support::pending(historical.as_mut()).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
        test_support::pending(historical.as_mut()).await;
    }
    assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
    shared.authz.stop();
    assert!(matches!(historical.await, Err(ClientError::Stopped)));
    tokio::time::timeout(Duration::from_secs(1), shared.authz.close())
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelled_shutdown_still_joins_and_concurrent_callers_complete() {
    let (authz, _peer, _service) = fixture().await;
    let (_dir, shared, _) = test_support::shared(authz);
    let client = crate::Client {
        shared: shared.clone(),
        tasks: std::sync::Mutex::new(vec![]),
        shutdown_task: std::sync::Mutex::new(None),
        stopped: watch::Sender::new(false),
    };
    let mut lease = client.authz().await.unwrap();
    // Fill the ciphertext writer while retaining the public lease. Each
    // cancelled sealed ask is a tombstone; the peer never reads these records.
    for _ in 0..8 {
        let ask = lease.ask(ToService::SubmitControl {
            log: bh_authz_proto::LogId {
                kind: bh_authz_proto::LogKind::Base,
                id: [1; 32],
            },
            event: vec![7; 60_000],
            delivery: None,
        });
        tokio::pin!(ask);
        test_support::pending(ask.as_mut()).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(shared.authz.admission.available_permits(), 0);
    {
        let shutdown = client.shutdown();
        tokio::pin!(shutdown);
        test_support::pending(shutdown.as_mut()).await;
    }
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    // The writer is still in its bounded close grace; waiter cancellation
    // cannot claim it has joined. The paused clock has not advanced yet.
    assert!(!*client.stopped.borrow());
    tokio::join!(client.shutdown(), client.shutdown());
    assert!(*client.stopped.borrow());
    assert!(shared.authz.slot.lock().unwrap().live.is_none());
    assert_eq!(lease.account_head().position, 42);
}
