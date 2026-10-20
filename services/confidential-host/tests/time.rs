#![cfg(unix)]

use bh_confidential_host::TimeSampler;
use bh_crypto::{Secret, SigningKey, sha512};
use bh_qualified_time::{Config, Counter, ServerRoot, Unavailable};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::oneshot};

struct Ticks(AtomicU64);
impl Ticks {
    fn new() -> Self {
        Self(AtomicU64::new(10))
    }
    fn set(&self, n: u64) {
        self.0.store(n, Ordering::SeqCst);
    }
}
impl Counter for Ticks {
    fn ticks(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}
fn config() -> Config {
    // Synthetic counter parameters belong to the fixture, NOT the VM.
    Config {
        hz: 1_000_000,
        drift_ppm: 500,
        smear_us: 0,
        max_age_ticks: 100_000,
        max_width_ms: 1_000,
    }
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[seed; 32]).unwrap())
}
fn root(seed: u8) -> ServerRoot {
    ServerRoot {
        key: key(seed).public(),
    }
}
fn message(mut fields: Vec<(&[u8; 4], Vec<u8>)>) -> Vec<u8> {
    fields.sort_by_key(|(tag, _)| u32::from_le_bytes(**tag));
    let mut out = Vec::new();
    out.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    let mut offset = 0u32;
    for (_, bytes) in fields.iter().take(fields.len() - 1) {
        offset += bytes.len() as u32;
        out.extend_from_slice(&offset.to_le_bytes());
    }
    for (tag, _) in &fields {
        out.extend_from_slice(*tag);
    }
    for (_, bytes) in &fields {
        out.extend_from_slice(bytes);
    }
    out
}
fn reply(seed: u8, nonce: &[u8; 64], midpoint: u64) -> Vec<u8> {
    reply_with_padding(seed, nonce, midpoint, false)
}
fn reply_with_padding(seed: u8, nonce: &[u8; 64], midpoint: u64, padded: bool) -> Vec<u8> {
    let root = key(seed);
    let online = key(seed + 10);
    let dele = message(vec![
        (b"PUBK", online.public().to_vec()),
        (b"MINT", 0u64.to_le_bytes().to_vec()),
        (b"MAXT", u64::MAX.to_le_bytes().to_vec()),
    ]);
    let mut d = b"RoughTime v1 delegation signature--\0".to_vec();
    d.extend_from_slice(&dele);
    let cert = message(vec![(b"DELE", dele), (b"SIG\0", root.sign(&d).to_vec())]);
    let mut leaf = [0; 65];
    leaf[1..].copy_from_slice(nonce);
    let srep = message(vec![
        (b"MIDP", midpoint.to_le_bytes().to_vec()),
        (b"RADI", 100u32.to_le_bytes().to_vec()),
        (b"ROOT", sha512(&leaf).to_vec()),
    ]);
    let mut s = b"RoughTime v1 response signature\0".to_vec();
    s.extend_from_slice(&srep);
    let mut fields: Vec<(&[u8; 4], Vec<u8>)> = vec![
        (b"CERT", cert),
        (b"SREP", srep),
        (b"SIG\0", online.sign(&s).to_vec()),
        (b"PATH", vec![]),
        (b"INDX", 0u32.to_le_bytes().to_vec()),
    ];
    if padded {
        let base_len = message(fields.clone()).len();
        fields.push((b"ZZZZ", vec![0; 4096 - base_len - 8]));
    }
    message(fields)
}
fn corrupt_response_signature(packet: &mut [u8]) {
    let n = u32::from_le_bytes(packet[..4].try_into().unwrap()) as usize;
    let i = (0..n)
        .find(|&i| packet[4 * n + 4 * i..4 * n + 4 * i + 4] == *b"SIG\0")
        .unwrap();
    let start = if i == 0 {
        0
    } else {
        u32::from_le_bytes(packet[4 * i..4 * i + 4].try_into().unwrap()) as usize
    };
    packet[8 * n + start] ^= 1;
}
fn nonce(request: &[u8]) -> [u8; 64] {
    assert_eq!(request.len(), 1024);
    assert_eq!(
        &request[..16],
        &[
            2u32.to_le_bytes(),
            64u32.to_le_bytes(),
            u32::from_le_bytes(*b"NONC").to_le_bytes(),
            u32::from_le_bytes(*b"PAD\xff").to_le_bytes()
        ]
        .concat()
    );
    assert!(request[80..].iter().all(|b| *b == 0));
    request[16..80].try_into().unwrap()
}
#[derive(Clone, Copy)]
enum Answer {
    Valid(u64),
    WrongRoot,
    WrongNonce,
    BadSignature,
    Oversize,
}
struct FixtureTask {
    release: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<[u8; 64]>,
}
async fn fixture(seed: u8, answer: Answer) -> (SocketAddr, FixtureTask) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (release, released) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request_nonce = nonce(&buf[..n]);
        let mut signed_nonce = request_nonce;
        if matches!(answer, Answer::WrongNonce) {
            signed_nonce[0] ^= 1;
        }
        let signing_seed = if matches!(answer, Answer::WrongRoot) {
            seed + 20
        } else {
            seed
        };
        let mut response = reply(
            signing_seed,
            &signed_nonce,
            match answer {
                Answer::Valid(mid) => mid,
                _ => 1_000_000_000,
            },
        );
        if matches!(answer, Answer::BadSignature) {
            assert!(bh_qualified_time::verify(&root(seed), &request_nonce, &response).is_ok());
            corrupt_response_signature(&mut response);
            assert_eq!(
                bh_qualified_time::verify(&root(seed), &request_nonce, &response),
                Err(Unavailable::Signature)
            );
        }
        if matches!(answer, Answer::WrongNonce) {
            assert!(bh_qualified_time::verify(&root(seed), &signed_nonce, &response).is_ok());
            assert_eq!(
                bh_qualified_time::verify(&root(seed), &request_nonce, &response),
                Err(Unavailable::Inclusion)
            );
        }
        if matches!(answer, Answer::WrongRoot) {
            assert!(
                bh_qualified_time::verify(&root(signing_seed), &request_nonce, &response).is_ok()
            );
            assert_eq!(
                bh_qualified_time::verify(&root(seed), &request_nonce, &response),
                Err(Unavailable::Signature)
            );
        }
        if matches!(answer, Answer::Oversize) {
            response = reply_with_padding(seed, &request_nonce, 1_000_000_000, true);
            assert_eq!(response.len(), 4096);
            assert!(bh_qualified_time::verify(&root(seed), &request_nonce, &response).is_ok());
            response.push(0); // a 4096-byte receive buffer would accept a valid prefix
        }
        socket.send_to(&response, peer).await.unwrap();
        released.await.unwrap(); // remain bound until refresh has returned
        assert!(socket.try_recv_from(&mut buf).is_err(), "unexpected retry");
        request_nonce
    });
    (addr, FixtureTask { release, task })
}
async fn setup(a: Answer, b: Answer, budget: Duration) -> (TimeSampler, [FixtureTask; 2]) {
    let (addr0, task0) = fixture(1, a).await;
    let (addr1, task1) = fixture(2, b).await;
    let sampler = TimeSampler::new([(addr0, root(1)), (addr1, root(2))], config(), budget).unwrap();
    (sampler, [task0, task1])
}
async fn finish(tasks: [FixtureTask; 2]) -> [[u8; 64]; 2] {
    let [a, b] = tasks;
    a.release.send(()).unwrap();
    b.release.send(()).unwrap();
    [
        tokio::time::timeout(Duration::from_secs(2), a.task)
            .await
            .unwrap()
            .unwrap(),
        tokio::time::timeout(Duration::from_secs(2), b.task)
            .await
            .unwrap()
            .unwrap(),
    ]
}
#[tokio::test]
async fn both_authenticated_requests_are_canonical_fresh_and_stamped() {
    let (sampler, tasks) = setup(
        Answer::Valid(1_000_000_000),
        Answer::Valid(1_000_000_000),
        Duration::from_secs(1),
    )
    .await;
    let ticks = Ticks::new();
    assert_eq!(sampler.now(&ticks), Err(Unavailable::Cold));
    let bounds = sampler.refresh(&ticks).await.unwrap();
    let nonces = finish(tasks).await;
    assert_ne!(nonces[0], nonces[1]);
    assert_ne!(nonces[0], [0; 64]);
    assert!(
        ticks.0.load(Ordering::SeqCst) >= 15,
        "two sends, two receipts and update must sample counter"
    );
    assert!(bounds.earliest_ms <= 1_000_000 && bounds.latest_ms >= 1_000_000);
    assert!(sampler.now(&ticks).is_ok());
}
#[tokio::test]
async fn each_authentication_failure_and_disagreement_refuses_time() {
    for (a, b) in [
        (Answer::Valid(1_000_000_000), Answer::WrongRoot),
        (Answer::Valid(1_000_000_000), Answer::WrongNonce),
        (Answer::Valid(1_000_000_000), Answer::BadSignature),
        (Answer::Valid(1_000_000_000), Answer::Valid(2_000_000_000)),
        (Answer::Valid(1_000_000_000), Answer::Oversize),
    ] {
        let (sampler, tasks) = setup(a, b, Duration::from_secs(1)).await;
        let ticks = Ticks::new();
        let result = sampler.refresh(&ticks).await;
        finish(tasks).await;
        assert!(
            result.is_err(),
            "must reject the reached two-server fixture"
        );
        assert_eq!(sampler.now(&ticks), Err(Unavailable::Cold));
    }
}
#[tokio::test]
async fn receipt_counter_after_transport_inflates_delayed_interval() {
    let (first, first_task) = fixture(1, Answer::Valid(1_000_000_000)).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = socket.local_addr().unwrap();
    let (seen_tx, seen_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let delayed = tokio::spawn(async move {
        let mut buf = [0; 2048];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        let fresh = nonce(&buf[..n]);
        seen_tx.send(()).unwrap();
        release_rx.await.unwrap();
        socket
            .send_to(&reply(2, &fresh, 1_000_000_000), peer)
            .await
            .unwrap();
    });
    let cfg = Config {
        max_age_ticks: 10_000_000,
        ..config()
    };
    let sampler = TimeSampler::new(
        [(first, root(1)), (second, root(2))],
        cfg,
        Duration::from_secs(2),
    )
    .unwrap();
    let ticks = Ticks::new();
    let mut refresh = Box::pin(sampler.refresh(&ticks));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { _ = &mut refresh => panic!("completed before second response"), _ = seen_rx => {} }
    }).await.unwrap();
    ticks.set(2_000_000); // fixture counter advances during the real pending receive
    release_tx.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), refresh)
            .await
            .unwrap()
            .is_err()
    );
    first_task.release.send(()).unwrap();
    first_task.task.await.unwrap();
    delayed.await.unwrap();
    assert_eq!(sampler.now(&ticks), Err(Unavailable::Cold));
}
// Each endpoint handles a successful refresh then observes the next request.
// The stalled one stays bound, rather than closing to produce a quick IO error.
async fn repeat_fixture(
    seed: u8,
    stall: bool,
) -> (
    SocketAddr,
    oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (seen_tx, seen_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut seen_tx = Some(seen_tx);
        let mut buf = [0u8; 2048];
        for i in 0..2 {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let fresh = nonce(&buf[..n]);
            if i == 1 {
                let _ = seen_tx.take().unwrap().send(());
            }
            if i == 0 || !stall {
                socket
                    .send_to(&reply(seed, &fresh, 1_000_000_000), peer)
                    .await
                    .unwrap();
            }
        }
        assert!(
            socket.try_recv_from(&mut buf).is_err(),
            "unexpected third request"
        );
    });
    (addr, seen_rx, task)
}
// Both renewal replies wait on explicit channels, so readers can run while
// acquisition is definitely pending. The first round qualifies the anchor.
async fn held_renewal(
    seed: u8,
    answer: Answer,
) -> (
    SocketAddr,
    oneshot::Receiver<()>,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (seen_tx, seen_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut buf = [0; 2048];
        let mut seen_tx = Some(seen_tx);
        let mut release_rx = Some(release_rx);
        for round in 0..2 {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let fresh = nonce(&buf[..n]);
            if round == 1 {
                seen_tx.take().unwrap().send(()).unwrap();
                release_rx.take().unwrap().await.unwrap();
            }
            let mut response = reply(seed, &fresh, 1_000_000_000);
            if round == 1 {
                match answer {
                    Answer::Valid(mid) => response = reply(seed, &fresh, mid),
                    Answer::BadSignature => corrupt_response_signature(&mut response),
                    Answer::Oversize => response = vec![0; 4097],
                    _ => panic!("unsupported renewal answer"),
                }
            }
            socket.send_to(&response, peer).await.unwrap();
        }
        assert!(socket.try_recv_from(&mut buf).is_err(), "unexpected retry");
    });
    (addr, seen_rx, release_tx, task)
}
async fn pending_renewal(
    second: Answer,
) -> (
    TimeSampler,
    Ticks,
    [oneshot::Receiver<()>; 2],
    [oneshot::Sender<()>; 2],
    [tokio::task::JoinHandle<()>; 2],
) {
    let (a, seen_a, release_a, task_a) = held_renewal(1, Answer::Valid(1_000_000_000)).await;
    let (b, seen_b, release_b, task_b) = held_renewal(2, second).await;
    let sampler = TimeSampler::new(
        [(a, root(1)), (b, root(2))],
        config(),
        Duration::from_secs(2),
    )
    .unwrap();
    let ticks = Ticks::new();
    sampler.refresh(&ticks).await.unwrap();
    assert!(sampler.now(&ticks).is_ok());
    (
        sampler,
        ticks,
        [seen_a, seen_b],
        [release_a, release_b],
        [task_a, task_b],
    )
}

#[tokio::test]
async fn reads_keep_original_bounds_while_both_renewal_replies_are_pending() {
    let (sampler, ticks, [seen_a, seen_b], [release_a, release_b], tasks) =
        pending_renewal(Answer::Valid(1_000_000_050)).await;
    let old = sampler.now(&ticks).unwrap();
    let old_end = ticks.0.load(Ordering::SeqCst);
    let mut refresh = Box::pin(sampler.refresh(&ticks));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { _ = &mut refresh => panic!("completed without replies"), _ = seen_a => {} }
    })
    .await
    .unwrap();
    // The first server is still held. This arrival also proves the second query
    // was sent concurrently rather than waiting for the first reply.
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { _ = &mut refresh => panic!("completed without replies"), _ = seen_b => {} }
    })
    .await
    .unwrap();
    assert!(
        sampler.refresh(&ticks).await.is_err(),
        "a second refresh must not overlap"
    );
    let during = sampler.now(&ticks).unwrap();
    assert!(during.earliest_ms >= old.earliest_ms);
    assert!(during.latest_ms <= old.latest_ms + 1);
    release_a.send(()).unwrap();
    release_b.send(()).unwrap();
    let fresh = tokio::time::timeout(Duration::from_secs(2), refresh)
        .await
        .unwrap()
        .unwrap();
    assert!(fresh.latest_ms >= during.latest_ms);
    for task in tasks {
        task.await.unwrap();
    }
    // Old stamps have aged out, but the installed renewal is still young.
    ticks.set(old_end + 100_000);
    assert!(sampler.now(&ticks).is_ok());
}

#[tokio::test]
async fn old_anchor_expires_during_pending_renewal() {
    let (sampler, ticks, [seen_a, seen_b], [release_a, release_b], tasks) =
        pending_renewal(Answer::Valid(1_000_000_000)).await;
    let mut refresh = Box::pin(sampler.refresh(&ticks));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { _ = &mut refresh => panic!("completed without replies"), _ = seen_a => {} }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), seen_b)
        .await
        .unwrap()
        .unwrap();
    ticks.set(200_000);
    assert_eq!(sampler.now(&ticks), Err(Unavailable::Stale));
    release_a.send(()).unwrap();
    release_b.send(()).unwrap();
    // It is legitimate for the delayed pair to fail after artificial ageing.
    let _ = tokio::time::timeout(Duration::from_secs(2), refresh)
        .await
        .unwrap();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reader_during_install_cannot_create_a_false_counter_rollback() {
    struct GatedCounter {
        reads: AtomicU64,
        block_at: AtomicU64,
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Counter for GatedCounter {
        fn ticks(&self) -> u64 {
            let tick = self.reads.fetch_add(1, Ordering::SeqCst);
            if tick == self.block_at.load(Ordering::SeqCst) {
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
            }
            tick + 10
        }
    }
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let ticks = Arc::new(GatedCounter {
        reads: AtomicU64::new(0),
        block_at: AtomicU64::new(u64::MAX),
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(release_rx),
    });
    let (a, seen_a, release_a, task_a) = held_renewal(1, Answer::Valid(1_000_000_000)).await;
    let (b, seen_b, release_b, task_b) = held_renewal(2, Answer::Valid(1_000_000_000)).await;
    let sampler = Arc::new(
        TimeSampler::new(
            [(a, root(1)), (b, root(2))],
            config(),
            Duration::from_secs(2),
        )
        .unwrap(),
    );
    sampler.refresh(ticks.as_ref()).await.unwrap();
    ticks
        .block_at
        .store(ticks.reads.load(Ordering::SeqCst) + 4, Ordering::SeqCst);
    let refreshing = {
        let sampler = Arc::clone(&sampler);
        let ticks = Arc::clone(&ticks);
        tokio::spawn(async move { sampler.refresh(ticks.as_ref()).await })
    };
    tokio::time::timeout(Duration::from_secs(2), seen_a)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), seen_b)
        .await
        .unwrap()
        .unwrap();
    release_a.send(()).unwrap();
    release_b.send(()).unwrap();
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(2)).unwrap())
        .await
        .unwrap();
    let (reader_started, reader_ready) = std::sync::mpsc::channel();
    let reader = {
        let sampler = Arc::clone(&sampler);
        let ticks = Arc::clone(&ticks);
        tokio::task::spawn_blocking(move || {
            reader_started.send(()).unwrap();
            sampler.now(ticks.as_ref())
        })
    };
    tokio::task::spawn_blocking(move || reader_ready.recv_timeout(Duration::from_secs(2)).unwrap())
        .await
        .unwrap();
    release_tx.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), refreshing)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    assert!(sampler.now(ticks.as_ref()).is_ok());
    task_a.await.unwrap();
    task_b.await.unwrap();
}

#[tokio::test]
async fn known_transport_failure_invalidates_without_waiting_for_other_peer() {
    use std::{future::Future, task::Poll};
    let (sampler, ticks, [seen_a, seen_b], [release_a, release_b], [task_a, task_b]) =
        pending_renewal(Answer::Oversize).await;
    let mut refresh = Box::pin(sampler.refresh(&ticks));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            _ = &mut refresh => panic!("completed before responses"),
            _ = async { seen_a.await.unwrap(); seen_b.await.unwrap(); } => {}
        }
    })
    .await
    .unwrap();
    let before_receipt = ticks.0.load(Ordering::SeqCst);
    release_b.send(()).unwrap();
    task_b.await.unwrap(); // oversized datagram sent; the other server is held
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| {
            let outcome = refresh.as_mut().poll(cx);
            if outcome.is_ready() || ticks.0.load(Ordering::SeqCst) > before_receipt {
                // request() stamped the oversized receipt during this poll.
                Poll::Ready(outcome)
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    let after_failure = sampler.now(&ticks);
    drop(refresh);
    release_a.send(()).unwrap();
    task_a.await.unwrap();
    assert_eq!(
        after_failure,
        Err(Unavailable::Cold),
        "known failure must invalidate immediately"
    );
    assert!(
        matches!(outcome, Poll::Ready(Err(_))),
        "must not wait for the other peer"
    );
}

#[tokio::test]
async fn failed_renewal_invalidates_previous_anchor() {
    for failure in [Answer::BadSignature, Answer::Valid(2_000_000_000)] {
        let (sampler, ticks, [seen_a, seen_b], [release_a, release_b], tasks) =
            pending_renewal(failure).await;
        let mut refresh = Box::pin(sampler.refresh(&ticks));
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! { _ = &mut refresh => panic!("completed without replies"), _ = seen_a => {} }
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), seen_b)
            .await
            .unwrap()
            .unwrap();
        release_a.send(()).unwrap();
        release_b.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), refresh)
                .await
                .unwrap()
                .is_err()
        );
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(sampler.now(&ticks), Err(Unavailable::Cold));
    }
}

async fn qualified_then_stalled(
    budget: Duration,
) -> (
    TimeSampler,
    Ticks,
    oneshot::Receiver<()>,
    oneshot::Receiver<()>,
    [tokio::task::JoinHandle<()>; 2],
) {
    let (a, seen_a, task_a) = repeat_fixture(1, false).await;
    let (b, seen_b, task_b) = repeat_fixture(2, true).await;
    let sampler = TimeSampler::new([(a, root(1)), (b, root(2))], config(), budget).unwrap();
    let ticks = Ticks::new();
    sampler.refresh(&ticks).await.unwrap();
    assert!(sampler.now(&ticks).is_ok());
    (sampler, ticks, seen_a, seen_b, [task_a, task_b])
}
#[tokio::test]
async fn total_deadline_discard_previously_qualified_anchor() {
    let (sampler, ticks, a, b, tasks) = qualified_then_stalled(Duration::from_millis(100)).await;
    // Independent watchdog distinguishes our total bound from a test hang.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), sampler.refresh(&ticks))
            .await
            .unwrap()
            .is_err()
    );
    a.await.unwrap();
    b.await.unwrap();
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(sampler.now(&ticks), Err(Unavailable::Cold));
}
#[tokio::test]
async fn cancellation_after_first_send_discards_previous_anchor() {
    let (sampler, ticks, a, b, tasks) = qualified_then_stalled(Duration::from_secs(1)).await;
    let mut refresh = Box::pin(sampler.refresh(&ticks));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { _ = &mut refresh => panic!("stalled server unexpectedly completed"), _ = b => {} }
    }).await.unwrap();
    drop(refresh);
    a.await.unwrap();
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(sampler.now(&ticks), Err(Unavailable::Cold));
}
#[tokio::test]
async fn rejects_invalid_configuration_and_detects_rollback() {
    let (sampler, tasks) = setup(
        Answer::Valid(1_000_000_000),
        Answer::Valid(1_000_000_000),
        Duration::from_secs(1),
    )
    .await;
    let ticks = Ticks::new();
    sampler.refresh(&ticks).await.unwrap();
    finish(tasks).await;
    ticks.set(0);
    assert_eq!(sampler.now(&ticks), Err(Unavailable::Counter));
    assert_eq!(sampler.now(&ticks), Err(Unavailable::Counter));
}

#[test]
fn constructor_rejects_each_invalid_input_independently() {
    let a: SocketAddr = "127.0.0.1:2001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:2002".parse().unwrap();
    let valid = [(a, root(1)), (b, root(2))];
    let budget = Duration::from_secs(1);
    assert!(TimeSampler::new(valid, config(), budget).is_ok());
    assert!(
        TimeSampler::new([(a, root(1)), (a, root(2))], config(), budget).is_err(),
        "same endpoint"
    );
    assert!(
        TimeSampler::new([(a, root(1)), (b, root(1))], config(), budget).is_err(),
        "same root"
    );
    assert!(
        TimeSampler::new(valid, Config { hz: 0, ..config() }, budget).is_err(),
        "invalid clock config"
    );
    assert!(
        TimeSampler::new(valid, config(), Duration::ZERO).is_err(),
        "zero timeout"
    );
    assert!(
        TimeSampler::new(valid, config(), Duration::MAX).is_err(),
        "overflowing timeout"
    );
}

#[tokio::test]
async fn synchronous_completion_after_deadline_does_not_qualify_time() {
    // No mocked verifier or forged timestamps: both UDP servers sign the request
    // nonce. The honest monotonic counter models descheduling in the synchronous
    // final clock update; Tokio cannot preempt that step to enforce timeout_at.
    struct PausingCounter {
        reads: AtomicU64,
        pause_at: AtomicU64,
        start: std::time::Instant,
    }
    impl Counter for PausingCounter {
        fn ticks(&self) -> u64 {
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            if read == self.pause_at.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(300));
            }
            self.start.elapsed().as_micros() as u64
        }
    }
    let (a, seen_a, release_a, task_a) = held_renewal(1, Answer::Valid(1_000_000_000)).await;
    let (b, seen_b, release_b, task_b) = held_renewal(2, Answer::Valid(1_000_000_000)).await;
    let sampler = TimeSampler::new(
        [(a, root(1)), (b, root(2))],
        Config {
            max_age_ticks: 1_000_000,
            ..config()
        },
        Duration::from_millis(100),
    )
    .unwrap();
    let ticks = PausingCounter {
        reads: AtomicU64::new(0),
        pause_at: AtomicU64::new(u64::MAX),
        start: std::time::Instant::now(),
    };
    sampler.refresh(&ticks).await.unwrap();
    assert!(sampler.now(&ticks).is_ok());
    let before = ticks.reads.load(Ordering::SeqCst);
    ticks.pause_at.store(before + 4, Ordering::SeqCst); // two sends + two receives, then update
    let mut refresh = Box::pin(sampler.refresh(&ticks));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! { _ = &mut refresh => panic!("completed without replies"), _ = seen_a => {} }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), seen_b)
        .await
        .unwrap()
        .unwrap();
    let started = std::time::Instant::now();
    release_a.send(()).unwrap();
    release_b.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), refresh)
        .await
        .unwrap();
    let elapsed = started.elapsed();
    task_a.await.unwrap();
    task_b.await.unwrap();
    assert_eq!(
        ticks.reads.load(Ordering::SeqCst),
        before + 5,
        "both signed replies reached synchronous update"
    );
    assert!(
        elapsed >= Duration::from_millis(300),
        "actual total budget was exceeded"
    );
    assert!(
        result.is_err(),
        "over-budget synchronous completion must not return bounds"
    );
    assert_eq!(
        sampler.now(&ticks),
        Err(Unavailable::Cold),
        "late success must not leave an anchor"
    );
}

// Answers every request with a signed reply until aborted, so a test can drive
// many refreshes without sleeps. `corrupt` makes replies fail verification.
async fn serving_fixture(
    seed: u8,
    corrupt: Arc<AtomicBool>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut response = reply(seed, &nonce(&buf[..n]), 1_000_000_000);
            if corrupt.load(Ordering::SeqCst) {
                corrupt_response_signature(&mut response);
            }
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    (addr, task)
}
struct Serving {
    sampler: TimeSampler,
    ticks: Ticks,
    corrupt: Arc<AtomicBool>,
    tasks: [tokio::task::JoinHandle<()>; 2],
}
impl Drop for Serving {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn serving(refreshes: u32) -> Serving {
    let corrupt = Arc::new(AtomicBool::new(false));
    let (a, task_a) = serving_fixture(1, corrupt.clone()).await;
    let (b, task_b) = serving_fixture(2, corrupt.clone()).await;
    let sampler = TimeSampler::new(
        [(a, root(1)), (b, root(2))],
        config(),
        Duration::from_secs(2),
    )
    .unwrap();
    let ticks = Ticks::new();
    for i in 0..refreshes {
        assert!(
            sampler.refresh(&ticks).await.is_ok(),
            "refresh {i} must succeed"
        );
        assert!(sampler.now(&ticks).is_ok(), "time after refresh {i}");
    }
    Serving {
        sampler,
        ticks,
        corrupt,
        tasks: [task_a, task_b],
    }
}

// One clock holds 4096 nonces, two per refresh: a 60 s refresher would stop
// after about 34 hours unless the sampler replaces its clock.
#[tokio::test]
async fn refreshes_continue_past_one_clocks_nonce_history() {
    serving(5_000).await;
}

// Replacing the clock keeps its counter floor: a step back that the old clock
// would catch is still caught when the next refresh replaces it.
#[tokio::test]
async fn clock_replacement_keeps_counter_rollback_detection() {
    let s = serving(TimeSampler::REFRESHES_PER_CLOCK).await;
    s.ticks.set(50_000);
    assert!(s.sampler.now(&s.ticks).is_ok());
    s.ticks.set(20_000); // still after the last anchor's receipt
    assert!(s.sampler.refresh(&s.ticks).await.is_err());
    assert_eq!(s.sampler.now(&s.ticks), Err(Unavailable::Counter));
    assert!(s.sampler.refresh(&s.ticks).await.is_err());
}

// A failed refresh that would replace the clock leaves no anchor at all, then
// the next good refresh qualifies time again.
#[tokio::test]
async fn failed_replacing_refresh_serves_no_old_anchor() {
    let s = serving(TimeSampler::REFRESHES_PER_CLOCK).await;
    s.corrupt.store(true, Ordering::SeqCst);
    assert!(s.sampler.refresh(&s.ticks).await.is_err());
    assert_eq!(s.sampler.now(&s.ticks), Err(Unavailable::Cold));
    s.corrupt.store(false, Ordering::SeqCst);
    assert!(s.sampler.refresh(&s.ticks).await.is_ok());
    assert!(s.sampler.now(&s.ticks).is_ok());
}
