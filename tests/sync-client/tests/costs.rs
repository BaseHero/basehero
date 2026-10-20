//! The fixture's clock, injected costs and counters do what they claim:
//! each cost is paid once at its own seam, by exactly its amount of the
//! runtime's paused clock, and each counter counts exactly what crossed.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::proto::{FromService, ToService, Want};
use bh_sync::{
    Digest, Head,
    permit::{LogId, LogKind, Scope},
    wire::{Refusal, Request, Response},
};
use bh_sync_client::{Signer, data::DataSocket};
use std::time::Duration;
use support::{
    device::{Device, until},
    fake::{Costs, Hosted},
};
use tokio::time::{Instant, sleep};

fn log() -> LogId {
    LogId {
        kind: LogKind::Base,
        id: [3; 32],
    }
}

const fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Only the edge's calls to its log objects cost anything.
const OBJECT_ONLY: Costs = Costs {
    edge_object: ms(20),
    ..Costs::FREE
};

#[tokio::test(start_paused = true)]
async fn the_service_clock_moves_with_the_runtime_and_permits_expire() {
    let hosted = Hosted::new();
    let before = hosted.edge.clock.now();
    sleep(ms(1234)).await;
    assert_eq!(hosted.edge.clock.now() - before, 1234);
    let permit = hosted.edge.permit(Scope::ReadEvents {
        log: log(),
        first: 1,
        last: 1,
    });
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let fresh = data
        .ask(|id| Request::Read {
            id,
            permit: permit.clone(),
        })
        .await;
    assert!(matches!(fresh, Ok(Response::Events { .. })), "{fresh:?}");
    // The permit's 30 s life passes on the runtime's clock alone.
    sleep(Duration::from_secs(31)).await;
    let late = data.ask(|id| Request::Read { id, permit }).await;
    assert!(
        matches!(
            late,
            Ok(Response::Refused {
                reason: Refusal::Expired,
                ..
            })
        ),
        "{late:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn data_frames_are_counted_both_ways_with_their_bytes() {
    let hosted = Hosted::new();
    let body = vec![7; 1024];
    let digest = hosted.edge.insert_body(log(), body.clone());
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let permit = hosted.edge.permit(Scope::ReadEvents {
        log: log(),
        first: 1,
        last: 1,
    });
    let request = Request::Read {
        id: 1,
        permit: permit.clone(),
    }
    .encode()
    .unwrap();
    let before = hosted.edge.counts();
    let answer = data.ask(|id| Request::Read { id, permit }).await.unwrap();
    let counted = hosted.edge.counts() - before;
    // The request, and the credit its answer gave back (one fixed frame).
    let credit = Request::Credit { bytes: 1 }.encode().unwrap().len();
    assert_eq!(
        (counted.data_up, counted.data_up_bytes),
        (
            1 + counted.credits,
            request.len() + counted.credits * credit
        )
    );
    assert_eq!(
        (counted.data_down, counted.data_down_bytes),
        (1, answer.encode().unwrap().len())
    );
    assert_eq!((counted.read_events, counted.read_bodies), (1, 0));
    assert_eq!(counted.body_bytes_down, 0);

    let permit = hosted.edge.permit(Scope::ReadBodies {
        log: log(),
        bodies: vec![digest],
    });
    let before = hosted.edge.counts();
    let answer = data.ask(|id| Request::Read { id, permit }).await.unwrap();
    let counted = hosted.edge.counts() - before;
    assert!(matches!(answer, Response::Body { .. }), "{answer:?}");
    assert_eq!((counted.read_events, counted.read_bodies), (0, 1));
    assert_eq!(counted.body_bytes_down, body.len());
    assert_eq!(counted.data_down_bytes, answer.encode().unwrap().len());
}

/// One registered device whose genesis is applied.
async fn registered(hosted: &std::sync::Arc<Hosted>) -> (Device, bh_sync_client::Client) {
    let device = Device::new();
    let (client, _) = device.start(hosted);
    until(60, "registered", || {
        device.registered() && device.progress().position >= 1
    })
    .await;
    (device, client)
}

#[tokio::test(start_paused = true)]
async fn authorization_records_and_permit_items_are_counted() {
    let hosted = Hosted::new();
    let (device, client) = registered(&hosted).await;
    sleep(Duration::from_secs(2)).await;
    let before = hosted.edge.counts();
    let messages = hosted
        .edge
        .authz_messages
        .load(std::sync::atomic::Ordering::SeqCst);
    let (_writer, update) = device.new_note("counted");
    client.wake();
    until(20, "acknowledged", || device.acked(update).is_some()).await;
    until(20, "own echo", || device.pending() == 0).await;
    let counted = hosted.edge.counts() - before;
    println!("{counted:?}");
    // One package: one Permits message asking for its stage and append
    // grants, one compound Publish, and the own echo read by ReadBatch.
    assert_eq!(counted.permits_messages, 1);
    assert_eq!((counted.want_stage, counted.want_append), (1, 1));
    assert_eq!(counted.publish, 1);
    assert!(counted.read_batches >= 1);
    // On an open session each request is one record, answered by one.
    assert_eq!(
        counted.authz_up,
        counted.permits_messages + counted.read_batches + counted.other_requests
    );
    assert_eq!(
        counted.authz_up,
        hosted
            .edge
            .authz_messages
            .load(std::sync::atomic::Ordering::SeqCst)
            - messages
    );
    assert_eq!(counted.authz_down, counted.authz_up);
    assert!(counted.authz_up_bytes > counted.authz_up * 60);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn each_read_through_the_edge_costs_its_two_hops_each_way() {
    let hosted = Hosted::new();
    let (device, client) = registered(&hosted).await;
    sleep(Duration::from_secs(2)).await;
    hosted.edge.set_costs(Costs {
        checker_edge: ms(20),
        edge_object: ms(20),
        ..Costs::FREE
    });
    let progress = device.progress();
    let mut session = client.authz().await.unwrap();
    let before = hosted.edge.counts();
    let asked = Instant::now();
    let answer = session
        .ask(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: device.log(),
                after: Head {
                    position: progress.position,
                    hash: Digest(progress.head_hash),
                },
                max_events: 48,
            },
        })
        .await
        .unwrap();
    let took = asked.elapsed();
    let reads = (hosted.edge.counts() - before).edge_reads;
    println!("ReadBatch: {reads} reads through the edge, {took:?}");
    assert!(matches!(answer, FromService::ReadBatch { .. }));
    // Account refresh, base controls and selection.
    assert_eq!(reads, 3);
    // Each read: service to edge to object and back, 4 x 20 ms. The
    // ReadBatch's reads run side by side.
    assert_eq!(took, ms(80));
    drop(session);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn each_data_request_pays_its_calls_to_the_object() {
    let hosted = Hosted::new();
    hosted.edge.set_costs(OBJECT_ONLY);
    let bodies: Vec<_> = (1..=2u8)
        .map(|n| hosted.edge.insert_body(log(), vec![n; 1024]))
        .collect();
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let permit = hosted.edge.permit(Scope::ReadEvents {
        log: log(),
        first: 1,
        last: 1,
    });
    let asked = Instant::now();
    data.ask(|id| Request::Read { id, permit }).await.unwrap();
    // One call to the object, there and back.
    assert_eq!(asked.elapsed(), ms(40));

    let permit = hosted.edge.permit(Scope::ReadBodies { log: log(), bodies });
    let asked = Instant::now();
    let mut answers = data.send(|id| Request::Read { id, permit }).unwrap();
    let mut arrived = Vec::new();
    while let Some(frame) = answers.next().await {
        arrived.push(asked.elapsed());
        if matches!(frame, Response::Body { last: true, .. }) {
            break;
        }
    }
    // The object names the bodies (40 ms), then each comes from the body
    // store in turn (40 ms each).
    assert_eq!(arrived, [ms(80), ms(120)]);
}

#[tokio::test(start_paused = true)]
async fn a_subscription_pays_its_socket_to_the_object_and_each_notice() {
    let hosted = Hosted::new();
    let (device, client) = registered(&hosted).await;
    client.shutdown().await;
    hosted.edge.set_costs(OBJECT_ONLY);
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let permit = hosted.edge.permit(Scope::Subscribe { log: device.log() });
    let asked = Instant::now();
    let mut heads = data
        .send(|id| Request::Subscribe {
            id,
            permit,
            after: 0,
        })
        .unwrap();
    let head = heads.next().await;
    assert!(matches!(head, Some(Response::Head { .. })), "{head:?}");
    // The edge opens its socket to the object (40 ms); the head already
    // there comes from the object to the edge (20 ms).
    assert_eq!(asked.elapsed(), ms(60));
}

#[tokio::test(start_paused = true)]
async fn the_signer_and_a_seal_commit_take_their_time() {
    let hosted = Hosted::new();
    let (device, client) = registered(&hosted).await;
    client.shutdown().await;
    drop(client);
    *device.signer.sign_time.lock().unwrap() = ms(30);
    let asked = Instant::now();
    device.signer.sign_event(b"timed".to_vec()).await.unwrap();
    assert_eq!(asked.elapsed(), ms(30));

    // Only the commit costs: a new package's seal is persisted 5 ms after
    // its run is captured.
    hosted.edge.set_costs(Costs {
        commit: ms(5),
        ..Costs::FREE
    });
    let (client, _) = device.start(&hosted);
    sleep(Duration::from_secs(3)).await;
    let mut typist = device.new_typist();
    let update = device.type_key(&mut typist, 'x');
    let asked = device.signer.sign_asked.lock().unwrap().len();
    client.wake();
    while device.package(update).is_none() {
        sleep(ms(1)).await;
    }
    let captured = device.signer.sign_asked.lock().unwrap()[asked];
    let sealed = Instant::now() - captured;
    assert!((ms(5)..=ms(6)).contains(&sealed), "{sealed:?}");
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_constrained_uplink_carries_frames_at_its_rate() {
    let hosted = Hosted::new();
    hosted.edge.set_uplink(Some(10_000));
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let permit = hosted.edge.permit(Scope::ReadEvents {
        log: log(),
        first: 1,
        last: 1,
    });
    let len = Request::Read {
        id: 1,
        permit: permit.clone(),
    }
    .encode()
    .unwrap()
    .len();
    let asked = Instant::now();
    data.ask(|id| Request::Read { id, permit }).await.unwrap();
    let took = asked.elapsed();
    // 10,000 bytes a second: 100 µs a byte, to the millisecond the timer
    // keeps.
    let carry = Duration::from_micros(len as u64 * 100);
    assert!(
        took >= carry && took <= carry + ms(1),
        "{took:?} for {len} bytes"
    );
}
