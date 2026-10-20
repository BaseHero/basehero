//! The data socket against the fake edge: one request's answer never holds
//! up another's, a request on a closing socket fails at once, and an idle
//! subscription is not taken for a lost one.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_sync::{
    permit::{LogId, LogKind, Scope},
    wire::{Request, Response},
};
use bh_sync_client::data::DataSocket;
use std::time::Duration;
use support::fake::Hosted;

fn log() -> LogId {
    LogId {
        kind: LogKind::Base,
        id: [3; 32],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unread_answer_does_not_hold_up_other_requests() {
    let hosted = Hosted::new();
    let bodies: Vec<_> = (1..=4u8)
        .map(|n| hosted.edge.insert_body(log(), vec![n; 1024]))
        .collect();
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    // Four Body frames nobody reads yet.
    let permit = hosted.edge.permit(Scope::ReadBodies {
        log: log(),
        bodies: bodies.clone(),
    });
    let mut unread = data.send(|id| Request::Read { id, permit }).unwrap();
    let permit = hosted.edge.permit(Scope::ReadEvents {
        log: log(),
        first: 1,
        last: 1,
    });
    let answer = tokio::time::timeout(
        Duration::from_secs(5),
        data.ask(|id| Request::Read { id, permit }),
    )
    .await
    .expect("answered while another answer is unread");
    assert!(matches!(answer, Ok(Response::Events { .. })));
    // The unread answer is still whole, in order.
    for index in 0..4u8 {
        let Some(Response::Body { index: got, .. }) = unread.next().await else {
            panic!("body {index}")
        };
        assert_eq!(got, index);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_on_a_closing_socket_fails_at_once() {
    let hosted = Hosted::new();
    for _ in 0..50 {
        hosted.come_up();
        let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
        hosted.go_down();
        // Each request either fails to send or ends at once: none waits for
        // the lost-frame limit on a socket that is gone.
        for _ in 0..20 {
            let permit = hosted.edge.permit(Scope::ReadEvents {
                log: log(),
                first: 1,
                last: 1,
            });
            if let Ok(mut answers) = data.send(|id| Request::Read { id, permit }) {
                let next = tokio::time::timeout(Duration::from_secs(2), answers.next()).await;
                assert!(
                    matches!(next, Ok(None) | Ok(Some(_))),
                    "a request on a closed socket waited"
                );
            }
            tokio::task::yield_now().await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn an_idle_subscription_is_not_lost() {
    let hosted = Hosted::new();
    // The client's own wait is under test, not the permit's life, which
    // ends a subscription at its deadline (30 s) once the clock moves.
    hosted.edge.clock.stand_still();
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let permit = hosted.edge.permit(Scope::Subscribe { log: log() });
    let mut heads = data
        .send(|id| Request::Subscribe {
            id,
            permit,
            after: 0,
        })
        .unwrap();
    // Well past the lost-frame limit for answers: a subscription waits for
    // the next head as long as its socket is open.
    let next = tokio::time::timeout(Duration::from_secs(300), heads.next()).await;
    assert!(next.is_err(), "an idle subscription ended: {:?}", next.ok());
    // A request that expects an answer still has the limit.
    hosted.go_down();
    assert!(heads.next().await.is_none());
}
