//! The data socket against the fake edge: one request's answer never holds
//! up another's, a request on a closing socket fails at once, and an idle
//! subscription is not taken for a lost one.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_sync::{
    BaseId, EventId, OpaqueEvent, Route,
    permit::{LogId, LogKind, Scope},
    receipt,
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

#[tokio::test]
async fn unbounded_control_read_covers_an_empty_base_on_both_paths() {
    use bh_authz::EdgeReader;
    let hosted = Hosted::new();
    let base = log();
    let permit = hosted.edge.permit(Scope::ReadControls {
        log: base,
        after: 0,
    });
    let selected = hosted
        .edge
        .read_log_with_receipt(permit.clone())
        .await
        .expect("unbounded checker read must be supported");
    assert!(selected.items.is_empty());
    assert!(selected.receipt.is_none());
    let endpoint = selected.coverage.expect("an empty log still has coverage");
    assert_eq!(endpoint.order, bh_sync::OrderState::EMPTY);
    assert!(endpoint.receipt.is_none());

    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let Response::Events {
        items,
        receipt: None,
        coverage: Some(endpoint),
        ..
    } = data.ask(|id| Request::Read { id, permit }).await.unwrap()
    else {
        panic!("unbounded DATA read must cover empty log")
    };
    assert!(items.is_empty());
    assert_eq!(endpoint.order, bh_sync::OrderState::EMPTY);
    assert!(endpoint.receipt.is_none());
}

#[tokio::test]
async fn unbounded_control_read_covers_full_head_after_trailing_content() {
    use bh_authz::EdgeReader;
    let hosted = Hosted::new();
    let first = OpaqueEvent::new(EventId([41; 32]), vec![2; 1024]).unwrap();
    let base = LogId {
        kind: LogKind::Base,
        id: first.digest().0,
    };
    hosted.edge.order(base, &first, None, Route::Control);
    let second = OpaqueEvent::new(EventId([42; 32]), vec![3; 1024]).unwrap();
    hosted.edge.order(base, &second, None, Route::Content);
    let expected = hosted.edge.entries(base)[1].0.after();
    let permit = hosted.edge.permit(Scope::ReadControls {
        log: base,
        after: 1,
    });
    let selected = hosted
        .edge
        .read_log_with_receipt(permit.clone())
        .await
        .unwrap();
    // This later append must not be mistaken for an endpoint of the prior read.
    let later = OpaqueEvent::new(EventId([43; 32]), vec![4; 1024]).unwrap();
    hosted.edge.order(base, &later, None, Route::Control);
    assert!(selected.items.is_empty());
    assert!(selected.receipt.is_none());
    let endpoint = selected
        .coverage
        .expect("sparse empty page retains full endpoint");
    assert_eq!(endpoint.order, expected);
    assert_eq!(
        receipt::verify(
            &hosted.edge.root(),
            BaseId(base.id),
            &endpoint.receipt.unwrap()
        )
        .unwrap()
        .head(),
        expected.head(BaseId(base.id))
    );

    let Response::Events {
        items,
        receipt: None,
        coverage: Some(endpoint),
        ..
    } = DataSocket::open(hosted.connector().as_ref())
        .await
        .unwrap()
        .ask(|id| Request::Read { id, permit })
        .await
        .unwrap()
    else {
        panic!("unbounded DATA page must carry full endpoint")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1, later.encode());
    assert_eq!(endpoint.order, hosted.edge.entries(base)[2].0.after());
    assert_eq!(
        receipt::verify(
            &hosted.edge.root(),
            BaseId(base.id),
            &endpoint.receipt.unwrap()
        )
        .unwrap()
        .head(),
        endpoint.order.head(BaseId(base.id))
    );
}

#[tokio::test]
async fn unbounded_control_probe_is_not_a_bounded_batch_read() {
    use bh_authz::EdgeReader;
    let hosted = Hosted::new();
    let base = log();
    let permit = hosted.edge.permit(Scope::ReadControls {
        log: base,
        after: 0,
    });
    hosted.edge.read_log_with_receipt(permit).await.unwrap();
    assert!(hosted.edge.selected_reads(base).is_empty());
    let permit = hosted.edge.permit(Scope::ReadEvents {
        log: base,
        first: 1,
        last: 64,
    });
    hosted.edge.read_log_with_receipt(permit).await.unwrap();
    assert_eq!(hosted.edge.selected_reads(base), vec![(1, 64)]);
}

#[tokio::test]
async fn sparse_pages_keep_the_full_endpoint_when_controls_exceed_one_page() {
    use bh_authz::EdgeReader;
    let hosted = Hosted::new();
    let first = OpaqueEvent::new(EventId([50; 32]), vec![1; 1024]).unwrap();
    let base = LogId {
        kind: LogKind::Base,
        id: first.digest().0,
    };
    hosted.edge.order(base, &first, None, Route::Control);
    for n in 1..=64u8 {
        let event = OpaqueEvent::new(EventId([n; 32]), vec![n; 1024]).unwrap();
        hosted.edge.order(base, &event, None, Route::Control);
    }
    let trailing = OpaqueEvent::new(EventId([80; 32]), vec![3; 1024]).unwrap();
    hosted.edge.order(base, &trailing, None, Route::Content);
    let expected = hosted.edge.entries(base)[65].0.after();
    for (after, count) in [(0, 64), (64, 1), (65, 0)] {
        let permit = hosted.edge.permit(Scope::ReadControls { log: base, after });
        let page = hosted.edge.read_log_with_receipt(permit).await.unwrap();
        assert_eq!(page.items.len(), count);
        assert!(page.receipt.is_none());
        let endpoint = page.coverage.unwrap();
        assert_eq!(endpoint.order, expected);
        assert_eq!(
            receipt::verify(
                &hosted.edge.root(),
                BaseId(base.id),
                &endpoint.receipt.unwrap()
            )
            .unwrap()
            .head(),
            expected.head(BaseId(base.id))
        );
    }
}

#[tokio::test]
async fn sparse_bounded_read_refuses_missing_endpoint_and_freeze_only_hides_rows() {
    use bh_authz::EdgeReader;
    let hosted = Hosted::new();
    let first = OpaqueEvent::new(EventId([91; 32]), vec![2; 1024]).unwrap();
    let base = LogId {
        kind: LogKind::Base,
        id: first.digest().0,
    };
    hosted.edge.order(base, &first, None, Route::Control);
    let second = OpaqueEvent::new(EventId([92; 32]), vec![3; 1024]).unwrap();
    hosted.edge.order(base, &second, None, Route::Control);
    let expected = hosted.edge.entries(base)[1].0.after();
    hosted.edge.freeze_reads(Some(1));
    let permit = hosted.edge.permit(Scope::ReadControls {
        log: base,
        after: 1,
    });
    let page = hosted.edge.read_log_with_receipt(permit).await.unwrap();
    assert!(
        page.items.is_empty(),
        "frozen reads must still omit later rows"
    );
    assert_eq!(
        page.coverage.unwrap().order,
        expected,
        "omission must not shrink canonical coverage"
    );
    hosted.edge.freeze_reads(None);
    let permit = hosted.edge.permit(Scope::ReadControlRange {
        log: base,
        after: 0,
        through: 3,
    });
    assert!(
        hosted
            .edge
            .read_log_with_receipt(permit.clone())
            .await
            .is_err()
    );
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    assert!(matches!(
        data.ask(|id| Request::Read { id, permit }).await.unwrap(),
        Response::Refused { .. }
    ));
}

#[tokio::test]
async fn fake_control_range_keeps_its_log_and_issue_head() {
    let hosted = Hosted::new();
    let genesis = OpaqueEvent::new(EventId([1; 32]), vec![2; 1024]).unwrap();
    let base = LogId {
        kind: LogKind::Base,
        id: genesis.digest().0,
    };
    hosted.edge.order(base, &genesis, None, Route::Control);
    let permit = hosted.edge.permit(Scope::ReadControlRange {
        log: base,
        after: 0,
        through: 1,
    });
    let content = OpaqueEvent::new(EventId([2; 32]), vec![3; 1024]).unwrap();
    hosted.edge.order(base, &content, None, Route::Content);
    let later = OpaqueEvent::new(EventId([3; 32]), vec![4; 1024]).unwrap();
    hosted.edge.order(base, &later, None, Route::Control);
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let answer = data.ask(|id| Request::Read { id, permit }).await.unwrap();
    let Response::Events {
        items,
        coverage: Some(endpoint),
        ..
    } = answer
    else {
        panic!("expected sparse events and endpoint")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1, genesis.encode());
    assert_eq!(endpoint.order.position(), 1);
    let proof = receipt::verify(
        &hosted.edge.root(),
        BaseId(base.id),
        &endpoint.receipt.unwrap(),
    )
    .unwrap();
    assert_eq!(proof.head(), endpoint.order.head(BaseId(base.id)));
    let other = OpaqueEvent::new(EventId([4; 32]), vec![5; 1024]).unwrap();
    let foreign = LogId {
        kind: LogKind::Base,
        id: other.digest().0,
    };
    hosted.edge.order(foreign, &other, None, Route::Control);
    let permit = hosted.edge.permit(Scope::ReadControlRange {
        log: foreign,
        after: 0,
        through: 1,
    });
    let answer = data.ask(|id| Request::Read { id, permit }).await.unwrap();
    let Response::Events { items, .. } = answer else {
        panic!("expected events")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1, other.encode());
}

#[tokio::test]
async fn sparse_empty_page_captures_content_endpoint_before_later_appends() {
    use bh_authz::EdgeReader;
    let hosted = Hosted::new();
    let first = OpaqueEvent::new(EventId([11; 32]), vec![2; 1024]).unwrap();
    let base = LogId {
        kind: LogKind::Base,
        id: first.digest().0,
    };
    let second = OpaqueEvent::new(EventId([12; 32]), vec![3; 1024]).unwrap();
    hosted.edge.order(base, &first, None, Route::Control);
    hosted.edge.order(base, &second, None, Route::Content);
    let expected = hosted.edge.entries(base)[1].0.after();
    let permit = hosted.edge.permit(Scope::ReadControlRange {
        log: base,
        after: 1,
        through: 2,
    });
    let later = OpaqueEvent::new(EventId([13; 32]), vec![4; 1024]).unwrap();
    hosted.edge.order(base, &later, None, Route::Control);
    let selected = hosted
        .edge
        .read_log_with_receipt(permit.clone())
        .await
        .unwrap();
    assert!(selected.items.is_empty());
    let endpoint = selected.coverage.unwrap();
    assert_eq!(endpoint.order, expected);
    assert_eq!(
        receipt::verify(
            &hosted.edge.root(),
            BaseId(base.id),
            &endpoint.receipt.unwrap()
        )
        .unwrap()
        .head(),
        expected.head(BaseId(base.id))
    );
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let Response::Events {
        items,
        coverage: Some(endpoint),
        ..
    } = data.ask(|id| Request::Read { id, permit }).await.unwrap()
    else {
        panic!("sparse DATA response")
    };
    assert!(items.is_empty());
    assert_eq!(endpoint.order, expected);
    let full = hosted.edge.permit(Scope::ReadEvents {
        log: base,
        first: 1,
        last: 3,
    });
    let Response::Events { coverage: None, .. } = data
        .ask(|id| Request::Read { id, permit: full })
        .await
        .unwrap()
    else {
        panic!("full read cannot claim sparse coverage")
    };
    let account = LogId {
        kind: LogKind::Account,
        id: [42; 32],
    };
    let permit = hosted.edge.permit(Scope::ReadEvents {
        log: account,
        first: 1,
        last: 64,
    });
    let Response::Events {
        items,
        coverage: None,
        ..
    } = data.ask(|id| Request::Read { id, permit }).await.unwrap()
    else {
        panic!("ordinary account read cannot claim sparse coverage")
    };
    assert!(items.is_empty());
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
