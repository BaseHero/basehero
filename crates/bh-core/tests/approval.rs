use bh_core::{AccountEvent, ApprovalId, DeviceId};
use bh_testkit::{device, new_signup, pending_device_for, request_count};
use serde_json::json;
use std::time::Duration;

async fn create_request(a: &bh_core::Account) -> (bh_testkit::RawDevice, ApprovalId, DeviceId) {
    let pending = pending_device_for(a).await;
    let id = ApprovalId::random();
    let new_id: DeviceId = pending.device_id.parse().unwrap();
    let (status, body) = pending
        .post("/v1/approvals", json!({"approvalId": id, "request": "AQ"}))
        .await;
    assert!(status.is_success(), "{body}");
    (pending, id, new_id)
}

#[tokio::test]
async fn a_full_device_hears_a_new_request_without_polling() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut events = a.events();
    tokio::time::timeout(Duration::from_secs(2), async {
        while request_count(&a, "v1/approvals") == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let before = request_count(&a, "v1/approvals");
    let (_, id, new_id) = create_request(&a).await;
    let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(event, AccountEvent::ApprovalRequested(r) if r.id == id && r.device_id == new_id)
    );
    assert!(
        request_count(&a, "v1/approvals") - before <= 1,
        "listener polled unnecessarily"
    );
}

#[tokio::test]
async fn a_request_made_while_offline_is_heard_on_reconnect() {
    let mut server = bh_testkit::LocalServer::start();
    let core = bh_testkit::device_on_server("mac", &bh_core::Clock::system(), &server);
    let signup = bh_core::SignUp {
        server: server.url(),
        invite: bh_testkit::invite(&server),
        email: format!("{}@example.test", bh_core::AccountId::random()),
        password: bh_testkit::TEST_PASSWORD.to_string().into(),
        device_name: "mac".into(),
    };
    let (a, _) = core.sign_up(signup).await.unwrap();
    let mut events = a.events();
    server.restart();
    let pending = bh_testkit::pending_device_on(&a, &server).await;
    let id = ApprovalId::random();
    let (status, body) = pending
        .post("/v1/approvals", json!({"approvalId": id, "request": "AQ"}))
        .await;
    assert!(status.is_success(), "{body}");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop { if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalRequested(r) if r.id == id) { break; } }
    }).await.unwrap();
}

#[tokio::test]
async fn listing_requests_sends_nothing() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let (pending, id, _) = create_request(&a).await;
    assert!(
        a.approval_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == id)
    );
    let (status, state) = pending.get(&format!("/v1/approvals/{id}"), json!({})).await;
    assert!(status.is_success());
    assert_eq!(state["state"], "requested");
    assert_eq!(request_count(&a, &format!("v1/approvals/{id}/respond")), 0);
}

#[tokio::test]
async fn a_declined_request_closes_everywhere() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let b = device("fold")
        .sign_in(bh_testkit::signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let mut events = b.events();
    tokio::time::timeout(Duration::from_secs(2), async {
        while request_count(&b, "v1/approvals") == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (pending, id, _) = create_request(&a).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop { if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalRequested(r) if r.id == id) { break; } }
    }).await.unwrap_or_else(|_| panic!("b missed request: live={}, list={}, requests={:?}", request_count(&b, "v1/approvals/live"), request_count(&b, "v1/approvals"), request_count(&a, "v1/approvals")));
    a.decline(id).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop { if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalClosed(closed) if closed == id) { break; } }
    }).await.unwrap();
    let (_, state) = pending.get(&format!("/v1/approvals/{id}"), json!({})).await;
    assert_eq!(state["endReason"], "declined");
    assert!(
        b.approval_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.id != id)
    );
}

#[tokio::test]
async fn an_idle_request_expires_and_closes_on_a_full_device() {
    let server = bh_testkit::LocalServer::start_with_vars(&[("APPROVAL_TTL_MS", "700")]);
    let core = bh_testkit::device_on_server("mac", &bh_core::Clock::system(), &server);
    let (a, _) = core
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: bh_testkit::TEST_PASSWORD.to_string().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    let mut events = a.events();
    tokio::time::timeout(Duration::from_secs(2), async {
        while request_count(&a, "v1/approvals") == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let first = bh_testkit::pending_device_on(&a, &server).await;
    let second = bh_testkit::pending_device_on(&a, &server).await;
    let ids = [ApprovalId::random(), ApprovalId::random()];
    let (one, two) = tokio::join!(
        first.post(
            "/v1/approvals",
            json!({"approvalId": ids[0], "request": "AQ"})
        ),
        second.post(
            "/v1/approvals",
            json!({"approvalId": ids[1], "request": "AQ"})
        ),
    );
    assert!(one.0.is_success(), "{}", one.1);
    assert!(two.0.is_success(), "{}", two.1);
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut requested = Vec::new();
        while requested.len() < 2 {
            if let AccountEvent::ApprovalRequested(r) = events.recv().await.unwrap() {
                assert!(ids.contains(&r.id));
                requested.push(r.id);
            }
        }
        assert_ne!(requested[0], requested[1]);
    })
    .await
    .expect("both requests must be seen before expiry");
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut closed = Vec::new();
        while closed.len() < 2 {
            if let AccountEvent::ApprovalClosed(id) = events.recv().await.unwrap() {
                assert!(ids.contains(&id));
                closed.push(id);
            }
        }
        assert_ne!(closed[0], closed[1]);
    })
    .await
    .expect("both idle expiries must be sent to the full device");
    for (pending, id) in [(first, ids[0]), (second, ids[1])] {
        let (_, state) = pending.get(&format!("/v1/approvals/{id}"), json!({})).await;
        assert_eq!(state["endReason"], "expired");
    }
}

#[tokio::test]
async fn signing_out_stops_the_listener_and_drops_its_socket() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let mut events = a.events();
    tokio::time::timeout(Duration::from_secs(2), async {
        while request_count(&a, "v1/approvals") == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    a.sign_out().await.unwrap(); // Awaits the listener's termination (and socket drop).
    assert!(core.accounts().is_empty());
    assert!(matches!(
        core.account(a.id()),
        Err(bh_core::Error::NotFound)
    ));
    assert!(matches!(
        events.recv().await.unwrap(),
        AccountEvent::Removed
    ));
    let before = request_count(&a, "v1/approvals/live");
    // A terminated task must not retry, even after its former socket closes.
    let result = tokio::time::timeout(Duration::from_millis(750), events.recv()).await;
    assert!(
        result.is_err(),
        "unexpected event after sign-out: {result:?}"
    );
    assert_eq!(request_count(&a, "v1/approvals/live"), before);
}

#[tokio::test]
async fn pending_devices_cannot_list_requests() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    // Pending tokens also cannot list at the relay.
    let pending = pending_device_for(&a).await;
    let (status, _) = pending.get("/v1/approvals", json!({})).await;
    assert_eq!(status.as_u16(), 403);
    assert!(a.approval_requests().await.is_ok());
}
