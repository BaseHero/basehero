//! Live changes against the local Worker, through two encrypted core stores.

use bh_core::{Base, BaseEvent, Clock};
use bh_testkit::{
    LocalServer, TEST_PASSWORD, append_text, device_on_server, invite, note_with_text, pause_sync,
    raw_device, resume_sync, two_devices_sharing_a_base, wait_for,
};
use std::time::{Duration, Instant};

fn text(base: &Base, id: bh_core::ObjectId) -> Option<String> {
    base.note(id).ok().map(|doc| doc.text())
}

#[tokio::test]
async fn a_live_edit_arrives_without_polling() {
    let (a, b) = two_devices_sharing_a_base().await;
    let since = format!("v1/bases/{}/since", b.base.id());
    let initial = b.account.test_request_count(&since);
    let id = note_with_text(&a.base, "Live arrival");
    a.base.flush().await.unwrap();
    wait_for(|| text(&b.base, id).as_deref() == Some("Live arrival")).await;
    // The since request count, not elapsed CPU time, proves delivery used live
    // notifications rather than the fallback catch-up path.
    assert_eq!(
        b.account.test_request_count(&since),
        initial,
        "polled since after catch-up"
    );
}

#[tokio::test]
async fn a_gap_in_the_live_stream_refetches_the_object() {
    let (a, b) = two_devices_sharing_a_base().await;
    let id = note_with_text(&a.base, "First");
    a.base.flush().await.unwrap();
    wait_for(|| text(&b.base, id).as_deref() == Some("First")).await;
    let path = format!("v1/bases/{}/fetch", b.base.id());
    let before = b.account.test_request_count(&path);
    // The local Worker omits exactly one notification to b, not the committed change.
    let raw = bh_testkit::raw_device(&b.account);
    let (status, body) = raw
        .post(
            &format!("/v1/bases/{}/drop-next-live", b.base.id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let doc = a.base.note(id).unwrap();
    doc.apply(5, &append_text(&doc.state(), "Second")).unwrap();
    a.base.flush().await.unwrap();
    doc.apply(5, &append_text(&doc.state(), "Third")).unwrap();
    a.base.flush().await.unwrap();
    wait_for(|| text(&b.base, id) == text(&a.base, id)).await;
    assert!(
        b.account.test_request_count(&path) > before,
        "gap did not fetch"
    );
}

#[tokio::test]
async fn devices_reconnect_after_a_server_restart() {
    let mut server = LocalServer::start();
    bh_core::test_support::set_test_bypass(server.operator_token());
    let clock = Clock::system();
    let a = device_on_server("a", &clock, &server);
    let (a, kit) = a
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: invite(&server),
            email: format!("{}@example.test", bh_testkit::random_id()),
            password: TEST_PASSWORD.to_string().into(),
            device_name: String::new(),
        })
        .await
        .unwrap();
    let b = device_on_server("b", &clock, &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            email: a.email(),
            password: TEST_PASSWORD.to_string().into(),
            device_name: String::new(),
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Restart").await.unwrap();
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let other = b.base(base.id()).unwrap();
    wait_for(|| other.sync_state().online).await;
    server.restart();
    let id = note_with_text(&base, "After restart");
    base.flush().await.unwrap();
    wait_for(|| text(&other, id).as_deref() == Some("After restart") && other.sync_state().online)
        .await;
}

#[tokio::test]
async fn an_aged_live_socket_reconnects_and_catches_up() {
    let server = LocalServer::start_with_vars(&[("LIVE_SOCKET_MAX_AGE_MS", "500")]);
    let clock = Clock::system();
    let a = device_on_server("a", &clock, &server);
    let (a, kit) = a
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: invite(&server),
            email: format!("{}@example.test", bh_testkit::random_id()),
            password: TEST_PASSWORD.to_string().into(),
            device_name: String::new(),
        })
        .await
        .unwrap();
    let b = device_on_server("b", &clock, &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            email: a.email(),
            password: TEST_PASSWORD.to_string().into(),
            device_name: String::new(),
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Socket age").await.unwrap();
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let other = b.base(base.id()).unwrap();
    wait_for(|| other.sync_state().online).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    let since = format!("v1/bases/{}/since", base.id());
    let before = b.test_request_count(&since);
    let id = note_with_text(&base, "Caught up after age");
    base.flush().await.unwrap();
    wait_for(|| {
        text(&other, id).as_deref() == Some("Caught up after age") && other.sync_state().online
    })
    .await;
    assert!(
        b.test_request_count(&since) > before,
        "did not catch up on reconnect"
    );
}

#[tokio::test]
async fn dropping_the_last_base_closes_its_live_socket() {
    let (a, b) = two_devices_sharing_a_base().await;
    let raw = bh_testkit::raw_device(&b.account);
    let path = format!("/v1/bases/{}/live-count", a.base.id());
    let (status, count) = raw.get(&path, serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{count}");
    assert_eq!(count["count"], 2);
    drop(b.base);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (status, count) = raw.get(&path, serde_json::json!({})).await;
        assert_eq!(status, reqwest::StatusCode::OK, "{count}");
        if count["count"] == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "socket remained open: {count}");
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn a_missing_fetch_body_retries_catch_up_without_another_live_change() {
    let (a, b) = two_devices_sharing_a_base().await;
    pause_sync(&b.base);
    let id = note_with_text(&a.base, "Fetched after retry");
    a.base.flush().await.unwrap();
    let raw = raw_device(&b.account);
    let path = format!("/v1/bases/{}/miss-next-fetch", b.base.id());
    let (status, body) = raw.post(&path, serde_json::json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let since = format!("v1/bases/{}/since", b.base.id());
    let initial = b.account.test_request_count(&since);
    resume_sync(&b.base);
    wait_for(|| {
        text(&b.base, id).as_deref() == Some("Fetched after retry")
            && b.account.test_request_count(&since) >= initial + 2
    })
    .await;
}

#[tokio::test]
async fn a_short_fetch_retries_the_unaccounted_object() {
    let (a, b) = two_devices_sharing_a_base().await;
    pause_sync(&b.base);
    let first = note_with_text(&a.base, "First after retry");
    let second = note_with_text(&a.base, "Second after retry");
    a.base.flush().await.unwrap();
    let raw = raw_device(&b.account);
    let (status, body) = raw
        .post(
            &format!("/v1/bases/{}/short-next-fetch", b.base.id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let since = format!("v1/bases/{}/since", b.base.id());
    let initial = b.account.test_request_count(&since);
    resume_sync(&b.base);
    wait_for(|| {
        text(&b.base, first).as_deref() == Some("First after retry")
            && text(&b.base, second).as_deref() == Some("Second after retry")
            && b.account.test_request_count(&since) >= initial + 2
    })
    .await;
}

#[tokio::test]
async fn a_device_ignores_the_echo_of_its_own_change() {
    let (a, b) = two_devices_sharing_a_base().await;
    wait_for(|| a.base.sync_state().online && b.base.sync_state().online).await;
    let raw = raw_device(&a.account);
    let base_path = format!("/v1/bases/{}", a.base.id());
    let (status, body) = raw
        .post(
            &format!("{base_path}/hold-change-reply"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    pause_sync(&a.base);
    let mut events = a.base.events();
    let id = note_with_text(&a.base, "Own echo");
    while events.try_recv().is_ok() {} // Drain both local create and edit events.
    resume_sync(&a.base);
    let fetch_path = format!("v1/bases/{}/fetch", a.base.id());
    let before = a.account.test_request_count(&fetch_path);
    let sending = a.base.clone();
    let flush = tokio::spawn(async move { sending.flush().await });
    wait_for(|| text(&b.base, id).as_deref() == Some("Own echo")).await;
    // The other socket received the broadcast; the sender still has no reply.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let confirmed_while_held = a.base.test_confirmed_seq(id);
    let changed = std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, BaseEvent::ObjectsChanged(ids) if ids.contains(&id)))
        .count();
    let fetched_while_held = a.account.test_request_count(&fetch_path);
    let replied_early = flush.is_finished();
    assert_eq!(
        raw.post(
            &format!("{base_path}/release-change-reply"),
            serde_json::json!({})
        )
        .await
        .0,
        reqwest::StatusCode::OK
    );
    assert!(!replied_early, "change reply was not held");
    assert_eq!(confirmed_while_held, 0, "echo confirmed before the reply");
    assert_eq!(changed, 0, "own echo applied the local edit a second time");
    assert_eq!(fetched_while_held, before, "own echo fetched");
    flush.await.unwrap().unwrap();
    wait_for(|| a.base.test_confirmed_seq(id) > 0).await;
    assert_eq!(a.account.test_request_count(&fetch_path), before);
}
