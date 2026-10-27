//! Sync: the outbox, catch-up and the client invariant.

use bh_core::{Base, BaseEvent, Clock, Error, ObjectId};
use bh_testkit::{
    LocalServer, append_text, b64, device_with_clock, drop_next_reply, found_under, insert_text,
    local_only, note, note_with_text, pause_sync, random, random_id, raw_device, resume_sync,
    two_devices, two_devices_sharing_a_base, wait_for_base,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;
use yrs::{Doc, Map, Transact, WriteTxn};

fn text_of(base: &Base, id: bh_core::ObjectId) -> Option<String> {
    base.note(id).ok().map(|n| n.text())
}

/// The server's head for an object, read through `device`.
async fn server_head(device: &bh_testkit::RawDevice, base: &Base, id: bh_core::ObjectId) -> u64 {
    let (status, body) = device
        .post(
            &format!("/v1/bases/{}/fetch", base.id()),
            json!({ "objectIds": [id.to_string()] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["objects"][0]["head"].as_u64().unwrap()
}

/// The changes the server stores for an object (a test-only view).
async fn stored(device: &bh_testkit::RawDevice, base: &Base, id: bh_core::ObjectId) -> Vec<Value> {
    let (status, body) = device
        .get(
            &format!("/v1/bases/{}/stored?object={id}", base.id()),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["changes"].as_array().unwrap().clone()
}

#[tokio::test]
async fn an_edit_on_one_device_appears_on_another() {
    let (a, b) = two_devices_sharing_a_base().await;
    let id = note_with_text(&a.base, "Pack the tripod");
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        text_of(&b.base, id).as_deref() == Some("Pack the tripod")
    })
    .await;
}

#[tokio::test]
async fn a_new_base_reaches_another_device_with_its_name() {
    let (a, b) = two_devices().await;
    let base = a.create_base("Travel").await.unwrap();
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let other = b.base(base.id()).expect("open base");
    wait_for_base(&other, || other.name() == "Travel").await;
}

#[tokio::test]
async fn base_names_never_reach_the_server_in_readable_form() {
    local_only!();
    let (a, _) = two_devices().await;
    let base = a.create_base("Zebra Holiday Plans").await.unwrap();
    base.flush().await.unwrap();
    let dir = LocalServer::from_env().persist_dir();
    assert!(!found_under(dir, b"Zebra Holiday Plans"));
}

#[tokio::test]
async fn a_change_that_fails_to_apply_is_set_aside() {
    let (a, b) = two_devices_sharing_a_base().await;
    let (status, body) = raw_device(&a.account)
        .post(
            &format!("/v1/bases/{}/changes", a.base.id()),
            json!({ "changes": [{
                "changeId": random_id(), "objectId": random_id(), "kind": "update",
                "body": b64(&[vec![1], random(63)].concat()),
            }] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = note_with_text(&a.base, "After the garbage");
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        text_of(&b.base, id).as_deref() == Some("After the garbage")
    })
    .await;
    let set_aside = b.base.test_set_aside();
    assert_eq!(set_aside.len(), 1, "{set_aside:?}");
}

#[tokio::test]
async fn a_lost_reply_resends_the_identical_change() {
    let (a, b) = two_devices_sharing_a_base().await;
    pause_sync(&a.base);
    let id = note_with_text(&a.base, "Only once");
    drop_next_reply(&a.account, &a.base);
    resume_sync(&a.base);
    // The first send's reply is lost; flushing again resends the same change.
    let _ = a.base.flush().await;
    a.base.flush().await.unwrap();
    let raw = raw_device(&a.account);
    assert_eq!(stored(&raw, &a.base, id).await.len(), 1);
    wait_for_base(&b.base, || {
        text_of(&b.base, id).as_deref() == Some("Only once")
    })
    .await;
    assert!(a.base.test_outbox().is_empty());
}

#[tokio::test]
async fn an_interleaved_write_never_advances_confirmed_seq_past_a_missed_change() {
    let (a, b) = two_devices_sharing_a_base().await;
    let raw = raw_device(&a.account);
    let id = note_with_text(&a.base, "First");
    a.base.flush().await.unwrap();
    let before = server_head(&raw, &a.base, id).await;
    wait_for_base(&b.base, || b.base.test_confirmed_seq(id) == before).await;
    pause_sync(&b.base);
    let state = a.base.note(id).unwrap().state();
    a.base
        .note(id)
        .unwrap()
        .apply(5, &append_text(&state, "From a"))
        .unwrap();
    a.base.flush().await.unwrap();
    let state = b.base.note(id).unwrap().state();
    b.base
        .note(id)
        .unwrap()
        .apply(5, &append_text(&state, "From b"))
        .unwrap();
    // b's own post comes back with a's change as its prevHead, so b fetches.
    resume_sync(&b.base);
    b.base.flush().await.unwrap();
    let head = server_head(&raw, &a.base, id).await;
    assert_eq!(head, before + 2);
    wait_for_base(&b.base, || b.base.test_confirmed_seq(id) == head).await;
    let text = text_of(&b.base, id).unwrap();
    assert!(text.contains("From a") && text.contains("From b"), "{text}");
}

#[tokio::test]
async fn offline_edits_on_two_devices_converge() {
    let (a, b) = two_devices_sharing_a_base().await;
    let id = note_with_text(&a.base, "Start");
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || text_of(&b.base, id).is_some()).await;
    pause_sync(&a.base);
    pause_sync(&b.base);
    for (device, text) in [(&a, "Offline on a"), (&b, "Offline on b")] {
        let doc = device.base.note(id).unwrap();
        doc.apply(5, &append_text(&doc.state(), text)).unwrap();
    }
    resume_sync(&a.base);
    resume_sync(&b.base);
    a.base.flush().await.unwrap();
    b.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        let (x, y) = (text_of(&a.base, id).unwrap(), text_of(&b.base, id).unwrap());
        x == y && x.contains("Offline on a") && x.contains("Offline on b")
    })
    .await;
}

#[tokio::test]
async fn a_retried_batch_is_not_duplicated() {
    let (a, b) = two_devices_sharing_a_base().await;
    let id = a.base.create(note()).unwrap();
    a.base.flush().await.unwrap();
    let body = a.base.test_seal_update(id, &insert_text("Said once"));
    let request = json!({ "changes": [{
        "changeId": random_id(), "objectId": id.to_string(), "kind": "update", "body": b64(&body),
    }] });
    let raw = raw_device(&a.account);
    let path = format!("/v1/bases/{}/changes", a.base.id());
    let (first, one) = raw.post(&path, request.clone()).await;
    let (second, two) = raw.post(&path, request).await;
    assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
    assert_eq!(one["results"][0]["seq"], two["results"][0]["seq"]);
    wait_for_base(&b.base, || {
        text_of(&b.base, id).as_deref() == Some("Said once")
    })
    .await;
    wait_for_base(&a.base, || {
        text_of(&a.base, id).as_deref() == Some("Said once")
    })
    .await;
}

#[tokio::test]
async fn a_new_device_fetches_states_and_tails_not_history() {
    let (a, b) = two_devices_sharing_a_base().await;
    let id = note_with_text(&a.base, "Edit 0");
    let doc = a.base.note(id).unwrap();
    for i in 1..300 {
        doc.apply(5, &append_text(&doc.state(), &format!("Edit {i}")))
            .unwrap();
        a.base.flush().await.unwrap();
    }
    let (status, body) = raw_device(&b.account)
        .post(
            &format!("/v1/bases/{}/fetch", a.base.id()),
            json!({ "objectIds": [id.to_string()] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let object = &body["objects"][0];
    assert!(object["state"].is_object(), "{object}");
    assert!(object["updates"].as_array().unwrap().len() < 100);
}

#[tokio::test]
async fn the_server_stores_only_ciphertext() {
    local_only!();
    let (a, b) = two_devices_sharing_a_base().await;
    let id = note_with_text(&a.base, "Secret ferry times");
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        text_of(&b.base, id).as_deref() == Some("Secret ferry times")
    })
    .await;
    let dir = LocalServer::from_env().persist_dir();
    assert!(!found_under(dir, b"Secret ferry times"));
}

#[tokio::test]
async fn a_change_over_8_mib_is_refused() {
    let (a, _) = two_devices().await;
    let base = a.create_base("Big").await.unwrap();
    base.flush().await.unwrap();
    let (status, body) = raw_device(&a)
        .post(
            &format!("/v1/bases/{}/changes", base.id()),
            json!({ "changes": [{
                "changeId": random_id(), "objectId": random_id(), "kind": "update",
                "body": b64(&vec![7; (8 << 20) + 1]),
            }] }),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "too_large");
}

#[tokio::test]
async fn a_large_outbox_goes_in_batches_within_the_request_limits() {
    let (a, b) = two_devices_sharing_a_base().await;
    pause_sync(&a.base);
    // More objects than one request holds.
    let ids: Vec<_> = (0..1001).map(|_| a.base.create(note()).unwrap()).collect();
    // Edits to one object larger together than one request holds.
    let big = note_with_text(&a.base, "Big");
    let doc = a.base.note(big).unwrap();
    for letter in ["x", "y", "z"] {
        doc.apply(5, &append_text(&doc.state(), &letter.repeat(3 << 20)))
            .unwrap();
    }
    resume_sync(&a.base);
    a.base.flush().await.unwrap();
    assert!(a.base.test_outbox().is_empty());
    assert!(stored(&raw_device(&a.account), &a.base, big).await.len() >= 2);
    wait_for_base(&b.base, || {
        ids.iter().all(|id| b.base.get(*id).unwrap().is_some())
    })
    .await;
    wait_for_base(&b.base, || {
        text_of(&b.base, big).is_some_and(|t| t.len() == 3 + 3 * (3 << 20) + 3)
    })
    .await;
}

#[tokio::test]
async fn successive_background_batches_throttle_each_object_on_the_manual_clock() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("rate", &clock);
    let (account, _) = core.sign_up(bh_testkit::new_signup()).await.unwrap();
    let base = account.create_base("Rate").await.unwrap();
    let id = note_with_text(&base, "First");
    base.flush().await.unwrap();
    let path = format!("v1/bases/{}/changes", base.id());
    let sent = account.test_request_count(&path);
    let stored_before = stored(&raw_device(&account), &base, id).await.len();
    let doc = base.note(id).unwrap();
    doc.apply(5, &append_text(&doc.state(), "Second")).unwrap();
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(account.test_request_count(&path), sent);
    manual.advance(Duration::from_millis(499));
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(account.test_request_count(&path), sent);
    manual.advance(Duration::from_millis(1));
    wait_for_base(&base, || base.test_outbox().is_empty()).await;
    assert_eq!(account.test_request_count(&path), sent + 1);
    assert_eq!(
        stored(&raw_device(&account), &base, id).await.len(),
        stored_before + 1
    );
}

#[tokio::test]
async fn refresh_does_not_send_before_the_interval() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("refresh-rate", &clock);
    let (account, _) = core.sign_up(bh_testkit::new_signup()).await.unwrap();
    let base = account.create_base("Rate").await.unwrap();
    let id = note_with_text(&base, "First");
    base.flush().await.unwrap();
    let path = format!("v1/bases/{}/changes", base.id());
    let sent = account.test_request_count(&path);
    let doc = base.note(id).unwrap();
    doc.apply(5, &append_text(&doc.state(), "Second")).unwrap();
    account.refresh().await.unwrap();
    assert_eq!(account.test_request_count(&path), sent);
    assert_eq!(base.test_outbox().len(), 1);
    manual.advance(Duration::from_millis(500));
    wait_for_base(&base, || base.test_outbox().is_empty()).await;
    assert_eq!(account.test_request_count(&path), sent + 1);
}

#[tokio::test]
async fn a_newer_object_does_not_block_catch_up_or_sending() {
    let (a, b) = two_devices_sharing_a_base().await;
    pause_sync(&b.base);
    let first = note_with_text(&a.base, "Before future");
    a.base.flush().await.unwrap();
    let newer = ObjectId::random();
    let source = Doc::new();
    let newer_type = {
        let mut txn = source.transact_mut();
        let meta = txn.get_or_insert_map("meta");
        meta.insert(&mut txn, "type", "core.note");
        meta.insert(&mut txn, "v", 2);
        txn.encode_update_v1()
    };
    let future = a.base.test_seal_update(newer, &newer_type);
    let raw = raw_device(&a.account);
    let (status, body) = raw
        .post(
            &format!("/v1/bases/{}/changes", a.base.id()),
            json!({ "changes": [{ "changeId": random_id(), "objectId": newer.to_string(),
            "kind": "update", "body": b64(&future) }] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let future_head = server_head(&raw, &a.base, newer).await;
    let last = note_with_text(&a.base, "After future");
    a.base.flush().await.unwrap();
    let mut events = b.base.events();
    resume_sync(&b.base);
    wait_for_base(&b.base, || {
        text_of(&b.base, first).as_deref() == Some("Before future")
            && text_of(&b.base, last).as_deref() == Some("After future")
            && b.base.test_future_bodies(newer) == [future.clone()]
    })
    .await;
    let mut saw_update = false;
    while let Ok(event) = events.try_recv() {
        saw_update |= format!("{event:?}") == "NeedsUpdate";
    }
    assert!(saw_update, "no NeedsUpdate event");
    assert_eq!(b.base.test_future_bodies(newer), [future]);
    assert!(matches!(b.base.get(newer), Err(Error::NeedsUpdate)));
    assert!(matches!(b.base.note(newer), Err(Error::NeedsUpdate)));
    assert!(matches!(
        b.base.set_fields(newer, Default::default()),
        Err(Error::NeedsUpdate)
    ));
    let next = note_with_text(&b.base, "Sent despite future");
    b.base.flush().await.unwrap();
    wait_for_base(&a.base, || {
        text_of(&a.base, next).as_deref() == Some("Sent despite future")
    })
    .await;
    assert_eq!(server_head(&raw, &a.base, newer).await, future_head);
    assert_eq!(stored(&raw, &a.base, newer).await.len(), 1);
}

#[tokio::test]
async fn dropping_the_last_base_handle_stops_polling() {
    let (account, _) = bh_testkit::device("drop")
        .sign_up(bh_testkit::new_signup())
        .await
        .unwrap();
    let base = account.create_base("Short lived").await.unwrap();
    base.flush().await.unwrap();
    let path = format!("v1/bases/{}/since", base.id());
    wait_for_base(&base, || account.test_request_count(&path) > 0).await;
    drop(base);
    let at_drop = account.test_request_count(&path);
    // Give the old once-a-second poll two opportunities to expose a leak.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(account.test_request_count(&path), at_drop);
}

#[tokio::test]
async fn sync_state_counts_waiting_changes_and_events_report_them() {
    let (a, _) = two_devices_sharing_a_base().await;
    let mut events = a.base.events();
    pause_sync(&a.base);
    let id = note_with_text(&a.base, "Waiting");
    assert_eq!(a.base.sync_state().pending, 1);
    loop {
        if let BaseEvent::ObjectsChanged(ids) = events.recv().await.unwrap() {
            assert_eq!(ids, [id]);
            break;
        }
    }
    resume_sync(&a.base);
    a.base.flush().await.unwrap();
    let state = a.base.sync_state();
    assert_eq!(state.pending, 0);
    assert!(state.online && state.last_synced_at.is_some());
}
