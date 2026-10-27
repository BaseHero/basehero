//! End-to-end compaction against the local Worker.

use bh_core::{Base, Clock, Error, ObjectId};
use bh_testkit::{
    append_text, b64, device_with_clock, note_with_text, pause_sync, random_id, raw_device,
    resume_sync, two_devices, two_devices_sharing_a_base, wait_for_base,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;
use yrs::{Doc, Map, Transact, WriteTxn};

fn text(base: &Base, id: ObjectId) -> Option<String> {
    base.note(id).ok().map(|n| n.text())
}

async fn stored(raw: &bh_testkit::RawDevice, base: &Base, id: ObjectId) -> Vec<Value> {
    let (status, body) = raw
        .get(
            &format!("/v1/bases/{}/stored?object={id}", base.id()),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["changes"].as_array().unwrap().clone()
}

async fn edit_many(base: &Base, id: ObjectId, count: usize) {
    let doc = base.note(id).unwrap();
    for i in 0..count {
        doc.apply(5, &append_text(&doc.state(), &format!(" edit {i}")))
            .unwrap();
        base.flush().await.unwrap();
    }
}

#[tokio::test]
async fn compaction_keeps_content_and_drops_covered_updates() {
    let (account, kit) = bh_testkit::device("a")
        .sign_up(bh_testkit::new_signup())
        .await
        .unwrap();
    let base = account.create_base("Compact").await.unwrap();
    let id = note_with_text(&base, "first");
    edit_many(&base, id, 250).await;
    let changes = stored(&raw_device(&account), &base, id).await;
    assert_eq!(changes.iter().filter(|c| c["kind"] == "state").count(), 1);
    assert!(changes.iter().filter(|c| c["kind"] == "update").count() < 100);
    let fresh = bh_testkit::device("fresh")
        .sign_in(bh_testkit::signin_for(&account))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    fresh.refresh().await.unwrap();
    let other = fresh.base(base.id()).unwrap();
    wait_for_base(&other, || text(&other, id) == text(&base, id)).await;
    assert!(text(&other, id).unwrap().contains("edit 249"));
}

#[tokio::test]
async fn concurrent_compaction_is_harmless() {
    let (a, kit) = bh_testkit::device("a")
        .sign_up(bh_testkit::new_signup())
        .await
        .unwrap();
    let base = a.create_base("Concurrent").await.unwrap();
    let id = note_with_text(&base, "same state");
    base.flush().await.unwrap();
    let b = bh_testkit::device("b")
        .sign_in(bh_testkit::signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let other = b.base(base.id()).unwrap();
    wait_for_base(&other, || text(&other, id).is_some()).await;
    let raw_a = raw_device(&a);
    let raw_b = raw_device(&b);
    let path = format!("/v1/bases/{}/changes", base.id());
    let (status, fetched) = raw_a
        .post(
            &format!("/v1/bases/{}/fetch", base.id()),
            json!({"objectIds": [id.to_string()]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    let covers = fetched["objects"][0]["head"].as_u64().unwrap();
    let state_a = b64(&base.test_seal_state(id, &base.note(id).unwrap().state()));
    let state_b = b64(&other.test_seal_state(id, &other.note(id).unwrap().state()));
    let (x, y) = tokio::join!(
        raw_a.post(&path, json!({"changes": [{"changeId": random_id(), "objectId": id.to_string(), "kind": "state", "covers": covers, "body": state_a}]})),
        raw_b.post(&path, json!({"changes": [{"changeId": random_id(), "objectId": id.to_string(), "kind": "state", "covers": covers, "body": state_b}]})),
    );
    assert_eq!((x.0, y.0), (StatusCode::OK, StatusCode::OK));
    assert_ne!(x.1["results"][0]["stale"], y.1["results"][0]["stale"]);
    let changes = stored(&raw_a, &base, id).await;
    assert_eq!(changes.iter().filter(|c| c["kind"] == "state").count(), 1);
    let fresh = bh_testkit::device("fresh")
        .sign_in(bh_testkit::signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    fresh.refresh().await.unwrap();
    let fetched = fresh.base(base.id()).unwrap();
    wait_for_base(&fetched, || {
        text(&fetched, id).as_deref() == Some("same state")
    })
    .await;
    assert_eq!(text(&base, id), text(&other, id));
}

#[tokio::test]
async fn a_device_offline_through_compaction_keeps_its_edits() {
    let (a, c) = two_devices_sharing_a_base().await;
    let id = note_with_text(&a.base, "initial");
    a.base.flush().await.unwrap();
    wait_for_base(&c.base, || text(&c.base, id).is_some()).await;
    pause_sync(&c.base);
    let doc = c.base.note(id).unwrap();
    doc.apply(5, &append_text(&doc.state(), "offline c"))
        .unwrap();
    edit_many(&a.base, id, 300).await;
    assert!(
        stored(&raw_device(&a.account), &a.base, id)
            .await
            .iter()
            .any(|c| c["kind"] == "state")
    );
    resume_sync(&c.base);
    c.base.flush().await.unwrap();
    wait_for_base(&a.base, || text(&a.base, id) == text(&c.base, id)).await;
    let combined = text(&a.base, id).unwrap();
    assert!(combined.contains("offline c") && combined.contains("edit 299"));
}

#[tokio::test]
async fn a_kept_state_survives_later_compaction() {
    let (a, _) = two_devices_sharing_a_base().await;
    let id = note_with_text(&a.base, "kept");
    a.base.flush().await.unwrap();
    let raw = raw_device(&a.account);
    let (status, fetched) = raw
        .post(
            &format!("/v1/bases/{}/fetch", a.base.id()),
            json!({"objectIds": [id.to_string()]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    let covers = fetched["objects"][0]["head"].as_u64().unwrap();
    let body = b64(&a
        .base
        .test_seal_state(id, &a.base.note(id).unwrap().state()));
    let (status, response) = raw.post(&format!("/v1/bases/{}/changes", a.base.id()), json!({"changes": [{
        "changeId": random_id(), "objectId": id.to_string(), "kind": "state", "covers": covers, "keep": true, "body": body
    }]})).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let kept_seq = response["results"][0]["seq"].as_u64().unwrap();
    edit_many(&a.base, id, 250).await;
    let changes = stored(&raw, &a.base, id).await;
    assert!(
        changes
            .iter()
            .any(|c| c["seq"] == kept_seq && c["keep"] == true),
        "{changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| c["kind"] == "state" && c["seq"] != kept_seq)
    );
}

#[tokio::test]
async fn a_large_pending_tail_compacts_without_bypassing_background_throttle() {
    let (clock, manual) = Clock::manual();
    let (account, _) = device_with_clock("rate", &clock)
        .sign_up(bh_testkit::new_signup())
        .await
        .unwrap();
    let base = account.create_base("Rate").await.unwrap();
    let id = note_with_text(&base, "first");
    base.flush().await.unwrap();
    manual.advance(Duration::from_millis(500));
    let doc = base.note(id).unwrap();
    doc.apply(5, &append_text(&doc.state(), &"x".repeat(300 << 10)))
        .unwrap();
    wait_for_base(&base, || base.test_outbox().is_empty()).await;
    let raw = raw_device(&account);
    assert_eq!(
        stored(&raw, &base, id)
            .await
            .iter()
            .filter(|c| c["kind"] == "state")
            .count(),
        0
    );
    manual.advance(Duration::from_millis(499));
    assert_eq!(
        stored(&raw, &base, id)
            .await
            .iter()
            .filter(|c| c["kind"] == "state")
            .count(),
        0
    );
    let path = format!("v1/bases/{}/changes", base.id());
    let before = account.test_request_count(&path);
    manual.advance(Duration::from_millis(1));
    wait_for_base(&base, || account.test_request_count(&path) > before).await;
    assert_eq!(
        stored(&raw, &base, id)
            .await
            .iter()
            .filter(|c| c["kind"] == "state")
            .count(),
        1
    );
}

#[tokio::test]
async fn multiple_large_states_stay_within_the_request_limit() {
    let (a, _) = two_devices_sharing_a_base().await;
    let ids = [
        note_with_text(&a.base, "one"),
        note_with_text(&a.base, "two"),
    ];
    a.base.flush().await.unwrap();
    let raw = raw_device(&a.account);
    for id in ids {
        let doc = a.base.note(id).unwrap();
        let update = append_text(&doc.state(), &"x".repeat(5 << 20));
        let body = b64(&a.base.test_seal_update(id, &update));
        let (status, response) = raw.post(&format!("/v1/bases/{}/changes", a.base.id()),
            json!({"changes": [{"changeId": random_id(), "objectId": id.to_string(), "kind": "update", "body": body}]})).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        wait_for_base(&a.base, || a.base.note(id).unwrap().text().len() >= 5 << 20).await;
    }
    pause_sync(&a.base);
    for id in ids {
        let doc = a.base.note(id).unwrap();
        doc.apply(5, &append_text(&doc.state(), "small")).unwrap();
    }
    resume_sync(&a.base);
    tokio::time::timeout(Duration::from_secs(30), a.base.flush())
        .await
        .expect("compaction stalled")
        .unwrap();
    for id in ids {
        assert_eq!(
            stored(&raw, &a.base, id)
                .await
                .iter()
                .filter(|c| c["kind"] == "state")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn a_newer_type_version_is_never_compacted() {
    let (a, _) = two_devices().await;
    let base = a.create_base("Future").await.unwrap();
    base.flush().await.unwrap();
    let id = ObjectId::random();
    let source = Doc::new();
    let initial = {
        let mut txn = source.transact_mut();
        let meta = txn.get_or_insert_map("meta");
        meta.insert(&mut txn, "type", "core.note");
        meta.insert(&mut txn, "v", 2);
        txn.encode_update_v1()
    };
    let raw = raw_device(&a);
    let path = format!("/v1/bases/{}/changes", base.id());
    let body = b64(&base.test_seal_update(id, &initial));
    let changes: Vec<_> = (0..150)
        .map(|_| {
            json!({
                "changeId": random_id(), "objectId": id.to_string(), "kind": "update", "body": body
            })
        })
        .collect();
    let (status, response) = raw.post(&path, json!({"changes": changes})).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    wait_for_base(&base, || matches!(base.get(id), Err(Error::NeedsUpdate))).await;
    let other = note_with_text(&base, "ordinary");
    base.flush().await.unwrap();
    assert_eq!(
        stored(&raw, &base, id)
            .await
            .iter()
            .filter(|c| c["kind"] == "state")
            .count(),
        0
    );
    assert_eq!(stored(&raw, &base, id).await.len(), 150);
    assert_eq!(text(&base, other).as_deref(), Some("ordinary"));
}
