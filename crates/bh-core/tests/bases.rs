//! Bases in the core: creating, listing, opening and refreshing them.

use bh_core::{AccountEvent, Error, Mode};
use bh_testkit::{
    b64, device, new_signup, pending_device_for, random, random_id, raw_device, two_devices,
    wait_for_base,
};
use reqwest::StatusCode;
use serde_json::json;

#[tokio::test]
async fn a_second_device_of_the_account_opens_the_same_base() {
    let (a, b) = two_devices().await;
    let base = a.create_base("Travel").await.unwrap();
    b.refresh().await.unwrap();
    assert!(b.bases().iter().any(|s| s.id == base.id()));
    assert_eq!(b.base(base.id()).unwrap().mode(), Mode::ReadWrite); // the key unwrapped
}

#[tokio::test]
async fn a_new_bases_name_reaches_other_devices_when_its_handle_is_dropped_at_once() {
    let (a, b) = two_devices().await;
    // As the app's sign-up does: create the base and keep no handle to it.
    let id = a.create_base("Travel").await.unwrap().id();
    b.refresh().await.unwrap();
    let base = b.base(id).unwrap();
    wait_for_base(&base, || base.name() == "Travel").await;
}

#[tokio::test]
async fn other_accounts_and_pending_devices_are_refused() {
    let (a, _) = device("a").sign_up(new_signup()).await.unwrap();
    let base = a.create_base("Travel").await.unwrap();
    let path = format!("/v1/bases/{}/key", base.id());

    let (other, _) = device("other").sign_up(new_signup()).await.unwrap();
    let (status, body) = raw_device(&other).get(&path, json!({})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
    other.refresh().await.unwrap();
    assert!(other.bases().is_empty());
    assert_eq!(other.base(base.id()).unwrap_err(), Error::NotFound);

    let (status, body) = pending_device_for(&a).await.get(&path, json!({})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("pending"))
    );
}

#[tokio::test]
async fn a_base_is_one_open_handle_per_process_and_lists_with_its_name() {
    let (a, _) = device("a").sign_up(new_signup()).await.unwrap();
    let mut events = a.events();
    let base = a.create_base("  Travel ").await.unwrap();
    assert_eq!(events.recv().await.unwrap(), AccountEvent::BasesChanged);
    assert_eq!(base.name(), "Travel");
    let listed = a.bases();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].id, listed[0].name.as_str(), listed[0].mode),
        (base.id(), "Travel", Mode::ReadWrite)
    );
    // Both handles are one open base: they share each note's one document.
    let again = a.base(base.id()).unwrap();
    let id = again.create(bh_testkit::note()).unwrap();
    let window = base.note(id).unwrap();
    let mut updates = window.subscribe();
    again
        .note(id)
        .unwrap()
        .apply(9, &bh_testkit::insert_text("hi"))
        .unwrap();
    assert_eq!(updates.try_recv().unwrap().origin, 9);
    assert!(matches!(a.create_base(" ").await, Err(Error::Invalid(_))));
}

#[tokio::test]
async fn a_base_whose_key_this_device_cant_open_is_left_out() {
    let (a, _) = device("a").sign_up(new_signup()).await.unwrap();
    let id = random_id();
    // In the envelope format, but sealed under some other key.
    let mut wrapper = vec![1, 0, 0, 0, 1];
    wrapper.extend(random(72));
    let (status, body) = raw_device(&a)
        .post(
            "/v1/bases",
            json!({ "baseId": id, "epoch": 1, "wrapper": b64(&wrapper) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mine = a.create_base("Mine").await.unwrap();
    a.refresh().await.unwrap();
    let listed: Vec<_> = a.bases().iter().map(|s| (s.id, s.hidden)).collect();
    assert_eq!(listed, [(mine.id(), false)]);
    assert_eq!(a.base(id.parse().unwrap()).unwrap_err(), Error::NotFound);

    // A wrapper cached while still readable may stop opening on this device.
    let stored = mine.id();
    a.test_replace_base_wrapper(stored, wrapper).unwrap();
    assert!(a.bases().is_empty());
    assert_eq!(a.base(stored).unwrap_err(), Error::NotFound);
}

#[tokio::test]
async fn a_newer_wrapper_reports_update_after_opening_other_bases() {
    let (a, b) = two_devices().await;
    let id = random_id();
    let (status, body) = raw_device(&a)
        .post(
            "/v1/bases",
            json!({ "baseId": id, "epoch": 1, "wrapper": b64(&[2, 0, 0, 0, 1]) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let older = a.create_base("Readable").await.unwrap();
    assert_eq!(b.refresh().await, Err(Error::NeedsUpdate));
    assert!(b.bases().iter().any(|s| s.id == older.id()));
    assert_eq!(b.base(id.parse().unwrap()).unwrap_err(), Error::NotFound);
}
