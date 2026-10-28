//! Versions are kept only after local editing has paused.
use base64::Engine as _;
use bh_core::{
    AppRequest, BaseGrantRequest, Clock, Core, CoreConfig, FieldDef, FieldKind, FileSecretStore,
    Mode, NewFile, NewObject, TypeDef, TypeRef,
};
use bh_testkit::{
    append_text, device_with_clock, drop_next_reply, new_signup, note_with_text, raw_device,
    wait_for_base,
};
use reqwest::StatusCode;
use serde_json::{Map, Value};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use yrs::updates::decoder::Decode;
use yrs::{
    Any, GetString, ReadTxn, Text, Transact, WriteTxn, Xml, XmlElementPrelim, XmlFragment,
    XmlTextPrelim,
};

async fn marked(base: &bh_core::Base, manual: &bh_core::ManualClock, id: bh_core::ObjectId) -> u64 {
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    base.versions(id, None, 50).await.unwrap().0[0].seq
}

#[tokio::test]
async fn versions_list_newest_first_with_device_names() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "first");
    let first = marked(&base, &manual, id).await;
    manual.advance(Duration::from_secs(60 * 60));
    base.set_fields(
        id,
        Map::from_iter([("title".into(), Value::from("second"))]),
    )
    .unwrap();
    let second = marked(&base, &manual, id).await;
    let (rows, more) = base.versions(id, None, 1).await.unwrap();
    assert_eq!(rows[0].seq, second);
    assert_eq!(rows[0].device_name.as_deref(), Some("mac"));
    assert!(more);
    let (older, more) = base.versions(id, Some(second), 1).await.unwrap();
    assert_eq!(older[0].seq, first);
    assert!(!more);
}

#[tokio::test]
async fn versions_from_two_devices_have_local_names() {
    let (clock, manual) = Clock::manual();
    let a = device_with_clock("mac", &clock);
    let (owner, kit) = a.sign_up(new_signup()).await.unwrap();
    let base = owner.create_base("History").await.unwrap();
    base.flush().await.unwrap();
    let b = device_with_clock("fold", &clock);
    let other = b
        .sign_in(bh_testkit::signin_for(&owner))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    other.refresh().await.unwrap();
    let remote = other.base(base.id()).unwrap();
    let id = note_with_text(&base, "first");
    let first = marked(&base, &manual, id).await;
    wait_for_base(&remote, || remote.note(id).is_ok()).await;
    remote
        .set_fields(
            id,
            Map::from_iter([("title".into(), Value::from("fold's edit"))]),
        )
        .unwrap();
    let second = marked(&remote, &manual, id).await;
    assert_eq!(
        base.versions(id, None, 1).await.unwrap().0[0].device_name,
        None
    );
    owner.devices().await.unwrap(); // Refresh the decrypted device list, not server names.
    let (rows, _) = base.versions(id, None, 10).await.unwrap();
    assert_eq!(
        (rows[0].seq, rows[0].device_name.as_deref()),
        (second, Some("fold"))
    );
    assert_eq!(
        (rows[1].seq, rows[1].device_name.as_deref()),
        (first, Some("mac"))
    );
}

#[tokio::test]
async fn a_version_holds_its_content() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "Ferry at 9");
    let seq = marked(&base, &manual, id).await;
    let bytes = base.version(id, seq).await.unwrap();
    let doc = yrs::Doc::new();
    doc.transact_mut()
        .apply_update(yrs::Update::decode_v1(&bytes).unwrap())
        .unwrap();
    let txn = doc.transact();
    assert!(
        txn.get_xml_fragment("default")
            .unwrap()
            .get_string(&txn)
            .contains("Ferry at 9")
    );
}

#[tokio::test]
async fn restoring_is_undoable_and_syncs_to_other_devices() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "Ferry at 9");
    let first = marked(&base, &manual, id).await;
    let note = base.note(id).unwrap();
    note.apply(10, &append_text(&note.state(), "Ferry at 10"))
        .unwrap();
    base.flush().await.unwrap();
    let previous = note.text();
    base.restore_version(id, first).await.unwrap();
    base.flush().await.unwrap();
    assert_eq!(note.text(), "Ferry at 9");
    let current = base.versions(id, None, 1).await.unwrap().0[0].seq;
    assert!(current > first);
    assert!(base.version(id, current).await.is_ok());
    let other = bh_testkit::device_with_clock("fold", &clock)
        .sign_in(bh_testkit::signin_for(&account))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    other.refresh().await.unwrap();
    let remote = other.base(base.id()).unwrap();
    wait_for_base(&remote, || {
        remote.note(id).is_ok_and(|n| n.text() == "Ferry at 9")
    })
    .await;
    base.restore_version(id, current).await.unwrap();
    base.flush().await.unwrap();
    assert_eq!(note.text(), previous);
    wait_for_base(&remote, || {
        remote.note(id).is_ok_and(|n| n.text() == previous)
    })
    .await;
}

#[tokio::test]
async fn locked_during_version_fetch_returns_not_found() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account
        .create_hidden_base(
            "History",
            zeroize::Zeroizing::new("ferry lantern quartz".into()),
        )
        .await
        .unwrap();
    let id = note_with_text(&base, "old");
    let seq = marked(&base, &manual, id).await;
    let entered = base.test_hold_version_fetch();
    let fetching = tokio::spawn({
        let base = base.clone();
        async move { base.version(id, seq).await }
    });
    bh_testkit::wait_for(|| entered.load(Ordering::SeqCst)).await;
    account.lock_hidden(base.id()).await.unwrap();
    base.test_resume_version_fetch();
    assert_eq!(fetching.await.unwrap(), Err(bh_core::Error::NotFound));
}

#[tokio::test]
async fn locked_during_restore_fetch_returns_not_found() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account
        .create_hidden_base(
            "History",
            zeroize::Zeroizing::new("ferry lantern quartz".into()),
        )
        .await
        .unwrap();
    let id = note_with_text(&base, "old");
    let seq = marked(&base, &manual, id).await;
    let entered = base.test_hold_version_fetch();
    let fetching = tokio::spawn({
        let base = base.clone();
        async move { base.restore_version(id, seq).await }
    });
    bh_testkit::wait_for(|| entered.load(Ordering::SeqCst)).await;
    account.lock_hidden(base.id()).await.unwrap();
    base.test_resume_version_fetch();
    assert_eq!(fetching.await.unwrap(), Err(bh_core::Error::NotFound));
}

#[tokio::test]
async fn restoring_after_a_pause_does_not_duplicate_the_latest_version() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "old");
    let first = marked(&base, &manual, id).await;
    manual.advance(Duration::from_secs(60 * 60));
    base.set_fields(id, Map::from_iter([("title".into(), Value::from("new"))]))
        .unwrap();
    let latest = marked(&base, &manual, id).await;
    base.restore_version(id, first).await.unwrap();
    assert_eq!(base.versions(id, None, 2).await.unwrap().0[0].seq, latest);
}

#[tokio::test]
async fn restoring_a_note_with_a_link_does_not_duplicate_the_latest_version() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let entered = base.test_hold_version_tick();
    manual.advance(Duration::from_secs(60));
    bh_testkit::wait_for(|| entered.load(Ordering::SeqCst)).await;
    let id = note_with_text(&base, "old");
    let first = marked(&base, &manual, id).await;
    manual.advance(Duration::from_secs(60 * 60));
    let note = base.note(id).unwrap();
    let doc = yrs::Doc::new();
    let mut txn = doc.transact_mut();
    txn.apply_update(yrs::Update::decode_v1(&note.state()).unwrap())
        .unwrap();
    let before = txn.state_vector();
    let body = txn.get_or_insert_xml_fragment("default");
    let paragraph = body.push_back(&mut txn, XmlElementPrelim::empty("paragraph"));
    let text = paragraph.push_back(&mut txn, XmlTextPrelim::new(""));
    let link: yrs::types::Attrs = [(
        "link".into(),
        Any::Map(
            [
                ("href".into(), Any::String("https://example.com".into())),
                ("target".into(), Any::String("_blank".into())),
                ("rel".into(), Any::String("noopener noreferrer".into())),
                ("class".into(), Any::String("external".into())),
                ("title".into(), Any::String("Ticket".into())),
            ]
            .into_iter()
            .collect::<std::collections::HashMap<_, _>>()
            .into(),
        ),
    )]
    .into();
    text.insert_with_attributes(&mut txn, 0, "ticket", link);
    let update = txn.encode_state_as_update_v1(&before);
    drop(txn);
    note.apply(11, &update).unwrap();
    let latest = marked(&base, &manual, id).await;
    base.restore_version(id, first).await.unwrap();
    let (versions, _) = base.versions(id, None, 10).await.unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].seq, latest);
}

#[tokio::test]
async fn restore_keeps_an_edit_received_during_the_version_fetch() {
    let (clock, manual) = Clock::manual();
    let a = device_with_clock("mac", &clock);
    let (account, kit) = a.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "old");
    let first = marked(&base, &manual, id).await;
    let b = device_with_clock("fold", &clock);
    let other = b
        .sign_in(bh_testkit::signin_for(&account))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    other.refresh().await.unwrap();
    let remote = other.base(base.id()).unwrap();
    wait_for_base(&remote, || remote.note(id).is_ok()).await;
    let entered = base.test_hold_version_fetch();
    let restoring = tokio::spawn({
        let base = base.clone();
        async move { base.restore_version(id, first).await }
    });
    bh_testkit::wait_for(|| entered.load(Ordering::SeqCst)).await;
    let note = remote.note(id).unwrap();
    note.apply(10, &append_text(&note.state(), "remote edit"))
        .unwrap();
    remote.flush().await.unwrap();
    wait_for_base(&base, || {
        base.note(id)
            .is_ok_and(|n| n.text().contains("remote edit"))
    })
    .await;
    base.test_resume_version_fetch();
    restoring.await.unwrap().unwrap();
    let newest = base.versions(id, None, 1).await.unwrap().0[0].seq;
    let bytes = base.version(id, newest).await.unwrap();
    let doc = yrs::Doc::new();
    doc.transact_mut()
        .apply_update(yrs::Update::decode_v1(&bytes).unwrap())
        .unwrap();
    let txn = doc.transact();
    assert!(
        txn.get_xml_fragment("default")
            .unwrap()
            .get_string(&txn)
            .contains("remote edit")
    );
}

#[tokio::test]
async fn restore_keeps_the_note_where_it_is_and_notifies_open_editors() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "old");
    let first = marked(&base, &manual, id).await;
    let folder = base
        .create(NewObject {
            ty: TypeRef::new("core.folder", 1),
            parent: None,
            after: None,
            fields: Map::from_iter([("name".into(), Value::from("Trips"))]),
        })
        .unwrap();
    base.move_to(id, Some(folder), None).unwrap();
    let before = base.get(id).unwrap().unwrap();
    base.set_fields(id, Map::from_iter([("added".into(), Value::from("later"))]))
        .unwrap();
    let note = base.note(id).unwrap();
    let mut updates = note.subscribe();
    note.apply(10, &append_text(&note.state(), "new")).unwrap();
    let _ = updates.recv().await.unwrap();
    base.restore_version(id, first).await.unwrap();
    assert_eq!(updates.recv().await.unwrap().origin, u64::MAX);
    let after = base.get(id).unwrap().unwrap();
    assert_eq!(
        (after.parent, after.position, after.deleted),
        (before.parent, before.position, before.deleted)
    );
    assert!(!after.fields.contains_key("added"));
}

#[tokio::test]
async fn restore_keeps_formatting_and_images() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = base.create(bh_testkit::note()).unwrap();
    let note = base.note(id).unwrap();
    let doc = yrs::Doc::new();
    let mut txn = doc.transact_mut();
    txn.apply_update(yrs::Update::decode_v1(&note.state()).unwrap())
        .unwrap();
    let before = txn.state_vector();
    let body = txn.get_or_insert_xml_fragment("default");
    let heading = body.push_back(&mut txn, XmlElementPrelim::empty("heading"));
    heading.insert_attribute(&mut txn, "level", "2");
    let title = heading.push_back(&mut txn, XmlTextPrelim::new("Ferry "));
    let bold: yrs::types::Attrs = [("bold".into(), Any::Map(Default::default()))].into();
    title.insert_with_attributes(&mut txn, 6, "at 9", bold);
    let task = body.push_back(&mut txn, XmlElementPrelim::empty("taskItem"));
    task.insert_attribute(&mut txn, "checked", "true");
    let linked = task.push_back(&mut txn, XmlTextPrelim::new("See "));
    let link: yrs::types::Attrs = [("link".into(), Any::Map(Default::default()))].into();
    linked.insert_with_attributes(&mut txn, 4, "ticket", link);
    let image = body.push_back(&mut txn, XmlElementPrelim::empty("image"));
    image.insert_attribute(&mut txn, "file", "0123456789abcdef0123456789abcdef");
    let update = txn.encode_state_as_update_v1(&before);
    drop(txn);
    note.apply(11, &update).unwrap();
    let seq = marked(&base, &manual, id).await;
    let historical = base.version(id, seq).await.unwrap();
    let old = yrs::Doc::new();
    old.transact_mut()
        .apply_update(yrs::Update::decode_v1(&historical).unwrap())
        .unwrap();
    let expected = old
        .transact()
        .get_xml_fragment("default")
        .unwrap()
        .get_string(&old.transact());
    note.apply(10, &append_text(&note.state(), "later"))
        .unwrap();
    base.restore_version(id, seq).await.unwrap();
    let restored = yrs::Doc::new();
    restored
        .transact_mut()
        .apply_update(yrs::Update::decode_v1(&note.state()).unwrap())
        .unwrap();
    let txn = restored.transact();
    let fragment = txn.get_xml_fragment("default").unwrap();
    assert_eq!(fragment.get_string(&txn), expected);
    assert_eq!(fragment.len(&txn), 3);
    let yrs::XmlOut::Element(heading) = fragment.get(&txn, 0).unwrap() else {
        panic!("heading")
    };
    let yrs::XmlOut::Text(title) = heading.get(&txn, 0).unwrap() else {
        panic!("title")
    };
    assert!(
        title
            .diff(&txn, |_: yrs::types::text::YChange| ())
            .iter()
            .any(|chunk| chunk
                .attributes
                .as_deref()
                .is_some_and(|attrs| attrs.contains_key("bold")))
    );
    let yrs::XmlOut::Element(task) = fragment.get(&txn, 1).unwrap() else {
        panic!("task")
    };
    assert_eq!(
        task.get_attribute(&txn, "checked").unwrap().to_string(&txn),
        "true"
    );
    let yrs::XmlOut::Text(linked) = task.get(&txn, 0).unwrap() else {
        panic!("link")
    };
    assert!(
        linked
            .diff(&txn, |_: yrs::types::text::YChange| ())
            .iter()
            .any(|chunk| chunk
                .attributes
                .as_deref()
                .is_some_and(|attrs| attrs.contains_key("link")))
    );
    let yrs::XmlOut::Element(image) = fragment.get(&txn, 2).unwrap() else {
        panic!("image")
    };
    assert_eq!(
        image.get_attribute(&txn, "file").unwrap().to_string(&txn),
        "0123456789abcdef0123456789abcdef"
    );
}

#[tokio::test]
async fn a_read_only_base_cannot_restore() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "old");
    let seq = marked(&base, &manual, id).await;
    let credentials = account
        .connect_app(AppRequest {
            app_name: "Reader".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    let reader = app.base(base.id()).unwrap();
    assert_eq!(
        reader.versions(id, None, 1).await.unwrap().0[0].device_name,
        None
    );
    assert_eq!(
        reader.restore_version(id, seq).await,
        Err(bh_core::Error::ReadOnly)
    );
}

#[tokio::test]
async fn restore_needs_a_connection_and_does_not_change_text() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("mac", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("History").await.unwrap();
    let id = note_with_text(&base, "old");
    let first = marked(&base, &manual, id).await;
    let note = base.note(id).unwrap();
    note.apply(10, &append_text(&note.state(), "new")).unwrap();
    let before = note.text();
    base.test_pause_sync();
    assert!(matches!(
        base.restore_version(id, first).await,
        Err(bh_core::Error::Network(_))
    ));
    assert_eq!(note.text(), before);
    base.test_resume_sync();
}

async fn versions(
    account: &bh_core::Account,
    base: &bh_core::Base,
    id: bh_core::ObjectId,
) -> Vec<Value> {
    let (status, reply) = raw_device(account)
        .get(
            &format!("/v1/bases/{}/objects/{id}/versions", base.id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply["versions"].as_array().unwrap().clone()
}

#[tokio::test]
async fn a_pause_after_editing_marks_a_version() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "first edit");
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(4 * 60));
    base.tick_versions().await.unwrap();
    assert!(versions(&account, &base, id).await.is_empty());
    base.set_fields(
        id,
        Map::from_iter([("title".into(), Value::from("new edit"))]),
    )
    .unwrap();
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(2 * 60));
    base.tick_versions().await.unwrap();
    assert!(versions(&account, &base, id).await.is_empty());
    manual.advance(Duration::from_secs(4 * 60));
    base.tick_versions().await.unwrap();
    let listed = versions(&account, &base, id).await;
    assert_eq!(listed.len(), 1);
    let (status, body) = raw_device(&account)
        .get(
            &format!(
                "/v1/bases/{}/objects/{id}/versions/{}",
                base.id(),
                listed[0]["seq"].as_u64().unwrap()
            ),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sealed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body["body"].as_str().unwrap())
        .unwrap();
    assert!(
        !sealed
            .windows(b"first edit".len())
            .any(|b| b == b"first edit")
    );
    assert_eq!(
        base.test_open_kept_state(id, &sealed).unwrap(),
        base.note(id).unwrap().state()
    );
    assert!(
        base.test_open_kept_state(bh_core::ObjectId::random(), &sealed)
            .is_err()
    );
}

#[tokio::test]
async fn a_tick_during_reconnect_waits_for_live_catch_up() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (a, kit) = core.sign_up(new_signup()).await.unwrap();
    let base = a.create_base("Versions").await.unwrap();
    base.flush().await.unwrap();
    let other = bh_testkit::device("other")
        .sign_in(bh_testkit::signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    other.refresh().await.unwrap();
    let remote = other.base(base.id()).unwrap();
    wait_for_base(&remote, || remote.name() == "Versions").await;

    let id = note_with_text(&base, "local edit");
    base.flush().await.unwrap();
    drop_next_reply(&a, &base);
    base.set_fields(id, Map::from_iter([("title".into(), Value::from("local"))]))
        .unwrap();
    assert!(base.flush().await.is_err());
    base.test_hold_version_tick();
    manual.advance(Duration::from_secs(6 * 60));
    assert!(base.tick_versions().await.is_err());
    assert!(versions(&a, &base, id).await.is_empty());

    let remote_id = note_with_text(&remote, "during reconnect");
    remote.flush().await.unwrap();
    wait_for_base(&base, || base.note(remote_id).is_ok()).await;
}

#[tokio::test]
async fn an_edit_after_sealing_gets_its_own_version() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "initial");
    base.flush().await.unwrap();
    base.test_hold_version_tick();
    manual.advance(Duration::from_secs(6 * 60));
    let entered = base.test_hold_kept_reply();
    let tick_base = base.clone();
    let tick = tokio::spawn(async move { tick_base.tick_versions().await });
    bh_testkit::wait_for(|| entered.load(Ordering::SeqCst)).await;
    manual.advance(Duration::from_secs(60));
    base.set_fields(id, Map::from_iter([("title".into(), Value::from("later"))]))
        .unwrap();
    base.test_resume_kept_reply();
    tokio::time::timeout(Duration::from_secs(30), tick)
        .await
        .expect("kept reply did not resume")
        .unwrap()
        .unwrap();
    base.flush().await.unwrap();
    assert_eq!(versions(&account, &base, id).await.len(), 1);
    manual.advance(Duration::from_secs(60 * 60));
    base.tick_versions().await.unwrap();
    assert_eq!(versions(&account, &base, id).await.len(), 2);
}

#[tokio::test]
async fn a_retried_kept_send_does_not_create_a_second_version() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "initial");
    base.flush().await.unwrap();
    base.test_hold_version_tick();
    manual.advance(Duration::from_secs(6 * 60));
    drop_next_reply(&account, &base);
    assert!(base.tick_versions().await.is_err());
    let entered = base.test_hold_kept_reply();
    let flushing = base.clone();
    let flush = tokio::spawn(async move { flushing.flush().await });
    bh_testkit::wait_for(|| entered.load(Ordering::SeqCst)).await;
    let tick_base = base.clone();
    let tick = tokio::spawn(async move { tick_base.tick_versions().await });
    tokio::task::yield_now().await;
    base.test_resume_kept_reply();
    tokio::time::timeout(Duration::from_secs(30), async {
        flush.await.unwrap().unwrap();
        tick.await.unwrap().unwrap();
    })
    .await
    .expect("retry and tick did not complete");
    assert_eq!(versions(&account, &base, id).await.len(), 1);
}

#[tokio::test]
async fn versions_are_at_most_hourly_per_object_per_device() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "first edit");
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    assert_eq!(versions(&account, &base, id).await.len(), 1);
    manual.advance(Duration::from_secs(10 * 60));
    base.set_fields(id, Map::from_iter([("title".into(), Value::from("next"))]))
        .unwrap();
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(10 * 60));
    base.tick_versions().await.unwrap();
    assert_eq!(versions(&account, &base, id).await.len(), 1);
    manual.advance(Duration::from_secs(41 * 60));
    base.tick_versions().await.unwrap();
    assert_eq!(versions(&account, &base, id).await.len(), 2);
}

#[tokio::test]
async fn only_notes_folders_and_projects_get_versions() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let ids: Vec<_> = ["core.note", "core.folder", "core.project"]
        .into_iter()
        .map(|name| {
            base.create(NewObject {
                ty: TypeRef::new(name, 1),
                parent: None,
                after: None,
                fields: Map::new(),
            })
            .unwrap()
        })
        .collect();
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    for id in ids {
        assert_eq!(versions(&account, &base, id).await.len(), 1);
    }
    base.define_type(TypeDef {
        name: "demo.record".into(),
        version: 1,
        doc: String::new(),
        title_field: None,
        fields: vec![FieldDef {
            name: "value".into(),
            kind: FieldKind::Text,
            required: false,
            unit: None,
            doc: String::new(),
        }],
    })
    .unwrap();
    let record = base
        .create(NewObject {
            ty: TypeRef::new("demo.record", 1),
            parent: None,
            after: None,
            fields: Map::new(),
        })
        .unwrap();
    let file = base
        .add_file(
            NewFile {
                parent: None,
                name: "photo".into(),
                mime: "image/png".into(),
            },
            b"not an image",
        )
        .unwrap();
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    for id in [record, file] {
        assert!(versions(&account, &base, id).await.is_empty());
    }
}

#[tokio::test]
async fn edits_made_before_a_restart_still_get_a_version() {
    let (clock, manual) = Clock::manual();
    let tmp = tempfile::tempdir().unwrap();
    let open = || {
        Core::open_with_clock(
            CoreConfig {
                data_dir: tmp.path().join("data"),
                secrets: Arc::new(FileSecretStore::new(tmp.path().join("secrets")).unwrap()),
            },
            clock.clone(),
        )
        .unwrap()
    };
    // The server test bypass is needed by the locally spawned worker.
    let _ = device_with_clock("bypass", &clock);
    let core = open();
    core.set_test_device_name("versions");
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "before restart");
    base.flush().await.unwrap();
    let (account_id, base_id) = (account.id(), base.id());
    drop(base);
    drop(account);
    drop(core);
    let reopened = open();
    let account = reopened.account(account_id).unwrap();
    let base = account.base(base_id).unwrap();
    wait_for_base(&base, || base.sync_state().online).await;
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    assert_eq!(versions(&account, &base, id).await.len(), 1);
}

#[tokio::test]
async fn a_device_keeps_no_version_for_edits_it_only_received() {
    let (clock, manual) = Clock::manual();
    let (a, kit) = bh_testkit::device("a").sign_up(new_signup()).await.unwrap();
    let b = device_with_clock("b", &clock)
        .sign_in(bh_testkit::signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let remote = b.base(base.id()).unwrap();
    wait_for_base(&remote, || remote.name() == "Shared").await;
    let id = note_with_text(&base, "remote edit");
    base.flush().await.unwrap();
    wait_for_base(&remote, || remote.note(id).is_ok()).await;
    manual.advance(Duration::from_secs(6 * 60));
    remote.tick_versions().await.unwrap();
    assert!(versions(&b, &remote, id).await.is_empty());
}

#[tokio::test]
async fn versions_survive_later_compaction() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "initial");
    base.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    let first = versions(&account, &base, id).await[0]["seq"].clone();
    for i in 0..150 {
        base.set_fields(
            id,
            Map::from_iter([("title".into(), Value::from(format!("edit {i}")))]),
        )
        .unwrap();
        base.flush().await.unwrap();
    }
    let (status, stored) = raw_device(&account)
        .get(
            &format!("/v1/bases/{}/stored?object={id}", base.id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert!(
        stored["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "state" && c["keep"] == false)
    );
    assert!(
        versions(&account, &base, id)
            .await
            .iter()
            .any(|v| v["seq"] == first)
    );
}

#[tokio::test]
async fn a_newer_type_version_gets_no_version() {
    use yrs::{Doc, Map as _, Transact, WriteTxn};
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "original");
    base.flush().await.unwrap();
    let doc = Doc::new();
    let update = {
        let mut txn = doc.transact_mut();
        let meta = txn.get_or_insert_map("meta");
        meta.insert(&mut txn, "type", "core.note");
        meta.insert(&mut txn, "v", 2);
        txn.encode_update_v1()
    };
    let (status, reply) = raw_device(&account)
        .post(
            &format!("/v1/bases/{}/changes", base.id()),
            serde_json::json!({
                "changes": [{
                    "changeId": bh_testkit::random_id(), "objectId": id.to_string(),
                    "kind": "update", "body": bh_testkit::b64(&base.test_seal_update(id, &update))
                }]
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    wait_for_base(&base, || {
        matches!(base.note(id), Err(bh_core::Error::NeedsUpdate))
    })
    .await;
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    assert!(versions(&account, &base, id).await.is_empty());
}

#[tokio::test]
async fn a_version_after_compaction_with_a_remaining_tail_is_kept() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = note_with_text(&base, "before compaction");
    for i in 0..150 {
        base.set_fields(
            id,
            Map::from_iter([("title".into(), Value::from(format!("edit {i}")))]),
        )
        .unwrap();
        base.flush().await.unwrap();
    }
    manual.advance(Duration::from_secs(6 * 60));
    base.tick_versions().await.unwrap();
    assert_eq!(versions(&account, &base, id).await.len(), 1);
}

#[tokio::test]
async fn closing_a_base_awaits_the_version_tick() {
    let (clock, manual) = Clock::manual();
    let core = device_with_clock("versions", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account
        .create_hidden_base(
            "Private",
            zeroize::Zeroizing::new("ferry lantern quartz".into()),
        )
        .await
        .unwrap();
    let id = note_with_text(&base, "locked");
    base.flush().await.unwrap();
    let entered = base.test_hold_version_tick();
    manual.advance(Duration::from_secs(6 * 60));
    bh_testkit::wait_for(|| entered.load(Ordering::SeqCst)).await;
    tokio::time::timeout(Duration::from_secs(30), account.lock_hidden(base.id()))
        .await
        .expect("close did not stop the held version tick")
        .unwrap();
    assert!(versions(&account, &base, id).await.is_empty());
    let unlocked = account
        .unlock_hidden(zeroize::Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let reopened = account.base(unlocked[0].id).unwrap();
    wait_for_base(&reopened, || reopened.sync_state().online).await;
    reopened.tick_versions().await.unwrap();
    assert_eq!(versions(&account, &reopened, id).await.len(), 1);
}
