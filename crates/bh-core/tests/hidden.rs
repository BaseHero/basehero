//! Hidden base account lifecycle and sync, against a local encrypted server.
use bh_core::{
    AccountEvent, AppRequest, Base, BaseGrantRequest, Error, Mode, TypeDef, hero::HeroEvent,
};
use bh_models::testing::ScriptedModel;
use bh_testkit::{
    LocalServer, append_text, device, device_on_server, new_signup, note_with_text, raw_device,
    signin_for, wait_for,
};
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}
fn ids(list: Vec<bh_core::BaseSummary>) -> Vec<bh_core::BaseId> {
    list.into_iter().map(|s| s.id).collect()
}

async fn hidden_epoch(a: &bh_core::Account, server: &LocalServer, id: bh_core::BaseId) -> u64 {
    let response = reqwest::Client::new()
        .get(server.url().join(&format!("/v1/bases/{id}/key")).unwrap())
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(raw_device(a).token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    response.json::<serde_json::Value>().await.unwrap()["epoch"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn a_hidden_base_is_listed_only_while_unlocked() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra Diary", pw("ferry lantern quartz"))
        .await
        .unwrap();
    assert!(
        a.bases()
            .iter()
            .any(|s| s.id == h.id() && s.hidden && s.name == "Zebra Diary")
    );
    a.lock_hidden(h.id()).await.unwrap();
    assert!(a.bases().iter().all(|s| s.id != h.id()));
    assert!(matches!(a.base(h.id()), Err(Error::NotFound)));
    assert_eq!(
        ids(a.unlock_hidden(pw("ferry lantern quartz")).await.unwrap()),
        [h.id()]
    );
}

#[tokio::test]
async fn one_password_opens_every_base_made_with_it_and_no_other() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let p = "ferry lantern quartz";
    let h1 = a.create_hidden_base("A", pw(p)).await.unwrap();
    let h2 = a.create_hidden_base("B", pw(p)).await.unwrap();
    let h3 = a
        .create_hidden_base("C", pw("bamboo velvet ocean"))
        .await
        .unwrap();
    a.lock_all_hidden().await;
    let mut opened = ids(a.unlock_hidden(pw(p)).await.unwrap());
    opened.sort();
    let mut expected = vec![h1.id(), h2.id()];
    expected.sort();
    assert_eq!(opened, expected);
    assert_eq!(ids(a.unlock_hidden(pw(p)).await.unwrap()).len(), 2);
    assert!(!a.bases().iter().any(|s| s.id == h3.id()));
    assert_eq!(
        ids(a.unlock_hidden(pw("bamboo velvet ocean")).await.unwrap()),
        [h3.id()]
    );
    a.lock_hidden(h3.id()).await.unwrap();
    assert_eq!(a.bases().iter().filter(|s| s.hidden).count(), 2);
    assert_eq!(a.lock_hidden(h3.id()).await, Err(Error::NotFound));
}

#[tokio::test(flavor = "current_thread")]
async fn lock_all_waits_for_an_unlock_in_progress() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    let (release, entered) = a.test_hold_next_hidden_open();
    let account = a.clone();
    let unlock =
        tokio::spawn(async move { account.unlock_hidden(pw("ferry lantern quartz")).await });
    wait_for(|| entered.load(Ordering::SeqCst)).await;
    let account = a.clone();
    let lock_all = tokio::spawn(async move { account.lock_all_hidden().await });
    tokio::task::yield_now().await; // lock_all has queued behind the in-progress unlock
    release.add_permits(1);
    unlock.await.unwrap().unwrap();
    lock_all.await.unwrap();
    assert!(matches!(a.base(h.id()), Err(Error::NotFound)));
}

#[tokio::test(flavor = "current_thread")]
async fn sign_out_racing_unlock_does_not_leave_a_base_open() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    let (release, entered) = a.test_hold_next_hidden_open();
    let account = a.clone();
    let unlock =
        tokio::spawn(async move { account.unlock_hidden(pw("ferry lantern quartz")).await });
    wait_for(|| entered.load(Ordering::SeqCst)).await;
    let account = a.clone();
    let sign_out = tokio::spawn(async move { account.sign_out().await });
    tokio::task::yield_now().await;
    release.add_permits(1);
    let _ = unlock.await.unwrap();
    sign_out.await.unwrap().unwrap();
    assert!(matches!(a.base(h.id()), Err(Error::Revoked)));
    assert!(a.bases().iter().all(|s| s.id != h.id()));
}

#[tokio::test]
async fn lock_all_uses_one_flush_deadline_for_every_base() {
    // A time budget for the device's own work; over the internet to dev it can
    // overrun under load, and the server plays no part in it.
    bh_testkit::local_only!();
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let first = a
        .create_hidden_base("First", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let second = a
        .create_hidden_base("Second", pw("bamboo velvet ocean"))
        .await
        .unwrap();
    for base in [&first, &second] {
        base.test_pause_sync();
        note_with_text(base, "Pending");
    }
    let start = tokio::time::Instant::now();
    a.lock_all_hidden().await;
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "all bases share one two-second budget"
    );
    assert!(matches!(first.children(None), Err(Error::NotFound)));
    assert!(matches!(second.children(None), Err(Error::NotFound)));
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_a_lock_caller_still_closes_the_base() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    h.test_pause_sync();
    note_with_text(&h, "Unsent");
    let mut events = a.events();
    let account = a.clone();
    let id = h.id();
    let locking = tokio::spawn(async move { account.lock_hidden(id).await });
    assert_eq!(events.recv().await.unwrap(), AccountEvent::BasesChanged);
    locking.abort();
    tokio::time::timeout(Duration::from_secs(4), async {
        while !matches!(h.children(None), Err(Error::NotFound)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a cancelled caller must not leave a syncing base alive");
}

#[tokio::test]
async fn partial_unlock_still_announces_the_base_it_opened() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let core = bh_core::Core::open(bh_core::CoreConfig {
        data_dir: data_dir.clone(),
        secrets: Arc::new(bh_core::FileSecretStore::new(tmp.path().join("secrets")).unwrap()),
    })
    .unwrap();
    core.set_test_device_name("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let first = a
        .create_hidden_base("First", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let second = a
        .create_hidden_base("Second", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let (good, bad) = if first.id() < second.id() {
        (first, second)
    } else {
        (second, first)
    };
    a.lock_all_hidden().await;
    let store = data_dir
        .join("accounts")
        .join(a.id().to_string())
        .join("bases")
        .join(format!("{}.sqlite", bad.id()));
    std::fs::remove_file(&store).unwrap();
    std::fs::create_dir(&store).unwrap(); // second wrapper's store cannot open
    let mut events = a.events();
    assert!(a.unlock_hidden(pw("ferry lantern quartz")).await.is_err());
    assert!(a.bases().iter().any(|s| s.id == good.id()));
    assert!(matches!(a.base(bad.id()), Err(Error::NotFound)));
    assert_eq!(events.recv().await.unwrap(), AccountEvent::BasesChanged);
}

#[tokio::test]
async fn a_failed_first_open_does_not_announce_any_base() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let core = bh_core::Core::open(bh_core::CoreConfig {
        data_dir: data_dir.clone(),
        secrets: Arc::new(bh_core::FileSecretStore::new(tmp.path().join("secrets")).unwrap()),
    })
    .unwrap();
    core.set_test_device_name("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    let store = data_dir
        .join("accounts")
        .join(a.id().to_string())
        .join("bases")
        .join(format!("{}.sqlite", h.id()));
    std::fs::remove_file(&store).unwrap();
    std::fs::create_dir(&store).unwrap();
    let mut events = a.events();
    assert!(a.unlock_hidden(pw("ferry lantern quartz")).await.is_err());
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn a_wrong_password_unlocks_nothing_and_says_only_that() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    let requests = a.test_request_count("v1/");
    assert!(matches!(
        a.unlock_hidden(pw("ferry lantern quartx")).await,
        Err(Error::NothingUnlocked)
    ));
    assert_eq!(a.test_request_count("v1/"), requests);
    let (empty, _) = device("empty").sign_up(new_signup()).await.unwrap();
    let empty_requests = empty.test_request_count("v1/");
    assert!(matches!(
        empty.unlock_hidden(pw("ferry lantern quartx")).await,
        Err(Error::NothingUnlocked)
    ));
    assert_eq!(empty.test_request_count("v1/"), empty_requests);
}

#[tokio::test]
async fn another_device_unlocks_offline_after_one_refresh() {
    let mut server = LocalServer::start();
    let (a, kit) = device_on_server("a", &bh_core::Clock::system(), &server)
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            ..new_signup()
        })
        .await
        .unwrap();
    let b = device_on_server("b", &bh_core::Clock::system(), &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let id = note_with_text(&h, "Gelato with Marguerite");
    h.flush().await.unwrap();
    b.refresh().await.unwrap();
    server.stop();
    assert_eq!(
        ids(b.unlock_hidden(pw("ferry lantern quartz")).await.unwrap()),
        [h.id()]
    );
    assert_eq!(b.base(h.id()).unwrap().id(), h.id());
    server.restart();
    let other = b.base(h.id()).unwrap();
    wait_for(|| {
        other
            .note(id)
            .is_ok_and(|note| note.text() == "Gelato with Marguerite")
    })
    .await;
}

#[tokio::test]
async fn a_hidden_base_unlocked_offline_after_a_removal_opens_and_rekeys_online() {
    let mut server = LocalServer::start();
    let (a, kit) = device_on_server("a", &bh_core::Clock::system(), &server)
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            ..new_signup()
        })
        .await
        .unwrap();
    let b = device_on_server("b", &bh_core::Clock::system(), &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let c = device_on_server("c", &bh_core::Clock::system(), &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let h = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    let old = note_with_text(&h, "old");
    h.flush().await.unwrap();
    b.refresh().await.unwrap();
    b.unlock_hidden(pw("extra password")).await.unwrap();
    let from_b = b.base(h.id()).unwrap();
    wait_for(|| from_b.note(old).is_ok()).await;
    b.lock_hidden(h.id()).await.unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    a.remove_device(
        c.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(hidden_epoch(&a, &server, h.id()).await, 1);
    server.stop();
    assert_eq!(
        ids(b.unlock_hidden(pw("extra password")).await.unwrap()),
        [h.id()]
    );
    assert_eq!(b.base(h.id()).unwrap().note(old).unwrap().text(), "old");
    server.restart();
    let online = b.base(h.id()).unwrap();
    for _ in 0..20 {
        let _ = online.sync_now().await;
        if hidden_epoch(&a, &server, h.id()).await == 2 {
            break;
        }
    }
    assert_eq!(
        hidden_epoch(&a, &server, h.id()).await,
        2,
        "the open hidden base did not re-key after reconnecting"
    );
    let fresh = note_with_text(&b.base(h.id()).unwrap(), "fresh");
    b.base(h.id()).unwrap().flush().await.unwrap();
    b.lock_hidden(h.id()).await.unwrap();
    b.unlock_hidden(pw("extra password")).await.unwrap();
    assert_eq!(b.base(h.id()).unwrap().note(fresh).unwrap().text(), "fresh");
    a.unlock_hidden(pw("extra password")).await.unwrap();
    a.refresh().await.unwrap();
    let from_a = a.base(h.id()).unwrap();
    wait_for(|| from_a.note(old).is_ok() && from_a.note(fresh).is_ok()).await;
}

#[tokio::test]
async fn an_offline_hidden_edit_is_stored_only_at_the_new_epoch_after_removal() {
    use base64::Engine as _;
    let mut server = LocalServer::start();
    let (a, kit) = device_on_server("a", &bh_core::Clock::system(), &server)
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            ..new_signup()
        })
        .await
        .unwrap();
    let b = device_on_server("b", &bh_core::Clock::system(), &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let c = device_on_server("c", &bh_core::Clock::system(), &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let diary = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    diary.flush().await.unwrap();
    a.lock_hidden(diary.id()).await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    c.refresh().await.unwrap();
    c.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(hidden_epoch(&c, &server, diary.id()).await, 1);
    server.stop();
    a.unlock_hidden(pw("extra password")).await.unwrap();
    let reopened = a.base(diary.id()).unwrap();
    let edit = note_with_text(&reopened, "written after removal while offline");
    assert!(
        reopened.sync_state().pending > 0,
        "edit must be queued before reconnect"
    );
    reopened.test_pause_sync();
    let old_body = reopened.test_seal_update(edit, b"probe");
    assert_eq!(u32::from_be_bytes(old_body[1..5].try_into().unwrap()), 1);
    server.restart();
    let refused = reqwest::Client::new()
        .post(
            server
                .url()
                .join(&format!("/v1/bases/{}/changes", diary.id()))
                .unwrap(),
        )
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(raw_device(&c).token)
        .json(&serde_json::json!({"changes": [{
            "changeId": bh_testkit::random_id(), "objectId": edit.to_string(),
            "kind": "update", "body": bh_testkit::b64(&old_body)
        }]}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::CONFLICT);
    assert_eq!(
        refused.json::<serde_json::Value>().await.unwrap()["error"],
        "rekey_needed"
    );
    reopened.test_resume_sync();
    for _ in 0..20 {
        let _ = reopened.sync_now().await;
        if hidden_epoch(&c, &server, diary.id()).await == 2 && reopened.sync_state().pending == 0 {
            break;
        }
    }
    assert_eq!(
        hidden_epoch(&c, &server, diary.id()).await,
        2,
        "no automatic re-key after the server refused the old-epoch send; rekey requests {}, key requests {}",
        a.test_request_count(&format!("v1/bases/{}/rekey", diary.id())),
        a.test_request_count(&format!("v1/bases/{}/key", diary.id()))
    );
    assert_eq!(
        reopened.sync_state().pending,
        0,
        "queued edit was not resent at the new epoch"
    );
    reopened.flush().await.unwrap();
    let response: serde_json::Value = reqwest::Client::new()
        .post(
            server
                .url()
                .join(&format!("/v1/bases/{}/fetch", diary.id()))
                .unwrap(),
        )
        .header("BH-Protocol", "2")
        .header("BH-Test-Bypass", server.operator_token())
        .bearer_auth(raw_device(&c).token)
        .json(&serde_json::json!({"objectIds": [edit.to_string()]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let object = &response["objects"][0];
    let mut bodies: Vec<&str> = object["updates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|update| update["body"].as_str().unwrap())
        .collect();
    if let Some(state) = object["state"]["body"].as_str() {
        bodies.push(state);
    }
    assert!(!bodies.is_empty(), "server must hold the post-removal edit");
    for body in bodies {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(bytes[1..5].try_into().unwrap()),
            2,
            "server accepted an old-epoch edit after removal"
        );
    }
    assert_eq!(
        reopened.note(edit).unwrap().text(),
        "written after removal while offline"
    );
    c.unlock_hidden(pw("extra password")).await.unwrap();
    let other = c.base(diary.id()).unwrap();
    wait_for(|| {
        other
            .note(edit)
            .is_ok_and(|note| note.text() == "written after removal while offline")
    })
    .await;
}

#[tokio::test]
async fn repeated_refusals_start_only_one_hidden_rekey() {
    let (a, b) = bh_testkit::two_devices().await;
    let base = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    base.flush().await.unwrap();
    a.lock_hidden(base.id()).await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    let (release, entered) = a.test_hold_hidden_rekey(base.id());
    a.unlock_hidden(pw("extra password")).await.unwrap();
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    let open = a.base(base.id()).unwrap();
    note_with_text(&open, "waiting for new key");
    let path = format!("v1/bases/{}/changes", base.id());
    for _ in 0..4 {
        let before = a.test_request_count(&path);
        let _ = open.sync_now().await;
        assert!(
            a.test_request_count(&path) > before,
            "each refusal must reach the fence"
        );
    }
    // Let all waiting re-keys proceed. Only one request may have started.
    release.add_permits(32);
    for _ in 0..20 {
        let _ = open.sync_now().await;
        if open.sync_state().pending == 0 {
            break;
        }
    }
    open.flush().await.unwrap();
    assert_eq!(
        entered.available_permits(),
        0,
        "a second re-key entered while the first was held"
    );
    assert_eq!(
        a.test_request_count(&format!("v1/bases/{}/rekey", base.id())),
        1
    );
}

#[tokio::test]
async fn locking_aborts_a_hidden_rekey_before_it_is_sent() {
    let (a, b) = bh_testkit::two_devices().await;
    let base = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    base.flush().await.unwrap();
    a.lock_hidden(base.id()).await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    let (release, entered) = a.test_hold_hidden_rekey(base.id());
    a.unlock_hidden(pw("extra password")).await.unwrap();
    bh_testkit::wait_entered(&entered, std::panic::Location::caller()).await;
    let path = format!("v1/bases/{}/rekey", base.id());
    a.lock_hidden(base.id()).await.unwrap();
    release.add_permits(1);
    assert_eq!(
        a.test_request_count(&path),
        0,
        "a locked base sent a re-key"
    );
    a.refresh().await.unwrap();
    assert_eq!(
        a.test_request_count(&path),
        0,
        "a locked base retried its re-key"
    );
}

#[tokio::test]
async fn a_quick_reunlock_rekeys_while_the_canceled_task_still_holds_its_marker() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = device("c")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let diary = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    diary.flush().await.unwrap();
    a.lock_hidden(diary.id()).await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    c.refresh().await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    let (release_send, entered_send) = a.test_hold_hidden_rekey(diary.id());
    let (release_cancel, entered_cancel) = a.test_hold_canceled_hidden_rekey(diary.id());
    a.unlock_hidden(pw("extra password")).await.unwrap();
    bh_testkit::wait_entered(&entered_send, std::panic::Location::caller()).await;
    a.lock_hidden(diary.id()).await.unwrap();
    // Old task has not dropped its guard.
    bh_testkit::wait_entered(&entered_cancel, std::panic::Location::caller()).await;
    a.unlock_hidden(pw("extra password")).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), entered_send.acquire())
        .await
        .expect("new re-key did not start while the old guard was retained")
        .unwrap()
        .forget(); // New task must start before old guard drops.
    let open = a.base(diary.id()).unwrap();
    let note = note_with_text(&open, "after re-unlock");
    release_cancel.add_permits(1); // Old guard drops while the new task is still held.
    let changes = format!("v1/bases/{}/changes", diary.id());
    for _ in 0..3 {
        let before = a.test_request_count(&changes);
        let _ = open.sync_now().await;
        assert!(a.test_request_count(&changes) > before);
    }
    assert_eq!(
        entered_send.available_permits(),
        0,
        "the old guard removed the new task's marker"
    );
    release_send.add_permits(1);
    for _ in 0..20 {
        if hidden_epoch(&a, LocalServer::from_env(), diary.id()).await == 2 {
            break;
        }
        let _ = open.sync_now().await;
    }
    assert_eq!(
        hidden_epoch(&a, LocalServer::from_env(), diary.id()).await,
        2
    );
    assert_eq!(
        a.test_request_count(&format!("v1/bases/{}/rekey", diary.id())),
        1
    );
    open.flush().await.unwrap();
    c.refresh().await.unwrap();
    c.unlock_hidden(pw("extra password")).await.unwrap();
    let other = c.base(diary.id()).unwrap();
    wait_for(|| {
        other
            .note(note)
            .is_ok_and(|item| item.text() == "after re-unlock")
    })
    .await;
    assert_eq!(open.note(note).unwrap().text(), "after re-unlock");
}

#[tokio::test]
async fn a_quick_reunlock_adopts_a_hidden_rekey_committed_before_its_reply() {
    let (a, b) = bh_testkit::two_devices().await;
    let kit = a.recovery_kit().unwrap().unwrap();
    let c = device("c")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let diary = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    let before = note_with_text(&diary, "before");
    diary.flush().await.unwrap();
    a.lock_hidden(diary.id()).await.unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    c.refresh().await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    let (release_reply, entered_reply) = a.test_hold_next_hidden_rekey_reply();
    let (release_cancel, entered_cancel) = a.test_hold_canceled_hidden_rekey(diary.id());
    a.unlock_hidden(pw("extra password")).await.unwrap();
    // Server has committed epoch 2.
    bh_testkit::wait_entered(&entered_reply, std::panic::Location::caller()).await;
    assert_eq!(
        hidden_epoch(&a, LocalServer::from_env(), diary.id()).await,
        2
    );
    a.lock_hidden(diary.id()).await.unwrap();
    bh_testkit::wait_entered(&entered_cancel, std::panic::Location::caller()).await;
    a.unlock_hidden(pw("extra password")).await.unwrap();
    let open = a.base(diary.id()).unwrap();
    for _ in 0..20 {
        let _ = open.sync_now().await;
        if open.note(before).is_ok() && open.sync_state().online {
            break;
        }
    }
    assert_eq!(open.note(before).unwrap().text(), "before");
    let after = note_with_text(&open, "after committed reply");
    open.flush().await.unwrap();
    assert_eq!(
        hidden_epoch(&a, LocalServer::from_env(), diary.id()).await,
        2
    );
    assert_eq!(
        a.test_request_count(&format!("v1/bases/{}/rekey", diary.id())),
        1
    );
    c.refresh().await.unwrap();
    c.unlock_hidden(pw("extra password")).await.unwrap();
    let other = c.base(diary.id()).unwrap();
    wait_for(|| other.note(before).is_ok() && other.note(after).is_ok()).await;
    assert_eq!(open.note(after).unwrap().text(), "after committed reply");
    release_cancel.add_permits(1);
    release_reply.add_permits(1);
}

#[tokio::test]
async fn a_hidden_base_open_during_the_removal_rekeys_without_relocking() {
    let (a, b) = bh_testkit::two_devices().await;
    let h = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    a.refresh().await.unwrap();
    b.refresh().await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    a.refresh().await.unwrap();
    assert_eq!(hidden_epoch(&a, LocalServer::from_env(), h.id()).await, 2);
    let note = note_with_text(&h, "after removal");
    h.flush().await.unwrap();
    assert_eq!(h.note(note).unwrap().text(), "after removal");
}

#[tokio::test]
async fn a_wrong_extra_password_opens_nothing_after_rotation() {
    let (a, b) = bh_testkit::two_devices().await;
    let h = a
        .create_hidden_base("Diary", pw("extra password"))
        .await
        .unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: pw(bh_testkit::TEST_PASSWORD),
            lost: false,
        },
    )
    .await
    .unwrap();
    a.unlock_hidden(pw("extra password")).await.unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    assert!(matches!(
        a.unlock_hidden(pw("wrong password")).await,
        Err(Error::NothingUnlocked)
    ));
}

#[tokio::test]
async fn refresh_catches_up_an_unlocked_hidden_base() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    h.flush().await.unwrap();
    let since = format!("v1/bases/{}/since", h.id());
    let previous = a.test_request_count(&since);
    a.refresh().await.unwrap();
    wait_for(|| a.test_request_count(&since) > previous).await;
}

#[tokio::test]
async fn lock_sends_waiting_edits_first() {
    let (a, kit) = device("a").sign_up(new_signup()).await.unwrap();
    let b = device("b")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let id = note_with_text(&h, "Gelato");
    a.lock_hidden(h.id()).await.unwrap();
    b.refresh().await.unwrap();
    let other = b.unlock_hidden(pw("ferry lantern quartz")).await.unwrap();
    assert_eq!(ids(other), [h.id()]);
    let bh = b.base(h.id()).unwrap();
    wait_for(|| bh.note(id).is_ok_and(|n| n.text() == "Gelato")).await;
}

#[tokio::test]
async fn offline_edits_wait_for_the_next_unlock() {
    let (a, kit) = device("a").sign_up(new_signup()).await.unwrap();
    let b = device("b")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    h.test_pause_sync();
    let id = note_with_text(&h, "Gelato");
    a.lock_hidden(h.id()).await.unwrap();
    let path = format!("v1/bases/{}/", h.id());
    let after_lock = a.test_request_count(&path);
    h.test_resume_sync();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(a.test_request_count(&path), after_lock);
    b.refresh().await.unwrap();
    let bh = b.unlock_hidden(pw("ferry lantern quartz")).await.unwrap();
    assert_eq!(ids(bh), [h.id()]);
    assert!(b.base(h.id()).unwrap().note(id).is_err());
    a.unlock_hidden(pw("ferry lantern quartz")).await.unwrap();
    let other = b.base(h.id()).unwrap();
    wait_for(|| other.note(id).is_ok_and(|n| n.text() == "Gelato")).await;
}

#[tokio::test]
async fn locking_ends_every_handle_and_open_document() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let id = note_with_text(&h, "Gelato");
    let doc = h.note(id).unwrap();
    let mut updates = doc.subscribe();
    let mut events = h.events();
    let clone: Base = h.clone();
    a.lock_hidden(h.id()).await.unwrap();
    assert!(matches!(clone.children(None), Err(Error::NotFound)));
    assert_eq!(
        doc.apply(4, &bh_testkit::insert_text("more")),
        Err(Error::NotFound)
    );
    assert_eq!(doc.text(), "");
    assert_eq!(doc.title(), "");
    assert!(matches!(
        updates.recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Closed)
    ));
    while events.try_recv().is_ok() {}
    assert!(matches!(
        events.recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Closed)
    ));
}

#[tokio::test]
async fn a_racing_read_never_panics_during_lock() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let concurrent = h.clone();
    let reader = tokio::task::spawn_blocking(move || {
        for _ in 0..10000 {
            if concurrent.children(None) == Err(Error::NotFound) {
                return;
            }
        }
    });
    a.lock_hidden(h.id()).await.unwrap();
    reader.await.expect("fallible read must not panic");
}

#[tokio::test]
async fn create_unlock_and_lock_announce_bases_changed() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut events = a.events();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    assert_eq!(events.recv().await.unwrap(), AccountEvent::BasesChanged);
    a.lock_hidden(h.id()).await.unwrap();
    assert_eq!(events.recv().await.unwrap(), AccountEvent::BasesChanged);
    assert!(matches!(
        a.unlock_hidden(pw("wrong")).await,
        Err(Error::NothingUnlocked)
    ));
    assert!(events.try_recv().is_err());
    a.unlock_hidden(pw("ferry lantern quartz")).await.unwrap();
    assert_eq!(events.recv().await.unwrap(), AccountEvent::BasesChanged);
}

#[tokio::test]
async fn a_hidden_base_syncs_only_while_unlocked() {
    let (a, kit) = device("a").sign_up(new_signup()).await.unwrap();
    let b = device("b")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let id = note_with_text(&h, "Start");
    h.flush().await.unwrap();
    b.refresh().await.unwrap();
    b.unlock_hidden(pw("ferry lantern quartz")).await.unwrap();
    let other = b.base(h.id()).unwrap();
    wait_for(|| other.note(id).is_ok_and(|n| n.text() == "Start")).await;
    b.lock_hidden(h.id()).await.unwrap();
    let raw = raw_device(&a);
    let (_, count) = raw
        .get(
            &format!("/v1/bases/{}/live-count", h.id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(count["count"], 1); // a's socket remains, b's is gone
    let paths: Vec<_> = ["since", "fetch", "changes", "live"]
        .iter()
        .map(|end| format!("v1/bases/{}/{end}", h.id()))
        .collect();
    let before: Vec<_> = paths.iter().map(|p| b.test_request_count(p)).collect();
    let note = h.note(id).unwrap();
    for n in 0..5 {
        note.apply(5, &append_text(&note.state(), &format!("Edit {n}")))
            .unwrap();
    }
    h.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        paths
            .iter()
            .map(|p| b.test_request_count(p))
            .collect::<Vec<_>>(),
        before
    );
    b.unlock_hidden(pw("ferry lantern quartz")).await.unwrap();
    let opened = b.base(h.id()).unwrap();
    wait_for(|| opened.note(id).is_ok_and(|n| n.text().contains("Edit 4"))).await;
}

#[tokio::test]
async fn locking_awaits_background_work() {
    let (a, _) = device("a").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    h.flush().await.unwrap();
    let path = format!("/v1/bases/{}/live-count", h.id());
    let raw = raw_device(&a);
    let (_, count) = raw.get(&path, serde_json::json!({})).await;
    assert_eq!(count["count"], 1);
    a.lock_hidden(h.id()).await.unwrap();
    assert!(!h.sync_state().online);
    // The local socket is dropped when lock returns. The server observes the
    // TCP close on its own scheduler, which can lag the immediate GET.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let (_, count) = raw.get(&path, serde_json::json!({})).await;
            if count["count"] == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the server must observe the closed live socket");
}

#[tokio::test]
async fn an_unlocked_hidden_base_cannot_register_an_app() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let before = a.test_request_count("v1/devices");
    let grant = || AppRequest {
        app_name: "Test".into(),
        app_id: None,
        bases: vec![BaseGrantRequest::Existing {
            base: h.id(),
            mode: Mode::ReadOnly,
        }],
        replaces: None,
    };
    assert!(matches!(
        a.connect_app(grant()).await,
        Err(Error::Forbidden)
    ));
    assert_eq!(a.test_request_count("v1/devices"), before);
    a.lock_hidden(h.id()).await.unwrap();
    assert!(matches!(
        a.connect_app(grant()).await,
        Err(Error::Forbidden)
    ));
    assert_eq!(a.test_request_count("v1/devices"), before);
}

#[tokio::test]
async fn defining_a_type_on_a_closed_base_returns_not_found() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    let def = TypeDef {
        name: "demo.trip".into(),
        version: 1,
        doc: String::new(),
        title_field: None,
        fields: vec![],
    };
    assert_eq!(h.define_type(def), Err(Error::NotFound));
}

#[tokio::test]
async fn hero_resubscribes_to_chats_after_a_hidden_base_is_reopened() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let h = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let hero = a.hero_with_model(ScriptedModel::new(vec![]));
    hero.chats(h.id()).unwrap(); // starts the first base-event watcher
    a.lock_hidden(h.id()).await.unwrap();
    a.unlock_hidden(pw("ferry lantern quartz")).await.unwrap();
    hero.chats(h.id()).unwrap(); // must watch the reopened store even if old watcher is exiting
    let mut events = hero.events();
    let chat = a
        .base(h.id())
        .unwrap()
        .create(bh_core::NewObject {
            ty: bh_core::TypeRef::new("core.chat", 1),
            parent: None,
            after: None,
            fields: serde_json::Map::from_iter([("title".into(), serde_json::json!("New chat"))]),
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let HeroEvent::Changed {
                base,
                chat: changed,
            } = events.recv().await.unwrap()
                && base == h.id()
                && changed == chat
            {
                break;
            }
        }
    })
    .await
    .expect("Hero must announce chat changes after reopening");
}

#[tokio::test]
async fn app_devices_cannot_create_or_unlock() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let ordinary = a.create_base("Ordinary").await.unwrap();
    let creds = a
        .connect_app(AppRequest {
            app_name: "Test".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: ordinary.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = device("app").install_app(creds).await.unwrap();
    assert!(matches!(
        app.create_hidden_base("Zebra", pw("password")).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        app.unlock_hidden(pw("password")).await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn creating_needs_the_network_a_name_and_a_password() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    assert!(matches!(
        a.create_hidden_base("", pw("password")).await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        a.create_hidden_base("Name", pw("")).await,
        Err(Error::Invalid(_))
    ));
    // A local-only server can be stopped without touching the shared test server.
    let mut server = LocalServer::start();
    let (offline, _) = device_on_server("offline", &bh_core::Clock::system(), &server)
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            ..new_signup()
        })
        .await
        .unwrap();
    server.stop();
    assert!(matches!(
        offline.create_hidden_base("Name", pw("password")).await,
        Err(Error::Network(_))
    ));
}

#[tokio::test]
async fn the_server_cannot_tell_a_hidden_base_from_an_ordinary_one() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let ordinary = a.create_base("Personal").await.unwrap();
    let hidden = a
        .create_hidden_base("Zebra", pw("ferry lantern quartz"))
        .await
        .unwrap();
    let raw = raw_device(&a);
    let (_, h) = raw
        .get(
            &format!("/v1/bases/{}/key", hidden.id()),
            serde_json::json!({}),
        )
        .await;
    let (_, p) = raw
        .get(
            &format!("/v1/bases/{}/key", ordinary.id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(
        h.as_object().unwrap().keys().collect::<Vec<_>>(),
        p.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    assert_eq!(bh_testkit::unb64(&h["wrapper"]).len(), 77);
    assert_eq!(bh_testkit::unb64(&p["wrapper"]).len(), 77);
    let (_, account) = raw.get("/v1/account", serde_json::json!({})).await;
    assert!(
        account["bases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &hidden.id().to_string())
    );
    assert!(
        account["bases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == &ordinary.id().to_string())
    );
}
