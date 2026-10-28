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
    tokio::time::timeout(Duration::from_secs(2), async {
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
