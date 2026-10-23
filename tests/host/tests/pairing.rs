//! Pairing between two hosts over the in-process hosted environment (the
//! real authorization service with labelled synthetic attestation, a fake
//! edge and relay), and, opt-in, over the real local stack. Each device is
//! the host's own account registry, signer and sync with a labelled
//! software key store (`test_support`) in place of a platform's.
#![cfg(feature = "synthetic-attestation")]
#[path = "../../sync-client/tests/support/fake.rs"]
mod fake;

use bh_device::ContainerId;
use bh_host::{
    accounts::{AccountOperation, Screen, SharedAccountHost, fresh_test_host, ready_test_host},
    pairing::{PairingHost, Refusal, Scope},
    sync::{Configured, HostSigner, StatusView, StatusWindows, SyncHost},
    test_support::{FakeStore, PlainProtector},
};
use bh_sync_client::{Appraisal, Endpoint, Signer};
use fake::Hosted;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

type Host = SharedAccountHost<FakeStore, PlainProtector>;

#[derive(Default)]
struct Seen {
    posts: Mutex<Vec<StatusView>>,
    wakes: Mutex<Vec<String>>,
}
impl StatusWindows for Seen {
    fn post_status(&self, _: ContainerId, view: &StatusView) {
        self.posts.lock().unwrap().push(view.clone());
    }
    fn wake_delivery(&self, window: String) {
        self.wakes.lock().unwrap().push(window);
    }
    fn authority_ended(&self, _: ContainerId, _: Vec<String>) {}
}
impl Seen {
    fn state(&self) -> Option<&'static str> {
        self.posts.lock().unwrap().last().map(|view| view.state)
    }
}

fn endpoint(hosted: &Hosted) -> Endpoint {
    Endpoint {
        edge_url: "http://edge.invalid".into(),
        hosting_root: hosted.edge.root(),
        app_root: hosted.policy_root.public(),
        policy: Vec::new(),
        policy_signature: Vec::new(),
        limits: bh_confidential_policy::Limits {
            max_lifetime_secs: 86_400,
            max_uncertainty_secs: 0,
        },
        build_floor: 1,
        appraisal: Appraisal::Synthetic,
        device_clock: std::sync::Arc::new(bh_sync_client::SystemDeviceClock),
        recovery_key: hosted.edge.recovery_certificate(),
    }
}

async fn until(seconds: u64, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One device: its container owner, account registry and sync.
struct Device {
    _dir: tempfile::TempDir,
    owner: Arc<bh_device::Owner>,
    host: Host,
    store: FakeStore,
    sync: SyncHost,
    seen: Arc<Seen>,
}
impl Device {
    fn sync(owner: &Arc<bh_device::Owner>, hosted: &Arc<Hosted>) -> SyncHost {
        SyncHost::with_transport(
            Configured::Ready(endpoint(hosted)),
            owner.clone(),
            hosted.connector(),
            hosted.relay(),
        )
    }
    /// The account's first device, signed up, its notes open in `main`.
    async fn mac(hosted: &Arc<Hosted>) -> Self {
        Self::mac_with(|owner| Self::sync(owner, hosted)).await
    }
    async fn mac_with(sync: impl Fn(&Arc<bh_device::Owner>) -> SyncHost) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::gated();
        let host = ready_test_host(&owner, dir.path(), store.clone()).await;
        let device = Self {
            sync: sync(&owner),
            _dir: dir,
            owner,
            host,
            store,
            seen: Arc::default(),
        };
        device.open().await;
        device
    }
    /// A device with no account yet, at its first-run screen.
    async fn fold(hosted: &Arc<Hosted>) -> Self {
        Self::fold_with(|owner| Self::sync(owner, hosted)).await
    }
    async fn fold_with(sync: impl Fn(&Arc<bh_device::Owner>) -> SyncHost) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let (host, screen) = fresh_test_host(&owner, dir.path(), store.clone()).await;
        assert_eq!(screen, bh_host::accounts::Screen::Welcome);
        Self {
            sync: sync(&owner),
            _dir: dir,
            owner,
            host,
            store,
            seen: Arc::default(),
        }
    }
    fn id(&self) -> ContainerId {
        self.host.ready_authority().unwrap().0
    }
    /// As account_open_note: authorize notes, start sync.
    async fn open(&self) {
        let (id, cap, base) = self.host.note_authority().unwrap();
        self.owner.authorize(id, cap, base).unwrap();
        self.sync
            .ensure_started(&self.host, id, self.seen.clone())
            .await;
    }
    fn scope(&self, window: &str, page: u64) -> Scope {
        Scope {
            window: window.into(),
            page: Some(page),
            container: Some(self.id()),
        }
    }
    /// Save one paragraph in `note` (or the home note), shown in `window`.
    fn save(&self, window: &str, note: Option<[u8; 32]>, text: &str, request: u8) -> [u8; 32] {
        let id = self.id();
        match note {
            Some(note) => self.owner.show_note(window, id, note).unwrap(),
            None => drop(self.owner.open_home(window, id).unwrap()),
        }
        let note = self.owner.bound_note(window).unwrap();
        // As the editor does, a save that lost its writer to a concurrent
        // accepted apply reopens the note and saves again.
        for attempt in 0..5 {
            let opened = self.owner.open_leased(window, note).unwrap();
            let lease = opened.writer.unwrap();
            let mut author = bh_device::Owner::core_author(&opened).unwrap();
            let delta = author.try_append_paragraph(text).unwrap();
            let request = [request, attempt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            match self
                .owner
                .commit_leased(window, opened.generation, lease.token, request, &delta)
            {
                Ok(_) => break,
                Err(error) if attempt == 4 => panic!("save failed: {error:?}"),
                Err(_) => {}
            }
        }
        self.sync.wake(id);
        note
    }
    fn text(&self, window: &str, note: [u8; 32]) -> Vec<u8> {
        self.owner.show_note(window, self.id(), note).unwrap();
        let opened = self.owner.open_leased(window, note).unwrap();
        bh_device::Owner::core_author(&opened)
            .unwrap()
            .state()
            .unwrap()
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// The real local stack through this build's own endpoint (built from
/// `BH_SYNC_ENDPOINT` with synthetic attestation): no fake transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs local-stack.test.sh: the local stack and its endpoint file"]
async fn local_stack_pairs_bootstraps_and_syncs_both_ways() {
    // The stack's endpoint file, read as an app build reads its own.
    let dir = std::env::var("LOCAL_STACK_DIR").expect("LOCAL_STACK_DIR");
    let text = std::fs::read_to_string(format!("{dir}/endpoint.json")).unwrap();
    let built = |owner: &Arc<bh_device::Owner>| {
        let configured = Configured::from_text(&text);
        assert!(
            matches!(configured, Configured::Ready(_)),
            "the stack's endpoint, with synthetic attestation"
        );
        SyncHost::new(configured, owner.clone())
    };
    let mac = Device::mac_with(built).await;
    let note = mac.save("main", None, "from the mac", 1);
    until(120, "mac synced", || mac.seen.state() == Some("synced")).await;
    until(120, "mac home stored", || {
        mac.seen
            .posts
            .lock()
            .unwrap()
            .last()
            .is_some_and(|v| v.home == Some("done"))
    })
    .await;
    let fold = Device::fold_with(built).await;
    let pairing = PairingHost::default();
    let shown = pairing.show(mac.scope("main", 1), &mac.sync).unwrap();
    let ticket = pairing
        .join(
            "main",
            &fold.host,
            &fold.sync,
            &shown.qr_text,
            b"Local stack phone".to_vec(),
        )
        .unwrap();
    let status = |p: &PairingHost| p.status(&mac.scope("main", 1), &shown.session).unwrap();
    until(120, "candidate", || status(&pairing).state == "candidate").await;
    let prompts = mac.store.prompts();
    pairing
        .approve(&mac.scope("main", 1), &shown.session)
        .unwrap();
    until(180, "ordered", || status(&pairing).state == "ordered").await;
    until(180, "fold ready", || {
        pairing.join_status("main", &ticket.ticket).unwrap().state == "ready"
    })
    .await;
    until(180, "mac copied", || mac.seen.state() == Some("synced")).await;
    assert_eq!(mac.store.prompts(), prompts + 1, "one confirmation");
    fold.open().await;
    assert!(contains(&fold.text("fold-main", note), "from the mac"));
    fold.save("fold-main", Some(note), "from the fold", 1);
    until(180, "fold synced", || fold.seen.state() == Some("synced")).await;
    until(180, "mac woken", || {
        mac.seen.wakes.lock().unwrap().contains(&"main".into())
    })
    .await;
    let text = mac.text("main", note);
    assert!(contains(&text, "from the mac") && contains(&text, "from the fold"));
    mac.sync.shutdown_all().await;
    fold.sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mac_shows_a_fold_joins_and_both_keep_writing_the_same_note() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    let note = mac.save("main", None, "from the mac", 1);
    until(60, "mac synced", || mac.seen.state() == Some("synced")).await;

    let fold = Device::fold(&hosted).await;
    let pairing = PairingHost::default();
    let shown = pairing.show(mac.scope("main", 1), &mac.sync).unwrap();
    assert_eq!(shown.qr_text.len(), 167);
    assert!(shown.qr_svg.starts_with("<svg"));
    let ticket = pairing
        .join(
            "main",
            &fold.host,
            &fold.sync,
            &shown.qr_text,
            b"Test phone".to_vec(),
        )
        .unwrap();
    assert_eq!(
        pairing
            .join(
                "main",
                &fold.host,
                &fold.sync,
                &shown.qr_text,
                b"Test phone".to_vec()
            )
            .unwrap()
            .ticket,
        ticket.ticket,
        "a second submission follows the same join"
    );
    let status = |p: &PairingHost| p.status(&mac.scope("main", 1), &shown.session).unwrap();
    until(30, "candidate", || status(&pairing).state == "candidate").await;
    assert_eq!(status(&pairing).label.as_deref(), Some("Test phone"));
    assert_eq!(
        pairing.join_status("main", &ticket.ticket).unwrap().state,
        "waiting-approval"
    );
    let prompts = mac.store.prompts();
    assert_eq!(
        pairing
            .approve(&mac.scope("main", 1), &shown.session)
            .unwrap()
            .state,
        "approving"
    );
    until(60, "ordered", || status(&pairing).state == "ordered").await;
    until(90, "fold ready", || {
        pairing.join_status("main", &ticket.ticket).unwrap().state == "ready"
    })
    .await;
    let joined = pairing.join_status("main", &ticket.ticket).unwrap();
    assert!(joined.total.is_some_and(|total| total >= 1));
    // The Mac copies the addition into the base under the same one
    // confirmation: no second prompt.
    until(60, "mac copied and synced", || {
        mac.seen.state() == Some("synced")
    })
    .await;
    assert_eq!(mac.store.prompts(), prompts + 1, "one confirmation in all");

    // The Fold is a usable account: its notes open and sync.
    fold.open().await;
    assert!(contains(&fold.text("fold-main", note), "from the mac"));
    fold.save("fold-main", Some(note), "from the fold", 1);
    until(60, "fold synced", || fold.seen.state() == Some("synced")).await;
    // The Mac's open window is woken after the commit, through the
    // delivery dispatcher, and the note has both edits.
    until(60, "mac woken", || {
        mac.seen.wakes.lock().unwrap().contains(&"main".into())
    })
    .await;
    let text = mac.text("main", note);
    assert!(contains(&text, "from the mac") && contains(&text, "from the fold"));
    mac.sync.shutdown_all().await;
    fold.sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_belongs_to_its_window_page_and_account() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    let pairing = PairingHost::default();
    let shown = pairing.show(mac.scope("main", 7), &mac.sync).unwrap();
    let session = shown.session.as_str();
    assert_eq!(
        pairing
            .status(&mac.scope("main", 7), session)
            .unwrap()
            .state,
        "waiting"
    );
    assert!(
        pairing.status(&mac.scope("note-2", 7), session).is_err(),
        "other window"
    );
    assert!(
        pairing.status(&mac.scope("main", 8), session).is_err(),
        "reloaded page"
    );
    let other_account = Scope {
        container: Some(ContainerId([9; 16])),
        ..mac.scope("main", 7)
    };
    assert!(
        pairing.status(&other_account, session).is_err(),
        "other account"
    );
    // A code is shown only for the scope's own account's client.
    assert_eq!(
        pairing.show(other_account.clone(), &mac.sync).err(),
        Some(Refusal::Unavailable)
    );
    assert_eq!(
        pairing
            .show(
                Scope {
                    page: None,
                    ..mac.scope("main", 7)
                },
                &mac.sync
            )
            .err(),
        Some(Refusal::Unavailable)
    );
    assert!(pairing.approve(&mac.scope("note-2", 7), session).is_err());
    assert!(pairing.cancel(&mac.scope("note-2", 7), session).is_err());
    assert!(
        pairing
            .status(&mac.scope("main", 7), "not-a-session")
            .is_err()
    );
    // A join ticket is not a showing session, nor from another window.
    assert!(pairing.join_status("main", session).is_err());
    // The page going away ends the session it showed.
    pairing.window_gone("main");
    assert!(pairing.status(&mac.scope("main", 7), session).is_err());
    mac.sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_before_approval_adds_nothing() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    let fold = Device::fold(&hosted).await;
    let pairing = PairingHost::default();
    let shown = pairing.show(mac.scope("main", 1), &mac.sync).unwrap();
    pairing
        .join(
            "main",
            &fold.host,
            &fold.sync,
            &shown.qr_text,
            b"Test phone".to_vec(),
        )
        .unwrap();
    let scope = mac.scope("main", 1);
    until(30, "candidate", || {
        pairing.status(&scope, &shown.session).unwrap().state == "candidate"
    })
    .await;
    let prompts = mac.store.prompts();
    assert_eq!(
        pairing.cancel(&scope, &shown.session).unwrap().state,
        "cancelled"
    );
    assert!(
        pairing
            .approve(&scope, &shown.session)
            .is_ok_and(|s| s.state == "cancelled")
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(mac.store.prompts(), prompts, "nothing to confirm");
    let signer = HostSigner::start(mac.host.clone(), mac.id()).await.unwrap();
    assert!(signer.staged_addition().unwrap().is_none());
    assert_eq!(signer.current_account().unwrap().head().position, 3);
    mac.sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joining_is_refused_on_a_device_that_has_an_account() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    let pairing = PairingHost::default();
    let text = format!("BH1:{}", "A".repeat(163));
    assert!(
        pairing
            .join("main", &mac.host, &mac.sync, &text, b"x".to_vec())
            .is_err()
    );
    let fold = Device::fold(&hosted).await;
    assert!(
        pairing
            .join("main", &fold.host, &fold.sync, "not a code", b"x".to_vec())
            .is_err(),
        "an unreadable code"
    );
    let local = SyncHost::new(Configured::Missing, fold.owner.clone());
    let shown = pairing.show(mac.scope("main", 1), &mac.sync).unwrap();
    assert!(
        pairing
            .join("main", &fold.host, &local, &shown.qr_text, b"x".to_vec())
            .is_err(),
        "no sync in this build"
    );
    mac.sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupted_bootstrap_resumes_after_a_restart() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    long_history(&mac, &hosted).await;
    let fold = Device::fold(&hosted).await;
    let pairing = PairingHost::default();
    let shown = pairing.show(mac.scope("main", 1), &mac.sync).unwrap();
    // The base's history past its first read is not served for now.
    hosted.edge.hold_reads_after(Some(64));
    let ticket = pairing
        .join(
            "main",
            &fold.host,
            &fold.sync,
            &shown.qr_text,
            b"Test phone".to_vec(),
        )
        .unwrap();
    let scope = mac.scope("main", 1);
    until(30, "candidate", || {
        pairing.status(&scope, &shown.session).unwrap().state == "candidate"
    })
    .await;
    pairing.approve(&scope, &shown.session).unwrap();
    until(90, "bootstrapping", || {
        pairing.join_status("main", &ticket.ticket).unwrap().state == "bootstrapping"
    })
    .await;
    // The app quits mid-bootstrap: everything holding its files ends.
    drop(pairing);
    let dir = fold._dir;
    let gone = Arc::downgrade(&fold.owner);
    drop(fold.host);
    fold.sync.shutdown_all().await;
    drop(fold.sync);
    drop(fold.owner);
    until(10, "files released", || gone.upgrade().is_none()).await;
    hosted.edge.hold_reads_after(None);
    // Restart: the kept admission resumes as a join, never a new device.
    // (A process restart frees the files at once; here the aborted join's
    // native worker may still hold them for a moment.)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (owner, host, screen) = loop {
        let owner = Arc::new(bh_device::Owner::default());
        let (host, screen) = fresh_test_host(&owner, dir.path(), fold.store.clone()).await;
        if screen != bh_host::accounts::Screen::Retry || tokio::time::Instant::now() > deadline {
            break (owner, host, screen);
        }
        drop((host, owner));
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        matches!(screen, bh_host::accounts::Screen::Joining { .. }),
        "{screen:?}"
    );
    let sync = Device::sync(&owner, &hosted);
    let pairing = PairingHost::default();
    let ticket = joining(
        pairing
            .setup_screen("main", &host, &sync, AccountOperation::Startup)
            .await,
    );
    until(90, "ready", || {
        pairing.join_status("main", &ticket).unwrap().state == "ready"
    })
    .await;
    assert!(host.ready_authority().is_some());
    assert_eq!(
        pairing
            .setup_screen("main", &host, &sync, AccountOperation::Startup)
            .await,
        Ok(Screen::Ready)
    );
    mac.sync.shutdown_all().await;
}

/// More than one 64-event read of the Mac's base history. Saves made
/// while one is in flight share a package, so save until it is long enough.
async fn long_history(mac: &Device, hosted: &Hosted) {
    let base = mac.host.ready_parts(mac.id()).unwrap().own_base.id().0;
    let log = bh_sync::permit::LogId {
        kind: bh_sync::permit::LogKind::Base,
        id: base,
    };
    let mut n = 0u8;
    while hosted.edge.head(log).position <= 70 {
        n += 1;
        mac.save("main", None, &format!("mac paragraph {n}"), n);
        until(60, "mac synced", || mac.seen.state() == Some("synced")).await;
    }
}

/// The ticket of a setup screen that follows a join.
fn joining(screen: Result<Screen, &'static str>) -> String {
    match screen {
        Ok(Screen::Joining { ticket }) if !ticket.is_empty() => ticket,
        other => panic!("not a join with a ticket: {other:?}"),
    }
}

/// The joining device's one container: anchored once admitted.
fn joined_container(device: &Device) -> ContainerId {
    let anchored = device.owner.anchored_databases();
    assert_eq!(anchored.len(), 1);
    anchored[0].0
}

/// The device's one container file, opened beside its owner.
fn raw(device: &Device) -> (std::path::PathBuf, rusqlite::Connection) {
    let files: Vec<_> = std::fs::read_dir(device._dir.path().join("accounts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|x| x == "sqlite"))
        .collect();
    assert_eq!(files.len(), 1, "one container, never a second identity");
    let connection = rusqlite::Connection::open(&files[0]).unwrap();
    (files[0].clone(), connection)
}

/// Show on the Mac, join from the Fold, approve; the join's ticket.
async fn approved_join(mac: &Device, fold: &Device, pairing: &PairingHost) -> String {
    let shown = pairing.show(mac.scope("main", 1), &mac.sync).unwrap();
    let ticket = pairing
        .join(
            "main",
            &fold.host,
            &fold.sync,
            &shown.qr_text,
            b"Test phone".to_vec(),
        )
        .unwrap()
        .ticket;
    let scope = mac.scope("main", 1);
    until(30, "candidate", || {
        pairing.status(&scope, &shown.session).unwrap().state == "candidate"
    })
    .await;
    pairing.approve(&scope, &shown.session).unwrap();
    ticket
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_or_retry_during_a_bootstrap_follows_the_same_join() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    long_history(&mac, &hosted).await;
    let fold = Device::fold(&hosted).await;
    let pairing = PairingHost::default();
    // Base history past the first read is not served for now.
    hosted.edge.hold_reads_after(Some(64));
    let ticket = approved_join(&mac, &fold, &pairing).await;
    until(90, "bootstrapping", || {
        pairing.join_status("main", &ticket).unwrap().state == "bootstrapping"
    })
    .await;
    let id = joined_container(&fold);
    let capability = fold.host.ready_parts(id).unwrap().capability;
    // The setup page reloads, then the person presses Try again.
    for operation in [AccountOperation::Startup, AccountOperation::Retry] {
        let screen = pairing
            .setup_screen("main", &fold.host, &fold.sync, operation)
            .await;
        assert_eq!(joining(screen), ticket, "the same join");
        let now = fold.host.ready_parts(id).unwrap().capability;
        assert!(
            std::sync::Arc::ptr_eq(&now, &capability),
            "its authority kept"
        );
        assert_eq!(
            pairing.join_status("main", &ticket).unwrap().state,
            "bootstrapping"
        );
    }
    hosted.edge.hold_reads_after(None);
    until(90, "ready", || {
        pairing.join_status("main", &ticket).unwrap().state == "ready"
    })
    .await;
    assert_eq!(
        pairing
            .setup_screen("main", &fold.host, &fold.sync, AccountOperation::Startup)
            .await,
        Ok(Screen::Ready)
    );
    assert_eq!(fold.host.ready_authority().unwrap().0, id);
    mac.sync.shutdown_all().await;
    fold.sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_window_cannot_steal_a_committed_join_or_strand_its_retry() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    long_history(&mac, &hosted).await;
    let fold = Device::fold(&hosted).await;
    let pairing = PairingHost::default();
    hosted.edge.hold_reads_after(Some(64));
    let ticket = approved_join(&mac, &fold, &pairing).await;
    until(90, "bootstrapping", || {
        pairing.join_status("main", &ticket).unwrap().state == "bootstrapping"
    })
    .await;
    let id = joined_container(&fold);
    let capability = fold.host.ready_parts(id).unwrap().capability;
    let (file, db) = raw(&fold);
    db.execute_batch(
        "CREATE TRIGGER no_activation BEFORE UPDATE OF activated ON joined_device \
         WHEN NEW.activated = 1 BEGIN SELECT RAISE(FAIL, 'no space'); END;",
    )
    .unwrap();

    // This is a different window using the shared API, not the GUI's
    // main-only command adapter. It has no ticket to follow.
    let other = tokio::time::timeout(
        Duration::from_secs(10),
        pairing.setup_screen("other", &fold.host, &fold.sync, AccountOperation::Retry),
    )
    .await
    .expect("other window must not wait for the bootstrap");
    assert_eq!(other, Err("account busy"));
    assert!(Arc::ptr_eq(
        &fold.host.ready_parts(id).unwrap().capability,
        &capability
    ));
    assert_eq!(
        pairing.join_status("main", &ticket).unwrap().state,
        "bootstrapping"
    );
    assert_eq!(raw(&fold).0, file, "one unchanged container");
    assert_eq!(
        joining(
            pairing
                .setup_screen("main", &fold.host, &fold.sync, AccountOperation::Retry)
                .await
        ),
        ticket,
        "the owning window follows its ticket"
    );

    hosted.edge.hold_reads_after(None);
    until(90, "failed activation", || {
        pairing.join_status("main", &ticket).unwrap().state == "failed"
    })
    .await;
    assert!(fold.host.ready_authority().is_none());
    db.execute_batch("DROP TRIGGER no_activation").unwrap();
    let resumed = joining(
        pairing
            .setup_screen("main", &fold.host, &fold.sync, AccountOperation::Retry)
            .await,
    );
    until(90, "resumed join ready", || {
        pairing.join_status("main", &resumed).unwrap().state == "ready"
    })
    .await;
    assert_eq!(fold.host.ready_authority().unwrap().0, id);
    assert_eq!(raw(&fold).0, file);
    let device = fold.host.ready_authority().unwrap().1.device_id();
    let signer = mac.sync.signer(mac.id()).unwrap();
    let account = signer.current_account().unwrap();
    assert!(account.active_device(device).is_ok());
    assert_eq!(account.head().position, 4, "only one addition");
    mac.sync.shutdown_all().await;
    fold.sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_that_fails_after_its_commit_resumes_without_a_restart() {
    let hosted = Hosted::new();
    let mac = Device::mac(&hosted).await;
    mac.save("main", None, "from the mac", 1);
    until(60, "mac synced", || mac.seen.state() == Some("synced")).await;
    let fold = Device::fold(&hosted).await;
    let pairing = PairingHost::default();
    let shown = pairing.show(mac.scope("main", 1), &mac.sync).unwrap();
    let ticket = pairing
        .join(
            "main",
            &fold.host,
            &fold.sync,
            &shown.qr_text,
            b"Test phone".to_vec(),
        )
        .unwrap()
        .ticket;
    // The joined container cannot record its activation for now: the
    // admission commits, the bootstrap reads, then activation fails.
    let (file, db) = raw(&fold);
    db.execute_batch(
        "CREATE TRIGGER no_activation BEFORE UPDATE OF activated ON joined_device \
         WHEN NEW.activated = 1 BEGIN SELECT RAISE(FAIL, 'no space'); END;",
    )
    .unwrap();
    let scope = mac.scope("main", 1);
    until(30, "candidate", || {
        pairing.status(&scope, &shown.session).unwrap().state == "candidate"
    })
    .await;
    pairing.approve(&scope, &shown.session).unwrap();
    until(90, "failed", || {
        pairing.join_status("main", &ticket).unwrap().state == "failed"
    })
    .await;
    let id = joined_container(&fold);
    assert!(fold.host.ready_authority().is_none(), "not usable");
    let activated = || -> i64 {
        db.query_row("SELECT activated FROM joined_device", [], |row| row.get(0))
            .unwrap()
    };
    assert_eq!(activated(), 0);

    // Try again in this build with a configuration it cannot use: the
    // same join resumes and says so, still not activated.
    let mut unusable = endpoint(&hosted);
    unusable.policy = b"not a policy".to_vec();
    unusable.policy_signature = vec![0; 64];
    let unusable = SyncHost::with_transport(
        Configured::Ready(unusable),
        fold.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    db.execute_batch("DROP TRIGGER no_activation").unwrap();
    let again = joining(
        pairing
            .setup_screen("main", &fold.host, &unusable, AccountOperation::Retry)
            .await,
    );
    until(60, "unsupported", || {
        pairing.join_status("main", &again).unwrap().reason == Some("unsupported")
    })
    .await;
    assert_eq!(pairing.join_status("main", &again).unwrap().state, "failed");
    assert!(fold.host.ready_authority().is_none());
    assert_eq!(activated(), 0, "never activated early");

    // Try again with a usable one: the same container, identity and
    // admission become the ready account, without a restart.
    let resumed = joining(
        pairing
            .setup_screen("main", &fold.host, &fold.sync, AccountOperation::Retry)
            .await,
    );
    until(90, "ready", || {
        pairing.join_status("main", &resumed).unwrap().state == "ready"
    })
    .await;
    assert_eq!(activated(), 1);
    assert_eq!(fold.host.ready_authority().unwrap().0, id);
    assert_eq!(raw(&fold).0, file);
    // The Mac's account added exactly one device: this one.
    let device = fold.host.ready_authority().unwrap().1.device_id();
    let signer = mac.sync.signer(mac.id()).unwrap();
    let account = signer.current_account().unwrap();
    assert!(account.active_device(device).is_ok());
    assert_eq!(account.head().position, 4, "one addition");
    fold.open().await;
    mac.sync.shutdown_all().await;
    fold.sync.shutdown_all().await;
}
