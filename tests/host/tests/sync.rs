//! The sync host over the in-process hosted environment: the real
//! authorization service behind the real attested channel with labelled
//! synthetic attestation, and a fake edge and log objects. The account
//! registry and key store are the host's own, with a labelled software key
//! store (`test_support`) in place of a platform's.
#![cfg(feature = "synthetic-attestation")]
#[path = "../../sync-client/tests/support/fake.rs"]
mod fake;

use bh_device::ContainerId;
use bh_host::{
    accounts::{AccountOperation, Screen, SharedAccountHost, ready_test_host},
    sync::{Configured, Notice, StatusView, StatusWindows, SyncHost, state_name},
    test_support::{FakeStore, PlainProtector},
};
use bh_sync_client::{Appraisal, ClientError, Endpoint, SyncStatus};
use fake::Hosted;
use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

type Host = SharedAccountHost<FakeStore, PlainProtector>;

/// What the host told windows, as a real window set records it.
#[derive(Default)]
struct Seen {
    posts: Mutex<Vec<(ContainerId, StatusView)>>,
    wakes: Mutex<Vec<String>>,
    ended: Mutex<Vec<ContainerId>>,
}
impl StatusWindows for Seen {
    fn post_status(&self, container: ContainerId, view: &StatusView) {
        self.posts.lock().unwrap().push((container, view.clone()));
    }
    fn wake_delivery(&self, window: String) {
        self.wakes.lock().unwrap().push(window);
    }
    fn authority_ended(&self, container: ContainerId, _: Vec<String>) {
        self.ended.lock().unwrap().push(container);
    }
}
impl Seen {
    fn last(&self) -> Option<StatusView> {
        self.posts
            .lock()
            .unwrap()
            .last()
            .map(|(_, view)| view.clone())
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

struct Ready {
    _dir: tempfile::TempDir,
    owner: Arc<bh_device::Owner>,
    host: Host,
    id: ContainerId,
}
async fn ready(store: FakeStore) -> Ready {
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(bh_device::Owner::default());
    let host = ready_test_host(&owner, dir.path(), store).await;
    let (id, _) = host.ready_authority().unwrap();
    let (_, cap, base) = host.note_authority().unwrap();
    owner.authorize(id, cap, base).unwrap();
    Ready {
        _dir: dir,
        owner,
        host,
        id,
    }
}

/// Save one paragraph in `window`'s home note, as the editor does.
fn save(owner: &bh_device::Owner, id: ContainerId, window: &str, text: &str, request: u8) {
    owner.open_home(window, id).unwrap();
    let note = owner.bound_note(window).unwrap();
    let opened = owner.open_leased(window, note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = bh_device::Owner::core_author(&opened).unwrap();
    let delta = author.try_append_paragraph(text).unwrap();
    owner
        .commit_leased(
            window,
            opened.generation,
            lease.token,
            [request; 16],
            &delta,
        )
        .unwrap();
}

async fn until(seconds: u64, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn sign_self_removal(r: &Ready) -> Vec<u8> {
    let (id, cap) = r.host.ready_authority().unwrap();
    r.host
        .run_lent(id, &cap, |owner, cap| {
            Box::pin(async move {
                let request = owner.prepare_remove_self(&cap).unwrap();
                owner
                    .sign_control(&cap, &request)
                    .await
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            })
        })
        .await
        .unwrap()
}

/// An endpoint file's recovery key is used only if its own hosting root
/// signed it.
#[test]
fn an_endpoint_whose_recovery_key_its_root_did_not_sign_is_invalid() {
    use bh_crypto::{KemKey, SigningKey};
    use bh_sync::evidence::certify_recovery_key;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let root = SigningKey::generate();
    let key = KemKey::generate().public();
    let text = |certificate: &[u8]| {
        serde_json::json!({
            "edge_url": "http://edge.invalid",
            "hosting_root": hex(&root.public()),
            "app_root": hex(&[1; 32]),
            "policy": "",
            "policy_signature": "",
            "max_lifetime_secs": 86400,
            "max_uncertainty_secs": 0,
            "build_floor": 1,
            "appraisal": "synthetic",
            "recovery_key": hex(certificate),
        })
        .to_string()
    };
    let genuine = certify_recovery_key(&root, &key).encode();
    assert!(matches!(
        Configured::from_text(&text(&genuine)),
        Configured::Ready(_)
    ));
    // Another root's signature, naming this root.
    let mut forged = certify_recovery_key(&SigningKey::generate(), &key).encode();
    forged[2..34].copy_from_slice(&root.public());
    assert!(matches!(
        Configured::from_text(&text(&forged)),
        Configured::Invalid
    ));
}

#[test]
fn every_sync_status_has_its_own_state() {
    let statuses = [
        SyncStatus::SavedLocal { pending: 2 },
        SyncStatus::Syncing { pending: 2 },
        SyncStatus::Synced,
        SyncStatus::WaitingNetwork,
        SyncStatus::WaitingAuthorization,
        SyncStatus::HistoryMissing,
        SyncStatus::Unsupported,
        SyncStatus::Stopped,
        SyncStatus::PublishingStopped,
        SyncStatus::NotAccepted { notes: 3 },
        SyncStatus::ControlNotAccepted,
    ];
    let states: std::collections::BTreeSet<_> =
        statuses.iter().map(|status| state_name(*status)).collect();
    assert_eq!(states.len(), statuses.len());
    let view = StatusView::of(
        Some(SyncStatus::NotAccepted { notes: 3 }),
        Some(bh_sync_client::HomeStatus::Retrying(
            bh_sync_client::HomeRetryReason::Unavailable,
        )),
        Notice::default(),
        5,
    );
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["state"], "not-accepted");
    assert_eq!(json["notes"], 3);
    assert_eq!(json["pending"], 5);
    assert_eq!(json["home"], "retrying");
    assert_eq!(json["homeReason"], "unavailable");
    assert_eq!(json["account"], "active");
    assert_eq!(json["confirm"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_endpoint_means_local_only() {
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::new(Configured::Missing, r.owner.clone());
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert!(!sync.running(r.id));
    let opened = seen.last().expect("its windows hear at once");
    assert_eq!(
        (opened.state, opened.network, opened.pending),
        ("saved-local", "off", 0)
    );
    save(&r.owner, r.id, "main", "kept on this device", 1);
    sync.wake(r.id);
    let view = seen.last().unwrap();
    assert_eq!(view.state, "saved-local");
    assert_eq!(view.pending, 1);
    assert_eq!(view.network, "off");
    assert_eq!(view.home, None);
    assert_eq!(
        sync.view(r.id).unwrap(),
        view,
        "a rebinding window reads it"
    );
}

/// A window learns its account's status from pushed views and from the view
/// it asks for after binding; the newer revision wins whichever arrives last.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_status_gets_a_newer_revision_and_an_unchanged_one_is_not_sent() {
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::new(Configured::Missing, r.owner.clone());
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    let first = seen.last().unwrap();
    assert!(first.revision > 0);
    assert_eq!(sync.view(r.id).unwrap(), first);
    // Nothing changed: nothing is sent, and the current view keeps its revision.
    sync.wake(r.id);
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert_eq!(seen.posts.lock().unwrap().len(), 1);
    assert_eq!(sync.view(r.id).unwrap(), first);
    save(&r.owner, r.id, "main", "one change", 1);
    sync.wake(r.id);
    let second = seen.last().unwrap();
    assert_eq!((second.state, second.pending), ("saved-local", 1));
    assert!(second.revision > first.revision);
    assert_eq!(sync.view(r.id).unwrap(), second);
    assert_eq!(
        serde_json::to_value(&second).unwrap()["revision"],
        second.revision
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revisions_keep_rising_when_an_accounts_client_restarts() {
    let hosted = Hosted::new();
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    save(&r.owner, r.id, "main", "before the restart", 1);
    sync.wake(r.id);
    until(60, "synced", || {
        seen.last().is_some_and(|v| v.state == "synced")
    })
    .await;
    let before = seen.last().unwrap().revision;
    // The account locks and opens again in the same app: a new client.
    sync.lock_accounts(&r.host).await;
    assert_eq!(
        bh_host::pairing::PairingHost::default()
            .setup_screen("main", &r.host, &sync, AccountOperation::Startup)
            .await,
        Ok(Screen::Ready)
    );
    let (_, cap, base) = r.host.note_authority().unwrap();
    r.owner.authorize(r.id, cap, base).unwrap();
    let sent = seen.posts.lock().unwrap().len();
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert!(sync.running(r.id));
    save(&r.owner, r.id, "main", "after the restart", 2);
    sync.wake(r.id);
    until(60, "synced again", || {
        let posts = seen.posts.lock().unwrap();
        posts.len() > sent + 1 && posts.last().unwrap().1.state == "synced"
    })
    .await;
    let after: Vec<u64> = seen.posts.lock().unwrap()[sent..]
        .iter()
        .map(|(_, view)| view.revision)
        .collect();
    assert!(
        after.iter().all(|revision| *revision > before),
        "{after:?} after {before}"
    );
    assert_eq!(
        sync.view(r.id).unwrap().revision,
        *after.iter().max().unwrap(),
        "the current view is the newest sent"
    );
    sync.shutdown_all().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_endpoint_never_starts_sync() {
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::new(Configured::Invalid, r.owner.clone());
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert!(!sync.running(r.id));
    assert_eq!(seen.last().unwrap().state, "unsupported");
    assert_eq!(seen.last().unwrap().network, "unsupported");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ready_account_syncs_once_with_home_shown_on_its_own() {
    let hosted = Hosted::new();
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    let first = sync.client(r.id).unwrap();
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert!(Arc::ptr_eq(&first, &sync.client(r.id).unwrap()), "reused");
    save(&r.owner, r.id, "main", "to the cloud", 1);
    sync.wake(r.id);
    until(60, "synced", || {
        seen.last()
            .is_some_and(|v| v.state == "synced" && v.home == Some("done"))
    })
    .await;
    assert_eq!(seen.last().unwrap().pending, 0);
    assert!(
        seen.posts
            .lock()
            .unwrap()
            .iter()
            .all(|(container, _)| *container == r.id),
        "only this account's windows"
    );
    sync.shutdown_all().await;
    assert!(!sync.running(r.id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_locked_account_stops_its_client_and_cannot_restart_it() {
    let hosted = Hosted::new();
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert!(sync.running(r.id));
    sync.lock_accounts(&r.host).await;
    assert!(!sync.running(r.id));
    // Not ready: nothing starts.
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert!(!sync.running(r.id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_device_stops_its_client_and_ends_its_windows() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let r = ready(store.clone()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.set_erase({
        let accounts = r.host.clone();
        Arc::new(move |id| {
            let accounts = accounts.clone();
            Box::pin(async move {
                let _ = accounts.erase_removed(id).await;
            })
        })
    });
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    save(&r.owner, r.id, "main", "before removal", 1);
    sync.wake(r.id);
    until(60, "synced and home done", || {
        seen.last()
            .is_some_and(|v| v.state == "synced" && v.home == Some("done"))
    })
    .await;
    // This device's own removal, ordered at the account home.
    let id = r.id;
    let removal = sign_self_removal(&r).await;
    let signer = sync.signer(id).unwrap();
    let genesis = signer.identity().unwrap().genesis;
    let log = bh_sync::permit::LogId {
        kind: bh_sync::permit::LogKind::Account,
        id: bh_authz::proto::account_log_id(&genesis).unwrap(),
    };
    let verdict = sync.client(id).unwrap().removal_verdict();
    let position = hosted.edge.order_account(log, &removal);
    // The home's exact confirmation, as the follow reads and keeps it.
    let confirmed = {
        let client = sync.client(id).unwrap();
        let mut session = client.authz().await.unwrap();
        let answer = session
            .ask(bh_authz::proto::ToService::ReadAccountEvidence {
                genesis: genesis.clone(),
                first: position,
                last: position,
                challenge: [7; 32],
            })
            .await
            .unwrap();
        let bh_authz::proto::FromService::AccountEvidence { confirmations, .. } = answer else {
            panic!("account evidence: {answer:?}");
        };
        let bytes = confirmations.last().unwrap().clone();
        let bounds = bh_sync::evidence::OrderingConfirmation::decode(&bytes)
            .unwrap()
            .claim()
            .bounds;
        let time = bh_account::ConfirmedTime {
            earliest_ms: bounds.earliest_ms,
            latest_ms: bounds.latest_ms,
        };
        (time, bytes)
    };
    // The account follow moves its checkpoint past its own removal and
    // applies it with the home's confirmation, as the client's follow does
    // (driven here; the client's own follow may win the race). The checkpoint
    // moves first so the check finds the owner's view behind it.
    let name = r.host.container_name(id).unwrap();
    let database = r.owner.shared_database(id).unwrap();
    let before = database
        .lock()
        .unwrap()
        .account_outer_progress(log.id, hosted.edge.root())
        .unwrap()
        .order;
    let after = hosted.edge.entries(log).last().unwrap().0.after();
    let _ =
        database
            .lock()
            .unwrap()
            .advance_account_outer(log.id, hosted.edge.root(), before, after);
    if let Ok(account) = signer.current_account() {
        let _ = signer
            .apply_account_timed(account.head(), vec![(removal, Some(confirmed))])
            .await;
    }
    until(60, "ended", || seen.ended.lock().unwrap().contains(&id)).await;
    until(10, "stopped", || !sync.running(id)).await;
    assert_eq!(seen.last().unwrap().account, "removed");
    assert!(r.owner.bound_container("main").is_none(), "windows unbound");
    // The owner's notice did not erase: the client's own verification of
    // the public evidence did.
    assert!(
        matches!(
            *verdict.borrow(),
            bh_sync_client::RemovalVerdict::Removed { .. }
        ),
        "erased through the verified verdict: {:?}",
        *verdict.borrow()
    );
    // The detached erasure runs to the end even though stopping this client
    // aborts the task that reported the removal.
    let accounts = r._dir.path().join("accounts");
    until(20, "keys erased", || store.keys.lock().unwrap().is_empty()).await;
    until(20, "container and sidecars gone", || {
        !accounts.join(format!("{name}.sqlite")).exists()
            && !accounts.join(format!("{name}.sqlite-wal")).exists()
            && !accounts.join(format!("{name}.sqlite-shm")).exists()
    })
    .await;
    assert!(!accounts.join(format!("{name}.erasing")).exists());
    until(20, "erased screen kept", || r.host.screen().is_some()).await;
    assert_eq!(r.host.screen(), Some(Screen::Erased { unsent: 0 }));
}

/// The erase hook the app installs: the registry erases and keeps its screen.
fn erase_through(sync: &SyncHost, accounts: &Host) {
    let accounts = accounts.clone();
    sync.set_erase(Arc::new(move |id| {
        let accounts = accounts.clone();
        Box::pin(async move {
            let _ = accounts.erase_removed(id).await;
        })
    }));
}

/// The home orders this device's removal while its client is stopped. On
/// the next start the service refuses the device, so the owner never follows
/// the removal and no notice reports it: only the running client's own
/// verification of the public evidence does, and that verdict alone must
/// carry the erasure through to the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_running_clients_removal_verdict_erases_the_account() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let r = ready(store.clone()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    erase_through(&sync, &r.host);
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    save(&r.owner, r.id, "main", "before removal", 1);
    sync.wake(r.id);
    until(60, "synced and home done", || {
        seen.last()
            .is_some_and(|v| v.state == "synced" && v.home == Some("done"))
    })
    .await;
    let id = r.id;
    let name = r.host.container_name(id).unwrap();
    let genesis = sync.signer(id).unwrap().identity().unwrap().genesis;
    let log = bh_sync::permit::LogId {
        kind: bh_sync::permit::LogKind::Account,
        id: bh_authz::proto::account_log_id(&genesis).unwrap(),
    };
    let removal = sign_self_removal(&r).await;
    sync.shutdown_all().await;
    // Two edits saved meanwhile are never ordered.
    save(&r.owner, id, "main", "after removal", 2);
    save(&r.owner, id, "main", "and another", 3);
    hosted.edge.order_account(log, &removal);
    sync.ensure_started(&r.host, id, seen.clone()).await;
    assert!(sync.running(id), "the client runs until it verifies");
    let verdict = sync.client(id).unwrap().removal_verdict();
    until(60, "stopped", || !sync.running(id)).await;
    assert!(
        matches!(
            *verdict.borrow(),
            bh_sync_client::RemovalVerdict::Removed { .. }
        ),
        "the client's own verification reported the removal: {:?}",
        *verdict.borrow()
    );
    assert_eq!(
        seen.last().unwrap().account,
        "active",
        "the owner never applied the removal, so no notice reported it"
    );
    let accounts = r._dir.path().join("accounts");
    until(20, "keys erased", || store.keys.lock().unwrap().is_empty()).await;
    until(20, "container and sidecars gone", || {
        !accounts.join(format!("{name}.sqlite")).exists()
            && !accounts.join(format!("{name}.sqlite-wal")).exists()
            && !accounts.join(format!("{name}.sqlite-shm")).exists()
    })
    .await;
    until(20, "marker cleared", || {
        !accounts.join(format!("{name}.erasing")).exists()
    })
    .await;
    // Three saved edits, one acknowledged: the two the home never ordered
    // are counted, not silently lost.
    until(20, "erased screen kept", || r.host.screen().is_some()).await;
    assert_eq!(r.host.screen(), Some(Screen::Erased { unsent: 2 }));
    until(20, "windows ended", || {
        seen.ended.lock().unwrap().contains(&id)
    })
    .await;
}

/// The home orders this device's removal while its client runs and syncs.
/// Whichever reports it first, the account follow or the client's own
/// verification, the erasure runs to the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_ordered_while_running_erases_the_account() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let r = ready(store.clone()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    erase_through(&sync, &r.host);
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    save(&r.owner, r.id, "main", "before removal", 1);
    sync.wake(r.id);
    until(60, "synced and home done", || {
        seen.last()
            .is_some_and(|v| v.state == "synced" && v.home == Some("done"))
    })
    .await;
    let id = r.id;
    let name = r.host.container_name(id).unwrap();
    let genesis = sync.signer(id).unwrap().identity().unwrap().genesis;
    let log = bh_sync::permit::LogId {
        kind: bh_sync::permit::LogKind::Account,
        id: bh_authz::proto::account_log_id(&genesis).unwrap(),
    };
    hosted.edge.order_account(log, &sign_self_removal(&r).await);
    // The next edit asks for permits mid-session.
    save(&r.owner, id, "main", "after removal", 2);
    sync.wake(id);
    until(60, "stopped", || !sync.running(id)).await;
    let accounts = r._dir.path().join("accounts");
    until(20, "erasure finished", || {
        matches!(
            r.host.screen(),
            Some(Screen::Erased { .. } | Screen::EraseIncomplete { .. })
        )
    })
    .await;
    assert_eq!(r.host.screen(), Some(Screen::Erased { unsent: 1 }));
    assert!(store.keys.lock().unwrap().is_empty(), "keys erased");
    assert!(!accounts.join(format!("{name}.sqlite")).exists());
    assert!(!accounts.join(format!("{name}.erasing")).exists());
}

/// A device whose owner applied its own self-removal while its client was
/// stopped, before any check answered, then restarted: what startup shows.
struct Restarted {
    dir: tempfile::TempDir,
    store: FakeStore,
    name: String,
    first: Screen,
    screen: Result<Screen, &'static str>,
}

/// The removal is ordered at the home only when `ordered`; otherwise the
/// owner holds it with a confirmation the public evidence does not carry.
async fn removed_then_restarted(ordered: bool) -> Restarted {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let r = ready(store.clone()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    erase_through(&sync, &r.host);
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    save(&r.owner, r.id, "main", "before removal", 1);
    sync.wake(r.id);
    until(60, "synced and home done", || {
        seen.last()
            .is_some_and(|v| v.state == "synced" && v.home == Some("done"))
    })
    .await;
    let id = r.id;
    let name = r.host.container_name(id).unwrap();
    let genesis = sync.signer(id).unwrap().identity().unwrap().genesis;
    let log = bh_sync::permit::LogId {
        kind: bh_sync::permit::LogKind::Account,
        id: bh_authz::proto::account_log_id(&genesis).unwrap(),
    };
    let removal = sign_self_removal(&r).await;
    // The client stops before it could answer any check.
    sync.shutdown_all().await;
    let evidence = if ordered {
        hosted.edge.order_account(log, &removal);
        hosted.confirmed_account(log).await.pop().unwrap().1
    } else {
        let now = hosted.edge.clock.now();
        let time = bh_account::ConfirmedTime {
            earliest_ms: now,
            latest_ms: now,
        };
        Some((time, b"confirmed".to_vec()))
    };
    let (_, cap) = r.host.ready_authority().unwrap();
    r.host
        .run_lent(id, &cap, move |owner, _| {
            Box::pin(async move { owner.apply_incoming_timed(&[(removal.as_slice(), evidence)]) })
        })
        .await
        .unwrap()
        .expect("the owner applied this device's removal");
    // Restart: a new container owner, registry and sync host on the same
    // files and keys.
    drop(sync);
    let Ready {
        _dir: dir,
        owner,
        host,
        ..
    } = r;
    drop((host, owner));
    let owner = Arc::new(bh_device::Owner::default());
    let (host, first) = bh_host::accounts::fresh_test_host(&owner, dir.path(), store.clone()).await;
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    erase_through(&sync, &host);
    let screen = tokio::time::timeout(
        Duration::from_secs(60),
        bh_host::pairing::PairingHost::default().setup_screen(
            "main",
            &host,
            &sync,
            AccountOperation::Startup,
        ),
    )
    .await
    .expect("startup answered");
    sync.shutdown_all().await;
    Restarted {
        dir,
        store,
        name,
        first,
        screen,
    }
}

/// The owner applied this device's removal, and the client stopped before
/// its check answered. On the next start the owner no longer activates the
/// device; checking the public evidence from its last member view verifies
/// the removal, and the account is erased.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_applied_before_a_restart_is_erased_on_the_next_start() {
    let r = removed_then_restarted(true).await;
    assert_eq!(r.first, Screen::Return, "the device is no longer active");
    assert_eq!(r.screen, Ok(Screen::Erased { unsent: 0 }));
    let accounts = r.dir.path().join("accounts");
    assert!(r.store.keys.lock().unwrap().is_empty(), "keys erased");
    assert!(!accounts.join(format!("{}.sqlite", r.name)).exists());
    assert!(!accounts.join(format!("{}.erasing", r.name)).exists());
}

/// The owner holds a removal of this device that the public evidence does
/// not carry. Not being active is not proof of removal: nothing is erased.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_the_public_evidence_does_not_verify_erases_nothing() {
    let r = removed_then_restarted(false).await;
    assert_eq!(r.first, Screen::Return, "the device is no longer active");
    assert_eq!(r.screen, Ok(Screen::Return));
    let accounts = r.dir.path().join("accounts");
    assert!(!r.store.keys.lock().unwrap().is_empty(), "keys kept");
    assert!(accounts.join(format!("{}.sqlite", r.name)).exists());
    assert!(!accounts.join(format!("{}.erasing", r.name)).exists());
}

/// Note sync can finish before first-device home setup. The owner must not
/// accept a successor until the home has supplied the setup's verified times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_waits_for_home_setup_even_when_notes_are_synced() {
    let hosted = Hosted::new();
    let hold = hosted.edge.hold_next_home_store();
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    tokio::time::timeout(Duration::from_secs(60), hold.arrived)
        .await
        .expect("home store arrived")
        .unwrap();
    save(&r.owner, r.id, "main", "before removal", 1);
    sync.wake(r.id);
    until(60, "notes synced while home pending", || {
        seen.last()
            .is_some_and(|v| v.state == "synced" && v.home == Some("pending"))
    })
    .await;

    let removal = sign_self_removal(&r).await;
    let signer = sync.signer(r.id).unwrap();
    let head = signer.current_account().unwrap().head();
    let now = hosted.edge.clock.now();
    let time = bh_account::ConfirmedTime {
        earliest_ms: now,
        latest_ms: now,
    };
    // Diagnose the owner's precise rejection, not just the host's coarser
    // Unavailable result (which also covers a stale head or failed lend).
    let (id, cap) = r.host.ready_authority().unwrap();
    let for_owner = removal.clone();
    let owner_error = r
        .host
        .run_lent(id, &cap, move |owner, _| {
            Box::pin(async move {
                owner.apply_incoming_timed(&[(
                    for_owner.as_slice(),
                    Some((time, b"confirmed".to_vec())),
                )])
            })
        })
        .await
        .unwrap();
    assert!(matches!(
        owner_error,
        Err(bh_account::owner::OwnerError::Invalid(
            bh_account::Error::Unavailable
        ))
    ));
    assert_eq!(
        signer
            .apply_account_timed(
                head,
                vec![(removal.clone(), Some((time, b"confirmed".to_vec())))]
            )
            .await,
        Err(bh_sync_client::AccountApplyError::Unavailable)
    );
    assert_eq!(signer.current_account().unwrap().head(), head);
    assert!(sync.running(id));

    hold.release.send(()).unwrap();
    until(60, "home done", || {
        seen.last().is_some_and(|v| v.home == Some("done"))
    })
    .await;
    let now = hosted.edge.clock.now();
    let time = bh_account::ConfirmedTime {
        earliest_ms: now,
        latest_ms: now,
    };
    signer
        .apply_account_timed(head, vec![(removal, Some((time, b"confirmed".to_vec())))])
        .await
        .unwrap();
    until(60, "ended", || seen.ended.lock().unwrap().contains(&id)).await;
    until(10, "stopped", || !sync.running(id)).await;
    assert_eq!(seen.last().unwrap().account, "removed");
    assert!(r.owner.bound_container("main").is_none(), "windows unbound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_held_on_one_account_does_not_pause_anothers_sync() {
    let hosted = Hosted::new();
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(bh_device::Owner::default());
    let (host, [a, b]) =
        bh_host::accounts::two_ready_test_host(&owner, dir.path(), FakeStore::default()).await;
    let authority = |id| {
        let parts = host.ready_parts(id).unwrap();
        let base = parts.own_base.id().0;
        owner.authorize(id, parts.capability.clone(), base).unwrap();
        parts.capability
    };
    let cap_a = authority(a);
    authority(b);
    let seen_a = Arc::new(Seen::default());
    let seen_b = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.ensure_started(&host, a, seen_a.clone()).await;
    sync.ensure_started(&host, b, seen_b.clone()).await;
    // Account A's owner sits in a long native prompt.
    let (release, held) = tokio::sync::oneshot::channel::<()>();
    let prompt = tokio::spawn({
        let host = host.clone();
        async move {
            host.run_lent(a, &cap_a, move |_, _| {
                Box::pin(async move {
                    let _ = held.await;
                })
            })
            .await
        }
    });
    save(&owner, b, "window-b", "account b keeps syncing", 1);
    sync.wake(b);
    until(60, "b synced", || {
        seen_b.last().is_some_and(|v| v.state == "synced")
    })
    .await;
    // A's local saves still land while its prompt is open.
    save(&owner, a, "window-a", "account a saves locally", 1);
    assert!(!prompt.is_finished());
    release.send(()).unwrap();
    prompt.await.unwrap().unwrap();
    sync.wake(a);
    until(60, "a synced", || {
        seen_a.last().is_some_and(|v| v.state == "synced")
    })
    .await;
    sync.shutdown_all().await;
}

/// The edge's name for account `id`'s own base log.
fn base_log(host: &Host, id: ContainerId) -> bh_sync::permit::LogId {
    bh_sync::permit::LogId {
        kind: bh_sync::permit::LogKind::Base,
        id: host.ready_parts(id).unwrap().own_base.id().0,
    }
}

/// Hold account `id`'s one owner, as a native prompt does, until released.
async fn hold_owner(
    host: &Host,
    id: ContainerId,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), bh_host::accounts::Unavailable>>,
) {
    let cap = host.ready_parts(id).unwrap().capability;
    let (release, held) = tokio::sync::oneshot::channel::<()>();
    let prompt = tokio::spawn({
        let host = host.clone();
        let cap = cap.clone();
        async move {
            host.run_lent(id, &cap, move |_, _| {
                Box::pin(async move {
                    let _ = held.await;
                })
            })
            .await
        }
    });
    until(10, "owner lent", || {
        host.with_owner(id, &cap, |_| ()).is_none()
    })
    .await;
    (release, prompt)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_ends_the_clients_work_while_a_pairing_holds_its_handle() {
    let hosted = Hosted::new();
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    save(&r.owner, r.id, "main", "synced first", 1);
    sync.wake(r.id);
    until(60, "synced", || {
        seen.last().is_some_and(|v| v.state == "synced")
    })
    .await;
    // A pairing keeps the client's handle across a native prompt, which
    // holds the account's owner.
    let handle = sync.handle(r.id).unwrap();
    let kept = handle.clone();
    let (release, prompt) = hold_owner(&r.host, r.id).await;
    hosted.go_down();
    save(&r.owner, r.id, "main", "kept on this device", 2);
    sync.wake(r.id);
    // The account locks: its client stops at once, prompt or not.
    tokio::time::timeout(Duration::from_secs(3), sync.lock_accounts(&r.host))
        .await
        .expect("the stop does not wait for the handle");
    assert!(!sync.running(r.id));
    assert!(sync.handle(r.id).is_none());
    assert_eq!(
        Arc::strong_count(&seen),
        1,
        "its status report and wake forwarding ended"
    );
    let connects = hosted.edge.authz_connects.load(Ordering::SeqCst);
    hosted.come_up();
    assert!(matches!(
        kept.client.authz().await,
        Err(ClientError::Stopped)
    ));
    // The prompt ends; nothing it returns to starts work again.
    release.send(()).unwrap();
    prompt.await.unwrap().unwrap();
    kept.client.wake();
    assert!(kept.ops.reconfirm().await.is_err(), "the account is locked");
    assert_eq!(hosted.edge.authz_connects.load(Ordering::SeqCst), connects);
    let pending = r
        .owner
        .shared_database(r.id)
        .unwrap()
        .lock()
        .unwrap()
        .outbox_summary()
        .unwrap()
        .unaccepted;
    assert_eq!(pending, 1, "the unsent update is kept");
    drop((handle, kept));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_starts_at_once_make_one_client_and_another_account_carries_on() {
    let hosted = Hosted::new();
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(bh_device::Owner::default());
    let (host, [a, b]) =
        bh_host::accounts::two_ready_test_host(&owner, dir.path(), FakeStore::default()).await;
    for id in [a, b] {
        let parts = host.ready_parts(id).unwrap();
        let base = parts.own_base.id().0;
        owner.authorize(id, parts.capability, base).unwrap();
    }
    let seen_a = Arc::new(Seen::default());
    let seen_b = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    // Account A's owner sits in a prompt: both starts wait past their
    // first check for a client.
    let (release, prompt) = hold_owner(&host, a).await;
    let start = || {
        let (sync, host, seen) = (sync.clone(), host.clone(), seen_a.clone());
        tokio::spawn(async move { sync.ensure_started(&host, a, seen).await })
    };
    let (first, second) = (start(), start());
    // Account B starts and syncs meanwhile.
    sync.ensure_started(&host, b, seen_b.clone()).await;
    save(&owner, b, "window-b", "account b carries on", 1);
    sync.wake(b);
    until(60, "b synced", || {
        seen_b.last().is_some_and(|v| v.state == "synced")
    })
    .await;
    assert!(!first.is_finished() && !second.is_finished());
    release.send(()).unwrap();
    prompt.await.unwrap().unwrap();
    first.await.unwrap();
    second.await.unwrap();
    assert!(sync.running(a));
    save(&owner, a, "window-a", "account a syncs once", 1);
    sync.wake(a);
    until(60, "a synced", || {
        seen_a.last().is_some_and(|v| v.state == "synced")
    })
    .await;
    assert_eq!(
        hosted.edge.subscriptions(base_log(&host, a)),
        1,
        "one client's subscription"
    );
    sync.shutdown_all().await;
    assert_eq!(Arc::strong_count(&seen_a), 1, "no client left running");
    assert_eq!(Arc::strong_count(&seen_b), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_or_fenced_start_installs_no_client() {
    let hosted = Hosted::new();
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    // A start that waits for the owner is cancelled: a later one starts.
    let (release, prompt) = hold_owner(&r.host, r.id).await;
    let mut start = Box::pin(sync.ensure_started(&r.host, r.id, seen.clone()));
    assert!(futures_util::poll!(&mut start).is_pending());
    drop(start);
    release.send(()).unwrap();
    prompt.await.unwrap().unwrap();
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    assert!(sync.running(r.id));

    // A start waiting while the app quits installs nothing after it, even
    // though its account's authority is still current.
    sync.shutdown_all().await;
    let (release, prompt) = hold_owner(&r.host, r.id).await;
    let mut start = Box::pin(sync.ensure_started(&r.host, r.id, seen.clone()));
    assert!(futures_util::poll!(&mut start).is_pending());
    sync.shutdown_all().await;
    release.send(()).unwrap();
    prompt.await.unwrap().unwrap();
    start.await;
    assert!(r.host.ready_parts(r.id).is_some(), "still the account's");
    assert!(!sync.running(r.id));
    assert_eq!(Arc::strong_count(&seen), 1, "no client left running");

    // A start waiting while the account locks installs nothing after it.
    let (release, prompt) = hold_owner(&r.host, r.id).await;
    let mut start = Box::pin(sync.ensure_started(&r.host, r.id, seen.clone()));
    assert!(futures_util::poll!(&mut start).is_pending());
    sync.lock_accounts(&r.host).await;
    release.send(()).unwrap();
    prompt.await.unwrap().unwrap();
    start.await;
    assert!(!sync.running(r.id));
    assert_eq!(Arc::strong_count(&seen), 1, "no client left running");
}

/// The count the final screen shows is the one read after the client stopped,
/// not a stale snapshot published while work could still move.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_freezes_the_unsent_count_at_the_destructive_step() {
    let r = ready(FakeStore::default()).await;
    save(&r.owner, r.id, "main", "an edit no server acknowledged", 1);
    assert_eq!(
        r.host.erase_removed(r.id).await,
        Some(Screen::Erased { unsent: 1 })
    );
}
