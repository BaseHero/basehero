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
    let r = ready(FakeStore::default()).await;
    let seen = Arc::new(Seen::default());
    let sync = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        r.owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    sync.ensure_started(&r.host, r.id, seen.clone()).await;
    save(&r.owner, r.id, "main", "before removal", 1);
    sync.wake(r.id);
    until(60, "synced", || {
        seen.last().is_some_and(|v| v.state == "synced")
    })
    .await;
    // This device's own removal, ordered at the account home.
    let (id, cap) = r.host.ready_authority().unwrap();
    let removal = r
        .host
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
        .unwrap();
    // The client follows the account to its own removal (a service
    // refuses this device's new sessions, so the follow is driven here).
    let signer = sync.signer(id).unwrap();
    let head = signer.current_account().unwrap().head();
    signer.apply_account(head, vec![removal]).await.unwrap();
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
