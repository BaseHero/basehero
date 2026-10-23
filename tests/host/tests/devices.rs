//! Your devices through the host over the in-process hosted environment:
//! the real authorization service behind the real attested channel with
//! labelled synthetic attestation, a fake edge and log objects, and the
//! host's own registry with a labelled software key store.
#![cfg(feature = "synthetic-attestation")]
#[path = "../../sync-client/tests/support/fake.rs"]
mod fake;

use bh_account::{
    DeviceId, DevicePublicKeys, REMOVAL_WAIT_MS as WAIT,
    crypto::{KemKey, SigningKey},
    directory::DirectoryEntry,
    recovery::Password,
};
use bh_device::ContainerId;
use bh_host::{
    accounts::{AccountOperation, Screen, SharedAccountHost, fresh_test_host, ready_test_host},
    devices::{self, DevicesView},
    pairing::PairingHost,
    sync::{Configured, StatusView, StatusWindows, SyncHost},
    test_support::{FakeStore, PlainProtector},
};
use bh_sync::permit::{LogId, LogKind};
use bh_sync_client::{Appraisal, Endpoint, Signer};
use fake::{Hook, Hosted};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

type Host = SharedAccountHost<FakeStore, PlainProtector>;

/// The password `ready_test_host` signs up with.
const PASSWORD: &str = "ripple amber horizon nectar willow";

#[derive(Default)]
struct Seen {
    posts: Mutex<Vec<StatusView>>,
}
impl StatusWindows for Seen {
    fn post_status(&self, _: ContainerId, view: &StatusView) {
        self.posts.lock().unwrap().push(view.clone());
    }
    fn wake_delivery(&self, _: String) {}
    fn authority_ended(&self, _: ContainerId, _: Vec<String>) {}
}
impl Seen {
    fn last(&self) -> Option<StatusView> {
        self.posts.lock().unwrap().last().cloned()
    }
}

fn endpoint(hosted: &Hosted) -> Endpoint {
    Endpoint {
        edge_url: "http://edge.invalid".into(),
        hosting_root: hosted.edge.root(),
        recovery_key: hosted.edge.recovery_certificate(),
        app_root: hosted.policy_root.public(),
        policy: Vec::new(),
        policy_signature: Vec::new(),
        limits: bh_confidential_policy::Limits {
            max_lifetime_secs: 86_400,
            max_uncertainty_secs: 0,
        },
        build_floor: 1,
        appraisal: Appraisal::Synthetic,
        device_clock: Arc::new(bh_sync_client::SystemDeviceClock),
    }
}

/// How long one operation may take before the test fails: below the
/// client's wait for a frame, so a stuck request fails rather than hangs.
const OPERATION_WAIT: Duration = Duration::from_secs(30);

/// `operation`'s result, or a failure naming `what` if it takes longer than
/// `OPERATION_WAIT`.
async fn bounded<T>(what: &str, operation: impl Future<Output = T>) -> T {
    tokio::time::timeout(OPERATION_WAIT, Box::pin(operation))
        .await
        .unwrap_or_else(|_| panic!("{what} within {OPERATION_WAIT:?}"))
}

/// Wait for `done`, polling; fails after `seconds`.
async fn until(seconds: u64, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One device's running app: its registry and sync host on `owner`.
struct App {
    owner: Arc<bh_device::Owner>,
    host: Host,
    sync: SyncHost,
    seen: Arc<Seen>,
    id: ContainerId,
}

impl App {
    /// Start sync for the routed ready account of `host`.
    async fn start(hosted: &Arc<Hosted>, owner: Arc<bh_device::Owner>, host: Host) -> Self {
        Self::start_as(hosted, owner, host, "MacBook Pro").await
    }
    /// As `start`, on a device whose model is `model`.
    async fn start_as(
        hosted: &Arc<Hosted>,
        owner: Arc<bh_device::Owner>,
        host: Host,
        model: &str,
    ) -> Self {
        Self::start_at(hosted, owner, host, model, endpoint(hosted)).await
    }
    /// Run the same host session on a supplied device clock.
    async fn start_at(
        hosted: &Arc<Hosted>,
        owner: Arc<bh_device::Owner>,
        host: Host,
        model: &str,
        endpoint: Endpoint,
    ) -> Self {
        host.set_device_model(model);
        let (id, cap, base) = host.note_authority().unwrap();
        owner.authorize(id, cap, base).unwrap();
        let sync = SyncHost::with_transport(
            Configured::Ready(endpoint),
            owner.clone(),
            hosted.connector(),
            hosted.relay(),
        );
        let seen = Arc::new(Seen::default());
        let erasing = host.clone();
        sync.set_erase(Arc::new(move |id| {
            let accounts = erasing.clone();
            Box::pin(async move {
                let _ = accounts.erase_removed(id).await;
            })
        }));
        sync.ensure_started(&host, id, seen.clone()).await;
        Self {
            owner,
            host,
            sync,
            seen,
            id,
        }
    }
    /// A signed-up device whose home setup is done.
    async fn ready(hosted: &Arc<Hosted>, store: &FakeStore) -> (tempfile::TempDir, Self) {
        Self::ready_with_clock(hosted, store, false).await
    }
    async fn ready_on_shared_clock(
        hosted: &Arc<Hosted>,
        store: &FakeStore,
    ) -> (tempfile::TempDir, Self) {
        Self::ready_with_clock(hosted, store, true).await
    }
    async fn ready_with_clock(
        hosted: &Arc<Hosted>,
        store: &FakeStore,
        shared_clock: bool,
    ) -> (tempfile::TempDir, Self) {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = ready_test_host(&owner, dir.path(), store.clone()).await;
        let mut endpoint = endpoint(hosted);
        if shared_clock {
            endpoint.device_clock = hosted.edge.clock.clone();
        }
        let app = Self::start_at(hosted, owner, host, "MacBook Pro", endpoint).await;
        until(60, "home done", || {
            app.seen.last().is_some_and(|v| v.home == Some("done"))
        })
        .await;
        (dir, app)
    }
    /// Wait until the client registered the own base and read its tail:
    /// from here a held or refused base publication is an edit's, never
    /// the registration's.
    async fn synced(&self) {
        until(60, "synced", || {
            self.seen.last().is_some_and(|v| v.state == "synced")
        })
        .await;
    }
    fn signer(&self) -> Arc<dyn Signer> {
        self.sync.signer(self.id).unwrap()
    }
    fn this(&self) -> DeviceId {
        self.signer().identity().unwrap().device
    }
    fn view(&self) -> DevicesView {
        devices::view(&self.host, &self.sync).unwrap()
    }
    async fn run(&self, operation: AccountOperation) -> Result<Screen, &'static str> {
        bounded(
            "the operation",
            devices::run(&self.host, &self.sync, operation),
        )
        .await
    }
    /// Wait until this device followed account position `at`.
    async fn followed(&self, at: u64) {
        until(60, "followed", || {
            self.sync.wake(self.id);
            self.signer()
                .current_account()
                .is_ok_and(|account| account.head().position >= at)
        })
        .await;
    }
    /// Add `member` with this device's second key, have the home order it,
    /// and approve its copy into the own base.
    async fn add(&self, hosted: &Hosted, member: &Member) {
        let (id, cap) = self.host.ready_authority().unwrap();
        let keys = member.keys.clone();
        let addition = self
            .host
            .run_lent(id, &cap, move |owner, cap| {
                Box::pin(async move {
                    let request = owner.prepare_add_device(&cap, keys).unwrap();
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
        let at = hosted.edge.order_account(self.log(), &addition);
        self.followed(at).await;
        self.approve_copy().await;
    }
    /// Approve the base copy of a followed account change, which waits for
    /// the person.
    async fn approve_copy(&self) {
        until(60, "copy waits for the person", || {
            self.seen.last().is_some_and(|v| v.confirm)
        })
        .await;
        self.sync
            .handle(self.id)
            .unwrap()
            .ops
            .reconfirm()
            .await
            .unwrap();
        self.sync.wake(self.id);
        until(60, "copied", || {
            self.seen.last().is_some_and(|v| !v.confirm)
        })
        .await;
    }
    /// The device's item in Your devices.
    fn item(&self, device: DeviceId) -> devices::DeviceItem {
        let hex: String = device.0.iter().map(|b| format!("{b:02x}")).collect();
        self.view()
            .devices
            .into_iter()
            .find(|item| item.id_hex == hex)
            .unwrap()
    }
    fn appends(&self, hosted: &Hosted) -> usize {
        hosted.edge.appends(self.log().id).len()
    }
    /// Quit: stop sync and drop the registry and container owner.
    async fn quit(self) {
        self.sync.shutdown_all().await;
        drop((self.sync, self.host, self.owner));
    }
    fn log(&self) -> LogId {
        let genesis = self
            .sync
            .signer(self.id)
            .unwrap()
            .identity()
            .unwrap()
            .genesis;
        LogId {
            kind: LogKind::Account,
            id: bh_authz::proto::account_log_id(&genesis).unwrap(),
        }
    }
    /// The directory as the home holds it, opened by this device.
    async fn directory(&self, hosted: &Hosted) -> Vec<DirectoryEntry> {
        let entries = hosted
            .edge
            .directory(self.log())
            .into_iter()
            .map(|(_, _, bytes)| bytes)
            .collect();
        self.sync
            .signer(self.id)
            .unwrap()
            .open_directory_entries(entries)
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .map(|opened| opened.entry)
            .collect()
    }
    /// Open Your devices and wait until the client read the directory for it.
    async fn read_directory(&self, hosted: &Hosted) {
        let before = hosted.edge.directory_reads.load(Ordering::SeqCst);
        devices::view(&self.host, &self.sync).unwrap();
        until(60, "directory read", || {
            hosted.edge.directory_reads.load(Ordering::SeqCst) > before
        })
        .await;
    }
}

/// Another device of the account, by its keys alone.
struct Member {
    ordinary: SigningKey,
    control: SigningKey,
    keys: DevicePublicKeys,
}
impl Member {
    fn new() -> Self {
        let (ordinary, control) = (SigningKey::generate(), SigningKey::generate());
        let keys = DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Self {
            ordinary,
            control,
            keys,
        }
    }
    /// Its own name in the account's directory, as it would write it.
    async fn name_itself(&self, app: &App, hosted: &Hosted, name: &str) {
        let (id, cap) = app.host.ready_authority().unwrap();
        let (device, name) = (self.id(), name.to_owned());
        let ordinary = SigningKey::from_seed(&self.ordinary.export_seed());
        let bytes = app
            .host
            .run_lent(id, &cap, move |owner, cap| {
                Box::pin(async move {
                    let personal = owner.open_current_personal(&cap).await.unwrap();
                    let request = bh_account::directory::prepare_entry(
                        owner.verified(&cap).unwrap(),
                        &personal,
                        device,
                        &DirectoryEntry::DeviceName { device, name },
                        1,
                    )
                    .unwrap();
                    request
                        .finish(ordinary.sign(request.signing_bytes()))
                        .unwrap()
                })
            })
            .await
            .unwrap();
        let entry = bh_account::owner::staging::directory_entry_id(&bytes).unwrap();
        hosted.edge.put_directory_entry(app.log(), entry, 1, bytes);
    }
    fn id(&self) -> DeviceId {
        self.keys.id()
    }
    /// Its request to remove `target`, at `app`'s verified head.
    fn request_removal(&self, app: &App, target: DeviceId) -> Vec<u8> {
        let account = app.signer().current_account().unwrap();
        let request = account.request_removal(self.id(), target).unwrap();
        request
            .finish(self.control.sign(request.signing_bytes()))
            .unwrap()
            .as_bytes()
            .to_vec()
    }
}

/// Start the app again on the files and keys under `dir`. The last run's
/// files can stay held for a moment after it quits, which shows as `Retry`
/// (files busy): start again until they are free, for at most 10 s.
async fn restart(dir: &Path, store: &FakeStore) -> (Arc<bh_device::Owner>, Host, Screen) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let owner = Arc::new(bh_device::Owner::default());
        let (host, screen) = fresh_test_host(&owner, dir, store.clone()).await;
        if screen != Screen::Retry || tokio::time::Instant::now() >= deadline {
            return (owner, host, screen);
        }
        drop((host, owner));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signup_publishes_a_password_check_once() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let dir = tempfile::tempdir().unwrap();
    // The kit is saved; the app quits before its first sync.
    let owner = Arc::new(bh_device::Owner::default());
    drop(ready_test_host(&owner, dir.path(), store.clone()).await);
    drop(owner);
    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready);
    let app = App::start(&hosted, owner, host).await;
    until(60, "home done", || {
        app.seen.last().is_some_and(|v| v.home == Some("done"))
    })
    .await;
    until(60, "base, name and check written", || {
        hosted.edge.directory(app.log()).len() == 3
    })
    .await;
    let checks: Vec<_> = app
        .directory(&hosted)
        .await
        .into_iter()
        .filter_map(|entry| match entry {
            DirectoryEntry::PasswordCheck { check, .. } => Some(check),
            _ => None,
        })
        .collect();
    let [check] = checks.as_slice() else {
        panic!("one check: {}", checks.len());
    };
    bh_account::recovery::verify_password(check, &Password::new(PASSWORD).unwrap())
        .expect("the signup password's check");
    let written = hosted.edge.directory_writes.load(Ordering::SeqCst);
    assert_eq!(written, 3);
    app.read_directory(&hosted).await;
    assert_eq!(hosted.edge.directory_writes.load(Ordering::SeqCst), written);

    // Started again: nothing is written again.
    app.quit().await;
    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready);
    let app = App::start(&hosted, owner, host).await;
    app.read_directory(&hosted).await;
    assert_eq!(hosted.edge.directory_writes.load(Ordering::SeqCst), written);
    assert!(
        !app.view().password_change_needs_kit,
        "the read found the check"
    );
    app.quit().await;
}

/// The home's confirmation of account position `at`: its `latest_ms`.
async fn confirmed_latest(hosted: &Hosted, app: &App, at: u64) -> u64 {
    let originals = hosted.confirmed_account(app.log()).await;
    originals[at as usize - 1].1.as_ref().unwrap().0.latest_ms
}

/// The request's first append is ordered, then its answer is lost. The
/// device asks whether it was ordered before sending anything again, so the
/// account holds one request, and its deadline is that order's time plus
/// the wait, whenever the device learned of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_deadline_is_unchanged_by_a_lost_answer() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let before = app.appends(&hosted);
    hosted
        .edge
        .hook(Hook::DropAfterAccountAppend { then_down: false });
    let screen = app
        .run(AccountOperation::RequestRemoval {
            device: fold.id().0,
        })
        .await;
    assert_eq!(screen, Ok(Screen::Ready));
    assert_eq!(hosted.edge.hooks_left(), 0, "the answer was lost");
    assert_eq!(app.appends(&hosted), before + 1, "one request");
    let request = app.signer().current_account().unwrap().head().position;
    let pending = app.item(fold.id()).pending.unwrap();
    assert_eq!(pending.request, request);
    assert_eq!(
        pending.deadline_ms,
        confirmed_latest(&hosted, &app, request).await + WAIT
    );
    assert!(!app.item(fold.id()).can_remove, "already pending");
    app.quit().await;
}

/// Cancelling from the target of a removal is refused before any prompt or
/// request, and the target sees its pending removal with no cancel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_from_the_target_is_refused_before_any_prompt() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (_dir, app) = App::ready(&hosted, &store).await;
    // Mature by the home's time: only being the target stops the cancel.
    hosted.edge.clock.advance(WAIT);
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let at = hosted
        .edge
        .order_account(app.log(), &fold.request_removal(&app, app.this()));
    app.followed(at).await;
    let this = app.item(app.this());
    assert!(this.this_device);
    let pending = this.pending.expect("its pending removal");
    assert_eq!(pending.request, at);
    assert!(!this.can_cancel);
    let (prompts, appends) = (store.prompts(), app.appends(&hosted));
    assert_eq!(
        app.run(AccountOperation::CancelRemoval { request: at })
            .await,
        Err("not permitted")
    );
    assert_eq!(store.prompts(), prompts, "no prompt");
    assert_eq!(app.appends(&hosted), appends, "no request");
    assert!(app.signer().staged_control().unwrap().is_none());
    app.quit().await;
}

/// A removal request takes one confirmation, which also covers its copy into
/// the own base; a refused confirmation signs and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_is_signed_with_the_second_key_after_one_confirmation() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (_dir, app) = App::ready(&hosted, &store).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let request = AccountOperation::RequestRemoval {
        device: fold.id().0,
    };
    let (prompts, appends) = (store.prompts(), app.appends(&hosted));
    store.refuse_prompts.store(true, Ordering::SeqCst);
    assert_eq!(app.run(request).await, Err("not signed"));
    assert_eq!(store.prompts(), prompts + 1);
    assert!(app.signer().staged_control().unwrap().is_none());
    store.refuse_prompts.store(false, Ordering::SeqCst);
    let base = app.host.ready_parts(app.id).unwrap().own_base.id().0;
    let copies = hosted.edge.appends(base).len();
    let request = AccountOperation::RequestRemoval {
        device: fold.id().0,
    };
    assert_eq!(app.run(request).await, Ok(Screen::Ready));
    assert_eq!(store.prompts(), prompts + 2);
    assert_eq!(app.appends(&hosted), appends + 1);
    // Its copy into the own base is signed under that one confirmation.
    app.sync.wake(app.id);
    until(60, "copied", || hosted.edge.appends(base).len() > copies).await;
    assert!(!app.seen.last().unwrap().confirm);
    assert_eq!(store.prompts(), prompts + 2, "no second prompt");
    // The control was signed by this device's second key.
    let account = app.signer().current_account().unwrap();
    assert!(account.device_state(fold.id(), 0).is_ok());
    app.quit().await;
}

/// A timely cancellation confirms a ready screen and keeps the target
/// available even after the original request's deadline.
#[tokio::test(start_paused = true)]
async fn timely_cancel_shows_ready_and_keeps_the_device() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    hosted.edge.clock.advance(WAIT + 1);
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    assert_eq!(
        app.run(AccountOperation::RequestRemoval {
            device: fold.id().0
        })
        .await,
        Ok(Screen::Ready)
    );
    let pending = app.item(fold.id()).pending.unwrap();
    assert_eq!(
        app.run(AccountOperation::CancelRemoval {
            request: pending.request
        })
        .await,
        Ok(Screen::Ready)
    );
    assert!(app.item(fold.id()).pending.is_none());
    hosted
        .edge
        .clock
        .advance(pending.deadline_ms - hosted.edge.clock.now() + 1);
    assert!(app.item(fold.id()).pending.is_none());
    assert!(app.item(fold.id()).can_remove);
    app.quit().await;
}

/// Another member's removal reaches this device through its running host
/// session; the verified deadline erases locally and shows the erased screen.
#[tokio::test(start_paused = true)]
async fn remote_removal_shows_erased_screen_on_target() {
    let hosted = Hosted::new();
    let (_dir, target) = App::ready_on_shared_clock(&hosted, &FakeStore::default()).await;
    target.synced().await;
    let remover = Member::new();
    target.add(&hosted, &remover).await;
    let at = hosted.edge.order_account(
        target.log(),
        &remover.request_removal(&target, target.this()),
    );
    target.followed(at).await;
    let target_client = target.sync.handle(target.id).unwrap().client.clone();
    target_client.check_removal();
    until(30, "target sees pending remote removal", || {
        matches!(
            *target_client.removal_verdict().borrow(),
            bh_sync_client::RemovalVerdict::Pending { .. }
        )
    })
    .await;
    let bh_sync_client::RemovalVerdict::Pending { deadline_ms, .. } =
        *target_client.removal_verdict().borrow()
    else {
        unreachable!()
    };
    tokio::time::advance(Duration::from_millis(
        deadline_ms - hosted.edge.clock.now() + 1,
    ))
    .await;
    target_client.check_removal();
    until(30, "remote erasure shown", || {
        target.host.screen() == Some(Screen::Erased { unsent: 0 })
    })
    .await;
    assert_eq!(target.host.screen(), Some(Screen::Erased { unsent: 0 }));
    target.quit().await;
}

/// The host delivers a refused-change alert when a lying home certifies
/// a removal with an invalid accepted head, rather than erasing the app.
#[tokio::test(start_paused = true)]
async fn forged_removal_alert_is_visible_in_host() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app) = App::ready(&hosted, &store).await;
    app.synced().await;
    let log = app.log();
    let (id, cap) = app.host.ready_authority().unwrap();
    let signed = app
        .host
        .run_lent(id, &cap, move |owner, cap| {
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
    app.quit().await;
    hosted.edge.order_account(log, &signed);
    hosted.corrupt_accepted_account(log, true);
    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready);
    let app = App::start(&hosted, owner, host).await;
    let alerts = app.host.alerts();
    app.sync.handle(app.id).unwrap().client.check_removal();
    until(30, "refused change delivered to host", || {
        app.sync.wake(app.id);
        alerts
            .borrow()
            .iter()
            .any(|alert| alert.kind == "refused_change")
    })
    .await;
    assert!(
        app.view()
            .alerts
            .iter()
            .any(|alert| alert.kind == "refused_change")
    );
    assert_eq!(app.host.screen(), Some(Screen::Ready));
    app.quit().await;
}

/// A valid kit claim whose answer is lost records a notice but adds no
/// account event. A subscribed running host must receive that kit alert.
#[tokio::test(start_paused = true)]
async fn kit_use_notice_reaches_subscribed_host_without_opening_devices() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, mac, code) = ready_with_kit(&hosted, &store).await;
    mac.synced().await;
    until(60, "signup directory ready", || {
        hosted.edge.directory(mac.log()).len() == 3
    })
    .await;
    let log = mac.log();
    mac.quit().await;
    hosted.lose_next_recover_answer();
    let fold = Fresh::new(&hosted).await;
    assert_eq!(
        fold.recover(PASSWORD, &code).await,
        Ok(refused("unreachable", None, None))
    );
    assert_eq!(
        hosted.edge.entries(log).len(),
        3,
        "no account change delivered the notice"
    );
    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready);
    let alerts = host.alerts();
    assert!(alerts.borrow().is_empty());
    let mac = App::start(&hosted, owner, host).await;
    until(60, "kit notice durably read", || {
        mac.owner
            .shared_database(mac.id)
            .unwrap()
            .lock()
            .unwrap()
            .alerts(20)
            .unwrap()
            .iter()
            .any(|alert| alert.kind == bh_storage::AlertKind::KitUsed)
    })
    .await;
    until(60, "kit notice delivered to the running host", || {
        alerts.borrow().iter().any(|alert| alert.kind == "kit_used")
    })
    .await;
    assert!(alerts.borrow().iter().any(|alert| alert.kind == "kit_used"));
    mac.quit().await;
}

/// A full notice page commits 64 alerts before the next page's network
/// failure. The first page still reaches a subscribed host immediately.
#[tokio::test(start_paused = true)]
async fn committed_kit_notice_page_is_delivered_when_next_page_disconnects() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, mac, _) = ready_with_kit(&hosted, &store).await;
    mac.synced().await;
    until(60, "signup directory ready", || {
        hosted.edge.directory(mac.log()).len() == 3
    })
    .await;
    let identity = mac.signer().identity().unwrap();
    let added = mac
        .signer()
        .current_account()
        .unwrap()
        .added_at(identity.device)
        .unwrap();
    mac.quit().await;
    hosted.seed_notices(identity.account, added + 1, 64);
    hosted.drop_notices_after_first();
    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready);
    let alerts = host.alerts();
    assert!(alerts.borrow().is_empty());
    let mac = App::start(&hosted, owner, host).await;
    until(60, "first notice page kept", || {
        mac.owner
            .shared_database(mac.id)
            .unwrap()
            .lock()
            .unwrap()
            .alerts(100)
            .unwrap()
            .iter()
            .filter(|a| a.kind == bh_storage::AlertKind::KitUsed)
            .count()
            == 64
    })
    .await;
    until(60, "second notice page attempted", || {
        hosted.notice_attempts() >= 2
    })
    .await;
    until(
        30,
        "committed page delivered without the second answer",
        || {
            alerts
                .borrow()
                .iter()
                .filter(|a| a.kind == "kit_used")
                .count()
                == 64
        },
    )
    .await;
    assert_eq!(
        alerts
            .borrow()
            .iter()
            .filter(|a| a.kind == "kit_used")
            .count(),
        64
    );
    mac.quit().await;
}

/// A cancel ordered only after the removal's deadline did not cancel it:
/// the device says it already took effect, never that it was cancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lapsed_cancel_shows_took_effect() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    // This device is in the account for the wait by the home's time.
    hosted.edge.clock.advance(WAIT);
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    assert_eq!(
        app.run(AccountOperation::RequestRemoval {
            device: fold.id().0
        })
        .await,
        Ok(Screen::Ready)
    );
    let pending = app.item(fold.id());
    assert!(pending.can_cancel);
    let request = pending.pending.unwrap().request;
    // The cancel is staged while the home is out of reach, and reaches it
    // only after the deadline.
    hosted.go_down();
    let cancel = tokio::spawn({
        let (host, sync) = (app.host.clone(), app.sync.clone());
        async move { devices::run(&host, &sync, AccountOperation::CancelRemoval { request }).await }
    });
    until(60, "cancel staged", || {
        app.signer()
            .staged_control()
            .unwrap()
            .is_some_and(|staged| staged.kind == 7)
    })
    .await;
    hosted.edge.clock.advance(WAIT + 1);
    hosted.come_up();
    app.sync.wake(app.id);
    let screen = tokio::time::timeout(Duration::from_secs(120), cancel)
        .await
        .expect("settled")
        .unwrap();
    assert_eq!(screen, Ok(Screen::CancelTookEffect));
    app.quit().await;
}

/// Removing this device first sends its unsent work, then the verified
/// removal erases the account here; told not to, it reports what was not
/// sent. A failed erasure step is shown, never success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_self_sends_unsent_work_first_unless_told_not_to() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    app.synced().await;
    let held = hosted.edge.hold_next_stage();
    save(&app, "an edit not sent yet", 1);
    let removing = tokio::spawn({
        let (host, sync) = (app.host.clone(), app.sync.clone());
        async move {
            devices::run(
                &host,
                &sync,
                AccountOperation::RemoveSelf {
                    without_sync: false,
                },
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(60), held.arrived)
        .await
        .unwrap()
        .unwrap();
    let log = app.log();
    let appends = hosted.edge.appends(log.id).len();
    assert!(!removing.is_finished());
    assert!(app.signer().staged_control().unwrap().is_none(), "waits");
    held.release.send(()).unwrap();
    let screen = tokio::time::timeout(Duration::from_secs(120), removing)
        .await
        .expect("erased")
        .unwrap();
    assert_eq!(screen, Ok(Screen::Erased { unsent: 0 }));
    assert_eq!(hosted.edge.appends(log.id).len(), appends + 1);
}

/// Removed without sending first, the account is erased here, and the edit
/// the home never accepted is reported as not sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erased_screen_reports_unsent() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app) = App::ready(&hosted, &store).await;
    // The home refuses the edit each time, retryably: it stays unsent, and
    // nothing the removal asks waits behind it.
    app.synced().await;
    let base = app.host.ready_parts(app.id).unwrap().own_base.id().0;
    let before = hosted.edge.appends(base).len();
    hosted
        .edge
        .refuse_next_event(bh_sync::wire::Refusal::Reclaiming);
    save(&app, "an edit never sent", 1);
    until(60, "edit refused", || {
        hosted.edge.appends(base).len() > before
    })
    .await;
    let screen = app
        .run(AccountOperation::RemoveSelf { without_sync: true })
        .await;
    assert_eq!(screen, Ok(Screen::Erased { unsent: 1 }));
    assert!(store.keys.lock().unwrap().is_empty(), "keys erased");
    assert!(
        std::fs::read_dir(dir.path().join("accounts"))
            .unwrap()
            .all(|entry| !entry.unwrap().path().to_string_lossy().ends_with(".sqlite"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_erase_is_shown_honestly() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (_dir, app) = App::ready(&hosted, &store).await;
    store.fail_erase.store(true, Ordering::SeqCst);
    let screen = app
        .run(AccountOperation::RemoveSelf { without_sync: true })
        .await;
    assert_eq!(screen, Ok(Screen::EraseIncomplete { failed: 1 }));
    assert!(!store.keys.lock().unwrap().is_empty(), "keys kept");
}

/// Save an edit and wait until the receiver accepted it from its echo.
async fn edit_accepted(app: &App, hosted: &Hosted, request: u8) {
    let base = app.host.ready_parts(app.id).unwrap().own_base.id().0;
    let before = hosted.edge.appends(base).len();
    save(app, "an edit", request);
    until(60, "edit appended", || {
        hosted.edge.appends(base).len() > before
    })
    .await;
    // Unaccepted from here until its echo is read.
    let appended = app.seen.posts.lock().unwrap().len();
    until(60, "edit accepted", || {
        app.seen.posts.lock().unwrap()[appended..]
            .iter()
            .any(|v| v.state == "synced" && v.pending == 0)
    })
    .await;
}

/// Save one paragraph in the home note, as the editor does.
fn save(app: &App, text: &str, request: u8) {
    let window = "main";
    app.owner.open_home(window, app.id).unwrap();
    let note = app.owner.bound_note(window).unwrap();
    let opened = app.owner.open_leased(window, note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = bh_device::Owner::core_author(&opened).unwrap();
    let delta = author.try_append_paragraph(text).unwrap();
    app.owner
        .commit_leased(
            window,
            opened.generation,
            lease.token,
            [request; 16],
            &delta,
        )
        .unwrap();
    app.sync.wake(app.id);
}

/// Each new alert reaches whoever watches, with the names of the devices it
/// is about, once: not again to a later watcher, nor after a restart. The
/// list under Your devices keeps them all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alerts_are_delivered_once_with_names() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app) = App::ready(&hosted, &store).await;
    let alerts = app.host.alerts();
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    fold.name_itself(&app, &hosted, "Pixel 10 Pro Fold").await;
    app.read_directory(&hosted).await;
    assert_eq!(
        app.run(AccountOperation::RequestRemoval {
            device: fold.id().0
        })
        .await,
        Ok(Screen::Ready)
    );
    until(60, "two alerts", || alerts.borrow().len() == 2).await;
    let delivered = alerts.borrow().clone();
    let kinds: Vec<_> = delivered.iter().map(|alert| alert.kind).collect();
    assert_eq!(
        kinds,
        ["removal_requested", "device_added_by_qr"],
        "newest first"
    );
    let requested = &delivered[0];
    assert_eq!(requested.subject_name.as_deref(), Some("Pixel 10 Pro Fold"));
    assert_eq!(requested.actor_name.as_deref(), Some("MacBook Pro"));
    assert!(requested.deadline_ms.is_some());
    assert_eq!(delivered[1].actor_name.as_deref(), Some("MacBook Pro"));
    // A later watcher gets nothing new; the list keeps both, named.
    let later = app.host.alerts();
    assert_eq!(*later.borrow(), delivered);
    let listed = app.view().alerts;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].subject_name.as_deref(), Some("Pixel 10 Pro Fold"));
    app.quit().await;

    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready);
    let app = App::start(&hosted, owner, host).await;
    let alerts = app.host.alerts();
    app.read_directory(&hosted).await;
    assert!(alerts.borrow().is_empty(), "not delivered again");
    assert_eq!(app.view().alerts.len(), 2);
    app.quit().await;
}

/// An alert about a device whose name this run has not read waits for a
/// read of the names, and is then delivered once, named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alerts_wait_for_names_this_run_has_not_read() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app) = App::ready(&hosted, &store).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    fold.name_itself(&app, &hosted, "Pixel 10 Pro Fold").await;
    app.quit().await;

    let (owner, host, _) = restart(dir.path(), &store).await;
    let app = App::start(&hosted, owner, host).await;
    let alerts = app.host.alerts();
    until(60, "the addition alerted", || {
        app.sync.wake(app.id);
        !alerts.borrow().is_empty()
    })
    .await;
    let delivered = alerts.borrow().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].kind, "device_added_by_qr");
    assert_eq!(
        delivered[0].subject_name.as_deref(),
        Some("Pixel 10 Pro Fold")
    );
    app.quit().await;
}

const NEW_PASSWORD: &str = "copper lantern velvet river pebble";

/// A wrong current password is refused on this device, from the check it
/// holds or reads from the directory: no prompt, nothing staged or sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_password_refuses_a_wrong_current_password_locally() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (dir, app) = App::ready(&hosted, &store).await;
    until(60, "check written", || {
        hosted.edge.directory(app.log()).len() == 3
    })
    .await;
    let change = || AccountOperation::ChangePassword {
        current: "willow nectar horizon amber ripple".into(),
        new: Some(NEW_PASSWORD.into()),
        code: None,
    };
    let (prompts, appends) = (store.prompts(), app.appends(&hosted));
    assert_eq!(app.run(change()).await, Err("wrong password"));
    assert_eq!(store.prompts(), prompts, "no prompt");
    assert!(app.signer().staged_control().unwrap().is_none());
    assert_eq!(app.appends(&hosted), appends);

    // Started again, the check is read from the directory first.
    app.quit().await;
    let (owner, host, _) = restart(dir.path(), &store).await;
    let app = App::start(&hosted, owner, host).await;
    let reads = hosted.edge.directory_reads.load(Ordering::SeqCst);
    assert_eq!(app.run(change()).await, Err("wrong password"));
    assert!(hosted.edge.directory_reads.load(Ordering::SeqCst) > reads);
    assert_eq!(store.prompts(), prompts, "no prompt");
    assert!(app.signer().staged_control().unwrap().is_none());
    assert_eq!(app.appends(&hosted), appends);
    app.quit().await;
}

/// The new kit is shown after one confirmation and kept until the person
/// saves it, across a restart; its replacement is not sent before then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_password_keeps_the_new_kit_until_saved_across_restart() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (dir, app) = App::ready(&hosted, &store).await;
    let (prompts, appends) = (store.prompts(), app.appends(&hosted));
    let screen = app
        .run(AccountOperation::ChangePassword {
            current: PASSWORD.into(),
            new: Some(NEW_PASSWORD.into()),
            code: None,
        })
        .await
        .unwrap();
    let Screen::NewKit { code } = screen.clone() else {
        panic!("{screen:?}");
    };
    assert_eq!(store.prompts(), prompts + 1, "one confirmation");
    let staged = app.signer().staged_control().unwrap().unwrap();
    assert_eq!(staged.kind, 8);
    assert!(staged.sealed_kit.is_some(), "the kit, until saved");
    assert_eq!(app.host.screen(), Some(screen.clone()));
    // Later passes do not send it: each edit is accepted from its echo,
    // which the receiver's next pass reads before its trust lane runs.
    for request in 1..=2 {
        edit_accepted(&app, &hosted, request).await;
    }
    assert_eq!(app.appends(&hosted), appends, "not sent before it is saved");

    let log = app.log();
    app.quit().await;
    let (owner, host, again) = restart(dir.path(), &store).await;
    assert_eq!(again, Screen::NewKit { code }, "shown again");
    assert_eq!(hosted.edge.appends(log.id).len(), appends);
    // Saved with no sync running (it starts only once the account is
    // ready); sync then sends the replacement, and one rotation follows.
    let idle = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    assert_eq!(
        devices::run(&host, &idle, AccountOperation::ConfirmNewKit).await,
        Ok(Screen::Ready)
    );
    assert_eq!(store.prompts(), prompts + 1, "saving prompts nothing");
    drop(idle);
    let app = App::start(&hosted, owner, host).await;
    until(60, "the replacement and one rotation", || {
        app.sync.wake(app.id);
        app.appends(&hosted) == appends + 2
    })
    .await;
    app.quit().await;
}

/// Order `fold`'s request to remove `app`'s device at the home directly, as
/// another device's control would be: it takes the position `app` staged a
/// control for.
fn compete(hosted: &Hosted, app: &App, fold: &Member) -> u64 {
    let request = fold.request_removal(app, app.this());
    hosted.edge.order_account(app.log(), &request)
}

async fn change_password(app: &App) -> Screen {
    app.run(AccountOperation::ChangePassword {
        current: PASSWORD.into(),
        new: Some(NEW_PASSWORD.into()),
        code: None,
    })
    .await
    .unwrap()
}

/// No kit-not-changed alert is kept: saving the kit said so instead.
fn no_kit_alert(app: &App) -> bool {
    app.view()
        .alerts
        .iter()
        .all(|alert| alert.kind != "kit_not_changed")
}

/// Another device's event takes the replacement's position while its new
/// kit shows: the kit shown is dropped, saving it is not reported as a
/// change, and the old recovery key stays the account's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_lost_while_its_kit_shows_is_not_saved() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let before = app.signer().current_account().unwrap();
    assert!(matches!(change_password(&app).await, Screen::NewKit { .. }));
    let at = compete(&hosted, &app, &fold);
    app.followed(at).await;
    until(60, "the kit no longer shows", || {
        app.sync.wake(app.id);
        !matches!(app.host.screen(), Some(Screen::NewKit { .. }))
    })
    .await;
    assert_eq!(
        app.run(AccountOperation::ConfirmNewKit).await,
        Err("kit not changed")
    );
    assert!(app.signer().staged_control().unwrap().is_none());
    assert!(no_kit_alert(&app), "told on saving, not again");
    let account = app.signer().current_account().unwrap();
    assert_eq!(
        account.record_digest(),
        before.record_digest(),
        "the old kit"
    );
    app.quit().await;
}

/// Change the password, and have `fold`'s event take the replacement's
/// position while its new kit shows, unsaved.
async fn lose_unsaved_kit(app: &App, hosted: &Hosted, fold: &Member) {
    until(60, "check written", || {
        hosted.edge.directory(app.log()).len() == 3
    })
    .await;
    assert!(matches!(change_password(app).await, Screen::NewKit { .. }));
    let at = compete(hosted, app, fold);
    app.followed(at).await;
    until(60, "the kit no longer shows", || {
        app.sync.wake(app.id);
        !matches!(app.host.screen(), Some(Screen::NewKit { .. }))
    })
    .await;
    app.approve_copy().await;
}

/// A kit lost unsaved says nothing about a later change: that one's
/// replacement is taken, and saving again is not a lost kit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_kit_is_not_reported_for_a_later_change() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    lose_unsaved_kit(&app, &hosted, &fold).await;
    let before = app.signer().current_account().unwrap();
    assert!(matches!(change_password(&app).await, Screen::NewKit { .. }));
    assert_eq!(
        app.run(AccountOperation::ConfirmNewKit).await,
        Ok(Screen::Ready)
    );
    let account = app.signer().current_account().unwrap();
    assert_ne!(account.record_digest(), before.record_digest(), "new kit");
    assert_eq!(
        app.run(AccountOperation::ConfirmNewKit).await,
        Err("not permitted")
    );
    app.quit().await;
}

/// A kit lost unsaved, then a later change's kit saved and sync stopped
/// before its replacement settles: it is sent when sync runs again, not
/// reported unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_kit_is_not_reported_when_a_later_save_stops() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    lose_unsaved_kit(&app, &hosted, &fold).await;
    assert!(matches!(change_password(&app).await, Screen::NewKit { .. }));
    hosted.go_down();
    let saving = tokio::spawn({
        let (host, sync) = (app.host.clone(), app.sync.clone());
        async move { devices::run(&host, &sync, AccountOperation::ConfirmNewKit).await }
    });
    until(60, "kit cleared", || {
        app.signer()
            .staged_control()
            .unwrap()
            .is_some_and(|staged| staged.kind == 8 && staged.sealed_kit.is_none())
    })
    .await;
    app.sync.shutdown_all().await;
    let saved = tokio::time::timeout(Duration::from_secs(60), saving)
        .await
        .expect("stopped")
        .unwrap();
    assert_eq!(saved, Err("sync unavailable"));
    assert_eq!(app.host.screen(), Some(Screen::Ready));
    app.quit().await;
}

/// The kit is saved while the home is out of reach, and another device's
/// event takes the replacement's position before it is sent: saving
/// reports the kit not changed once history settles it, never success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_lost_after_its_kit_is_saved_is_reported() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let before = app.signer().current_account().unwrap();
    change_password(&app).await;
    hosted.go_down();
    let saving = tokio::spawn({
        let (host, sync) = (app.host.clone(), app.sync.clone());
        async move { devices::run(&host, &sync, AccountOperation::ConfirmNewKit).await }
    });
    until(60, "kit cleared", || {
        app.signer()
            .staged_control()
            .unwrap()
            .is_some_and(|staged| staged.kind == 8 && staged.sealed_kit.is_none())
    })
    .await;
    compete(&hosted, &app, &fold);
    hosted.come_up();
    app.sync.wake(app.id);
    let saved = tokio::time::timeout(Duration::from_secs(120), saving)
        .await
        .expect("settled")
        .unwrap();
    assert_eq!(saved, Err("kit not changed"));
    assert_eq!(app.host.screen(), Some(Screen::Ready));
    assert!(no_kit_alert(&app), "told on saving, not again");
    let account = app.signer().current_account().unwrap();
    assert_eq!(account.record_digest(), before.record_digest());
    app.quit().await;
}

/// The kit is saved after a restart with no sync running, and another
/// device's event takes the replacement's position before sync starts: the
/// loss reaches the person as one alert on this device, and the old kit is
/// still the account's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_lost_after_a_saved_kit_and_restart_is_alerted() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app) = App::ready(&hosted, &store).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let before = app.signer().current_account().unwrap();
    assert!(matches!(change_password(&app).await, Screen::NewKit { .. }));
    let competing = fold.request_removal(&app, app.this());
    let log = app.log();
    app.quit().await;

    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert!(matches!(screen, Screen::NewKit { .. }), "{screen:?}");
    let idle = SyncHost::with_transport(
        Configured::Ready(endpoint(&hosted)),
        owner.clone(),
        hosted.connector(),
        hosted.relay(),
    );
    assert_eq!(
        devices::run(&host, &idle, AccountOperation::ConfirmNewKit).await,
        Ok(Screen::Ready)
    );
    drop(idle);
    let at = hosted.edge.order_account(log, &competing);
    let app = App::start(&hosted, owner, host).await;
    let alerts = app.host.alerts();
    app.followed(at).await;
    app.approve_copy().await;
    until(60, "the replacement settled", || {
        app.sync.wake(app.id);
        app.signer().staged_control().unwrap().is_none()
    })
    .await;
    let not_changed = |list: &[devices::AlertItem]| {
        list.iter()
            .filter(|alert| alert.kind == "kit_not_changed")
            .count()
    };
    let delivered_not_changed = |list: &[devices::DeliveredAlert]| {
        list.iter()
            .filter(|alert| alert.kind == "kit_not_changed")
            .count()
    };
    // Kept as history settles it, and listed under Your devices.
    assert_eq!(not_changed(&app.view().alerts), 1, "listed");
    until(60, "the loss delivered", || {
        app.sync.wake(app.id);
        delivered_not_changed(&alerts.borrow()) > 0
    })
    .await;
    app.read_directory(&hosted).await;
    assert_eq!(delivered_not_changed(&alerts.borrow()), 1, "delivered once");
    assert_eq!(delivered_not_changed(&app.host.alerts().borrow()), 1);
    let account = app.signer().current_account().unwrap();
    assert_eq!(
        account.record_digest(),
        before.record_digest(),
        "the old kit"
    );
    assert_eq!(app.host.screen(), Some(Screen::Ready));
    app.quit().await;
}

/// Another device's event takes this device's removal's position: removing
/// it fails, at once, rather than waiting for an erasure that never comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_self_removal_fails_without_waiting() {
    let hosted = Hosted::new();
    let (_dir, app) = App::ready(&hosted, &FakeStore::default()).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    hosted.go_down();
    let removing = tokio::spawn({
        let (host, sync) = (app.host.clone(), app.sync.clone());
        async move {
            devices::run(
                &host,
                &sync,
                AccountOperation::RemoveSelf { without_sync: true },
            )
            .await
        }
    });
    until(60, "removal staged", || {
        app.signer()
            .staged_control()
            .unwrap()
            .is_some_and(|staged| staged.kind == 2)
    })
    .await;
    compete(&hosted, &app, &fold);
    hosted.come_up();
    app.sync.wake(app.id);
    let removed = tokio::time::timeout(Duration::from_secs(120), removing)
        .await
        .expect("settled")
        .unwrap();
    assert_eq!(removed, Err("not accepted"));
    assert_eq!(app.host.screen(), Some(Screen::Ready));
    app.quit().await;
}

/// While a control is staged, another is refused as busy before any
/// prompt; a new password this build cannot take is refused as such.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_control_is_busy_before_any_prompt() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (_dir, app) = App::ready(&hosted, &store).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let prompts = store.prompts();
    assert_eq!(
        app.run(AccountOperation::ChangePassword {
            current: PASSWORD.into(),
            new: Some(String::new()),
            code: None,
        })
        .await,
        Err("invalid password")
    );
    assert_eq!(store.prompts(), prompts, "no prompt");
    // A removal staged while the home is out of reach.
    hosted.go_down();
    let requesting = tokio::spawn({
        let (host, sync) = (app.host.clone(), app.sync.clone());
        let device = fold.id().0;
        async move { devices::run(&host, &sync, AccountOperation::RequestRemoval { device }).await }
    });
    until(60, "request staged", || {
        app.signer()
            .staged_control()
            .unwrap()
            .is_some_and(|staged| staged.kind == 5)
    })
    .await;
    let prompts = store.prompts();
    // Bounded: a second request that went ahead would wait for the home.
    let busy = |operation| tokio::time::timeout(Duration::from_secs(60), app.run(operation));
    assert_eq!(
        busy(AccountOperation::RequestRemoval {
            device: fold.id().0
        })
        .await,
        Ok(Err("busy"))
    );
    assert_eq!(
        busy(AccountOperation::ChangePassword {
            current: PASSWORD.into(),
            new: Some(NEW_PASSWORD.into()),
            code: None,
        })
        .await,
        Ok(Err("busy"))
    );
    assert_eq!(store.prompts(), prompts, "no prompt");
    assert_eq!(app.signer().staged_control().unwrap().unwrap().kind, 5);
    requesting.abort();
    app.quit().await;
}

/// A removal staged and not yet ordered shows as submitting, after a
/// restart too, and cannot be asked for again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_staged_removal_shows_submitting_across_restart() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app) = App::ready(&hosted, &store).await;
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    assert!(!app.item(fold.id()).submitting);
    hosted.go_down();
    let requesting = tokio::spawn({
        let (host, sync) = (app.host.clone(), app.sync.clone());
        let device = fold.id().0;
        async move { devices::run(&host, &sync, AccountOperation::RequestRemoval { device }).await }
    });
    until(60, "request staged", || {
        app.signer()
            .staged_control()
            .unwrap()
            .is_some_and(|staged| staged.kind == 5)
    })
    .await;
    let item = app.item(fold.id());
    assert!(item.submitting && !item.can_remove);
    requesting.abort();
    app.quit().await;
    let (owner, host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready);
    let app = App::start(&hosted, owner, host).await;
    let item = app.item(fold.id());
    assert!(item.submitting && !item.can_remove && item.pending.is_none());
    assert!(!app.item(app.this()).submitting);
    app.quit().await;
}

fn replacement_position(staged: &bh_account::journal::StagedControl) -> u64 {
    bh_account::AccountEvent::decode(&staged.event)
        .unwrap()
        .head()
        .position
}

/// The account's container database, opened beside the app's own handle.
fn raw(dir: &Path) -> rusqlite::Connection {
    let file = std::fs::read_dir(dir.join("accounts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|x| x == "sqlite"))
        .unwrap();
    rusqlite::Connection::open(file).unwrap()
}

/// Once the kit is saved, the replacement travels as its recovery record
/// and the personal key's seal to the new recovery key, with no body; the
/// home takes it, the personal key rotates once, the kit change is alerted,
/// and the new password's check is written under the new key alone. The
/// saved kit is not shown again after a restart, and the home no longer
/// knows the old kit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_recovery_rotates_and_retires_the_old_kit() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app, old_kit) = ready_with_kit(&hosted, &store).await;
    until(60, "signup check written", || {
        hosted.edge.directory(app.log()).len() == 3
    })
    .await;
    let alerts = app.host.alerts();
    let before = app.signer().current_account().unwrap();
    let appends = app.appends(&hosted);
    let screen = app
        .run(AccountOperation::ChangePassword {
            current: PASSWORD.into(),
            new: Some(NEW_PASSWORD.into()),
            code: None,
        })
        .await
        .unwrap();
    assert!(matches!(screen, Screen::NewKit { .. }));
    let replacement = app.signer().staged_control().unwrap().unwrap();
    assert_eq!(
        app.run(AccountOperation::ConfirmNewKit).await,
        Ok(Screen::Ready)
    );
    assert_eq!(app.host.screen(), Some(Screen::Ready));
    until(60, "rotated", || {
        app.signer()
            .current_account()
            .is_ok_and(|account| account.personal_public().ok() != before.personal_public().ok())
    })
    .await;
    let account = app.signer().current_account().unwrap();
    assert_ne!(account.record_digest(), before.record_digest());
    assert_eq!(
        app.appends(&hosted),
        appends + 2,
        "the replacement and one rotation"
    );
    assert_eq!(
        account.head().position,
        replacement_position(&replacement) + 1
    );
    until(60, "kit change alerted", || {
        alerts
            .borrow()
            .iter()
            .any(|alert| alert.kind == "kit_changed")
    })
    .await;
    // The base entry, the name and the check under the new key.
    until(60, "new key's entries written", || {
        hosted.edge.directory(app.log()).len() == 6
    })
    .await;
    let checks: Vec<_> = app
        .directory(&hosted)
        .await
        .into_iter()
        .filter_map(|entry| match entry {
            DirectoryEntry::PasswordCheck { check, .. } => Some(check),
            _ => None,
        })
        .collect();
    let [check] = checks.as_slice() else {
        panic!("one check under the new key: {}", checks.len());
    };
    bh_account::recovery::verify_password(check, &Password::new(NEW_PASSWORD).unwrap())
        .expect("the new password's check");
    until(60, "rotation settled", || {
        app.signer().staged_control().unwrap().is_none()
    })
    .await;
    app.quit().await;
    let (_owner, _host, again) = restart(dir.path(), &store).await;
    assert_eq!(again, Screen::Ready, "a saved kit is not shown again");
    let other = Fresh::new(&hosted).await;
    assert_eq!(
        other.recover(PASSWORD, &old_kit).await,
        Ok(refused("not_recognised", None, None)),
        "the old kit is retired"
    );
}

/// Saving the kit clears it from the staged replacement in one step: a
/// crash at any point leaves the replacement staged, with or without its
/// kit, never gone. A crash after a first of two writes is stood in for by
/// refusing any write that would stage the replacement again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saving_the_kit_cannot_lose_its_replacement() {
    let hosted = Hosted::new();
    let store = FakeStore::default();
    let (dir, app) = App::ready(&hosted, &store).await;
    let before = app.signer().current_account().unwrap();
    app.run(AccountOperation::ChangePassword {
        current: PASSWORD.into(),
        new: Some(NEW_PASSWORD.into()),
        code: None,
    })
    .await
    .unwrap();
    let replacement = app.signer().staged_control().unwrap().unwrap();
    raw(dir.path())
        .execute_batch(
            "CREATE TRIGGER no_restage BEFORE INSERT ON staged_account_control \
             WHEN NEW.kind = 8 BEGIN SELECT RAISE(ABORT, 'crashed'); END;",
        )
        .unwrap();
    let saved = app.run(AccountOperation::ConfirmNewKit).await;
    // Read the stage before the account: the stage is settled away only
    // once verified history holds the replacement.
    let staged = app.signer().staged_control().unwrap();
    let account = app.signer().current_account().unwrap();
    match staged {
        Some(staged) => assert!(
            staged
                == bh_account::journal::StagedControl {
                    sealed_kit: None,
                    ..replacement.clone()
                },
            "the same replacement, without its kit"
        ),
        None => assert!(
            account.head().position >= replacement_position(&replacement)
                && account.record_digest() != before.record_digest(),
            "the replacement is lost"
        ),
    }
    assert_eq!(saved, Ok(Screen::Ready));
    until(60, "replaced", || {
        app.signer()
            .current_account()
            .is_ok_and(|account| account.record_digest() != before.record_digest())
    })
    .await;
    app.quit().await;
}

// ---- Recovery with the password and kit, and removal with the kit ----

/// A fresh install as `bh_host` builds it, with the build's transport.
fn idle_sync(hosted: &Arc<Hosted>, owner: &Arc<bh_device::Owner>) -> SyncHost {
    SyncHost::with_transport(
        Configured::Ready(endpoint(hosted)),
        owner.clone(),
        hosted.connector(),
        hosted.relay(),
    )
}

/// A signed up device as `App::ready` makes one, through the setup window,
/// and the text of the recovery kit it saved.
async fn ready_with_kit(
    hosted: &Arc<Hosted>,
    store: &FakeStore,
) -> (tempfile::TempDir, App, String) {
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(bh_device::Owner::default());
    let (host, screen) = fresh_test_host(&owner, dir.path(), store.clone()).await;
    assert_eq!(screen, Screen::Welcome);
    let idle = idle_sync(hosted, &owner);
    let pairing = PairingHost::default();
    let Ok(Screen::Kit { code }) = pairing
        .setup_screen(
            "main",
            &host,
            &idle,
            AccountOperation::Create(PASSWORD.into()),
        )
        .await
    else {
        panic!("signup shows the kit");
    };
    assert_eq!(
        pairing
            .setup_screen("main", &host, &idle, AccountOperation::ConfirmKit)
            .await,
        Ok(Screen::Ready)
    );
    drop(idle);
    let app = App::start(hosted, owner, host).await;
    until(60, "home done", || {
        app.seen.last().is_some_and(|v| v.home == Some("done"))
    })
    .await;
    (dir, app, code)
}

fn refused(reason: &'static str, tries_left: Option<u8>, next_try_ms: Option<u64>) -> Screen {
    Screen::RecoverRefused {
        reason,
        tries_left,
        next_try_ms,
    }
}

/// A device with no account of its own yet, at Welcome or `Recover`.
struct Fresh {
    dir: tempfile::TempDir,
    owner: Arc<bh_device::Owner>,
    host: Host,
    sync: SyncHost,
    store: FakeStore,
}
impl Fresh {
    async fn new(hosted: &Arc<Hosted>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let (host, screen) = fresh_test_host(&owner, dir.path(), store.clone()).await;
        assert_eq!(screen, Screen::Welcome);
        Self {
            sync: idle_sync(hosted, &owner),
            dir,
            owner,
            host,
            store,
        }
    }
    /// As the setup window recovers with the password and kit.
    async fn recover(&self, password: &str, code: &str) -> Result<Screen, &'static str> {
        self.recover_with(&PairingHost::default(), password, code)
            .await
    }
    /// As `recover`, through the setup window's `pairing`.
    async fn recover_with(
        &self,
        pairing: &PairingHost,
        password: &str,
        code: &str,
    ) -> Result<Screen, &'static str> {
        bounded(
            "recovery",
            pairing.setup_screen(
                "main",
                &self.host,
                &self.sync,
                AccountOperation::Recover {
                    password: password.into(),
                    code: code.into(),
                },
            ),
        )
        .await
    }
    /// Quit and start again on the same files: the screen it starts on.
    async fn restart(self, hosted: &Arc<Hosted>) -> (Self, Screen) {
        let Self {
            dir,
            store,
            sync,
            host,
            owner,
        } = self;
        sync.shutdown_all().await;
        drop((sync, host, owner));
        let (owner, host, screen) = restart(dir.path(), &store).await;
        let fresh = Self {
            sync: idle_sync(hosted, &owner),
            dir,
            owner,
            host,
            store,
        };
        (fresh, screen)
    }
    /// The recovered account's app, its notes open and syncing.
    async fn start(self, hosted: &Arc<Hosted>, model: &str) -> (tempfile::TempDir, App) {
        let Self {
            dir,
            sync,
            host,
            owner,
            ..
        } = self;
        drop(sync);
        (dir, App::start_as(hosted, owner, host, model).await)
    }
}

/// Count the home's answers to recovery claims, and alter released ones
/// while `corrupt` is set, as a home that lies about the record would.
fn count_recovery_answers(hosted: &Hosted) -> (Arc<AtomicUsize>, Arc<AtomicBool>) {
    let (answers, corrupt) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    let (counted, corrupting) = (answers.clone(), corrupt.clone());
    hosted.tamper_recovery(Some(Box::new(move |answer| {
        counted.fetch_add(1, Ordering::SeqCst);
        if corrupting.load(Ordering::SeqCst)
            && let bh_authz::proto::RecoveryAnswer::Released { record, .. } = answer
        {
            record[40] ^= 1;
        }
    })));
    (answers, corrupt)
}

/// The note `note`'s text on `app`.
fn note_text(app: &App, note: [u8; 32]) -> Vec<u8> {
    app.owner.show_note("recovered", app.id, note).unwrap();
    let opened = app.owner.open_leased("recovered", note).unwrap();
    bh_device::Owner::core_author(&opened)
        .unwrap()
        .state()
        .unwrap()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Write a note on `app` and wait until it is sent and accepted.
async fn written_and_lost(hosted: &Hosted, app: App) -> [u8; 32] {
    edit_accepted(&app, hosted, 1).await;
    let note = app.owner.bound_note("main").unwrap();
    app.quit().await;
    note
}

/// With no device of the account left, a fresh install recovers it with
/// the password and kit: the account opens, its notes are downloaded, and
/// the new device names itself in the directory, as any device does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovered_device_opens_its_notes_and_names_itself() {
    let hosted = Hosted::new();
    let (_mac_dir, mac, code) = ready_with_kit(&hosted, &FakeStore::default()).await;
    let log = mac.log();
    let note = written_and_lost(&hosted, mac).await;
    let fold = Fresh::new(&hosted).await;
    assert_eq!(fold.recover(PASSWORD, &code).await, Ok(Screen::Recovered));
    assert_eq!(fold.host.screen(), Some(Screen::Ready));
    let (dir, app) = fold.start(&hosted, "Pixel 10 Pro Fold").await;
    assert_eq!(app.log(), log);
    until(60, "note downloaded", || {
        contains(&note_text(&app, note), "an edit")
    })
    .await;
    let this = app.this();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let named = app.directory(&hosted).await.into_iter().any(|entry| {
            matches!(entry, DirectoryEntry::DeviceName { device, name }
                if device == this && name == "Pixel 10 Pro Fold")
        });
        if named {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out: named");
        app.sync.wake(app.id);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let store = app.host.ready_parts(app.id).unwrap().store;
    app.quit().await;
    let (_owner, _host, screen) = restart(dir.path(), &store).await;
    assert_eq!(screen, Screen::Ready, "an account like any other");
}

/// The stages a join by QR shows once its device is admitted, in order
/// (`pairing::bootstrap_joined`).
const JOIN_STAGES: [&str; 3] = ["admitted", "bootstrapping", "ready"];

/// While it runs, a recovery shows the same stages as a join by QR: the
/// account is open here, its own base downloads with counts, then it is
/// ready, as the operation answers `Recovered`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_shows_a_joins_download_stages() {
    let hosted = Hosted::new();
    let (_mac_dir, mac, code) = ready_with_kit(&hosted, &FakeStore::default()).await;
    written_and_lost(&hosted, mac).await;
    let fold = Fresh::new(&hosted).await;
    let pairing = PairingHost::default();
    assert_eq!(pairing.recovery_status("main"), None);
    // The download's first read past the base's genesis is answered once
    // the download shows.
    let mut held = Some(hosted.edge.hold_next_read_after(1).release);
    let mut shown: Vec<bh_host::pairing::JoinStatus> = Vec::new();
    let recovering = fold.recover_with(&pairing, PASSWORD, &code);
    tokio::pin!(recovering);
    let screen = loop {
        tokio::select! {
            screen = &mut recovering => break screen,
            () = tokio::time::sleep(Duration::from_millis(5)) => {
                if let Some(status) = pairing.recovery_status("main")
                    && shown.last() != Some(&status)
                {
                    if status.state == "bootstrapping"
                        && let Some(release) = held.take()
                    {
                        release.send(()).unwrap();
                    }
                    shown.push(status);
                }
            }
        }
    };
    assert_eq!(screen, Ok(Screen::Recovered));
    assert!(held.is_none(), "the download was shown while it waited");
    let ready = pairing.recovery_status("main").expect("ready");
    assert_eq!(ready.state, "ready");
    shown.push(ready);
    let mut states: Vec<&str> = shown.iter().map(|status| status.state).collect();
    states.dedup();
    assert!(states.contains(&"bootstrapping"), "{states:?}");
    assert!(
        states.is_sorted_by_key(|state| JOIN_STAGES.iter().position(|s| s == state)),
        "{states:?}"
    );
    assert!(
        states.iter().all(|state| JOIN_STAGES.contains(state)),
        "{states:?}"
    );
    let downloading = shown
        .iter()
        .filter(|status| status.state != "admitted")
        .collect::<Vec<_>>();
    assert!(
        downloading
            .iter()
            .all(|status| status.done.is_some() && status.total.is_some()),
        "counts, as a join shows: {downloading:?}"
    );
}

/// Each answer the home gives is shown as it is: an unknown kit uses no
/// try, a wrong password shows the tries left, then when the next try is
/// allowed; an unreachable home can be asked again. What the home released
/// and does not verify is refused at once, never asked again unseen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recover_refused_maps_each_service_answer() {
    let hosted = Hosted::new();
    let (_mac_dir, mac, code) = ready_with_kit(&hosted, &FakeStore::default()).await;
    mac.quit().await;
    let (answers, corrupt) = count_recovery_answers(&hosted);
    let fold = Fresh::new(&hosted).await;
    let other = bh_account::recovery::RecoveryCode::generate().to_kit_text();
    assert_eq!(
        fold.recover(PASSWORD, &other).await,
        Ok(refused("not_recognised", None, None))
    );
    assert_eq!(answers.load(Ordering::SeqCst), 1);
    let wrong = "willow nectar horizon amber ripple";
    for left in (1..=4).rev() {
        assert_eq!(
            fold.recover(wrong, &code).await,
            Ok(refused("password", Some(left), None))
        );
    }
    let Ok(Screen::RecoverRefused {
        reason: "password",
        tries_left: Some(0),
        next_try_ms: Some(next),
    }) = fold.recover(wrong, &code).await
    else {
        panic!("the fifth wrong password says when to try again");
    };
    assert_eq!(
        fold.recover(PASSWORD, &code).await,
        Ok(refused("wait", None, Some(next)))
    );
    hosted.go_down();
    assert_eq!(
        fold.recover(PASSWORD, &code).await,
        Ok(refused("unreachable", None, None))
    );
    hosted.come_up();
    hosted
        .edge
        .clock
        .advance(next - hosted.edge.clock.now() + 1);
    corrupt.store(true, Ordering::SeqCst);
    let asked = answers.load(Ordering::SeqCst);
    assert_eq!(fold.recover(PASSWORD, &code).await, Err("not verified"));
    assert_eq!(answers.load(Ordering::SeqCst), asked + 1, "asked once");
    assert_eq!(fold.host.screen(), Some(Screen::Welcome));
}

/// A recovery the home stops answering in its last step keeps its
/// progress: started again, the device asks for the password and kit, and
/// recovery finishes on the device it already added.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_recovery_restarts_at_recover() {
    let hosted = Hosted::new();
    let (_mac_dir, mac, code) = ready_with_kit(&hosted, &FakeStore::default()).await;
    let log = mac.log();
    let note = written_and_lost(&hosted, mac).await;
    let fold = Fresh::new(&hosted).await;
    // The copy into the own base commits; its answer is lost and the home
    // goes away.
    hosted.edge.hook(Hook::DropAfterAppend { then_down: true });
    assert_eq!(
        fold.recover(PASSWORD, &code).await,
        Ok(refused("unreachable", None, None))
    );
    let added = hosted.edge.appends(log.id).len();
    // A reload asks for them again too, as a restart does.
    assert_eq!(
        PairingHost::default()
            .setup_screen("main", &fold.host, &fold.sync, AccountOperation::Startup)
            .await,
        Ok(Screen::Recover)
    );
    let (fold, screen) = fold.restart(&hosted).await;
    assert_eq!(screen, Screen::Recover);
    hosted.come_up();
    assert_eq!(fold.recover(PASSWORD, &code).await, Ok(Screen::Recovered));
    assert_eq!(hosted.edge.appends(log.id).len(), added, "no second device");
    let (_dir, app) = fold.start(&hosted, "Pixel 10 Pro Fold").await;
    until(60, "note downloaded", || {
        contains(&note_text(&app, note), "an edit")
    })
    .await;
    app.quit().await;
}

/// Wait until `app`'s personal key is no longer `before`'s.
async fn rotated(app: &App, before: &bh_account::VerifiedAccount) {
    until(60, "rotated", || {
        app.sync.wake(app.id);
        app.signer()
            .current_account()
            .is_ok_and(|account| account.personal_public().ok() != before.personal_public().ok())
    })
    .await;
}

/// A device in the account for the wait removes another at once with the
/// password and kit: one confirmation, and the removed device is gone at
/// once, by the home's time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_now_with_kit_from_a_mature_device_takes_effect_at_once() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (_dir, app, code) = ready_with_kit(&hosted, &store).await;
    hosted.edge.clock.advance(WAIT);
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    assert!(app.item(fold.id()).can_remove_now);
    let before = app.signer().current_account().unwrap();
    let base = app.host.ready_parts(app.id).unwrap().own_base.id().0;
    let copies = hosted.edge.appends(base).len();
    let (prompts, appends) = (store.prompts(), app.appends(&hosted));
    assert_eq!(
        app.run(AccountOperation::RemoveNow {
            device: fold.id().0,
            password: PASSWORD.into(),
            code: code.clone(),
        })
        .await,
        Ok(Screen::Ready)
    );
    assert_eq!(store.prompts(), prompts + 1, "one confirmation");
    assert!(app.appends(&hosted) > appends);
    let hex: String = fold.id().0.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        app.view().devices.iter().all(|item| item.id_hex != hex),
        "removed at once"
    );
    // Its copy into the own base is signed under that one confirmation, and
    // its protection is renewed with no other prompt.
    until(60, "copied", || {
        app.sync.wake(app.id);
        hosted.edge.appends(base).len() > copies
    })
    .await;
    rotated(&app, &before).await;
    assert!(
        !app.seen.last().unwrap().confirm,
        "nothing waits for the person"
    );
    assert_eq!(store.prompts(), prompts + 1, "no second prompt");
    app.quit().await;
}

/// A device not yet in the account for the wait cannot remove another at
/// once: refused before any prompt, kit check or request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_now_from_a_recent_device_is_refused_before_signing() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (_dir, app, code) = ready_with_kit(&hosted, &store).await;
    let (answers, _) = count_recovery_answers(&hosted);
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    assert!(!app.item(fold.id()).can_remove_now);
    let (prompts, appends) = (store.prompts(), app.appends(&hosted));
    assert_eq!(
        app.run(AccountOperation::RemoveNow {
            device: fold.id().0,
            password: PASSWORD.into(),
            code,
        })
        .await,
        Err("not permitted")
    );
    assert_eq!(store.prompts(), prompts, "no prompt");
    assert_eq!(answers.load(Ordering::SeqCst), 0, "no kit check");
    assert_eq!(app.appends(&hosted), appends, "no request");
    assert!(app.signer().staged_control().unwrap().is_none());
    app.quit().await;
}

/// A kit the home does not know, or a wrong password, is shown as the
/// home's answer, and nothing is asked of the person or signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_now_with_a_wrong_kit_prompts_nothing() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (_dir, app, code) = ready_with_kit(&hosted, &store).await;
    hosted.edge.clock.advance(WAIT);
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    let (prompts, appends) = (store.prompts(), app.appends(&hosted));
    let remove = |password: &str, code: String| AccountOperation::RemoveNow {
        device: fold.id().0,
        password: password.into(),
        code,
    };
    let other = bh_account::recovery::RecoveryCode::generate().to_kit_text();
    assert_eq!(
        app.run(remove(PASSWORD, other)).await,
        Ok(refused("not_recognised", None, None))
    );
    assert_eq!(
        app.run(remove("willow nectar horizon amber ripple", code))
            .await,
        Ok(refused("password", Some(4), None))
    );
    assert_eq!(store.prompts(), prompts, "no prompt");
    assert_eq!(app.appends(&hosted), appends, "nothing sent");
    assert!(app.signer().staged_control().unwrap().is_none());
    assert!(app.item(fold.id()).pending.is_none());
    app.quit().await;
}

/// An account whose password check was lost (the home's directory has
/// none, and no device holds it) changes its password only with the kit
/// as well, checked by the home: a wrong kit or password prompts nothing,
/// the right ones give the new kit after one confirmation. A rotation
/// writes no check either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_password_without_a_check_needs_the_kit_and_uses_the_home_check() {
    let hosted = Hosted::new();
    let store = FakeStore::gated();
    let (dir, app, code) = ready_with_kit(&hosted, &store).await;
    let log = app.log();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let check = 'written: loop {
        assert!(tokio::time::Instant::now() < deadline, "timed out: check");
        app.sync.wake(app.id);
        for (entry, _, bytes) in hosted.edge.directory(log) {
            let opened = app.signer().open_directory_entries(vec![bytes]).await;
            if let Ok([Ok(opened)]) = opened.as_deref()
                && matches!(opened.entry, DirectoryEntry::PasswordCheck { .. })
            {
                break 'written entry;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    hosted.edge.clock.advance(WAIT);
    let fold = Member::new();
    app.add(&hosted, &fold).await;
    // The home loses the check while the app is not running; started
    // again, this run holds none and finds none.
    app.quit().await;
    hosted.edge.remove_directory_entry(log, check);
    let (owner, host, _) = restart(dir.path(), &store).await;
    let app = App::start(&hosted, owner, host).await;
    // Known once the host has taken a read: none holds a check for the
    // current record.
    until(60, "no check after restart", || {
        app.view().password_change_needs_kit
    })
    .await;
    let before = app.signer().current_account().unwrap();
    assert_eq!(
        app.run(AccountOperation::RemoveNow {
            device: fold.id().0,
            password: PASSWORD.into(),
            code: code.clone(),
        })
        .await,
        Ok(Screen::Ready)
    );
    rotated(&app, &before).await;
    app.read_directory(&hosted).await;
    until(60, "none after the rotation", || {
        app.view().password_change_needs_kit
    })
    .await;
    let (answers, _) = count_recovery_answers(&hosted);
    let change = |current: &str, code: Option<String>| AccountOperation::ChangePassword {
        current: current.into(),
        new: Some(NEW_PASSWORD.into()),
        code,
    };
    let prompts = store.prompts();
    assert_eq!(app.run(change(PASSWORD, None)).await, Err("needs kit"));
    let other = bh_account::recovery::RecoveryCode::generate().to_kit_text();
    assert_eq!(
        app.run(change(PASSWORD, Some(other))).await,
        Ok(refused("not_recognised", None, None))
    );
    assert_eq!(
        app.run(change(
            "willow nectar horizon amber ripple",
            Some(code.clone())
        ))
        .await,
        Ok(refused("password", Some(4), None))
    );
    assert_eq!(answers.load(Ordering::SeqCst), 2, "the home checked each");
    assert_eq!(store.prompts(), prompts, "no prompt");
    assert!(app.signer().staged_control().unwrap().is_none());
    let screen = app.run(change(PASSWORD, Some(code))).await.unwrap();
    assert!(matches!(screen, Screen::NewKit { .. }), "{screen:?}");
    assert_eq!(answers.load(Ordering::SeqCst), 3);
    assert_eq!(store.prompts(), prompts + 1, "one confirmation");
    assert_eq!(app.signer().staged_control().unwrap().unwrap().kind, 8);
    app.quit().await;
}

/// After a rotation, the own base's current key comes only with an
/// admission this build cannot read yet: recovery says it cannot reach
/// recovery now, keeps the device it added, and asks again on restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_after_a_rotation_waits_as_unreachable_and_keeps_its_progress() {
    let hosted = Hosted::new();
    let (_mac_dir, mac, code) = ready_with_kit(&hosted, &FakeStore::default()).await;
    until(60, "signup entries written", || {
        hosted.edge.directory(mac.log()).len() == 3
    })
    .await;
    hosted.edge.clock.advance(WAIT);
    let member = Member::new();
    mac.add(&hosted, &member).await;
    let before = mac.signer().current_account().unwrap();
    assert_eq!(
        mac.run(AccountOperation::RemoveNow {
            device: member.id().0,
            password: PASSWORD.into(),
            code: code.clone(),
        })
        .await,
        Ok(Screen::Ready)
    );
    rotated(&mac, &before).await;
    until(60, "rekeyed and rewritten", || {
        mac.sync.wake(mac.id);
        hosted.edge.directory(mac.log()).len() == 6
    })
    .await;
    let log = mac.log();
    mac.quit().await;
    let fold = Fresh::new(&hosted).await;
    assert_eq!(
        fold.recover(PASSWORD, &code).await,
        Ok(refused("unreachable", None, None))
    );
    let added = hosted.edge.appends(log.id).len();
    let (fold, screen) = fold.restart(&hosted).await;
    assert_eq!(screen, Screen::Recover);
    assert_eq!(
        fold.recover(PASSWORD, &code).await,
        Ok(refused("unreachable", None, None))
    );
    assert_eq!(hosted.edge.appends(log.id).len(), added, "the same device");
}
