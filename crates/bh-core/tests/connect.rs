//! Connecting an app by approval through the local Worker: the app types an
//! email, shows digits, and a full device types them and chooses the grant.

use bh_core::{
    Account, AccountEvent, AppChoice, AppOffer, ApprovalId, BaseGrantRequest, BaseId, Clock, Core,
    CoreConfig, DeviceId, DeviceKind, Digits, EndReason, Error, FileSecretStore, Mode, RequestKind,
    SecretStore,
};
use bh_testkit::{
    LocalServer, app_identity, approve_next_app, device, device_with_clock, found_under,
    new_signup, note_with_text, pending_device_for, random_id, raw_device, two_devices,
    wait_for_base,
};
use serde_json::json;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::oneshot;

const WAIT: Duration = Duration::from_secs(30);

#[track_caller]
fn wait<T>(future: impl Future<Output = T>) -> impl Future<Output = T> {
    let caller = std::panic::Location::caller();
    async move {
        tokio::time::timeout(WAIT, future)
            .await
            .unwrap_or_else(|_| panic!("connection wait exceeded 30 s at {caller}"))
    }
}

fn defaults(offer: &AppOffer) -> AppChoice {
    AppChoice {
        bases: offer
            .bases
            .iter()
            .map(|grant| BaseGrantRequest::Existing {
                base: grant.base,
                mode: grant.mode,
            })
            .collect(),
        cap_micro_usd: offer.cap_micro_usd,
        replaces: None,
    }
}

fn server() -> bh_core::Url {
    LocalServer::from_env().url()
}

fn other(digits: &Digits) -> Digits {
    Digits::parse(if digits.as_str() == "000000" {
        "000001"
    } else {
        "000000"
    })
    .unwrap()
}

/// A full device whose account has "Personal", then "Work".
async fn full_with_bases() -> (Account, BaseId) {
    let (full, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let personal = full.create_base("Personal").await.unwrap();
    full.create_base("Work").await.unwrap();
    (full, personal.id())
}

async fn device_ids(full: &Account) -> Vec<DeviceId> {
    let mut ids: Vec<_> = full
        .devices()
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    ids.sort();
    ids
}

/// Runs a whole connection, the app on `app` and the approval on `full`.
async fn connect(
    full: &Account,
    app: &Core,
    email: &str,
    choose: impl FnOnce(&AppOffer) -> AppChoice + Send + 'static,
) -> (Account, DeviceId) {
    let mut pending = app
        .start_connection(server(), email, app_identity())
        .await
        .unwrap();
    let (tx, rx) = oneshot::channel();
    let approver = tokio::spawn({
        let full = full.clone();
        async move { approve_next_app(&full, rx, choose).await }
    });
    let digits = wait(pending.digits()).await.unwrap();
    tx.send(digits).unwrap();
    let account = wait(pending.wait()).await.unwrap();
    let device = wait(approver).await.unwrap().unwrap();
    (account, device)
}

async fn device_request(full: &Account) -> ApprovalId {
    let pending = pending_device_for(full).await;
    let id = ApprovalId::random();
    let (status, body) = pending
        .post("/v1/approvals", json!({"approvalId": id, "request": "AQ"}))
        .await;
    assert!(status.is_success(), "{body}");
    id
}

#[tokio::test]
async fn an_app_connects_with_typed_digits() {
    let (full, personal) = full_with_bases().await;
    let (app, device) = connect(&full, &device("phone"), &full.email(), defaults).await;
    assert_eq!(app.device_id(), device);
    assert_eq!(app.kind(), DeviceKind::App);
    assert_eq!(
        app.bases()
            .iter()
            .map(|b| (b.id, b.mode))
            .collect::<Vec<_>>(),
        vec![(personal, Mode::ReadWrite)]
    );
    let written = app
        .base(personal)
        .unwrap()
        .create(bh_testkit::note())
        .unwrap();
    app.base(personal).unwrap().flush().await.unwrap();
    let on_full = full.base(personal).unwrap();
    wait_for_base(&on_full, || on_full.get(written).unwrap().is_some()).await;
    let local = full.email().split('@').next().unwrap().to_string();
    let you = local[..1].to_uppercase() + &local[1..];
    let listed = full.devices().await.unwrap();
    let listed = listed.iter().find(|d| d.id == device).unwrap();
    assert_eq!(listed.name, format!("{you} - Sample"));
    assert_eq!(listed.kind, DeviceKind::App);
    assert_eq!(listed.cap_micro_usd, Some(1_000_000));
    let apps = full.apps();
    let entry = apps.iter().find(|a| a.device_id == device).unwrap();
    assert_eq!(entry.app_id.as_deref(), Some("app.basehero.sample"));
}

#[tokio::test]
async fn an_app_approved_after_rotation_reads_old_and_new_notes() {
    let (full, personal) = full_with_bases().await;
    let base = full.base(personal).unwrap();
    let old = note_with_text(&base, "before rotation");
    base.flush().await.unwrap();
    full.test_rotate_account(None).await.unwrap();
    let (app, _) = connect(&full, &device("phone"), &full.email(), defaults).await;
    let new = note_with_text(&base, "after rotation");
    base.flush().await.unwrap();
    let reader = app.base(personal).unwrap();
    wait_for_base(&reader, || {
        reader.note(old).is_ok() && reader.note(new).is_ok()
    })
    .await;
    let ring = app
        .test_secrets()
        .get(&format!("acct.{}.appkey", app.id()))
        .unwrap()
        .unwrap();
    assert_eq!(u32::from_be_bytes(ring[..4].try_into().unwrap()), 2);
}

#[tokio::test]
async fn an_app_connected_by_approval_has_its_public_key_recorded() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let full_dir = tempfile::tempdir().unwrap();
    let full_secrets = Arc::new(FileSecretStore::new(full_dir.path().join("secrets")).unwrap());
    let full_core = Core::open(CoreConfig {
        data_dir: full_dir.path().join("data"),
        secrets: full_secrets.clone(),
    })
    .unwrap();
    let (full, _) = full_core
        .sign_up(bh_core::SignUp {
            device_name: "mac".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    full.create_base("Personal").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let secrets = Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap());
    let core = Core::open(CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: secrets.clone(),
    })
    .unwrap();
    let (app, id) = connect(&full, &core, &full.email(), defaults).await;
    let seed = secrets
        .get(&format!("acct.{}.kem", app.id()))
        .unwrap()
        .unwrap();
    let public = URL_SAFE_NO_PAD.encode(
        bh_crypto::KemKey::from_seed(&bh_crypto::Secret::<32>::from_slice(&seed).unwrap()).public(),
    );
    let dbkey = full
        .test_secrets()
        .get(&format!("acct.{}.dbkey", full.id()))
        .unwrap()
        .unwrap();
    let db = full_dir
        .path()
        .join("data/accounts")
        .join(full.id().to_string())
        .join("account.sqlite");
    let dump = bh_testkit::inspect::dump_store(&db, &dbkey);
    assert!(
        dump.contains(&public),
        "approver must record the requesting app's public key"
    );
    assert!(
        !dump.contains(&URL_SAFE_NO_PAD.encode(&seed)),
        "the approving device must not retain the requesting app's seed"
    );
    assert!(
        dump.contains(&id.to_string()),
        "approver must record the app device ID"
    );
    assert!(
        full.test_secrets()
            .get(&format!("acct.{}.kem", full.id()))
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_email_typed_differently_still_connects() {
    let (full, personal) = full_with_bases().await;
    let typed = format!(" {} ", full.email().to_uppercase());
    let (app, _) = connect(&full, &device("phone"), &typed, defaults).await;
    assert_eq!(app.id(), full.id());
    assert_eq!(app.bases()[0].id, personal);
}

#[tokio::test]
async fn the_request_reads_an_app_wants_to_connect_until_the_digits_match() {
    let (full, _) = full_with_bases().await;
    let mut events = full.events();
    let app = device("phone");
    let mut pending = app
        .start_connection(server(), &full.email(), app_identity())
        .await
        .unwrap();
    let id = pending.id();
    let heard = wait(async {
        loop {
            if let Ok(AccountEvent::ApprovalRequested(request)) = events.recv().await
                && request.id == id
            {
                break request;
            }
        }
    })
    .await;
    assert_eq!(heard.kind, RequestKind::App);
    let listed = full.approval_requests().await.unwrap();
    let listed = listed.iter().find(|r| r.id == id).unwrap();
    assert_eq!(listed, &heard);
    for shown in [
        serde_json::to_string(&heard).unwrap(),
        serde_json::to_string(listed).unwrap(),
    ] {
        assert!(!shown.contains("Sample") && !shown.contains("app.basehero"));
    }
    assert!(matches!(
        full.open_request(id).await,
        Err(Error::Invalid(_))
    ));
    let other = device_request(&full).await;
    assert!(matches!(
        full.open_app_request(other).await,
        Err(Error::Invalid(_))
    ));
    let listed = full.approval_requests().await.unwrap();
    assert!(
        listed
            .iter()
            .any(|r| r.id == id && r.kind == RequestKind::App)
    );
    assert!(
        listed
            .iter()
            .any(|r| r.id == other && r.kind == RequestKind::Device)
    );
    let (mut open, digits) =
        wait(async { tokio::try_join!(full.open_app_request(id), pending.digits()) })
            .await
            .unwrap();
    let offer = open.check_digits(&digits).await.unwrap();
    assert_eq!(
        (offer.name.as_str(), offer.app_id.as_str()),
        ("Sample", "app.basehero.sample")
    );
}

#[tokio::test]
async fn wrong_digits_end_it_for_both_and_register_nothing() {
    let (full, _) = full_with_bases().await;
    let before = device_ids(&full).await;
    let app = device("phone");
    let mut pending = app
        .start_connection(server(), &full.email(), app_identity())
        .await
        .unwrap();
    let (mut open, digits) =
        wait(async { tokio::try_join!(full.open_app_request(pending.id()), pending.digits()) })
            .await
            .unwrap();
    assert_eq!(
        open.check_digits(&other(&digits)).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::WrongDigits)
    );
    assert_eq!(
        wait(pending.wait()).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::WrongDigits)
    );
    assert_eq!(device_ids(&full).await, before);
    drop(open);
    let (account, _) = connect(&full, &app, &full.email(), defaults).await;
    assert_eq!(account.id(), full.id());
}

#[tokio::test]
async fn a_late_approval_leaves_no_app_device() {
    let (clock, manual) = Clock::manual();
    let (full, _) = device_with_clock("mac", &clock)
        .sign_up(new_signup())
        .await
        .unwrap();
    full.create_base("Personal").await.unwrap();
    let before = device_ids(&full).await;
    let app = device_with_clock("phone", &clock);
    let mut pending = app
        .start_connection(server(), &full.email(), app_identity())
        .await
        .unwrap();
    let (mut open, digits) =
        wait(async { tokio::try_join!(full.open_app_request(pending.id()), pending.digits()) })
            .await
            .unwrap();
    let offer = open.check_digits(&digits).await.unwrap();
    manual.advance(Duration::from_secs(120));
    assert_eq!(
        full.approve_app(open, defaults(&offer)).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Expired)
    );
    assert_eq!(device_ids(&full).await, before);
    assert_eq!(
        pending.wait().await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Expired)
    );
}

#[tokio::test]
async fn two_devices_cannot_both_answer_an_app() {
    let (a, b) = two_devices().await;
    a.create_base("Personal").await.unwrap();
    b.refresh().await.unwrap();
    let app = device("phone");
    let mut pending = app
        .start_connection(server(), &a.email(), app_identity())
        .await
        .unwrap();
    let id = pending.id();
    let (first, second, digits) = wait(async {
        tokio::join!(
            a.open_app_request(id),
            b.open_app_request(id),
            pending.digits()
        )
    })
    .await;
    assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
    let (winner, open, lost) = match (first, second) {
        (Ok(open), lost) => (&a, open, lost),
        (lost, Ok(open)) => (&b, open, lost),
        _ => unreachable!(),
    };
    assert!(matches!(
        lost,
        Err(Error::ApprovalEnded(EndReason::AlreadyAnswered))
    ));
    let mut open = open;
    let offer = open.check_digits(&digits.unwrap()).await.unwrap();
    winner.approve_app(open, defaults(&offer)).await.unwrap();
    wait(pending.wait()).await.unwrap();
}

#[tokio::test]
async fn the_app_can_cancel_and_the_device_can_decline() {
    let (full, _) = full_with_bases().await;
    let app = device("phone");
    let mut pending = app
        .start_connection(server(), &full.email(), app_identity())
        .await
        .unwrap();
    let (mut open, digits) =
        wait(async { tokio::try_join!(full.open_app_request(pending.id()), pending.digits()) })
            .await
            .unwrap();
    pending.cancel().await.unwrap();
    assert_eq!(
        open.check_digits(&digits).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Cancelled)
    );
    let mut declined = app
        .start_connection(server(), &full.email(), app_identity())
        .await
        .unwrap();
    full.decline(declined.id()).await.unwrap();
    assert_eq!(
        wait(declined.digits()).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Declined)
    );
}

#[tokio::test]
async fn an_unanswered_request_expires_on_the_app() {
    let (clock, manual) = Clock::manual();
    let app = device_with_clock("phone", &clock);
    let email = format!("{}@example.test", random_id());
    let mut pending = app
        .start_connection(server(), &email, app_identity())
        .await
        .unwrap();
    let digits = tokio::spawn(async move { pending.digits().await });
    // Polling until an answer is covered by the tests where the approver answers.
    manual.advance(Duration::from_secs(120));
    assert_eq!(
        wait(digits).await.unwrap().unwrap_err(),
        Error::ApprovalEnded(EndReason::Expired)
    );
}

#[tokio::test]
async fn hidden_bases_are_never_offered_or_granted() {
    let (full, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let hidden = full
        .create_hidden_base(
            "Private",
            zeroize::Zeroizing::new("ferry lantern quartz".into()),
        )
        .await
        .unwrap();
    let personal = full.create_base("Personal").await.unwrap();
    let before = device_ids(&full).await;
    let app = device("phone");
    let mut pending = app
        .start_connection(server(), &full.email(), app_identity())
        .await
        .unwrap();
    let (mut open, digits) =
        wait(async { tokio::try_join!(full.open_app_request(pending.id()), pending.digits()) })
            .await
            .unwrap();
    let offer = open.check_digits(&digits).await.unwrap();
    assert_eq!(
        offer.bases.iter().map(|g| g.base).collect::<Vec<_>>(),
        vec![personal.id()]
    );
    let choice = AppChoice {
        bases: vec![BaseGrantRequest::Existing {
            base: hidden.id(),
            mode: Mode::ReadWrite,
        }],
        ..defaults(&offer)
    };
    assert_eq!(
        full.approve_app(open, choice).await.unwrap_err(),
        Error::Forbidden
    );
    assert_eq!(device_ids(&full).await, before);
    assert!(wait(pending.wait()).await.is_err());
}

#[tokio::test]
async fn the_app_never_gets_the_account_key() {
    bh_testkit::local_only!(); // Reads the local device's files.
    let (full, _) = full_with_bases().await;
    let temp = tempfile::tempdir().unwrap();
    let secrets = Arc::new(FileSecretStore::new(temp.path().join("secrets")).unwrap());
    let app = Core::open(CoreConfig {
        data_dir: temp.path().join("data"),
        secrets: secrets.clone(),
    })
    .unwrap();
    let (account, _) = connect(&full, &app, &full.email(), defaults).await;
    let key = full
        .test_secrets()
        .get(&format!("acct.{}.key", full.id()))
        .unwrap()
        .unwrap();
    assert!(!found_under(temp.path(), &key));
    assert!(
        secrets
            .get(&format!("acct.{}.key", account.id()))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_new_base_and_a_cap_can_be_chosen() {
    let (full, _) = full_with_bases().await;
    let (app, device) = connect(&full, &device("phone"), &full.email(), |_| AppChoice {
        bases: vec![BaseGrantRequest::New {
            name: "Sample readings".into(),
            mode: Mode::ReadWrite,
        }],
        cap_micro_usd: 250_000,
        replaces: None,
    })
    .await;
    let bases = app.bases();
    assert_eq!(bases.len(), 1);
    // The name is a record in the base, so it arrives by sync.
    full.base(bases[0].id).unwrap().flush().await.unwrap();
    let base = app.base(bases[0].id).unwrap();
    wait_for_base(&base, || base.name() == "Sample readings").await;
    let listed = full.devices().await.unwrap();
    assert_eq!(
        listed
            .iter()
            .find(|d| d.id == device)
            .unwrap()
            .cap_micro_usd,
        Some(250_000)
    );
}

async fn reconnect_offer(
    full: &Account,
    app: &Core,
) -> (
    bh_core::PendingConnection,
    bh_core::OpenAppRequest,
    AppOffer,
) {
    let mut pending = app
        .start_connection(server(), &full.email(), app_identity())
        .await
        .unwrap();
    let (mut open, digits) =
        wait(async { tokio::try_join!(full.open_app_request(pending.id()), pending.digits()) })
            .await
            .unwrap();
    let offer = open.check_digits(&digits).await.unwrap();
    (pending, open, offer)
}

#[tokio::test]
async fn a_reinstalled_app_gets_its_base_back() {
    let (full, _) = full_with_bases().await;
    let first = device("first install");
    let (old_app, old) = connect(&full, &first, &full.email(), |_| AppChoice {
        bases: vec![BaseGrantRequest::New {
            name: "Sample readings".into(),
            mode: Mode::ReadWrite,
        }],
        cap_micro_usd: 1_000_000,
        replaces: None,
    })
    .await;
    let base = old_app.bases()[0].id;
    let record = old_app
        .base(base)
        .unwrap()
        .create(bh_testkit::note())
        .unwrap();
    old_app.base(base).unwrap().flush().await.unwrap();
    drop(old_app);
    drop(first);
    let fresh = device("reinstalled");
    let (mut pending, open, offer) = reconnect_offer(&full, &fresh).await;
    assert_eq!(offer.old.as_ref().map(|old| old.device_id), Some(old));
    assert_eq!(
        offer.bases,
        vec![bh_core::AppGrant {
            base,
            mode: Mode::ReadWrite
        }]
    );
    assert!(!offer.remove_old);
    let (new_id, removed) = full.approve_app(open, defaults(&offer)).await.unwrap();
    assert!(!removed);
    let new_app = wait(pending.wait()).await.unwrap();
    let reopened = new_app.base(base).unwrap();
    wait_for_base(&reopened, || reopened.get(record).unwrap().is_some()).await;
    assert!(device_ids(&full).await.contains(&old));
    assert!(device_ids(&full).await.contains(&new_id));
}

#[tokio::test]
async fn an_old_connection_never_used_is_ticked_for_removal() {
    let (full, _) = full_with_bases().await;
    let first = device("first");
    let (pending, open, offer) = reconnect_offer(&full, &first).await;
    let (old, removed) = full.approve_app(open, defaults(&offer)).await.unwrap();
    assert!(!removed);
    // The app quits without accepting the transfer or using its new token.
    drop(pending);
    let old_device = full
        .devices()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.id == old)
        .unwrap();
    assert_eq!(old_device.last_seen_at, old_device.created_at);
    let fresh = device("second");
    let (_pending, _open, offer) = reconnect_offer(&full, &fresh).await;
    assert_eq!(offer.old.as_ref().map(|old| old.device_id), Some(old));
    assert!(offer.remove_old);
}

#[tokio::test]
async fn an_old_connection_unseen_for_a_week_is_ticked_for_removal() {
    bh_testkit::local_only!();
    let (full, _) = full_with_bases().await;
    let (_, old) = connect(&full, &device("old"), &full.email(), defaults).await;
    let raw = raw_device(&full);
    let now = full
        .devices()
        .await
        .unwrap()
        .iter()
        .find(|device| device.id == old)
        .unwrap()
        .last_seen_at;
    let path = "/v1/devices/test-last-seen";
    assert_eq!(
        raw.post(
            path,
            json!({"deviceId":old,"lastSeenAt":now - 6 * bh_core::approval::connect::WEEK_MS / 7})
        )
        .await
        .0,
        reqwest::StatusCode::OK
    );
    let (mut pending, open, offer) = reconnect_offer(&full, &device("new")).await;
    assert!(!offer.remove_old);
    pending.cancel().await.unwrap();
    drop(open);
    assert_eq!(
        raw.post(
            path,
            json!({"deviceId":old,"lastSeenAt":now - 8 * bh_core::approval::connect::WEEK_MS / 7})
        )
        .await
        .0,
        reqwest::StatusCode::OK
    );
    let fresh = device("replacement");
    let (mut pending, open, offer) = reconnect_offer(&full, &fresh).await;
    assert_eq!(offer.old.as_ref().map(|old| old.device_id), Some(old));
    assert!(offer.remove_old);
    let (_, removed) = full
        .approve_app(
            open,
            AppChoice {
                replaces: Some(old),
                ..defaults(&offer)
            },
        )
        .await
        .unwrap();
    assert!(removed);
    wait(pending.wait()).await.unwrap();
    assert_eq!(
        full.devices()
            .await
            .unwrap()
            .iter()
            .find(|device| device.id == old)
            .unwrap()
            .status,
        "revoked"
    );
    assert!(!full.apps().iter().any(|app| app.device_id == old));
}

#[tokio::test]
async fn the_old_connection_goes_only_after_the_transfer() {
    let (clock, manual) = Clock::manual();
    let (full, _) = device_with_clock("mac", &clock)
        .sign_up(new_signup())
        .await
        .unwrap();
    full.create_base("Personal").await.unwrap();
    let first = device_with_clock("old", &clock);
    let (_, old) = connect(&full, &first, &full.email(), defaults).await;
    let fresh = device_with_clock("new", &clock);
    let (mut pending, open, offer) = reconnect_offer(&full, &fresh).await;
    manual.advance(Duration::from_secs(120));
    assert_eq!(
        full.approve_app(
            open,
            AppChoice {
                replaces: Some(old),
                ..defaults(&offer)
            }
        )
        .await,
        Err(Error::ApprovalEnded(EndReason::Expired))
    );
    assert!(device_ids(&full).await.contains(&old));
    assert!(full.apps().iter().any(|app| app.device_id == old));
    assert_eq!(
        pending.wait().await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Expired)
    );
}

#[tokio::test]
async fn only_the_apps_old_connection_can_be_replaced() {
    let (full, _) = full_with_bases().await;
    let first = device("old");
    let (_, old) = connect(&full, &first, &full.email(), defaults).await;
    let (_pending, open, offer) = reconnect_offer(&full, &device("new")).await;
    assert_eq!(offer.old.as_ref().map(|o| o.device_id), Some(old));
    let before = device_ids(&full).await;
    // Any other device, even this one, is refused before anything is registered.
    assert!(matches!(
        full.approve_app(
            open,
            AppChoice {
                replaces: Some(full.device_id()),
                ..defaults(&offer)
            }
        )
        .await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(device_ids(&full).await, before);
}

#[tokio::test]
async fn a_failed_old_removal_keeps_the_new_app_after_transfer() {
    bh_testkit::local_only!();
    let (full, _) = full_with_bases().await;
    let (_, old) = connect(&full, &device("old"), &full.email(), defaults).await;
    let fresh = device("new");
    let (mut pending, open, offer) = reconnect_offer(&full, &fresh).await;
    assert_eq!(
        raw_device(&full)
            .post("/v1/devices/fail-next-removal", json!({}))
            .await
            .0,
        reqwest::StatusCode::OK
    );
    let (device, removed) = full
        .approve_app(
            open,
            AppChoice {
                replaces: Some(old),
                ..defaults(&offer)
            },
        )
        .await
        .unwrap();
    assert!(!removed);
    let installed = wait(pending.wait()).await.unwrap();
    assert_eq!(installed.device_id(), device);
    let listed = full.devices().await.unwrap();
    assert_eq!(
        listed.iter().find(|d| d.id == old).unwrap().status,
        "active"
    );
    assert_eq!(
        listed
            .iter()
            .find(|d| d.id == installed.device_id())
            .unwrap()
            .status,
        "active"
    );
}

#[tokio::test]
async fn the_most_recent_active_connection_is_offered() {
    bh_testkit::local_only!();
    let (full, personal) = full_with_bases().await;
    let (_, preferred) = connect(&full, &device("preferred"), &full.email(), defaults).await;
    full.set_app_cap(preferred, 3_000_000).await.unwrap();
    let (_, other) = connect(&full, &device("other"), &full.email(), |_| AppChoice {
        bases: vec![BaseGrantRequest::New {
            name: "Other".into(),
            mode: Mode::ReadOnly,
        }],
        cap_micro_usd: 500_000,
        replaces: None,
    })
    .await;
    let raw = raw_device(&full);
    let now = full
        .devices()
        .await
        .unwrap()
        .iter()
        .find(|d| d.id == other)
        .unwrap()
        .last_seen_at;
    for (id, age_days) in [(preferred, 1), (other, 2)] {
        assert_eq!(raw.post("/v1/devices/test-last-seen", json!({
            "deviceId": id, "lastSeenAt": now - age_days * bh_core::approval::connect::WEEK_MS / 7
        })).await.0, reqwest::StatusCode::OK);
    }
    let fresh = device("new");
    let (_pending, _open, offer) = reconnect_offer(&full, &fresh).await;
    assert_eq!(offer.old.as_ref().map(|old| old.device_id), Some(preferred));
    assert_eq!(
        offer.bases,
        vec![bh_core::AppGrant {
            base: personal,
            mode: Mode::ReadWrite
        }]
    );
    assert_eq!(offer.cap_micro_usd, 3_000_000);
}

#[tokio::test]
async fn the_old_cap_is_offered_again() {
    let (full, _) = full_with_bases().await;
    let (_, old) = connect(&full, &device("old"), &full.email(), defaults).await;
    full.set_app_cap(old, 3_000_000).await.unwrap();
    let fresh = device("new");
    let (_pending, _open, offer) = reconnect_offer(&full, &fresh).await;
    assert_eq!(offer.cap_micro_usd, 3_000_000);
}

#[tokio::test]
async fn devices_show_and_change_an_apps_cap() {
    let (full, _) = full_with_bases().await;
    let fresh = device("app");
    let (app, id) = connect(&full, &fresh, &full.email(), defaults).await;
    let listed = full.devices().await.unwrap();
    assert_eq!(
        listed.iter().find(|d| d.id == id).unwrap().cap_micro_usd,
        Some(1_000_000)
    );
    assert_eq!(
        listed
            .iter()
            .find(|d| d.id == full.device_id())
            .unwrap()
            .cap_micro_usd,
        None
    );
    let mut events = full.events();
    full.set_app_cap(id, 0).await.unwrap();
    assert_eq!(events.try_recv().unwrap(), AccountEvent::DevicesChanged);
    assert_eq!(
        full.devices()
            .await
            .unwrap()
            .iter()
            .find(|d| d.id == id)
            .unwrap()
            .cap_micro_usd,
        Some(0)
    );
    assert_eq!(
        full.set_app_cap(full.device_id(), 1).await,
        Err(Error::NotFound)
    );
    assert_eq!(app.set_app_cap(id, 1).await, Err(Error::Forbidden));
    let token = app
        .test_secrets()
        .get(&format!("acct.{}.token", app.id()))
        .unwrap()
        .unwrap();
    let response = reqwest::Client::new()
        .post(
            server()
                .join("/v1/models/tinfoil/v1/chat/completions")
                .unwrap(),
        )
        .header("BH-Protocol", "1")
        .bearer_auth(String::from_utf8(token.to_vec()).unwrap())
        .header("ehbp-encapsulated-key", "ab".repeat(32))
        .header("x-tinfoil-enclave-url", "https://inference.tinfoil.sh")
        .header("x-tinfoil-model", "deepseek-v4-1-flash")
        .body("opaque")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"],
        "rate_limited"
    );
}

#[tokio::test]
async fn a_disconnected_app_erases_its_copy() {
    bh_testkit::local_only!();
    let (full, _) = full_with_bases().await;
    let dir = tempfile::tempdir().unwrap();
    let app_core = Core::open(CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let (app, id) = connect(&full, &app_core, &full.email(), defaults).await;
    let account_dir = dir.path().join("data/accounts").join(app.id().to_string());
    assert!(account_dir.exists());
    let mut events = app.events();
    full.remove_device(id, bh_core::Removal::Plain)
        .await
        .unwrap();
    assert_eq!(app.refresh().await, Err(Error::Revoked));
    assert_eq!(wait(events.recv()).await.unwrap(), AccountEvent::Removed);
    assert!(app_core.accounts().is_empty());
    assert!(!account_dir.exists());
}
