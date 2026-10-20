//! QR pairing and the joining device's bootstrap against the fake hosted
//! environment: the real authorization service behind the attested channel,
//! a data edge and pairing relay that behave as the Worker does, and two
//! genuine native identities. The first device signs up; the second makes
//! its own keys, joins by the QR text alone, verifies the account and its
//! own admission from the account log, opens the personal key its addition
//! carried, reads the own base through the receiver and only then becomes
//! usable. Nothing is copied between the two devices' stores.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::{Head as AccountHead, pairing::PairError};
use bh_authz::proto::{account_log_unwrap, account_log_wrap, delivery_body};
use bh_device::join::JoinError;
use bh_sync_client::{
    Client, SyncStatus,
    bootstrap::{self, BootstrapError, Progress},
    pairing::{
        AdmissionHint, Approvals, JoiningPairing, PairingError, ShowingPairing, Side,
        parse_qr_text, resume_admission,
    },
};
use std::{
    rc::Rc,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::{
    device::{Device, store, until},
    fake::{Hook, Hosted},
    pair::Joiner,
};
use tokio::sync::watch;

type Started = (Client, watch::Receiver<SyncStatus>);

async fn registered(hosted: &Arc<Hosted>, device: &Device) -> Started {
    let started = device.start(hosted);
    until(20, "registered", || {
        device.registered() && device.progress().position >= 1
    })
    .await;
    started
}

fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

/// The first device shows a code. Its base copies controls only under an
/// approval the person gave, as a host's signer does.
fn show(hosted: &Arc<Hosted>, mac: &Device) -> (ShowingPairing, String) {
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    ShowingPairing::start(
        mac.signer.identity_account(),
        mac.signer.device_id(),
        hosted.relay(),
    )
}

/// The person approves on the first device: one control signature for the
/// addition, staged exactly, and an approval for its base copy.
async fn approve(mac: &Device, showing: &mut ShowingPairing) -> Result<(), PairingError> {
    let (mut account, capability, _) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    showing
        .stage(&mut account, &capability, &personal, &mac.signer.approvals)
        .await
}

/// The account log's originals, in order.
fn account_originals(hosted: &Hosted, mac: &Device) -> Vec<Vec<u8>> {
    hosted
        .edge
        .entries(mac.account_log)
        .iter()
        .map(|(_, event)| account_log_unwrap(event).unwrap().0.to_vec())
        .collect()
}

/// Pair a new device to `mac` end to end and bootstrap it. Returns the
/// joined device (not started) and the ordered addition's head.
async fn pair(hosted: &Arc<Hosted>, mac: &Device, mac_client: &Client) -> (Device, AccountHead) {
    let (mut showing, qr) = show(hosted, mac);
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    // The relay holds sealed bytes only: neither the joining device's keys
    // nor its label.
    for held in hosted.relay_held(Side::Join) {
        let contains = |part: &[u8]| held.windows(part.len()).any(|w| w == part);
        assert!(!contains(joiner.keys.signing()) && !contains(b"Fold"));
    }
    let candidate = showing.candidate().await.unwrap();
    assert_eq!(candidate.keys, joiner.keys);
    assert_eq!(candidate.label, b"Fold");
    approve(mac, &mut showing).await.unwrap();
    let endpoint = mac.endpoint(hosted);
    let (head, admission) = tokio::join!(
        showing.finish(mac_client),
        joining.wait_admitted(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
    );
    let head = head.unwrap();
    let admission = admission.unwrap();
    joiner.admit(&admission).await;
    (joiner.into_device(), head)
}

/// Bootstrap a joined device to the base's tail through the receiver.
async fn bootstrapped(hosted: &Arc<Hosted>, fold: &Device) {
    let (progress, _) = watch::channel(Progress::default());
    bootstrap::run(
        fold.endpoint(hosted),
        hosted.connector(),
        fold.owner.clone(),
        fold.id,
        fold.signer.clone(),
        progress,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_activates_with_held_content_without_claiming_synced() {
    let hosted = Hosted::new();
    let first = Device::new();
    let first_client = registered(&hosted, &first).await;
    let mut bomb = vec![1, 1, 1, 0, 8, 1, 4, b'b', b'o', b'm', b'b', 1];
    for _ in 0..100_000 {
        bomb.extend_from_slice(&[117, 1]);
    }
    bomb.extend_from_slice(&[126, 0]);
    let poisoned = [222; 32];
    first.remote_note(&hosted, poisoned, &bomb);
    let (joined, _) = pair(&hosted, &first, &first_client.0).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        bootstrapped(&hosted, &joined),
    )
    .await
    .unwrap();
    assert!(joined.usable());
    assert_eq!(
        joined.progress().position,
        hosted.edge.head(joined.log()).position
    );
    assert!(
        joined
            .owner
            .shared_database(joined.id)
            .unwrap()
            .lock()
            .unwrap()
            .note_is_held(joined.key(poisoned))
            .unwrap()
    );
    assert!(
        joined
            .owner
            .show_note("poisoned", joined.id, poisoned)
            .is_err()
    );
    // Receiving after activation commits under current note authority.
    joined.authorize().unwrap();
    let (client, mut status) = joined.start(&hosted);
    until(20, "post-bootstrap status", || {
        matches!(
            *status.borrow_and_update(),
            SyncStatus::Synced | SyncStatus::Syncing { pending: 0 }
        )
    })
    .await;
    assert_ne!(*status.borrow_and_update(), SyncStatus::Synced);
    client.shutdown().await;
    first_client.0.shutdown().await;
}

/// Bootstrap commits without note authority, so it runs only before
/// activation: once the container is usable it is refused and reads nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_is_refused_once_the_container_is_active() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let (fold, _) = pair(&hosted, &mac, &mac_client.0).await;
    bootstrapped(&hosted, &fold).await;
    assert!(fold.usable());
    let reads = hosted.edge.reads(mac.log()).len();
    let (progress, _) = watch::channel(Progress::default());
    let again = bootstrap::run(
        fold.endpoint(&hosted),
        hosted.connector(),
        fold.owner.clone(),
        fold.id,
        fold.signer.clone(),
        progress,
    )
    .await;
    assert_eq!(again, Err(BootstrapError::Active));
    assert_eq!(hosted.edge.reads(mac.log()).len(), reads);
    mac_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_and_bootstrap_fake_hosted() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let (writer, id) = mac.new_note("written before pairing");
    mac_client.0.wake();
    until(20, "accepted", || {
        mac.pending() == 0 && mac.acked(id).is_some()
    })
    .await;

    let (fold, head) = pair(&hosted, &mac, &mac_client.0).await;
    assert_eq!(head.position, 4);
    // Its own keys, its own store: nothing of the mac's.
    assert!(fold.signer.device_id() != mac.signer.device_id());
    assert!(!fold.usable(), "not usable before activation");
    bootstrapped(&hosted, &fold).await;
    assert!(fold.usable());
    assert_eq!(
        fold.reopened(writer.note).digest().unwrap(),
        mac.reopened(writer.note).digest().unwrap()
    );
    assert_eq!(fold.inserted(writer.note, "written before pairing"), 1);
    until(20, "addition copied", || copied(&mac) == 4).await;
    // The joined device never registered the existing base: its genesis
    // was appended once, by the mac.
    let genesis = hosted.edge.entries(mac.log())[0].1.encode();
    assert_eq!(
        hosted
            .edge
            .appends(mac.log().id)
            .iter()
            .filter(|a| **a == genesis)
            .count(),
        1
    );
    // The addition carried its delivery as the account event's body.
    let (_, added) = &hosted.edge.entries(mac.account_log)[3];
    assert!(account_log_unwrap(added).unwrap().1.is_some());
    mac_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joined_device_writes_and_first_device_receives() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let (fold, _) = pair(&hosted, &mac, &mac_client.0).await;
    bootstrapped(&hosted, &fold).await;
    until(20, "addition copied", || copied(&mac) == 4).await;
    fold.authorize().unwrap();
    let fold_client = fold.start(&hosted);
    let (writer, id) = fold.new_note("written by the joined device");
    fold_client.0.wake();
    until(20, "fold accepted", || {
        fold.pending() == 0 && fold.acked(id).is_some()
    })
    .await;
    mac_client.0.wake();
    until(20, "mac received", || {
        mac.inserted(writer.note, "written by the joined device") == 1
    })
    .await;
    assert_eq!(
        mac.reopened(writer.note).digest().unwrap(),
        fold.reopened(writer.note).digest().unwrap()
    );
    fold_client.0.shutdown().await;
    mac_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_context_signs_only_this_addition_and_its_copy() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, mut mac_status) = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let _joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    let before = store.state().sign_calls;
    showing
        .stage(&mut account, &capability, &personal, &mac.signer.approvals)
        .await
        .unwrap();
    drop(account);
    assert_eq!(
        store.state().sign_calls,
        before + 1,
        "one account signature"
    );
    showing.finish(&mac_client).await.unwrap();
    until(20, "addition copied", || copied(&mac) == 4).await;
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);

    // A later account change is not covered: its copy waits for the person.
    let requests = mac.signer.control_requests.load(Ordering::SeqCst);
    let third = Joiner::new();
    let other = mac.signer.add_device(third.keys.clone());
    hosted.edge.order_account(mac.account_log, &other);
    mac_client.wake();
    until(20, "asked", || {
        mac.signer.control_requests.load(Ordering::SeqCst) > requests
    })
    .await;
    until(20, "waits", || {
        *mac_status.borrow_and_update() == SyncStatus::WaitingAuthorization
    })
    .await;
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    assert_eq!(copied(&mac), 4);

    // The context itself: exactly one event, once, until it expires.
    let approvals = Approvals::default();
    let later = tokio::time::Instant::now() + Duration::from_secs(60);
    approvals.grant(b"addition".to_vec(), later);
    assert!(!approvals.take(b"another"));
    assert!(approvals.take(b"addition"));
    assert!(!approvals.take(b"addition"), "single use");
    approvals.grant(b"addition".to_vec(), tokio::time::Instant::now());
    assert!(!approvals.take(b"addition"), "expired");
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_before_staging_no_addition() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let _joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    showing.cancel();
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    let before = store.state().sign_calls;
    assert_eq!(
        showing
            .stage(&mut account, &capability, &personal, &mac.signer.approvals)
            .await,
        Err(PairingError::Ended)
    );
    assert_eq!(store.state().sign_calls, before, "nothing signed");
    assert!(account.staged_admission().unwrap().is_none());
    drop(account);
    mac_client.wake();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(hosted.edge.entries(mac.account_log).len(), 3);
    assert_eq!(copied(&mac), 3);
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_after_staging_orders_exact_addition() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    showing
        .stage(&mut account, &capability, &personal, &mac.signer.approvals)
        .await
        .unwrap();
    let staged = account.staged_admission().unwrap().unwrap();
    let signed = store.state().sign_calls;
    drop(account);
    // Cancelling ends the code, not the staged admission.
    showing.cancel();
    let head = showing.finish(&mac_client).await.unwrap();
    assert_eq!(head.position, staged.position);
    until(20, "copied", || copied(&mac) == 4).await;
    let originals = account_originals(&hosted, &mac);
    assert_eq!(originals.len(), 4);
    assert_eq!(originals[3], staged.event, "exactly the staged bytes");
    assert_eq!(store.state().sign_calls, signed, "never signed again");
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    // The row is settled from verified history.
    until(20, "staged row cleared", || {
        mac.signer
            .account_owner()
            .0
            .staged_admission()
            .unwrap()
            .is_none()
    })
    .await;
    // The ended code delivers nothing to the joining device.
    assert_eq!(hosted.relay_messages(Side::Show), 0);
    let waited = tokio::time::timeout(
        Duration::from_secs(2),
        joining.wait_admitted(
            &mac.endpoint(&hosted),
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        ),
    )
    .await;
    assert!(waited.is_err(), "no admission hint");
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_reply_rejected() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    // The relay alters what it serves: part of the sealed reply is
    // replaced with another device's key.
    let other = Joiner::new();
    hosted.tamper_relay(
        Side::Join,
        Box::new(move |reply: &mut Vec<u8>| {
            let keys = other.keys.clone();
            reply[24..56].copy_from_slice(keys.signing());
        }),
    );
    let _joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    let candidate = tokio::time::timeout(Duration::from_secs(2), showing.candidate()).await;
    assert!(candidate.is_err(), "no candidate from a tampered reply");
    let (mut account, capability, _) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    assert_eq!(
        showing
            .stage(&mut account, &capability, &personal, &mac.signer.approvals)
            .await,
        Err(PairingError::Pair(PairError::NoReply))
    );
    drop(account);
    assert_eq!(hosted.edge.entries(mac.account_log).len(), 3);
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_reply_ends_session() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let first = Joiner::new();
    let second = Joiner::new();
    let _a = JoiningPairing::join(&qr, first.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    let _b = JoiningPairing::join(&qr, second.keys.clone(), b"Other", hosted.relay())
        .await
        .unwrap();
    assert_eq!(
        showing.candidate().await.err(),
        Some(PairingError::Competing)
    );
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    let before = store.state().sign_calls;
    assert_eq!(
        showing
            .stage(&mut account, &capability, &personal, &mac.signer.approvals)
            .await,
        Err(PairingError::Ended)
    );
    assert_eq!(store.state().sign_calls, before);
    drop(account);
    assert_eq!(hosted.edge.entries(mac.account_log).len(), 3);
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn relay_expiry_ends_without_addition() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    // The person does not approve within the relay's five minutes.
    tokio::time::sleep(Duration::from_secs(301)).await;
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    let before = store.state().sign_calls;
    assert_eq!(
        showing
            .stage(&mut account, &capability, &personal, &mac.signer.approvals)
            .await,
        Err(PairingError::Ended)
    );
    assert_eq!(store.state().sign_calls, before);
    assert!(account.staged_admission().unwrap().is_none());
    drop(account);
    // The joining device bounds its wait the same way.
    assert_eq!(
        joining
            .wait_admitted(
                &mac.endpoint(&hosted),
                hosted.connector(),
                joiner.owner.clone(),
                joiner.id,
                joiner.prover(),
            )
            .await
            .err(),
        Some(PairingError::Ended)
    );
    assert!(!joiner.has_account());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_qr_account_rejected() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let other = Device::new();
    let (mut showing, qr) = show(&hosted, &mac);

    // A code altered to name another account: the showing device refuses
    // the reply made for it.
    let mut altered = parse_qr_text(&qr).unwrap();
    altered.account = other.signer.identity_account();
    let joiner = Joiner::new();
    let _joining = JoiningPairing::join(
        &bh_sync_client::pairing::qr_text(&altered),
        joiner.keys.clone(),
        b"Fold",
        hosted.relay(),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), showing.candidate())
            .await
            .is_err()
    );

    // A hint, authenticated with the code, naming another account's
    // genesis: refused before anything is sent or kept.
    let (_showing, qr) = show(&hosted, &mac);
    let code = parse_qr_text(&qr).unwrap();
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    let hint = AdmissionHint {
        genesis: other.originals[0].clone(),
        head: AccountHead {
            position: 3,
            hash: bh_crypto::hash(&other.originals[2]),
        },
        base: other.base.0,
        package: mac.own_base_package(),
    };
    let connects = hosted.edge.authz_connects.load(Ordering::SeqCst);
    hosted.put_relay(&code, Side::Show, 0, hint.seal(&code.relay()));
    assert_eq!(
        joining
            .wait_admitted(
                &mac.endpoint(&hosted),
                hosted.connector(),
                joiner.owner.clone(),
                joiner.id,
                joiner.prover(),
            )
            .await
            .err(),
        Some(PairingError::Invalid)
    );
    assert_eq!(hosted.edge.authz_connects.load(Ordering::SeqCst), connects);
    assert!(!joiner.has_account());
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_without_own_admission_refused() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let (_showing, qr) = show(&hosted, &mac);
    let code = parse_qr_text(&qr).unwrap();
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    // A genuine hint for the right account, but no addition was ordered:
    // relay messages alone never admit.
    let hint = AdmissionHint {
        genesis: mac.originals[0].clone(),
        head: AccountHead {
            position: 3,
            hash: bh_crypto::hash(&mac.originals[2]),
        },
        base: mac.base.0,
        package: mac.own_base_package(),
    };
    hosted.put_relay(&code, Side::Show, 0, hint.seal(&code.relay()));
    assert_eq!(
        joining
            .wait_admitted(
                &mac.endpoint(&hosted),
                hosted.connector(),
                joiner.owner.clone(),
                joiner.id,
                joiner.prover(),
            )
            .await
            .err(),
        Some(PairingError::Refused)
    );
    assert!(!joiner.has_account());
    assert!(!joiner.has_own_base());
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_interrupted_resumes() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let ids: Vec<_> = (0..130)
        .map(|n| mac.new_note(&format!("bulk {n}")).1)
        .collect();
    mac_client.0.wake();
    until(60, "mac accepted all", || {
        mac.pending() == 0 && ids.iter().all(|id| mac.acked(*id).is_some())
    })
    .await;
    let (fold, _) = pair(&hosted, &mac, &mac_client.0).await;
    until(20, "addition copied", || copied(&mac) == 4).await;
    let end = hosted.edge.head(mac.log()).position;

    // Interrupted after the first batch: the next read goes unanswered.
    hosted.edge.hold_reads_after(Some(64));
    let (progress, watching) = watch::channel(Progress::default());
    let task = tokio::spawn(bootstrap::run(
        fold.endpoint(&hosted),
        hosted.connector(),
        fold.owner.clone(),
        fold.id,
        fold.signer.clone(),
        progress,
    ));
    until(30, "first batch", || fold.progress().position == 64).await;
    until(10, "first batch reported", || watching.borrow().done == 64).await;
    task.abort();
    let _ = task.await;
    hosted.edge.hold_reads_after(None);
    let stopped = fold.progress().position;
    assert_eq!(stopped, 64);
    assert!(end > 128, "{end}");
    assert!(!fold.usable(), "not usable before activation");
    assert!(fold.authorize().is_err());

    let reads_before = hosted.edge.reads(mac.log()).len();
    let (progress, watching) = watch::channel(Progress::default());
    bootstrap::run(
        fold.endpoint(&hosted),
        hosted.connector(),
        fold.owner.clone(),
        fold.id,
        fold.signer.clone(),
        progress,
    )
    .await
    .unwrap();
    assert_eq!(fold.progress().position, end);
    assert_eq!(watching.borrow().done, end);
    let reads: Vec<_> = hosted.edge.reads(mac.log())[reads_before..].to_vec();
    assert_eq!(reads.first().map(|(first, _)| *first), Some(stopped + 1));
    assert!(reads.iter().all(|(first, _)| *first > stopped));
    assert!(fold.usable());
    fold.authorize().unwrap();
    mac_client.0.shutdown().await;
}

/// A pass that committed is followed at once by the read that confirms the
/// tail: a small base's bootstrap never idles for news it does not need.
#[tokio::test(start_paused = true)]
async fn bootstrap_confirms_the_tail_without_idling_after_a_committed_pass() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let (fold, _) = pair(&hosted, &mac, &mac_client.0).await;
    let before = hosted.edge.counts();
    let started = tokio::time::Instant::now();
    bootstrapped(&hosted, &fold).await;
    let took = started.elapsed();
    let counts = hosted.edge.counts() - before;
    assert!(fold.usable());
    assert_eq!(
        fold.progress().position,
        hosted.edge.head(mac.log()).position
    );
    // The batch's events and bodies, then one empty read that proves the tail.
    assert_eq!((counts.read_events, counts.read_batches), (1, 1));
    // The receiver's wait for news is a second; a committed pass skips it.
    assert!(took < Duration::from_millis(500), "{took:?}");
    mac_client.0.shutdown().await;
}

/// A pass that committed nothing waits for news before the next pass: an
/// empty read is not progress, so bootstrap neither spins against the
/// service nor stops before the base has a tail it can trust.
#[test]
fn bootstrap_waits_after_a_pass_that_committed_nothing() {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let failure = runtime.block_on(async {
            let hosted = Hosted::new();
            let mac = Device::new();
            let mac_client = registered(&hosted, &mac).await;
            let (fold, _) = pair(&hosted, &mac, &mac_client.0).await;
            mac_client.0.shutdown().await;
            // The base's log is empty, as one just registered but not yet
            // ordered into: the first pass commits nothing and has no tail
            // to call caught up.
            hosted.edge.forget_log(mac.log());
            let (progress, mut passes) = watch::channel(Progress::default());
            let task = tokio::spawn(bootstrap::run(
                fold.endpoint(&hosted),
                hosted.connector(),
                fold.owner.clone(),
                fold.id,
                fold.signer.clone(),
                progress,
            ));
            let before = hosted.edge.counts();
            // The first pass, then no second one until the poll has passed.
            passes.changed().await.unwrap();
            if hosted.edge.counts().read_events - before.read_events != 1 {
                return Some("the first pass read the wrong count");
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                _ = passes.changed() => return Some("passed again without waiting for news"),
            }
            // After the poll it does pass again: the wait is bounded, not a stop.
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(700)) => {
                    return Some("no pass after the poll");
                }
                _ = passes.changed() => {}
            }
            if fold.progress().position != 0 {
                return Some("the empty base committed something");
            }
            task.abort();
            let _ = task.await;
            None::<&str>
        });
        let _ = done.send(failure);
    });
    // The poll is virtual, so a loop that waits reports at once. One that
    // never yields cannot reach any timer: fail instead of hanging the suite.
    let failure = match finished.recv_timeout(Duration::from_secs(5)) {
        Ok(failure) => failure,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Some("the bootstrap never waited for news")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the bootstrap runner panicked")
        }
    };
    assert_eq!(failure, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_resumes_from_the_kept_hint() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    // Someone holding the code puts junk first on the showing side: the
    // hint goes to the next index and the joining device skips the junk.
    let code = parse_qr_text(&qr).unwrap();
    hosted.put_relay(&code, Side::Show, 0, vec![1; 64]);
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    approve(&mac, &mut showing).await.unwrap();
    let endpoint = mac.endpoint(&hosted);
    let (head, first) = tokio::join!(
        showing.finish(&mac_client.0),
        joining.wait_admitted(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
    );
    head.unwrap();
    // Interrupted before the admission was committed: verified again from
    // the kept hint, without the relay.
    drop(first.unwrap());
    assert!(!joiner.has_account());
    let resume = || {
        resume_admission(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            &joiner.keys,
            joiner.prover(),
        )
    };
    let admission = resume().await.unwrap().unwrap();
    joiner.admit(&admission).await;
    assert!(resume().await.unwrap().is_none(), "committed already");
    let fold = joiner.into_device();
    bootstrapped(&hosted, &fold).await;
    assert!(fold.usable());
    mac_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rescan_after_admission_sends_only_the_hint() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    approve(&mac, &mut showing).await.unwrap();
    let head = showing.finish(&mac_client.0).await.unwrap();
    // The joining device restarted before it read the hint: the secret is
    // gone with it. A new code for the same journaled keys needs no second
    // signature; only the hint is sent.
    drop(joining);
    let (mut showing, qr) = show(&hosted, &mac);
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    let signed = store.state().sign_calls;
    showing
        .stage(&mut account, &capability, &personal, &mac.signer.approvals)
        .await
        .unwrap();
    assert_eq!(store.state().sign_calls, signed, "nothing signed again");
    drop(account);
    let endpoint = mac.endpoint(&hosted);
    let (again, admission) = tokio::join!(
        showing.finish(&mac_client.0),
        joining.wait_admitted(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
    );
    assert_eq!(again.unwrap(), head);
    joiner.admit(&admission.unwrap()).await;
    assert_eq!(hosted.edge.entries(mac.account_log).len(), 4, "added once");
    let fold = joiner.into_device();
    bootstrapped(&hosted, &fold).await;
    assert!(fold.usable());
    mac_client.0.shutdown().await;
}

/// The staged row on the first device, if any.
fn staged_row(mac: &Device) -> Option<bh_account::journal::StagedAdmission> {
    mac.signer.account_owner().0.staged_admission().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_addition_with_lost_answer_settles_after_restart() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let appends_before = hosted.edge.appends(mac.account_log.id).len();
    let stages_before = hosted.edge.stages(mac.account_log.id).len();
    // The addition is ordered on the account log, its answer is lost and
    // the edge goes away before this device reads it back.
    hosted
        .edge
        .hook(Hook::DropAfterAccountAppend { then_down: true });
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    showing
        .stage(&mut account, &capability, &personal, &mac.signer.approvals)
        .await
        .unwrap();
    let staged = account.staged_admission().unwrap().unwrap();
    let signed = store.state().sign_calls;
    drop(account);
    mac_client.wake();
    until(20, "ordered, answer lost", || {
        hosted.edge.hooks_left() == 0 && hosted.edge.entries(mac.account_log).len() == 4
    })
    .await;
    hosted.go_down();
    // Stopped before the account owner learned of it.
    mac_client.shutdown().await;
    assert!(mac.signer.applied.lock().unwrap().is_empty());
    assert_eq!(staged_row(&mac), Some(staged.clone()));

    hosted.come_up();
    let (mac_client, _) = mac.start(&hosted);
    let endpoint = mac.endpoint(&hosted);
    let (head, admission) = tokio::join!(
        showing.finish(&mac_client),
        joining.wait_admitted(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
    );
    assert_eq!(head.unwrap().position, staged.position);
    until(20, "copied", || copied(&mac) == 4).await;
    until(20, "staged row settled", || staged_row(&mac).is_none()).await;
    // Exactly the staged bytes, ordered once; nothing signed or sent anew.
    let originals = account_originals(&hosted, &mac);
    assert_eq!(originals.len(), 4);
    assert_eq!(originals[3], staged.event);
    assert_eq!(store.state().sign_calls, signed, "never signed again");
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    let delivery = delivery_body(&staged.delivery).unwrap();
    let event = account_log_wrap(&staged.event, Some(delivery.commitment()))
        .unwrap()
        .encode();
    let appends = hosted.edge.appends(mac.account_log.id);
    assert!(appends[appends_before..].iter().all(|sent| *sent == event));
    let stages = hosted.edge.stages(mac.account_log.id);
    assert!(
        stages[stages_before..]
            .iter()
            .all(|sent| sent == delivery.bytes())
    );
    // The joining device is admitted by that addition.
    let admission = admission.unwrap();
    assert_eq!(admission.added_at, staged.position);
    joiner.admit(&admission).await;
    let fold = joiner.into_device();
    bootstrapped(&hosted, &fold).await;
    assert!(fold.usable());
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_account_event_resolves_staged_addition() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    mac_client.shutdown().await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let _joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    // Another genuine account change, made before this addition was
    // staged, is ordered at the staged position first.
    let other = mac.signer.add_device(Joiner::new().keys);
    approve(&mac, &mut showing).await.unwrap();
    let staged = staged_row(&mac).unwrap();
    assert_eq!(
        hosted.edge.order_account(mac.account_log, &other),
        staged.position
    );
    let appends_before = hosted.edge.appends(mac.account_log.id).len();

    let (mac_client, _) = mac.start(&hosted);
    until(20, "followed past the staged position", || {
        mac.signer
            .applied
            .lock()
            .unwrap()
            .iter()
            .any(|head| head.position == staged.position)
    })
    .await;
    until(20, "staged row settled", || staged_row(&mac).is_none()).await;
    let (account, capability, _) = mac.signer.account_owner();
    let verified = account.verified(&capability).unwrap();
    assert_eq!(verified.head().hash, bh_crypto::hash(&other));
    assert!(verified.active_device(joiner.keys.id()).is_err());
    drop(account);
    // Not added: the person is told, and nothing replaces it.
    assert_eq!(
        showing.finish(&mac_client).await.err(),
        Some(PairingError::Refused)
    );
    let originals = account_originals(&hosted, &mac);
    assert_eq!(originals.len(), 4);
    assert!(!originals.contains(&staged.event));
    assert_eq!(
        hosted.edge.appends(mac.account_log.id).len(),
        appends_before,
        "nothing sent to the account log"
    );
    // Following goes on.
    let later = mac.signer.add_device(Joiner::new().keys);
    assert_eq!(hosted.edge.order_account(mac.account_log, &later), 5);
    mac_client.wake();
    until(20, "followed on", || {
        mac.signer
            .applied
            .lock()
            .unwrap()
            .iter()
            .any(|head| head.position == 5)
    })
    .await;
    assert!(staged_row(&mac).is_none());
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn expiry_while_the_prompt_is_open_stages_nothing() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let _joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    let (mut account, capability, store) = mac.signer.account_owner();
    let personal = account.open_personal(&capability).await.unwrap();
    let before = store.state().sign_calls;
    // The person starts approving before the deadline and answers the OS
    // prompt after it.
    let gate = Rc::new(store::SignGate::default());
    store.state_mut().sign_gate = Some(gate.clone());
    let answered = async {
        while !gate.entered() {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(301)).await;
        gate.open();
    };
    let (staged, ()) = tokio::join!(
        showing.stage(&mut account, &capability, &personal, &mac.signer.approvals),
        answered
    );
    assert_eq!(staged, Err(PairingError::Ended));
    assert_eq!(store.state().sign_calls, before + 1, "signed late");
    assert!(account.staged_admission().unwrap().is_none());
    // The session stays ended: nothing is signed again.
    assert_eq!(
        showing
            .stage(&mut account, &capability, &personal, &mac.signer.approvals)
            .await,
        Err(PairingError::Ended)
    );
    assert_eq!(store.state().sign_calls, before + 1);
    drop(account);
    // The late signature (the same request signs to the same bytes) has no
    // approval for its copy.
    let late = mac.signer.add_device(joiner.keys.clone());
    assert_eq!(late, mac.signer.add_device(joiner.keys.clone()));
    assert!(!mac.signer.approvals.take(&late));
}

/// The joined container is not usable and holds no own base: authority
/// stays fenced and opening never makes a base of its own.
fn fenced(joiner: &Joiner, base: [u8; 32]) {
    let joined = joiner.owner.joined(joiner.id).unwrap().unwrap();
    assert!(joined.delivery.is_none() && joined.added_at.is_none() && !joined.activated);
    assert!(!joiner.has_own_base());
    assert!(matches!(
        joiner.authorize(base),
        Err(bh_device::OwnerError::NotActivated)
    ));
    assert!(joiner.open_own_base().is_err());
    assert!(!joiner.has_own_base(), "no substitute base");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_with_foreign_or_tampered_base_package_refused() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let code = parse_qr_text(&qr).unwrap();
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    approve(&mac, &mut showing).await.unwrap();
    let staged = staged_row(&mac).unwrap();
    mac_client.wake();
    until(20, "addition ordered and verified", || {
        staged_row(&mac).is_none()
    })
    .await;
    // The addition is genuine; the hint's own-base package is another
    // account's.
    let other = Device::new();
    let hint = AdmissionHint {
        genesis: mac.originals[0].clone(),
        head: AccountHead {
            position: staged.position,
            hash: bh_crypto::hash(&staged.event),
        },
        base: mac.base.0,
        package: other.own_base_package(),
    };
    hosted.put_relay(&code, Side::Show, 0, hint.seal(&code.relay()));
    let admission = joining
        .wait_admitted(
            &mac.endpoint(&hosted),
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
        .await
        .unwrap();
    assert_eq!(admission.added_at, staged.position);
    assert!(matches!(
        joiner.try_admit(&admission).await,
        Err(JoinError::OwnBase(_))
    ));
    fenced(&joiner, mac.base.0);

    // The right package with one byte changed.
    let mut tampered = resume_admission(
        &mac.endpoint(&hosted),
        hosted.connector(),
        joiner.owner.clone(),
        joiner.id,
        &joiner.keys,
        joiner.prover(),
    )
    .await
    .unwrap()
    .unwrap();
    tampered.package = mac.own_base_package();
    *tampered.package.last_mut().unwrap() ^= 1;
    assert!(matches!(
        joiner.try_admit(&tampered).await,
        Err(JoinError::OwnBase(_))
    ));
    fenced(&joiner, mac.base.0);
    mac_client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_after_account_commit_resumes_admission() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    let (mut showing, qr) = show(&hosted, &mac);
    let joiner = Joiner::new();
    let mut joining = JoiningPairing::join(&qr, joiner.keys.clone(), b"Fold", hosted.relay())
        .await
        .unwrap();
    showing.candidate().await.unwrap();
    approve(&mac, &mut showing).await.unwrap();
    let endpoint = mac.endpoint(&hosted);
    let (head, admission) = tokio::join!(
        showing.finish(&mac_client),
        joining.wait_admitted(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            joiner.prover(),
        )
    );
    head.unwrap();
    let admission = admission.unwrap();
    // `admit` commits the account history, then stops before the admission
    // transaction.
    let history: Vec<&[u8]> = admission.history.iter().map(Vec::as_slice).collect();
    joiner
        .account()
        .adopt_joined(admission.account, &history)
        .unwrap();
    assert!(joiner.has_account());
    assert!(
        !joiner
            .owner
            .joined(joiner.id)
            .unwrap()
            .unwrap()
            .hint
            .is_empty()
    );
    fenced(&joiner, admission.base);

    let resume = || {
        resume_admission(
            &endpoint,
            hosted.connector(),
            joiner.owner.clone(),
            joiner.id,
            &joiner.keys,
            joiner.prover(),
        )
    };
    let resumed = resume().await.unwrap().unwrap();
    assert!(resumed.account == admission.account);
    assert_eq!(resumed.history, admission.history);
    assert_eq!(resumed.added_at, admission.added_at);
    assert_eq!(resumed.delivery, admission.delivery);
    assert_eq!(resumed.base, admission.base);
    assert_eq!(resumed.genesis_descriptor, admission.genesis_descriptor);
    assert_eq!(resumed.package, admission.package);
    joiner.admit(&resumed).await;
    joiner.admit(&resumed).await;
    assert!(resume().await.unwrap().is_none(), "committed");
    let joined = joiner.owner.joined(joiner.id).unwrap().unwrap();
    assert_eq!(joined.delivery.as_ref(), Some(&admission.delivery));
    assert_eq!(joined.added_at, Some(admission.added_at));
    assert!(!joined.activated);
    let fold = joiner.into_device();
    assert_eq!(fold.base.0, admission.base);
    assert!(fold.authorize().is_err(), "fenced until bootstrapped");
    bootstrapped(&hosted, &fold).await;
    assert!(fold.usable());
    fold.authorize().unwrap();
    mac_client.shutdown().await;
}
