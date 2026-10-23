//! The account's trust lane: a signed trust control this device staged is
//! ordered byte for byte, confirmed under the hosting root and settled by
//! verified history; a removal that took effect rotates the personal key
//! once, with no control-key signature; a rotation another device ordered
//! is accepted from its exact body. Real signed-up devices and their native
//! stores, the real authorization service behind the attested channel, and
//! the hosted fake's data edge, on a paused runtime with the edge's clock.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::{
    AccountChange, AccountEvent, DevicePublicKeys, REMOVAL_WAIT_MS, VerifiedAccount,
    journal::{AcceptedPersonal, AccountJournal},
    owner::staging::directory_entry_id,
    storage::DeviceJournal,
};
use bh_authz::proto::{Refusal, account_log_unwrap, rotation_body};
use bh_crypto::{KemKey, SigningKey};
use bh_sync::BodyObject;
use bh_sync_client::{
    Client, DeviceClock, Ordered, OrderedControl, RemovalVerdict, Signer, SyncStatus,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use support::{
    device::{Device, until},
    fake::{ConfirmTamper, Hook, Hosted},
    pair::{bootstrapped, paired},
};
use tokio::sync::watch;

type Started = (Client, watch::Receiver<SyncStatus>);

/// A device clock the test sets, apart from the home's.
struct LocalClock(AtomicU64);
impl DeviceClock for LocalClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

fn head(device: &Device) -> u64 {
    device.signer.current_account().unwrap().head().position
}

/// A device of the account with real keys, outside this test's containers.
struct Member {
    control: SigningKey,
    keys: DevicePublicKeys,
}
impl Member {
    fn new() -> Self {
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Self { control, keys }
    }
    /// Its removal of itself, after `account`'s head.
    fn leave(&self, account: &VerifiedAccount) -> Vec<u8> {
        let request = account.remove_self(self.keys.id()).unwrap();
        request
            .finish(self.control.sign(request.signing_bytes()))
            .unwrap()
            .as_bytes()
            .to_vec()
    }
}

/// The mac, registered and following, and a second device joined to its
/// account and base, its addition copied. The second device runs no client.
async fn two(hosted: &Arc<Hosted>) -> (Device, Started, Device) {
    let mac = Device::new();
    let mac_client = mac.start(hosted);
    until(20, "own base registered", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, hosted).await;
    mac_client.0.wake();
    until(20, "addition copied", || copied(&mac) == 4).await;
    (mac, mac_client, fold)
}

/// Add `member` with the mac's control key and wait until the mac copied it.
async fn add(hosted: &Hosted, mac: &Device, client: &Client, member: &Member) -> u64 {
    let at = hosted
        .edge
        .order_account(mac.account_log, &mac.signer.add_device(member.keys.clone()));
    client.wake();
    until(20, "member added", || copied(mac) == at).await;
    at
}

/// Every settled trust control `client` publishes, in order.
fn outcomes(client: &Client) -> Arc<Mutex<Vec<OrderedControl>>> {
    let mut trust = client.trust();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = seen.clone();
    tokio::spawn(async move {
        while trust.changed().await.is_ok() {
            if let Some(settled) = *trust.borrow_and_update() {
                kept.lock().unwrap().push(settled);
            }
        }
    });
    seen
}

/// The account log's originals, in order.
fn originals(hosted: &Hosted, device: &Device) -> Vec<Vec<u8>> {
    hosted
        .edge
        .entries(device.account_log)
        .iter()
        .map(|(_, event)| account_log_unwrap(event).unwrap().0.to_vec())
        .collect()
}

/// The positions of the account log's personal-key rotations.
fn rotations(hosted: &Hosted, device: &Device) -> Vec<u64> {
    originals(hosted, device)
        .iter()
        .enumerate()
        .filter(|(_, original)| {
            matches!(
                AccountEvent::decode(original).unwrap().change(),
                AccountChange::PersonalRotated { .. }
            )
        })
        .map(|(index, _)| index as u64 + 1)
        .collect()
}

fn count(hosted: &Hosted, device: &Device, original: &[u8]) -> usize {
    originals(hosted, device)
        .iter()
        .filter(|o| o.as_slice() == original)
        .count()
}

/// How many personal-key rotations were submitted to the home.
fn submitted_rotations(hosted: &Hosted) -> usize {
    hosted
        .edge
        .submitted
        .lock()
        .unwrap()
        .iter()
        .filter(|s| {
            matches!(
                AccountEvent::decode(s).unwrap().change(),
                AccountChange::PersonalRotated { .. }
            )
        })
        .count()
}

/// Every status `status` shows from now on.
fn shown(status: &watch::Receiver<SyncStatus>) -> Arc<Mutex<Vec<SyncStatus>>> {
    let mut status = status.clone();
    let seen = Arc::new(Mutex::new(vec![*status.borrow_and_update()]));
    let kept = seen.clone();
    tokio::spawn(async move {
        while status.changed().await.is_ok() {
            kept.lock().unwrap().push(*status.borrow_and_update());
        }
    });
    seen
}

fn submitted(hosted: &Hosted, original: &[u8]) -> usize {
    hosted
        .edge
        .submitted
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.as_slice() == original)
        .count()
}

/// Whether the device holds a durable refused-change alert.
fn alerted(device: &Device) -> bool {
    let db = device.owner.shared_database(device.id).unwrap();
    db.lock()
        .unwrap()
        .alerts(20)
        .unwrap()
        .iter()
        .any(|alert| alert.kind == bh_storage::AlertKind::RefusedChange)
}

/// What this device's keyring holds accepted.
fn accepted(device: &Device) -> AcceptedPersonal {
    DeviceJournal::from_shared(device.owner.shared_database(device.id).unwrap())
        .keyring_state()
        .unwrap()
        .accepted
}

fn settled(seen: &Arc<Mutex<Vec<OrderedControl>>>, kind: u8) -> Option<OrderedControl> {
    seen.lock()
        .unwrap()
        .iter()
        .rev()
        .find(|s| s.kind == kind)
        .copied()
}

// ---- Ordering a staged control ----

#[tokio::test(start_paused = true)]
async fn deadline_comes_from_the_confirmation_not_the_permit() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let seen = outcomes(&mac_client.0);
    // The request's append is ordered, then the home's clock moves on before
    // it confirms it; that confirmation's answer is lost.
    hosted
        .edge
        .hook(Hook::AdvanceAfterAccountAppend { ms: 5_000 });
    hosted.lose_next_confirm_answer();
    let permitted = hosted.edge.clock.now();
    let request = mac.signer.request_removal(fold.signer.device_id());
    mac.signer.stage(&request);
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    let settled = settled(&seen, 5).unwrap();
    let Ordered::Accepted { confirmation } = settled.outcome else {
        panic!("{settled:?}");
    };
    assert!(confirmation.latest_ms >= permitted + 5_000);
    assert!(confirmation.latest_ms < hosted.edge.clock.now());
    assert_eq!(
        settled.deadline_ms,
        Some(confirmation.latest_ms + REMOVAL_WAIT_MS)
    );
    assert_ne!(settled.deadline_ms, Some(permitted + REMOVAL_WAIT_MS));
    // The lost answer was never sent again.
    assert_eq!(submitted(&hosted, &request), 1);
    assert_eq!(count(&hosted, &mac, &request), 1);
    assert_eq!(mac.signer.staged(), None);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_lost_answer_resends_exact_bytes_and_keeps_the_first_ack() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    // The mac may cancel once it is mature.
    hosted.edge.clock.advance(REMOVAL_WAIT_MS);
    let seen = outcomes(&mac_client.0);
    // The append commits; its Ack is lost.
    hosted
        .edge
        .hook(Hook::DropAfterAccountAppend { then_down: false });
    let request = mac.signer.request_removal(fold.signer.device_id());
    mac.signer.stage(&request);
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    assert!(matches!(
        settled(&seen, 5).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    assert_eq!(count(&hosted, &mac, &request), 1);
    assert_eq!(submitted(&hosted, &request), 1);

    // An append lost before it is ordered: the home says it is not ordered,
    // and the very same bytes are sent again.
    hosted.edge.hook(Hook::DropBeforeAccountAppend);
    let position = head(&mac);
    let cancel = mac
        .signer
        .cancel_removal(fold.signer.device_id(), position)
        .unwrap();
    mac.signer.stage(&cancel);
    mac_client.0.wake();
    until(60, "cancel settled", || settled(&seen, 7).is_some()).await;
    assert!(matches!(
        settled(&seen, 7).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    assert_eq!(submitted(&hosted, &cancel), 2);
    assert_eq!(count(&hosted, &mac, &cancel), 1);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_lost_answer_or_not_ordered_never_discards() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let seen = outcomes(&mac_client.0);
    // Lost twice before it is ordered, then its confirmation's answer too.
    hosted.edge.hook(Hook::DropBeforeAccountAppend);
    hosted.edge.hook(Hook::DropBeforeAccountAppend);
    hosted.lose_next_confirm_answer();
    let request = mac.signer.request_removal(fold.signer.device_id());
    let staged = mac.signer.stage(&request);
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    assert!(matches!(
        settled(&seen, 5).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|s| s.outcome != Ordered::Refused),
        "never discarded"
    );
    assert!(submitted(&hosted, &staged.event) >= 3);
    assert_eq!(count(&hosted, &mac, &request), 1);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_confirmation_under_another_root_or_challenge_settles_nothing() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let seen = outcomes(&mac_client.0);
    let before = head(&mac);
    // Following cannot settle the request either: its confirmation is
    // missing from the account evidence. A confirmation the mac accepted
    // would end its asking; one it refuses never does.
    hosted.omit_account_confirmation(mac.account_log, before + 1);
    for tamper in [ConfirmTamper::Root, ConfirmTamper::Challenge] {
        hosted.tamper_confirmations(Some(tamper));
        let asked = hosted.edge.confirm_asks.load(Ordering::SeqCst);
        if mac.signer.staged().is_none() {
            mac.signer
                .stage(&mac.signer.request_removal(fold.signer.device_id()));
        }
        mac_client.0.wake();
        until(60, "asked twice", || {
            hosted.edge.confirm_asks.load(Ordering::SeqCst) >= asked + 2
        })
        .await;
        assert!(seen.lock().unwrap().is_empty(), "{tamper:?}");
        assert!(mac.signer.staged().is_some(), "{tamper:?}");
        assert_eq!(head(&mac), before, "{tamper:?}");
    }
    hosted.restore_account_confirmations();
    hosted.tamper_confirmations(None);
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    assert!(matches!(
        settled(&seen, 5).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    assert_eq!(head(&mac), before + 1);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_refused_control_is_discarded_and_a_rotation_can_stage() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let seen = outcomes(&mac_client.0);
    // A removal of itself signed with the wrong key: staged, then refused
    // for good by the home.
    let refused = mac.signer.remove_self_signed_by_ordinary_key();
    mac.signer.stage(&refused);
    mac_client.0.wake();
    until(60, "refusal settled", || settled(&seen, 2).is_some()).await;
    assert_eq!(settled(&seen, 2).unwrap().outcome, Ordered::Refused);
    assert_eq!(mac.signer.staged(), None);
    assert_eq!(count(&hosted, &mac, &refused), 0);

    // The stage no longer blocks the rotation a removal makes due.
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(60, "rotation settled", || settled(&seen, 9).is_some()).await;
    assert!(matches!(
        settled(&seen, 9).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    assert_eq!(rotations(&hosted, &mac), vec![left + 1]);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_refusal_retries_and_never_discards() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let seen = outcomes(&mac_client.0);
    // A session the home does not hold as authenticated says nothing about
    // the bytes: they are sent again, never dropped.
    hosted.refuse_submits(Some(Refusal::Unauthenticated));
    let request = mac.signer.request_removal(fold.signer.device_id());
    mac.signer.stage(&request);
    mac_client.0.wake();
    until(60, "refused twice", || submitted(&hosted, &request) >= 2).await;
    assert!(seen.lock().unwrap().is_empty());
    assert!(mac.signer.staged().is_some());
    hosted.refuse_submits(None);
    mac_client.0.wake();
    until(120, "request settled", || settled(&seen, 5).is_some()).await;
    assert!(matches!(
        settled(&seen, 5).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    assert_eq!(count(&hosted, &mac, &request), 1);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_lent_owner_never_shows_waiting_authorization() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let seen = outcomes(&mac_client.0);
    let statuses = shown(&mac_client.1);
    // The publisher holds the owner while the receiver passes: with nothing
    // staged, then with a request staged.
    mac.signer.owner_lent.store(true, Ordering::SeqCst);
    mac_client.0.wake();
    tokio::time::sleep(Duration::from_secs(10)).await;
    mac.signer
        .stage(&mac.signer.request_removal(fold.signer.device_id()));
    mac_client.0.wake();
    tokio::time::sleep(Duration::from_secs(10)).await;
    mac.signer.owner_lent.store(false, Ordering::SeqCst);
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    assert!(
        !statuses
            .lock()
            .unwrap()
            .contains(&SyncStatus::WaitingAuthorization),
        "{:?}",
        statuses.lock().unwrap()
    );
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn request_is_copied_into_the_base_without_closing_the_epoch() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let seen = outcomes(&mac_client.0);
    let epoch = mac.progress().epoch_id;
    assert!(epoch.is_some());
    mac.signer
        .stage(&mac.signer.request_removal(fold.signer.device_id()));
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    let at = settled(&seen, 5).unwrap().position;
    until(20, "request copied", || copied(&mac) == at).await;
    assert_eq!(mac.progress().epoch_id, epoch);
    // Notes go on under the same key.
    let (_, update) = mac.new_note("still under the same key");
    mac_client.0.wake();
    until(20, "note acknowledged", || mac.acked(update).is_some()).await;
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn request_then_cancel_keeps_the_device_syncing() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    // The mac may cancel once it is mature.
    hosted.edge.clock.advance(REMOVAL_WAIT_MS);
    let fold_client = fold.start(&hosted);
    until(20, "fold caught up", || copied(&fold) == 4).await;
    let seen = outcomes(&mac_client.0);
    mac.signer
        .stage(&mac.signer.request_removal(fold.signer.device_id()));
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    let request = settled(&seen, 5).unwrap();
    let deadline = request.deadline_ms.unwrap();
    let cancel = mac
        .signer
        .cancel_removal(fold.signer.device_id(), request.position)
        .unwrap();
    mac.signer.stage(&cancel);
    mac_client.0.wake();
    until(60, "cancel settled", || settled(&seen, 7).is_some()).await;
    assert!(matches!(
        settled(&seen, 7).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    // Past the deadline the fold is still a member and still syncs.
    hosted
        .edge
        .clock
        .advance(deadline - hosted.edge.clock.now() + 1);
    let (_, update) = fold.new_note("after the cancelled removal");
    fold_client.0.wake();
    until(30, "fold note acknowledged", || {
        fold.acked(update).is_some()
    })
    .await;
    assert_eq!(
        *fold_client.0.removal_verdict().borrow(),
        RemovalVerdict::Active
    );
    assert!(
        mac.signer
            .current_account()
            .unwrap()
            .active_device(fold.signer.device_id())
            .is_ok()
    );
    assert!(rotations(&hosted, &mac).is_empty());
    fold_client.0.shutdown().await;
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn cancel_that_lapses_reports_already_took_effect() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    // The mac may cancel once it is mature.
    hosted.edge.clock.advance(REMOVAL_WAIT_MS);
    let seen = outcomes(&mac_client.0);
    mac.signer
        .stage(&mac.signer.request_removal(fold.signer.device_id()));
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    let request = settled(&seen, 5).unwrap();
    let deadline = request.deadline_ms.unwrap();
    mac_client.0.shutdown().await;
    drop(mac_client);
    // The cancel is signed and staged before the deadline, but reaches the
    // home only after it.
    let cancel = mac
        .signer
        .cancel_removal(fold.signer.device_id(), request.position)
        .unwrap();
    mac.signer.stage(&cancel);
    hosted
        .edge
        .clock
        .advance(deadline - hosted.edge.clock.now() + 1);
    let mac_client = mac.start(&hosted);
    let seen = outcomes(&mac_client.0);
    until(60, "cancel settled", || settled(&seen, 7).is_some()).await;
    assert_eq!(
        settled(&seen, 7).unwrap().outcome,
        Ordered::CancelTookEffect
    );
    assert_eq!(mac.signer.staged(), None);
    assert_eq!(
        mac.signer
            .current_account()
            .unwrap()
            .device_state(fold.signer.device_id(), hosted.edge.clock.now()),
        Ok(bh_account::DeviceState::Removed)
    );
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn target_is_cut_off_at_the_deadline_while_no_remaining_device_is_online() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let fold_client = fold.start(&hosted);
    until(20, "fold caught up", || copied(&fold) == 4).await;
    let seen = outcomes(&mac_client.0);
    mac.signer
        .stage(&mac.signer.request_removal(fold.signer.device_id()));
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    let deadline = settled(&seen, 5).unwrap().deadline_ms.unwrap();
    // The only remaining device goes offline before the deadline.
    mac_client.0.shutdown().await;
    hosted
        .edge
        .clock
        .advance(deadline - hosted.edge.clock.now() + 1);
    let verdict = fold_client.0.removal_verdict();
    fold_client.0.wake();
    fold_client.0.check_removal();
    until(60, "fold cut off", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    // Nothing rotated: no remaining device was online.
    assert!(rotations(&hosted, &mac).is_empty());
    fold_client.0.shutdown().await;
}

// ---- Rotating the personal key ----

/// The fold rotates for `member`'s removal through the home, as the mac
/// does: its own trust lane. The mac does not run meanwhile.
async fn fold_rotates(hosted: &Arc<Hosted>, fold: &Device) -> (Started, u64) {
    let fold_client = fold.start(hosted);
    until(60, "fold rotated", || {
        rotations(hosted, fold).len() == 1 && head(fold) >= *rotations(hosted, fold).last().unwrap()
    })
    .await;
    let at = rotations(hosted, fold)[0];
    (fold_client, at)
}

#[tokio::test(start_paused = true)]
async fn concurrent_rotations_one_wins_other_retries_cleanly() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let member = Member::new();
    let added = add(&hosted, &mac, &mac_client.0, &member).await;
    mac_client.0.shutdown().await;
    drop(mac_client);
    // Both devices learn of the removal, and each stages its own rotation
    // for it before either is ordered.
    hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    let timed = hosted.confirmed_account(mac.account_log).await;
    for device in [&mac, &fold] {
        let at = head(device) as usize;
        device
            .signer
            .apply_account_timed(
                device.signer.current_account().unwrap().head(),
                timed[at..].to_vec(),
            )
            .await
            .unwrap();
    }
    let left = added + 1;
    let at = timed[left as usize - 1].1.as_ref().unwrap().0.earliest_ms;
    let mac_rotation = mac.signer.stage_rotation(at).await.unwrap();
    let fold_rotation = fold.signer.stage_rotation(at).await.unwrap();
    assert_ne!(mac_rotation.event, fold_rotation.event);

    let mac_client = mac.start(&hosted);
    let fold_client = fold.start(&hosted);
    let (mac_seen, fold_seen) = (outcomes(&mac_client.0), outcomes(&fold_client.0));
    until(60, "both settled", || {
        settled(&mac_seen, 9).is_some() && settled(&fold_seen, 9).is_some()
    })
    .await;
    let outcomes = [
        settled(&mac_seen, 9).unwrap().outcome,
        settled(&fold_seen, 9).unwrap().outcome,
    ];
    assert_eq!(
        outcomes.iter().filter(|o| **o == Ordered::Lost).count(),
        1,
        "{outcomes:?}"
    );
    // The loser stood down: one rotation, and neither staged another.
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert_eq!(rotations(&hosted, &mac), vec![left + 1]);
    for device in [&mac, &fold] {
        assert_eq!(device.signer.rotations_staged.load(Ordering::SeqCst), 1);
        assert_eq!(device.signer.staged(), None);
    }
    // The mac holds the winner's key, whichever device won.
    until(30, "mac accepted", || {
        matches!(accepted(&mac), AcceptedPersonal::Rotated { position, .. } if position == left + 1)
    })
    .await;
    assert_eq!(
        &mac.signer.accepted_personal(),
        mac.signer
            .current_account()
            .unwrap()
            .personal_public()
            .unwrap()
    );
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn losing_rotation_never_overwrites_the_accepted_personal_key() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let fold_started = fold.start(&hosted);
    until(20, "fold caught up", || head(&fold) == head(&mac)).await;
    fold_started.0.shutdown().await;
    drop(fold_started);
    let before = mac.signer.accepted_personal();
    // The mac learns of the removal and stages its rotation, then stops.
    mac.signer.refuse_rotation.store(true, Ordering::SeqCst);
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(20, "mac followed the removal", || head(&mac) == left).await;
    mac_client.0.shutdown().await;
    drop(mac_client);
    mac.signer.refuse_rotation.store(false, Ordering::SeqCst);
    let at = hosted.edge.clock.now();
    let mine = mac.signer.stage_rotation(at).await.unwrap();
    // The fold's rotation is ordered first.
    let (fold_client, rotated) = fold_rotates(&hosted, &fold).await;
    let mac_client = mac.start(&hosted);
    let seen = outcomes(&mac_client.0);
    until(60, "mac's rotation lost", || settled(&seen, 9).is_some()).await;
    assert_eq!(settled(&seen, 9).unwrap().outcome, Ordered::Lost);
    until(60, "mac accepted the winner", || {
        matches!(accepted(&mac), AcceptedPersonal::Rotated { position, .. } if position == rotated)
    })
    .await;
    let winner = *mac
        .signer
        .current_account()
        .unwrap()
        .personal_public()
        .unwrap();
    assert_eq!(mac.signer.accepted_personal(), winner);
    assert_ne!(winner, before);
    // The staged proposal was never accepted, nor ordered.
    assert_eq!(count(&hosted, &mac, &mine.event), 0);
    let AcceptedPersonal::Rotated { body, .. } = accepted(&mac) else {
        unreachable!()
    };
    assert_ne!(Some(body), mine.body);
    // The only acceptance asked for was the winner's.
    assert_eq!(mac.signer.accept_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(rotations(&hosted, &mac).len(), 1);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn three_due_effects_need_one_rotation() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let members = [Member::new(), Member::new(), Member::new()];
    for member in &members {
        add(&hosted, &mac, &mac_client.0, member).await;
    }
    let seen = outcomes(&mac_client.0);
    mac_client.0.shutdown().await;
    drop(mac_client);
    // All three leave before the mac looks again.
    let mut view = mac.signer.current_account().unwrap();
    let mut last = 0;
    for member in &members {
        let leave = member.leave(&view);
        last = hosted.edge.order_account(mac.account_log, &leave);
        let now = hosted.edge.clock.now();
        view.apply_timed(
            &leave,
            Some(bh_account::ConfirmedTime {
                earliest_ms: now,
                latest_ms: now,
            }),
        )
        .unwrap();
    }
    let mac_client = mac.start(&hosted);
    let seen_after = outcomes(&mac_client.0);
    until(60, "rotation settled", || settled(&seen_after, 9).is_some()).await;
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert_eq!(rotations(&hosted, &mac), vec![last + 1]);
    let rotation = AccountEvent::decode(&originals(&hosted, &mac)[last as usize]).unwrap();
    assert!(matches!(
        rotation.change(),
        AccountChange::PersonalRotated { reason, .. } if reason == last
    ));
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 1);
    assert_eq!(mac.signer.current_account().unwrap().rotation_due(0), None);
    assert!(seen.lock().unwrap().is_empty());
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_refused_rotation_is_retried_on_a_growing_backoff() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let seen = outcomes(&mac_client.0);
    // The home refuses every rotation for good, as one that has not
    // indexed the account's recovery record does.
    hosted.refuse_submits(Some(Refusal::Invalid));
    hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(60, "first rotation refused", || {
        settled(&seen, 9).is_some_and(|s| s.outcome == Ordered::Refused)
    })
    .await;
    let first = submitted_rotations(&hosted);
    let mut minutes = Vec::new();
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(60)).await;
        minutes.push(submitted_rotations(&hosted) - first);
    }
    // Each attempt waits twice as long, up to the 30 s cap: a few in the
    // first minute, then about two a minute. At the shortest wait it would
    // be one about every second.
    assert!(minutes[0] <= 6, "{minutes:?}");
    assert!(minutes[9] <= 30, "{minutes:?}");
    assert!(minutes[9] - minutes[8] <= 3, "{minutes:?}");
    assert!(minutes[9] - minutes[8] >= 1, "still retried: {minutes:?}");
    // An attempt may be in flight at the sample; once refused it is
    // discarded, never kept.
    until(60, "the refused stage discarded", || {
        mac.signer.staged().is_none()
    })
    .await;
    // Once the home orders it, the rotation settles.
    hosted.refuse_submits(None);
    until(120, "rotation accepted", || {
        settled(&seen, 9).is_some_and(|s| matches!(s.outcome, Ordered::Accepted { .. }))
    })
    .await;
    assert_eq!(rotations(&hosted, &mac).len(), 1);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_device_clock_past_the_deadline_waits_for_the_homes_time() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let seen = outcomes(&mac_client.0);
    mac.signer
        .stage(&mac.signer.request_removal(fold.signer.device_id()));
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    let deadline = settled(&seen, 5).unwrap().deadline_ms.unwrap();
    mac_client.0.shutdown().await;
    drop(mac_client);
    // The home's time stands ten minutes short of the deadline; the mac's
    // clock is an hour past it.
    hosted
        .edge
        .clock
        .advance(deadline - hosted.edge.clock.now() - 600_000);
    let mut endpoint = mac.endpoint(&hosted);
    endpoint.device_clock = Arc::new(LocalClock(AtomicU64::new(deadline + 3_600_000)));
    let (mac_client, _) = mac.start_at(&hosted, endpoint);
    until(20, "registered again", || mac.registered()).await;
    let before = hosted.edge.reads(mac.account_log).len();
    tokio::time::sleep(Duration::from_secs(60)).await;
    // Nothing staged on the device's clock, and it looks again only as
    // often as the home's time could have reached the deadline.
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 0);
    assert!(rotations(&hosted, &mac).is_empty());
    let looks = hosted.edge.reads(mac.account_log).len() - before;
    assert!(
        (1..=12).contains(&looks),
        "{looks} evidence reads in a minute"
    );
    // The home's time reaches the deadline: one rotation.
    until(660, "rotated", || rotations(&hosted, &mac).len() == 1).await;
    assert!(hosted.edge.clock.now() >= deadline);
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 1);
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn rotation_needs_no_control_key_signature() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let seen = outcomes(&mac_client.0);
    mac.signer.refuse_rotation.store(true, Ordering::SeqCst);
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(20, "removal copied", || copied(&mac) == left).await;
    let (control, signed) = (
        mac.signer.control_signatures.load(Ordering::SeqCst),
        mac.signer.signed.load(Ordering::SeqCst),
    );
    mac.signer.refuse_rotation.store(false, Ordering::SeqCst);
    mac_client.0.wake();
    until(60, "rotation accepted", || {
        settled(&seen, 9).is_some() && mac.signer.accepts.load(Ordering::SeqCst) == 1
    })
    .await;
    let rotated = rotations(&hosted, &mac)[0];
    until(60, "the base rekeyed", || {
        mac_client.0.wake();
        copied(&mac) == rotated && mac.progress().epoch_id.is_some()
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        control
    );
    // The rotation is signed with the ordinary key inside the account
    // owner, not by an event signature the client asked for; the base's
    // rekey asks for two, its one seal and its control, with that key.
    assert_eq!(mac.signer.signed.load(Ordering::SeqCst), signed + 2);
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 1);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_follower_accepts_the_winners_rotation_from_its_padded_body() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    mac_client.0.shutdown().await;
    drop(mac_client);
    let before = mac.signer.accepted_personal();
    hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    let (fold_client, rotated) = fold_rotates(&hosted, &fold).await;
    let (_, wrapper) = &hosted.edge.entries(mac.account_log)[rotated as usize - 1];
    let commitment = account_log_unwrap(wrapper).unwrap().1.unwrap();
    let mac_client = mac.start(&hosted);
    until(60, "mac accepted the rotation", || {
        mac.signer.accepts.load(Ordering::SeqCst) == 1
    })
    .await;
    assert!(hosted.edge.body_asks(commitment) >= 1);
    let now = *mac
        .signer
        .current_account()
        .unwrap()
        .personal_public()
        .unwrap();
    assert_eq!(mac.signer.accepted_personal(), now);
    assert_ne!(now, before);
    // Nothing more to do: one rotation, none of the mac's own.
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 0);
    assert_eq!(mac.signer.accept_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(rotations(&hosted, &mac), vec![rotated]);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

/// A device joined by the real QR flow keeps the account key across a
/// removal: a member is added and then leaves, the mac's lane rotates, and
/// the fold's own client accepts that rotation once, through its lane.
#[tokio::test(start_paused = true)]
async fn a_paired_follower_accepts_a_rotation_through_its_lane() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = mac.start(&hosted);
    until(20, "registered", || mac.registered() && !mac.home_pending()).await;
    let (fold, _) = paired(&hosted, &mac, &mac_client.0).await;
    bootstrapped(&hosted, &fold).await;
    until(20, "addition copied", || copied(&mac) == 4).await;
    fold.authorize().unwrap();
    // Only the mac's lane rotates; the fold accepts the rotation it orders.
    mac.signer.approve_controls.store(true, Ordering::SeqCst);
    fold.signer.refuse_rotation.store(true, Ordering::SeqCst);
    let before = fold.signer.accepted_personal();
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(120, "the mac rotated and accepted", || {
        mac_client.0.wake();
        rotations(&hosted, &mac) == vec![left + 1] && mac.signer.accepts.load(Ordering::SeqCst) == 1
    })
    .await;
    let fold_client = fold.start(&hosted);
    until(120, "the fold accepted the rotation", || {
        fold_client.0.wake();
        fold.signer.accepts.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(fold.signer.accept_attempts.load(Ordering::SeqCst), 1);
    let now = *fold
        .signer
        .current_account()
        .unwrap()
        .personal_public()
        .unwrap();
    assert_eq!(fold.signer.accepted_personal(), now);
    assert_ne!(now, before);
    fold_client.0.shutdown().await;
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_rotation_body_with_the_wrong_digest_is_refused() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    mac_client.0.shutdown().await;
    drop(mac_client);
    let before = mac.signer.accepted_personal();
    hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    let (fold_client, rotated) = fold_rotates(&hosted, &fold).await;
    let (_, wrapper) = &hosted.edge.entries(mac.account_log)[rotated as usize - 1];
    let commitment = account_log_unwrap(wrapper).unwrap().1.unwrap();
    // The edge hands out another rotation frame's padded body under the
    // ordered body's commitment.
    let genuine = hosted.edge.take_body(mac.account_log, commitment).unwrap();
    let other = rotation_body(&vec![7; 900]).unwrap().bytes().to_vec();
    hosted
        .edge
        .serve_body_as(mac.account_log, commitment, other);
    let mac_client = mac.start(&hosted);
    until(60, "body asked twice", || {
        hosted.edge.body_asks(commitment) >= 2
    })
    .await;
    assert_eq!(mac.signer.accept_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(mac.signer.accepted_personal(), before);
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 0);
    // The genuine body is accepted once it is served.
    hosted
        .edge
        .serve_body_as(mac.account_log, commitment, genuine);
    until(60, "mac accepted the rotation", || {
        mac.signer.accepts.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_ne!(mac.signer.accepted_personal(), before);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn crash_after_an_accepted_rotation_restarts_without_a_second_rotation() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let seen = outcomes(&mac_client.0);
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(60, "rotation accepted", || {
        settled(&seen, 9).is_some() && mac.signer.accepts.load(Ordering::SeqCst) == 1
    })
    .await;
    let key = mac.signer.accepted_personal();
    mac_client.0.shutdown().await;
    drop(mac_client);
    let mac = mac.restart();
    let mac_client = mac.start(&hosted);
    until(20, "registered again", || mac.registered()).await;
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert_eq!(rotations(&hosted, &mac), vec![left + 1]);
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 0);
    assert_eq!(mac.signer.accept_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(mac.signer.accepted_personal(), key);
    mac_client.0.shutdown().await;
}

/// The fold rotates for one member's removal with `recipients` devices left
/// active, and the mac, which ran no client meanwhile, follows: it accepts
/// the new key from the padded body the rotation ordered.
async fn rotate_for(recipients: usize) {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    // The mac and the fold, and all but the one member who leaves: the
    // mac adds the first, which adds the rest, and the mac copies them all.
    let members: Vec<Member> = (0..recipients - 1).map(|_| Member::new()).collect();
    add(&hosted, &mac, &mac_client.0, &members[0]).await;
    let mut view = mac.signer.current_account().unwrap();
    let mut last = 0;
    for member in &members[1..] {
        let draft = view
            .add_device(members[0].keys.id(), member.keys.clone())
            .unwrap();
        let event = draft
            .finish(members[0].control.sign(draft.signing_bytes()))
            .unwrap();
        last = hosted.edge.order_account(mac.account_log, event.as_bytes());
        let now = hosted.edge.clock.now();
        view.apply_timed(
            event.as_bytes(),
            Some(bh_account::ConfirmedTime {
                earliest_ms: now,
                latest_ms: now,
            }),
        )
        .unwrap();
    }
    mac_client.0.wake();
    until(300, "members added", || copied(&mac) == last).await;
    mac_client.0.shutdown().await;
    drop(mac_client);
    let before = mac.signer.accepted_personal();
    let current = mac.signer.current_account().unwrap();
    assert_eq!(current.active_devices().unwrap().count(), recipients + 1);
    let left = hosted
        .edge
        .order_account(mac.account_log, &members[0].leave(&current));
    let fold_client = fold.start(&hosted);
    until(300, "fold rotated", || {
        rotations(&hosted, &fold) == vec![left + 1] && head(&fold) > left
    })
    .await;
    fold_client.0.shutdown().await;
    // Its one body was staged once, before the rotation named it.
    let (_, wrapper) = &hosted.edge.entries(mac.account_log)[left as usize];
    let commitment = account_log_unwrap(wrapper).unwrap().1.unwrap();
    let stages = hosted.edge.stages(mac.account_log.id);
    assert_eq!(stages.len(), 1);
    assert_eq!(
        BodyObject::new(stages[0].clone()).unwrap().commitment(),
        commitment
    );
    let mac_client = mac.start(&hosted);
    until(300, "mac accepted the rotation", || {
        mac.signer.accepts.load(Ordering::SeqCst) == 1
    })
    .await;
    let now = *mac
        .signer
        .current_account()
        .unwrap()
        .personal_public()
        .unwrap();
    assert_eq!(mac.signer.accepted_personal(), now);
    assert_ne!(now, before);
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 0);
    mac_client.0.shutdown().await;
}

// A rotation's body once had to fit in its 64 KiB authorization message,
// which held only 47 recipients.
#[tokio::test(start_paused = true)]
async fn a_rotation_for_48_devices_is_ordered_and_followed() {
    rotate_for(48).await;
}

#[tokio::test(start_paused = true)]
async fn a_rotation_for_300_devices_is_ordered_and_followed() {
    rotate_for(300).await;
}

#[tokio::test(start_paused = true)]
async fn a_lost_rotation_submit_answer_restages_the_same_body() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let seen = outcomes(&mac_client.0);
    hosted.lose_next_submit_answer();
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(120, "rotation settled", || settled(&seen, 9).is_some()).await;
    assert!(matches!(
        settled(&seen, 9).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    assert_eq!(rotations(&hosted, &mac), vec![left + 1]);
    assert!(submitted_rotations(&hosted) >= 2);
    // Staged again for the second submission, byte for byte.
    let mut stages = hosted.edge.stages(mac.account_log.id);
    assert!(stages.len() >= 2, "{}", stages.len());
    stages.dedup();
    assert_eq!(stages.len(), 1);
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 1);
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn followed_new_tag_with_a_bad_confirmation_is_refused_and_alerts() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    // The mac follows the removal but cannot rotate for it now.
    mac.signer.refuse_rotation.store(true, Ordering::SeqCst);
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(20, "mac followed the removal", || head(&mac) == left).await;
    mac_client.0.shutdown().await;
    drop(mac_client);
    // The fold's rotation is ordered; the home then confirms it with a
    // claim naming another predecessor.
    let (fold_client, rotated) = fold_rotates(&hosted, &fold).await;
    fold_client.0.shutdown().await;
    hosted.wrong_account_predecessor(mac.account_log, rotated);
    let mac_client = mac.start(&hosted);
    until(60, "refused and alerted", || alerted(&mac)).await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert_eq!(head(&mac), left, "the rotation is not applied");
    assert_eq!(mac.signer.accept_attempts.load(Ordering::SeqCst), 0);
    assert!(!matches!(accepted(&mac), AcceptedPersonal::Rotated { .. }));
    mac_client.0.shutdown().await;
}

// ---- What the person sees ----

/// The base's rekey waits at its seal's signature: the account rotated
/// and this device accepted, and the base's copy is behind the rotation,
/// so it shows Protecting. Once the rekey is ordered and its key installs,
/// it is Synced under the new epoch.
#[tokio::test(start_paused = true)]
async fn protecting_until_the_base_epoch_reopens() {
    let hosted = Hosted::new();
    let (mac, mut mac_client, _fold) = two(&hosted).await;
    let genesis_epoch = mac.progress().epoch_id.unwrap();
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let sign = mac.signer.hold_next_sign();
    let left = hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(60, "removal copied and rotated", || {
        copied(&mac) == left && rotations(&hosted, &mac).len() == 1
    })
    .await;
    let rotated = rotations(&hosted, &mac)[0];
    tokio::time::timeout(Duration::from_secs(20), sign.arrived)
        .await
        .expect("the base's rekey is signed")
        .unwrap();
    until(20, "protecting", || {
        *mac_client.1.borrow_and_update() == SyncStatus::Protecting
    })
    .await;
    assert_eq!(copied(&mac), left, "the base's copy is behind the rotation");

    let _ = sign.release.send(());
    until(60, "mac accepted the rotation", || {
        matches!(accepted(&mac), AcceptedPersonal::Rotated { position, .. } if position == rotated)
    })
    .await;
    until(60, "synced under the new epoch", || {
        mac_client.0.wake();
        *mac_client.1.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    assert_eq!(copied(&mac), rotated);
    let epoch = mac.progress().epoch_id.unwrap();
    assert_ne!(epoch, genesis_epoch);
    assert!(mac.signer.holds_epoch(epoch));
    mac_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn an_own_base_entry_behind_the_epoch_is_rewritten_once() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let genesis_epoch = mac.progress().epoch_id.unwrap();
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    // The lane rotates and the base's rekey installs a new epoch, at a base
    // position above the genesis epoch's.
    until(60, "rotated and rekeyed", || {
        rotations(&hosted, &mac).len() == 1
            && mac
                .progress()
                .epoch_id
                .is_some_and(|epoch| epoch != genesis_epoch)
            && matches!(mac.signer.directory_state().unwrap(), Some((v, true)) if v > 1)
    })
    .await;
    let epoch = mac.progress().epoch_id.unwrap();
    let (version, _) = mac.signer.directory_state().unwrap().unwrap();
    mac_client.0.shutdown().await;
    drop(mac_client);
    // The home holds the own base's entry below that version, naming the
    // epoch before, as when the device that produced the rekey never wrote.
    let behind = mac
        .signer
        .prepare_base_entry(
            mac.base,
            genesis_epoch,
            "http://edge.invalid".into(),
            version - 1,
        )
        .await
        .unwrap();
    let id = directory_entry_id(&behind).unwrap();
    hosted
        .edge
        .put_directory_entry(mac.account_log, id, version - 1, behind);
    let writes = || hosted.edge.directory_writes.load(Ordering::SeqCst);
    let reads = || hosted.edge.directory_reads.load(Ordering::SeqCst);
    let written = writes();

    // Upgraded with no record of its entry, the mac reads it: behind its
    // epoch, so it writes the current one once, then reads no more.
    mac.raw()
        .execute("DELETE FROM account_directory_state", [])
        .unwrap();
    let (mac_client, _) = mac.start(&hosted);
    until(60, "entry rewritten", || {
        mac.signer.directory_state().unwrap() == Some((version, true))
    })
    .await;
    let entry = hosted
        .edge
        .directory(mac.account_log)
        .into_iter()
        .find(|(held, _, _)| *held == id)
        .unwrap();
    assert_eq!(entry.1, version);
    let opened = mac
        .signer
        .open_directory_entries(vec![entry.2])
        .await
        .unwrap();
    assert!(matches!(
        &opened[0].as_ref().unwrap().entry,
        bh_account::directory::DirectoryEntry::Base { epoch_id, .. } if *epoch_id == epoch
    ));
    assert_eq!(writes(), written + 1);
    let settled = reads();
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!((reads(), writes()), (settled, written + 1));
    mac_client.shutdown().await;
}

// ---- The rotation and the base's rekey together ----

/// The epoch of the own base's rekey at base position `position`, if the
/// control there installed one.
fn installed_at(device: &Device, position: u64) -> Option<[u8; 32]> {
    let fact = device
        .owner
        .control_fact(device.id, device.log(), position)
        .unwrap()?;
    (fact.epoch_installed.0 == position).then_some(fact.epoch?)
}

/// A removal request takes effect once its wait passes. With no prompt,
/// the lane rotates the personal key, the copier rekeys the base with the
/// ordinary key, and the epoch reopens under a key sealed to the new
/// personal key: the status goes from Protecting to Synced, and a new note
/// is protected by the new key. No control-key signature after the request
/// was approved.
#[tokio::test(start_paused = true)]
async fn effective_after_the_wait_rotates_and_rekeys_without_a_prompt() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold) = two(&hosted).await;
    let old = mac.progress().epoch_id.unwrap();
    let seen = outcomes(&mac_client.0);
    mac.signer
        .stage(&mac.signer.request_removal(fold.signer.device_id()));
    mac_client.0.wake();
    until(60, "request settled", || settled(&seen, 5).is_some()).await;
    let request = settled(&seen, 5).unwrap();
    until(20, "request copied", || copied(&mac) == request.position).await;
    let control = mac.signer.control_signatures.load(Ordering::SeqCst);
    let signed = mac.signer.signed.load(Ordering::SeqCst);
    let statuses = shown(&mac_client.1);

    hosted
        .edge
        .clock
        .advance(request.deadline_ms.unwrap() - hosted.edge.clock.now() + 1);
    mac_client.0.wake();
    until(120, "rotated, rekeyed and synced", || {
        mac_client.0.wake();
        rotations(&hosted, &mac).len() == 1
            && copied(&mac) == rotations(&hosted, &mac)[0]
            && mac
                .progress()
                .epoch_id
                .is_some_and(|epoch| epoch != old && mac.signer.holds_epoch(epoch))
            && *mac_client.1.borrow() == SyncStatus::Synced
    })
    .await;
    let rotated = rotations(&hosted, &mac)[0];
    let epoch = mac.progress().epoch_id.unwrap();
    assert!(matches!(
        accepted(&mac),
        AcceptedPersonal::Rotated { position, .. } if position == rotated
    ));
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        control,
        "no control-key signature"
    );
    assert_eq!(
        mac.signer.signed.load(Ordering::SeqCst),
        signed + 2,
        "the rekey's one seal and its control, with the ordinary key"
    );
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 1);
    let statuses = statuses.lock().unwrap().clone();
    let protecting = statuses
        .iter()
        .position(|status| *status == SyncStatus::Protecting)
        .expect("Protecting shown");
    assert!(
        statuses[protecting..]
            .iter()
            .all(|status| matches!(status, SyncStatus::Protecting | SyncStatus::Synced)),
        "Protecting until Synced: {statuses:?}"
    );

    let (_, update) = mac.new_note("protected by the new key");
    until(20, "note acknowledged", || {
        mac_client.0.wake();
        mac.acked(update).is_some()
    })
    .await;
    let package = mac.package(update).unwrap();
    assert_eq!(
        bh_event::sealed_epoch(&package.descriptor, mac.metadata_key().expose(), mac.base).unwrap(),
        epoch
    );
    mac_client.0.shutdown().await;
}

/// The device stops after its rotation is ordered, while the copier signs
/// the base's rekey and before anything of it is kept. Restarted, it
/// settles and accepts its own rotation and rekeys the base once: no second
/// rotation is staged or submitted.
#[tokio::test(start_paused = true)]
async fn crash_after_rotation_before_base_rekey_resumes_without_second_rotation() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let old = mac.progress().epoch_id.unwrap();
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let sign = mac.signer.hold_next_sign();
    hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    tokio::time::timeout(Duration::from_secs(60), sign.arrived)
        .await
        .expect("the base's rekey is signed")
        .unwrap();
    let rotated = rotations(&hosted, &mac)[0];
    assert!(
        mac.raw()
            .query_row(
                "SELECT COUNT(*) FROM base_control_outbox WHERE account_position=?1",
                [rotated as i64],
                |r| r.get::<_, i64>(0)
            )
            .unwrap()
            == 0,
        "nothing of the rekey kept"
    );
    mac_client.0.shutdown().await;
    drop(mac_client);
    drop(sign.release);
    until(20, "the client released the owner", || {
        Arc::strong_count(&mac.owner) == 1 && Arc::strong_count(&mac.signer) == 1
    })
    .await;
    let mac = mac.restart();
    let mut mac_client = mac.start(&hosted);
    until(120, "rekeyed and synced after the restart", || {
        mac_client.0.wake();
        copied(&mac) == rotated
            && mac
                .progress()
                .epoch_id
                .is_some_and(|epoch| epoch != old && mac.signer.holds_epoch(epoch))
            && *mac_client.1.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(rotations(&hosted, &mac), vec![rotated], "one rotation");
    assert_eq!(submitted_rotations(&hosted), 1);
    assert_eq!(mac.signer.rotations_staged.load(Ordering::SeqCst), 0);
    assert!(matches!(
        accepted(&mac),
        AcceptedPersonal::Rotated { position, .. } if position == rotated
    ));
    let rekeys = (1..=hosted.edge.head(mac.log()).position)
        .filter(|position| *position > 1 && installed_at(&mac, *position).is_some())
        .count();
    assert_eq!(rekeys, 1, "one rekey");
    mac_client.0.shutdown().await;
}

/// The device whose rekey the base ordered writes the own base's directory
/// entry once for the new epoch, at the rekey's base position, its key
/// sealed to the new personal key.
#[tokio::test(start_paused = true)]
async fn the_rekeys_producer_rewrites_the_directory_entry_under_the_new_personal_key() {
    let hosted = Hosted::new();
    let (mac, mac_client, _fold) = two(&hosted).await;
    let old = mac.progress().epoch_id.unwrap();
    until(20, "genesis entry written", || {
        mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    let member = Member::new();
    add(&hosted, &mac, &mac_client.0, &member).await;
    let writes = || hosted.edge.directory_writes.load(Ordering::SeqCst);
    let before = writes();
    hosted.edge.order_account(
        mac.account_log,
        &member.leave(&mac.signer.current_account().unwrap()),
    );
    mac_client.0.wake();
    until(120, "rekeyed and its entry written", || {
        mac_client.0.wake();
        mac.progress().epoch_id.is_some_and(|epoch| epoch != old)
            && matches!(mac.signer.directory_state().unwrap(), Some((v, true)) if v > 1)
    })
    .await;
    let epoch = mac.progress().epoch_id.unwrap();
    let (version, _) = mac.signer.directory_state().unwrap().unwrap();
    assert_eq!(
        installed_at(&mac, version),
        Some(epoch),
        "at the rekey's position"
    );
    assert_eq!(writes(), before + 1);
    let (_, held, bytes) = hosted
        .edge
        .directory(mac.account_log)
        .into_iter()
        .find(|(_, held, _)| *held == version)
        .unwrap();
    assert_eq!(held, version);
    let opened = mac
        .signer
        .open_directory_entries(vec![bytes])
        .await
        .unwrap();
    let bh_account::directory::DirectoryEntry::Base {
        epoch_id,
        current_key_seal,
        metadata_seal,
        ..
    } = &opened[0].as_ref().unwrap().entry
    else {
        panic!("a base entry")
    };
    assert_eq!(*epoch_id, epoch);
    let header = bh_device::base_keys::SealHeader::decode(current_key_seal).unwrap();
    let personal = *mac
        .signer
        .current_account()
        .unwrap()
        .personal_public()
        .unwrap();
    assert_eq!(header.key_id, epoch);
    assert_eq!(header.recipient, bh_crypto::hash(&personal), "sealed to P′");
    // The base's M, rewritten beside it, opens under P′.
    let metadata = bh_device::base_keys::SealHeader::decode(metadata_seal).unwrap();
    assert_eq!(
        metadata.purpose,
        bh_device::base_keys::BaseKeyPurpose::Metadata
    );
    assert_eq!(metadata.recipient, bh_crypto::hash(&personal));
    let (mut account, cap, _) = mac.signer.account_owner();
    let rotated = account.open_current_personal(&cap).await.unwrap();
    assert_eq!(rotated.public(), personal);
    let at = account.verified_at(&cap, metadata.head.position).unwrap();
    let opened = bh_device::base_keys::open_seal(&at, &metadata, metadata_seal, &rotated).unwrap();
    assert_eq!(Some(bh_event::key_id(&opened)), mac.progress().metadata_id);

    mac_client.0.shutdown().await;
}

/// A recovery replacement waiting for its new kit to be saved is not an
/// order attempt: however long the kit shows, the replacement is sent at
/// once when it is saved, on no grown backoff.
#[tokio::test(start_paused = true)]
async fn a_replacement_waiting_for_its_kit_is_sent_at_once_when_saved() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = mac.start(&hosted);
    until(20, "own base registered", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let seen = outcomes(&client);
    let (mut owner, cap, _) = mac.signer.account_owner();
    let password = bh_account::recovery::Password::new("a new password").unwrap();
    support::device::ready(owner.stage_recovery_replacement(&cap, &password)).unwrap();
    for _ in 0..30 {
        client.wake();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(settled(&seen, 8).is_none(), "not sent before it is saved");
    owner.confirm_staged_kit().unwrap();
    drop(owner);
    client.wake();
    until(2, "sent at once", || settled(&seen, 8).is_some()).await;
    assert!(matches!(
        settled(&seen, 8).unwrap().outcome,
        Ordered::Accepted { .. }
    ));
    client.shutdown().await;
}
