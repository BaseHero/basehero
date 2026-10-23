//! The base's rekey after the account rotates its personal key: the copier
//! finds the rotation next in the base's copy of the account and copies it
//! by one `ACCOUNT_REKEY`, whose new key it never sees. The key is drawn
//! and sealed to the new personal key inside the device; the seal and the
//! control are signed with the ordinary key, with no prompt; the control
//! and its seal set are kept before they are first sent, and every retry
//! sends both exactly. This device, like every other, gets the key from its
//! own seal once the base orders the rekey. Two genuine devices joined by
//! pairing, their native stores, the real authorization service behind the
//! attested channel, and the hosted fake's data edge.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::DevicePublicKeys;
use bh_authz::proto::{FromService, RecoveryAttachment, ToService, account_log_wrap};
use bh_crypto::{KemKey, SigningKey};
use bh_storage::sync_state::ControlOutcome;
use bh_sync::{
    OpaqueEvent, Route,
    permit::AppendAck,
    wire::{Request, Response},
};
use bh_sync_client::{Client, Signer, SyncStatus, data::DataSocket};
use std::sync::{Arc, atomic::Ordering};
use support::{
    device::{Device, until},
    fake::{Hook, Hosted, Seen},
    pair::{bootstrapped, paired},
};
use tokio::sync::watch;

type Started = (Client, watch::Receiver<SyncStatus>);

fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

async fn registered(hosted: &Arc<Hosted>, device: &Device) -> Started {
    let started = device.start(hosted);
    until(20, "registered", || {
        device.registered() && device.progress().position >= 1
    })
    .await;
    started
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
}

/// Two genuine devices, the second joined by pairing, and a third device
/// of the account whose addition both copied. Both clients stopped; every
/// control may be signed.
async fn joined_third() -> (Arc<Hosted>, Device, Device, Member) {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mac_client = registered(&hosted, &mac).await;
    let (fold, _) = paired(&hosted, &mac, &mac_client.0).await;
    bootstrapped(&hosted, &fold).await;
    until(20, "addition copied", || copied(&mac) == 4).await;
    fold.authorize().unwrap();
    for device in [&mac, &fold] {
        device.signer.approve_controls.store(true, Ordering::SeqCst);
        // These tests order the rotation themselves; the lanes stage none.
        device.signer.refuse_rotation.store(true, Ordering::SeqCst);
    }
    let fold_client = fold.start(&hosted);
    let third = Member::new();
    hosted
        .edge
        .order_account(mac.account_log, &mac.signer.add_device(third.keys.clone()));
    until(20, "third addition copied on both", || {
        mac_client.0.wake();
        fold_client.0.wake();
        copied(&mac) == 5 && copied(&fold) == 5
    })
    .await;
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
    (hosted, mac, fold, third)
}

/// The third device's removal of itself, signed with its control key.
fn leave(device: &Device, third: &Member) -> Vec<u8> {
    let request = device
        .signer
        .current_account()
        .unwrap()
        .remove_self(third.keys.id())
        .unwrap();
    request
        .finish(third.control.sign(request.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// As `joined_third`, and the third device leaves, copied on both, so the
/// removal closed the base's epoch. Both clients stopped.
async fn removed() -> (Arc<Hosted>, Device, Device) {
    let (hosted, mac, fold, third) = joined_third().await;
    let mac_client = mac.start(&hosted);
    let fold_client = fold.start(&hosted);
    hosted
        .edge
        .order_account(mac.account_log, &leave(&mac, &third));
    until(20, "removal copied on both", || {
        mac_client.0.wake();
        fold_client.0.wake();
        copied(&mac) == 6 && copied(&fold) == 6
    })
    .await;
    assert_eq!(
        mac.progress().epoch_id,
        None,
        "the removal closed the epoch"
    );
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
    (hosted, mac, fold)
}

/// One request on `client`'s authorization session.
async fn ask(client: &Client, message: ToService) -> FromService {
    client.authz().await.unwrap().ask(message).await.unwrap()
}

/// Stage each body, then append `event`, over a fresh data socket. Returns
/// the appended position.
async fn publish(
    hosted: &Arc<Hosted>,
    stages: Vec<(Vec<u8>, Vec<u8>)>,
    append: (Vec<u8>, Vec<u8>),
) -> u64 {
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    for (permit, body) in stages {
        let staged = data
            .ask(|id| Request::Stage { id, permit, body })
            .await
            .unwrap();
        assert!(matches!(staged, Response::Staged { .. }), "{staged:?}");
    }
    let (permit, event) = append;
    match data
        .ask(|id| Request::Append { id, permit, event })
        .await
        .unwrap()
    {
        Response::Acked { ack, .. } => AppendAck::decode(&ack).unwrap().head.position,
        other => panic!("{other:?}"),
    }
}

/// The rotation of the personal key for the removal at `reason`, signed
/// with `device`'s ordinary key and ordered through the account home with
/// its seals: its position and its body.
async fn order_rotation(
    hosted: &Arc<Hosted>,
    device: &Device,
    client: &Client,
    reason: u64,
) -> (u64, Vec<u8>) {
    let (rotation, prepared, _) = device
        .signer
        .rotate_personal(reason, hosted.edge.clock.now());
    let body = support::stage_rotation(hosted, client, device.account_log, &prepared.body).await;
    let answer = ask(
        client,
        ToService::SubmitControl {
            log: device.account_log,
            event: rotation.clone(),
            delivery: None,
            attachment: Some(Box::new(RecoveryAttachment {
                record: None,
                recovery_seal: prepared.recovery_seal.clone(),
                rotation_body: Some(body),
            })),
        },
    )
    .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let items: Vec<Vec<u8>> = items.into_iter().map(Result::unwrap).collect();
    assert_eq!(items.len(), 1, "the body is staged already");
    let wrapped = account_log_wrap(&rotation, Some(body)).unwrap();
    let at = publish(hosted, vec![], (items[0].clone(), wrapped.encode())).await;
    (at, prepared.body)
}

/// The judged control at `position` of the device's own base.
fn judged(device: &Device, position: u64) -> Option<bh_device::control::ControlFact> {
    device
        .owner
        .control_fact(device.id, device.log(), position)
        .unwrap()
}

/// The control kept for the base copy's successor at `position`, settled
/// or not.
fn kept(device: &Device, position: u64) -> Option<bh_storage::sync_state::BaseControl> {
    device
        .raw()
        .query_row(
            "SELECT event_id,descriptor,body FROM base_control_outbox
             WHERE base=?1 AND account_position=?2",
            rusqlite::params![device.base.0.as_slice(), position as i64],
            |r| {
                Ok(bh_storage::sync_state::BaseControl {
                    base: device.base.0,
                    account_position: position,
                    event_id: r.get::<_, Vec<u8>>(0)?.try_into().unwrap(),
                    descriptor: r.get(1)?,
                    body: r.get(2)?,
                })
            },
        )
        .ok()
}

fn outcome(device: &Device, position: u64) -> Option<Option<ControlOutcome>> {
    device
        .owner
        .shared_database(device.id)
        .unwrap()
        .lock()
        .unwrap()
        .base_control_outcome(device.base.0, position)
        .unwrap()
}

/// The seal set `device` kept with its rekey `event_id`.
fn kept_set(device: &Device, event_id: [u8; 32]) -> Option<Vec<u8>> {
    device
        .owner
        .shared_database(device.id)
        .unwrap()
        .lock()
        .unwrap()
        .kept_seal_set(event_id)
        .unwrap()
}

/// The new key id a rekey's exact bytes name.
fn rekey_epoch(device: &Device, descriptor: &[u8], body: &[u8]) -> [u8; 32] {
    let metadata = device.metadata_key();
    bh_event::rekey::rekey_seal_set(
        device.base,
        &OpaqueEvent::decode(descriptor).unwrap(),
        body,
        metadata.expose(),
    )
    .unwrap()
    .unwrap()
    .key_id
}

/// The rekeys the base log holds, by event id, in order.
fn rekeys(hosted: &Hosted, device: &Device) -> Vec<[u8; 32]> {
    hosted
        .edge
        .entries(device.log())
        .iter()
        .filter(|(ordered, _)| ordered.route() == Route::Control)
        .filter_map(|(ordered, event)| {
            let fact = judged(device, ordered.head().position)?;
            (fact.epoch_installed.0 == ordered.head().position && fact.position > 1)
                .then(|| event.publication_id(Route::Control).0)
        })
        .collect()
}

/// Wait until `device` holds the new epoch's key: its base's content epoch
/// is one it installed.
async fn holds_new_epoch(device: &Device, client: &Client, what: &str) -> [u8; 32] {
    until(20, what, || {
        client.wake();
        device
            .progress()
            .epoch_id
            .is_some_and(|epoch| device.signer.holds_epoch(epoch))
    })
    .await;
    device.progress().epoch_id.unwrap()
}

/// The rotation that takes effect is next in the base's copy of the
/// account: the copier copies it by one rekey signed with the ordinary key,
/// with no control-key signature. Its seal is sealed to the new personal
/// key: the base's epoch reopens, and the other device, once it accepts the
/// rotation, reads and writes under the new key.
#[tokio::test(start_paused = true)]
async fn an_effective_rotation_is_copied_by_one_rekey_without_a_prompt() {
    let (hosted, mac, fold) = removed().await;
    let mac_client = mac.start(&hosted);
    until(20, "mac caught up", || {
        mac.progress().position == hosted.edge.head(mac.log()).position
    })
    .await;
    let control_signatures = mac.signer.control_signatures.load(Ordering::SeqCst);
    let signed = mac.signer.signed.load(Ordering::SeqCst);
    let (rotation_at, body) = order_rotation(&hosted, &mac, &mac_client.0, 6).await;
    until(20, "mac followed the rotation", || {
        mac_client.0.wake();
        mac.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    mac.signer.accept_rotation(rotation_at, &body);
    let epoch = holds_new_epoch(&mac, &mac_client.0, "the mac installed its rekey's key").await;
    assert_eq!(copied(&mac), rotation_at);
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        control_signatures,
        "no control-key signature"
    );
    assert_eq!(
        mac.signer.signed.load(Ordering::SeqCst),
        signed + 2,
        "one ordinary signature for the seal, one for the control"
    );
    let rekeys = rekeys(&hosted, &mac);
    assert_eq!(rekeys.len(), 1, "one rekey");
    assert_eq!(
        outcome(&mac, rotation_at),
        Some(Some(ControlOutcome::Committed))
    );
    assert!(kept_set(&mac, rekeys[0]).is_some());

    // The other device accepts the rotation and opens the new key from the
    // mac's seal: both read and write under it.
    let fold_client = fold.start(&hosted);
    until(20, "the fold followed the rotation", || {
        fold_client.0.wake();
        fold.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    fold.signer.accept_rotation(rotation_at, &body);
    assert_eq!(
        holds_new_epoch(&fold, &fold_client.0, "the fold installed the new key").await,
        epoch
    );
    let (from_mac, mac_note) = mac.new_note("from the mac under the new key");
    let (from_fold, fold_note) = fold.new_note("from the fold under the new key");
    until(20, "each read the other's note", || {
        mac_client.0.wake();
        fold_client.0.wake();
        fold.inserted(from_mac.note, "from the mac under the new key") == 1
            && mac.inserted(from_fold.note, "from the fold under the new key") == 1
    })
    .await;
    for (device, update) in [(&mac, mac_note), (&fold, fold_note)] {
        let package = device.package(update).unwrap();
        assert_eq!(
            bh_event::sealed_epoch(
                &package.descriptor,
                device.metadata_key().expose(),
                device.base
            )
            .unwrap(),
            epoch
        );
    }
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

/// The mac's rotation, ordered and followed, with its client running: the
/// mac's copier is about to rekey. Returns the rotation's position and body.
async fn rotated(hosted: &Arc<Hosted>, mac: &Device, client: &Client) -> (u64, Vec<u8>) {
    until(20, "mac caught up", || {
        mac.progress().position == hosted.edge.head(mac.log()).position
    })
    .await;
    let (rotation_at, body) = order_rotation(hosted, mac, client, 6).await;
    until(20, "mac followed the rotation", || {
        client.wake();
        mac.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    (rotation_at, body)
}

/// Every base append of `kept`'s event, and every stage of its seal set.
fn sends(
    hosted: &Hosted,
    device: &Device,
    kept: &bh_storage::sync_state::BaseControl,
) -> (usize, usize) {
    let set = kept_set(device, kept.event_id).unwrap();
    let appends = hosted.edge.appends(device.log().id);
    let stages = hosted.edge.stages(device.log().id);
    (
        appends.iter().filter(|a| **a == kept.descriptor).count(),
        stages.iter().filter(|s| **s == set).count(),
    )
}

/// The edge loses the rekey's staged seal set and body before its append,
/// so that send has no effect; the copier sends the same control again and
/// stages the same seal set. That append orders and its answer is lost
/// with its socket; the verified log settles the one rekey. No second key
/// is drawn and nothing is signed again.
#[tokio::test(start_paused = true)]
async fn a_lost_rekey_answer_resends_the_same_control_and_set() {
    let (hosted, mac, _fold) = removed().await;
    let mac_client = mac.start(&hosted);
    hosted.edge.hook(Hook::ReclaimBeforeAppend);
    hosted.edge.hook(Hook::DropAfterAppend { then_down: false });
    let signed = mac.signer.signed.load(Ordering::SeqCst);
    let (rotation_at, body) = rotated(&hosted, &mac, &mac_client.0).await;
    mac.signer.accept_rotation(rotation_at, &body);
    holds_new_epoch(&mac, &mac_client.0, "the mac installed its rekey's key").await;
    let first = kept(&mac, rotation_at).unwrap();
    let set = kept_set(&mac, first.event_id).unwrap();
    assert_eq!(hosted.edge.hooks_left(), 0);
    assert_eq!(
        sends(&hosted, &mac, &first),
        (2, 2),
        "the same control and set, sent again"
    );
    assert_eq!(rekeys(&hosted, &mac), vec![first.event_id], "ordered once");
    assert_eq!(
        outcome(&mac, rotation_at),
        Some(Some(ControlOutcome::Committed))
    );
    assert_eq!(kept_set(&mac, first.event_id).unwrap(), set);
    assert_eq!(
        mac.signer.signed.load(Ordering::SeqCst),
        signed + 2,
        "one key's seal and control, nothing signed again"
    );
    assert_eq!(
        mac.progress().epoch_id,
        Some(rekey_epoch(&mac, &first.descriptor, &first.body))
    );
    mac_client.0.shutdown().await;
}

/// Wait, at most 20 s, for a held signature to be asked for.
async fn signing(arrived: tokio::sync::oneshot::Receiver<()>) {
    tokio::time::timeout(std::time::Duration::from_secs(20), arrived)
        .await
        .expect("the copier signs a rekey")
        .unwrap();
}

/// Wait until the client let go of the device's state, then restart it.
async fn restarted(device: Device, client: Started) -> Device {
    client.0.shutdown().await;
    drop(client);
    until(20, "the client released the owner", || {
        Arc::strong_count(&device.owner) == 1 && Arc::strong_count(&device.signer) == 1
    })
    .await;
    let device = device.restart();
    device.signer.refuse_rotation.store(true, Ordering::SeqCst);
    device
}

/// A rekey kept before it could be sent survives a restart: the restarted
/// client sends that control and stages that seal set, signing nothing and
/// drawing no second key.
#[tokio::test(start_paused = true)]
async fn restart_between_keeping_and_sending_a_rekey_resends_it() {
    let (hosted, mac, _fold) = removed().await;
    let mac_client = mac.start(&hosted);
    let sign = mac.signer.hold_next_sign();
    let (rotation_at, body) = rotated(&hosted, &mac, &mac_client.0).await;
    signing(sign.arrived).await;
    // The edge goes away while the copier signs: it keeps the rekey and
    // cannot send it.
    hosted.go_down();
    let _ = sign.release.send(());
    until(20, "the rekey kept", || kept(&mac, rotation_at).is_some()).await;
    let first = kept(&mac, rotation_at).unwrap();
    let set = kept_set(&mac, first.event_id).unwrap();
    let mac = restarted(mac, mac_client).await;
    assert_eq!(sends(&hosted, &mac, &first), (0, 0), "never sent");
    hosted.come_up();
    mac.signer.accept_rotation(rotation_at, &body);
    let mac_client = mac.start(&hosted);
    holds_new_epoch(&mac, &mac_client.0, "the mac installed its rekey's key").await;
    assert_eq!(sends(&hosted, &mac, &first), (1, 1), "sent once, exactly");
    assert_eq!(rekeys(&hosted, &mac), vec![first.event_id]);
    assert_eq!(kept_set(&mac, first.event_id).unwrap(), set);
    assert_eq!(
        mac.signer.signed.load(Ordering::SeqCst),
        0,
        "nothing signed after the restart"
    );
    assert_eq!(
        mac.progress().epoch_id,
        Some(rekey_epoch(&mac, &first.descriptor, &first.body))
    );
    mac_client.0.shutdown().await;
}

/// Both devices find the rotation next and each keeps its own rekey: the
/// base orders one; the other's copy is superseded, its key never used.
#[tokio::test(start_paused = true)]
async fn two_devices_rekey_one_base_and_the_loser_stands_down() {
    let (hosted, mac, fold) = removed().await;
    let mac_client = mac.start(&hosted);
    let fold_client = fold.start(&hosted);
    until(20, "both caught up", || {
        let head = hosted.edge.head(mac.log()).position;
        mac.progress().position == head && fold.progress().position == head
    })
    .await;
    // Each copier waits at its seal's signature until both are there.
    let holds = [mac.signer.hold_next_sign(), fold.signer.hold_next_sign()];
    let (rotation_at, body) = order_rotation(&hosted, &mac, &mac_client.0, 6).await;
    let mut released = Vec::new();
    for hold in holds {
        until(20, "both followed the rotation", || {
            mac_client.0.wake();
            fold_client.0.wake();
            true
        })
        .await;
        signing(hold.arrived).await;
        released.push(hold.release);
    }
    for release in released {
        let _ = release.send(());
    }
    until(20, "both settled their rekeys", || {
        mac_client.0.wake();
        fold_client.0.wake();
        outcome(&mac, rotation_at).is_some_and(|o| o.is_some())
            && outcome(&fold, rotation_at).is_some_and(|o| o.is_some())
    })
    .await;
    let outcomes = [
        outcome(&mac, rotation_at).unwrap().unwrap(),
        outcome(&fold, rotation_at).unwrap().unwrap(),
    ];
    let (winner, loser) = match outcomes {
        [ControlOutcome::Committed, ControlOutcome::Superseded] => (&mac, &fold),
        [ControlOutcome::Superseded, ControlOutcome::Committed] => (&fold, &mac),
        other => panic!("one wins, one stands down: {other:?}"),
    };
    let won = kept(winner, rotation_at).unwrap();
    let lost = kept(loser, rotation_at).unwrap();
    assert_eq!(rekeys(&hosted, &mac), vec![won.event_id]);
    let epoch = rekey_epoch(winner, &won.descriptor, &won.body);
    assert_ne!(rekey_epoch(loser, &lost.descriptor, &lost.body), epoch);
    for (device, client) in [(&mac, &mac_client), (&fold, &fold_client)] {
        until(20, "followed", || {
            client.0.wake();
            device.signer.current_account().unwrap().head().position == rotation_at
        })
        .await;
        device.signer.accept_rotation(rotation_at, &body);
        assert_eq!(
            holds_new_epoch(device, &client.0, "installed the winner's key").await,
            epoch
        );
    }
    assert!(
        hosted
            .edge
            .entries(mac.log())
            .iter()
            .all(|(_, event)| event.publication_id(Route::Control).0 != lost.event_id),
        "the loser's rekey never ordered"
    );
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

/// The edge refuses the stage of the rekey's seal set: the rekey stays
/// kept and is sent again with that same set, no new key drawn.
#[tokio::test(start_paused = true)]
async fn a_refused_seal_set_stage_keeps_the_rekey_and_retries() {
    let (hosted, mac, _fold) = removed().await;
    let mac_client = mac.start(&hosted);
    let signed = mac.signer.signed.load(Ordering::SeqCst);
    let sign = mac.signer.hold_next_sign();
    let (rotation_at, body) = rotated(&hosted, &mac, &mac_client.0).await;
    signing(sign.arrived).await;
    // The seal set's stage permit lapses before the edge checks it.
    hosted.edge.hook(Hook::ExpireStage);
    let _ = sign.release.send(());
    mac.signer.accept_rotation(rotation_at, &body);
    holds_new_epoch(&mac, &mac_client.0, "the mac installed its rekey's key").await;
    assert_eq!(hosted.edge.hooks_left(), 0);
    assert!(
        hosted
            .edge
            .seen()
            .iter()
            .filter(|s| **s
                == Seen::Refused {
                    reason: bh_sync::wire::Refusal::Expired
                })
            .count()
            >= 1,
        "the set's stage was refused"
    );
    let first = kept(&mac, rotation_at).unwrap();
    assert_eq!(
        sends(&hosted, &mac, &first),
        (1, 1),
        "then the same set staged and the control appended"
    );
    assert_eq!(rekeys(&hosted, &mac), vec![first.event_id]);
    assert_eq!(mac.signer.signed.load(Ordering::SeqCst), signed + 2);
    mac_client.0.shutdown().await;
}

/// A kept rekey whose seen claim fell further behind the log than the
/// services take is never sent again: it is replaced, with a fresh key and
/// seal set, by one prepared from the base's current state, which orders.
#[tokio::test(start_paused = true)]
async fn a_rekey_kept_past_the_seen_window_is_replaced_and_never_sent() {
    let (hosted, mac, _fold) = removed().await;
    *hosted.edge.seen_window.lock().unwrap() = Some(3);
    // Every send of the first rekey is refused, so it stays kept.
    hosted
        .edge
        .refuse_next_event(bh_sync::wire::Refusal::Predecessor);
    let mac_client = mac.start(&hosted);
    let signed = mac.signer.signed.load(Ordering::SeqCst);
    let (rotation_at, body) = rotated(&hosted, &mac, &mac_client.0).await;
    until(20, "the first rekey kept and refused", || {
        mac_client.0.wake();
        kept(&mac, rotation_at).is_some_and(|first| sends(&hosted, &mac, &first).0 >= 1)
    })
    .await;
    let first = kept(&mac, rotation_at).unwrap();
    mac_client.0.shutdown().await;
    // The log moves on past the window, and the service lets the first
    // rekey's permits lapse.
    for note in 0..4 {
        mac.remote_note(&hosted, [80 + note; 32], b"later");
    }
    hosted.edge.clock.advance(120_000);
    let stale = sends(&hosted, &mac, &first);
    mac.signer.accept_rotation(rotation_at, &body);
    let mac_client = mac.start(&hosted);
    let epoch = holds_new_epoch(&mac, &mac_client.0, "the fresh rekey's key installed").await;
    let fresh = kept(&mac, rotation_at).unwrap();
    assert_ne!(fresh.event_id, first.event_id);
    assert_eq!(rekeys(&hosted, &mac), vec![fresh.event_id]);
    assert_eq!(rekey_epoch(&mac, &fresh.descriptor, &fresh.body), epoch);
    assert_ne!(
        rekey_epoch(&mac, &first.descriptor, &first.body),
        epoch,
        "a fresh key"
    );
    assert_eq!(kept_set(&mac, first.event_id), None, "the old set is gone");
    let appends = hosted.edge.appends(mac.log().id);
    assert_eq!(
        appends.iter().filter(|a| **a == first.descriptor).count(),
        stale.0,
        "the stale rekey was never sent again"
    );
    let ordered = hosted
        .edge
        .entries(mac.log())
        .into_iter()
        .find(|(_, event)| event.publication_id(Route::Control).0 == fresh.event_id)
        .unwrap();
    let metadata = mac.metadata_key();
    let seen = bh_event::sealed_seen(&ordered.1, metadata.expose(), mac.base)
        .unwrap()
        .position;
    assert!(ordered.0.head().position - seen <= 3, "within the window");
    assert_eq!(mac.signer.signed.load(Ordering::SeqCst), signed + 4);
    mac_client.0.shutdown().await;
}

/// A rekey after a long account history reads only what the base lacks:
/// the earlier entries are copied in runs, and the rekey itself costs one
/// ordinary signature for its one seal and one for its control, with no
/// control-key signature and no account read from the genesis.
#[tokio::test(start_paused = true)]
async fn a_rekey_after_long_history_reads_only_the_copied_range() {
    let (hosted, mac, _fold) = removed().await;
    let mac_client = mac.start(&hosted);
    // Devices join and leave, one after another: the account stays small
    // while its history grows.
    let mut at = 6;
    while at < 200 {
        let member = Member::new();
        let added = hosted
            .edge
            .order_account(mac.account_log, &mac.signer.add_device(member.keys.clone()));
        until(20, "followed", || {
            mac_client.0.wake();
            mac.signer.current_account().unwrap().head().position == added
        })
        .await;
        let request = mac
            .signer
            .current_account()
            .unwrap()
            .remove_self(member.keys.id())
            .unwrap();
        let leave = request
            .finish(member.control.sign(request.signing_bytes()))
            .unwrap();
        at = hosted.edge.order_account(mac.account_log, leave.as_bytes());
        until(20, "followed", || {
            mac_client.0.wake();
            mac.signer.current_account().unwrap().head().position == at
        })
        .await;
    }
    let through = at;
    until(20, "the earlier history copied", || {
        mac_client.0.wake();
        copied(&mac) == through
    })
    .await;
    let control_signatures = mac.signer.control_signatures.load(Ordering::SeqCst);
    let signed = mac.signer.signed.load(Ordering::SeqCst);
    let reads = hosted.edge.reads(mac.account_log).len();
    let (rotation_at, body) = order_rotation(&hosted, &mac, &mac_client.0, through).await;
    until(20, "mac followed the rotation", || {
        mac_client.0.wake();
        mac.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    mac.signer.accept_rotation(rotation_at, &body);
    holds_new_epoch(&mac, &mac_client.0, "the mac installed its rekey's key").await;
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        control_signatures
    );
    assert_eq!(mac.signer.signed.load(Ordering::SeqCst), signed + 2);
    let later = &hosted.edge.reads(mac.account_log)[reads..];
    assert!(!later.is_empty());
    assert!(
        later.iter().all(|(first, _)| *first > through),
        "account reads start past what the base holds: {later:?}"
    );
    mac_client.0.shutdown().await;
}

/// Local work of the mac's: a note update or a typed mutation's package.
#[derive(Clone, Copy)]
enum Work {
    Note(i64),
    Typed(i64),
}
impl Work {
    /// Its sealed package's exact bytes, if it has one.
    fn package(self, device: &Device) -> Option<(bh_sync::EventId, OpaqueEvent)> {
        match self {
            Work::Note(update) => device.package(update).map(|p| (p.event_id, p.descriptor)),
            Work::Typed(id) => device.typed_package(id).map(|p| (p.event_id, p.descriptor)),
        }
    }
    fn acked(self, device: &Device) -> Option<u64> {
        match self {
            Work::Note(update) => device.acked(update),
            Work::Typed(id) => device.typed_acked(id),
        }
    }
}

/// The epoch a package's exact bytes were sealed under.
fn sealed_under(device: &Device, descriptor: &OpaqueEvent) -> [u8; 32] {
    bh_event::sealed_epoch(descriptor, device.metadata_key().expose(), device.base).unwrap()
}

/// The mac seals local work under the base's epoch while it cannot read
/// the removal the fold already copied: the service refuses it for that
/// epoch. Then the mac reads on and its content passes the removal: the
/// package can never be ordered and is never sent again, its work waiting
/// for the new epoch's key. Returns the fold's client, the work, its first package's id
/// and the epoch it was sealed under.
async fn refused_behind_a_removal(
    typed: bool,
) -> (
    Arc<Hosted>,
    Device,
    Started,
    Device,
    Started,
    Work,
    bh_sync::EventId,
) {
    let (hosted, mac, fold, third) = joined_third().await;
    let fold_client = fold.start(&hosted);
    hosted
        .edge
        .order_account(mac.account_log, &leave(&fold, &third));
    until(20, "the fold copied the removal", || {
        fold_client.0.wake();
        copied(&fold) == 6 && fold.progress().position == hosted.edge.head(fold.log()).position
    })
    .await;
    let removal_at = hosted.edge.head(mac.log()).position;
    let old = mac.progress().epoch_id.unwrap();
    // The mac cannot read the removal yet: it seals under the old epoch.
    hosted.edge.freeze_reads(Some(removal_at - 1));
    let work = if typed {
        Work::Typed(
            mac.typed_submit(bh_data::mutation::ops::Operation::DefineApp {
                app: bh_data::AppId([7; 32]),
                name: "Sealed behind a removal".into(),
            })
            .1,
        )
    } else {
        Work::Note(mac.new_note("sealed behind a removal").1)
    };
    let asked = hosted.edge.counts().want_stage;
    let mac_client = mac.start(&hosted);
    // The service refuses it for that epoch. The removal took effect, so
    // the device shows it is renewing protection.
    let mut status = mac_client.1.clone();
    until(20, "sealed under the old epoch and refused", || {
        mac_client.0.wake();
        work.package(&mac).is_some()
            && hosted.edge.counts().want_stage > asked
            && *status.borrow_and_update() == SyncStatus::Protecting
    })
    .await;
    let (first, descriptor) = work.package(&mac).unwrap();
    assert_eq!(sealed_under(&mac, &descriptor), old);
    assert!(
        !hosted.edge.seen().iter().any(
            |seen| matches!(seen, Seen::Publish { event, .. } if *event == descriptor.encode())
        ),
        "its permits were refused: nothing reached the edge"
    );
    assert_eq!(
        mac.progress().epoch_id,
        Some(old),
        "content has not passed it"
    );
    // Content passes the removal: the package can never be ordered and is
    // never sent again; its work waits for the new epoch's key.
    hosted.edge.freeze_reads(None);
    until(20, "content passed the removal", || {
        mac_client.0.wake();
        mac.progress().epoch_id.is_none()
    })
    .await;
    let stages = hosted.edge.counts().want_stage;
    for _ in 0..30 {
        mac_client.0.wake();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert_eq!(work.package(&mac).unwrap().0, first, "kept until resealed");
    assert_eq!(
        hosted.edge.counts().want_stage,
        stages,
        "nothing asked to send it"
    );
    assert_eq!(work.acked(&mac), None);
    (hosted, mac, mac_client, fold, fold_client, work, first)
}

/// The fold rotates the personal key for the removal; the base is rekeyed
/// and both devices accept the rotation and hold the new key.
async fn rotate_and_rekey(
    hosted: &Arc<Hosted>,
    mac: &Device,
    mac_client: &Client,
    fold: &Device,
    fold_client: &Client,
) -> [u8; 32] {
    let (rotation_at, body) = order_rotation(hosted, fold, fold_client, 6).await;
    for (device, client) in [(mac, mac_client), (fold, fold_client)] {
        until(20, "followed the rotation", || {
            client.wake();
            device.signer.current_account().unwrap().head().position == rotation_at
        })
        .await;
        device.signer.accept_rotation(rotation_at, &body);
    }
    let epoch = holds_new_epoch(mac, mac_client, "the mac holds the new key").await;
    assert_eq!(
        holds_new_epoch(fold, fold_client, "the fold holds the new key").await,
        epoch
    );
    epoch
}

/// What the base log holds of `work` once it is ordered: its package's id,
/// which is not `first`'s, and that it orders once under the new epoch.
fn ordered_once(
    hosted: &Hosted,
    mac: &Device,
    work: Work,
    first: bh_sync::EventId,
    epoch: [u8; 32],
) {
    let (again, descriptor) = work.package(mac).unwrap();
    assert_ne!(again, first, "a new package with a new id");
    assert_eq!(sealed_under(mac, &descriptor), epoch);
    let entries = hosted.edge.entries(mac.log());
    assert!(
        entries
            .iter()
            .all(|(ordered, _)| ordered.event_id() != first),
        "the first package never ordered"
    );
    assert_eq!(
        entries
            .iter()
            .filter(|(ordered, _)| ordered.event_id() == again)
            .count(),
        1
    );
    assert!(
        !hosted
            .edge
            .appends(mac.log().id)
            .iter()
            .skip_while(
                |a| OpaqueEvent::decode(a).is_ok_and(|e| e.publication_id(Route::Content) != again)
            )
            .any(
                |a| OpaqueEvent::decode(a).is_ok_and(|e| e.publication_id(Route::Content) == first)
            ),
        "the first package's bytes were not sent again once resealed"
    );
}

/// A note sealed under an epoch before the device read the removal that
/// replaced it is refused for that epoch and waits; once content passes the
/// removal it can never be ordered, so once the new epoch's key is held its
/// work is sealed again as a new package that replaces it in one
/// transaction, and orders.
#[tokio::test(start_paused = true)]
async fn a_package_refused_under_a_replaced_epoch_is_resealed_once_content_passes_the_removal() {
    let (hosted, mac, mac_client, fold, fold_client, work, first) =
        refused_behind_a_removal(false).await;
    let epoch = rotate_and_rekey(&hosted, &mac, &mac_client.0, &fold, &fold_client.0).await;
    until(20, "resealed and ordered", || {
        mac_client.0.wake();
        work.acked(&mac).is_some()
    })
    .await;
    ordered_once(&hosted, &mac, work, first, epoch);
    let Work::Note(update) = work else {
        unreachable!()
    };
    let note: Vec<u8> = mac
        .raw()
        .query_row("SELECT note FROM note_updates WHERE id=?1", [update], |r| {
            r.get(0)
        })
        .unwrap();
    until(20, "the fold read it", || {
        fold_client.0.wake();
        fold.inserted(note.clone().try_into().unwrap(), "sealed behind a removal") == 1
    })
    .await;
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

/// The same for a typed mutation's package: its saved work kept, and
/// sealed again under the new epoch with a new id in the same entry.
#[tokio::test(start_paused = true)]
async fn a_typed_package_refused_under_a_replaced_epoch_is_resealed_once_content_passes_the_removal()
 {
    let (hosted, mac, mac_client, fold, fold_client, work, first) =
        refused_behind_a_removal(true).await;
    let epoch = rotate_and_rekey(&hosted, &mac, &mac_client.0, &fold, &fold_client.0).await;
    until(20, "resealed and ordered", || {
        mac_client.0.wake();
        work.acked(&mac).is_some()
    })
    .await;
    ordered_once(&hosted, &mac, work, first, epoch);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

/// A restart after content passed the removal and before the work is
/// sealed again: the package is replaced once, by exactly one new package,
/// ordered once.
#[tokio::test(start_paused = true)]
async fn a_restart_before_the_reseal_orders_exactly_one_new_package() {
    let (hosted, mac, mac_client, fold, fold_client, work, first) =
        refused_behind_a_removal(false).await;
    let mac = restarted(mac, mac_client).await;
    assert_eq!(work.package(&mac).unwrap().0, first);
    let mac_client = mac.start(&hosted);
    let epoch = rotate_and_rekey(&hosted, &mac, &mac_client.0, &fold, &fold_client.0).await;
    until(20, "resealed and ordered", || {
        mac_client.0.wake();
        work.acked(&mac).is_some()
    })
    .await;
    ordered_once(&hosted, &mac, work, first, epoch);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

/// The service granted a note's permits while its epoch was open, and the
/// send was lost before its append. Once content passes the removal that
/// replaced that epoch and the new key is held, its work is sealed again and
/// sent once, under fresh permits: never the old package's, which name other
/// bytes.
#[tokio::test(start_paused = true)]
async fn a_resealed_package_is_sent_under_fresh_permits_not_its_old_ones() {
    resealed_under_fresh_permits(false).await;
}

/// The same for a typed mutation's package.
#[tokio::test(start_paused = true)]
async fn a_resealed_typed_package_is_sent_under_fresh_permits_not_its_old_ones() {
    resealed_under_fresh_permits(true).await;
}

async fn resealed_under_fresh_permits(typed: bool) {
    let (hosted, mac, fold, third) = joined_third().await;
    let old = mac.progress().epoch_id.unwrap();
    let work = if typed {
        Work::Typed(
            mac.typed_submit(bh_data::mutation::ops::Operation::DefineApp {
                app: bh_data::AppId([7; 32]),
                name: "Sent under fresh permits".into(),
            })
            .1,
        )
    } else {
        Work::Note(mac.new_note("sent under fresh permits").1)
    };
    // Its publish is staged and held before its append, under permits for
    // the open epoch.
    let hold = hosted.edge.hold_next_stage();
    let mac_client = mac.start(&hosted);
    let mut status = mac_client.1.clone();
    signing(hold.arrived).await;
    let (first, descriptor) = work.package(&mac).unwrap();
    assert_eq!(sealed_under(&mac, &descriptor), old);
    let fold_client = fold.start(&hosted);
    hosted
        .edge
        .order_account(mac.account_log, &leave(&fold, &third));
    until(20, "content passed the removal", || {
        mac_client.0.wake();
        fold_client.0.wake();
        copied(&mac) == 6 && mac.progress().epoch_id.is_none()
    })
    .await;
    // The socket drops: the send is lost, and its permits are still live.
    drop(hold.release);
    let epoch = rotate_and_rekey(&hosted, &mac, &mac_client.0, &fold, &fold_client.0).await;
    let mut alarmed = false;
    until(20, "resealed and ordered", || {
        mac_client.0.wake();
        alarmed |= matches!(*status.borrow_and_update(), SyncStatus::NotAccepted { .. });
        work.acked(&mac).is_some()
    })
    .await;
    ordered_once(&hosted, &mac, work, first, epoch);
    let (_, descriptor) = work.package(&mac).unwrap();
    let publishes = hosted
        .edge
        .seen()
        .into_iter()
        .filter(|seen| matches!(seen, Seen::Publish { event, .. } if *event == descriptor.encode()))
        .count();
    assert!(!alarmed, "nothing refused it as out of scope");
    assert_eq!(publishes, 1, "the new package was sent once, and accepted");
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}
