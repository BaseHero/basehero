//! A base's new content epoch reaching a device that does not hold its key
//! yet: the account rotates its personal key after a removal and another
//! device rekeys the own base. The control feed judges the rekey with M
//! alone and keeps a durable wait for its seal set; content keeps its one
//! ordered cursor before the new epoch's first event; the receiver reads the
//! set by its commitment and the signer installs this account's key, then
//! content resumes in order. Real signed-up devices and their native stores,
//! the real authorization service behind the attested channel, and the
//! hosted fake's data edge.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::DevicePublicKeys;
use bh_authz::proto::{
    FromService, RecoveryAttachment, ToService, Want, account_log_wrap, rotation_body,
};
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_sync::{
    BodyObject, Digest, Head,
    permit::AppendAck,
    referenced_body,
    wire::{Request, Response},
};
use bh_sync_client::{Client, EpochInstalled, Signer, SyncStatus, data::DataSocket};
use std::sync::{Arc, atomic::Ordering};
use support::{
    device::{Device, until},
    fake::Hosted,
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

/// Two devices of one account on the first one's base: the second joined by
/// the real QR flow, its addition copied into the base by the first, both
/// caught up.
async fn two(hosted: &Arc<Hosted>) -> (Device, Started, Device, Started) {
    let mac = Device::new();
    let mac_client = mac.start(hosted);
    until(20, "own base registered", || {
        mac.registered() && mac.progress().position >= 1
    })
    .await;
    let (fold, _) = paired(hosted, &mac, &mac_client.0).await;
    bootstrapped(hosted, &fold).await;
    fold.authorize().unwrap();
    // These tests order the rotation themselves; the lanes stage none. The
    // person has approved controls, as after pairing's one approval.
    for device in [&mac, &fold] {
        device.signer.approve_controls.store(true, Ordering::SeqCst);
        device.signer.refuse_rotation.store(true, Ordering::SeqCst);
    }
    until(20, "addition copied", || copied(&mac) == 4).await;
    let fold_client = fold.start(hosted);
    until(20, "joined device caught up", || {
        fold.progress().position == mac.progress().position && copied(&fold) == 4
    })
    .await;
    (mac, mac_client, fold, fold_client)
}

/// The judged control at `position` of the device's own base.
fn judged(device: &Device, position: u64) -> Option<bh_device::control::ControlFact> {
    device
        .owner
        .control_fact(device.id, device.log(), position)
        .unwrap()
}

fn waits(device: &Device) -> Vec<bh_device::control::SealWait> {
    device.owner.seal_waits(device.id).unwrap()
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

/// The base after a rekey the mac has no key for: its position, the new
/// key, its seal set and the rotation the mac accepts.
struct Rekeyed {
    hosted: Arc<Hosted>,
    mac: Device,
    fold: Device,
    rekey_at: u64,
    key: Secret<32>,
    set: Vec<u8>,
    rotation_at: u64,
    body: Vec<u8>,
    note: [u8; 32],
    note_at: u64,
}

/// One request on `client`'s authorization session.
async fn ask(client: &Client, message: ToService) -> FromService {
    client.authz().await.unwrap().ask(message).await.unwrap()
}

/// The permits an answer granted, in order.
fn permits(answer: FromService) -> Vec<Vec<u8>> {
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    items.into_iter().map(Result::unwrap).collect()
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

/// A third device joins and leaves, both copied into the base (the removal
/// closes its epoch); the fold rotates the personal key for that removal
/// and rekeys the base, both through the service, sealing the new key to
/// the new personal key; then it writes a note under the new key. The seal
/// set is withheld.
async fn rekeyed() -> Rekeyed {
    rekeyed_with(false).await.0
}

/// A note the fold wrote before the removal, whose body the edge withholds
/// from the mac: its position and body bytes.
struct Gap {
    at: u64,
    body: Digest,
    bytes: Vec<u8>,
}

/// As `rekeyed`; with `gap`, the mac stops before the removal and the fold
/// writes a note whose body is then withheld, so the mac's content waits
/// below the removal while its control feed judges past it.
async fn rekeyed_with(gap: bool) -> (Rekeyed, Option<Gap>) {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    let third = Member::new();
    hosted.edge.order_account(
        fold.account_log,
        &fold.signer.add_device(third.keys.clone()),
    );
    fold_client.0.wake();
    mac_client.0.wake();
    until(20, "addition copied", || {
        copied(&mac) == 5 && copied(&fold) == 5
    })
    .await;
    let gap = if gap {
        mac_client.0.shutdown().await;
        let (_, update) = fold.new_note("below the removal");
        fold_client.0.wake();
        // The fold applies its own note before the edge loses its body.
        until(20, "fold wrote below the removal", || {
            fold.acked(update).is_some() && fold.pending() == 0
        })
        .await;
        let body = referenced_body(&fold.package(update).unwrap().descriptor).unwrap();
        let bytes = hosted.edge.take_body(fold.log(), body).unwrap();
        Some(Gap {
            at: fold.acked(update).unwrap(),
            body,
            bytes,
        })
    } else {
        None
    };
    let leave = {
        let request = fold
            .signer
            .current_account()
            .unwrap()
            .remove_self(third.keys.id())
            .unwrap();
        request
            .finish(third.control.sign(request.signing_bytes()))
            .unwrap()
    };
    hosted
        .edge
        .order_account(fold.account_log, leave.as_bytes());
    fold_client.0.wake();
    mac_client.0.wake();
    until(20, "removal copied", || {
        (gap.is_some() || copied(&mac) == 6)
            && copied(&fold) == 6
            && fold.progress().position == hosted.edge.head(fold.log()).position
    })
    .await;
    if gap.is_none() {
        assert_eq!(
            mac.progress().epoch_id,
            None,
            "the removal closed the epoch"
        );
    }
    mac_client.0.shutdown().await;
    drop(mac_client);

    // The rotation, with its seals, through the account home; the fold
    // follows it. Its own copier would rekey the base at once, with a key
    // only its seal holds: its first signature, if it gets that far, waits
    // until this test's rekey, under a key the fold is then given, is
    // ordered first, and then it stands down.
    let held = fold.signer.hold_next_sign();
    let (rotation, prepared, next) = fold.signer.rotate_personal(6, hosted.edge.clock.now());
    let body =
        support::stage_rotation(&hosted, &fold_client.0, fold.account_log, &prepared.body).await;
    let items = permits(
        ask(
            &fold_client.0,
            ToService::SubmitControl {
                log: fold.account_log,
                event: rotation.clone(),
                delivery: None,
                attachment: Some(Box::new(RecoveryAttachment {
                    record: None,
                    recovery_seal: prepared.recovery_seal.clone(),
                    rotation_body: Some(body),
                })),
            },
        )
        .await,
    );
    assert_eq!(items.len(), 1, "the body is staged already");
    let wrapped = account_log_wrap(&rotation, Some(body)).unwrap();
    let rotation_at = publish(&hosted, vec![], (items[0].clone(), wrapped.encode())).await;
    fold_client.0.wake();
    until(20, "fold followed the rotation", || {
        fold.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    let confirmation = fold
        .owner
        .shared_database(fold.id)
        .unwrap()
        .lock()
        .unwrap()
        .confirmation(rotation_at)
        .unwrap()
        .unwrap()
        .bytes;

    // The fold's rekey of the base and its seal set, through the service.
    let key = Secret::<32>::random();
    let seal = fold.signer.seal_content_key(fold.base, &key, &next);
    let (rekey, set) = fold.prepare_rekey(&rotation, &confirmation, &key, vec![seal]);
    let items = permits(
        ask(
            &fold_client.0,
            ToService::SubmitBaseControl {
                log: fold.log(),
                descriptor: rekey.descriptor.encode(),
                body: rekey.body.clone(),
                metadata: fold.metadata_key(),
            },
        )
        .await,
    );
    let set_stage = permits(
        ask(
            &fold_client.0,
            ToService::Permits {
                items: vec![Want::Stage {
                    log: fold.log(),
                    body: set.commitment(),
                    len: set.bytes().len() as u32,
                }],
            },
        )
        .await,
    );
    let rekey_at = publish(
        &hosted,
        vec![
            (set_stage[0].clone(), set.bytes().to_vec()),
            (items[0].clone(), rekey.body.clone()),
        ],
        (items[1].clone(), rekey.descriptor.encode()),
    )
    .await;
    let withheld = hosted.edge.take_body(fold.log(), set.commitment()).unwrap();
    assert_eq!(withheld, set.bytes());
    // The fold's copier goes on if it reached its own rekey: this one was
    // ordered first. One pass it lost (a fresh read racing the rotation's
    // append, say) may let it find the base rekeyed and sign nothing.
    let _ = held.release.send(());

    // The fold, given the new key, passes the rekey and writes under it.
    fold.signer
        .hold_epoch(Secret::from_slice(key.expose()).unwrap());
    let (writer, update) = fold.new_note("under the new key");
    fold_client.0.wake();
    until(20, "fold wrote under the new key", || {
        fold.acked(update).is_some()
    })
    .await;
    let note_at = fold.acked(update).unwrap();
    assert_eq!(note_at, rekey_at + 1);
    fold_client.0.shutdown().await;
    let rekeyed = Rekeyed {
        hosted,
        mac,
        fold,
        rekey_at,
        key,
        set: set.bytes().to_vec(),
        rotation_at,
        body: prepared.body,
        note: writer.note,
        note_at,
    };
    (rekeyed, gap)
}

/// Wait until the device's lane accepted the rotation it followed, as it
/// does once it reads the rotation's body.
async fn lane_accepted(client: &Client, device: &Device) {
    until_woken(client, 20, "the lane accepted the rotation", || {
        device.signer.accepts.load(Ordering::SeqCst) >= 1
    })
    .await;
}

/// Wake the client on every check, so that its waits never decide the
/// test's pace: only the receiver's own schedule does.
async fn until_woken(client: &Client, seconds: u64, what: &str, mut done: impl FnMut() -> bool) {
    until(seconds, what, || {
        client.wake();
        done()
    })
    .await;
}

/// The seal set withheld, then other bytes under its commitment, then the
/// set before this account accepted the key it is sealed to: the wait stays
/// through each and through a restart, and content waits before the new
/// epoch. Once the rotation is accepted the key installs, from memory, and
/// content resumes in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withheld_seal_set_keeps_content_waiting_until_its_key_installs() {
    let Rekeyed {
        hosted,
        mac,
        fold,
        rekey_at,
        key,
        set,
        rotation_at,
        body,
        note,
        note_at,
    } = rekeyed().await;
    let epoch = bh_crypto::committed_key_id(&key);
    let commitment = BodyObject::new(set.clone()).unwrap().commitment();
    // The edge withholds the rotation's body from the mac, so it follows
    // the rotation without accepting it.
    let padded = hosted
        .edge
        .take_body(mac.account_log, rotation_body(&body).unwrap().commitment())
        .unwrap();

    let started = mac.start(&hosted);
    until_woken(&started.0, 20, "the feed judged the rekey", || {
        judged(&mac, rekey_at).is_some_and(|f| f.accepted && f.epoch == Some(epoch))
    })
    .await;
    until_woken(&started.0, 20, "the withheld set was asked for", || {
        hosted.edge.body_asks(commitment) >= 1
    })
    .await;
    until_woken(&started.0, 20, "content waits before the new epoch", || {
        mac.progress().position == rekey_at
    })
    .await;
    assert_eq!(waits(&mac).len(), 1);
    assert_eq!(waits(&mac)[0].key_id, epoch);
    assert_eq!(mac.signer.install_attempts.load(Ordering::SeqCst), 0);
    assert!(!mac.signer.holds_epoch(epoch));

    // Other bytes under the set's commitment never reach the signer.
    hosted
        .edge
        .serve_body_as(mac.log(), commitment, vec![0; set.len()]);
    let asked = hosted.edge.body_asks(commitment);
    until_woken(&started.0, 20, "other bytes were read", || {
        hosted.edge.body_asks(commitment) > asked
    })
    .await;
    assert_eq!(mac.signer.install_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(waits(&mac).len(), 1);

    // The set itself, sealed to a personal key this account has not
    // accepted yet: nothing installs and the wait stays.
    hosted
        .edge
        .serve_body_as(mac.log(), commitment, set.clone());
    until_woken(&started.0, 20, "the set reached the signer", || {
        mac.signer.install_attempts.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(mac.signer.installs.load(Ordering::SeqCst), 0);
    assert_eq!(waits(&mac).len(), 1);
    assert_eq!(mac.progress().position, rekey_at);
    assert_eq!(mac.inserted(note, "under the new key"), 0);
    until_woken(&started.0, 20, "the rotation followed", || {
        mac.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    assert_eq!(mac.signer.accepts.load(Ordering::SeqCst), 0, "not accepted");

    // The wait survives a restart; the account accepts the rotation, and
    // the key installs and content resumes in order.
    started.0.shutdown().await;
    drop(started);
    // An aborted lane task lets go of the client's state a moment later.
    until(20, "the client released the owner", || {
        Arc::strong_count(&mac.owner) == 1 && Arc::strong_count(&mac.signer) == 1
    })
    .await;
    let mac = mac.restart();
    assert_eq!(waits(&mac).len(), 1);
    hosted.edge.insert_body(mac.account_log, padded);
    let started = mac.start(&hosted);
    let installed = started.0.epoch_installed();
    until_woken(
        &started.0,
        20,
        "content passed the new epoch's first event",
        || mac.progress().position == note_at && mac.inserted(note, "under the new key") == 1,
    )
    .await;
    assert_eq!(mac.signer.accepts.load(Ordering::SeqCst), 1);
    assert_eq!(mac.signer.installs.load(Ordering::SeqCst), 1);
    assert!(mac.signer.holds_epoch(epoch));
    assert!(waits(&mac).is_empty());
    assert_eq!(
        *installed.borrow(),
        Some(EpochInstalled {
            base: mac.base.0,
            epoch,
            installed_at: Head {
                position: rekey_at,
                hash: Digest(judged(&mac, rekey_at).unwrap().head_hash),
            },
        })
    );
    started.0.shutdown().await;
    drop(fold);
}

/// While content waits for a new epoch's key, the account still changes:
/// the device copies each change, a removal included, into its base from
/// the control feed's verified state with M alone, and the feed judges each
/// copy; the removal closes the new epoch in the base's control state.
/// Content passes them in order once the key installs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_changes_are_copied_while_content_waits_for_a_key() {
    let Rekeyed {
        hosted,
        mac,
        fold,
        rekey_at,
        key,
        set,
        rotation_at,
        note,
        note_at,
        ..
    } = rekeyed().await;
    let started = mac.start(&hosted);
    until_woken(&started.0, 20, "content waits before the new epoch", || {
        mac.progress().position == rekey_at
            && mac.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    // The fold, its client stopped, adds a device that then leaves; only
    // the mac can copy either.
    let fourth = Member::new();
    let added_at = hosted.edge.order_account(
        fold.account_log,
        &fold.signer.add_device(fourth.keys.clone()),
    );
    let copied_at = |account: u64| {
        let head = hosted.edge.head(mac.log()).position;
        (head > note_at && judged(&mac, head).is_some_and(|f| f.accepted && f.account.0 == account))
            .then_some(head)
    };
    until_woken(&started.0, 20, "the mac copied the addition", || {
        copied_at(added_at).is_some()
    })
    .await;
    let addition_at = copied_at(added_at).unwrap();
    until(20, "the mac followed the addition", || {
        mac.signer.current_account().unwrap().head().position == added_at
    })
    .await;
    let leave = {
        let request = mac
            .signer
            .current_account()
            .unwrap()
            .remove_self(fourth.keys.id())
            .unwrap();
        request
            .finish(fourth.control.sign(request.signing_bytes()))
            .unwrap()
    };
    let left_at = hosted
        .edge
        .order_account(fold.account_log, leave.as_bytes());
    until_woken(&started.0, 20, "the mac copied the removal", || {
        copied_at(left_at).is_some()
    })
    .await;
    let removal_at = copied_at(left_at).unwrap();
    assert!(removal_at > addition_at);
    assert_eq!(
        judged(&mac, removal_at).unwrap().epoch,
        None,
        "the removal closed the epoch"
    );
    assert_eq!(
        judged(&mac, addition_at).unwrap().epoch,
        Some(bh_crypto::committed_key_id(&key))
    );
    assert_eq!(mac.progress().position, rekey_at, "content still waits");
    assert_eq!(waits(&mac).len(), 1);

    lane_accepted(&started.0, &mac).await;
    hosted.edge.serve_body_as(
        mac.log(),
        BodyObject::new(set.clone()).unwrap().commitment(),
        set,
    );
    until_woken(
        &started.0,
        20,
        "content passed both copies in order",
        || mac.progress().position == removal_at && mac.inserted(note, "under the new key") == 1,
    )
    .await;
    assert_eq!(copied(&mac), left_at);
    assert_eq!(mac.progress().epoch_id, None);
    started.0.shutdown().await;
}

/// A note written after a removal closed the epoch is never sealed under
/// the old key: it waits while the epoch is closed and while the new
/// epoch's key is missing, though controls and earlier content go on, and
/// is published under the new key once it installs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_note_written_while_the_epoch_is_closed_waits_for_the_new_key() {
    let Rekeyed {
        hosted,
        mac,
        key,
        set,
        rotation_at,
        rekey_at,
        ..
    } = rekeyed().await;
    let epoch = bh_crypto::committed_key_id(&key);
    assert_eq!(mac.progress().epoch_id, None);
    let (_, update) = mac.new_note("written while closed");
    let started = mac.start(&hosted);
    until_woken(&started.0, 20, "controls moved on to the new epoch", || {
        judged(&mac, rekey_at).is_some_and(|f| f.epoch == Some(epoch))
            && mac.progress().position == rekey_at
            && mac.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    assert!(
        mac.package(update).is_none(),
        "nothing sealed without its key"
    );
    assert_eq!(mac.acked(update), None);

    lane_accepted(&started.0, &mac).await;
    hosted.edge.serve_body_as(
        mac.log(),
        BodyObject::new(set.clone()).unwrap().commitment(),
        set,
    );
    until_woken(&started.0, 20, "published under the new key", || {
        mac.acked(update).is_some()
    })
    .await;
    let package = mac.package(update).unwrap();
    assert_eq!(
        bh_event::sealed_epoch(&package.descriptor, mac.metadata_key().expose(), mac.base).unwrap(),
        epoch
    );
    started.0.shutdown().await;
}

/// A removal the control feed judged ahead of content closes the epoch for
/// new content at once: a note written while content waits below the
/// removal, with the old epoch's key still held, is never sealed under it.
/// Once content reaches the rekey's epoch and its key installs, the note is
/// sealed under the new key and ordered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_note_waits_once_the_feed_judged_a_removal_content_has_not_reached() {
    let (
        Rekeyed {
            hosted,
            mac,
            rekey_at,
            key,
            set,
            rotation_at,
            ..
        },
        gap,
    ) = rekeyed_with(true).await;
    let gap = gap.unwrap();
    let old = mac.progress().epoch_id.unwrap();
    let epoch = bh_crypto::committed_key_id(&key);
    let started = mac.start(&hosted);
    until_woken(&started.0, 20, "the feed judged past content", || {
        judged(&mac, rekey_at).is_some_and(|f| f.epoch == Some(epoch))
            && mac.progress().position == gap.at - 1
            && mac.signer.current_account().unwrap().head().position == rotation_at
    })
    .await;
    assert_eq!(
        mac.progress().epoch_id,
        Some(old),
        "content is in the old epoch"
    );
    assert!(mac.signer.holds_epoch(old));

    // While content waits at the missing body, only the publisher asks for
    // the old epoch's key: once to seal the note, again on its next round.
    mac.signer.epoch_asks.lock().unwrap().clear();
    let (_, update) = mac.new_note("written behind the removal");
    let asked = || {
        mac.signer
            .epoch_asks
            .lock()
            .unwrap()
            .iter()
            .filter(|asked| **asked == Some(old))
            .count()
    };
    until_woken(&started.0, 20, "the publisher looked at the note", || {
        asked() >= 2 || mac.package(update).is_some()
    })
    .await;
    assert!(
        mac.package(update).is_none(),
        "nothing sealed under the epoch the removal closed"
    );

    // The body arrives, the rotation is accepted and the key installs.
    hosted.edge.insert_body(mac.log(), gap.bytes);
    lane_accepted(&started.0, &mac).await;
    hosted.edge.serve_body_as(
        mac.log(),
        BodyObject::new(set.clone()).unwrap().commitment(),
        set,
    );
    until_woken(&started.0, 20, "published under the new key", || {
        mac.acked(update).is_some()
    })
    .await;
    let package = mac.package(update).unwrap();
    assert_eq!(
        bh_event::sealed_epoch(&package.descriptor, mac.metadata_key().expose(), mac.base).unwrap(),
        epoch
    );
    assert!(mac.acked(update).unwrap() > rekey_at);
    let _ = gap.body;
    started.0.shutdown().await;
}

/// A seal set the edge serves wrongly is one wait not installed this time:
/// content below its rekey goes on in the same pass, over the same link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_seal_set_does_not_hold_content_below_its_rekey() {
    let (
        Rekeyed {
            hosted,
            mac,
            rekey_at,
            key,
            set,
            ..
        },
        gap,
    ) = rekeyed_with(true).await;
    let gap = gap.unwrap();
    let epoch = bh_crypto::committed_key_id(&key);
    let commitment = BodyObject::new(set.clone()).unwrap().commitment();
    hosted
        .edge
        .serve_body_as(mac.log(), commitment, vec![0; set.len()]);
    let started = mac.start_named(&hosted, "mac");
    until_woken(
        &started.0,
        20,
        "the wait exists and its set was read",
        || {
            judged(&mac, rekey_at).is_some_and(|f| f.epoch == Some(epoch))
                && mac.progress().position == gap.at - 1
                && hosted.edge.body_asks_by(commitment, "mac") >= 1
        },
    )
    .await;
    let links = hosted.edge.body_links_by(commitment, "mac");
    let asks = hosted.edge.body_asks_by(commitment, "mac");
    assert_eq!(links, 1, "the set's first read used one data link");
    // The body below the rekey arrives; the set is still served wrongly.
    hosted.edge.insert_body(mac.log(), gap.bytes);
    until_woken(&started.0, 20, "content went on to the rekey", || {
        mac.progress().position == rekey_at
    })
    .await;
    until_woken(&started.0, 20, "the bad set was read again", || {
        hosted.edge.body_asks_by(commitment, "mac") > asks
    })
    .await;
    assert_eq!(
        hosted.edge.body_links_by(commitment, "mac"),
        links,
        "the same data link served the set again"
    );
    assert_eq!(
        hosted
            .edge
            .body_links_across(&[commitment, gap.body], "mac"),
        1,
        "the gap body and the set again shared one data link"
    );
    assert_eq!(mac.signer.install_attempts.load(Ordering::SeqCst), 0);
    assert_eq!(waits(&mac).len(), 1);
    started.0.shutdown().await;
}

/// A note held while the epoch is closed, its publisher's backoff long
/// grown, is published within a pass of content reaching the new epoch
/// with its key held: the publisher is woken by the install and the
/// receiver's next pass, with no local write and no wake from outside.
#[tokio::test(start_paused = true)]
async fn a_held_note_publishes_within_a_pass_of_content_reaching_the_new_epoch() {
    let Rekeyed {
        hosted,
        mac,
        key,
        set,
        rotation_at,
        body,
        rekey_at,
        ..
    } = rekeyed().await;
    let epoch = bh_crypto::committed_key_id(&key);
    let (_, update) = mac.new_note("held for the new key");
    let (started, _) = mac.start(&hosted);
    until(20, "content waits for the new key", || {
        mac.progress().position == rekey_at
            && mac.signer.current_account().unwrap().head().position == rotation_at
            && mac.signer.epoch_asks.lock().unwrap().contains(&Some(epoch))
    })
    .await;
    // The publisher retried and backed off for a while.
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert!(mac.package(update).is_none());

    mac.signer.accept_rotation(rotation_at, &body);
    hosted.edge.serve_body_as(
        mac.log(),
        BodyObject::new(set.clone()).unwrap().commitment(),
        set,
    );
    // The set is read again on its own backoff, at most a minute apart.
    until(90, "content reached the new epoch with its key", || {
        mac.progress().epoch_id == Some(epoch) && mac.signer.holds_epoch(epoch)
    })
    .await;
    until(2, "published within a pass", || mac.acked(update).is_some()).await;
    started.shutdown().await;
}
