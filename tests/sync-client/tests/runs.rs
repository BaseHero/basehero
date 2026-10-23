//! Account changes copied into the own base as runs: each control carries
//! the account's entries after the base's copy, each with its kept ordering
//! confirmation, at most `MAX_RUN` and no more than one authorization
//! message holds. A run ends before a personal-key rotation that takes
//! effect, which only the base's rekey copies, and at the last change this
//! device's control key made: the person's approval of that change covers
//! the run through it and never past it. A confirmation this device does
//! not keep is read again and verified; an entry is never copied untimed.
//! Real signed-up devices and their native stores, the real authorization
//! service behind the attested channel, and the hosted fake's data edge.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::DevicePublicKeys;
use bh_crypto::{KemKey, SigningKey};
use bh_event::account_run::{MAX_RUN, decode_copies};
use bh_sync::Route;
use bh_sync_client::{Client, Signer, SyncStatus};
use std::sync::{Arc, atomic::Ordering};
use support::{
    device::{Device, until},
    fake::Hosted,
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

/// One copied account entry: its original and its confirmation.
type Copied = (Vec<u8>, Option<Vec<u8>>);

/// Each accepted account copy in the base log, in order: the account
/// entries it copied, as originals with their confirmations.
fn runs(hosted: &Hosted, device: &Device) -> Vec<Vec<Copied>> {
    hosted
        .edge
        .entries(device.log())
        .iter()
        .filter(|(ordered, _)| ordered.route() == Route::Control && ordered.head().position > 1)
        .filter_map(|(ordered, _)| {
            let fact = device
                .owner
                .control_fact(device.id, device.log(), ordered.head().position)
                .unwrap()?;
            let record = fact.account_change.filter(|_| fact.accepted)?;
            Some(
                decode_copies(&record)
                    .unwrap()
                    .into_iter()
                    .map(|copy| (copy.original, copy.confirmation))
                    .collect(),
            )
        })
        .collect()
}

/// The run data one control carries for `run`.
fn run_bytes(run: &[Copied]) -> usize {
    1 + run
        .iter()
        .map(|(original, confirmation)| 4 + original.len() + confirmation.as_ref().unwrap().len())
        .sum::<usize>()
}

/// 130 account entries the base lacks are copied in runs, each timed entry
/// once, in order: each run at most `MAX_RUN` entries and within the bytes
/// one control carries, and each but the last as long as those allow. One
/// control signature per run.
#[tokio::test(start_paused = true)]
async fn missing_entries_are_copied_in_runs_of_at_most_64() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let started = registered(&hosted, &mac).await;
    until(20, "signup copied", || copied(&mac) == 3).await;
    started.0.shutdown().await;
    let additions = mac.signer.signed_additions(130, hosted.edge.clock.now());
    for event in &additions {
        hosted.edge.order_account(mac.account_log, event);
    }
    let started = mac.start(&hosted);
    until(20, "every entry copied", || {
        started.0.wake();
        copied(&mac) == 133
    })
    .await;
    let runs = runs(&hosted, &mac);
    let originals: Vec<Vec<u8>> = runs.iter().flatten().map(|(o, _)| o.clone()).collect();
    assert_eq!(originals, additions, "each entry once, in order");
    assert!(runs.iter().flatten().all(|(_, c)| c.is_some()), "all timed");
    for (index, run) in runs.iter().enumerate() {
        assert!(run.len() <= MAX_RUN);
        assert!(run_bytes(run) <= bh_device::RUN_BYTES);
        if let Some(next) = runs.get(index + 1) {
            let mut longer = run.clone();
            longer.push(next[0].clone());
            assert!(
                longer.len() > MAX_RUN || run_bytes(&longer) > bh_device::RUN_BYTES,
                "run {index} could have carried one more"
            );
        }
    }
    assert!(runs.len() > 2);
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        runs.len()
    );
    started.0.shutdown().await;
}

/// `device`'s control key's addition of `keys`, signed at its current head,
/// ordered: its position and bytes.
fn own_addition(hosted: &Hosted, device: &Device, keys: DevicePublicKeys) -> (u64, Vec<u8>) {
    let event = device.signer.add_device(keys);
    (hosted.edge.order_account(device.account_log, &event), event)
}

/// `member`'s addition of `keys`, signed with its control key at the
/// device's current head, ordered: its position and bytes.
fn member_addition(
    hosted: &Hosted,
    device: &Device,
    member: &Member,
    keys: DevicePublicKeys,
) -> (u64, Vec<u8>) {
    let request = device
        .signer
        .current_account()
        .unwrap()
        .add_device(member.keys.id(), keys)
        .unwrap();
    let event = request
        .finish(member.control.sign(request.signing_bytes()))
        .unwrap();
    let bytes = event.as_bytes().to_vec();
    (hosted.edge.order_account(device.account_log, &bytes), bytes)
}

async fn followed(device: &Device, client: &Client, position: u64) {
    until(20, "followed", || {
        client.wake();
        device.signer.current_account().unwrap().head().position == position
    })
    .await;
}

/// The person approved copying X, this device's own change, as pairing
/// does. Other devices' changes before X are already authorised history:
/// the one approval signs the one run from the base's first missing entry
/// through X, and nothing past X, which waits for its own approval.
#[tokio::test(start_paused = true)]
async fn one_approval_signs_one_run_ending_at_its_original() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let started = registered(&hosted, &mac).await;
    let member = Member::new();
    let (added, _) = own_addition(&hosted, &mac, member.keys.clone());
    until(20, "the member's addition copied", || {
        started.0.wake();
        copied(&mac) == added
    })
    .await;
    // From here the control key signs only what the person approves.
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    let signatures = mac.signer.control_signatures.load(Ordering::SeqCst);
    let (a, a_bytes) = member_addition(&hosted, &mac, &member, Member::new().keys);
    followed(&mac, &started.0, a).await;
    let (b, b_bytes) = member_addition(&hosted, &mac, &member, Member::new().keys);
    followed(&mac, &started.0, b).await;
    let (x, x_bytes) = own_addition(&hosted, &mac, Member::new().keys);
    followed(&mac, &started.0, x).await;
    let (c, _) = member_addition(&hosted, &mac, &member, Member::new().keys);
    followed(&mac, &started.0, c).await;
    let requests = mac.signer.control_requests.load(Ordering::SeqCst);
    until(20, "the copier asked and waits", || {
        started.0.wake();
        mac.signer.control_requests.load(Ordering::SeqCst) > requests
    })
    .await;
    assert_eq!(copied(&mac), added, "nothing copied without approval");

    mac.signer.approvals.grant(
        x_bytes.clone(),
        tokio::time::Instant::now() + std::time::Duration::from_secs(600),
    );
    until(20, "the run through X copied", || {
        started.0.wake();
        copied(&mac) == x
    })
    .await;
    let copies = runs(&hosted, &mac);
    let last: Vec<Vec<u8>> = copies
        .last()
        .unwrap()
        .iter()
        .map(|(o, _)| o.clone())
        .collect();
    assert_eq!(last, vec![a_bytes, b_bytes, x_bytes], "one run, X last");
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        signatures + 1
    );
    // The entry after X is not copied under X's approval.
    let requests = mac.signer.control_requests.load(Ordering::SeqCst);
    until(20, "the copier asked for the entry after X", || {
        started.0.wake();
        mac.signer.control_requests.load(Ordering::SeqCst) > requests
    })
    .await;
    assert_eq!(copied(&mac), x);
    assert!(c > x);
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        signatures + 1
    );
    started.0.shutdown().await;
}

/// A rotation that takes effect ends a run: the run before it is copied,
/// the rotation by the base's rekey alone, and a later change of this
/// device's in a run after it, never across it.
#[tokio::test(start_paused = true)]
async fn a_run_stops_before_an_effective_rotation() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let started = registered(&hosted, &mac).await;
    let member = Member::new();
    let (added, _) = own_addition(&hosted, &mac, member.keys.clone());
    until(20, "the member's addition copied", || {
        started.0.wake();
        copied(&mac) == added
    })
    .await;
    // The base copy waits while the account goes on: the member leaves,
    // the personal key rotates for it, and this device adds another. This
    // test orders the rotation itself; the lane stages none.
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    mac.signer.refuse_rotation.store(true, Ordering::SeqCst);
    let request = mac
        .signer
        .current_account()
        .unwrap()
        .remove_self(member.keys.id())
        .unwrap();
    let leave = request
        .finish(member.control.sign(request.signing_bytes()))
        .unwrap();
    let left = hosted.edge.order_account(mac.account_log, leave.as_bytes());
    followed(&mac, &started.0, left).await;
    let (rotation, prepared, _) = mac.signer.rotate_personal(left, hosted.edge.clock.now());
    let rotated = rotation_ordered(&hosted, &mac, &started.0, &rotation, &prepared).await;
    followed(&mac, &started.0, rotated).await;
    let (later, later_bytes) = own_addition(&hosted, &mac, Member::new().keys);
    followed(&mac, &started.0, later).await;
    assert_eq!(copied(&mac), added);
    let signatures = mac.signer.control_signatures.load(Ordering::SeqCst);
    let signed = mac.signer.signed.load(Ordering::SeqCst);
    mac.signer.approve_controls.store(true, Ordering::SeqCst);
    mac.signer.accept_rotation(rotated, &prepared.body);
    until(20, "everything copied", || {
        started.0.wake();
        copied(&mac) == later
    })
    .await;
    let copies: Vec<Vec<Vec<u8>>> = runs(&hosted, &mac)
        .into_iter()
        .map(|run| run.into_iter().map(|(o, _)| o).collect())
        .collect();
    let n = copies.len();
    assert_eq!(
        copies[n - 3..],
        [
            vec![leave.as_bytes().to_vec()],
            vec![rotation.clone()],
            vec![later_bytes]
        ],
        "the run before the rotation, its rekey, the run after"
    );
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        signatures + 2,
        "two runs; the rekey needs no control key"
    );
    assert_eq!(mac.signer.signed.load(Ordering::SeqCst), signed + 2);
    started.0.shutdown().await;
}

/// Order a signed rotation with its seals through the account home.
async fn rotation_ordered(
    hosted: &Arc<Hosted>,
    device: &Device,
    client: &Client,
    rotation: &[u8],
    prepared: &bh_account::personal::PreparedRotation,
) -> u64 {
    use bh_authz::proto::{FromService, RecoveryAttachment, ToService, account_log_wrap};
    use bh_sync::{
        permit::AppendAck,
        wire::{Request, Response},
    };
    let body = support::stage_rotation(hosted, client, device.account_log, &prepared.body).await;
    let answer = client
        .authz()
        .await
        .unwrap()
        .ask(ToService::SubmitControl {
            log: device.account_log,
            event: rotation.to_vec(),
            delivery: None,
            attachment: Some(Box::new(RecoveryAttachment {
                record: None,
                recovery_seal: prepared.recovery_seal.clone(),
                rotation_body: Some(body),
            })),
        })
        .await
        .unwrap();
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let [append] = <[_; 1]>::try_from(items).unwrap();
    let append = append.unwrap();
    let event = account_log_wrap(rotation, Some(body)).unwrap().encode();
    let data = bh_sync_client::data::DataSocket::open(hosted.connector().as_ref())
        .await
        .unwrap();
    match data
        .ask(|id| Request::Append {
            id,
            permit: append,
            event,
        })
        .await
        .unwrap()
    {
        Response::Acked { ack, .. } => AppendAck::decode(&ack).unwrap().head.position,
        other => panic!("{other:?}"),
    }
}

/// An entry whose confirmation this device does not keep is read again
/// from the account home: a confirmation that does not verify under the
/// hosting root copies nothing; the genuine one times the entry in its run.
#[tokio::test(start_paused = true)]
async fn a_missing_confirmation_is_fetched_and_a_forged_one_refused() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let started = registered(&hosted, &mac).await;
    until(20, "signup copied", || copied(&mac) == 3).await;
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    let additions = mac.signer.signed_additions(2, hosted.edge.clock.now());
    for event in &additions {
        hosted.edge.order_account(mac.account_log, event);
    }
    followed(&mac, &started.0, 5).await;
    started.0.shutdown().await;
    // The first entry's kept confirmation is gone, and the account home
    // now signs confirmations under another root.
    let raw = mac.raw();
    raw.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    raw.execute("DELETE FROM account_confirmations WHERE position=4", [])
        .unwrap();
    drop(raw);
    hosted.foreign_root_account_confirmations(mac.account_log);
    mac.signer.approve_controls.store(true, Ordering::SeqCst);
    let started = mac.start(&hosted);
    until(20, "the entry read again", || {
        started.0.wake();
        hosted.edge.reads(mac.account_log).contains(&(4, 4))
    })
    .await;
    let reads = hosted.edge.reads(mac.account_log).len();
    until(20, "and again", || {
        started.0.wake();
        hosted.edge.reads(mac.account_log)[reads..].contains(&(4, 4))
    })
    .await;
    assert_eq!(copied(&mac), 3, "nothing copied with a forged confirmation");
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 0);

    hosted.restore_account_confirmations();
    until(20, "copied with the genuine confirmation", || {
        started.0.wake();
        copied(&mac) == 5
    })
    .await;
    let copies = runs(&hosted, &mac);
    let all: Vec<_> = copies.iter().flatten().collect();
    assert_eq!(all.len(), 2);
    for ((original, confirmation), expected) in all.iter().zip(&additions) {
        assert_eq!(original, expected);
        let proof = bh_sync::evidence::OrderingConfirmation::decode(confirmation.as_ref().unwrap())
            .unwrap();
        proof.verify(&hosted.edge.root()).unwrap();
    }
    started.0.shutdown().await;
}
