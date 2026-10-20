//! The publish path against the fake hosted environment: a real signed-up
//! device and its native store, the real authorization service behind the
//! attested channel, and a data edge that behaves as the Worker and log
//! object do.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::proto::{FromService, ToService, Want};
use bh_device::incoming::StopReason;
use bh_sync::{
    receipt,
    wire::{Refusal, Request, Response},
};
use bh_sync_client::{SyncStatus, data::DataSocket};
use std::{
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};
use support::{
    device::{Device, until},
    fake::{Hook, Hosted, ProofFault, Seen},
};

fn setup() -> (Arc<Hosted>, Device) {
    (Hosted::new(), Device::new())
}

/// Started, with the own base registered and its genesis applied.
async fn registered(
    hosted: &Arc<Hosted>,
    device: &Device,
) -> (
    bh_sync_client::Client,
    tokio::sync::watch::Receiver<SyncStatus>,
) {
    let (client, status) = device.start(hosted);
    until(20, "registered", || {
        device.registered() && device.progress().position == 1
    })
    .await;
    (client, status)
}

fn refused(hosted: &Hosted, reason: Refusal) -> usize {
    hosted
        .edge
        .seen()
        .iter()
        .filter(|s| **s == Seen::Refused { reason })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_base_once_and_after_crash() {
    let (hosted, device) = setup();
    let log = device.log();
    // The genesis is ordered, then the device loses the Ack and stops.
    hosted.edge.hook(Hook::DropAfterAppend { then_down: true });
    let (client, _) = device.start(&hosted);
    until(20, "genesis ordered", || {
        hosted.edge.entries(log).len() == 1
    })
    .await;
    client.shutdown().await;
    assert!(!device.registered());
    let (ordered, genesis) = hosted.edge.entries(log)[0].clone();

    // A restart registers again with the same bytes: the service and the
    // log object answer with the original result.
    hosted.come_up();
    let (client, _) = registered(&hosted, &device).await;
    assert_eq!(hosted.edge.entries(log).len(), 1);
    let appends = hosted.edge.appends(log.id);
    assert_eq!(appends.len(), 2);
    assert!(appends.iter().all(|a| *a == genesis.encode()));
    let stages = hosted.edge.stages(log.id);
    assert_eq!(stages.len(), 2);
    assert_eq!(stages[0], stages[1]);
    let db = device.owner.shared_database(device.id).unwrap();
    let recorded = db
        .lock()
        .unwrap()
        .registration(device.base.0)
        .unwrap()
        .unwrap()
        .genesis_receipt
        .unwrap();
    let proven = receipt::verify(&hosted.edge.root(), device.base, &recorded).unwrap();
    assert_eq!(proven.head(), ordered.head());
    assert_eq!(device.progress().head_hash, ordered.head().hash.0);
    client.shutdown().await;

    // Registered once: a later start publishes without registering again.
    let (client, _) = device.start(&hosted);
    let (_, id) = device.new_note("after restart");
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    assert_eq!(hosted.edge.appends(log.id).len(), 3);
    assert_eq!(hosted.edge.stages(log.id).len(), 3);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn any_holder_stops_the_client_and_it_opens_nothing_after() {
    let (hosted, device) = setup();
    let (client, _) = registered(&hosted, &device).await;
    let client = Arc::new(client);
    // Another holder keeps the client, as a pairing across a prompt does.
    let kept = client.clone();
    hosted.go_down();
    let (_, id) = device.new_note("kept on this device");
    kept.wake();
    // Stopped through one holder while the other still has it; a second,
    // concurrent stop is harmless.
    tokio::join!(client.shutdown(), kept.shutdown());
    let connects = hosted.edge.authz_connects.load(Ordering::SeqCst);
    hosted.come_up();
    assert!(matches!(
        kept.authz().await,
        Err(bh_sync_client::ClientError::Stopped)
    ));
    kept.wake();
    kept.shutdown().await;
    assert_eq!(
        hosted.edge.authz_connects.load(Ordering::SeqCst),
        connects,
        "no session opened after the stop"
    );
    assert!(device.acked(id).is_none());
    let db = device.owner.shared_database(device.id).unwrap();
    assert_eq!(
        db.lock().unwrap().outbox_summary().unwrap().unaccepted,
        1,
        "its work is kept"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_client_ends_its_loops() {
    let (hosted, device) = setup();
    let (client, _) = registered(&hosted, &device).await;
    assert!(
        Arc::strong_count(&device.signer) > 1,
        "its loops use the signer"
    );
    drop(client);
    until(20, "loops ended", || Arc::strong_count(&device.signer) == 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_one_package_per_note_in_order() {
    let (hosted, device) = setup();
    let log = device.log();
    let (mut a, a1) = device.new_note("a1");
    let a2 = device.append(&mut a, "a2");
    let (mut b, b1) = device.new_note("b1");
    let a3 = device.append(&mut a, "a3");
    let b2 = device.append(&mut b, "b2");
    let (client, status) = device.start(&hosted);
    let all = [a1, a2, a3, b1, b2];
    until(20, "all acked", || {
        all.iter().all(|id| device.acked(*id).is_some())
    })
    .await;
    let at = |id| device.acked(id).unwrap();
    assert_eq!((at(a1), at(a2)), (at(a3), at(a3)));
    assert_eq!(at(b1), at(b2));

    // Each logged event is exactly its persisted package, ordered once.
    let entries = hosted.edge.entries(log);
    assert_eq!(entries.len(), 3);
    for id in all {
        let stored = device.package(id).unwrap();
        let (ordered, event) = &entries[at(id) as usize - 1];
        assert_eq!(event.encode(), stored.descriptor.encode());
        assert_eq!(ordered.event_id(), stored.event_id);
    }
    assert_eq!(hosted.edge.appends(log.id).len(), 3);
    let a4 = device.append(&mut a, "a4");
    let b3 = device.append(&mut b, "b3");
    client.wake();
    until(20, "next runs acked", || {
        device.acked(a4).is_some() && device.acked(b3).is_some()
    })
    .await;
    assert!(at(a3) < at(a4));
    assert!(at(b2) < at(b3));

    // One package in flight per note: a note's next append reached the
    // edge only after its previous Ack had left it.
    let seen = hosted.edge.seen();
    let arrived = |id: bh_sync::EventId| {
        seen.iter()
            .position(|s| *s == Seen::Arrived { event: id })
            .unwrap()
    };
    let acked = |id: bh_sync::EventId| {
        seen.iter()
            .position(|s| matches!(s, Seen::Acked { event, .. } if *event == id))
            .unwrap()
    };
    for note in [[a3, a4].as_slice(), [b2, b3].as_slice()] {
        for pair in note.windows(2) {
            let earlier = device.package(pair[0]).unwrap().event_id;
            let later = device.package(pair[1]).unwrap().event_id;
            assert!(acked(earlier) < arrived(later));
        }
    }
    let mut status = status;
    until(20, "synced", || {
        *status.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compound_publication_records_proof_without_ack_readback_or_accepting_echo() {
    let (hosted, device) = setup();
    let (client, _) = registered(&hosted, &device).await;
    let log = device.log();
    // Batch history reads lag at genesis; single-position Ack reads still
    // work in the legacy path, so distinguish them in the observed reads.
    hosted.edge.freeze_reads(Some(1));
    let (_, id) = device.new_note("one compound request");
    client.wake();
    until(10, "compound proof recorded", || {
        device.acked(id) == Some(2)
    })
    .await;
    let package = device.package(id).unwrap();
    let publishes: Vec<_> = hosted
        .edge
        .seen()
        .into_iter()
        .filter_map(|seen| match seen {
            Seen::Publish { event, body } if event == package.descriptor.encode() => {
                Some((event, body))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        publishes,
        vec![(package.descriptor.encode(), package.body.clone())]
    );
    // The fake observes internal durable staging/ordering; only Publish
    // reached the client-facing socket as a request for this package.
    assert_eq!(
        hosted
            .edge
            .reads(log)
            .iter()
            .filter(|(first, last)| *first == 2 && *last == 2)
            .count(),
        0,
        "no Ack-only readback"
    );
    assert_eq!(
        device.pending(),
        1,
        "ordering proof is not author acceptance"
    );
    hosted.edge.freeze_reads(None);
    client.wake();
    until(10, "accepted echo", || device.pending() == 0).await;
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn stage_durability_gate_precedes_ordered_proof() {
    let (hosted, device) = setup();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.freeze_reads(Some(1));
    let barrier = hosted.edge.hold_next_stage();
    let (_, id) = device.new_note("durability first");
    client.wake();
    barrier
        .arrived
        .await
        .expect("stage reached durable boundary");
    assert!(device.acked(id).is_none());
    assert_eq!(
        hosted.edge.entries(device.log()).len(),
        1,
        "not ordered before durable stage"
    );
    barrier.release.send(()).unwrap();
    until(10, "verified proof", || device.acked(id) == Some(2)).await;
    assert_eq!(device.pending(), 1);
    hosted.edge.freeze_reads(None);
    client.wake();
    until(10, "accepted echo", || device.pending() == 0).await;
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn invalid_compound_proofs_keep_the_package_and_retry_at_its_original_position() {
    for fault in [
        ProofFault::Log,
        ProofFault::Event,
        ProofFault::Descriptor,
        ProofFault::Receipt,
        ProofFault::Root,
        ProofFault::Route,
        ProofFault::Commitment,
        ProofFault::Head,
        ProofFault::RequestId,
    ] {
        let (hosted, device) = setup();
        let (client, _) = registered(&hosted, &device).await;
        let log = device.log();
        hosted.edge.freeze_reads(Some(1));
        hosted.edge.hook(Hook::BadPublished(fault));
        // This barrier applies only to the next *valid* Published reply.
        // Its arrival means the faulty frame was discarded and a retry
        // completed at the edge, but no valid reply can yet reach the client.
        let valid_retry = hosted.edge.hold_next_valid_publish_reply();
        let (_, id) = device.new_note("proof must match");
        client.wake();
        tokio::time::timeout(Duration::from_secs(65), valid_retry.arrived)
            .await
            .expect("faulty reply rejected and another Publish sent")
            .expect("valid retry reached reply barrier");
        let stored = device.package(id).unwrap();
        assert!(
            hosted.edge.seen().contains(&Seen::BadProof(fault)),
            "{fault:?} was injected"
        );
        assert_eq!(
            device.acked(id),
            None,
            "{fault:?} recorded an unverified Ack"
        );
        assert_eq!(device.pending(), 1, "{fault:?} cannot accept an echo");
        let publishes: Vec<_> = hosted
            .edge
            .seen()
            .into_iter()
            .filter_map(|seen| match seen {
                Seen::Publish { event, body } if event == stored.descriptor.encode() => {
                    Some((event, body))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            publishes,
            vec![
                (stored.descriptor.encode(), stored.body.clone()),
                (stored.descriptor.encode(), stored.body.clone()),
            ],
            "{fault:?} must retry the exact stored bytes before Ack"
        );
        valid_retry.release.send(()).expect("release valid proof");
        until(20, "valid retry proof recorded", || {
            device.acked(id) == Some(2)
        })
        .await;
        assert_eq!(
            hosted.edge.entries(log).len(),
            2,
            "{fault:?} did not duplicate ordering"
        );
        assert_eq!(
            device.package(id).unwrap().descriptor.encode(),
            stored.descriptor.encode()
        );
        assert_eq!(device.package(id).unwrap().body, stored.body);
        assert_eq!(device.pending(), 1, "Ack alone cannot retire {fault:?}");
        hosted.edge.freeze_reads(None);
        client.wake();
        until(20, "accepted echo", || device.pending() == 0).await;
        client.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_ack_resends_identical_bytes() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.hook(Hook::DropAfterAppend { then_down: false });
    // No echo arrives meanwhile: only the exact resend's Ack can settle it.
    hosted.edge.freeze_reads(Some(1));
    let (_, id) = device.new_note("lost");
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    let stored = device.package(id).unwrap();
    let appends = hosted.edge.appends(log.id);
    assert_eq!(appends.len(), 3, "the genesis, then the same event twice");
    assert!(
        appends[1..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    assert_eq!(hosted.edge.entries(log).len(), 2);
    assert_eq!(device.acked(id), Some(2));
    hosted.edge.freeze_reads(None);
    client.wake();
    until(20, "accepted", || device.pending() == 0).await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_ack_commitment_is_not_recorded() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    let (mut note, first) = device.new_note("first");
    client.wake();
    until(20, "first acked", || device.acked(first).is_some()).await;

    // The Ack names the head of the first note's event, with its genuine
    // receipt, and the read of that position names this package there.
    // Recording it would leave the update acknowledged at position 2, with
    // nothing pending, so the client would show Synced.
    hosted.edge.hook(Hook::ForgeAck);
    let second = device.append(&mut note, "second");
    client.wake();
    until(20, "acked", || device.acked(second).is_some()).await;
    assert_eq!(hosted.edge.hooks_left(), 0);
    assert_eq!(device.acked(second), Some(3), "the genuine position only");
    let stored = device.package(second).unwrap();
    let appends = hosted.edge.appends(log.id);
    assert_eq!(appends.len(), 4, "the genesis, the first, then this twice");
    assert!(
        appends[2..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    assert_eq!(hosted.edge.entries(log).len(), 3);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stuck_notes_do_not_hold_back_a_healthy_one() {
    let (hosted, device) = setup();
    // More notes than one round takes, each with old local work that has no
    // writer declaration, so none can be sealed; then one healthy note.
    let stuck: Vec<i64> = (0..17)
        .map(|n| device.new_note(&format!("stuck {n}")).1)
        .collect();
    let raw = device.raw();
    raw.busy_timeout(Duration::from_secs(5)).unwrap();
    for id in &stuck {
        raw.execute("DELETE FROM note_update_writer WHERE update_id=?1", [id])
            .unwrap();
    }
    let (_, healthy) = device.new_note("healthy");
    let (client, _) = device.start(&hosted);
    until(20, "healthy acked", || device.acked(healthy).is_some()).await;
    for id in stuck {
        assert!(device.package(id).is_none(), "never sealed");
    }
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_package_is_not_accepted_and_backs_off_alone() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, mut status) = registered(&hosted, &device).await;
    hosted.edge.refuse_next_event(Refusal::Conflict);
    let (_, refused_id) = device.new_note("refused");
    client.wake();
    until(20, "not accepted", || {
        *status.borrow_and_update() == SyncStatus::NotAccepted { notes: 1 }
    })
    .await;
    let stored = device.package(refused_id).unwrap();

    // Other notes keep publishing; their progress does not retry the
    // refused one each time. Each is its own note's first package, so none
    // waits for a note's spacing.
    let (_, first) = device.new_note("other");
    client.wake();
    until(20, "other acked", || device.acked(first).is_some()).await;
    for n in 0..8 {
        let (_, id) = device.new_note(&format!("more {n}"));
        client.wake();
        until(20, "more acked", || device.acked(id).is_some()).await;
    }
    let tries = hosted
        .edge
        .appends(log.id)
        .iter()
        .filter(|a| **a == stored.descriptor.encode())
        .count();
    assert!((1..=4).contains(&tries), "{tries} tries");
    // The work is kept as it was, with no outcome recorded.
    let again = device.package(refused_id).unwrap();
    assert_eq!(again.descriptor.encode(), stored.descriptor.encode());
    assert_eq!(again.body, stored.body);
    assert_eq!(device.acked(refused_id), None);
    assert_eq!(*status.borrow(), SyncStatus::NotAccepted { notes: 1 });
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_permit_refreshes_same_bytes() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.hook(Hook::ExpireStage);
    let (_, id) = device.new_note("late");
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    assert!(refused(&hosted, Refusal::Expired) >= 1);
    let stored = device.package(id).unwrap();
    let stages = hosted.edge.stages(log.id);
    assert!(stages.len() >= 2, "the genesis and a fresh durable stage");
    assert!(
        hosted
            .edge
            .seen()
            .iter()
            .filter(
                |s| matches!(s, Seen::Publish { event, .. } if *event == stored.descriptor.encode())
            )
            .count()
            >= 2,
        "the first compound request expired; the same package was retried"
    );
    assert!(stages[1..].iter().all(|s| *s == stored.body));
    let appends = hosted.edge.appends(log.id);
    assert!(
        appends[1..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    assert_eq!(hosted.edge.entries(log).len(), 2);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_ack_after_deadline_reconciles_by_exact_retry() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.hook(Hook::WithholdAck);
    // No echo arrives meanwhile: only the exact retry's Ack can settle it.
    hosted.edge.freeze_reads(Some(1));
    let (_, id) = device.new_note("withheld");
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    assert!(refused(&hosted, Refusal::Expired) >= 1);
    let stored = device.package(id).unwrap();
    let appends = hosted.edge.appends(log.id);
    assert!(appends.len() >= 3);
    assert!(
        appends[1..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    // The commit stood: the exact retry got its original position.
    assert_eq!(hosted.edge.entries(log).len(), 2);
    assert_eq!(device.acked(id), Some(2));
    let acks: Vec<_> = hosted
        .edge
        .seen()
        .into_iter()
        .filter(|s| matches!(s, Seen::Acked { event, .. } if *event == stored.event_id))
        .collect();
    assert_eq!(
        acks,
        vec![Seen::Acked {
            event: stored.event_id,
            position: 2
        }]
    );
    hosted.edge.freeze_reads(None);
    client.wake();
    until(20, "accepted", || device.pending() == 0).await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_staged_restages_same_bytes() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.hook(Hook::ReclaimBeforeAppend);
    let (_, id) = device.new_note("reclaimed");
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    assert_eq!(refused(&hosted, Refusal::NotStaged), 1);
    let stored = device.package(id).unwrap();
    let stages = hosted.edge.stages(log.id);
    assert_eq!(stages.len(), 3, "the genesis, then the same body twice");
    assert!(stages[1..].iter().all(|s| *s == stored.body));
    assert!(
        hosted.edge.appends(log.id)[1..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    assert_eq!(hosted.edge.entries(log).len(), 2);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epoch_refusal_waits_no_reseal() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, mut status) = registered(&hosted, &device).await;
    hosted.edge.close_epoch(log);
    let (_, id) = device.new_note("closed");
    client.wake();
    until(20, "sealed package waiting for authorization", || {
        // An earlier read can already be waiting for authorization before
        // this newly committed note has reached the publisher.
        *status.borrow_and_update() == SyncStatus::WaitingAuthorization
            && device.package(id).is_some()
    })
    .await;
    let stored = device.package(id).unwrap();
    until(20, "retried and refused", || {
        hosted.edge.appends(log.id).len() >= 3 && refused(&hosted, Refusal::Epoch) >= 2
    })
    .await;
    assert!(refused(&hosted, Refusal::Epoch) >= 2);
    assert!(
        hosted.edge.appends(log.id)[1..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    // Never resealed, never acknowledged, and the work stays pending.
    let again = device.package(id).unwrap();
    assert_eq!(again.event_id, stored.event_id);
    assert_eq!(again.descriptor.encode(), stored.descriptor.encode());
    assert_eq!(again.body, stored.body);
    assert_eq!(device.acked(id), None);
    assert_eq!(hosted.edge.entries(log).len(), 1);
    assert_eq!(*status.borrow(), SyncStatus::WaitingAuthorization);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn package_sealed_before_a_rotation_names_its_own_epoch() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, mut status) = registered(&hosted, &device).await;
    hosted.go_down();
    let (_, id) = device.new_note("sealed under the first epoch");
    client.wake();
    until(20, "sealed", || device.package(id).is_some()).await;
    let stored = device.package(id).unwrap();

    // The base moves on to another epoch, on the log and on this device.
    // The package still belongs to the epoch it was sealed under.
    let rotated = [0x5e; 32];
    hosted.edge.rotate_epoch(log, rotated);
    let raw = device.raw();
    raw.busy_timeout(Duration::from_secs(5)).unwrap();
    raw.execute("UPDATE log_progress SET epoch_id=?1", [rotated.as_slice()])
        .unwrap();
    hosted.come_up();
    client.wake();
    until(20, "refused by the log object", || {
        refused(&hosted, Refusal::Epoch) >= 1
            && *status.borrow_and_update() == SyncStatus::WaitingAuthorization
    })
    .await;
    assert!(
        hosted.edge.appends(log.id)[1..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    let again = device.package(id).unwrap();
    assert_eq!(again.descriptor.encode(), stored.descriptor.encode());
    assert_eq!(again.body, stored.body);
    assert_eq!(device.acked(id), None);
    assert_eq!(hosted.edge.entries(log).len(), 1);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_queue_survives_restart() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, mut status) = registered(&hosted, &device).await;
    hosted.go_down();
    let (_, a) = device.new_note("offline a");
    let (_, b) = device.new_note("offline b");
    client.wake();
    until(20, "sealed offline", || {
        device.package(a).is_some()
            && device.package(b).is_some()
            && *status.borrow_and_update() == SyncStatus::WaitingNetwork
    })
    .await;
    let before = [device.package(a).unwrap(), device.package(b).unwrap()];
    client.shutdown().await;

    hosted.come_up();
    let (client, _) = device.start(&hosted);
    until(20, "acked after restart", || {
        device.acked(a).is_some() && device.acked(b).is_some()
    })
    .await;
    let appends = hosted.edge.appends(log.id);
    assert_eq!(appends.len(), 3);
    let stages = hosted.edge.stages(log.id);
    for stored in &before {
        assert!(appends.contains(&stored.descriptor.encode()));
        assert!(stages.contains(&stored.body));
    }
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credit_returned_per_frame() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    // Three 4 MiB bodies, read twice: 24 MiB through an 8 MiB window.
    let bodies: Vec<_> = (1..=3u8)
        .map(|n| hosted.edge.insert_body(log, vec![n; 4 * 1024 * 1024]))
        .collect();
    let answer = {
        let mut session = client.authz().await.unwrap();
        let want = Want::ReadBodies {
            log,
            bodies: bodies.clone(),
        };
        session
            .ask(ToService::Permits {
                items: vec![want.clone(), want],
            })
            .await
            .unwrap()
    };
    let FromService::Permits { items } = answer else {
        panic!("permits: {answer:?}")
    };
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let read = async {
        let mut total = 0;
        for permit in items {
            let permit = permit.unwrap();
            let mut answers = data.send(|id| Request::Read { id, permit }).unwrap();
            for index in 0..3u8 {
                let Some(Response::Body {
                    index: got, bytes, ..
                }) = answers.next().await
                else {
                    panic!("body {index}")
                };
                assert_eq!(got, index);
                assert_eq!(bytes, vec![index + 1; 4 * 1024 * 1024]);
                total += bytes.len();
            }
        }
        total
    };
    let total = tokio::time::timeout(Duration::from_secs(20), read)
        .await
        .expect("the window was granted back");
    assert_eq!(total, 24 * 1024 * 1024);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_transitions() {
    let (hosted, device) = setup();
    let log = device.log();
    let (mut first, _) = device.new_note("first");
    device.append(&mut first, "second");
    let (client, status) = device.start(&hosted);
    let history = Arc::new(Mutex::new(Vec::new()));
    let recorder = {
        let history = history.clone();
        let mut status = status.clone();
        tokio::spawn(async move {
            history.lock().unwrap().push(*status.borrow_and_update());
            while status.changed().await.is_ok() {
                history.lock().unwrap().push(*status.borrow_and_update());
            }
        })
    };
    let reached = |want: SyncStatus| {
        let history = history.clone();
        move || history.lock().unwrap().contains(&want)
    };
    until(20, "synced", reached(SyncStatus::Synced)).await;
    {
        let history = history.lock().unwrap();
        let at = |s| history.iter().position(|h| *h == s).unwrap();
        assert!(at(SyncStatus::SavedLocal { pending: 1 }) < at(SyncStatus::Syncing { pending: 1 }));
        assert!(at(SyncStatus::Syncing { pending: 1 }) < at(SyncStatus::Synced));
    }

    hosted.go_down();
    device.append(&mut first, "offline");
    client.wake();
    until(
        20,
        "waiting for the network",
        reached(SyncStatus::WaitingNetwork),
    )
    .await;
    history.lock().unwrap().clear();
    hosted.come_up();
    client.wake();
    until(20, "synced again", reached(SyncStatus::Synced)).await;

    hosted.edge.close_epoch(log);
    let closed = device.append(&mut first, "closed");
    client.wake();
    until(
        20,
        "waiting for authorization",
        reached(SyncStatus::WaitingAuthorization),
    )
    .await;

    // Work the log ordered but did not accept is shown as such.
    until(20, "sealed", || device.package(closed).is_some()).await;
    let raw = device.raw();
    raw.busy_timeout(Duration::from_secs(5)).unwrap();
    raw.execute(
        "INSERT INTO note_outbox_progress(update_id,staged,acked_position,outcome) VALUES (?1,1,9,4)",
        [closed],
    )
    .unwrap();
    client.wake();
    until(
        20,
        "not accepted",
        reached(SyncStatus::NotAccepted { notes: 1 }),
    )
    .await;

    device
        .owner
        .record_stop(device.id, log, StopReason::Integrity)
        .unwrap();
    client.wake();
    until(20, "stopped", reached(SyncStatus::Stopped)).await;
    client.shutdown().await;
    recorder.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authz_for_others_shares_the_session_backoff() {
    let (hosted, device) = setup();
    hosted.go_down();
    let (client, _) = device.start(&hosted);
    for _ in 0..20 {
        assert!(client.authz().await.is_err());
    }
    let tried = hosted.edge.authz_connects.load(Ordering::SeqCst);
    assert!(tried <= 4, "{tried} connection attempts");
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_session_older_than_its_life_is_replaced_when_taken() {
    let (hosted, device) = setup();
    let (client, _) = registered(&hosted, &device).await;
    drop(client.authz().await.unwrap());
    let before = hosted.edge.authz_connects.load(Ordering::SeqCst);
    drop(client.authz().await.unwrap());
    assert_eq!(hosted.edge.authz_connects.load(Ordering::SeqCst), before);
    tokio::time::advance(Duration::from_secs(541)).await;
    drop(client.authz().await.unwrap());
    assert!(hosted.edge.authz_connects.load(Ordering::SeqCst) > before);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn base_keys_are_asked_for_by_base_and_outside_owner_locks() {
    let (hosted, device) = setup();
    let (client, _) = registered(&hosted, &device).await;
    let (_, id) = device.new_note("keys");
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    assert!(!device.signer.wrong_base.load(Ordering::SeqCst));
    assert!(!device.signer.owner_lock_held.load(Ordering::SeqCst));
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_that_does_not_verify_is_unsupported() {
    let (hosted, device) = setup();
    let mut endpoint = device.endpoint(&hosted);
    endpoint.policy = b"{}".to_vec();
    endpoint.policy_signature = vec![0; 64];
    let (client, mut status) = device.start_at(&hosted, endpoint);
    until(20, "unsupported", || {
        *status.borrow_and_update() == SyncStatus::Unsupported
    })
    .await;
    assert!(!device.registered());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_seen_receipt_refuses_to_seal() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, mut status) = registered(&hosted, &device).await;
    let good = device.progress().receipt.unwrap();
    let mut forged = good;
    forged[299] ^= 1;
    let raw = device.raw();
    raw.busy_timeout(Duration::from_secs(5)).unwrap();
    raw.execute("UPDATE log_progress SET receipt=?1", [forged.as_slice()])
        .unwrap();
    let (_, id) = device.new_note("unprovable");
    client.wake();
    until(20, "held locally", || {
        *status.borrow_and_update() == SyncStatus::SavedLocal { pending: 1 }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(device.package(id).is_none(), "nothing sealed");
    assert_eq!(hosted.edge.appends(log.id).len(), 1, "only the genesis");

    // The same work publishes once the verified receipt is back.
    raw.execute("UPDATE log_progress SET receipt=?1", [good.as_slice()])
        .unwrap();
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_that_lost_the_registration_gets_the_same_genesis_again() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    let (mut note, first) = device.new_note("before");
    client.wake();
    until(20, "acked", || device.acked(first).is_some()).await;
    let genesis = hosted.edge.entries(log)[0].1.encode();

    // The base is unknown to the restored service: content permits are
    // refused until RegisterBase sends the same genesis, whose append is
    // an exact retry of the ordered one.
    hosted.restart_service_empty();
    let second = device.append(&mut note, "after");
    client.wake();
    until(20, "acked after re-registration", || {
        device.acked(second).is_some()
    })
    .await;
    let appends = hosted.edge.appends(log.id);
    assert_eq!(appends.iter().filter(|a| **a == genesis).count(), 2);
    assert_eq!(hosted.edge.entries(log).len(), 3);
    assert_eq!(device.acked(second), Some(3));
    client.shutdown().await;
}
