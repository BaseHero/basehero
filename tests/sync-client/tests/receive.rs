//! The receive path, account following and exact base-control copies
//! against the fake hosted environment: real signed-up devices and their
//! native stores, the real authorization service behind the attested
//! channel, and a data edge that behaves as the Worker and log object do.
//!
//! Two-device tests use two genuine device identities of one account, each
//! with its own native keys. The second is provisioned by the
//! `Device::join` fixture (see there) until pairing supplies it.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_device::incoming::Unaccepted;
use bh_storage::sync_state::{BaseControl, ControlOutcome};
use bh_sync::{
    BaseId, BodyObject, Commitment, EventId, OpaqueEvent, Route, referenced_body, wire::Refusal,
};
use bh_sync_client::{Client, Signer, SyncStatus};
use std::sync::{Arc, atomic::Ordering};
use support::{
    device::{Device, test_keys, until},
    fake::{Hook, Hosted},
};
use tokio::sync::watch;

type Started = (Client, watch::Receiver<SyncStatus>);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn altered_wrapper_of_signed_signup_original_cannot_poison_outer_checkpoint() {
    let hosted = Hosted::new();
    let mac = Device::new();
    hosted
        .edge
        .alter_account_second_on_append
        .store(true, Ordering::SeqCst);
    let db = mac.owner.shared_database(mac.id).unwrap();
    let (client, _) = mac.start(&hosted);
    until(20, "forged outer page read", || {
        hosted
            .edge
            .reads(mac.account_log)
            .iter()
            .any(|(first, last)| *first == 1 && *last == 64)
    })
    .await;
    until(20, "own base registered", || mac.registered()).await;
    assert_eq!(mac.signer.current_account().unwrap().head().position, 3);
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        0
    );
    client.shutdown().await;
    hosted
        .edge
        .alter_account_second_on_append
        .store(false, Ordering::SeqCst);
    hosted.edge.serve_ordered(mac.account_log);
    let (client, _) = mac.start(&hosted);
    until(20, "honest signup prefix checkpoint", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 3
    })
    .await;
    let next = mac.signer.add_device(test_keys(81));
    hosted.edge.order_account(mac.account_log, &next);
    client.wake();
    until(20, "honest suffix applied and checkpointed", || {
        mac.signer.current_account().unwrap().head().position == 4
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 4
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_outer_page_with_wrong_opening_cannot_advance_checkpoint() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "outer signup checkpoint", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 3
    })
    .await;
    let first = mac.signer.add_device(test_keys(71));
    hosted.edge.order_account(mac.account_log, &first);
    client.wake();
    until(20, "outer fourth", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 4
    })
    .await;
    client.shutdown().await;
    let opening3 = hosted.edge.entries(mac.account_log)[2].0.after();
    let alternate = bh_authz::proto::account_log_wrap(b"alternate fourth", None).unwrap();
    let fork4 = Commitment::order(
        BaseId(mac.account_log.id),
        opening3,
        &alternate,
        Route::Control,
    )
    .unwrap();
    let next = mac.signer.add_device(test_keys(81));
    hosted.edge.order_account(mac.account_log, &next);
    hosted
        .edge
        .serve_account_after(mac.account_log, 5, fork4.after(), &[next]);
    let prior = hosted.edge.reads(mac.account_log).len();
    let (client, mut status) = mac.start(&hosted);
    until(20, "wrong outer page", || {
        hosted.edge.reads(mac.account_log).len() > prior
    })
    .await;
    client.wake();
    until(20, "wrong outer page retried", || {
        hosted.edge.reads(mac.account_log).len() > prior + 1
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        4
    );
    assert_eq!(mac.signer.current_account().unwrap().head().position, 4);
    assert_ne!(*status.borrow_and_update(), SyncStatus::Stopped);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outer_page_that_differs_from_the_stored_inner_original_does_not_advance() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    // This test commits a successor directly: setup must first finish its
    // separate evidence-attachment transaction.
    until(20, "setup confirmed", || !mac.home_pending()).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "outer signup checkpoint", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 3
    })
    .await;
    client.shutdown().await;
    let kept = mac.signer.add_device(test_keys(71));
    let other = mac.signer.add_device(test_keys(81));
    let at = hosted.edge.order_account(mac.account_log, &kept);
    let confirmed = hosted.edge.account_confirmation(mac.account_log, at);
    mac.signer
        .apply_account_timed(
            mac.signer.current_account().unwrap().head(),
            vec![(kept, Some(confirmed))],
        )
        .await
        .unwrap();
    hosted.edge.serve_account(mac.account_log, 4, &[other]);
    let prior = hosted.edge.reads(mac.account_log).len();
    let (client, mut status) = mac.start(&hosted);
    until(20, "mismatch read", || {
        hosted.edge.reads(mac.account_log).len() > prior
    })
    .await;
    client.wake();
    until(20, "mismatch retried", || {
        hosted.edge.reads(mac.account_log).len() > prior + 1
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );
    assert_eq!(mac.signer.current_account().unwrap().head().position, 4);
    assert_eq!(mac.signer.applied.lock().unwrap().len(), 1);
    assert_ne!(*status.borrow_and_update(), SyncStatus::Stopped);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_outer_checkpoint_write_retries_exact_inner_overlap() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "outer signup checkpoint", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 3
    })
    .await;
    client.shutdown().await;
    let sql = mac.raw();
    sql.execute_batch(
        "CREATE TRIGGER fail_outer BEFORE UPDATE ON account_outer_progress
        BEGIN SELECT RAISE(FAIL, 'checkpoint denied'); END;",
    )
    .unwrap();
    let first = mac.signer.add_device(test_keys(71));
    hosted.edge.order_account(mac.account_log, &first);
    let (client, _) = mac.start(&hosted);
    until(20, "inner applied", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );
    client.shutdown().await;
    sql.execute_batch("DROP TRIGGER fail_outer").unwrap();
    let (client, _) = mac.start(&hosted);
    until(20, "outer reconciled", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 4
    })
    .await;
    assert_eq!(mac.signer.applied.lock().unwrap().len(), 1);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inner_commit_before_outer_checkpoint_reconciles_exactly_without_reapplying() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    // The fixture's owner may still be completing private signup while the
    // follower has already checkpointed the public three-event prefix.
    until(
        20,
        "outer signup checkpoint and local home completion",
        || {
            !mac.home_pending()
                && db
                    .lock()
                    .unwrap()
                    .account_outer_progress(mac.account_log.id, hosted.edge.root())
                    .unwrap()
                    .order
                    .position()
                    == 3
        },
    )
    .await;
    client.shutdown().await;
    let first = mac.signer.add_device(test_keys(71));
    let at = hosted.edge.order_account(mac.account_log, &first);
    let confirmed = hosted
        .confirmed_account(mac.account_log)
        .await
        .pop()
        .unwrap()
        .1
        .unwrap();
    assert_eq!(at, 4);
    let before = mac.signer.current_account().unwrap().head();
    mac.signer
        .apply_account_timed(before, vec![(first, Some(confirmed))])
        .await
        .unwrap();
    assert_eq!(mac.signer.applied.lock().unwrap().len(), 1);
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );

    let (client, _) = mac.start(&hosted);
    until(20, "outer caught up", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 4
    })
    .await;
    assert_eq!(
        mac.signer.applied.lock().unwrap().len(),
        1,
        "the already committed inner change must not be applied twice"
    );
    let next = mac.signer.add_device(test_keys(81));
    hosted.edge.order_account(mac.account_log, &next);
    client.wake();
    until(20, "new suffix", || {
        mac.signer.current_account().unwrap().head().position == 5
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 5
    })
    .await;
    assert_eq!(mac.signer.applied.lock().unwrap().len(), 2);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_device_restart_reads_only_outer_suffix() {
    let hosted = Hosted::new();
    let (_mac, mac_client, fold, fold_client) = two(&hosted).await;
    let db = fold.owner.shared_database(fold.id).unwrap();
    until(20, "joined outer checkpoint", || {
        db.lock()
            .unwrap()
            .account_outer_progress(fold.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 4
    })
    .await;
    fold_client.0.shutdown().await;
    mac_client.0.shutdown().await;
    let prior = hosted.edge.reads(fold.account_log).len();
    let (client, _) = fold.start(&hosted);
    until(20, "joined resumed read", || {
        hosted.edge.reads(fold.account_log).len() > prior
    })
    .await;
    assert_eq!(
        hosted.edge.reads(fold.account_log)[prior].0,
        5,
        "a durable opening must not replay the four-entry account prefix"
    );
    client.shutdown().await;
}

/// Started, with the own base registered and its genesis applied.
async fn registered(hosted: &Arc<Hosted>, device: &Device) -> Started {
    let started = device.start(hosted);
    until(20, "registered", || {
        device.registered() && device.progress().position >= 1
    })
    .await;
    started
}

/// The base's copy of the account has reached `position`.
fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

/// Two devices of one account on the first one's base: the second joined,
/// its addition copied into the base by the first, both caught up.
async fn two(hosted: &Arc<Hosted>) -> (Device, Started, Device, Started) {
    let mac = Device::new();
    let mac_client = registered(hosted, &mac).await;
    let fold = Device::join(&mac, hosted).await;
    until(20, "addition copied", || copied(&mac) == 4).await;
    let fold_client = fold.start(hosted);
    until(20, "joined device caught up", || {
        fold.progress().position == mac.progress().position && copied(&fold) == 4
    })
    .await;
    (mac, mac_client, fold, fold_client)
}

fn status(started: &mut Started) -> SyncStatus {
    *started.1.borrow_and_update()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trapped_remote_note_does_not_block_own_echo_or_claim_synced() {
    let hosted = Hosted::new();
    let device = Device::new();
    let mut started = registered(&hosted, &device).await;
    until(20, "initially synced", || {
        status(&mut started) == SyncStatus::Synced
    })
    .await;
    let poisoned = [222; 32];
    let mut bomb = vec![1, 1, 1, 0, 8, 1, 4, b'b', b'o', b'm', b'b', 1];
    for _ in 0..100_000 {
        bomb.extend_from_slice(&[117, 1]);
    }
    bomb.extend_from_slice(&[126, 0]);
    device.remote_note(&hosted, poisoned, &bomb);
    let (healthy, _) = device.new_note("healthy after poison");
    started.0.wake();
    until(20, "tail and own echo", || {
        device.progress().position == hosted.edge.head(device.log()).position
            && device.pending() == 0
    })
    .await;
    until(20, "held status settled", || {
        matches!(
            status(&mut started),
            SyncStatus::Synced | SyncStatus::Syncing { pending: 0 }
        )
    })
    .await;
    assert_ne!(status(&mut started), SyncStatus::Synced);
    assert_eq!(device.inserted(healthy.note, "healthy after poison"), 1);
    assert!(
        device
            .owner
            .shared_database(device.id)
            .unwrap()
            .lock()
            .unwrap()
            .has_held_notes()
            .unwrap()
    );
    assert!(device.progress().stopped.is_none());
    started.0.shutdown().await;
    let mut restarted = device.start(&hosted);
    until(20, "restart checked", || {
        matches!(
            status(&mut restarted),
            SyncStatus::Synced | SyncStatus::Syncing { pending: 0 }
        )
    })
    .await;
    assert_ne!(status(&mut restarted), SyncStatus::Synced);
    restarted.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_remote_note_and_fanout_after_commit() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    let wakes = mac_client.0.window_wakes();
    let (mut mine, first) = mac.new_note("from the mac");
    let note = mine.note;
    mac_client.0.wake();
    until(20, "mac accepted", || mac.pending() == 0).await;
    until(20, "fold received", || {
        fold.inserted(note, "from the mac") == 1
    })
    .await;
    assert!(mac.acked(first).is_some());
    // Mac's window had nothing queued for its own accepted work.
    let _ = wakes.take();

    let mut theirs = fold.writer(note);
    fold.append(&mut theirs, "from the fold");
    fold_client.0.wake();
    until(20, "mac received", || {
        mac.inserted(note, "from the fold") == 1
    })
    .await;
    // The window showing the note is woken only after the batch committed,
    // and its delivery is queued for it.
    let woken = tokio::time::timeout(std::time::Duration::from_secs(10), wakes.next())
        .await
        .expect("window woken");
    assert!(woken.contains(&mine.window().to_string()));
    assert!(mac.owner.has_queued_delivery(mine.window()));
    until(20, "fold accepted", || fold.pending() == 0).await;
    assert_eq!(mac.inserted(note, "from the mac"), 1);
    assert_eq!(
        mac.reopened(note).digest().unwrap(),
        fold.reopened(note).digest().unwrap()
    );
    let _ = mac.append(&mut mine, "more");
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_echo_accepted_retires_once() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = registered(&hosted, &device).await;
    let (writer, id) = device.new_note("echoed once");
    client.wake();
    until(20, "accepted", || device.pending() == 0).await;
    let position = device.acked(id).unwrap();
    assert_eq!(device.progress().position, position);
    let unaccepted = device
        .owner
        .unaccepted(device.id, device.key(writer.note))
        .unwrap();
    assert!(unaccepted.is_empty());
    client.shutdown().await;
    // A restart reads on from stored progress: the echo is not applied again.
    let reads_before = hosted.edge.selected_reads(device.log()).len();
    let (client, _) = device.start(&hosted);
    until(20, "read again", || {
        hosted.edge.selected_reads(device.log()).len() > reads_before
    })
    .await;
    let reads = hosted.edge.selected_reads(device.log());
    assert!(
        reads[reads_before..]
            .iter()
            .all(|(first, _)| *first > position)
    );
    assert_eq!(device.inserted(writer.note, "echoed once"), 1);
    assert_eq!(device.progress().position, position);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_not_synced_until_accepted_echo() {
    let hosted = Hosted::new();
    let device = Device::new();
    let mut started = registered(&hosted, &device).await;
    until(20, "synced", || status(&mut started) == SyncStatus::Synced).await;
    // The Ack is verified and recorded, and a notice proves the new head,
    // but the log's batch reads lag: no echo yet, so not Synced.
    hosted.edge.freeze_reads(Some(device.progress().position));
    let (_, id) = device.new_note("acked, not yet echoed");
    started.0.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(device.pending(), 1);
    assert_eq!(status(&mut started), SyncStatus::Syncing { pending: 1 });
    hosted.edge.freeze_reads(None);
    started.0.wake();
    until(20, "synced after the echo", || {
        status(&mut started) == SyncStatus::Synced
    })
    .await;
    assert_eq!(device.pending(), 0);
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ack_before_echo_and_wrong_route_does_not_claim_content_identity() {
    let hosted = Hosted::new();
    let device = Device::new();
    let mut started = registered(&hosted, &device).await;
    let log = device.log();

    // Acknowledged, but the echo cannot commit yet: the work stays pending
    // as Acked, in its working note.
    let raw = device.raw();
    raw.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER no_echo BEFORE INSERT ON log_seen BEGIN SELECT RAISE(ABORT,'injected'); END;",
    )
    .unwrap();
    let (mut writer, id) = device.new_note("acked first");
    started.0.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(device.pending(), 1);
    let state = device
        .owner
        .unaccepted(device.id, device.key(writer.note))
        .unwrap();
    assert_eq!(state[0].state, Unaccepted::Acked);
    assert_eq!(device.inserted(writer.note, "acked first"), 1);
    // The local commit failure shows as work saved here, never as Synced.
    assert_eq!(status(&mut started), SyncStatus::SavedLocal { pending: 1 });
    raw.execute_batch("DROP TRIGGER no_echo;").unwrap();
    started.0.wake();
    until(20, "accepted from the echo", || device.pending() == 0).await;
    assert_eq!(device.inserted(writer.note, "acked first"), 1);

    // The same bytes first ordered on the wrong route consume a separate
    // routed ID. They cannot reserve the pending content package's ID.
    hosted.go_down();
    let second = device.append(&mut writer, "rejected");
    started.0.wake();
    until(20, "sealed", || device.package(second).is_some()).await;
    let stored = device.package(second).unwrap();
    let wrong_at = hosted.edge.order(
        log,
        &stored.descriptor,
        Some(stored.body.clone()),
        Route::Control,
    );
    // Keep the independently routed content publication pending while the
    // receiver judges this wrong-route use of the same exact descriptor.
    hosted.edge.refuse_next_event(Refusal::Predecessor);
    hosted.come_up();
    started.0.wake();
    until(20, "wrong-route original judged", || {
        device.progress().position >= wrong_at
    })
    .await;
    assert_ne!(
        stored.descriptor.publication_id(Route::Control),
        stored.descriptor.publication_id(Route::Content),
    );
    // The wrong-route append used its staged body. The exact pending content
    // package cannot restage that already ordered body, but it is not falsely
    // marked rejected, accepted or conflicted by the control's routed ID.
    assert_eq!(device.pending(), 1);
    let current = device.package(second).unwrap();
    assert_eq!(current.descriptor.encode(), stored.descriptor.encode());
    assert_eq!(current.body, stored.body);
    assert_eq!(current.event_id, stored.event_id);
    let unaccepted = device
        .owner
        .unaccepted(device.id, device.key(writer.note))
        .unwrap();
    assert_eq!(unaccepted.len(), 1);
    assert_eq!(unaccepted[0].update_id, second);
    assert_eq!(unaccepted[0].state, Unaccepted::Sealed);
    assert_eq!(device.inserted(writer.note, "rejected"), 1);
    assert_ne!(status(&mut started), SyncStatus::PublishingStopped);
    assert!(
        !hosted
            .edge
            .entries(log)
            .iter()
            .any(|(c, e)| c.route() == Route::Content && e.digest() == stored.descriptor.digest())
    );
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_exact_own_content_keeps_work_and_stops_resends_after_judgment() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    fold_client.0.shutdown().await;
    hosted.go_down();
    let (writer, update) = mac.new_note("sealed before closure");
    mac_client.0.wake();
    until(20, "sealed while offline", || mac.package(update).is_some()).await;
    let stored = mac.package(update).unwrap();
    mac_client.0.shutdown().await;
    hosted
        .edge
        .order_account(mac.account_log, &fold.signer.remove_self());
    hosted.come_up();
    let (client, mut current) = mac.start(&hosted);
    until(20, "content epoch closed", || {
        copied(&mac) == 5 && mac.progress().epoch_id.is_none()
    })
    .await;
    let at = hosted.edge.order(
        mac.log(),
        &stored.descriptor,
        Some(stored.body.clone()),
        Route::Content,
    );
    client.wake();
    let judged = || {
        mac.owner
            .unaccepted(mac.id, mac.key(writer.note))
            .unwrap()
            .first()
            .map(|entry| entry.state)
            == Some(Unaccepted::Rejected)
    };
    until(20, "exact own original rejected by history", || {
        mac.progress().position >= at && judged()
    })
    .await;
    assert_eq!(mac.pending(), 1);
    assert_eq!(
        mac.package(update).unwrap().descriptor.encode(),
        stored.descriptor.encode()
    );
    assert_eq!(mac.inserted(writer.note, "sealed before closure"), 1);
    until(20, "not accepted shown", || {
        *current.borrow_and_update() == SyncStatus::NotAccepted { notes: 1 }
    })
    .await;
    let sent = || {
        hosted
            .edge
            .appends(mac.log().id)
            .iter()
            .filter(|bytes| **bytes == stored.descriptor.encode())
            .count()
    };
    let before = sent();
    client.wake();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(sent(), before, "judged exact package is never resent");
    assert!(judged());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn judgment_of_exact_invalid_kept_bytes_stops_an_eligible_publisher() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = registered(&hosted, &device).await;
    hosted.go_down();
    let (writer, update) = device.new_note("kept invalid original");
    client.wake();
    until(20, "sealed", || device.package(update).is_some()).await;
    client.shutdown().await;
    // Keep the body reference and nonce but invalidate the binding ciphertext.
    // This fault-injected exact outbox package has a valid routed ID; the
    // publisher remains eligible until verified history judges it rejected.
    let stored = device.package(update).unwrap();
    let mut envelope = stored.descriptor.envelope().to_vec();
    envelope[500] ^= 1;
    let invalid = OpaqueEvent::new(stored.descriptor.nonce(), envelope).unwrap();
    let raw = device.raw();
    raw.execute(
        "UPDATE note_outbox SET descriptor=?2,event_id=?3 WHERE update_id=?1",
        rusqlite::params![
            update,
            invalid.encode(),
            invalid.publication_id(Route::Content).0.as_slice()
        ],
    )
    .unwrap();
    let exact = device.package(update).unwrap();
    assert_eq!(exact.descriptor.encode(), invalid.encode());
    assert_eq!(exact.body, stored.body);
    let before = hosted.edge.counts().want_stage;
    hosted.come_up();
    let (client, mut current) = device.start(&hosted);
    until(20, "eligible publisher tried invalid package", || {
        hosted.edge.counts().want_stage > before
    })
    .await;
    let at = hosted.edge.order(
        device.log(),
        &invalid,
        Some(exact.body.clone()),
        Route::Content,
    );
    client.wake();
    let judged = || {
        device
            .owner
            .unaccepted(device.id, device.key(writer.note))
            .unwrap()
            .first()
            .map(|entry| entry.state)
            == Some(Unaccepted::Rejected)
    };
    until(20, "rejected exact stored bytes", || {
        device.progress().position >= at && judged()
    })
    .await;
    assert_eq!(device.pending(), 1);
    assert_eq!(device.inserted(writer.note, "kept invalid original"), 1);
    until(20, "not accepted", || {
        *current.borrow_and_update() == SyncStatus::NotAccepted { notes: 1 }
    })
    .await;
    let requests = hosted.edge.counts().want_stage;
    client.wake();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        hosted.edge.counts().want_stage,
        requests,
        "no new staging after judgment"
    );
    assert!(judged());
    client.shutdown().await;
    let (restarted, mut status) = device.start(&hosted);
    until(20, "reopened judged package", || {
        *status.borrow_and_update() == SyncStatus::NotAccepted { notes: 1 }
    })
    .await;
    restarted.wake();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        hosted.edge.counts().want_stage,
        requests,
        "restart cannot resend judged bytes"
    );
    assert_eq!(
        device.package(update).unwrap().descriptor.encode(),
        invalid.encode()
    );
    restarted.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_concurrent_edits_then_reconnect_equal_after_reopen() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    let (mut mine, _) = mac.new_note("shared");
    let note = mine.note;
    mac_client.0.wake();
    until(20, "fold has it", || fold.inserted(note, "shared") == 1).await;
    let mut theirs = fold.writer(note);

    hosted.go_down();
    for n in 0..3 {
        mac.append(&mut mine, &format!("mac offline {n}"));
        fold.append(&mut theirs, &format!("fold offline {n}"));
    }
    mac_client.0.wake();
    fold_client.0.wake();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    hosted.come_up();
    mac_client.0.wake();
    fold_client.0.wake();
    until(30, "both accepted everything", || {
        mac.pending() == 0
            && fold.pending() == 0
            && mac.progress().position == fold.progress().position
            && mac.progress().position == hosted.edge.head(mac.log()).position
    })
    .await;
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;

    // Reopened from SQLite on each device: the same note, every edit once.
    assert_eq!(
        mac.reopened(note).digest().unwrap(),
        fold.reopened(note).digest().unwrap()
    );
    for n in 0..3 {
        for device in [&mac, &fold] {
            assert_eq!(device.inserted(note, &format!("mac offline {n}")), 1);
            assert_eq!(device.inserted(note, &format!("fold offline {n}")), 1);
        }
    }
    // And again after both restart.
    let mac_client = mac.start(&hosted);
    let fold_client = fold.start(&hosted);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        mac.reopened(note).digest().unwrap(),
        fold.reopened(note).digest().unwrap()
    );
    assert_eq!(mac.inserted(note, "shared"), 1);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_response_exact_control_retry_after_restart() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let log = mac.log();
    // The copy is ordered, then the device loses the answer and the edge.
    hosted.edge.hook(Hook::DropAfterAppend { then_down: true });
    let _fold = Device::join(&mac, &hosted).await;
    until(20, "copy ordered", || hosted.edge.entries(log).len() == 2).await;
    client.shutdown().await;
    assert_eq!(copied(&mac), 3, "not yet verified here");
    let db = mac.owner.shared_database(mac.id).unwrap();
    let kept = db.lock().unwrap().pending_base_control(mac.base.0).unwrap();
    let kept = kept.expect("kept before it was first sent");
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);

    hosted.come_up();
    let (client, _) = mac.start(&hosted);
    until(20, "settled", || {
        db.lock()
            .unwrap()
            .base_control_outcome(mac.base.0, 4)
            .unwrap()
            == Some(Some(ControlOutcome::Committed))
    })
    .await;
    assert_eq!(copied(&mac), 4);
    // Never signed again; only the kept bytes were ever sent; ordered once.
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    let appends = hosted.edge.appends(log.id);
    let copies: Vec<_> = appends[1..].iter().collect();
    assert!(!copies.is_empty());
    assert!(copies.iter().all(|a| **a == kept.descriptor));
    assert_eq!(hosted.edge.entries(log).len(), 2);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_add_copy_then_new_device_can_write() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = registered(&hosted, &mac).await;
    mac_client.shutdown().await;
    // The fold is in the account, not yet in the base's copy of it. It has
    // no approval to copy its own addition; a confirmed run permits a
    // newly added copier, but does not confer the person's approval.
    let fold = Device::join(&mac, &hosted).await;
    fold.signer.approve_controls.store(false, Ordering::SeqCst);
    let mut fold_started = fold.start(&hosted);
    let (note_writer, id) = fold.new_note("written by the fold");
    fold_started.0.wake();
    until(20, "fold read the base", || fold.progress().position == 1).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(fold.package(id).is_none(), "cannot seal before the copy");
    assert_eq!(copied(&fold), 3);
    assert_ne!(status(&mut fold_started), SyncStatus::Synced);

    // The mac follows the account, copies the addition, and the fold's
    // work is accepted on both devices.
    let (mac_client, _) = mac.start(&hosted);
    until(20, "copied", || copied(&mac) == 4 && copied(&fold) == 4).await;
    fold_started.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    until(20, "mac received", || {
        mac.inserted(note_writer.note, "written by the fold") == 1
    })
    .await;
    assert_eq!(mac.signer.applied.lock().unwrap().len(), 1);
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    assert_eq!(fold.signer.control_signatures.load(Ordering::SeqCst), 0);
    mac_client.shutdown().await;
    fold_started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_after_already_ordered_copy_reconciles_from_verified_log() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let log = mac.log();
    // The copy is ordered and its Ack lost; the edge stays up. The service
    // then confirms the copy from the log and refuses it as no longer next.
    hosted.edge.hook(Hook::DropAfterAppend { then_down: false });
    let _fold = Device::join(&mac, &hosted).await;
    until(20, "copied", || copied(&mac) == 4).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "settled", || {
        db.lock()
            .unwrap()
            .pending_base_control(mac.base.0)
            .unwrap()
            .is_none()
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .base_control_outcome(mac.base.0, 4)
            .unwrap(),
        Some(Some(ControlOutcome::Committed))
    );
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    assert_eq!(hosted.edge.entries(log).len(), 2, "ordered once");
    let kept_appends = hosted.edge.appends(log.id);
    assert!(kept_appends[1..].iter().all(|a| *a == kept_appends[1]));
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_change_pending_and_resync_handling() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mut started = registered(&hosted, &mac).await;
    let log = mac.log();
    // Without the person's approval the copy waits; so does content, which
    // the service refuses until the base has the account change.
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    let _fold = Device::join(&mac, &hosted).await;
    let (_, id) = mac.new_note("waits for the copy");
    started.0.wake();
    until(20, "waiting for authorization", || {
        status(&mut started) == SyncStatus::WaitingAuthorization
    })
    .await;
    until(20, "asked", || {
        mac.signer.control_requests.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(mac.acked(id), None);
    assert_eq!(hosted.edge.entries(log).len(), 1);
    assert_eq!(mac.pending(), 1);
    mac.signer.approve_controls.store(true, Ordering::SeqCst);
    started.0.wake();
    until(20, "copied and published", || {
        copied(&mac) == 4 && mac.pending() == 0
    })
    .await;
    until(20, "synced", || status(&mut started) == SyncStatus::Synced).await;

    // The service loses its record of the base. The next copy is refused as
    // Resync: the same genesis is registered again, then the kept copy is
    // sent byte for byte. An ordinary start never registers again.
    started.0.shutdown().await;
    let genesis = hosted.edge.entries(log)[0].1.encode();
    let registrations = || {
        hosted
            .edge
            .appends(log.id)
            .iter()
            .filter(|a| **a == genesis)
            .count()
    };
    assert_eq!(registrations(), 1);
    let mut started = mac.start(&hosted);
    until(20, "synced after restart", || {
        status(&mut started) == SyncStatus::Synced
    })
    .await;
    assert_eq!(registrations(), 1);
    hosted.restart_service_without_bases().await;
    let signatures = mac.signer.control_signatures.load(Ordering::SeqCst);
    let _third = Device::join(&mac, &hosted).await;
    until(20, "second copy", || copied(&mac) == 5).await;
    assert_eq!(registrations(), 2);
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        signatures + 1
    );
    started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn remote_removal_before_account_follow_is_not_unsupported() {
    let hosted = Hosted::new();
    let (mac, mut mac_started, fold, fold_client) = two(&hosted).await;
    fold_client.0.shutdown().await;
    let known = mac.signer.current_account().unwrap().head().position;
    let refused_before = hosted.edge.refused_read_batches.load(Ordering::SeqCst);
    let selected_before = hosted.edge.selected_reads(mac.log()).len();
    // Withhold account hints. Order an unread base event and then the removal
    // without yielding, so the receiver must request ReadBatch into copy lag.
    hosted
        .edge
        .suppress_account_notices
        .store(true, Ordering::SeqCst);
    fold.remote_note(&hosted, [99; 32], b"preceding the removal");
    hosted
        .edge
        .order_account(mac.account_log, &fold.signer.remove_self());
    assert_eq!(mac.signer.current_account().unwrap().head().position, known);
    let mut observed = mac_started.1.clone();
    let (stop_monitor, mut monitor_stop) = tokio::sync::oneshot::channel::<()>();
    let status_monitor = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut monitor_stop => break,
                changed = observed.changed() => {
                    if changed.is_err() { break; }
                    // A routine account change is followed while syncing: it
                    // is neither unsupported nor missing history.
                    let shown = *observed.borrow_and_update();
                    assert_ne!(shown, SyncStatus::Unsupported);
                    assert_ne!(shown, SyncStatus::HistoryMissing);
                }
            }
        }
    });
    mac_started.0.wake();
    until(10, "refused ReadBatch while account is behind", || {
        assert_ne!(status(&mut mac_started), SyncStatus::Unsupported);
        hosted.edge.refused_read_batches.load(Ordering::SeqCst) > refused_before
    })
    .await;
    // ACCOUNT_POLL is 300s; with notices suppressed, copying within ten
    // virtual seconds requires the receiver's follow handoff.
    until(10, "receiver-led account follow and copy", || {
        assert_ne!(status(&mut mac_started), SyncStatus::Unsupported);
        copied(&mac) > known
    })
    .await;
    let _ = stop_monitor.send(());
    status_monitor.await.unwrap();
    mac_started.0.shutdown().await;
    let mut reopened = mac.start(&hosted);
    until(10, "ordinary batch after follow", || {
        hosted.edge.selected_reads(mac.log()).len() > selected_before
    })
    .await;
    assert_ne!(status(&mut reopened), SyncStatus::Unsupported);
    reopened.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removal_closure_waits_and_keeps_work() {
    let hosted = Hosted::new();
    let (mac, mut mac_started, fold, fold_client) = two(&hosted).await;
    fold_client.0.shutdown().await;
    // The fold removes itself in the account; the mac copies the removal,
    // which closes the base's content epoch. The mac's rotation for it
    // waits until the closed epoch has been seen.
    mac.signer.refuse_rotation.store(true, Ordering::SeqCst);
    let removal = fold.signer.remove_self();
    hosted.edge.order_account(mac.account_log, &removal);
    until(20, "removal copied", || copied(&mac) == 5).await;
    assert_eq!(mac.progress().epoch_id, None);
    let (writer, id) = mac.new_note("kept while closed");
    mac_started.0.wake();
    until(20, "protecting", || {
        status(&mut mac_started) == SyncStatus::Protecting
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(mac.acked(id), None);
    assert_eq!(mac.pending(), 1);
    assert_eq!(mac.inserted(writer.note, "kept while closed"), 1);
    assert_eq!(status(&mut mac_started), SyncStatus::Protecting);
    // The rotation and the base's rekey reopen the epoch: the kept work is
    // acknowledged under the new key.
    mac.signer.refuse_rotation.store(false, Ordering::SeqCst);
    until(30, "acknowledged once the epoch reopens", || {
        mac_started.0.wake();
        mac.acked(id).is_some() && status(&mut mac_started) == SyncStatus::Synced
    })
    .await;
    let epoch = mac.progress().epoch_id.unwrap();
    assert!(mac.signer.holds_epoch(epoch));
    let package = mac.package(id).unwrap();
    assert_eq!(
        bh_event::sealed_epoch(&package.descriptor, mac.metadata_key().expose(), mac.base).unwrap(),
        epoch
    );
    mac_started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_body_waits_then_recovers() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    let before = mac.progress().position;
    let (fold_note, _) = fold.new_note("first from the fold");
    let (lost_note, lost) = fold.new_note("its body goes missing");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    let stored = fold.package(lost).unwrap();
    let body = referenced_body(&stored.descriptor).unwrap();
    let bytes = hosted.edge.take_body(mac.log(), body).unwrap();

    // The mac keeps its own work and everything verified before the gap.
    let (own, _) = mac.new_note("offline work stays");
    let mut started = mac.start(&hosted);
    until(20, "history missing", || {
        status(&mut started) == SyncStatus::HistoryMissing
    })
    .await;
    let lost_at = fold.acked(lost).unwrap();
    assert_eq!(mac.progress().position, lost_at - 1);
    assert!(mac.progress().position > before);
    assert_eq!(mac.inserted(fold_note.note, "first from the fold"), 1);
    assert_eq!(mac.inserted(lost_note.note, "its body goes missing"), 0);
    assert_eq!(
        mac.pending(),
        1,
        "its own work is not accepted past the gap"
    );
    assert_eq!(mac.inserted(own.note, "offline work stays"), 1);

    hosted.edge.insert_body(mac.log(), bytes);
    started.0.wake();
    until(20, "recovered", || {
        mac.inserted(lost_note.note, "its body goes missing") == 1 && mac.pending() == 0
    })
    .await;
    started.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_original_then_valid_progresses() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = registered(&hosted, &device).await;
    let (_, first) = device.new_note("valid before");
    client.wake();
    until(20, "accepted", || device.pending() == 0).await;
    let log = device.log();
    // A known-version original under another event id than the one it was
    // signed with: ordered, and an invalid submission.
    let stored = device.package(first).unwrap();
    let forged =
        OpaqueEvent::new(EventId([0x5f; 32]), stored.descriptor.envelope().to_vec()).unwrap();
    let forged_at = hosted
        .edge
        .order(log, &forged, Some(stored.body.clone()), Route::Content);
    let (writer, after) = device.new_note("valid after");
    client.wake();
    until(20, "valid after accepted", || device.pending() == 0).await;
    assert!(device.acked(after).unwrap() > forged_at);
    assert_eq!(device.progress().position, hosted.edge.head(log).position);
    assert_eq!(device.inserted(writer.note, "valid after"), 1);
    assert_eq!(device.progress().stopped, None);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_base_receives_from_production_batch_without_data_descriptor_read() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    let before = hosted.edge.reads(mac.log()).len();
    let (writer, _) = fold.new_note("selected by checker");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    mac_client.0.wake();
    until(20, "mac accepted", || {
        mac.inserted(writer.note, "selected by checker") == 1
    })
    .await;
    // L2c2's separate publisher still does a one-position Ack proof read.
    assert!(
        hosted.edge.reads(mac.log())[before..]
            .iter()
            .all(|(first, last)| first == last),
        "ordinary receiver must not reread a descriptor page on DATA: {:?}",
        hosted.edge.reads(mac.log())
    );
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn selected_grant_wrong_body_ordinal_never_advances_or_retires_echo() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = registered(&hosted, &device).await;
    let before = device.progress();
    let selected_before = hosted.edge.selected_reads(device.log()).len();
    hosted.edge.wrong_body_index.store(true, Ordering::SeqCst);
    let (_, id) = device.new_note("wrong body ordinal");
    client.wake();
    until(20, "ordered", || device.acked(id).is_some()).await;
    until(20, "producer selected", || {
        hosted.edge.selected_reads(device.log()).len() > selected_before
    })
    .await;
    tokio::time::advance(std::time::Duration::from_millis(200)).await;
    assert_eq!(device.progress().position, before.position);
    assert_eq!(device.pending(), 1);
    hosted.edge.wrong_body_index.store(false, Ordering::SeqCst);
    client.wake();
    until(20, "accepted after correct ordinal", || {
        device.pending() == 0
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incorrect_final_body_flag_never_advances_or_retires_echo() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.wrong_body_last.store(true, Ordering::SeqCst);
    let (_, id) = device.new_note("wrong final body");
    let before = device.progress();
    client.wake();
    until(20, "ordered", || device.acked(id).is_some()).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(device.progress().position, before.position);
    assert_eq!(device.pending(), 1);
    hosted.edge.wrong_body_last.store(false, Ordering::SeqCst);
    client.wake();
    until(20, "accepted after correct frame", || device.pending() == 0).await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_fork_stops() {
    let hosted = Hosted::new();
    let device = Device::new();
    let mut started = registered(&hosted, &device).await;
    let (writer, _) = device.new_note("before the fork");
    let (_, second) = device.new_note("rewritten");
    started.0.wake();
    until(20, "accepted", || device.pending() == 0).await;
    let good = device.progress();
    let selected_before = hosted.edge.selected_reads(device.log()).len();
    let data_before = hosted.edge.reads(device.log()).len();
    hosted.edge.fork(device.log());
    started.0.wake();
    until(20, "stopped", || {
        status(&mut started) == SyncStatus::Stopped
    })
    .await;
    assert!(
        hosted.edge.selected_reads(device.log()).len() > selected_before,
        "producer must inspect the contradictory first predecessor"
    );
    assert!(
        hosted.edge.reads(device.log()).len() > data_before,
        "Repair must give the legacy verifier the exact page"
    );
    let stopped = device.progress();
    assert!(stopped.stopped.is_some());
    // Everything verified before the contradiction is kept.
    assert_eq!(stopped.position, good.position);
    assert_eq!(stopped.head_hash, good.head_hash);
    assert_eq!(device.inserted(writer.note, "before the fork"), 1);
    assert!(device.acked(second).is_some());
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_commit_failure_keeps_cursor_and_retries_batch() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    let before = mac.progress();
    let raw = mac.raw();
    raw.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER fail_commit BEFORE INSERT ON log_seen BEGIN SELECT RAISE(ABORT,'injected'); END;",
    )
    .unwrap();
    let (writer, _) = fold.new_note("committed on retry");
    fold_client.0.wake();
    until(20, "fold acked", || fold.pending() == 0).await;
    mac_client.0.wake();
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    // Nothing committed, nothing lost; the same batch is read again.
    assert_eq!(mac.progress(), before);
    assert_eq!(mac.inserted(writer.note, "committed on retry"), 0);
    let first = before.position + 1;
    let tries = hosted
        .edge
        .selected_reads(mac.log())
        .iter()
        .filter(|(f, _)| *f == first)
        .count();
    assert!(tries >= 2, "{tries} reads from {first}");
    raw.execute_batch("DROP TRIGGER fail_commit;").unwrap();
    mac_client.0.wake();
    until(20, "committed", || {
        mac.inserted(writer.note, "committed on retry") == 1
    })
    .await;
    assert!(mac.progress().position > before.position);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn batch_resumes_from_sqlite_without_replay() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    let start = mac.progress().position;
    let ids: Vec<_> = (0..130)
        .map(|n| fold.new_note(&format!("bulk {n}")).1)
        .collect();
    fold_client.0.wake();
    until(60, "fold accepted all", || fold.pending() == 0).await;
    fold_client.0.shutdown().await;
    let end = hosted.edge.head(mac.log()).position;
    assert!(end >= start + 130);
    assert!(ids.iter().all(|id| fold.acked(*id).is_some()));

    let reads_before = hosted.edge.selected_reads(mac.log()).len();
    // The first run stops after its first batch, before it could catch up.
    hosted.edge.freeze_reads(Some(start + 48));
    let (client, _) = mac.start(&hosted);
    until(30, "first batch", || mac.progress().position == start + 48).await;
    client.shutdown().await;
    hosted.edge.freeze_reads(None);
    let resumed = mac.progress().position;
    let (client, _) = mac.start(&hosted);
    until(30, "all", || mac.progress().position == end).await;
    client.shutdown().await;
    let reads: Vec<_> = hosted.edge.selected_reads(mac.log())[reads_before..].to_vec();
    // Every read is bounded and starts after verified progress; after the
    // restart none goes back before where SQLite left off.
    assert!(reads.iter().all(|(first, last)| last - first < 64));
    assert!(reads.iter().all(|(first, _)| *first > start));
    let restart = reads
        .iter()
        .position(|(first, _)| *first == resumed + 1)
        .expect("resumed from stored progress");
    assert!(reads[restart..].iter().all(|(first, _)| *first > resumed));
}

#[tokio::test(start_paused = true)]
async fn quiet_subscription_renews_without_reconnect() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = registered(&hosted, &device).await;
    let log = device.log();
    until(20, "subscribed", || hosted.edge.subscriptions(log) >= 1).await;
    let connects = hosted.edge.data_connects.load(Ordering::SeqCst);
    let subscribed = hosted.edge.subscriptions(log);
    // Nothing happens on the log for a while: the short permits are
    // renewed over the same data socket before they end.
    tokio::time::sleep(std::time::Duration::from_secs(55)).await;
    assert!(hosted.edge.subscriptions(log) >= subscribed + 2);
    assert_eq!(hosted.edge.data_connects.load(Ordering::SeqCst), connects);
    // A head still arrives as a notice and is read.
    let (_, id) = device.new_note("after a quiet while");
    client.wake();
    until(20, "accepted", || device.pending() == 0).await;
    assert!(device.acked(id).is_some());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_byte_window_progress_and_cut_batches() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = registered(&hosted, &device).await;
    let log = device.log();
    // Three events with 4 MiB bodies: more than one batch's byte budget and
    // the edge's whole initial window. They are invalid submissions, so
    // they hold their positions with no effect.
    hosted.edge.freeze_reads(Some(device.progress().position));
    let mut positions = Vec::new();
    for n in 0..3u8 {
        let body = vec![n; 4 * 1024 * 1024];
        let commitment = BodyObject::new(body.clone()).unwrap().commitment();
        let mut envelope = vec![n; 1024];
        envelope[..32].copy_from_slice(&commitment.0);
        let event = OpaqueEvent::new(EventId([n + 1; 32]), envelope).unwrap();
        positions.push(hosted.edge.order(log, &event, Some(body), Route::Content));
    }
    hosted.edge.freeze_reads(None);
    client.wake();
    until(30, "all read", || {
        device.progress().position == *positions.last().unwrap()
    })
    .await;
    // A batch cut short by its byte budget commits with its own exact
    // receipt, from a read ending at its last event.
    let reads = hosted.edge.reads(log);
    assert!(
        reads.iter().any(|(first, last)| first == last),
        "prefix needs its own DATA receipt: {reads:?}"
    );
    assert_eq!(device.progress().stopped, None);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publishing_stopped_is_shown_and_keeps_work() {
    let hosted = Hosted::new();
    let device = Device::new();
    let mut started = registered(&hosted, &device).await;
    let (_, first) = device.new_note("published");
    started.0.wake();
    until(20, "accepted", || device.pending() == 0).await;
    // As a verified echo records when this device's own key signed other
    // bytes under one of its event ids.
    let raw = device.raw();
    raw.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    raw.execute(
        "INSERT INTO sync_alarm(kind,update_id,position) VALUES (1,?1,2)",
        [first],
    )
    .unwrap();
    let (writer, id) = device.new_note("kept, not published");
    started.0.wake();
    until(20, "publishing stopped", || {
        status(&mut started) == SyncStatus::PublishingStopped
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(device.package(id).is_none(), "nothing sealed");
    assert_eq!(device.pending(), 1);
    assert_eq!(device.inserted(writer.note, "kept, not published"), 1);
    started.0.shutdown().await;
}

/// The kept copy of the account change at `position`, once it was sent.
async fn kept_and_sent(hosted: &Arc<Hosted>, device: &Device, position: u64) -> BaseControl {
    let db = device.owner.shared_database(device.id).unwrap();
    let mut kept = None;
    until(20, "copy kept and sent", || {
        kept = db
            .lock()
            .unwrap()
            .pending_base_control(device.base.0)
            .unwrap()
            .filter(|k| k.account_position == position);
        kept.as_ref()
            .is_some_and(|k| hosted.edge.appends(device.log().id).contains(&k.descriptor))
    })
    .await;
    kept.unwrap()
}

fn outcome(device: &Device, position: u64) -> Option<Option<ControlOutcome>> {
    let db = device.owner.shared_database(device.id).unwrap();
    let db = db.lock().unwrap();
    db.base_control_outcome(device.base.0, position).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_account_event_is_refused_then_valid_progresses() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mut started = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "verified signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    // The account home orders a valid addition; the edge serves the
    // device a copy whose signature does not verify.
    let valid = mac.signer.add_device(test_keys(71));
    let mut forged = valid.clone();
    *forged.last_mut().unwrap() ^= 1;
    let reads = hosted.edge.reads(mac.account_log).len();
    let applies = mac.signer.apply_attempts.load(Ordering::SeqCst);
    hosted.edge.serve_account(mac.account_log, 4, &[forged]);
    hosted.edge.order_account(mac.account_log, &valid);
    started.0.wake();
    until(20, "unconfirmed substitution read twice", || {
        hosted.edge.reads(mac.account_log).len() >= reads + 2
    })
    .await;
    // The reader, not the owner, refuses bytes the home did not confirm.
    assert_eq!(mac.signer.apply_attempts.load(Ordering::SeqCst), applies);
    let db = mac.owner.shared_database(mac.id).unwrap();
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );
    assert_eq!(mac.signer.current_account().unwrap().head().position, 3);
    // Nothing applied and nothing latched: the device stays active.
    assert!(!mac.signer.account_stopped());
    assert!(mac.signer.applied.lock().unwrap().is_empty());
    assert_ne!(status(&mut started), SyncStatus::Stopped);
    assert_eq!(copied(&mac), 3);

    hosted.edge.serve_ordered(mac.account_log);
    started.0.wake();
    until(20, "copied", || copied(&mac) == 4).await;
    assert_eq!(mac.signer.applied.lock().unwrap().len(), 1);
    until(20, "synced", || status(&mut started) == SyncStatus::Synced).await;
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_signed_wrong_accepted_head_or_commitment_never_advances_state() {
    for bad_hash in [true, false] {
        let hosted = Hosted::new();
        let mac = Device::new();
        let (client, _) = registered(&hosted, &mac).await;
        let db = mac.owner.shared_database(mac.id).unwrap();
        until(20, "signup checkpoint", || {
            !mac.home_pending()
                && db
                    .lock()
                    .unwrap()
                    .account_outer_progress(mac.account_log.id, hosted.edge.root())
                    .unwrap()
                    .order
                    .position()
                    == 3
        })
        .await;
        client.shutdown().await;
        let prior = db.lock().unwrap().observed_account_floor().unwrap();
        let original = mac.signer.add_device(test_keys(71));
        hosted.edge.order_account(mac.account_log, &original);
        hosted.corrupt_accepted_account(mac.account_log, bad_hash);
        let applies = mac.signer.apply_attempts.load(Ordering::SeqCst);
        let (client, _) = mac.start(&hosted);
        until(20, "wrong accepted retried", || {
            hosted
                .edge
                .reads(mac.account_log)
                .iter()
                .filter(|(first, _)| *first == 4)
                .count()
                >= 2
        })
        .await;
        assert_eq!(mac.signer.apply_attempts.load(Ordering::SeqCst), applies);
        assert_eq!(
            db.lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position(),
            3
        );
        assert_eq!(db.lock().unwrap().observed_account_floor().unwrap(), prior);
        assert_eq!(mac.signer.current_account().unwrap().head().position, 3);
        client.shutdown().await;
        hosted.restore_account_confirmations();
        let (client, _) = mac.start(&hosted);
        until(20, "honest original applied", || {
            mac.signer.current_account().unwrap().head().position == 4
        })
        .await;
        client.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ahead_accepted_time_does_not_bless_earlier_account_page() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    client.shutdown().await;
    for original in mac.signer.signed_additions(65, hosted.edge.clock.now()) {
        hosted.edge.order_account(mac.account_log, &original);
    }
    let _ = hosted.confirmed_account(mac.account_log).await;
    hosted.edge.clock.advance(25_000);
    let accepted_at = hosted.edge.clock.now();
    hosted.omit_account_confirmation(mac.account_log, 68);
    let (client, _) = mac.start(&hosted);
    until(20, "first full page applied", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 67
    })
    .await;
    until(20, "missing later proof read", || {
        hosted
            .edge
            .reads(mac.account_log)
            .iter()
            .any(|(first, _)| *first == 68)
    })
    .await;
    assert_eq!(mac.signer.current_account().unwrap().head().position, 67);
    assert!(
        db.lock()
            .unwrap()
            .observed_account_floor()
            .unwrap()
            .is_none_or(|floor| floor < accepted_at)
    );
    client.shutdown().await;
    hosted.restore_account_confirmations();
    let (client, _) = mac.start(&hosted);
    until(20, "exact later page observed", || {
        db.lock()
            .unwrap()
            .observed_account_floor()
            .unwrap()
            .is_some_and(|floor| floor >= accepted_at)
    })
    .await;
    assert_eq!(mac.signer.current_account().unwrap().head().position, 68);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_head_ahead_of_full_page_observes_only_after_exact_later_match() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    client.shutdown().await;
    for original in mac.signer.signed_additions(65, hosted.edge.clock.now()) {
        hosted.edge.order_account(mac.account_log, &original);
    }
    assert_eq!(hosted.edge.head(mac.account_log).position, 68);
    let _ = hosted.confirmed_account(mac.account_log).await;
    hosted.edge.clock.advance(25_000);
    let accepted_at = hosted.edge.clock.now();
    let (client, _) = mac.start(&hosted);
    until(20, "later exact accepted", || {
        db.lock()
            .unwrap()
            .observed_account_floor()
            .unwrap()
            .is_some_and(|floor| floor >= accepted_at)
            && mac.signer.current_account().unwrap().head().position == 68
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 68
    })
    .await;
    assert_eq!(mac.signer.current_account().unwrap().head().position, 68);
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        68
    );
    let reads = hosted.edge.reads(mac.account_log);
    assert!(reads.iter().any(|(first, last)| *first == 4 && *last == 67));
    assert!(
        reads
            .iter()
            .any(|(first, last)| *first == 68 && *last == 131)
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_full_initial_proof_page_with_later_accepted_head_does_not_apply() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    client.shutdown().await;
    let creator = mac
        .signer
        .identity()
        .unwrap()
        .anchor
        .added_at(mac.signer.identity().unwrap().device);
    // Sixty-four genuine signed successors fill the first bounded follow
    // page. The challenged AcceptedHead at 67 remains valid while all 64
    // confirmations on that page are withheld.
    for original in mac.signer.signed_additions(64, hosted.edge.clock.now()) {
        hosted.edge.order_account(mac.account_log, &original);
    }
    assert_eq!(hosted.edge.head(mac.account_log).position, 67);
    hosted.omit_account_proof_range(mac.account_log, 4, 67);
    let applies = mac.signer.apply_attempts.load(Ordering::SeqCst);
    let (client, _) = mac.start(&hosted);
    until(20, "whole missing page retried", || {
        hosted
            .edge
            .reads(mac.account_log)
            .iter()
            .filter(|(first, last)| *first == 4 && *last == 67)
            .count()
            >= 2
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );
    assert_eq!(mac.signer.apply_attempts.load(Ordering::SeqCst), applies);
    assert_eq!(mac.signer.current_account().unwrap().head().position, 3);
    assert_eq!(
        mac.signer
            .identity()
            .unwrap()
            .anchor
            .added_at(mac.signer.identity().unwrap().device),
        creator
    );
    assert!(db.lock().unwrap().confirmation(4).unwrap().is_none());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_stored_historical_proof_never_falls_back_to_v1_copy() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    until(20, "signup copied", || {
        !mac.home_pending() && copied(&mac) == 3
    })
    .await;
    client.shutdown().await;
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    let original = mac.signer.add_device(test_keys(71));
    hosted.edge.order_account(mac.account_log, &original);
    let (client, _) = mac.start(&hosted);
    until(20, "account ahead", || {
        mac.signer.current_account().unwrap().head().position == 4
            && mac.signer.control_requests.load(Ordering::SeqCst) > 0
    })
    .await;
    client.shutdown().await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    let saved = db.lock().unwrap().confirmation(4).unwrap().unwrap();
    mac.raw()
        .execute("DELETE FROM account_confirmations WHERE position=4", [])
        .unwrap();
    assert!(db.lock().unwrap().confirmation(4).unwrap().is_none());
    let signatures = mac.signer.control_signatures.load(Ordering::SeqCst);
    mac.signer.approve_controls.store(true, Ordering::SeqCst);
    let (client, _) = mac.start(&hosted);
    let reads = hosted.edge.reads(mac.account_log).len();
    until(20, "missing proof retry", || {
        hosted.edge.reads(mac.account_log).len() >= reads + 2
    })
    .await;
    assert_eq!(copied(&mac), 3);
    assert!(
        db.lock()
            .unwrap()
            .pending_base_control(mac.base.0)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        mac.signer.control_signatures.load(Ordering::SeqCst),
        signatures
    );
    client.shutdown().await;
    mac.raw().execute("INSERT INTO account_confirmations(position,earliest_ms,latest_ms,confirmation) VALUES(4,?1,?2,?3)",
        rusqlite::params![i64::try_from(saved.earliest_ms).unwrap(), i64::try_from(saved.latest_ms).unwrap(), saved.bytes]).unwrap();
    let (client, _) = mac.start(&hosted);
    until(20, "exact proof copy resumes", || copied(&mac) == 4).await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lagging_base_copies_one_historical_v2_proof_not_the_current_head() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending() && copied(&mac) == 3
    })
    .await;
    client.shutdown().await;
    mac.signer.approve_controls.store(false, Ordering::SeqCst);
    let originals = mac.signer.signed_additions(2, hosted.edge.clock.now());
    for original in &originals {
        hosted.edge.order_account(mac.account_log, original);
    }
    let (client, _) = mac.start(&hosted);
    until(20, "account two ahead of base", || {
        mac.signer.current_account().unwrap().head().position == 5
            && mac.signer.control_requests.load(Ordering::SeqCst) > 0
    })
    .await;
    assert_eq!(copied(&mac), 3);
    let proof = db.lock().unwrap().confirmation(4).unwrap().unwrap().bytes;
    mac.signer.approve_controls.store(true, Ordering::SeqCst);
    client.wake();
    until(20, "historical fourth copied", || copied(&mac) >= 4).await;
    let rows = db
        .lock()
        .unwrap()
        .log_account_changes(bh_sync::permit::LogKind::Base as u8, mac.base.0)
        .unwrap();
    let first = bh_event::account_run::decode_copies(&rows[0]).unwrap();
    assert_eq!(first.len(), 2, "both entries in one approved run");
    assert_eq!(first[0].original, originals[0]);
    assert_eq!(first[1].original, originals[1]);
    assert_eq!(first[0].confirmation.as_deref(), Some(proof.as_slice()));
    let verified = bh_sync::evidence::OrderingConfirmation::decode(&proof).unwrap();
    let claim = verified
        .verify_for(&hosted.edge.root(), &originals[0], None)
        .unwrap();
    assert_eq!(claim.original_previous.position, 3);
    assert_eq!(
        claim.original_previous.hash.0,
        mac.signer.identity().unwrap().anchor.head().hash
    );
    assert_eq!(claim.original_head.position, 4);
    assert_ne!(
        claim.original_head.position,
        mac.signer.current_account().unwrap().head().position
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_initial_confirmation_does_not_advance_account_or_anchor() {
    let hosted = Hosted::new();
    let mac = Device::new();
    hosted.omit_account_confirmation(mac.account_log, 2);
    let db = mac.owner.shared_database(mac.id).unwrap();
    let (client, _) = mac.start(&hosted);
    until(20, "missing initial proof retried", || {
        hosted.edge.reads(mac.account_log).len() >= 2
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        0
    );
    assert!(db.lock().unwrap().confirmation(2).unwrap().is_none());
    assert_eq!(
        mac.signer
            .identity()
            .unwrap()
            .anchor
            .added_at(mac.signer.identity().unwrap().device),
        None
    );
    assert!(mac.home_pending());
    client.shutdown().await;
    hosted.restore_account_confirmations();
    let (client, _) = mac.start(&hosted);
    until(20, "honest signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    assert!(db.lock().unwrap().confirmation(2).unwrap().is_some());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_stored_confirmation_never_observes_or_checkpoints() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    client.shutdown().await;
    let original = mac.signer.add_device(test_keys(71));
    let position = hosted.edge.order_account(mac.account_log, &original);
    // Independently root-signed, but not the home-confirmed exact proof.
    let alternate = hosted.edge.account_confirmation(mac.account_log, position);
    let before = mac.signer.current_account().unwrap().head();
    mac.signer
        .apply_account_timed(before, vec![(original, Some(alternate))])
        .await
        .unwrap();
    let floor = db.lock().unwrap().observed_account_floor().unwrap();
    let reads = hosted.edge.reads(mac.account_log).len();
    let (client, _) = mac.start(&hosted);
    until(20, "conflicting proof retried", || {
        hosted.edge.reads(mac.account_log).len() >= reads + 2
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );
    assert_eq!(db.lock().unwrap().observed_account_floor().unwrap(), floor);
    assert_eq!(mac.signer.current_account().unwrap().head().position, 4);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_exact_head_establishes_removal_deadline_alert_after_restart() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    let target = test_keys(71).id();
    hosted
        .edge
        .order_account(mac.account_log, &mac.signer.add_device(test_keys(71)));
    client.wake();
    until(20, "addition verified", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    hosted
        .edge
        .order_account(mac.account_log, &mac.signer.request_removal(target));
    client.wake();
    until(20, "request verified", || {
        mac.signer.current_account().unwrap().head().position == 5
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 5
    })
    .await;
    let deadline = db
        .lock()
        .unwrap()
        .alerts(20)
        .unwrap()
        .into_iter()
        .find(|alert| {
            alert.kind == bh_storage::AlertKind::RemovalRequested && alert.position == Some(5)
        })
        .unwrap()
        .deadline_ms
        .unwrap();
    assert!(deadline > hosted.edge.clock.now());
    assert_eq!(
        deadline
            - db.lock()
                .unwrap()
                .confirmation(5)
                .unwrap()
                .unwrap()
                .latest_ms,
        bh_account::REMOVAL_WAIT_MS
    );
    client.shutdown().await;
    hosted
        .edge
        .clock
        .advance(deadline - hosted.edge.clock.now() + 1);
    let (client, _) = mac.start(&hosted);
    until(20, "exact-head deadline observed", || {
        db.lock().unwrap().alerts(20).unwrap().iter().any(|alert| {
            alert.kind == bh_storage::AlertKind::RemovalEffective && alert.position == Some(5)
        })
    })
    .await;
    assert_eq!(mac.signer.current_account().unwrap().head().position, 5);
    assert!(
        db.lock()
            .unwrap()
            .observed_account_floor()
            .unwrap()
            .unwrap()
            >= deadline
    );
    client.shutdown().await;
    let count = db
        .lock()
        .unwrap()
        .alerts(20)
        .unwrap()
        .iter()
        .filter(|a| a.kind == bh_storage::AlertKind::RemovalEffective)
        .count();
    let previous_floor = db
        .lock()
        .unwrap()
        .observed_account_floor()
        .unwrap()
        .unwrap();
    hosted.edge.clock.advance(25_000);
    let next_floor = hosted.edge.clock.now();
    assert!(next_floor > previous_floor);
    let (client, _) = mac.start(&hosted);
    until(20, "restarted exact observation", || {
        db.lock()
            .unwrap()
            .observed_account_floor()
            .unwrap()
            .unwrap()
            >= next_floor
    })
    .await;
    assert_eq!(
        db.lock()
            .unwrap()
            .alerts(20)
            .unwrap()
            .iter()
            .filter(|a| a.kind == bh_storage::AlertKind::RemovalEffective)
            .count(),
        count
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_exact_account_head_records_verified_observation() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "verified signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    let before = db.lock().unwrap().observed_account_floor().unwrap();
    hosted.edge.clock.advance(25_000);
    let observed_at = hosted.edge.clock.now();
    client.shutdown().await;
    let (client, _) = mac.start(&hosted);
    until(20, "exact accepted observation", || {
        db.lock()
            .unwrap()
            .observed_account_floor()
            .unwrap()
            .is_some_and(|floor| floor >= observed_at)
    })
    .await;
    assert_eq!(mac.signer.current_account().unwrap().head().position, 3);
    assert!(db.lock().unwrap().observed_account_floor().unwrap() > before);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_account_event_pauses_then_recovers() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mut started = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    let applies = mac.signer.apply_attempts.load(Ordering::SeqCst);
    let valid = mac.signer.add_device(test_keys(71));
    // A newer version of the account event format, after the 23-byte domain.
    let mut newer = valid.clone();
    newer[23..27].copy_from_slice(&[0, 3, 0, 3]);
    hosted.edge.serve_account(mac.account_log, 4, &[newer]);
    hosted.edge.order_account(mac.account_log, &valid);
    hosted.confirm_served_account(mac.account_log);
    started.0.wake();
    until(20, "unsupported", || {
        status(&mut started) == SyncStatus::Unsupported
    })
    .await;
    assert!(
        mac.signer.apply_attempts.load(Ordering::SeqCst) > applies,
        "root-confirmed unknown version reached the owner"
    );
    assert!(!mac.signer.account_stopped());
    assert!(mac.signer.applied.lock().unwrap().is_empty());
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );
    assert_eq!(mac.signer.current_account().unwrap().head().position, 3);

    // Readable history in its place: the pause ends.
    hosted.edge.serve_ordered(mac.account_log);
    hosted.confirm_ordered_account();
    started.0.wake();
    until(20, "copied", || copied(&mac) == 4).await;
    until(20, "synced", || status(&mut started) == SyncStatus::Synced).await;
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_account_fork_stops() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mut started = registered(&hosted, &mac).await;
    let _fold = Device::join(&mac, &hosted).await;
    until(20, "addition copied", || copied(&mac) == 4).await;
    let head = mac.signer.applied.lock().unwrap()[0];
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "addition checkpoint", || {
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 4
    })
    .await;
    // The mac's own control key signed a successor of another event at
    // position 4, and the edge serves it after the ordered one: history
    // contradicting what the mac verified.
    hosted
        .edge
        .serve_account(mac.account_log, 5, &[mac.signer.fork_successor()]);
    let next = mac.signer.add_device(test_keys(111));
    hosted.edge.order_account(mac.account_log, &next);
    hosted.confirm_served_account(mac.account_log);
    started.0.wake();
    until(20, "stopped", || {
        status(&mut started) == SyncStatus::Stopped
    })
    .await;
    assert!(mac.signer.account_stopped());
    assert_eq!(*mac.signer.applied.lock().unwrap(), vec![head]);
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        4
    );
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_bytes_with_the_kept_copys_nonce_are_not_its_commit() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mut started = registered(&hosted, &mac).await;
    let (_, note) = mac.new_note("a note");
    started.0.wake();
    until(20, "accepted", || mac.pending() == 0).await;
    let log = mac.log();
    // Every send of the copy is refused, so it stays kept.
    hosted.edge.refuse_next_event(Refusal::Predecessor);
    let _fold = Device::join(&mac, &hosted).await;
    let kept = kept_and_sent(&hosted, &mac, 4).await;
    // Different bytes can reuse the copy's nonce without reserving the
    // copy's route-derived ID or satisfying its pending outcome.
    let stored = mac.package(note).unwrap();
    let other = OpaqueEvent::new(
        OpaqueEvent::decode(&kept.descriptor).unwrap().nonce(),
        stored.descriptor.envelope().to_vec(),
    )
    .unwrap();
    let other_at = hosted
        .edge
        .order(log, &other, Some(stored.body.clone()), Route::Content);
    assert_eq!(
        other.nonce(),
        OpaqueEvent::decode(&kept.descriptor).unwrap().nonce()
    );
    assert_ne!(other.publication_id(Route::Content).0, kept.event_id);
    started.0.wake();
    until(20, "other bytes followed", || {
        mac.progress().position == other_at
    })
    .await;
    let sends = || {
        hosted
            .edge
            .appends(log.id)
            .iter()
            .filter(|a| **a == kept.descriptor)
            .count()
    };
    let sent = sends();
    started.0.wake();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    // Still kept and unsettled; a refusal can retry its exact stored bytes,
    // but a nonce collision must never cause a second control signature.
    assert_eq!(outcome(&mac, 4), Some(None));
    assert!(sends() >= sent);
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    assert_eq!(copied(&mac), 3);
    assert_ne!(status(&mut started), SyncStatus::Synced);
    started.0.shutdown().await;
    let prior_sends = sends();
    let (client, _) = mac.start(&hosted);
    until(20, "exact persisted copy retried", || sends() > prior_sends).await;
    let pending = mac
        .owner
        .shared_database(mac.id)
        .unwrap()
        .lock()
        .unwrap()
        .pending_base_control(mac.base.0)
        .unwrap()
        .unwrap();
    assert_eq!(pending.descriptor, kept.descriptor);
    assert_eq!(pending.body, kept.body);
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_device_copying_first_supersedes_the_kept_copy() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    fold_client.0.shutdown().await;
    let log = mac.log();
    // The mac's copy of the next change is refused every time it is sent.
    hosted.edge.refuse_next_event(Refusal::Predecessor);
    let _third = Device::join(&mac, &hosted).await;
    let kept = kept_and_sent(&hosted, &mac, 5).await;
    mac_client.0.shutdown().await;
    // Once the service lets the mac's permitted copy lapse, the fold
    // copies the same change first.
    hosted.edge.clock.advance(120_000);
    let fold_client = fold.start(&hosted);
    until(20, "fold copied", || copied(&fold) == 5).await;
    let mut mac_started = mac.start(&hosted);
    until(20, "superseded", || {
        outcome(&mac, 5) == Some(Some(ControlOutcome::Superseded))
    })
    .await;
    assert_eq!(copied(&mac), 5);
    assert!(
        hosted
            .edge
            .entries(log)
            .iter()
            .all(|(_, event)| event.publication_id(bh_sync::Route::Control).0 != kept.event_id)
    );
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 2);
    assert_eq!(fold.signer.control_signatures.load(Ordering::SeqCst), 1);
    until(20, "synced", || {
        status(&mut mac_started) == SyncStatus::Synced
    })
    .await;
    mac_started.0.shutdown().await;
    fold_client.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_signed_original_rejects_a_proof_with_another_predecessor() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    client.shutdown().await;
    hosted
        .edge
        .order_account(mac.account_log, &mac.signer.add_device(test_keys(71)));
    hosted.wrong_account_predecessor(mac.account_log, 4);
    let applies = mac.signer.apply_attempts.load(Ordering::SeqCst);
    let (client, _) = mac.start(&hosted);
    until(20, "wrong predecessor evidence handled", || {
        mac.signer.current_account().unwrap().head().position == 4
            || hosted
                .edge
                .reads(mac.account_log)
                .iter()
                .filter(|(first, _)| *first == 4)
                .count()
                >= 2
    })
    .await;
    assert_eq!(mac.signer.apply_attempts.load(Ordering::SeqCst), applies);
    assert_eq!(mac.signer.current_account().unwrap().head().position, 3);
    assert_eq!(
        db.lock()
            .unwrap()
            .account_outer_progress(mac.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position(),
        3
    );
    assert!(db.lock().unwrap().confirmation(4).unwrap().is_none());
    assert!(
        db.lock()
            .unwrap()
            .pending_base_control(mac.base.0)
            .unwrap()
            .is_none()
    );
    client.shutdown().await;
    hosted.restore_account_confirmations();
    let (client, _) = mac.start(&hosted);
    until(20, "honest proof accepted", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn later_page_observes_its_own_newer_accepted_head() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    client.shutdown().await;
    for original in mac.signer.signed_additions(65, hosted.edge.clock.now()) {
        hosted.edge.order_account(mac.account_log, &original);
    }
    let proof68 = hosted.confirmed_account(mac.account_log).await[67]
        .1
        .as_ref()
        .unwrap()
        .1
        .clone();
    hosted.edge.clock.advance(25_000);
    let new_time = hosted.edge.clock.now();
    let last = mac.signer.signed_additions(66, new_time).pop().unwrap();
    hosted.edge.order_account(mac.account_log, &last);
    hosted.first_account_page_claim(mac.account_log, 68, proof68);
    let (client, _) = mac.start(&hosted);
    until(20, "newer later-page observation", || {
        db.lock()
            .unwrap()
            .observed_account_floor()
            .unwrap()
            .is_some_and(|t| t >= new_time)
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 69
    })
    .await;
    assert_eq!(mac.signer.current_account().unwrap().head().position, 69);
    assert!(db.lock().unwrap().confirmation(69).unwrap().is_some());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn already_committed_challenged_head_is_observed_before_its_suffix() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = registered(&hosted, &mac).await;
    let db = mac.owner.shared_database(mac.id).unwrap();
    until(20, "signup checkpoint", || {
        !mac.home_pending()
            && db
                .lock()
                .unwrap()
                .account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position()
                == 3
    })
    .await;
    client.shutdown().await;
    let originals = mac.signer.signed_additions(2, hosted.edge.clock.now());
    hosted.edge.order_account(mac.account_log, &originals[0]);
    hosted.edge.clock.advance(25_000);
    let new_time = hosted.edge.clock.now();
    hosted.edge.order_account(mac.account_log, &originals[1]);
    let confirmed = hosted.confirmed_account(mac.account_log).await;
    let proof4 = confirmed[3].1.as_ref().unwrap().1.clone();
    let confirmation = bh_sync::evidence::OrderingConfirmation::decode(&proof4).unwrap();
    let claim = confirmation.claim();
    let inner = mac.signer.current_account().unwrap().head();
    mac.signer
        .apply_account_timed(
            inner,
            vec![(
                originals[0].clone(),
                Some((
                    bh_account::ConfirmedTime {
                        earliest_ms: claim.bounds.earliest_ms,
                        latest_ms: claim.bounds.latest_ms,
                    },
                    proof4.clone(),
                )),
            )],
        )
        .await
        .unwrap();
    let before = db.lock().unwrap().observed_account_floor().unwrap();
    hosted.matched_account_page_claim(mac.account_log, 4, proof4);
    let (client, _) = mac.start(&hosted);
    until(
        20,
        "committed challenged head observed before suffix",
        || {
            db.lock()
                .unwrap()
                .observed_account_floor()
                .unwrap()
                .is_some_and(|t| t >= new_time)
                && db
                    .lock()
                    .unwrap()
                    .account_outer_progress(mac.account_log.id, hosted.edge.root())
                    .unwrap()
                    .order
                    .position()
                    == 5
        },
    )
    .await;
    let (floor, outer) = {
        let mut db = db.lock().unwrap();
        (
            db.observed_account_floor().unwrap(),
            db.account_outer_progress(mac.account_log.id, hosted.edge.root())
                .unwrap()
                .order
                .position(),
        )
    };
    assert!(
        floor.is_some_and(|t| t >= new_time),
        "floor={floor:?}, outer={outer}, account={}",
        mac.signer.current_account().unwrap().head().position
    );
    assert!(db.lock().unwrap().observed_account_floor().unwrap() > before);
    assert_eq!(mac.signer.current_account().unwrap().head().position, 5);
    assert!(db.lock().unwrap().confirmation(5).unwrap().is_some());
    client.shutdown().await;
}

/// The judged control at `position` of the device's own base, if its
/// control feed has one.
fn judged(device: &Device, position: u64) -> Option<bh_device::control::ControlFact> {
    device
        .owner
        .control_fact(device.id, device.log(), position)
        .unwrap()
}

/// The metadata-only control feed judges a control the content cursor has
/// not reached, while content waits at a missing body before it; content
/// then passes the control only because the feed judged it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controls_advance_from_the_feed_while_content_waits() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    let (lost_note, lost) = fold.new_note("its body goes missing");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    let lost_at = fold.acked(lost).unwrap();
    let body = referenced_body(&fold.package(lost).unwrap().descriptor).unwrap();
    let bytes = hosted.edge.take_body(mac.log(), body).unwrap();
    // The fold adds a device and copies the addition into the base: a
    // control after the gap.
    let third = test_keys(91);
    hosted
        .edge
        .order_account(fold.account_log, &fold.signer.add_device(third.clone()));
    fold_client.0.wake();
    until(20, "fold copied the addition", || copied(&fold) == 5).await;
    let copy_at = hosted.edge.head(mac.log()).position;
    assert!(copy_at > lost_at);
    assert!(judged(&fold, copy_at).is_some_and(|f| f.accepted));

    let mut started = mac.start(&hosted);
    until(20, "the feed judged the copy", || {
        judged(&mac, copy_at).is_some_and(|f| f.accepted)
    })
    .await;
    until(20, "content waits at the gap", || {
        status(&mut started) == SyncStatus::HistoryMissing
    })
    .await;
    assert_eq!(mac.progress().position, lost_at - 1);
    let anchor = mac.signer.identity().unwrap().anchor;
    let view = mac.owner.control_view(mac.id, mac.log(), &anchor).unwrap();
    let third = bh_device::control::Author {
        account: mac.signer.identity_account(),
        device: third.id(),
    };
    assert_eq!(view.authorised_at(third, copy_at), Ok(true));
    assert_eq!(view.authorised_at(third, lost_at), Ok(false));

    hosted.edge.insert_body(mac.log(), bytes);
    started.0.wake();
    until(20, "content passed the judged control", || {
        mac.progress().position == copy_at
            && mac.inserted(lost_note.note, "its body goes missing") == 1
    })
    .await;
    assert_eq!(copied(&mac), 5);
    started.0.shutdown().await;
    fold_client.0.shutdown().await;
}

/// Content never passes a control the feed has not judged: with the
/// device's control reads refused, content stops just before the control,
/// and continues once the feed can read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_waits_at_a_control_the_feed_has_not_judged() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    let (_, before) = fold.new_note("before the control");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    let before_at = fold.acked(before).unwrap();
    hosted
        .edge
        .order_account(fold.account_log, &fold.signer.add_device(test_keys(93)));
    fold_client.0.wake();
    until(20, "fold copied the addition", || copied(&fold) == 5).await;
    let copy_at = hosted.edge.head(mac.log()).position;
    let (after_note, after) = fold.new_note("after the control");
    fold_client.0.wake();
    until(20, "fold accepted again", || fold.pending() == 0).await;
    assert!(fold.acked(after).unwrap() > copy_at);

    fold_client.0.shutdown().await;
    hosted
        .edge
        .refuse_control_reads
        .store(true, Ordering::SeqCst);
    let reads = hosted.edge.counts().read_controls;
    let started = mac.start(&hosted);
    until(20, "content up to the control", || {
        mac.progress().position == copy_at - 1
    })
    .await;
    assert_eq!(copy_at - 1, before_at);
    // The feed was asked again after a refusal, and content still waits.
    until(20, "control reads refused twice", || {
        hosted.edge.counts().read_controls >= reads + 2
    })
    .await;
    assert_eq!(mac.progress().position, copy_at - 1);
    assert!(judged(&mac, copy_at).is_none());
    assert_eq!(mac.inserted(after_note.note, "after the control"), 0);

    hosted
        .edge
        .refuse_control_reads
        .store(false, Ordering::SeqCst);
    started.0.wake();
    until(20, "content passed the judged control", || {
        mac.inserted(after_note.note, "after the control") == 1
    })
    .await;
    assert!(judged(&mac, copy_at).is_some_and(|f| f.accepted));
    started.0.shutdown().await;
}

/// Content at a position where the feed judged a control is a second head
/// there, each proven under the pinned root: the base stops, keeping what
/// verified before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_at_a_judged_controls_position_stops_the_base() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    let (lost_note, lost) = fold.new_note("its body goes missing");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    let lost_at = fold.acked(lost).unwrap();
    let body = referenced_body(&fold.package(lost).unwrap().descriptor).unwrap();
    let bytes = hosted.edge.take_body(mac.log(), body).unwrap();
    hosted
        .edge
        .order_account(fold.account_log, &fold.signer.add_device(test_keys(94)));
    fold_client.0.wake();
    until(20, "fold copied the addition", || copied(&fold) == 5).await;
    fold_client.0.shutdown().await;
    let copy_at = hosted.edge.head(mac.log()).position;
    assert!(copy_at > lost_at);

    // The feed judges the copy while content waits before the gap.
    let started = mac.start(&hosted);
    until(20, "the feed judged the copy", || {
        judged(&mac, copy_at).is_some_and(|f| f.accepted)
    })
    .await;
    until(20, "content waits at the gap", || {
        mac.progress().position == lost_at - 1
    })
    .await;
    started.0.shutdown().await;
    assert_eq!(hosted.edge.head(mac.log()).position, copy_at);

    // The service now orders content at the copy's position. Control reads
    // are refused: only content meets it.
    hosted.edge.fork(mac.log());
    hosted
        .edge
        .refuse_control_reads
        .store(true, Ordering::SeqCst);
    hosted.edge.insert_body(mac.log(), bytes);
    let mut started = mac.start(&hosted);
    until(20, "stopped", || {
        status(&mut started) == SyncStatus::Stopped
    })
    .await;
    let stopped = mac.progress();
    assert!(stopped.stopped.is_some());
    assert_eq!(stopped.position, copy_at - 1);
    assert_eq!(mac.inserted(lost_note.note, "its body goes missing"), 1);
    assert!(judged(&mac, copy_at).is_some_and(|f| f.accepted));
    started.0.shutdown().await;
}

/// Content that meets a control appended after the feed's endpoint scans
/// for it again in the same pass: it passes the control without ever
/// reporting missing history.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_after_the_feeds_endpoint_is_scanned_for_without_missing_history() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    hosted
        .edge
        .order_account(fold.account_log, &fold.signer.add_device(test_keys(95)));
    fold_client.0.wake();
    until(20, "fold copied the addition", || copied(&fold) == 5).await;
    let copy_at = hosted.edge.head(mac.log()).position;
    let (after_note, _) = fold.new_note("after the control");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    fold_client.0.shutdown().await;

    *hosted.edge.lag_next_control_read.lock().unwrap() = Some(copy_at - 1);
    let started = mac.start(&hosted);
    let mut statuses = started.1.clone();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorder = {
        let seen = seen.clone();
        tokio::spawn(async move {
            while statuses.changed().await.is_ok() {
                let status = *statuses.borrow_and_update();
                seen.lock().unwrap().push(status);
            }
        })
    };
    until(20, "content passed the control", || {
        mac.inserted(after_note.note, "after the control") == 1
    })
    .await;
    assert!(
        hosted.edge.lag_next_control_read.lock().unwrap().is_none(),
        "the lagging read was made"
    );
    assert!(judged(&mac, copy_at).is_some_and(|f| f.accepted));
    let seen = seen.lock().unwrap().clone();
    assert!(!seen.contains(&SyncStatus::HistoryMissing), "{seen:?}");
    recorder.abort();
    started.0.shutdown().await;
}

/// A control at a position the feed covered, where it judged none, is a
/// second history at that position, each proven under the pinned root: the
/// base stops, keeping what verified before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_where_the_feed_judged_none_stops_the_base() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    let (lost_note, lost) = fold.new_note("its body goes missing");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    let lost_at = fold.acked(lost).unwrap();
    let (_, between) = fold.new_note("between the gap and the control");
    fold_client.0.wake();
    until(20, "fold accepted again", || fold.pending() == 0).await;
    let between_at = fold.acked(between).unwrap();
    assert_eq!(between_at, lost_at + 1);
    let body = referenced_body(&fold.package(lost).unwrap().descriptor).unwrap();
    let bytes = hosted.edge.take_body(mac.log(), body).unwrap();
    hosted
        .edge
        .order_account(fold.account_log, &fold.signer.add_device(test_keys(96)));
    fold_client.0.wake();
    until(20, "fold copied the addition", || copied(&fold) == 5).await;
    fold_client.0.shutdown().await;
    let copy_at = hosted.edge.head(mac.log()).position;
    assert!(copy_at > between_at);

    // The feed judges through the copy while content waits at the gap.
    let started = mac.start(&hosted);
    until(20, "the feed judged the copy", || {
        judged(&mac, copy_at).is_some_and(|f| f.accepted)
    })
    .await;
    until(20, "content waits at the gap", || {
        mac.progress().position == lost_at - 1
    })
    .await;
    started.0.shutdown().await;
    assert!(judged(&mac, between_at).is_none());

    // The service now orders a control where the feed judged none. Control
    // reads are refused: only content meets it.
    hosted.edge.flip_route(mac.log(), between_at);
    hosted
        .edge
        .refuse_control_reads
        .store(true, Ordering::SeqCst);
    hosted.edge.insert_body(mac.log(), bytes);
    let mut started = mac.start(&hosted);
    until(20, "stopped", || {
        status(&mut started) == SyncStatus::Stopped
    })
    .await;
    let stopped = mac.progress();
    assert!(stopped.stopped.is_some());
    assert_eq!(stopped.position, lost_at);
    assert_eq!(mac.inserted(lost_note.note, "its body goes missing"), 1);
    assert!(judged(&mac, copy_at).is_some_and(|f| f.accepted));
    started.0.shutdown().await;
}

/// A kept copy whose seen claim fell further behind the log than the
/// services take is never sent again: the same account change is prepared
/// and signed afresh from the base's current state, and that copy orders.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kept_copy_older_than_the_seen_window_is_prepared_and_signed_again() {
    let hosted = Hosted::new();
    *hosted.edge.seen_window.lock().unwrap() = Some(3);
    let mac = Device::new();
    let started = registered(&hosted, &mac).await;
    let log = mac.log();
    // Every send of the first copy is refused, so it stays kept.
    hosted.edge.refuse_next_event(Refusal::Predecessor);
    let _fold = Device::join(&mac, &hosted).await;
    let kept = kept_and_sent(&hosted, &mac, 4).await;
    let metadata = mac.metadata_key();
    let seen_of = |descriptor: &[u8]| {
        bh_event::sealed_seen(
            &OpaqueEvent::decode(descriptor).unwrap(),
            metadata.expose(),
            mac.base,
        )
        .unwrap()
        .position
    };
    let kept_seen = seen_of(&kept.descriptor);
    // The log moves on past the window, and the service lets the first
    // copy's permit lapse, as it has long before a copy falls this far
    // behind.
    for note in 0..4 {
        mac.remote_note(&hosted, [80 + note; 32], b"later");
    }
    hosted.edge.clock.advance(120_000);
    started.0.wake();
    until(20, "the change copied afresh", || copied(&mac) == 4).await;
    let entries = hosted.edge.entries(log);
    assert!(
        entries
            .iter()
            .all(|(_, event)| event.publication_id(Route::Control).0 != kept.event_id),
        "the stale copy never ordered"
    );
    let (ordered, copy) = entries
        .iter()
        .rev()
        .find(|(ordered, _)| ordered.route() == Route::Control)
        .unwrap();
    let seen = seen_of(&copy.encode());
    assert!(seen > kept_seen + 3);
    assert!(ordered.head().position - seen <= 3, "within the window");
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 2);
    // The copier settles the fresh copy once it sees it ordered.
    until(20, "the fresh copy settled the change", || {
        started.0.wake();
        outcome(&mac, 4) == Some(Some(ControlOutcome::Committed))
    })
    .await;
    started.0.shutdown().await;
}

/// The control feed reads on from its own cursor, a control it judged,
/// never from the content cursor: here content waits at a note between
/// controls while the feed reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_reads_go_on_from_the_feeds_own_cursor() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    mac_client.0.shutdown().await;
    let (_, before) = fold.new_note("before the gap");
    let (lost_note, lost) = fold.new_note("its body goes missing");
    fold_client.0.wake();
    until(20, "fold accepted", || fold.pending() == 0).await;
    let (before_at, lost_at) = (fold.acked(before).unwrap(), fold.acked(lost).unwrap());
    assert!(before_at < lost_at);
    let body = referenced_body(&fold.package(lost).unwrap().descriptor).unwrap();
    let bytes = hosted.edge.take_body(mac.log(), body).unwrap();
    hosted
        .edge
        .order_account(fold.account_log, &fold.signer.add_device(test_keys(98)));
    fold_client.0.wake();
    until(20, "fold copied the addition", || copied(&fold) == 5).await;
    fold_client.0.shutdown().await;
    let copy_at = hosted.edge.head(mac.log()).position;
    hosted.edge.control_reads.lock().unwrap().clear();

    let started = mac.start(&hosted);
    until(20, "content waits at the gap, the feed past it", || {
        mac.progress().position == lost_at - 1 && judged(&mac, copy_at).is_some()
    })
    .await;
    let reads = hosted.edge.control_reads.lock().unwrap().clone();
    // Read again while content waits: from the feed's cursor at the copy.
    until(20, "the feed read again", || {
        started.0.wake();
        hosted.edge.control_reads.lock().unwrap().len() > reads.len()
    })
    .await;
    assert!(
        judged(&mac, lost_at - 1).is_none(),
        "content waits between controls"
    );
    let reads = hosted.edge.control_reads.lock().unwrap().clone();
    assert!(reads.iter().any(|(_, after)| *after == copy_at));
    for (log, after) in reads {
        assert_eq!(log, mac.log());
        assert!(
            judged(&mac, after).is_some(),
            "a control read after {after}, which is no judged control"
        );
    }
    hosted.edge.insert_body(mac.log(), bytes);
    until(20, "content passed the gap", || {
        started.0.wake();
        mac.inserted(lost_note.note, "its body goes missing") == 1
    })
    .await;
    started.0.shutdown().await;
}
