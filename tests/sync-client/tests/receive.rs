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
use bh_sync::{BodyObject, EventId, OpaqueEvent, Route, referenced_body, wire::Refusal};
use bh_sync_client::{Client, Signer, SyncStatus};
use std::sync::{Arc, atomic::Ordering};
use support::{
    device::{Device, test_keys, until},
    fake::{Hook, Hosted},
};
use tokio::sync::watch;

type Started = (Client, watch::Receiver<SyncStatus>);

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
    let fold = Device::join(&mac, hosted);
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
async fn ack_before_echo_and_rejected_own_keep_work() {
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

    // This device's exact package, ordered where it is an invalid
    // submission: rejected, its work kept and shown, never resent once
    // judged. The publisher does not wait for the receiver, so before the
    // echo is read it may send the bytes, on the note's own alarm backoff:
    // each is refused as a conflict and changes nothing.
    hosted.go_down();
    let second = device.append(&mut writer, "rejected");
    started.0.wake();
    until(20, "sealed", || device.package(second).is_some()).await;
    let stored = device.package(second).unwrap();
    hosted.edge.order(
        log,
        &stored.descriptor,
        Some(stored.body.clone()),
        Route::Control,
    );
    hosted.come_up();
    started.0.wake();
    let judged = || {
        device
            .owner
            .unaccepted(device.id, device.key(writer.note))
            .unwrap()
            .first()
            .map(|u| u.state)
    };
    until(20, "rejected from its echo", || {
        judged() == Some(Unaccepted::Rejected)
    })
    .await;
    until(20, "not accepted", || {
        status(&mut started) == SyncStatus::NotAccepted { notes: 1 }
    })
    .await;
    let state = device
        .owner
        .unaccepted(device.id, device.key(writer.note))
        .unwrap();
    assert_eq!(state.len(), 1);
    assert_eq!(device.inserted(writer.note, "rejected"), 1);
    let sent = |hosted: &Hosted| {
        hosted
            .edge
            .appends(log.id)
            .iter()
            .filter(|a| **a == stored.descriptor.encode())
            .count()
    };
    let before = sent(&hosted);
    started.0.wake();
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert_eq!(sent(&hosted), before, "never resent once judged");
    assert_eq!(status(&mut started), SyncStatus::NotAccepted { notes: 1 });
    started.0.shutdown().await;
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
    let _fold = Device::join(&mac, &hosted);
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
    // The fold is in the account, not yet in the base's copy of it.
    let fold = Device::join(&mac, &hosted);
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
    let _fold = Device::join(&mac, &hosted);
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
    let _fold = Device::join(&mac, &hosted);
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
    hosted.restart_service_empty();
    let signatures = mac.signer.control_signatures.load(Ordering::SeqCst);
    let _third = Device::join(&mac, &hosted);
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
        copied(&mac) == known + 1
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
    // which closes the base's content epoch.
    let removal = fold.signer.remove_self();
    hosted.edge.order_account(mac.account_log, &removal);
    until(20, "removal copied", || copied(&mac) == 5).await;
    assert_eq!(mac.progress().epoch_id, None);
    let (writer, id) = mac.new_note("kept while closed");
    mac_started.0.wake();
    until(20, "waiting for authorization", || {
        status(&mut mac_started) == SyncStatus::WaitingAuthorization
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(mac.acked(id), None);
    assert_eq!(mac.pending(), 1);
    assert_eq!(mac.inserted(writer.note, "kept while closed"), 1);
    assert_eq!(status(&mut mac_started), SyncStatus::WaitingAuthorization);
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
    // The account home orders a valid addition; the edge serves the
    // device a copy whose signature does not verify.
    let valid = mac.signer.add_device(test_keys(71));
    let mut forged = valid.clone();
    *forged.last_mut().unwrap() ^= 1;
    hosted.edge.serve_account(mac.account_log, 4, &[forged]);
    hosted.edge.order_account(mac.account_log, &valid);
    started.0.wake();
    until(20, "refused twice", || {
        mac.signer.apply_attempts.load(Ordering::SeqCst) >= 2
    })
    .await;
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
async fn unsupported_account_event_pauses_then_recovers() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mut started = registered(&hosted, &mac).await;
    let valid = mac.signer.add_device(test_keys(71));
    // A newer version of the account event format, after the 23-byte domain.
    let mut newer = valid.clone();
    newer[23..27].copy_from_slice(&[0, 2, 0, 2]);
    hosted.edge.serve_account(mac.account_log, 4, &[newer]);
    hosted.edge.order_account(mac.account_log, &valid);
    started.0.wake();
    until(20, "unsupported", || {
        status(&mut started) == SyncStatus::Unsupported
    })
    .await;
    assert!(!mac.signer.account_stopped());
    assert!(mac.signer.applied.lock().unwrap().is_empty());

    // Readable history in its place: the pause ends.
    hosted.edge.serve_ordered(mac.account_log);
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
    let _fold = Device::join(&mac, &hosted);
    until(20, "addition copied", || copied(&mac) == 4).await;
    let head = mac.signer.applied.lock().unwrap()[0];
    // The mac's own control key signed a successor of another event at
    // position 4, and the edge serves it after the ordered one: history
    // contradicting what the mac verified.
    hosted
        .edge
        .serve_account(mac.account_log, 5, &[mac.signer.fork_successor()]);
    let next = mac.signer.add_device(test_keys(111));
    hosted.edge.order_account(mac.account_log, &next);
    started.0.wake();
    until(20, "stopped", || {
        status(&mut started) == SyncStatus::Stopped
    })
    .await;
    assert!(mac.signer.account_stopped());
    assert_eq!(*mac.signer.applied.lock().unwrap(), vec![head]);
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_bytes_under_the_kept_copy_id_are_not_a_commit() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let mut started = registered(&hosted, &mac).await;
    let (_, note) = mac.new_note("a note");
    started.0.wake();
    until(20, "accepted", || mac.pending() == 0).await;
    let log = mac.log();
    // Every send of the copy is refused, so it stays kept.
    hosted.edge.refuse_next_event(Refusal::Predecessor);
    let _fold = Device::join(&mac, &hosted);
    let kept = kept_and_sent(&hosted, &mac, 4).await;
    // Other bytes ordered under the kept copy's id: an ordered original
    // that is not this copy and has no effect.
    let stored = mac.package(note).unwrap();
    let other = OpaqueEvent::new(
        EventId(kept.event_id),
        stored.descriptor.envelope().to_vec(),
    )
    .unwrap();
    let other_at = hosted
        .edge
        .order(log, &other, Some(stored.body.clone()), Route::Content);
    started.0.wake();
    until(20, "not accepted", || {
        status(&mut started) == SyncStatus::ControlNotAccepted
    })
    .await;
    assert_eq!(mac.progress().position, other_at);
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
    // Still kept and unsettled, never sent again or signed again.
    assert_eq!(outcome(&mac, 4), Some(None));
    assert_eq!(sends(), sent);
    assert_eq!(mac.signer.control_signatures.load(Ordering::SeqCst), 1);
    assert_eq!(copied(&mac), 3);
    assert_eq!(status(&mut started), SyncStatus::ControlNotAccepted);
    started.0.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_device_copying_first_supersedes_the_kept_copy() {
    let hosted = Hosted::new();
    let (mac, mac_client, fold, fold_client) = two(&hosted).await;
    fold_client.0.shutdown().await;
    let log = mac.log();
    // The mac's copy of the next change is refused every time it is sent.
    hosted.edge.refuse_next_event(Refusal::Predecessor);
    let _third = Device::join(&mac, &hosted);
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
            .all(|(_, event)| event.id().0 != kept.event_id)
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
