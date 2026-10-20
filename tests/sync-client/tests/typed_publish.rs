//! Typed work through the same publish lane note work uses: one sealed event
//! per pending mutation, its exact bytes on every retry, an Ack that records a
//! position only, and one local commit order across both kinds.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_data::{AppId, mutation::ops::Operation};
use bh_storage::sync_state::PackageOutcome;
use bh_sync_client::SyncStatus;
use support::{
    device::{Device, until},
    fake::{Hook, Hosted, Seen},
};

fn setup() -> (std::sync::Arc<Hosted>, Device) {
    (Hosted::new(), Device::new())
}

/// Started, with the own base registered and its genesis applied.
async fn registered(
    hosted: &std::sync::Arc<Hosted>,
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

fn app(seed: u8, name: &str) -> Operation {
    Operation::DefineApp {
        app: AppId([seed; 32]),
        name: name.to_owned(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_work_publishes_its_exact_bytes_and_an_ack_accepts_nothing() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, mut status) = registered(&hosted, &device).await;
    // The echo is held back: only this device's own publish path can move.
    hosted.edge.freeze_reads(Some(1));
    let (mutation, package) = device.typed_submit(app(3, "Memos"));
    client.wake();
    until(20, "typed ack", || device.typed_acked(package).is_some()).await;
    let stored = device.typed_package(package).expect("sealed");
    let at = device.typed_acked(package).unwrap();
    // Ordered exactly as this device sealed it, at the acked position.
    let (ordered, event) = &hosted.edge.entries(log)[at as usize - 1];
    assert_eq!(event.encode(), stored.descriptor.encode());
    assert_eq!(ordered.event_id(), stored.event_id);
    assert!(hosted.edge.stages(log.id).contains(&stored.body));
    // An Ack is not acceptance: the saved work is still pending there, and
    // the status counts typed work like unsent note work.
    assert_eq!(device.typed_state(mutation).as_deref(), Some("pending"));
    assert_eq!(
        device.typed_progress(package).unwrap().outcome,
        Some(PackageOutcome::Acked)
    );
    until(20, "pending typed work shows", || {
        matches!(
            *status.borrow_and_update(),
            SyncStatus::Syncing { pending: 1 }
        )
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_ack_retries_the_same_typed_bytes() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.freeze_reads(Some(1));
    hosted.edge.hook(Hook::DropAfterAppend { then_down: false });
    let (_, package) = device.typed_submit(app(4, "Memos"));
    client.wake();
    until(20, "acked", || device.typed_acked(package).is_some()).await;
    let stored = device.typed_package(package).expect("sealed");
    let appends = hosted.edge.appends(log.id);
    assert_eq!(appends.len(), 3, "the genesis, then the same event twice");
    assert!(
        appends[1..]
            .iter()
            .all(|a| *a == stored.descriptor.encode())
    );
    assert_eq!(
        hosted
            .edge
            .stages(log.id)
            .iter()
            .filter(|body| **body == stored.body)
            .count(),
        2
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn note_and_typed_work_publish_in_one_local_commit_order() {
    let (hosted, device) = setup();
    let log = device.log();
    // Work queued before the client starts is a backlog: no quiet period.
    let (mut note_a, a) = device.new_note("a1");
    let (_, typed_one) = device.typed_submit(app(5, "One"));
    let (_, b) = device.new_note("b1");
    let (_, typed_two) = device.typed_submit(app(6, "Two"));
    let a2 = device.append(&mut note_a, "a2");
    let (client, _) = registered(&hosted, &device).await;
    client.wake();
    until(20, "everything acked", || {
        device.typed_acked(typed_one).is_some()
            && device.typed_acked(typed_two).is_some()
            && device.acked(a2).is_some()
            && device.acked(b).is_some()
    })
    .await;
    // The note's whole pending run travels in one package, at its first
    // unsent update's place: a1's package, then typed one, then b1's
    // package, then typed two.
    let expected = [
        device
            .package(a)
            .expect("note a sealed")
            .descriptor
            .encode(),
        device
            .typed_package(typed_one)
            .expect("typed one sealed")
            .descriptor
            .encode(),
        device
            .package(b)
            .expect("note b sealed")
            .descriptor
            .encode(),
        device
            .typed_package(typed_two)
            .expect("typed two sealed")
            .descriptor
            .encode(),
    ];
    let appends: Vec<Vec<u8>> = hosted.edge.appends(log.id).into_iter().skip(1).collect();
    assert_eq!(
        appends, expected,
        "one local commit order across both kinds"
    );
    // One ordered event each, in the same order.
    let positions: Vec<usize> = expected
        .iter()
        .map(|event| {
            hosted
                .edge
                .entries(log)
                .iter()
                .position(|(_, ordered)| ordered.encode() == *event)
                .expect("ordered")
        })
        .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]));
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_round_never_pipelines_two_typed_packages_from_one_scope() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.freeze_reads(Some(1));
    let held = hosted.edge.hold_next_valid_publish_reply();
    let (_, first) = device.typed_submit(app(21, "First"));
    let (_, second) = device.typed_submit(app(22, "Second"));
    client.wake();
    held.arrived.await.unwrap();
    assert!(
        device.typed_package(second).is_none(),
        "no second package in the same round"
    );
    assert_eq!(
        hosted.edge.entries(log).len(),
        2,
        "genesis and first typed event only"
    );
    held.release.send(()).unwrap();
    until(20, "first typed ack", || {
        device.typed_acked(first).is_some()
    })
    .await;
    let first_at = device.typed_acked(first).unwrap();
    until(20, "second typed ack", || {
        device.typed_acked(second).is_some()
    })
    .await;
    let second_at = device.typed_acked(second).unwrap();
    assert!(first_at < second_at);
    let entries = hosted.edge.entries(log);
    assert_eq!(
        entries[first_at as usize - 1].1.id(),
        device.typed_package(first).unwrap().event_id
    );
    assert_eq!(
        entries[second_at as usize - 1].1.id(),
        device.typed_package(second).unwrap().event_id
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiting_typed_work_publishes_before_the_next_save_in_its_scope() {
    let (hosted, device) = setup();
    let log = device.log();
    let (mutation, package) = device.typed_submit(app(7, "Waiting"));
    device
        .raw()
        .execute("UPDATE data_pending SET state='waiting'", [])
        .unwrap();
    let (_, next) = device.typed_submit(app(8, "Next"));
    let (client, _) = registered(&hosted, &device).await;
    client.wake();
    until(20, "waiting typed ack", || {
        device.typed_acked(package).is_some()
    })
    .await;
    until(20, "next typed ack", || device.typed_acked(next).is_some()).await;
    assert!(device.typed_acked(package) < device.typed_acked(next));
    // The receive lane may already have applied the verified echo, which
    // retires the saved work; until then it stays waiting.
    let state = device.typed_state(mutation);
    assert!(
        matches!(state.as_deref(), Some("waiting") | None),
        "{state:?}"
    );
    if state.is_none() {
        assert_eq!(
            device.typed_progress(package).unwrap().outcome,
            Some(PackageOutcome::Accepted)
        );
    }
    let entries = hosted.edge.entries(log);
    assert_eq!(
        entries[device.typed_acked(package).unwrap() as usize - 1]
            .1
            .id(),
        device.typed_package(package).unwrap().event_id
    );
    assert_eq!(
        entries[device.typed_acked(next).unwrap() as usize - 1]
            .1
            .id(),
        device.typed_package(next).unwrap().event_id
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_note_that_cannot_be_sealed_does_not_hold_back_typed_work() {
    let (hosted, device) = setup();
    let (mut stuck, _) = device.new_note("stuck");
    // Old local work with no writer declaration cannot be sealed.
    let stuck_id = device.append(&mut stuck, "no declaration");
    device
        .raw()
        .execute(
            "DELETE FROM note_update_writer WHERE update_id=?1",
            [stuck_id],
        )
        .unwrap();
    let (_, package) = device.typed_submit(app(8, "Typed carries on"));
    let (client, _) = device.start(&hosted);
    until(20, "typed acked", || device.typed_acked(package).is_some()).await;
    assert!(
        device.package(stuck_id).is_none(),
        "the note is never sealed"
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_work_for_another_audience_waits_alone() {
    let (hosted, device) = setup();
    let (client, mut status) = registered(&hosted, &device).await;
    hosted.edge.freeze_reads(Some(1));
    let (_, package) = device.typed_submit_scoped([7; 32], app(9, "Elsewhere"));
    client.wake();
    // A note saved after the bad scope must not wait for lane-wide authorization.
    let (_, note) = device.new_note("healthy note");
    client.wake();
    until(20, "later note acked", || device.acked(note).is_some()).await;
    assert!(device.typed_package(package).is_none(), "never sealed");
    assert_ne!(
        *status.borrow_and_update(),
        SyncStatus::WaitingAuthorization
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_typed_publishing_stop_stops_every_package() {
    let (hosted, device) = setup();
    let (client, mut status) = registered(&hosted, &device).await;
    hosted.go_down();
    let (_, package) = device.typed_submit(app(10, "Stopped"));
    client.wake();
    until(20, "sealed offline", || {
        device.typed_package(package).is_some()
    })
    .await;
    let stored = device.typed_package(package).unwrap();
    // The verified echo reports this device's own key authored other bytes
    // under its event id, which stops all publishing in this container.
    let progress = device.progress();
    let ordered = bh_sync::Commitment::order(
        bh_sync::BaseId(device.base.0),
        bh_sync::Head {
            position: progress.position,
            hash: bh_sync::Digest(progress.head_hash),
        },
        &stored.descriptor,
        bh_sync::Route::Content,
    )
    .unwrap();
    let echoed = {
        let db = device.owner.shared_database(device.id).unwrap();
        let mut db = db.lock().unwrap();
        db.record_typed_echo(
            device.base.0,
            &bh_storage::TypedEcho {
                event_id: stored.event_id.0,
                ordered,
                outcome: Some(PackageOutcome::Refused(3)),
                publishing_stopped: true,
            },
        )
        .unwrap()
    };
    assert_eq!(echoed, Some(package));
    hosted.come_up();
    client.wake();
    until(20, "publishing stopped", || {
        *status.borrow_and_update() == SyncStatus::PublishingStopped
    })
    .await;
    // Nothing more can be published, not even a healthy note's work: the
    // store itself refuses to seal a package while publishing is stopped.
    let (_, note) = device.new_note("afterwards");
    {
        let db = device.owner.shared_database(device.id).unwrap();
        let db = db.lock().unwrap();
        assert!(matches!(
            db.prepare_note_package(note),
            Err(bh_storage::StoreError::PublishingStopped)
        ));
    }
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_typed_package_survives_a_restart_between_ack_and_echo() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, _) = registered(&hosted, &device).await;
    hosted.edge.freeze_reads(Some(1));
    let (mutation, package) = device.typed_submit(app(11, "Restart"));
    client.wake();
    until(20, "acked", || device.typed_acked(package).is_some()).await;
    let stored = device.typed_package(package).unwrap();
    client.shutdown().await;
    drop(client);
    // A real exit stops the lanes' tasks; wait for them to release the owner
    // rather than assume it.
    until(20, "lanes ended", || {
        std::sync::Arc::strong_count(&device.owner) == 1
            && std::sync::Arc::strong_count(&device.signer) == 1
    })
    .await;
    let device = device.restart();
    // The exact bytes, the Ack and the saved work are all still there.
    let again = device.typed_package(package).expect("kept");
    assert_eq!(again.descriptor.encode(), stored.descriptor.encode());
    assert_eq!(again.body, stored.body);
    assert_eq!(again.ack.unwrap().encode(), stored.ack.unwrap().encode());
    assert_eq!(device.typed_state(mutation).as_deref(), Some("pending"));
    // Not republished: an acknowledged package is no candidate, and nothing
    // follows it.
    {
        let db = device.owner.shared_database(device.id).unwrap();
        let db = db.lock().unwrap();
        assert!(
            db.outbox_candidates(bh_storage::OutboxOrder::START, None, 16)
                .unwrap()
                .is_empty()
        );
    }
    hosted.edge.freeze_reads(None);
    let (client, mut status) = device.start(&hosted);
    client.wake();
    until(20, "verified typed echo", || {
        device.progress().position >= 2
            && device.typed_progress(package).unwrap().outcome == Some(PackageOutcome::Accepted)
    })
    .await;
    assert_eq!(device.typed_state(mutation), None);
    assert_eq!(hosted.edge.appends(log.id).len(), 2);
    until(20, "typed work settled", || {
        *status.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_typed_package_is_never_resealed_when_the_epoch_closes() {
    let (hosted, device) = setup();
    let log = device.log();
    let (client, mut status) = registered(&hosted, &device).await;
    hosted.edge.freeze_reads(Some(1));
    hosted.edge.close_epoch(log);
    let (_, package) = device.typed_submit(app(12, "Closed epoch"));
    client.wake();
    until(20, "sealed, waiting for authorization", || {
        device.typed_package(package).is_some()
            && *status.borrow_and_update() == SyncStatus::WaitingAuthorization
    })
    .await;
    let stored = device.typed_package(package).unwrap();
    until(20, "refused", || {
        hosted.edge.seen().contains(&Seen::Refused {
            reason: bh_sync::wire::Refusal::Epoch,
        })
    })
    .await;
    let again = device.typed_package(package).unwrap();
    assert_eq!(again.descriptor.encode(), stored.descriptor.encode());
    assert_eq!(again.body, stored.body);
    assert_eq!(device.typed_acked(package), None);
    assert_eq!(hosted.edge.entries(log).len(), 1);
    client.shutdown().await;
}
