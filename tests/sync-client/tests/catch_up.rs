//! A new account's signup history exists only on its first device. Before
//! its own base is registered, the client publishes what the account log
//! lacks. Public ordering alone must not complete private home delivery.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::journal::AccountJournal;
use bh_authz::proto::account_log_wrap;
use std::time::Duration;
use support::{
    device::{Device, until},
    fake::{Hook, Hosted},
};

fn wrapped(device: &Device) -> Vec<Vec<u8>> {
    device
        .originals
        .iter()
        .map(|o| account_log_wrap(o, None).unwrap().encode())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_account_catches_up_then_registers() {
    let hosted = Hosted::new();
    let device = Device::new();
    assert!(hosted.edge.entries(device.account_log).is_empty());
    let (client, _) = device.start(&hosted);
    until(20, "registered", || {
        device.registered() && device.progress().position == 1
    })
    .await;
    let ordered: Vec<_> = hosted
        .edge
        .entries(device.account_log)
        .into_iter()
        .map(|(_, event)| event.encode())
        .collect();
    assert_eq!(ordered, wrapped(&device), "the signup history, in order");
    assert_eq!(hosted.edge.entries(device.log()).len(), 1);
    let (_, id) = device.new_note("first");
    client.wake();
    until(20, "acked", || device.acked(id).is_some()).await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_home_follow_verifies_outer_prefix_even_when_inner_signup_is_ahead() {
    let hosted = Hosted::new();
    let device = Device::new();
    let database = device.owner.shared_database(device.id).unwrap();
    assert_eq!(
        database
            .lock()
            .unwrap()
            .account_state()
            .unwrap()
            .unwrap()
            .head_position,
        3
    );
    let (client, _) = device.start(&hosted);
    // Home setup reads the three-event prefix as 1..=3, possibly more
    // than once. Identify the follower by its 64-position page instead of
    // depending on the relative scheduling of those setup reads.
    let follower_page = || {
        hosted
            .edge
            .reads(device.account_log)
            .into_iter()
            .find(|(first, last)| last.checked_sub(*first) == Some(63))
    };
    until(20, "home follower batch", || follower_page().is_some()).await;
    assert_eq!(
        follower_page().unwrap().0,
        1,
        "an uncheckpointed outer log must start at EMPTY, not the inner head"
    );
    until(20, "durable outer prefix", || {
        database
            .lock()
            .unwrap()
            .account_outer_progress(device.account_log.id, hosted.edge.root())
            .unwrap()
            .order
            .position()
            == 3
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catch_up_resumes_after_lost_answer() {
    let hosted = Hosted::new();
    let device = Device::new();
    // The genesis is ordered on the account log, and its answer lost.
    hosted
        .edge
        .hook(Hook::DropAfterAccountAppend { then_down: false });
    let (client, _) = device.start(&hosted);
    until(20, "registered", || device.registered()).await;
    assert_eq!(hosted.edge.hooks_left(), 0);
    let expected = wrapped(&device);
    let ordered: Vec<_> = hosted
        .edge
        .entries(device.account_log)
        .into_iter()
        .map(|(_, event)| event.encode())
        .collect();
    assert_eq!(ordered, expected, "each event ordered once");
    // Every account append sent was one of the exact signup events.
    let sent = hosted.edge.appends(device.account_log.id);
    assert!(sent.len() >= expected.len());
    assert!(sent.iter().all(|event| expected.contains(event)));
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_prefix_without_private_ack_keeps_home_pending() {
    let hosted = Hosted::new();
    let device = Device::new();
    assert!(device.home_pending());

    let database = device.owner.shared_database(device.id).unwrap();
    let bootstrap = database.lock().unwrap().initial_bootstrap().unwrap();
    assert!(bootstrap.is_some());
    let journal = bh_account::storage::DeviceJournal::from_shared(database.clone());
    let pending = journal.pending_setup().unwrap().unwrap();
    // The home never answers that it stored the private objects.
    hosted
        .edge
        .home_down
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // Nothing is confirmed while the account log cannot be read.
    hosted.go_down();
    let (client, _) = device.start(&hosted);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(device.home_pending());
    assert!(device.signer.home_ordered.lock().unwrap().is_empty());

    hosted.come_up();
    client.wake();
    until(20, "registered", || device.registered()).await;
    assert!(
        device.home_pending(),
        "private objects have not been acknowledged"
    );
    assert!(device.signer.home_ordered.lock().unwrap().is_empty());
    assert_eq!(hosted.edge.entries(device.account_log).len(), 3);
    assert!(database.lock().unwrap().initial_bootstrap().unwrap() == bootstrap);
    let after = journal.pending_setup().unwrap().unwrap();
    assert_eq!(after.version, pending.version);
    assert_eq!(after.stage, pending.stage);
    assert_eq!(after.kit_saved, pending.kit_saved);
    assert_eq!(after.blob, pending.blob);
    client.shutdown().await;
}
