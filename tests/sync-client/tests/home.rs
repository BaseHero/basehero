//! A first device's setup completes at its account home only once the
//! account log holds its exact signup prefix and the service answers that the
//! home durably stored exactly the three private objects signup retained.
//! Until then setup stays pending and the same bytes are sent again.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_sync::Digest;
use bh_sync_client::{HomeRetryReason, HomeStatus};
use std::time::Duration;
use support::{
    device::{Device, until},
    fake::Hosted,
};

/// The home's stored bundles must be exactly one: the retained objects at
/// the original prefix.
fn assert_stored_once(hosted: &Hosted, device: &Device) {
    let retained = device.retained();
    let bundle = device.retained_bundle();
    assert_eq!(bundle.len(), 2854);
    assert_eq!(
        hosted.edge.home_objects(device.account_log),
        vec![(
            Digest(retained.head.hash),
            bh_sync::home_objects::digest(&bundle).unwrap(),
            bundle.clone(),
        )]
    );
    assert!(
        hosted.edge.home_stores().iter().all(|sent| *sent == bundle),
        "every store sent the same retained bytes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn home_completes_only_after_public_and_exact_private_ack() {
    let hosted = Hosted::new();
    let device = Device::new();
    let retained = device.retained();
    assert_eq!(retained.head.position, 3);
    let hold = hosted.edge.hold_next_home_store();
    let (client, _) = device.start(&hosted);
    tokio::time::timeout(Duration::from_secs(20), hold.arrived)
        .await
        .expect("stored")
        .unwrap();
    // Ordered and stored, but not yet answered: still pending.
    assert_eq!(hosted.edge.entries(device.account_log).len(), 3);
    assert_eq!(hosted.edge.home_objects(device.account_log).len(), 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(device.home_pending());
    assert!(device.signer.home_ordered.lock().unwrap().is_empty());
    hold.release.send(()).unwrap();
    until(20, "home confirmed", || !device.home_pending()).await;
    assert_eq!(
        device.signer.home_ordered.lock().unwrap().as_slice(),
        &[(retained.head, 0)]
    );
    assert_stored_once(&hosted, &device);
    assert!(
        device.retained() == retained,
        "retained bytes kept as they were"
    );
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_home_answer_does_not_delay_new_note_ack() {
    let hosted = Hosted::new();
    let device = Device::new();
    let retained = device.retained();
    let hold = hosted.edge.hold_next_home_store();
    let (client, status) = device.start(&hosted);
    let home = client.home_status();
    tokio::time::timeout(Duration::from_secs(20), hold.arrived)
        .await
        .expect("home store arrived")
        .unwrap();
    assert!(device.home_pending());
    assert_eq!(*home.borrow(), HomeStatus::Pending);

    let (_, update) = device.new_note("written while home is waiting");
    client.wake();
    until(5, "note acknowledged before home answer", || {
        device.acked(update).is_some()
    })
    .await;
    until(5, "synced before home answer", || {
        matches!(*status.borrow(), bh_sync_client::SyncStatus::Synced)
    })
    .await;
    assert_eq!(hosted.edge.entries(device.log()).len(), 2);
    assert!(
        device.home_pending(),
        "the held answer has not completed home"
    );
    assert!(device.signer.home_ordered.lock().unwrap().is_empty());

    hold.release.send(()).unwrap();
    until(20, "home confirmed", || !device.home_pending()).await;
    assert_eq!(
        device.signer.home_ordered.lock().unwrap().as_slice(),
        &[(retained.head, 0)]
    );
    assert_stored_once(&hosted, &device);
    assert!(device.retained() == retained);
    assert_eq!(*home.borrow(), HomeStatus::Done);
    assert_eq!(device.signer.home_ordered.lock().unwrap().len(), 1);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_or_mismatched_storage_keeps_setup_pending() {
    for forged in [false, true] {
        let hosted = Hosted::new();
        let device = Device::new();
        let retained = device.retained();
        if forged {
            // Stored, but the answer names another bundle.
            hosted
                .edge
                .forge_home
                .store(true, std::sync::atomic::Ordering::SeqCst);
        } else {
            hosted
                .edge
                .home_down
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let (client, _) = device.start(&hosted);
        until(20, "registered", || device.registered()).await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(device.home_pending(), "forged: {forged}");
        assert!(device.signer.home_ordered.lock().unwrap().is_empty());
        assert!(device.retained() == retained);
        // Storage recovers: the same bytes complete setup.
        hosted
            .edge
            .home_down
            .store(false, std::sync::atomic::Ordering::SeqCst);
        hosted
            .edge
            .forge_home
            .store(false, std::sync::atomic::Ordering::SeqCst);
        client.wake();
        until(40, "home confirmed", || !device.home_pending()).await;
        assert_stored_once(&hosted, &device);
        client.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_or_mismatched_retained_setup_is_never_stored_or_completed() {
    type Case = fn(&mut bh_sync_client::HomeSetup);
    let cases: [(&str, Case); 7] = [
        ("record missing", |s| s.objects.record.clear()),
        ("record changed", |s| s.objects.record[100] ^= 1),
        ("device seal changed", |s| s.objects.device_seal[100] ^= 1),
        ("recovery seal changed", |s| {
            s.objects.recovery_seal[100] ^= 1
        }),
        ("seals swapped", |s| {
            std::mem::swap(&mut s.objects.device_seal, &mut s.objects.recovery_seal)
        }),
        ("prefix head changed", |s| s.prefix.head.hash[0] ^= 1),
        ("prefix event changed", |s| s.prefix.events[2][40] ^= 1),
    ];
    for (name, tamper) in cases {
        let hosted = Hosted::new();
        let device = Device::new();
        *device.signer.tamper.lock().unwrap() = Some(Box::new(tamper));
        let (client, _) = device.start(&hosted);
        let home = client.home_status();
        until(20, "invalid retained setup", || {
            *home.borrow() == HomeStatus::Retrying(HomeRetryReason::SetupNotReady)
        })
        .await;
        assert!(hosted.edge.home_stores().is_empty(), "{name}: sent");
        assert!(device.home_pending(), "{name}");
        assert!(device.signer.home_ordered.lock().unwrap().is_empty());
        client.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_device_missing_its_retained_signup_is_not_completed() {
    let hosted = Hosted::new();
    let device = Device::new();
    device
        .raw()
        .execute("DELETE FROM account_initial_bootstrap", [])
        .unwrap();
    let (client, status) = device.start(&hosted);
    let home = client.home_status();
    until(20, "home failure visible", || {
        *home.borrow() == HomeStatus::Retrying(HomeRetryReason::SetupNotReady)
    })
    .await;
    let (_, update) = device.new_note("still publishes");
    client.wake();
    until(10, "note acknowledged", || device.acked(update).is_some()).await;
    until(10, "note synced", || {
        *status.borrow() == bh_sync_client::SyncStatus::Synced
    })
    .await;
    assert!(hosted.edge.home_stores().is_empty());
    assert!(device.home_pending());
    assert!(device.signer.home_ordered.lock().unwrap().is_empty());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_after_durable_store_then_restart_completes_with_the_same_bundle() {
    let hosted = Hosted::new();
    let device = Device::new();
    let hold = hosted.edge.hold_next_home_store();
    let (client, _) = device.start(&hosted);
    tokio::time::timeout(Duration::from_secs(20), hold.arrived)
        .await
        .expect("stored")
        .unwrap();
    // The home holds the bundle; the client stops before learning so.
    client.shutdown().await;
    drop(hold.release);
    assert!(device.home_pending());
    assert!(device.signer.home_ordered.lock().unwrap().is_empty());
    let (client, _) = device.start(&hosted);
    until(20, "home confirmed", || !device.home_pending()).await;
    assert!(hosted.edge.home_stores().len() >= 2);
    assert_stored_once(&hosted, &device);
    assert_eq!(device.signer.home_ordered.lock().unwrap().len(), 1);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_superseded_during_storage_completes_only_when_current() {
    let hosted = Hosted::new();
    let device = Device::new();
    let hold = hosted.edge.hold_next_home_store();
    let (client, _) = device.start(&hosted);
    tokio::time::timeout(Duration::from_secs(20), hold.arrived)
        .await
        .expect("stored")
        .unwrap();
    // Locked and unlocked while the answer is outstanding.
    let current = device.signer.relock();
    hold.release.send(()).unwrap();
    until(20, "home confirmed", || !device.home_pending()).await;
    assert!(
        device
            .signer
            .stale_confirms
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "the answer to the superseded authority's request was not used"
    );
    assert_eq!(
        device.signer.home_ordered.lock().unwrap().as_slice(),
        &[(device.retained().head, current)]
    );
    assert!(hosted.edge.home_stores().len() >= 2);
    assert_stored_once(&hosted, &device);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registered_base_with_home_pending_still_stores_on_restart() {
    let hosted = Hosted::new();
    let device = Device::new();
    hosted
        .edge
        .home_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (client, _) = device.start(&hosted);
    until(20, "registered", || device.registered()).await;
    client.shutdown().await;
    assert!(device.home_pending());
    hosted
        .edge
        .home_down
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (client, _) = device.start(&hosted);
    until(20, "home confirmed", || !device.home_pending()).await;
    assert_stored_once(&hosted, &device);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_cleared_by_an_earlier_client_is_still_stored_exactly() {
    let hosted = Hosted::new();
    let device = Device::new();
    let retained = device.retained();
    device.clear_pending_as_earlier_client();
    assert!(!device.home_pending());
    let (client, _) = device.start(&hosted);
    until(20, "home acknowledged", || {
        !device.signer.home_ordered.lock().unwrap().is_empty()
    })
    .await;
    assert_stored_once(&hosted, &device);
    assert!(device.retained() == retained, "no regeneration");
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleared_pending_row_still_reports_invalid_retained_setup() {
    let hosted = Hosted::new();
    let device = Device::new();
    device.clear_pending_as_earlier_client();
    device
        .raw()
        .execute("DELETE FROM account_initial_bootstrap", [])
        .unwrap();
    let (client, _) = device.start(&hosted);
    let home = client.home_status();
    until(20, "retained setup failure", || {
        *home.borrow() == HomeStatus::Retrying(HomeRetryReason::SetupNotReady)
    })
    .await;
    assert!(hosted.edge.home_stores().is_empty());
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_home_reports_retrying_then_done() {
    let hosted = Hosted::new();
    let device = Device::new();
    hosted
        .edge
        .home_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (client, _) = device.start(&hosted);
    let home = client.home_status();
    until(20, "home unavailable", || {
        *home.borrow() == HomeStatus::Retrying(HomeRetryReason::Unavailable)
    })
    .await;
    hosted
        .edge
        .home_down
        .store(false, std::sync::atomic::Ordering::SeqCst);
    client.wake();
    until(20, "home done", || *home.borrow() == HomeStatus::Done).await;
    assert_eq!(device.signer.home_ordered.lock().unwrap().len(), 1);
    client.wake();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(*home.borrow(), HomeStatus::Done);
    assert_eq!(device.signer.home_ordered.lock().unwrap().len(), 1);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signer_with_no_initial_home_obligation_never_opens_home_session() {
    let hosted = Hosted::new();
    let device = Device::new();
    device
        .signer
        .no_home_obligation
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (client, _) = device.start(&hosted);
    let home = client.home_status();
    until(20, "no home obligation", || {
        *home.borrow() == HomeStatus::NotNeeded
    })
    .await;
    until(20, "base registered", || device.registered()).await;
    // Outbox uses two authenticated connections as registration changes the
    // account head. A third here would be the home task opening its own.
    assert_eq!(
        hosted
            .edge
            .authz_connects
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert!(hosted.edge.home_stores().is_empty());
    client.shutdown().await;
}
