//! Rust allocation counts, isolated to this test thread and to the measured request.
#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_authz::proto::{FromService, ToService, Want};
use bh_authz_test_alloc::{BYTES, Counting};
use support::*;
#[global_allocator]
static ALLOC: Counting = Counting;
async fn cost(cycles: usize) -> (usize, usize) {
    let h = Harness::new();
    let device = Device::new();
    let mut account = Account::create_full(&device);
    for _ in 0..cycles {
        let extra = Device::new();
        account.add_device(&device, &extra);
        account.remove_self(&extra);
    }
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let log = account.log;
    let request = || ToService::ReadBatch {
        want: Want::ReadBatch {
            log,
            after: h.edge.head(log),
            max_events: 48,
        },
    };
    // Warm the paths before measurement (including allocator/runtime initialization).
    assert!(matches!(
        connection.handle(request()).await,
        FromService::ReadBatch { .. }
    ));
    BYTES.with(|n| n.set(Some(0)));
    let answer = connection.handle(request()).await;
    let empty = BYTES.with(|n| n.replace(None).unwrap());
    assert!(matches!(answer, FromService::ReadBatch { .. }));
    let extra = Device::new();
    let change = account.add_device(&device, &extra);
    h.order_account_event(&account, &change);
    BYTES.with(|n| n.set(Some(0)));
    let answer = connection.handle(request()).await;
    let update = BYTES.with(|n| n.replace(None).unwrap());
    assert!(matches!(answer, FromService::ReadBatch { .. }));
    (empty, update)
}
#[tokio::test]
async fn warm_empty_and_one_update_do_not_copy_prior_history() {
    let small = cost(8).await;
    let large = cost(256).await;
    eprintln!(
        "allocated Rust bytes (empty, one update): 19 events={small:?}, 515 events={large:?}"
    );
    // BTree insertion splits may allocate a bounded node path; neither request
    // may copy the historical device/key/head maps. Allow 128 KiB for the
    // bounded insertion path in the large-key BTree nodes, not a latency threshold.
    assert!(large.0 <= small.0 + 4096, "empty {small:?} -> {large:?}");
    assert!(
        large.1 <= small.1 + 131072,
        "one update {small:?} -> {large:?}"
    );
}
