#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_authz::proto::{FromService, LogId, ReadBatchResult, ToService, Want};
use bh_authz::{EdgeError, EdgeReader, LogRead, Service};
use bh_sync::Head;
use futures_util::future::BoxFuture;
use std::sync::{Arc, Mutex};
use support::*;
use tokio::sync::{Semaphore, oneshot};

struct PausedSelection {
    edge: Arc<FakeEdge>,
    blocked_log: LogId,
    root: [u8; 32],
    clock: Arc<bh_authz::FixedClock>,
    arrived: Mutex<Option<oneshot::Sender<()>>>,
    release: Semaphore,
}
impl EdgeReader for PausedSelection {
    fn read_log(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<bh_authz::LogItems, EdgeError>> {
        self.edge.read_log(permit)
    }
    fn read_log_with_receipt(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<LogRead, EdgeError>> {
        Box::pin(async move {
            if let Ok(p) = bh_sync::permit::verify(self.root, &permit, self.clock.now())
                && matches!(p.scope, bh_sync::permit::Scope::ReadEvents { log, .. } if log == self.blocked_log)
            {
                if let Some(arrived) = self.arrived.lock().unwrap().take() {
                    let _ = arrived.send(());
                }
                let hold = self
                    .release
                    .acquire()
                    .await
                    .map_err(|_| EdgeError::Unavailable)?;
                hold.forget();
            }
            self.edge.read_log_with_receipt(permit).await
        })
    }
    fn read_bodies(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        self.edge.read_bodies(permit)
    }
}

#[tokio::test(start_paused = true)]
async fn one_accounts_selection_does_not_hold_other_accounts_lock_and_rechecks_advancement() {
    let h = Harness::new();
    let a_device = Device::new();
    let mut a = Account::create_full(&a_device);
    let b_device = Device::new();
    let b = Account::create_full(&b_device);
    h.publish(&a);
    h.publish(&b);
    let genesis = a.base_genesis(&a_device);
    let log = genesis.log();
    let (arrived, waiting) = oneshot::channel();
    let edge = Arc::new(PausedSelection {
        edge: h.edge.clone(),
        blocked_log: log,
        root: h.root.public(),
        clock: h.clock.clone(),
        arrived: Mutex::new(Some(arrived)),
        release: Semaphore::new(0),
    });
    let service = Service::open(
        &h.dir.path().join("paused.sqlite"),
        h.keys(),
        h.clock.clone(),
        edge.clone(),
    )
    .unwrap();
    let mut a_session = session(&service, &a, &a_device).await;
    let mut b_session = session(&service, &b, &b_device).await;
    order_genesis(&h, &a_session.handle(genesis.register()).await, &genesis);
    let pending = tokio::spawn(async move {
        a_session
            .handle(ToService::ReadBatch {
                want: Want::ReadBatch {
                    log,
                    after: Head::EMPTY,
                    max_events: 48,
                },
            })
            .await
    });
    waiting.await.unwrap();
    let b_answer = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        b_session.handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: b.log,
                after: Head::EMPTY,
                max_events: 48,
            },
        }),
    )
    .await
    .expect("B must not wait behind A's immutable selection");
    assert!(
        matches!(
            b_answer,
            FromService::ReadBatch {
                result: ReadBatchResult::Selected { .. },
                ..
            }
        ),
        "{b_answer:?}"
    );
    let newcomer = Device::new();
    let change = a.add_device(&a_device, &newcomer);
    h.order_account_event(&a, &change);
    // Disclosed advancement through another connection updates the guarded slot.
    // Merely changing an unseen remote log is not a cache generation check.
    let _advanced = session(&service, &a, &a_device).await;
    edge.release.add_permits(1);
    let answer = pending.await.unwrap();
    assert!(
        matches!(answer, FromService::Unavailable),
        "stale A selection: {answer:?}"
    );
}
