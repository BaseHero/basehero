#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_authz::proto::{FromService, ToService, Want, account_log_unwrap, account_log_wrap};
use bh_authz::{EdgeError, EdgeReader, LogItems, LogRead, Service};
use bh_sync::{
    Commitment, Head, OpaqueEvent, Route,
    permit::{self, Scope},
};
use futures_util::future::BoxFuture;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use support::{
    native::{Fold, Mac, order},
    *,
};
use tokio::sync::{Notify, Semaphore};
struct Fault {
    h: Arc<FakeEdge>,
    root: [u8; 32],
    clock: Arc<bh_authz::FixedClock>,
    corrupt: AtomicU64,
    pause: AtomicU64,
    entered: Notify,
    release: Semaphore,
}
impl EdgeReader for Fault {
    fn read_log(&self, p: Vec<u8>) -> BoxFuture<'_, Result<LogItems, EdgeError>> {
        Box::pin(async move {
            let signed = permit::verify(self.root, &p, self.clock.now()).unwrap();
            let mut items = self.h.read_log(p).await?;
            if let Scope::ReadEvents { first, .. } = signed.scope {
                if self.pause.load(Ordering::SeqCst) == first {
                    self.entered.notify_one();
                    self.release.acquire().await.unwrap().forget();
                }
                if self
                    .corrupt
                    .compare_exchange(first, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    let (ordered, bytes) = items.last_mut().unwrap();
                    let old = Commitment::decode(ordered).unwrap();
                    let wrapped = OpaqueEvent::decode(bytes).unwrap();
                    let (original, body) = account_log_unwrap(&wrapped).unwrap();
                    let mut bad = original.to_vec();
                    *bad.last_mut().unwrap() ^= 1; // signature, not outer chain
                    let event = account_log_wrap(&bad, body).unwrap();
                    *ordered = Commitment::order(old.base(), old.before(), &event, Route::Control)
                        .unwrap()
                        .encode();
                    *bytes = event.encode();
                }
            }
            Ok(items)
        })
    }
    fn read_log_with_receipt(&self, p: Vec<u8>) -> BoxFuture<'_, Result<LogRead, EdgeError>> {
        self.h.read_log_with_receipt(p)
    }
    fn read_bodies(&self, p: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        self.h.read_bodies(p)
    }
}
fn service(h: &Harness) -> (Service, Arc<Fault>) {
    let edge = Arc::new(Fault {
        h: h.edge.clone(),
        root: h.root.public(),
        clock: h.clock.clone(),
        corrupt: AtomicU64::new(0),
        pause: AtomicU64::new(0),
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    (
        Service::open(
            &h.dir.path().join("authz.sqlite"),
            h.keys(),
            h.clock.clone(),
            edge.clone(),
        )
        .unwrap(),
        edge,
    )
}
fn request(log: bh_authz::proto::LogId) -> ToService {
    ToService::ReadBatch {
        want: Want::ReadBatch {
            log,
            after: Head::EMPTY,
            max_events: 48,
        },
    }
}
fn db(h: &Harness) -> rusqlite::Connection {
    rusqlite::Connection::open(h.dir.path().join("authz.sqlite")).unwrap()
}
fn durable(h: &Harness) -> (i64, i64) {
    db(h)
        .query_row(
            "SELECT position, (SELECT COUNT(*) FROM account_events) FROM accounts",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}
fn changes(h: &Harness, account: &mut Account, by: &Device, pairs: usize) {
    for _ in 0..pairs {
        let extra = Device::new();
        account.add_device(by, &extra);
        account.remove_self(&extra);
    }
    h.publish(account);
}
#[tokio::test]
async fn late_verification_failure_keeps_only_committed_prefix_and_reloads() {
    let h = Harness::new();
    let device = Device::new();
    let mut a = Account::create_full(&device);
    h.publish(&a);
    let (service, edge) = service(&h);
    let mut c = session(&service, &a, &device).await;
    changes(&h, &mut a, &device, 33); // 64 + 2, fail the last signature in the second page
    edge.corrupt.store(68, Ordering::SeqCst);
    assert!(matches!(
        c.handle(request(a.log)).await,
        FromService::Unavailable
    ));
    assert_eq!(durable(&h), (67, 67));
    assert!(matches!(
        c.handle(request(a.log)).await,
        FromService::ReadBatch { .. }
    ));
    assert_eq!(durable(&h), (69, 69));
}
#[tokio::test]
async fn failed_store_rolls_back_whole_page_and_candidate_is_not_published() {
    let h = Harness::new();
    let device = Device::new();
    let mut a = Account::create_full(&device);
    h.publish(&a);
    let (service, _) = service(&h);
    let mut c = session(&service, &a, &device).await;
    changes(&h, &mut a, &device, 1);
    db(&h).execute_batch("CREATE TRIGGER fail_page BEFORE INSERT ON account_events WHEN NEW.position=5 BEGIN SELECT RAISE(FAIL, 'injected'); END;").unwrap();
    assert!(matches!(
        c.handle(request(a.log)).await,
        FromService::Unavailable
    ));
    assert_eq!(durable(&h), (3, 3));
    db(&h).execute_batch("DROP TRIGGER fail_page;").unwrap();
    assert!(matches!(
        c.handle(request(a.log)).await,
        FromService::ReadBatch { .. }
    ));
    assert_eq!(durable(&h), (5, 5));
}
#[tokio::test(start_paused = true)]
async fn cancellation_keeps_verified_prefix_and_next_refresh_resumes() {
    let h = Harness::new();
    let device = Device::new();
    let mut a = Account::create_full(&device);
    h.publish(&a);
    let (service, edge) = service(&h);
    let mut c = session(&service, &a, &device).await;
    changes(&h, &mut a, &device, 33);
    edge.pause.store(68, Ordering::SeqCst);
    let log = a.log;
    let pending = tokio::spawn(async move { c.handle(request(log)).await });
    edge.entered.notified().await;
    assert_eq!(durable(&h), (67, 67));
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    edge.pause.store(0, Ordering::SeqCst);
    let mut c = session(&service, &a, &device).await;
    assert!(matches!(
        c.handle(request(log)).await,
        FromService::ReadBatch { .. }
    ));
    assert_eq!(durable(&h), (69, 69));
}
#[tokio::test]
async fn failed_account_candidate_does_not_delete_pending_base_authority() {
    let h = Harness::new();
    let mut mac = Mac::new(&h);
    let fold = Fold::new();
    let (service, edge) = service(&h);
    let mut c = mac.session(&service).await;
    mac.register_and_order(&h, &mut c).await;
    let add = mac.pair(&fold);
    mac.submit_account(&h, &mut c, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let permitted = c.handle(mac.submit_copy(&copy)).await;
    let removal = mac.remove(&fold);
    h.order_original(mac.log, removal.as_bytes());
    edge.corrupt.store(5, Ordering::SeqCst);
    assert!(matches!(
        c.handle(request(mac.log)).await,
        FromService::Unavailable
    ));
    assert_eq!(durable(&h), (4, 4));
    let pending: (i64, i64) = db(&h)
        .query_row(
            "SELECT (SELECT COUNT(*) FROM bases), (SELECT COUNT(*) FROM base_pending)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(pending, (1, 1));
    assert!(matches!(
        c.handle(request(mac.log)).await,
        FromService::ReadBatch { .. }
    ));
    assert_eq!(durable(&h), (5, 5));
    order(&h, &permitted, &copy).unwrap();
    // Confirmation reloads the pending control, but its head is still behind
    // the real account. Completing that copy must not grant base read authority:
    // the base copy lags, so the read waits for the account change.
    assert!(matches!(
        c.handle(request(mac.base_log())).await,
        FromService::Refused {
            reason: bh_authz::proto::Refusal::AccountChangePending
        }
    ));
    let state: (i64, i64, i64) = db(&h).query_row(
        "SELECT (SELECT COUNT(*) FROM base_pending), account_position, (SELECT position FROM accounts) FROM base_controls",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(state, (0, 4, 5));
}

#[tokio::test]
async fn failed_confirmation_preserves_registry_pending_and_separate_account_progress() {
    let h = Harness::new();
    let mut mac = Mac::new(&h);
    let fold = Fold::new();
    let (service, _) = service(&h);
    let mut c = mac.session(&service).await;
    mac.register_and_order(&h, &mut c).await;
    let add = mac.pair(&fold);
    mac.submit_account(&h, &mut c, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let permitted = c.handle(mac.submit_copy(&copy)).await;
    order(&h, &permitted, &copy).unwrap();
    let disk = db(&h);
    disk.execute_batch("CREATE TRIGGER fail_control BEFORE INSERT ON base_controls BEGIN SELECT RAISE(FAIL, 'injected'); END;").unwrap();
    assert!(matches!(
        c.handle(request(mac.base_log())).await,
        FromService::Unavailable
    ));
    let state: (i64,i64,i64,i64)=disk.query_row("SELECT (SELECT COUNT(*) FROM bases), (SELECT COUNT(*) FROM base_pending), (SELECT account_position FROM base_controls), (SELECT position FROM accounts)",[],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(state, (1, 1, 3, 4));
    disk.execute_batch("DROP TRIGGER fail_control;").unwrap();
    assert!(matches!(
        c.handle(request(mac.base_log())).await,
        FromService::ReadBatch { .. }
    ));
    let state: (i64, i64) = disk
        .query_row(
            "SELECT (SELECT COUNT(*) FROM base_pending), account_position FROM base_controls",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, (0, 4));
}
