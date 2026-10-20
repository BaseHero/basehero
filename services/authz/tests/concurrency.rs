//! One account's requests share their currentness reads, and one ReadBatch
//! runs its reads side by side, under paused time and an edge whose every
//! read takes the same injected time.
#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_authz::proto::{FromService, LogId, LogKind, ReadBatchResult, Refusal, ToService, Want};
use bh_authz::{Connection, EdgeError, EdgeReader, FixedClock, LogItems, LogRead, Service};
use bh_sync::{
    Head,
    permit::{self, Scope},
};
use futures_util::future::BoxFuture;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use support::{
    native::{Fold, Mac, order},
    *,
};
use tokio::{
    sync::{Notify, Semaphore},
    time::Instant,
};

const D: Duration = Duration::from_millis(80);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// The account-log head lookup.
    Refresh,
    /// A base's control confirmation.
    Controls,
    /// The ReadBatch's immutable selection.
    Selection,
}

/// One read the edge holds until released, once.
struct Hold {
    kind: Kind,
    log: LogId,
    /// Hold the answer read before the hold, not the read itself.
    after_read: bool,
}

/// The test edge with a fixed time per read, counts by kind, and faults.
struct Slow {
    edge: Arc<FakeEdge>,
    root: [u8; 32],
    clock: Arc<FixedClock>,
    delay: Duration,
    counts: Mutex<Vec<Kind>>,
    /// Refresh reads still to fail, after their delay.
    fail_refresh: AtomicU64,
    hold: Mutex<Option<Hold>>,
    held: Notify,
    release: Semaphore,
}
impl Slow {
    fn new(h: &Harness, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            edge: h.edge.clone(),
            root: h.root.public(),
            clock: h.clock.clone(),
            delay,
            counts: Mutex::default(),
            fail_refresh: AtomicU64::new(0),
            hold: Mutex::default(),
            held: Notify::new(),
            release: Semaphore::new(0),
        })
    }
    fn count(&self, kind: Kind) -> usize {
        self.counts
            .lock()
            .unwrap()
            .iter()
            .filter(|k| **k == kind)
            .count()
    }
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.count(Kind::Refresh),
            self.count(Kind::Controls),
            self.count(Kind::Selection),
        )
    }
    fn hold(&self, kind: Kind, log: LogId, after_read: bool) {
        *self.hold.lock().unwrap() = Some(Hold {
            kind,
            log,
            after_read,
        });
    }
    async fn read<T>(
        &self,
        permit: &[u8],
        selection: bool,
        read: impl Future<Output = Result<T, EdgeError>>,
    ) -> Result<T, EdgeError> {
        let scope = permit::verify(self.root, permit, self.clock.now())
            .map_err(|_| EdgeError::Refused)?
            .scope;
        let (kind, log) = match scope {
            Scope::ReadEvents { log, .. } if selection => (Kind::Selection, log),
            Scope::ReadEvents { log, .. } if log.kind == LogKind::Account => (Kind::Refresh, log),
            Scope::ReadControls { log, .. } => (Kind::Controls, log),
            _ => return read.await,
        };
        self.counts.lock().unwrap().push(kind);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let held = {
            let mut hold = self.hold.lock().unwrap();
            match hold.as_ref() {
                Some(h) if h.kind == kind && h.log == log => hold.take(),
                _ => None,
            }
        };
        let wait = || async {
            self.held.notify_one();
            self.release.acquire().await.unwrap().forget();
        };
        let answer = match held {
            Some(h) if h.after_read => {
                let answer = read.await;
                wait().await;
                answer
            }
            Some(_) => {
                wait().await;
                read.await
            }
            None => read.await,
        };
        if kind == Kind::Refresh
            && self
                .fail_refresh
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return Err(EdgeError::Unavailable);
        }
        answer
    }
}
impl EdgeReader for Slow {
    fn read_log(&self, p: Vec<u8>) -> BoxFuture<'_, Result<LogItems, EdgeError>> {
        Box::pin(async move { self.read(&p.clone(), false, self.edge.read_log(p)).await })
    }
    fn read_log_with_receipt(&self, p: Vec<u8>) -> BoxFuture<'_, Result<LogRead, EdgeError>> {
        Box::pin(async move {
            self.read(&p.clone(), true, self.edge.read_log_with_receipt(p))
                .await
        })
    }
    fn read_bodies(&self, p: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        self.edge.read_bodies(p)
    }
}

fn open(h: &Harness, edge: Arc<Slow>) -> Service {
    Service::open(
        &h.dir.path().join("concurrency.sqlite"),
        h.keys(),
        h.clock.clone(),
        edge,
    )
    .unwrap()
}

fn read(log: LogId) -> ToService {
    ToService::ReadBatch {
        want: Want::ReadBatch {
            log,
            after: Head::EMPTY,
            max_events: 48,
        },
    }
}

fn selected(answer: &FromService) -> bool {
    matches!(
        answer,
        FromService::ReadBatch {
            result: ReadBatchResult::Selected { .. },
            ..
        }
    )
}

/// The base's durable control head position and pending-control count.
fn durable_base(h: &Harness, base: [u8; 32]) -> (i64, i64) {
    rusqlite::Connection::open(h.dir.path().join("concurrency.sqlite"))
        .unwrap()
        .query_row(
            "SELECT control_position,
               (SELECT COUNT(*) FROM base_pending WHERE base=?1)
             FROM base_controls WHERE base=?1",
            [base.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

/// An account of two devices with a registered, ordered base, and each
/// device's connection.
struct Fixture {
    h: Harness,
    edge: Arc<Slow>,
    service: Service,
    account: Account,
    device: Device,
    log: LogId,
    epoch: [u8; 32],
    first: Connection,
    second: Connection,
}
async fn fixture(delay: Duration) -> Fixture {
    let h = Harness::new();
    let device = Device::new();
    let other = Device::new();
    let mut account = Account::create_full(&device);
    account.add_device(&device, &other);
    h.publish(&account);
    let edge = Slow::new(&h, delay);
    let service = open(&h, edge.clone());
    let mut first = session(&service, &account, &device).await;
    let second = session(&service, &account, &other).await;
    let genesis = account.base_genesis(&device);
    order_genesis(&h, &first.handle(genesis.register()).await, &genesis);
    // Confirm the base once, so every later request starts warm.
    assert!(selected(&first.handle(read(genesis.log())).await));
    Fixture {
        log: genesis.log(),
        epoch: bh_event::key_id(&genesis.content),
        h,
        edge,
        service,
        account,
        device,
        first,
        second,
    }
}

#[tokio::test(start_paused = true)]
async fn a_base_read_batchs_currentness_and_selection_reads_overlap() {
    let mut f = fixture(D).await;
    let before = f.edge.counts();
    let start = Instant::now();
    let answer = f.first.handle(read(f.log)).await;
    assert!(selected(&answer), "{answer:?}");
    let after = f.edge.counts();
    assert_eq!(
        (after.0 - before.0, after.1 - before.1, after.2 - before.2),
        (1, 1, 1)
    );
    // The longest read, not the three in turn.
    assert_eq!(start.elapsed(), D);
}

#[tokio::test(start_paused = true)]
async fn one_accounts_concurrent_read_batches_share_one_refresh_and_confirmation() {
    let mut f = fixture(D).await;
    let before = f.edge.counts();
    let start = Instant::now();
    let (a, b) = tokio::join!(f.first.handle(read(f.log)), f.second.handle(read(f.log)));
    assert!(selected(&a), "{a:?}");
    assert!(selected(&b), "{b:?}");
    let after = f.edge.counts();
    // One head lookup and one control confirmation; each its own selection.
    assert_eq!(
        (after.0 - before.0, after.1 - before.1, after.2 - before.2),
        (1, 1, 2)
    );
    assert_eq!(start.elapsed(), D);
}

#[tokio::test(start_paused = true)]
async fn a_write_grant_shares_the_read_batchs_refresh() {
    let mut f = fixture(D).await;
    let before = f.edge.count(Kind::Refresh);
    let start = Instant::now();
    let grant = ToService::Permits {
        items: vec![Want::Append {
            log: f.log,
            event: base_event(3).0.encode(),
            epoch: f.epoch,
        }],
    };
    let (batch, permits) = tokio::join!(f.first.handle(read(f.log)), f.second.handle(grant));
    assert!(selected(&batch), "{batch:?}");
    let FromService::Permits { items } = permits else {
        panic!("{permits:?}")
    };
    assert!(items[0].is_ok(), "{items:?}");
    assert_eq!(f.edge.count(Kind::Refresh) - before, 1);
    assert_eq!(start.elapsed(), D);
}

#[tokio::test(start_paused = true)]
async fn a_failed_shared_refresh_fails_every_waiter_and_grants_nothing() {
    let mut f = fixture(D).await;
    let before = f.edge.count(Kind::Refresh);
    f.edge.fail_refresh.store(1, Ordering::SeqCst);
    let grant = ToService::Permits {
        items: vec![Want::Append {
            log: f.log,
            event: base_event(3).0.encode(),
            epoch: f.epoch,
        }],
    };
    let (a, b) = tokio::join!(f.first.handle(read(f.log)), f.second.handle(grant));
    assert!(matches!(a, FromService::Unavailable), "{a:?}");
    assert!(matches!(b, FromService::Unavailable), "{b:?}");
    assert_eq!(f.edge.count(Kind::Refresh) - before, 1);
    // Each retries on its own request.
    assert!(selected(&f.second.handle(read(f.log)).await));
    assert_eq!(f.edge.count(Kind::Refresh) - before, 2);
}

#[tokio::test(start_paused = true)]
async fn a_currentness_change_during_selection_discards_the_selection() {
    let Fixture {
        h,
        edge,
        mut account,
        device,
        log,
        mut first,
        mut second,
        ..
    } = fixture(D).await;
    edge.hold(Kind::Selection, log, false);
    let pending = tokio::spawn(async move { first.handle(read(log)).await });
    edge.held.notified().await;
    // The account changes, and another of its requests reads the change.
    let change = account.add_device(&device, &Device::new());
    h.order_account_event(&account, &change);
    let grant = second
        .handle(ToService::Permits {
            items: vec![read_events(log)],
        })
        .await;
    assert!(matches!(grant, FromService::Permits { .. }), "{grant:?}");
    edge.release.add_permits(1);
    let answer = pending.await.unwrap();
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
}

#[tokio::test(start_paused = true)]
async fn one_accounts_slow_refresh_does_not_delay_another_account() {
    let f = fixture(D).await;
    let other = Device::new();
    let b = Account::create_full(&other);
    f.h.publish(&b);
    let mut b_session = session(&f.service, &b, &other).await;
    f.edge.hold(Kind::Refresh, f.account.log, false);
    let log = f.log;
    let mut first = f.first;
    let pending = tokio::spawn(async move { first.handle(read(log)).await });
    f.edge.held.notified().await;
    let start = Instant::now();
    let answer = tokio::time::timeout(
        Duration::from_secs(1),
        b_session.handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: b.log,
                after: Head::EMPTY,
                max_events: 48,
            },
        }),
    )
    .await
    .expect("B must not wait for A");
    assert!(selected(&answer), "{answer:?}");
    // Its own head lookup and selection, side by side.
    assert_eq!(start.elapsed(), D);
    f.edge.release.add_permits(1);
    let answer = pending.await.unwrap();
    assert!(selected(&answer), "{answer:?}");
}

/// A request that joined reads begun before it arrived refuses only on
/// reads begun after: the base copy ordered meanwhile is seen. Returns the
/// answer to `late`, sent while the first request's confirmation is held.
async fn joined_late(late: impl FnOnce(&Mac) -> ToService) -> FromService {
    let h = Harness::new();
    let mut mac = Mac::new(&h);
    let edge = Slow::new(&h, Duration::ZERO);
    let service = open(&h, edge.clone());
    let mut first = mac.session(&service).await;
    mac.register_and_order(&h, &mut first).await;
    let mut second = mac.session(&service).await;
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&h, &mut first, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let permitted = first.handle(mac.submit_copy(&copy)).await;
    let log = mac.base_log();
    // The first request's confirmation reads before the copy is ordered.
    edge.hold(Kind::Controls, log, true);
    let early = tokio::spawn(async move { first.handle(read(log)).await });
    edge.held.notified().await;
    order(&h, &permitted, &copy).unwrap();
    let late = late(&mac);
    let late = tokio::spawn(async move { second.handle(late).await });
    // Let the later request reach the held confirmation.
    tokio::time::sleep(Duration::from_millis(1)).await;
    edge.release.add_permits(1);
    let early = early.await.unwrap();
    assert!(
        matches!(
            early,
            FromService::Refused {
                reason: Refusal::AccountChangePending
            }
        ),
        "{early:?}"
    );
    late.await.unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_read_batch_refusal_rests_on_reads_begun_after_the_request() {
    let late = joined_late(|mac| read(mac.base_log())).await;
    assert!(selected(&late), "{late:?}");
}

#[tokio::test(start_paused = true)]
async fn a_write_grant_refusal_rests_on_reads_begun_after_the_request() {
    let late = joined_late(|mac| ToService::Permits {
        items: vec![Want::Append {
            log: mac.base_log(),
            event: base_event(3).0.encode(),
            epoch: bh_event::key_id(&mac.content),
        }],
    })
    .await;
    let FromService::Permits { items } = late else {
        panic!("{late:?}")
    };
    assert!(items[0].is_ok(), "{items:?}");
}

/// A delayed registration replay must not replace a newer durable base
/// control head or delete a pending control ordered after it.
#[tokio::test(start_paused = true)]
async fn a_delayed_registration_replay_cannot_overwrite_newer_base_authority() {
    let h = Harness::new();
    let mut mac = Mac::new(&h);
    let fold = Fold::new();
    let edge = Slow::new(&h, Duration::ZERO);
    let service = open(&h, edge.clone());
    let mut first = mac.session(&service).await;
    mac.register_and_order(&h, &mut first).await;
    // The account carries two changes the base has not copied, so its control
    // record is still the genesis.
    let add = mac.pair(&fold);
    mac.submit_account(&h, &mut first, &add).await;
    let removal = mac.remove(&fold);
    h.order_original(mac.log, removal.as_bytes());
    let mut second = mac.session(&service).await;
    let base = mac.base.0;
    // Registration's replay reads the base log before the first copy is
    // ordered, and that stale answer is held.
    edge.hold(Kind::Controls, mac.base_log(), true);
    let register = mac.register();
    let mut registration = mac.session(&service).await;
    let held = tokio::spawn(async move { registration.handle(register).await });
    edge.held.notified().await;
    // Another connection copies, orders and confirms the first change: the
    // durable control head advances to C1.
    let copy1 = mac.copy(add.as_bytes()).unwrap();
    let permitted1 = first.handle(mac.submit_copy(&copy1)).await;
    order(&h, &permitted1, &copy1).unwrap();
    assert!(matches!(
        first.handle(read(mac.base_log())).await,
        FromService::Refused {
            reason: Refusal::AccountChangePending
        }
    ));
    mac.pull(&h);
    // It then permits the next copy, which stays pending after C1.
    let copy2 = mac.copy(removal.as_bytes()).unwrap();
    let permitted2 = second.handle(mac.submit_copy(&copy2)).await;
    assert!(
        matches!(permitted2, FromService::Permits { .. }),
        "{permitted2:?}"
    );
    assert_eq!(durable_base(&h, base), (2, 1));
    // Releasing the stale replay must neither regress C1 nor drop P2.
    edge.release.add_permits(1);
    let answer = held.await.unwrap();
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    assert_eq!(durable_base(&h, base), (2, 1));
    drop(first);
    drop(second);
    drop(service);
    // Both survive a fresh Store over the same disk.
    let service = open(&h, edge.clone());
    assert_eq!(durable_base(&h, base), (2, 1));
    // The retained pending control is still confirmable after the reload.
    order(&h, &permitted2, &copy2).unwrap();
    let mut reopened = mac.session(&service).await;
    assert!(selected(&reopened.handle(read(mac.base_log())).await));
    assert_eq!(durable_base(&h, base), (3, 0));
}

#[tokio::test(start_paused = true)]
async fn cancelling_one_shared_waiter_keeps_the_flight_for_the_other() {
    let f = fixture(D).await;
    let mut one = session(&f.service, &f.account, &f.device).await;
    let mut two = session(&f.service, &f.account, &f.device).await;
    let before = f.edge.count(Kind::Refresh);
    f.edge.hold(Kind::Refresh, f.account.log, true);
    let log = f.log;
    let first = tokio::spawn(async move { one.handle(read(log)).await });
    f.edge.held.notified().await;
    let second = tokio::spawn(async move { two.handle(read(log)).await });
    tokio::time::sleep(Duration::from_millis(1)).await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    f.edge.release.add_permits(1);
    assert!(selected(&second.await.unwrap()));
    // The surviving waiter kept the shared read alive; none was restarted.
    assert_eq!(f.edge.count(Kind::Refresh) - before, 1);
}

#[tokio::test(start_paused = true)]
async fn cancelling_all_shared_waiters_drops_the_flight_and_the_next_request_reads_again() {
    let mut f = fixture(D).await;
    let mut one = session(&f.service, &f.account, &f.device).await;
    let mut two = session(&f.service, &f.account, &f.device).await;
    let before = f.edge.count(Kind::Refresh);
    f.edge.hold(Kind::Refresh, f.account.log, true);
    let log = f.log;
    let first = tokio::spawn(async move { one.handle(read(log)).await });
    f.edge.held.notified().await;
    let second = tokio::spawn(async move { two.handle(read(log)).await });
    tokio::time::sleep(Duration::from_millis(1)).await;
    first.abort();
    second.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(second.await.unwrap_err().is_cancelled());
    // With no waiter left the flight is gone, so the next request reads again.
    assert!(selected(&f.first.handle(read(log)).await));
    assert_eq!(f.edge.count(Kind::Refresh) - before, 2);
}

#[tokio::test(start_paused = true)]
async fn a_late_joiner_past_the_shared_reads_deadline_is_not_granted() {
    let mut f = fixture(D).await;
    let mut one = session(&f.service, &f.account, &f.device).await;
    let mut two = session(&f.service, &f.account, &f.device).await;
    let before = f.edge.count(Kind::Refresh);
    f.edge.hold(Kind::Refresh, f.account.log, true);
    let log = f.log;
    let first = tokio::spawn(async move { one.handle(read(log)).await });
    f.edge.held.notified().await;
    let second = tokio::spawn(async move { two.handle(read(log)).await });
    tokio::time::sleep(Duration::from_millis(1)).await;
    // The authority clock, not the paused runtime, moves past the flight's
    // original permit deadline while the late joiner waits on it.
    f.h.clock.advance(permit::MAX_PERMIT_WINDOW_MS + 1);
    f.edge.release.add_permits(1);
    assert!(matches!(first.await.unwrap(), FromService::Unavailable));
    assert!(matches!(second.await.unwrap(), FromService::Unavailable));
    assert_eq!(f.edge.count(Kind::Refresh) - before, 1);
    // A request beginning after the advance reads and grants at the new time.
    assert!(selected(&f.first.handle(read(log)).await));
}
