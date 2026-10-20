//! Deduplicated background checkpoint, pending-index backfill, Note maintenance
//! and derived-state work (index builds, parked-work replay, search mappings).
//! Failures retain original rows; the next open/commit or registration re-arms
//! failed work without a retry timer or perpetual retries of a corrupt note.
//! Only Note maintenance waits for the local typing quiet period: derived work
//! is a separate queue item that runs in bounded turns while a Note is typed.
//! A full first repair page or a run of unavailable bodies can stop a drain
//! until the next trigger; it does not spin or skip original rows.
//!
//! Both workers share one locked receive/deferred state, so a deferred quiet
//! deadline is visible to whichever worker waits and a received Maintain is
//! registered before any worker can block indefinitely. Stopping sets a flag
//! checked between items: the item in flight finishes, and a worker already
//! blocked on a database lock cannot observe the flag, so shutdown waits for
//! that item rather than cancelling it.
use crate::ContainerId;
use bh_storage::{DeviceDatabase, NoteKey, StoreError};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    thread,
    time::{Duration, Instant},
};

// Small turns yield to foreground saves and to other containers. Eight repairs
// bound short writer transactions; sixteen bodies bound guard-free decode.
// FTS tokenisation is bounded by body bytes per guarded store chunk, not the
// SQLite VM meter (which still bounds ordinary indexed writes).
const MAX_REPAIRS: usize = 8;
const MAX_BODY_JOBS: usize = 16;
const MAX_STORE_BODY_BYTES: usize = 256 * 1024;
// Longer than the editor's commit interval, shorter than a reading pause.
const NOTE_QUIET_PERIOD: Duration = Duration::from_millis(750);
const MAX_BODY_VM_STEPS: u64 = bh_data::query::Budget::INTERACTIVE.vm_steps;
const STATS_CAPACITY: usize = 64;

/// Local, read-only diagnostics for foreground-wait measurements; no telemetry.
#[derive(Clone, Copy, Debug, Default)]
pub struct MaintenanceTurn {
    pub repair_hold: Duration,
    pub decode: Duration,
    /// Total time spent holding the writer guard across this turn's store sections.
    pub store_hold: Duration,
    /// Longest single guarded store section, so one long hold differs from many short ones.
    pub store_max: Duration,
    pub store_sections: usize,
    /// Sum and longest writer-guard holds for bounded derived-state work.
    pub derived_hold: Duration,
    pub derived_max: Duration,
    /// Time under the writer guard for the quiet, nonblocking WAL checkpoint.
    pub checkpoint_hold: Duration,
    /// Frames backfilled as reported by SQLite after this call (zero when skipped or errored).
    pub checkpoint_frames: i64,
    pub repaired: usize,
    pub attempted: usize,
    pub extracted: usize,
    pub more: bool,
}

struct TurnRing {
    entries: [MaintenanceTurn; STATS_CAPACITY],
    next: usize,
    count: usize,
}
impl Default for TurnRing {
    fn default() -> Self {
        Self {
            entries: [MaintenanceTurn::default(); STATS_CAPACITY],
            next: 0,
            count: 0,
        }
    }
}
impl TurnRing {
    fn push(&mut self, turn: MaintenanceTurn) {
        self.entries[self.next] = turn;
        self.next = (self.next + 1) % STATS_CAPACITY;
        self.count = (self.count + 1).min(STATS_CAPACITY);
    }
    fn snapshot(&self) -> Vec<MaintenanceTurn> {
        (0..self.count)
            .map(|i| self.entries[(self.next + STATS_CAPACITY - self.count + i) % STATS_CAPACITY])
            .collect()
    }
}

type Database = Arc<Mutex<DeviceDatabase>>;
type TurnNotifications = Arc<Mutex<Option<Sender<(ContainerId, usize)>>>>;
enum Work {
    Compact(ContainerId, NoteKey, Weak<Mutex<DeviceDatabase>>),
    Backfill(ContainerId, Weak<Mutex<DeviceDatabase>>),
    Maintain(ContainerId, Weak<Mutex<DeviceDatabase>>),
    Derived(ContainerId, Weak<Mutex<DeviceDatabase>>),
    Stop,
    /// Test support: asks a receiver blocked against a fake clock to recompute
    /// its deadlines. It is not a commit and carries no maintenance state.
    #[cfg(debug_assertions)]
    Wake,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum WorkerEvent {
    Deferred(ContainerId),
    Dispatched(ContainerId),
}
/// In-test acknowledgements that a worker deferred or dispatched a container,
/// and test-only limits on derived turns and checkpoint results. A normal
/// build has none of these, so the worker calls do nothing.
#[derive(Clone, Default)]
struct WorkerEvents {
    #[cfg(test)]
    sender: Option<Sender<WorkerEvent>>,
    /// Derived turns a test still allows. Spent at dispatch, so once it is
    /// zero no worker starts another derived turn and none is requeued.
    #[cfg(debug_assertions)]
    derived_turns: Option<Arc<std::sync::atomic::AtomicUsize>>,
    /// Checkpoint failures a test injects at a turn's checkpoint boundary.
    #[cfg(test)]
    checkpoint_faults: Option<Arc<std::sync::atomic::AtomicUsize>>,
}
impl WorkerEvents {
    fn start_derived(&self) -> bool {
        #[cfg(debug_assertions)]
        if let Some(turns) = &self.derived_turns {
            return turns
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                .is_ok();
        }
        true
    }
    fn continue_derived(&self) -> bool {
        #[cfg(debug_assertions)]
        if let Some(turns) = &self.derived_turns {
            return turns.load(Ordering::Acquire) > 0;
        }
        true
    }
    fn checkpoint(&self, db: &DeviceDatabase) -> Result<i64, StoreError> {
        #[cfg(test)]
        if let Some(faults) = &self.checkpoint_faults
            && faults
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                .is_ok()
        {
            return Err(StoreError::Io(std::io::Error::other("injected checkpoint")));
        }
        db.checkpoint_wal_if_needed()
    }
    fn deferred(&self, _id: ContainerId) {
        #[cfg(test)]
        if let Some(sender) = &self.sender {
            let _ = sender.send(WorkerEvent::Deferred(_id));
        }
    }
    fn dispatched(&self, _id: ContainerId) {
        #[cfg(test)]
        if let Some(sender) = &self.sender {
            let _ = sender.send(WorkerEvent::Dispatched(_id));
        }
    }
}
#[derive(Clone, Copy)]
struct MaintenanceState {
    generation: u64,
    last_local: Option<Instant>,
}
pub struct Scheduler {
    sender: Sender<Work>,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
    stop: Arc<AtomicBool>,
    enabled: AtomicBool,
    #[cfg(debug_assertions)]
    notifications: TurnNotifications,
    active: Arc<Mutex<HashSet<(ContainerId, NoteKey)>>>,
    backfilling: Arc<Mutex<HashSet<ContainerId>>>,
    maintaining: Arc<Mutex<HashMap<ContainerId, MaintenanceState>>>,
    /// Queued derived work per container, with a generation bumped by each
    /// trigger while a turn is queued or running.
    deriving: Arc<Mutex<HashMap<ContainerId, u64>>>,
    stats: Arc<Mutex<HashMap<ContainerId, TurnRing>>>,
    workers: Vec<thread::JoinHandle<()>>,
}
impl Default for Scheduler {
    fn default() -> Self {
        Self::with_clock(Instant::now, NOTE_QUIET_PERIOD)
    }
}
impl Scheduler {
    fn with_clock(now: impl Fn() -> Instant + Send + Sync + 'static, quiet: Duration) -> Self {
        Self::start(now, quiet, WorkerEvents::default())
    }
    fn start(
        now: impl Fn() -> Instant + Send + Sync + 'static,
        quiet: Duration,
        events: WorkerEvents,
    ) -> Self {
        let now: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(now);
        let stop = Arc::new(AtomicBool::new(false));
        let notifications: TurnNotifications = Arc::new(Mutex::new(None));
        let (sender, receiver) = mpsc::channel::<Work>();
        let active = Arc::new(Mutex::new(HashSet::new()));
        let backfilling = Arc::new(Mutex::new(HashSet::new()));
        let maintaining = Arc::new(Mutex::new(HashMap::new()));
        let deriving = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(Mutex::new(HashMap::new()));
        let shared = Arc::new(Mutex::new(ReceiverState {
            receiver,
            deferred: HashMap::new(),
        }));
        // Two process workers: a large note or one account's v5 migration
        // cannot monopolise every account's background progress. Each SQL
        // section reads at most one 256-row/256-KiB page or backfill batch.
        let mut workers = Vec::with_capacity(2);
        for n in 0..2 {
            let shared = Arc::clone(&shared);
            let queues = Queues {
                active: Arc::clone(&active),
                backfilling: Arc::clone(&backfilling),
                maintaining: Arc::clone(&maintaining),
                deriving: Arc::clone(&deriving),
                stats: Arc::clone(&stats),
            };
            let sender = sender.clone();
            let now = Arc::clone(&now);
            let stop = Arc::clone(&stop);
            let notifications = Arc::clone(&notifications);
            let events = events.clone();
            workers.push(
                thread::Builder::new()
                    .name(format!("bh-local-compaction-{n}"))
                    .spawn(move || {
                        run_worker(
                            shared,
                            sender,
                            queues,
                            now,
                            quiet,
                            stop,
                            notifications,
                            events,
                        )
                    })
                    .expect("background compaction worker"),
            );
        }
        Self {
            sender,
            now,
            stop,
            enabled: AtomicBool::new(true),
            #[cfg(debug_assertions)]
            notifications,
            active,
            backfilling,
            maintaining,
            deriving,
            stats,
            workers,
        }
    }
}
impl Drop for Scheduler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Worker-held senders keep the channel connected after this sender drops.
        for _ in 0..self.workers.len() {
            let _ = self.sender.send(Work::Stop);
        }
        // Stop is after the item in flight, not a cancellation: a worker can
        // still own the database while decoding or be blocked acquiring it.
        // Wait until it releases that Arc before the caller reopens the file.
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
impl Scheduler {
    /// Test support: report completed maintenance turns, including empty probes.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn notifying(sender: Sender<(ContainerId, usize)>) -> Self {
        let scheduler = Self::without_maintenance_delay();
        *scheduler
            .notifications
            .lock()
            .expect("maintenance notification lock") = Some(sender);
        scheduler
    }
    /// Test support: like [`Self::notifying`], but workers start at most
    /// `turns` derived turns. The budget is spent when a turn starts, before
    /// its completion is reported, so a test that has received the last
    /// allowed turn's report knows no worker runs or requeues another.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn notifying_with_derived_turns(
        sender: Sender<(ContainerId, usize)>,
        turns: usize,
    ) -> Self {
        let events = WorkerEvents {
            #[cfg(test)]
            sender: None,
            derived_turns: Some(Arc::new(std::sync::atomic::AtomicUsize::new(turns))),
            #[cfg(test)]
            checkpoint_faults: None,
        };
        let scheduler = Self::start(Instant::now, Duration::ZERO, events);
        *scheduler
            .notifications
            .lock()
            .expect("maintenance notification lock") = Some(sender);
        scheduler
    }
    /// Test support: disable only maintenance; checkpoint and backfill stay on.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn without_maintenance() -> Self {
        let scheduler = Self::default();
        scheduler.enabled.store(false, Ordering::Release);
        scheduler
    }
    /// Test support: queued maintenance has no quiet period.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn without_maintenance_delay() -> Self {
        Self::with_clock(Instant::now, Duration::ZERO)
    }
    /// Test support: allow a paused worker to resume from durable markers.
    #[cfg(debug_assertions)]
    pub fn resume_maintenance(&self) {
        self.enabled.store(true, Ordering::Release);
    }
    /// Test support: a notifying scheduler on a caller-driven clock. After
    /// moving the clock, [`Self::wake`] lets a waiting worker recompute its
    /// deadlines; time never passes by itself.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn notifying_with_clock(
        sender: Sender<(ContainerId, usize)>,
        now: impl Fn() -> Instant + Send + Sync + 'static,
        quiet: Duration,
    ) -> Self {
        let scheduler = Self::with_clock(now, quiet);
        *scheduler
            .notifications
            .lock()
            .expect("maintenance notification lock") = Some(sender);
        scheduler
    }
    /// Test support: wake a receiver waiting on a fake clock, without a commit.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn wake(&self) {
        let _ = self.sender.send(Work::Wake);
    }
    /// Test support: whether the container has no maintenance or derived
    /// turn queued, deferred or running. Read it after a turn's completion:
    /// a turn decides whether it continues before acknowledging.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn idle(&self, id: ContainerId) -> bool {
        !self
            .maintaining
            .lock()
            .expect("maintenance set lock")
            .contains_key(&id)
            && !self
                .deriving
                .lock()
                .expect("derived set lock")
                .contains_key(&id)
    }
    pub fn maintenance_stats(&self, id: ContainerId) -> Vec<MaintenanceTurn> {
        self.stats
            .lock()
            .expect("maintenance stats lock")
            .get(&id)
            .map_or_else(Vec::new, TurnRing::snapshot)
    }
    pub fn schedule_local_maintenance(&self, id: ContainerId, database: &Database) {
        self.schedule_maintenance_at(id, database, Some((self.now)()));
    }
    pub fn schedule_maintenance(&self, id: ContainerId, database: &Database) {
        self.schedule_maintenance_at(id, database, None);
    }
    fn schedule_maintenance_at(
        &self,
        id: ContainerId,
        database: &Database,
        local: Option<Instant>,
    ) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        queue_maintenance(
            &self.sender,
            &self.maintaining,
            id,
            Arc::downgrade(database),
            local,
        );
    }
    /// Queue one bounded derived-state turn. It never waits for, renews or
    /// shortens a Note's quiet period.
    pub fn schedule_derived(&self, id: ContainerId, database: &Database) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let mut queued = self.deriving.lock().expect("derived set lock");
        if let Some(generation) = queued.get_mut(&id) {
            *generation = generation.wrapping_add(1);
            return;
        }
        queued.insert(id, 0);
        if self
            .sender
            .send(Work::Derived(id, Arc::downgrade(database)))
            .is_err()
        {
            queued.remove(&id);
        }
    }
    /// Queue derived work only when durable markers ask for it: one indexed
    /// probe under the writer guard, so opening or syncing an idle container
    /// starts no turn. A failed probe leaves the markers for the next trigger.
    pub fn schedule_derived_if_pending(&self, id: ContainerId, database: &Database) {
        let pending = database
            .lock()
            .expect("container writer lock")
            .derived_pending()
            .unwrap_or(false);
        if pending {
            self.schedule_derived(id, database);
        }
    }
    pub fn schedule_backfill(&self, id: ContainerId, database: &Database) {
        let mut active = self.backfilling.lock().expect("backfill set lock");
        if !active.insert(id) {
            return;
        }
        if self
            .sender
            .send(Work::Backfill(id, Arc::downgrade(database)))
            .is_err()
        {
            active.remove(&id);
        }
    }
    pub fn schedule(&self, id: ContainerId, key: NoteKey, database: &Database) {
        let mut active = self.active.lock().expect("compaction set lock");
        if !active.insert((id, key)) {
            return;
        }
        if self
            .sender
            .send(Work::Compact(id, key, Arc::downgrade(database)))
            .is_err()
        {
            active.remove(&(id, key));
        }
    }
}
// A non-local trigger changes the generation of an active turn but never
// changes its Note quiet deadline.
fn queue_maintenance(
    sender: &Sender<Work>,
    maintaining: &Mutex<HashMap<ContainerId, MaintenanceState>>,
    id: ContainerId,
    weak: Weak<Mutex<DeviceDatabase>>,
    local: Option<Instant>,
) {
    let mut active = maintaining.lock().expect("maintenance set lock");
    if let Some(state) = active.get_mut(&id) {
        state.generation = state.generation.wrapping_add(1);
        if let Some(local) = local {
            state.last_local = Some(local);
        }
        return;
    }
    active.insert(
        id,
        MaintenanceState {
            generation: 0,
            last_local: local,
        },
    );
    if sender.send(Work::Maintain(id, weak)).is_err() {
        active.remove(&id);
    }
}

fn quiet_remaining(
    state: Option<&MaintenanceState>,
    now: Instant,
    quiet: Duration,
) -> Option<Duration> {
    state?
        .last_local?
        .checked_add(quiet)?
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
}

/// Receive ownership and the quiet-deferred set are one locked state. Whoever
/// owns the receiver also sees every pending deadline, so a Maintain handed to
/// a worker is registered before any worker can wait indefinitely, and the
/// timeout is always the earliest deadline across containers. A commit renews a
/// deadline without waiting for this lock; a timeout recomputes against it.
struct ReceiverState {
    receiver: Receiver<Work>,
    deferred: HashMap<ContainerId, Weak<Mutex<DeviceDatabase>>>,
}

/// Returns the next runnable work and releases receive ownership before the
/// caller executes it. No caller holds receive state across a database lock,
/// decode or store.
fn next_work(
    shared: &Mutex<ReceiverState>,
    maintaining: &Mutex<HashMap<ContainerId, MaintenanceState>>,
    now: &(dyn Fn() -> Instant + Send + Sync),
    quiet: Duration,
    stop: &AtomicBool,
    events: &WorkerEvents,
) -> Option<Work> {
    let mut shared = shared.lock().expect("compaction receive lock");
    loop {
        if stop.load(Ordering::Acquire) {
            return None;
        }
        let (ready, wait) = {
            let state = maintaining.lock().expect("maintenance set lock");
            let instant = now();
            let ready = shared
                .deferred
                .keys()
                .find(|id| quiet_remaining(state.get(id), instant, quiet).is_none())
                .copied();
            let wait = shared
                .deferred
                .keys()
                .filter_map(|id| quiet_remaining(state.get(id), instant, quiet))
                .min();
            (ready, wait)
        };
        if let Some(id) = ready {
            let weak = shared
                .deferred
                .remove(&id)
                .expect("deferred maintenance entry");
            return Some(Work::Maintain(id, weak));
        }
        let received = match wait {
            Some(wait) => match shared.receiver.recv_timeout(wait) {
                Ok(work) => work,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return None,
            },
            None => match shared.receiver.recv() {
                Ok(work) => work,
                Err(_) => return None,
            },
        };
        match received {
            Work::Maintain(id, weak) => {
                let defer = {
                    let state = maintaining.lock().expect("maintenance set lock");
                    quiet_remaining(state.get(&id), now(), quiet).is_some()
                };
                if defer {
                    // Deferring under receive ownership is what stops a peer
                    // starting an indefinite receive against it.
                    shared.deferred.insert(id, weak);
                    events.deferred(id);
                    continue;
                }
                return Some(Work::Maintain(id, weak));
            }
            work => return Some(work),
        }
    }
}

/// The deduplication and diagnostics state every worker shares.
#[derive(Clone, Default)]
struct Queues {
    active: Arc<Mutex<HashSet<(ContainerId, NoteKey)>>>,
    backfilling: Arc<Mutex<HashSet<ContainerId>>>,
    maintaining: Arc<Mutex<HashMap<ContainerId, MaintenanceState>>>,
    deriving: Arc<Mutex<HashMap<ContainerId, u64>>>,
    stats: Arc<Mutex<HashMap<ContainerId, TurnRing>>>,
}
impl Queues {
    /// Records a completed turn, then acknowledges it to a test listener, so
    /// an acknowledged turn's diagnostics are already readable.
    fn completed(&self, id: ContainerId, turn: MaintenanceTurn, notifications: &TurnNotifications) {
        self.stats
            .lock()
            .expect("maintenance stats lock")
            .entry(id)
            .or_default()
            .push(turn);
        if let Some(sender) = notifications
            .lock()
            .expect("maintenance notification lock")
            .as_ref()
        {
            let _ = sender.send((id, turn.extracted));
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "shared queue state, quiet gate and test acknowledgements"
)]
fn run_worker(
    shared: Arc<Mutex<ReceiverState>>,
    sender: Sender<Work>,
    queues: Queues,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
    quiet: Duration,
    stop: Arc<AtomicBool>,
    notifications: TurnNotifications,
    events: WorkerEvents,
) {
    let Queues {
        active,
        backfilling,
        maintaining,
        deriving,
        ..
    } = &queues;
    loop {
        let Some(work) = next_work(&shared, maintaining, now.as_ref(), quiet, &stop, &events)
        else {
            break;
        };
        if stop.load(Ordering::Acquire) {
            break;
        }
        match work {
            Work::Stop => break,
            #[cfg(debug_assertions)]
            Work::Wake => continue,
            Work::Compact(id, key, weak) => {
                if let Some(db) = weak.upgrade() {
                    let _ = compact(&db, key);
                }
                active
                    .lock()
                    .expect("compaction set lock")
                    .remove(&(id, key));
            }
            Work::Maintain(id, weak) => {
                // Recheck after dispatch. A commit that renewed quiet in this
                // window hands the work back to the shared scheduler instead
                // of starting a turn or parking it in a private map.
                let (generation, renewed) = {
                    let state = maintaining.lock().expect("maintenance set lock");
                    (
                        state.get(&id).map(|state| state.generation),
                        quiet_remaining(state.get(&id), now(), quiet),
                    )
                };
                if renewed.is_some() {
                    let _ = sender.send(Work::Maintain(id, weak));
                    continue;
                }
                events.dispatched(id);
                let turn = weak.upgrade().map(|db| {
                    maintenance_turn_with_hooks(&db, || {}, || {}, |db| events.checkpoint(db))
                });
                if let Some(Ok(turn)) = turn {
                    let mut active = maintaining.lock().expect("maintenance set lock");
                    let newly_scheduled =
                        active.get(&id).map(|state| state.generation) != generation;
                    let requeue = turn.more || newly_scheduled;
                    if !requeue {
                        active.remove(&id);
                    }
                    drop(active);
                    queues.completed(id, turn, &notifications);
                    if requeue {
                        let _ = sender.send(Work::Maintain(id, weak));
                    }
                } else {
                    // Failure or dropped container: retain original rows and
                    // let the next commit/open re-arm, without a retry timer.
                    maintaining
                        .lock()
                        .expect("maintenance set lock")
                        .remove(&id);
                }
            }
            Work::Derived(id, weak) => {
                // Never gated by the Note quiet clock. A queued or running
                // turn absorbs further triggers into its generation.
                let generation = deriving.lock().expect("derived set lock").get(&id).copied();
                let turn = events
                    .start_derived()
                    .then(|| weak.upgrade().map(|db| derived_turn(&db)))
                    .flatten();
                if let Some(Ok(turn)) = turn {
                    let mut queued = deriving.lock().expect("derived set lock");
                    let newly_scheduled = queued.get(&id).copied() != generation;
                    let requeue = (turn.more || newly_scheduled) && events.continue_derived();
                    if !requeue {
                        queued.remove(&id);
                    }
                    drop(queued);
                    if !requeue && !turn.more && turn.derived_hold > Duration::ZERO {
                        // A final derived batch can create Note body jobs. Arm
                        // extraction even if no further foreground event arrives.
                        queue_maintenance(&sender, maintaining, id, weak.clone(), None);
                    }
                    queues.completed(id, turn, &notifications);
                    if requeue {
                        let _ = sender.send(Work::Derived(id, weak));
                    }
                } else {
                    // Failure, a dropped container or a spent test budget:
                    // markers stay durable and the next trigger re-arms them.
                    deriving.lock().expect("derived set lock").remove(&id);
                }
            }
            Work::Backfill(id, weak) => {
                let step = weak.upgrade().map(|db| {
                    db.lock()
                        .expect("container writer lock")
                        .backfill_pending_scope(256)
                });
                // A successful incomplete batch yields behind other work.
                // Failure drops the active entry; the next open/registration
                // re-arms it, rather than spinning on a broken database.
                if matches!(step, Some(Ok(false))) && sender.send(Work::Backfill(id, weak)).is_ok()
                {
                    continue;
                }
                backfilling.lock().expect("backfill set lock").remove(&id);
            }
        }
    }
}

#[cfg(test)]
fn maintenance_turn(
    database: &Database,
    before_decode: impl FnOnce(),
) -> Result<MaintenanceTurn, StoreError> {
    maintenance_turn_with_hooks(
        database,
        before_decode,
        || {},
        |db| db.checkpoint_wal_if_needed(),
    )
}
fn maintenance_turn_with_hooks(
    database: &Database,
    before_decode: impl FnOnce(),
    mut on_store: impl FnMut(),
    checkpoint: impl FnOnce(&DeviceDatabase) -> Result<i64, StoreError>,
) -> Result<MaintenanceTurn, StoreError> {
    let mut turn = MaintenanceTurn::default();
    let source = {
        let mut db = database.lock().expect("container writer lock");
        let start = Instant::now();
        turn.repaired = db.repair_projections(MAX_REPAIRS)?;
        let source = db.note_body_source();
        drop(db);
        turn.repair_hold = start.elapsed();
        source
    };
    let start = Instant::now();
    before_decode(); // Hook before selection, after releasing the writer guard.
    let batch = source
        .map(|source| source.next_batch(MAX_BODY_JOBS))
        .transpose()?
        .unwrap_or_default();
    turn.decode = start.elapsed();
    let batch_len = batch.len();
    let mut cursor = 0;
    while cursor < batch_len {
        let start = cursor;
        let mut bytes = 0;
        while cursor < batch_len {
            let size = batch[cursor].body.as_ref().map_or(0, |body| body.len());
            if cursor > start && bytes + size > MAX_STORE_BODY_BYTES {
                break;
            }
            bytes += size;
            cursor += 1;
        }
        let mut db = database.lock().expect("container writer lock");
        let start_hold = Instant::now();
        on_store();
        let stored = db.store_body_batch(&batch[start..cursor], MAX_BODY_VM_STEPS);
        drop(db);
        let hold = start_hold.elapsed();
        turn.store_hold += hold;
        turn.store_max = turn.store_max.max(hold);
        turn.store_sections += 1;
        let stored = stored?;
        turn.attempted += stored.attempted;
        turn.extracted += stored.extracted;
        if stored.attempted < cursor - start {
            break; // The VM budget stopped inside this chunk; later jobs await the next turn.
        }
    }
    {
        let db = database.lock().expect("container writer lock");
        let start = Instant::now();
        let result = checkpoint(&db);
        turn.checkpoint_hold = start.elapsed();
        turn.checkpoint_frames = result.unwrap_or(0);
    }
    let progress = turn.repaired > 0 || turn.extracted > 0;
    turn.more = progress
        && (turn.repaired == MAX_REPAIRS
            || batch_len == MAX_BODY_JOBS
            || turn.attempted < batch_len);
    Ok(turn)
}

/// One derived-state turn: at most one index or rebuild batch, one parked
/// replay page and one search-mapping batch. Each has its own committed
/// transaction and released writer guard; continuation goes back through the
/// worker queue rather than looping ahead of foreground work.
fn derived_turn(database: &Database) -> Result<MaintenanceTurn, StoreError> {
    let mut turn = MaintenanceTurn::default();
    if !database
        .lock()
        .expect("container writer lock")
        .derived_pending()?
    {
        return Ok(turn);
    }
    for step in [
        bh_storage::DeviceDatabase::derived_index_step,
        bh_storage::DeviceDatabase::derived_replay_step,
        bh_storage::DeviceDatabase::derived_reproject_step,
    ] {
        let mut db = database.lock().expect("container writer lock");
        let start = Instant::now();
        let result = step(&mut db, MAX_BODY_VM_STEPS);
        let hold = start.elapsed();
        drop(db);
        turn.derived_hold += hold;
        turn.derived_max = turn.derived_max.max(hold);
        result?;
    }
    turn.more = database
        .lock()
        .expect("container writer lock")
        .derived_pending()?;
    Ok(turn)
}

fn compact(database: &Database, key: NoteKey) -> Result<(), StoreError> {
    let seed = {
        let db = database.lock().expect("container writer lock");
        if !db.checkpoint_due(key)? {
            return Ok(());
        }
        db.begin_checkpoint(key)?
    };
    let Some(seed) = seed else { return Ok(()) };
    let mut job = seed.start()?; // decode the prior checkpoint outside guards
    loop {
        let page = database
            .lock()
            .expect("container writer lock")
            .checkpoint_page(&job, 256)?;
        if page.is_empty() {
            break;
        }
        job.apply_page(&page)?;
    }
    if let Some(encoded) = job.finish()? {
        database
            .lock()
            .expect("container writer lock")
            .publish_checkpoint(&encoded)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Scheduler;
    use std::sync::Arc;

    // Missing maintenance wiring must fail these tests: they check durable
    // text jobs and projection repair, not just worker invocation counts.
    fn seeded(count: usize) -> (tempfile::TempDir, super::Database) {
        seeded_with_body(count, 0)
    }
    fn seeded_with_body(count: usize, extra: usize) -> (tempfile::TempDir, super::Database) {
        let dir = tempfile::tempdir().unwrap();
        let mut db = bh_storage::DeviceDatabase::open(dir.path().join("notes.db")).unwrap();
        db.commit_account_verified([4; 32], &[b"genesis"], 1, [5; 32], false)
            .unwrap();
        for n in 0..count {
            let note = db.create_note([2; 32], [0; 32]).unwrap();
            let mut body = bh_core::note::Note::new().unwrap();
            let delta = body
                .append_paragraph(&format!("paragraph {n}{}", "x".repeat(extra)))
                .unwrap();
            db.commit_working_update_with_title(
                bh_storage::NoteKey {
                    base: [2; 32],
                    audience: [0; 32],
                    note,
                },
                0,
                [4; 32],
                [n as u8; 16],
                &delta,
                "paragraph",
            )
            .unwrap();
        }
        (dir, Arc::new(std::sync::Mutex::new(db)))
    }

    fn pending(dir: &tempfile::TempDir) -> i64 {
        rusqlite::Connection::open(dir.path().join("notes.db"))
            .unwrap()
            .query_row("SELECT count(*) FROM data_text_job", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn derived_rebuild_arms_body_extraction_without_another_trigger() {
        let (dir, db) = seeded(1);
        assert_eq!(pending(&dir), 1);
        super::maintenance_turn(&db, || {}).unwrap();
        assert_eq!(pending(&dir), 0);
        db.lock()
            .unwrap()
            .with_data_write(|tx| {
                bh_data::index::begin_rebuild(tx)?;
                Ok(())
            })
            .unwrap();
        let id = crate::ContainerId([19; 16]);
        let live = Live::new(std::time::Duration::ZERO);
        live.scheduler.schedule_derived(id, &db);
        for _ in 0..20 {
            let (finished, extracted) = live.next_completion();
            assert_eq!(finished, id);
            if extracted > 0 {
                assert_eq!(pending(&dir), 0);
                return;
            }
        }
        panic!("derived rebuild never armed body extraction");
    }

    #[test]
    fn quiet_turn_checkpoints_a_populated_wal_and_records_guard_hold() {
        let (_dir, db) = seeded(16);
        let turn = super::maintenance_turn(&db, || {}).unwrap();
        assert!(
            turn.checkpoint_frames > 0,
            "quiet turn must checkpoint dirty WAL pages"
        );
        assert!(turn.checkpoint_hold > std::time::Duration::ZERO);
        let (_busy, log, checkpointed): (i64, i64, i64) = db
            .lock()
            .unwrap()
            .with_data_read(|conn| {
                Ok(conn
                    .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                    .unwrap())
            })
            .unwrap();
        assert_eq!(log, checkpointed, "quiet turn left no uncheckpointed pages");
    }

    #[test]
    fn failed_checkpoint_does_not_fail_committed_maintenance() {
        let (dir, db) = seeded(16);
        super::maintenance_turn(&db, || {}).unwrap();
        let wal = dir.path().join("notes.db-wal");
        let held = dir.path().join("held-wal");
        std::fs::rename(&wal, &held).unwrap();
        std::os::unix::fs::symlink(&wal, &wal).unwrap();
        let result = super::maintenance_turn(&db, || {});
        std::fs::remove_file(&wal).unwrap();
        std::fs::rename(held, wal).unwrap();
        let turn = result.unwrap();
        assert_eq!(turn.checkpoint_frames, 0);
    }

    #[test]
    fn checkpoint_error_keeps_a_storing_turn_and_its_continuation() {
        // More bodies than one turn stores, so the failing turn has more work.
        let (dir, db) = seeded(35);
        let id = crate::ContainerId([13; 16]);
        let faults = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let live =
            Live::with_checkpoint_faults(std::time::Duration::ZERO, Some(Arc::clone(&faults)));
        live.scheduler.schedule_maintenance(id, &db);
        live.expect_dispatched(id);
        // The completion is reported after its diagnostics are recorded.
        let (done, extracted) = live.next_completion();
        assert_eq!((done, extracted), (id, super::MAX_BODY_JOBS));
        assert_eq!(faults.load(std::sync::atomic::Ordering::Acquire), 0);
        let failed = live.scheduler.maintenance_stats(id)[0];
        assert_eq!(failed.extracted, super::MAX_BODY_JOBS);
        assert_eq!(failed.checkpoint_frames, 0, "the injected error is a skip");
        assert!(failed.more, "the failed checkpoint kept the continuation");
        // The worker continues from the committed bodies without a new trigger.
        // Follow the turns' own continuation flags rather than the job count:
        // the worker may finish the next turn before this thread looks again.
        let mut turns = 1;
        while live.scheduler.maintenance_stats(id)[turns - 1].more {
            live.expect_dispatched(id);
            assert_eq!(live.next_completion().0, id);
            turns += 1;
            assert!(turns < 10);
        }
        assert_eq!(pending(&dir), 0);
        let stats = live.scheduler.maintenance_stats(id);
        assert_eq!(stats.len(), turns);
        assert!(stats[1].checkpoint_frames > 0, "the next turn checkpoints");
        assert_eq!(stats.iter().map(|t| t.extracted).sum::<usize>(), 35);
    }

    #[test]
    fn bounded_turns_drain_upgrade_sized_body_queue() {
        let (dir, db) = seeded(35);
        let mut turns = 0;
        while super::maintenance_turn(&db, || {}).unwrap().more {
            turns += 1;
            assert!(turns < 10, "each turn must make progress");
        }
        assert!(turns >= 2, "a turn must not consume the entire queue");
        assert_eq!(pending(&dir), 0);
    }

    fn seeded_index(count: usize) -> (tempfile::TempDir, super::Database, i64) {
        let (dir, db) = seeded(count);
        let ix = db
            .lock()
            .unwrap()
            .with_data_write(|tx| {
                let sid = bh_data::store::records::lookup_scope(
                    tx,
                    bh_data::Scope {
                        base: [2; 32],
                        audience: [0; 32],
                    },
                )?
                .unwrap();
                bh_data::index::ensure_local(
                    tx,
                    sid,
                    bh_data::TypeId::core("note"),
                    vec![bh_data::KeyRef::Field(
                        bh_data::FieldPath::parse("/title").unwrap(),
                    )],
                )
            })
            .unwrap();
        assert_eq!(
            db.lock()
                .unwrap()
                .with_data_read(|conn| bh_data::index::state(conn, ix))
                .unwrap()
                .state,
            "building"
        );
        (dir, db, ix)
    }

    #[test]
    fn derived_turns_drive_a_populated_local_index_to_ready() {
        let (_dir, db, ix) = seeded_index(510);
        let mut turns = 0;
        loop {
            let turn = super::derived_turn(&db).unwrap();
            turns += 1;
            if !turn.more {
                break;
            }
            assert!(
                turns < 300,
                "bounded maintenance must progress: {:?}",
                db.lock()
                    .unwrap()
                    .with_data_read(|conn| bh_data::index::state(conn, ix))
                    .unwrap()
            );
        }
        assert!(turns >= 2);
        assert_eq!(
            db.lock()
                .unwrap()
                .with_data_read(|conn| bh_data::index::state(conn, ix))
                .unwrap()
                .state,
            "ready"
        );
    }

    #[test]
    fn worker_resumes_an_interrupted_index_after_reopen() {
        let (dir, db, ix) = seeded_index(510);
        let turn = super::derived_turn(&db).unwrap();
        assert!(turn.more);
        assert_eq!(
            db.lock()
                .unwrap()
                .with_data_read(|conn| bh_data::index::state(conn, ix))
                .unwrap()
                .state,
            "building"
        );
        drop(db);
        let reopened = Arc::new(std::sync::Mutex::new(
            bh_storage::DeviceDatabase::open(dir.path().join("notes.db")).unwrap(),
        ));
        let (tx, rx) = std::sync::mpsc::channel();
        let scheduler = Scheduler::notifying(tx);
        let id = crate::ContainerId([7; 16]);
        scheduler.schedule_derived_if_pending(id, &reopened);
        for _ in 0..300 {
            let (completed, _) = rx.recv_timeout(HUNG).unwrap();
            assert_eq!(completed, id);
            if reopened
                .lock()
                .unwrap()
                .with_data_read(|conn| bh_data::index::state(conn, ix))
                .unwrap()
                .state
                == "ready"
            {
                assert!(!reopened.lock().unwrap().derived_pending().unwrap());
                return;
            }
        }
        panic!("worker failed to resume the persisted index cursor");
    }

    #[test]
    fn scheduler_requeues_only_bounded_turns_behind_other_work() {
        let (dir, db) = seeded(35);
        let id = crate::ContainerId([9; 16]);
        let (sender, receiver) = std::sync::mpsc::channel();
        let shared = Arc::new(std::sync::Mutex::new(super::ReceiverState {
            receiver,
            deferred: Default::default(),
        }));
        let maintaining = Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([(
            id,
            super::MaintenanceState {
                generation: 0,
                last_local: None,
            },
        )])));
        let stats = Arc::new(std::sync::Mutex::new(Default::default()));
        sender
            .send(super::Work::Maintain(id, Arc::downgrade(&db)))
            .unwrap();
        let mut turns = 0;
        loop {
            // The stop is a deterministic other queue item: one worker can
            // execute at most one turn before yielding behind it.
            sender.send(super::Work::Stop).unwrap();
            super::run_worker(
                Arc::clone(&shared),
                sender.clone(),
                super::Queues {
                    maintaining: Arc::clone(&maintaining),
                    stats: Arc::clone(&stats),
                    ..Default::default()
                },
                Arc::new(std::time::Instant::now),
                std::time::Duration::ZERO,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                Arc::new(std::sync::Mutex::new(None)),
                super::WorkerEvents::default(),
            );
            turns += 1;
            assert!(turns < 10);
            if !maintaining.lock().unwrap().contains_key(&id) {
                break;
            }
            assert!(pending(&dir) > 0);
        }
        assert!(turns >= 3);
        assert_eq!(pending(&dir), 0);
        assert_eq!(stats.lock().unwrap().get(&id).unwrap().count, turns);
    }

    const HUNG: std::time::Duration = std::time::Duration::from_secs(10);

    /// The real two workers behind a fake clock, with deterministic
    /// acknowledgements for quiet deferral and dispatch. Completing a turn
    /// notifies through the production notification channel.
    struct Live {
        clock: Arc<std::sync::Mutex<std::time::Instant>>,
        scheduler: Scheduler,
        events: std::sync::mpsc::Receiver<super::WorkerEvent>,
        completed: std::sync::mpsc::Receiver<(crate::ContainerId, usize)>,
    }
    impl Live {
        fn new(quiet: std::time::Duration) -> Self {
            Self::with_checkpoint_faults(quiet, None)
        }
        fn with_checkpoint_faults(
            quiet: std::time::Duration,
            faults: Option<Arc<std::sync::atomic::AtomicUsize>>,
        ) -> Self {
            let clock = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
            let (events_sender, events) = std::sync::mpsc::channel();
            let scheduler = {
                let clock = Arc::clone(&clock);
                let events = super::WorkerEvents {
                    sender: Some(events_sender),
                    checkpoint_faults: faults,
                    ..Default::default()
                };
                Scheduler::start(move || *clock.lock().unwrap(), quiet, events)
            };
            let (completed_sender, completed) = std::sync::mpsc::channel();
            *scheduler.notifications.lock().unwrap() = Some(completed_sender);
            Self {
                clock,
                scheduler,
                events,
                completed,
            }
        }
        fn schedule_local(&self, id: crate::ContainerId, db: &super::Database) {
            self.scheduler.schedule_local_maintenance(id, db);
        }
        /// Advances the fake clock, then wakes a receiver waiting on a deadline
        /// computed before the advance. The wake is not a commit.
        fn advance(&self, elapsed: std::time::Duration) {
            *self.clock.lock().unwrap() += elapsed;
            self.scheduler.wake();
        }
        fn next_event(&self) -> super::WorkerEvent {
            self.events
                .recv_timeout(HUNG)
                .expect("worker scheduling acknowledgement")
        }
        fn next_completion(&self) -> (crate::ContainerId, usize) {
            self.completed
                .recv_timeout(HUNG)
                .expect("worker maintenance completion")
        }
        fn expect_deferred(&self, want: crate::ContainerId) {
            match self.next_event() {
                super::WorkerEvent::Deferred(id) => assert_eq!(id, want, "unexpected deferral"),
                super::WorkerEvent::Dispatched(id) => panic!("dispatched {id:?} inside quiet time"),
            }
        }
        fn expect_dispatched(&self, want: crate::ContainerId) {
            match self.next_event() {
                super::WorkerEvent::Dispatched(id) => assert_eq!(id, want, "unexpected dispatch"),
                super::WorkerEvent::Deferred(id) => {
                    panic!("deferred {id:?} instead of dispatching it")
                }
            }
        }
        fn no_more_events(&self) {
            assert!(
                matches!(
                    self.events.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ),
                "an unexpected worker event arrived"
            );
        }
    }

    fn note_key(dir: &tempfile::TempDir) -> (rusqlite::Connection, bh_storage::NoteKey) {
        let raw = rusqlite::Connection::open(dir.path().join("notes.db")).unwrap();
        let note: [u8; 32] = raw
            .query_row("SELECT note FROM notes LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let key = bh_storage::NoteKey {
            base: [2; 32],
            audience: [0; 32],
            note,
        };
        (raw, key)
    }

    #[test]
    fn fake_clock_keeps_checkpoint_outside_the_quiet_period() {
        let (_dir, db) = seeded(16);
        let id = crate::ContainerId([11; 16]);
        let live = Live::new(std::time::Duration::from_secs(20));
        live.schedule_local(id, &db);
        live.expect_deferred(id);
        assert!(live.scheduler.maintenance_stats(id).is_empty());
        live.no_more_events();
        live.advance(std::time::Duration::from_secs(21));
        live.expect_dispatched(id);
        assert_eq!(live.next_completion().0, id);
        assert!(
            live.scheduler
                .maintenance_stats(id)
                .iter()
                .any(|t| t.checkpoint_frames > 0)
        );
    }

    #[test]
    fn derived_work_completes_while_a_note_keeps_renewing_quiet() {
        let (dir, db, ix) = seeded_index(510);
        let id = crate::ContainerId([12; 16]);
        let live = Live::new(std::time::Duration::from_millis(750));
        let bodies = pending(&dir);
        assert!(bodies > 0);
        live.schedule_local(id, &db);
        live.expect_deferred(id);
        live.scheduler.schedule_derived(id, &db);
        let (raw, key) = note_key(&dir);
        let state = || {
            db.lock()
                .unwrap()
                .with_data_read(|conn| bh_data::index::state(conn, ix))
                .unwrap()
        };
        let mut frontier: i64 = raw
            .query_row(
                "SELECT max(id) FROM note_updates WHERE note=?1",
                [key.note.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        let mut received = 0;
        loop {
            // Each acknowledged derived turn is followed by another keystroke
            // in the same container, renewing its quiet period before expiry.
            assert_eq!(live.next_completion(), (id, 0));
            received += 1;
            assert!(received < 300, "derived work stalled: {:?}", state());
            let delta = bh_core::note::Note::new()
                .unwrap()
                .append_paragraph(&format!("keystroke {received}"))
                .unwrap();
            let mut request = [0xee; 16];
            request[..8].copy_from_slice(&(received as u64).to_be_bytes());
            frontier = db
                .lock()
                .unwrap()
                .commit_working_update_with_title(key, frontier, [4; 32], request, &delta, "typing")
                .unwrap()
                .update_id;
            live.schedule_local(id, &db);
            live.advance(std::time::Duration::from_millis(400));
            // Turns record their diagnostics before acknowledging, and only
            // derived turns run, so the last one acknowledged said no more.
            let stats = live.scheduler.maintenance_stats(id);
            if stats.len() == received && !stats[received - 1].more {
                break;
            }
        }
        assert_eq!(state().state, "ready");
        assert!(received >= 2, "the build took more than one bounded turn");
        // Typing never stopped: no Note body decode, store or checkpoint ran.
        live.no_more_events();
        assert_eq!(pending(&dir), bodies);
        let stats = live.scheduler.maintenance_stats(id);
        assert!(!stats.is_empty());
        for turn in &stats {
            assert_eq!(
                (turn.extracted, turn.store_sections, turn.checkpoint_frames),
                (0, 0, 0)
            );
            assert!(turn.derived_hold > std::time::Duration::ZERO);
            assert!(turn.derived_max <= turn.derived_hold);
        }
        let indexed: i64 = raw
            .query_row("SELECT count(*) FROM data_text_job", [], |r| r.get(0))
            .unwrap();
        assert_eq!(indexed, bodies, "body jobs still wait for quiet");
        // When typing stops, the deferred Note maintenance runs.
        live.advance(std::time::Duration::from_millis(751));
        live.expect_dispatched(id);
        let (done, extracted) = live.next_completion();
        assert_eq!(done, id);
        assert!(extracted > 0);
    }

    #[test]
    fn quiet_expiry_resumes_deferred_work_on_a_live_worker() {
        let (dir, db) = seeded(1);
        let id = crate::ContainerId([9; 16]);
        let live = Live::new(std::time::Duration::from_millis(750));
        live.schedule_local(id, &db);
        live.expect_deferred(id);
        assert_eq!(pending(&dir), 1);
        assert!(
            live.scheduler.maintenance_stats(id).is_empty(),
            "no checkpoint inside quiet period"
        );
        live.no_more_events(); // no decode before the quiet window ends

        // The last edit renews the window; it is not a reason to decode now.
        let (raw, key) = note_key(&dir);
        let delta = bh_core::note::Note::new()
            .unwrap()
            .append_paragraph("latest revision")
            .unwrap();
        db.lock()
            .unwrap()
            .commit_working_update_with_title(key, 1, [4; 32], [88; 16], &delta, "latest")
            .unwrap();
        live.schedule_local(id, &db);
        assert_eq!(pending(&dir), 1);
        let wanted: i64 = raw
            .query_row("SELECT wanted FROM data_text_job", [], |r| r.get(0))
            .unwrap();
        live.no_more_events();

        // Only the fake clock reaching the deadline releases the actual worker.
        live.advance(std::time::Duration::from_millis(751));
        live.expect_dispatched(id);
        assert_eq!(live.next_completion(), (id, 1));
        assert_eq!(pending(&dir), 0);
        let indexed: i64 = raw
            .query_row("SELECT text_rev FROM data_record LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(indexed, wanted, "the worker indexed the latest revision");
        let found: i64 = raw
            .query_row(
                "SELECT count(*) FROM data_fts WHERE data_fts MATCH 'latest'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "the indexed text is the latest revision");
        live.no_more_events();
    }

    #[test]
    fn deferred_containers_keep_their_own_quiet_deadlines() {
        let (typing_dir, typing_db) = seeded(1);
        let (other_dir, other_db) = seeded(1);
        let typing = crate::ContainerId([1; 16]);
        let other = crate::ContainerId([2; 16]);
        let live = Live::new(std::time::Duration::from_millis(750));
        live.schedule_local(typing, &typing_db);
        live.schedule_local(other, &other_db);
        let mut deferred = Vec::new();
        while deferred.len() < 2 {
            match live.next_event() {
                super::WorkerEvent::Deferred(id) => deferred.push(id),
                super::WorkerEvent::Dispatched(id) => {
                    panic!("dispatched {id:?} inside the quiet window")
                }
            }
        }
        deferred.sort_by_key(|id| id.0);
        assert_eq!(deferred, [typing, other]);

        // Renewing the typing container's window leaves the other untouched.
        live.advance(std::time::Duration::from_millis(400));
        live.schedule_local(typing, &typing_db);
        live.advance(std::time::Duration::from_millis(360));
        live.expect_dispatched(other);
        assert_eq!(live.next_completion(), (other, 1));
        assert_eq!(pending(&other_dir), 0);
        assert_eq!(pending(&typing_dir), 1);
        live.no_more_events();

        // The typing container waits for its own renewed window.
        live.advance(std::time::Duration::from_millis(400));
        live.expect_dispatched(typing);
        assert_eq!(live.next_completion(), (typing, 1));
        assert_eq!(pending(&typing_dir), 0);
        live.no_more_events();
    }

    #[test]
    fn commit_during_a_dispatched_turn_schedules_the_next_turn() {
        let (dir, db) = seeded(1);
        let id = crate::ContainerId([5; 16]);
        let live = Live::new(std::time::Duration::from_millis(750));
        live.schedule_local(id, &db);
        live.expect_deferred(id);

        // Hold the writer guard so a dispatched turn cannot select its batch.
        let mut writer = db.lock().unwrap();
        live.advance(std::time::Duration::from_millis(751));
        live.expect_dispatched(id);
        let (_, key) = note_key(&dir);
        let delta = bh_core::note::Note::new()
            .unwrap()
            .append_paragraph("during the turn")
            .unwrap();
        writer
            .commit_working_update_with_title(key, 1, [4; 32], [93; 16], &delta, "during")
            .unwrap();
        live.schedule_local(id, &db);
        drop(writer);

        // The in-flight turn sees the commit and its generation bump asks for
        // another turn, which the shared scheduler holds until quiet ends.
        assert_eq!(live.next_completion(), (id, 1));
        live.expect_deferred(id);
        assert_eq!(pending(&dir), 0);

        live.advance(std::time::Duration::from_millis(751));
        live.expect_dispatched(id);
        assert_eq!(live.next_completion(), (id, 0));
        assert_eq!(pending(&dir), 0);
        live.no_more_events();
    }

    #[test]
    fn stop_exits_with_deferred_work_without_waiting_for_quiet() {
        let (dir, db) = seeded(1);
        let id = crate::ContainerId([8; 16]);
        let live = Live::new(std::time::Duration::from_secs(3600));
        live.schedule_local(id, &db);
        live.expect_deferred(id);
        let started = std::time::Instant::now();
        drop(live);
        // This bound only guards a hang; waiting out quiet would take an hour.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "stop waited for quiet expiry"
        );
        assert_eq!(pending(&dir), 1);
    }

    #[test]
    fn store_body_bytes_are_chunked_with_separate_guard_sections() {
        let (dir, db) = seeded_with_body(2, 200_000);
        let (control_dir, control_db) = seeded_with_body(2, 200_000);
        let batch = control_db
            .lock()
            .unwrap()
            .note_body_source()
            .unwrap()
            .next_batch(16)
            .unwrap();
        control_db
            .lock()
            .unwrap()
            .store_body_batch(&batch, super::MAX_BODY_VM_STEPS)
            .unwrap();
        let mut sections = 0;
        let turn = super::maintenance_turn_with_hooks(
            &db,
            || {},
            || sections += 1,
            |db| db.checkpoint_wal_if_needed(),
        )
        .unwrap();
        assert_eq!(sections, 2);
        assert_eq!(turn.store_sections, sections);
        assert!(turn.store_max <= turn.store_hold);
        assert!(turn.store_hold <= turn.store_max * sections as u32);
        assert_eq!(turn.extracted, 2);
        assert_eq!(pending(&dir), pending(&control_dir));
        for db_path in [
            dir.path().join("notes.db"),
            control_dir.path().join("notes.db"),
        ] {
            let raw = rusqlite::Connection::open(db_path).unwrap();
            let indexed: i64 = raw
                .query_row(
                    "SELECT count(*) FROM data_fts WHERE data_fts MATCH 'paragraph'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(indexed, 2);
        }
    }

    #[test]
    fn unavailable_body_does_not_requeue_without_progress() {
        let (dir, db) = seeded(1);
        let raw = rusqlite::Connection::open(dir.path().join("notes.db")).unwrap();
        raw.execute("UPDATE note_updates SET delta=X'00'", [])
            .unwrap();
        let turn = super::maintenance_turn(&db, || {}).unwrap();
        assert!(!turn.more);
        assert_eq!(pending(&dir), 1);
    }

    #[test]
    fn dropped_database_weak_ends_maintenance_work() {
        let (_, db) = seeded(1);
        let weak = Arc::downgrade(&db);
        drop(db);
        let (sender, receiver) = std::sync::mpsc::channel();
        sender
            .send(super::Work::Maintain(crate::ContainerId([1; 16]), weak))
            .unwrap();
        sender.send(super::Work::Stop).unwrap();
        let active = Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([(
            crate::ContainerId([1; 16]),
            super::MaintenanceState {
                generation: 0,
                last_local: None,
            },
        )])));
        super::run_worker(
            Arc::new(std::sync::Mutex::new(super::ReceiverState {
                receiver,
                deferred: Default::default(),
            })),
            sender,
            super::Queues {
                maintaining: Arc::clone(&active),
                ..Default::default()
            },
            Arc::new(std::time::Instant::now),
            std::time::Duration::ZERO,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::Mutex::new(None)),
            super::WorkerEvents::default(),
        );
        assert!(active.lock().unwrap().is_empty());
    }

    #[test]
    fn writer_commit_completes_while_body_decoder_is_held() {
        let (_dir, db) = seeded(2);
        let key = {
            let mut writer = db.lock().unwrap();
            let note = writer.create_note([2; 32], [0; 32]).unwrap();
            let key = bh_storage::NoteKey {
                base: [2; 32],
                audience: [0; 32],
                note,
            };
            writer
                .insert_writer_slot(&bh_storage::note_writers::WriterSlot {
                    key,
                    account: [4; 32],
                    device: [6; 32],
                    slot: 0,
                    nonce: [7; 32],
                    client_id: 42,
                    retired: false,
                })
                .unwrap();
            key
        };
        let slot = db
            .lock()
            .unwrap()
            .writer_slots(key, [4; 32], [6; 32])
            .unwrap()
            .remove(0);
        let delta = bh_core::note::Note::new()
            .unwrap()
            .append_paragraph("foreground")
            .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            let worker_db = Arc::clone(&db);
            let worker = scope.spawn(move || {
                super::maintenance_turn(&worker_db, || {
                    entered_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                })
                .unwrap()
            });
            entered_rx.recv().unwrap(); // hook precedes selection, after guard release
            let saved = db
                .lock()
                .unwrap()
                .commit_writer_update(0, [4; 32], [99; 16], &delta, &slot)
                .unwrap();
            assert!(!saved.replayed);
            resume_tx.send(()).unwrap();
            worker.join().unwrap();
        });
    }

    #[test]
    fn worker_clears_durable_projection_repair() {
        let (dir, db) = seeded(0);
        let key = {
            let mut writer = db.lock().unwrap();
            let note = writer.create_note([2; 32], [0; 32]).unwrap();
            bh_storage::NoteKey {
                base: [2; 32],
                audience: [0; 32],
                note,
            }
        };
        let raw = rusqlite::Connection::open(dir.path().join("notes.db")).unwrap();
        // An existing Note may update its recency entry in place, while a
        // missing entry still inserts. Both failures must queue repair.
        raw.execute_batch("CREATE TRIGGER fail_projection BEFORE INSERT ON data_index_entry BEGIN SELECT RAISE(ABORT,'repair'); END; CREATE TRIGGER fail_projection_update BEFORE UPDATE ON data_index_entry BEGIN SELECT RAISE(ABORT,'repair'); END;").unwrap();
        let delta = bh_core::note::Note::new()
            .unwrap()
            .append_paragraph("repair")
            .unwrap();
        db.lock()
            .unwrap()
            .commit_working_update_with_title(key, 0, [4; 32], [81; 16], &delta, "repair")
            .unwrap();
        let repairs = || {
            raw.query_row("SELECT count(*) FROM note_projection_repair", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
        };
        assert_eq!(repairs(), 1);
        raw.execute_batch("DROP TRIGGER fail_projection; DROP TRIGGER fail_projection_update;")
            .unwrap();
        let turn = super::maintenance_turn(&db, || {}).unwrap();
        assert_eq!(turn.repaired, 1);
        assert_eq!(repairs(), 0);
    }

    #[test]
    fn stats_keep_only_the_last_64_turns_in_order() {
        let mut ring = super::TurnRing::default();
        for i in 0..70 {
            ring.push(super::MaintenanceTurn {
                attempted: i,
                ..Default::default()
            });
        }
        let entries = ring.snapshot();
        assert_eq!(entries.len(), 64);
        assert_eq!(entries.first().unwrap().attempted, 6);
        assert_eq!(entries.last().unwrap().attempted, 69);
    }

    #[test]
    fn stopped_worker_does_not_start_queued_maintenance() {
        let (dir, db) = seeded(1);
        let id = crate::ContainerId([7; 16]);
        let (sender, receiver) = std::sync::mpsc::channel();
        sender
            .send(super::Work::Maintain(id, Arc::downgrade(&db)))
            .unwrap();
        sender.send(super::Work::Stop).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(true));
        super::run_worker(
            Arc::new(std::sync::Mutex::new(super::ReceiverState {
                receiver,
                deferred: Default::default(),
            })),
            sender,
            super::Queues {
                maintaining: Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([(
                    id,
                    super::MaintenanceState {
                        generation: 0,
                        last_local: None,
                    },
                )]))),
                ..Default::default()
            },
            Arc::new(std::time::Instant::now),
            std::time::Duration::ZERO,
            stop,
            Arc::new(std::sync::Mutex::new(None)),
            super::WorkerEvents::default(),
        );
        assert_eq!(pending(&dir), 1);
    }

    #[test]
    fn dropping_scheduler_stops_its_workers() {
        // The workers alone retain this Arc after the scheduler is dropped.
        // A clone of the work sender in each worker otherwise keeps recv alive.
        let scheduler = Scheduler::default();
        let workers = Arc::downgrade(&scheduler.active);
        drop(scheduler);
        assert!(
            workers.upgrade().is_none(),
            "compaction workers outlived their scheduler"
        );
    }
}
