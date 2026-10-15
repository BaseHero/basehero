//! One native-only owner for device-local account containers and note surfaces.
//! A database row is not account authority: registration takes the independently
//! verified account state and compares its exact anchored head to the stored row.
//! There is no production session issuer yet; the app remains on setup.
mod compaction;
pub mod coordinator;

use bh_account::{AccountEvent, AccountId, VerifiedAccount, crypto::hash};
use bh_core::note::Note;
use bh_crypto::random;
use bh_storage::{DeviceDatabase, NoteKey, StoreError};
use compaction::Scheduler;
use coordinator::{Ack, AuthoritySource, Coordinator, Delivery, HostError, Opened};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ContainerId(pub [u8; 16]);

type Session = Arc<Mutex<Coordinator<Box<dyn AuthoritySource + Send>>>>;
type NoteWork = Mutex<HashMap<(ContainerId, NoteKey), Weak<Mutex<()>>>>;
struct WorkSlot<'a> {
    owner: &'a Owner,
    id: ContainerId,
    key: NoteKey,
    lock: Option<Arc<Mutex<()>>>,
}
impl Drop for WorkSlot<'_> {
    fn drop(&mut self) {
        let mut map = self
            .owner
            .note_work
            .lock()
            .expect("note work registry lock");
        // Release our strong reference while holding the map guard: the last
        // concurrent drop now sees zero and removes the dead weak entry.
        self.lock.take();
        if map
            .get(&(self.id, self.key))
            .is_some_and(|weak| weak.strong_count() == 0)
        {
            map.remove(&(self.id, self.key));
        }
    }
}
struct Container {
    anchor: Option<[u8; 32]>,
    session: Session,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct WindowRoute {
    container: ContainerId,
    generation: Option<u64>,
}
#[derive(Default)]
struct Registry {
    containers: HashMap<ContainerId, Container>,
    windows: HashMap<String, WindowRoute>,
}
const DELIVERY_LIMIT: usize = 64;
const DELIVERY_BYTES: usize = 256 * 1024;
#[derive(Default)]
struct SurfaceQueue {
    pending: VecDeque<(ContainerId, Delivery)>,
    draining: bool,
    drain_token: u64,
    bytes: usize,
}
#[derive(Default)]
pub struct Owner {
    registry: Mutex<Registry>,
    deliveries: Mutex<HashMap<String, SurfaceQueue>>,
    next_generation: AtomicU64,
    next_drain_token: AtomicU64,
    compaction: Scheduler,
    note_work: NoteWork,
}

#[derive(Debug)]
pub enum OwnerError {
    Store(StoreError),
    Unbound,
    UnknownContainer,
    Changed,
    DuplicateAnchor,
    AnchorMismatch,
}
impl From<StoreError> for OwnerError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
impl From<HostError> for OwnerError {
    fn from(error: HostError) -> Self {
        match error {
            HostError::Unbound => Self::Unbound,
            HostError::Changed => Self::Changed,
            HostError::Store(e) => Self::Store(e),
        }
    }
}
/// This canonical Note is held by the caller's per-note lease. SQLite and the
/// container coordinator are released between every bounded page and yrs apply.
fn load_working_note(
    database: &Arc<Mutex<DeviceDatabase>>,
    key: NoteKey,
    weigh_cold: bool,
) -> Result<(Note, i64, usize), StoreError> {
    let (cached, frontier, pool) = {
        let mut db = database.lock().expect("container writer lock");
        let frontier = db.local_frontier(key)?;
        let cached = db.take_cached_note(key, frontier);
        (cached, frontier, db.read_pool())
    };
    if let Some((note, weight)) = cached {
        return Ok((note, frontier, weight));
    }
    if let Some(pool) = pool {
        let loaded = pool.load_note(key)?;
        let weight = if weigh_cold {
            loaded.note.state().len().max(1)
        } else {
            0
        };
        return Ok((loaded.note, loaded.frontier, weight));
    }
    let (note, frontier) = rebuild_from_writer(database, key)?;
    let weight = if weigh_cold {
        note.state().len().max(1)
    } else {
        0
    };
    Ok((note, frontier, weight))
}
fn rebuild_from_writer(
    database: &Arc<Mutex<DeviceDatabase>>,
    key: NoteKey,
) -> Result<(Note, i64), StoreError> {
    let seed = database
        .lock()
        .expect("container writer lock")
        .note_seed(key)?;
    let mut note = Note::new();
    if !seed.encoded.is_empty() {
        note.apply_update(&seed.encoded)
            .map_err(|_| StoreError::InvalidUpdate)?;
    }
    let mut after = seed.covered;
    while after < seed.target {
        let page = database
            .lock()
            .expect("container writer lock")
            .note_seed_page(key, after, seed.target)?;
        if page.is_empty() {
            return Err(StoreError::InvalidUpdate);
        }
        for (id, delta) in page {
            note.apply_update(&delta)
                .map_err(|_| StoreError::InvalidUpdate)?;
            after = id;
        }
    }
    Ok((note, seed.target))
}
fn durable_snapshot(
    database: &Arc<Mutex<DeviceDatabase>>,
    key: NoteKey,
) -> Result<(Vec<u8>, i64), StoreError> {
    let pool = database.lock().expect("container writer lock").read_pool();
    if let Some(pool) = pool {
        let read = pool.note_state(key)?;
        return Ok((read.state, read.frontier));
    }
    let (note, frontier) = rebuild_from_writer(database, key)?;
    Ok((note.state(), frontier))
}

fn verified_anchor(
    database: &DeviceDatabase,
    proof: &VerifiedAccount,
) -> Result<[u8; 32], OwnerError> {
    let stored = database
        .account_state()?
        .ok_or(OwnerError::AnchorMismatch)?;
    if stored.anchor != proof.id().0
        || stored.head_position != proof.head().position
        || stored.head_hash != proof.head().hash
        || stored.stopped
        || proof.is_stopped()
    {
        return Err(OwnerError::AnchorMismatch);
    }
    let edges = database
        .account_history_edges()?
        .ok_or(OwnerError::AnchorMismatch)?;
    let genesis = AccountEvent::decode(&edges.first).map_err(|_| OwnerError::AnchorMismatch)?;
    if edges.count != stored.head_position
        || AccountId::of_genesis(&genesis).map_err(|_| OwnerError::AnchorMismatch)? != proof.id()
        || hash(&edges.last) != proof.head().hash
    {
        return Err(OwnerError::AnchorMismatch);
    }
    Ok(stored.anchor)
}

impl Owner {
    /// Native-only existing writer; does not create a second account store or
    /// grant note authority. A setup container remains unanchored until anchor.
    pub fn shared_database(
        &self,
        id: ContainerId,
    ) -> Result<Arc<Mutex<DeviceDatabase>>, OwnerError> {
        let session = {
            let registry = self.registry.lock().expect("owner registry lock");
            Arc::clone(
                &registry
                    .containers
                    .get(&id)
                    .ok_or(OwnerError::UnknownContainer)?
                    .session,
            )
        };
        Ok(session
            .lock()
            .expect("container session lock")
            .shared_database())
    }
    /// Promote the same setup container after its journal is committed. Keep
    /// its writer locked through the short registry insertion so validation
    /// cannot race a journal change; the long history check is off-registry.
    pub fn anchor(&self, id: ContainerId, verified: &VerifiedAccount) -> Result<(), OwnerError> {
        let database = self.shared_database(id)?;
        let db = database.lock().expect("container writer lock");
        let anchor = verified_anchor(&db, verified)?;
        let mut registry = self.registry.lock().expect("owner registry lock");
        let prior = registry
            .containers
            .get(&id)
            .ok_or(OwnerError::UnknownContainer)?
            .anchor;
        if prior.is_some() && prior != Some(anchor) {
            return Err(OwnerError::AnchorMismatch);
        }
        if registry
            .containers
            .iter()
            .any(|(other, c)| *other != id && c.anchor == Some(anchor))
        {
            return Err(OwnerError::DuplicateAnchor);
        }
        registry
            .containers
            .get_mut(&id)
            .expect("known container")
            .anchor = Some(anchor);
        Ok(())
    }
    /// The caller must verify signed account history independently; a registry
    /// filename, cached account ID, or the page is never that proof. First setup
    /// has no verified state and therefore no note authority.
    pub fn register(
        &self,
        database: DeviceDatabase,
        verified: Option<&VerifiedAccount>,
        authority: Box<dyn AuthoritySource + Send>,
    ) -> Result<ContainerId, OwnerError> {
        let anchor = match (database.account_state()?, verified) {
            (None, None) => None,
            (Some(_), Some(proof)) => Some(verified_anchor(&database, proof)?),
            _ => return Err(OwnerError::AnchorMismatch),
        };
        let mut registry = self.registry.lock().expect("owner registry lock");
        if anchor.is_some_and(|a| registry.containers.values().any(|c| c.anchor == Some(a))) {
            return Err(OwnerError::DuplicateAnchor);
        }
        let id = loop {
            let candidate = ContainerId(random::<16>());
            if candidate != ContainerId::default() && !registry.containers.contains_key(&candidate)
            {
                break candidate;
            }
        };
        let session = Coordinator::new(database, authority);
        let writer = session.shared_database();
        registry.containers.insert(
            id,
            Container {
                anchor,
                session: Arc::new(Mutex::new(session)),
            },
        );
        drop(registry);
        self.compaction.schedule_backfill(id, &writer);
        Ok(id)
    }
    /// Only native routing calls this; no IPC accepts a ContainerId.
    pub fn bind(&self, window: &str, id: ContainerId) -> Result<(), OwnerError> {
        let (old, new) = {
            let mut registry = self.registry.lock().expect("owner registry lock");
            let new = registry
                .containers
                .get(&id)
                .map(|c| Arc::clone(&c.session))
                .ok_or(OwnerError::UnknownContainer)?;
            let old = registry
                .windows
                .insert(
                    window.into(),
                    WindowRoute {
                        container: id,
                        generation: None,
                    },
                )
                .and_then(|route| {
                    registry
                        .containers
                        .get(&route.container)
                        .map(|c| Arc::clone(&c.session))
                });
            (old, new)
        };
        self.deliveries
            .lock()
            .expect("delivery lock")
            .remove(window);
        // Never wait for a cold open/commit while holding the process registry.
        if let Some(old) = old {
            old.lock()
                .expect("container session lock")
                .invalidate(window);
        }
        new.lock()
            .expect("container session lock")
            .allow_bound_window(window);
        Ok(())
    }
    fn routed(&self, window: &str) -> Result<(ContainerId, Session, [u8; 32]), OwnerError> {
        let registry = self.registry.lock().expect("owner registry lock");
        let route = registry.windows.get(window).ok_or(OwnerError::Unbound)?;
        let container = registry
            .containers
            .get(&route.container)
            .ok_or(OwnerError::UnknownContainer)?;
        Ok((
            route.container,
            Arc::clone(&container.session),
            container.anchor.ok_or(OwnerError::Unbound)?,
        ))
    }
    fn work_lock(&self, id: ContainerId, key: NoteKey) -> WorkSlot<'_> {
        let mut work = self.note_work.lock().expect("note work registry lock");
        let slot = work.entry((id, key)).or_default();
        let lock = slot.upgrade().unwrap_or_else(|| {
            let lock = Arc::new(Mutex::new(()));
            *slot = Arc::downgrade(&lock);
            lock
        });
        WorkSlot {
            owner: self,
            id,
            key,
            lock: Some(lock),
        }
    }
    #[doc(hidden)]
    pub fn note_work_slot_count(&self) -> usize {
        self.note_work
            .lock()
            .expect("note work registry lock")
            .len()
    }
    #[doc(hidden)]
    pub fn note_work_slot_users(&self, id: ContainerId, key: NoteKey) -> usize {
        self.note_work
            .lock()
            .expect("note work registry lock")
            .get(&(id, key))
            .map_or(0, Weak::strong_count)
    }
    fn route_current(&self, window: &str, id: ContainerId, generation: u64) -> bool {
        self.registry
            .lock()
            .expect("owner registry lock")
            .windows
            .get(window)
            == Some(&WindowRoute {
                container: id,
                generation: Some(generation),
            })
    }
    /// Native scheduler key, never sent to the page. It only reduces blocking
    /// thread occupancy; the owner rechecks scope and generation at commit.
    pub fn bound_work_key(&self, window: &str, generation: u64) -> Option<(ContainerId, NoteKey)> {
        let (id, session, anchor) = self.routed(window).ok()?;
        if !self.route_current(window, id, generation) {
            return None;
        }
        let guard = session.lock().ok()?;
        let scope = guard.bound_scope(window)?;
        (scope.account == anchor && guard.is_current(window, generation)).then_some((id, scope.key))
    }
    /// Early native admission only. `open` revalidates this exact authority
    /// after its permit and before publishing a window generation.
    pub fn bound_open_key(&self, window: &str, note: [u8; 32]) -> Option<(ContainerId, NoteKey)> {
        let (id, session, anchor) = self.routed(window).ok()?;
        let scope = session.lock().ok()?.bound_scope(window)?;
        (scope.account == anchor && scope.key.note == note).then_some((id, scope.key))
    }
    pub fn bound_note(&self, window: &str) -> Option<[u8; 32]> {
        let (_, session, anchor) = self.routed(window).ok()?;
        let scope = session.lock().ok()?.bound_scope(window)?;
        (scope.account == anchor).then_some(scope.key.note)
    }
    pub fn open(&self, window: &str, note: [u8; 32]) -> Result<Opened, OwnerError> {
        self.open_with_snapshot_hook(window, note, |_| {})
    }
    /// Native-only test seam, after the immutable read and outside guards.
    #[doc(hidden)]
    pub fn open_with_snapshot_hook(
        &self,
        window: &str,
        note: [u8; 32],
        mut after_snapshot: impl FnMut(u8),
    ) -> Result<Opened, OwnerError> {
        let (id, session, anchor) = self.routed(window)?;
        let generation = self
            .next_generation
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("generation exhausted");
        {
            let mut registry = self.registry.lock().expect("owner registry lock");
            let route = registry
                .windows
                .get_mut(window)
                .ok_or(OwnerError::Unbound)?;
            if route.container != id || route.generation.is_some_and(|prior| prior >= generation) {
                return Err(OwnerError::Unbound);
            }
            route.generation = Some(generation);
        }
        for attempt in 0..3 {
            let (scope, expected, database) = {
                let guard = session.lock().expect("container session lock");
                let scope = guard.bound_scope(window).ok_or(OwnerError::Unbound)?;
                if scope.account != anchor
                    || scope.key.note != note
                    || !self.route_current(window, id, generation)
                {
                    return Err(OwnerError::Unbound);
                }
                (
                    scope,
                    guard.note_revision(scope.key),
                    guard.shared_database(),
                )
            };
            // Borrow/rebuild under the per-note lease, but never under shared
            // guards. Release it for the test seam (and for another save); after
            // reacquiring it the revision/frontier checks fence any stale Note.
            let work = self.work_lock(id, scope.key);
            let lease = work
                .lock
                .as_ref()
                .unwrap()
                .lock()
                .expect("exclusive note work lock");
            let (built, frontier, _) = load_working_note(&database, scope.key, false)?;
            let state = built.state();
            let weight = state.len().max(1);
            let due = {
                database
                    .lock()
                    .expect("container writer lock")
                    .checkpoint_due(scope.key)?
            };
            let checkpoint_bytes = due.then(|| state.clone());
            drop(lease);
            after_snapshot(attempt);
            let lease = work
                .lock
                .as_ref()
                .unwrap()
                .lock()
                .expect("exclusive note work lock");
            let mut guard = session.lock().expect("container session lock");
            if guard.bound_scope(window) != Some(scope)
                || !self.route_current(window, id, generation)
            {
                // A navigated surface cannot publish its candidate to a new
                // generation. A later open can reconstruct it if needed.
                return Err(OwnerError::Unbound);
            }
            if database
                .lock()
                .expect("container writer lock")
                .local_frontier(scope.key)?
                != frontier
            {
                drop(guard);
                drop(lease);
                continue;
            }
            match guard.open_with_state(window, note, generation, expected, state) {
                Err(HostError::Changed) => {
                    drop(guard);
                    drop(lease);
                    continue;
                }
                other => {
                    let opened = other?;
                    // Reuse the exact owned Note for first save. A checkpoint
                    // gets the already encoded state; no second history replay.
                    let checkpoint = checkpoint_bytes.and_then(|state| {
                        database
                            .lock()
                            .expect("container writer lock")
                            .prepare_loaded_checkpoint(scope.key, frontier, state)
                            .ok()
                            .flatten()
                    });
                    database
                        .lock()
                        .expect("container writer lock")
                        .return_committed_note(scope.key, built, frontier, weight);
                    drop(guard);
                    drop(lease);
                    if let Some(checkpoint) = checkpoint {
                        let _ = database
                            .lock()
                            .expect("container writer lock")
                            .publish_checkpoint(&checkpoint);
                    }
                    self.compaction.schedule(id, scope.key, &database);
                    self.compaction.schedule_backfill(id, &database);
                    return Ok(opened);
                }
            }
        }
        // Do not fall back to an under-guard replay during a busy shared note.
        // The native bridge can explicitly retry this bounded operation.
        Err(OwnerError::Changed)
    }
    pub fn commit(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
        mut deliver: impl FnMut(Delivery),
    ) -> Result<Ack, OwnerError> {
        let (ack, targets, _) =
            self.commit_queued_with_work_hook(window, generation, request, update, || {})?;
        for target in targets {
            self.drain_surface(&target, &mut deliver);
        }
        Ok(ack)
    }
    /// Native save path: return after durable commit and queue publication;
    /// WebView evaluation belongs to a separate bounded delivery worker.
    pub fn commit_queued(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
    ) -> Result<(Ack, Vec<String>), OwnerError> {
        let (ack, targets, _) =
            self.commit_queued_with_work_hook(window, generation, request, update, || {})?;
        Ok((ack, targets))
    }
    /// Opt-in local instrumentation: SQL CAS/INSERT duration excludes mutex
    /// wait and yrs work. Nothing records this as product telemetry.
    pub fn commit_queued_timed(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
    ) -> Result<(Ack, Vec<String>, Duration), OwnerError> {
        self.commit_queued_with_work_hook(window, generation, request, update, || {})
    }
    /// Native-only test seam: the callback runs with only this note's exclusive
    /// ownership, never with the container, writer or process registry guard.
    #[doc(hidden)]
    pub fn commit_with_work_hook(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
        prepare: impl FnOnce(),
        mut deliver: impl FnMut(Delivery),
    ) -> Result<Ack, OwnerError> {
        let (ack, targets, _) =
            self.commit_queued_with_work_hook(window, generation, request, update, prepare)?;
        for target in targets {
            self.drain_surface(&target, &mut deliver);
        }
        Ok(ack)
    }
    fn commit_queued_with_work_hook(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
        prepare: impl FnOnce(),
    ) -> Result<(Ack, Vec<String>, Duration), OwnerError> {
        let (id, session, anchor) = self.routed(window)?;
        let scope = {
            let guard = session.lock().expect("container session lock");
            let scope = guard.bound_scope(window).ok_or(OwnerError::Unbound)?;
            if scope.account != anchor
                || !guard.is_current(window, generation)
                || !self.route_current(window, id, generation)
            {
                return Err(OwnerError::Unbound);
            }
            scope
        };
        let work = self.work_lock(id, scope.key);
        let note_guard = work
            .lock
            .as_ref()
            .unwrap()
            .lock()
            .expect("exclusive note work lock");
        let outcome = (|| -> Result<_, OwnerError> {
            let database = {
                let guard = session.lock().expect("container session lock");
                if guard.bound_scope(window) != Some(scope)
                    || !guard.is_current(window, generation)
                    || !self.route_current(window, id, generation)
                {
                    return Err(OwnerError::Unbound);
                }
                guard.shared_database()
            };
            let replayed = {
                database
                    .lock()
                    .expect("container writer lock")
                    .committed_request(scope.key, request, update)?
            };
            if let Some(replayed) = replayed {
                return Ok((
                    Ack {
                        request_id: request,
                        replayed: replayed.replayed,
                    },
                    Vec::new(),
                    database,
                    Duration::ZERO,
                ));
            }
            let (mut working, frontier, weight) = load_working_note(&database, scope.key, true)?;
            prepare();
            {
                let guard = session.lock().expect("container session lock");
                if guard.bound_scope(window) != Some(scope)
                    || !guard.is_current(window, generation)
                    || !self.route_current(window, id, generation)
                {
                    return Err(OwnerError::Unbound);
                }
            }
            working
                .apply_update(update)
                .map_err(|_| StoreError::InvalidUpdate)?;
            {
                let guard = session.lock().expect("container session lock");
                if guard.bound_scope(window) != Some(scope)
                    || !guard.is_current(window, generation)
                    || !self.route_current(window, id, generation)
                {
                    return Err(OwnerError::Unbound);
                }
            }
            // The only SQLite write section is this scoped CAS and insert.
            // A stale candidate is discarded, never installed or fanned out.
            let (committed, sql_hold) = database
                .lock()
                .expect("container writer lock")
                .commit_working_update_timed(scope.key, frontier, anchor, request, update)?;
            if !committed.replayed {
                database
                    .lock()
                    .expect("container writer lock")
                    .return_committed_note(
                        scope.key,
                        working,
                        committed.update_id,
                        weight.saturating_add(update.len()),
                    );
            }
            let mut targets = Vec::new();
            let (result, windows) = {
                let mut guard = session.lock().expect("container session lock");
                let result = guard.publish_local(window, scope, request, update, committed, |d| {
                    targets.push(d)
                });
                // Queue order is atomic with the subscription/sequence change.
                // Overflow replaces only committed queued bytes with one bounded
                // marker. An off-guard reader hydrates it before delivery.
                let mut windows = Vec::with_capacity(targets.len());
                let mut queues = self.deliveries.lock().expect("delivery lock");
                for item in targets {
                    windows.push(item.window.clone());
                    let queue = queues.entry(item.window.clone()).or_default();
                    if queue.pending.len() >= DELIVERY_LIMIT
                        || queue.bytes.saturating_add(item.update.len()) > DELIVERY_BYTES
                    {
                        queue.pending.clear();
                        queue.bytes = 0;
                        queue.pending.push_back((
                            id,
                            Delivery {
                                window: item.window,
                                generation: item.generation,
                                sequence: item.sequence,
                                through_update_id: item.through_update_id,
                                update: Vec::new(),
                                resync: true,
                            },
                        ));
                    } else {
                        queue.bytes = queue.bytes.saturating_add(item.update.len());
                        queue.pending.push_back((id, item));
                    }
                }
                (result, windows)
            };
            Ok((result, windows, database, sql_hold))
        })();
        drop(note_guard);
        drop(work);
        let (result, targets, database, sql_hold) = outcome?;
        self.compaction.schedule(id, scope.key, &database);
        Ok((result, targets, sql_hold))
    }
    fn delivery_scope(
        &self,
        window: &str,
        origin: ContainerId,
        generation: u64,
    ) -> Option<coordinator::Scope> {
        let (current, session, anchor) = self.routed(window).ok()?;
        if current != origin || !self.route_current(window, origin, generation) {
            return None;
        }
        let guard = session.lock().ok()?;
        if !guard.is_current(window, generation) {
            return None;
        }
        guard
            .bound_scope(window)
            .filter(|scope| scope.account == anchor)
    }
    pub fn drain_surface(&self, window: &str, deliver: &mut impl FnMut(Delivery)) -> bool {
        self.drain_surface_with_snapshot(window, deliver, |key| {
            let (_, session, _) = self.routed(window).map_err(|_| StoreError::InvalidUpdate)?;
            let database = session
                .lock()
                .expect("container session lock")
                .shared_database();
            durable_snapshot(&database, key)
        })
    }
    /// Native WebView dispatch takes at most one item, and must wait for the
    /// eval callback before taking another. False means a retryable marker.
    pub fn drain_surface_once(&self, window: &str, deliver: &mut impl FnMut(Delivery)) -> bool {
        self.drain_with_snapshot(window, deliver, true, |key| {
            let (_, session, _) = self.routed(window).map_err(|_| StoreError::InvalidUpdate)?;
            let database = session
                .lock()
                .expect("container session lock")
                .shared_database();
            durable_snapshot(&database, key)
        })
    }
    /// Test seam for deterministic snapshot failure. No callback runs under a
    /// writer, coordinator or process-owner guard. False means retry marker.
    #[doc(hidden)]
    pub fn drain_surface_with_snapshot(
        &self,
        window: &str,
        deliver: &mut impl FnMut(Delivery),
        snapshot: impl FnMut(NoteKey) -> Result<(Vec<u8>, i64), StoreError>,
    ) -> bool {
        self.drain_with_snapshot(window, deliver, false, snapshot)
    }
    fn drain_with_snapshot(
        &self,
        window: &str,
        deliver: &mut impl FnMut(Delivery),
        once: bool,
        mut snapshot: impl FnMut(NoteKey) -> Result<(Vec<u8>, i64), StoreError>,
    ) -> bool {
        let token = {
            let mut queues = self.deliveries.lock().expect("delivery lock");
            let Some(queue) = queues.get_mut(window) else {
                return true;
            };
            if queue.draining {
                return true;
            } // existing drainer owns this surface
            let token = self
                .next_drain_token
                .fetch_add(1, Ordering::Relaxed)
                .checked_add(1)
                .expect("drain token exhausted");
            queue.draining = true;
            queue.drain_token = token;
            token
        };
        // Even a failed snapshot that races a reopen must release this surface.
        // Otherwise new deliveries are stuck behind a permanently draining queue.
        struct DrainGuard<'a> {
            owner: &'a Owner,
            window: &'a str,
            token: u64,
        }
        impl Drop for DrainGuard<'_> {
            fn drop(&mut self) {
                if let Some(queue) = self
                    .owner
                    .deliveries
                    .lock()
                    .expect("delivery lock")
                    .get_mut(self.window)
                    && queue.drain_token == self.token
                {
                    queue.draining = false;
                }
            }
        }
        let _drain = DrainGuard {
            owner: self,
            window,
            token,
        };
        loop {
            let next = {
                let mut queues = self.deliveries.lock().expect("delivery lock");
                let Some(queue) = queues.get_mut(window) else {
                    return true;
                };
                if let Some(item) = queue.pending.pop_front() {
                    queue.bytes = queue.bytes.saturating_sub(item.1.update.len());
                    Some(item)
                } else {
                    // Release the drainer under the same lock that saw an empty queue;
                    // a producer can now start another drain without waiting for a commit.
                    queue.draining = false;
                    None
                }
            };
            let Some((origin, mut item)) = next else {
                return true;
            };
            let Some(scope) = self.delivery_scope(window, origin, item.generation) else {
                continue;
            }; // navigation/revocation fences
            if item.resync {
                // The marker was enqueued only *after* its committed row. The
                // immutable read begins later; it must cover that row before
                // claiming the marker's sequence. Later deltas remain queued.
                match snapshot(scope.key) {
                    Ok((state, frontier)) if frontier >= item.through_update_id => {
                        item.update = state
                    }
                    _ => {
                        // A transient read failure cannot grow the raw-delta
                        // queue or make a successful local save fail. Collapse
                        // later committed rows to a newer retryable marker.
                        let registry = self.registry.lock().expect("owner registry lock");
                        if registry.windows.get(window)
                            == Some(&WindowRoute {
                                container: origin,
                                generation: Some(item.generation),
                            })
                        {
                            let mut queues = self.deliveries.lock().expect("delivery lock");
                            if let Some(queue) = queues.get_mut(window) {
                                if queue.pending.iter().any(|(id, later)| {
                                    *id != origin || later.generation != item.generation
                                }) {
                                    return true;
                                }
                                if !queue.pending.iter().any(|(id, d)| {
                                    *id == origin
                                        && d.generation == item.generation
                                        && d.resync
                                        && d.sequence >= item.sequence
                                }) {
                                    if let Some((_, last)) = queue.pending.back() {
                                        item.sequence = item.sequence.max(last.sequence);
                                        item.through_update_id =
                                            item.through_update_id.max(last.through_update_id);
                                    }
                                    item.update.clear();
                                    queue.pending.clear();
                                    queue.bytes = 0;
                                    queue.pending.push_front((origin, item));
                                }
                                return false;
                            }
                        }
                        return true;
                    }
                }
            }
            // Snapshot may have taken time while the window navigated; never
            // dispatch to a different native surface or generation.
            if self.delivery_scope(window, origin, item.generation) == Some(scope) {
                deliver(item);
                if once {
                    return true;
                }
            }
        }
    }
    /// Rejected/failed eval cannot drop an already committed delivery. Merge
    /// it and subsequent items into one retryable resnapshot for this surface.
    pub fn delivery_current(&self, item: &Delivery) -> bool {
        let Ok((id, _, _)) = self.routed(&item.window) else {
            return false;
        };
        self.delivery_scope(&item.window, id, item.generation)
            .is_some()
    }
    pub fn retry_delivery(&self, item: &Delivery) {
        self.retry_delivery_with_hook(item, || {});
    }
    /// Test seam after scope validation but before queue mutation.
    #[doc(hidden)]
    pub fn retry_delivery_with_hook(&self, item: &Delivery, after_validation: impl FnOnce()) {
        let (id, _, _) = match self.routed(&item.window) {
            Ok(route) => route,
            Err(_) => return,
        };
        if self
            .delivery_scope(&item.window, id, item.generation)
            .is_none()
        {
            return;
        }
        after_validation();
        // Bind/open change the route under this same guard. The queue cannot
        // be replaced after a new generation publishes its committed delta.
        let registry = self.registry.lock().expect("owner registry lock");
        if registry.windows.get(&item.window)
            != Some(&WindowRoute {
                container: id,
                generation: Some(item.generation),
            })
        {
            return;
        }
        let mut queues = self.deliveries.lock().expect("delivery lock");
        let queue = queues.entry(item.window.clone()).or_default();
        if queue
            .pending
            .iter()
            .any(|(origin, later)| *origin != id || later.generation != item.generation)
        {
            return;
        }
        let (sequence, through_update_id) =
            queue
                .pending
                .back()
                .map_or((item.sequence, item.through_update_id), |(_, later)| {
                    (
                        item.sequence.max(later.sequence),
                        item.through_update_id.max(later.through_update_id),
                    )
                });
        queue.pending.clear();
        queue.bytes = 0;
        queue.pending.push_back((
            id,
            Delivery {
                window: item.window.clone(),
                generation: item.generation,
                sequence,
                through_update_id,
                update: Vec::new(),
                resync: true,
            },
        ));
    }
    pub fn has_queued_delivery(&self, window: &str) -> bool {
        self.deliveries
            .lock()
            .expect("delivery lock")
            .get(window)
            .is_some_and(|q| !q.pending.is_empty())
    }
    #[doc(hidden)]
    pub fn queued_delivery_budget(&self, window: &str) -> (usize, usize, bool) {
        self.deliveries
            .lock()
            .expect("delivery lock")
            .get(window)
            .map_or((0, 0, false), |q| {
                (
                    q.pending.len(),
                    q.bytes,
                    q.pending.iter().any(|(_, d)| d.resync),
                )
            })
    }
    pub fn close_generation(&self, window: &str, generation: u64) {
        if let Ok((id, session, _)) = self.routed(window) {
            if !self.route_current(window, id, generation) {
                return;
            }
            let mut guard = session.lock().expect("container session lock");
            if guard.is_current(window, generation) {
                guard.close_generation(window, generation);
                self.deliveries
                    .lock()
                    .expect("delivery lock")
                    .remove(window);
            }
        }
    }
    pub fn invalidate(&self, window: &str) {
        let previous = {
            let mut registry = self.registry.lock().expect("owner registry lock");
            registry.windows.remove(window).and_then(|route| {
                registry
                    .containers
                    .get(&route.container)
                    .map(|c| Arc::clone(&c.session))
            })
        };
        self.deliveries
            .lock()
            .expect("delivery lock")
            .remove(window);
        if let Some(session) = previous {
            session
                .lock()
                .expect("container session lock")
                .invalidate(window);
        }
    }
}
