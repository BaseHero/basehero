//! One native-only owner for device-local account containers and note surfaces.
//! A database row is not account authority: registration takes the independently
//! verified account state and compares its exact anchored head to the stored row.
//! Note authority comes only from `authorize` with a current account capability
//! and its verified own base; `register` takes fixture authority for tests.
pub mod base_keys;
mod compaction;
mod containers;
pub mod coordinator;
mod copy;
pub mod incoming;
pub mod join;
pub mod own_base;
mod records;
pub use records::{ApprovalRequest, RecordsHandle};
mod seal;
mod sync_fence;
pub mod writers;
pub use seal::SealRefusal;
pub use sync_fence::SyncFence;

use bh_account::{
    AccountEvent, AccountId, VerifiedAccount, crypto::hash, owner::AccountCapability,
};
use bh_core::note::{Note, OrderedState};
use bh_crypto::random;
use bh_data::{
    KeyRef, RecordId, Scope, TypeId,
    catalogue::Shipped,
    query::{self, Budget, Completeness, Query, SortKey, TypeSelect},
};
use bh_storage::{DeviceDatabase, NoteEntry, NoteKey, OpenError, ReadPool, StoreError, ViewRecord};
pub use compaction::MaintenanceTurn;
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

const ORDINARY_AUDIENCE: [u8; 32] = [0; 32];
/// Largest encoded Yjs selection position a restart record may carry.
pub const MAX_SELECTION_BYTES: usize = 1024;

/// Only native verified admission installs Account; fixture authority is separate.
enum AccountAuthority {
    Unbound,
    Account {
        capability: Arc<AccountCapability>,
        own_base: [u8; 32],
        windows: HashMap<String, [u8; 32]>,
    },
    Fixture(Box<dyn AuthoritySource + Send>),
}
impl AuthoritySource for AccountAuthority {
    fn bound_scope(&self, window: &str) -> Option<coordinator::Scope> {
        match self {
            Self::Account {
                capability,
                own_base,
                windows,
            } if capability.is_current() => windows.get(window).map(|note| coordinator::Scope {
                account: capability.account_id().0,
                key: NoteKey {
                    base: *own_base,
                    audience: ORDINARY_AUDIENCE,
                    note: *note,
                },
            }),
            Self::Fixture(source) => source.bound_scope(window),
            _ => None,
        }
    }
}
impl AccountAuthority {
    fn capability(&self) -> Option<&Arc<AccountCapability>> {
        match self {
            Self::Account { capability, .. } => Some(capability),
            _ => None,
        }
    }
    /// Own base and capability only while that capability is current.
    fn current(&self) -> Option<([u8; 32], Arc<AccountCapability>)> {
        match self {
            Self::Account {
                own_base,
                capability,
                ..
            } if capability.is_current() => Some((*own_base, Arc::clone(capability))),
            _ => None,
        }
    }
    fn forget(&mut self, window: &str) {
        if let Self::Account { windows, .. } = self {
            windows.remove(window);
        }
    }
}
type Session = Arc<Mutex<Coordinator<AccountAuthority>>>;
type RecordsWake = Arc<dyn Fn(ContainerId) + Send + Sync>;
type RecordsWakeSlot = Arc<Mutex<Option<RecordsWake>>>;
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
    readers: Option<Arc<ReadPool>>,
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
    // Lifecycle holds: Quit/update holds every window, a close only its own.
    all_held: Option<u64>,
    held_windows: HashMap<String, u64>,
    // Windows whose page replied drained under that fence: no further writes.
    drained: HashMap<String, u64>,
    next_fence: u64,
}
impl Registry {
    fn held(&self, window: &str) -> bool {
        self.all_held.is_some() || self.held_windows.contains_key(window)
    }
    fn holds(&self, window: &str, fence: DrainFence) -> bool {
        self.all_held == Some(fence.0) || self.held_windows.get(window) == Some(&fence.0)
    }
    fn fence(&mut self) -> DrainFence {
        self.next_fence = self
            .next_fence
            .checked_add(1)
            .expect("drain fence exhausted");
        DrainFence(self.next_fence)
    }
}
/// A native close/Quit/update drain. It never leaves native code and is not
/// note authority; ending an older fence cannot release a newer one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DrainFence(u64);
fn noop() {}
type Hooks = (fn(), fn(), fn());
const NO_HOOKS: Hooks = (noop, noop, noop);
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
    compaction: Arc<Scheduler>,
    note_work: NoteWork,
    writers: writers::Writers,
    records_wake: RecordsWakeSlot,
}

#[cfg(debug_assertions)]
#[doc(hidden)]
impl Owner {
    /// Test-only owner with background body extraction disabled.
    pub fn without_maintenance() -> Self {
        Self {
            compaction: Arc::new(Scheduler::without_maintenance()),
            ..Self::default()
        }
    }
    /// Test-only release of a paused worker, using the ordinary scheduling path.
    pub fn resume_maintenance(&self, id: ContainerId) -> Result<(), OwnerError> {
        let database = self.shared_database(id)?;
        self.compaction.resume_maintenance();
        self.compaction.schedule_maintenance(id, &database);
        self.compaction.schedule_derived_if_pending(id, &database);
        Ok(())
    }
    /// Test-only signal for completed body extractions, without a clock wait.
    pub fn notifying_maintenance(sender: std::sync::mpsc::Sender<(ContainerId, usize)>) -> Self {
        Self {
            compaction: Arc::new(Scheduler::notifying(sender)),
            ..Self::default()
        }
    }
    /// Test-only: as [`Self::notifying_maintenance`], on a caller-driven
    /// clock with the given quiet period. Call [`Self::wake_maintenance`]
    /// after moving the clock.
    pub fn notifying_maintenance_with_clock(
        sender: std::sync::mpsc::Sender<(ContainerId, usize)>,
        now: impl Fn() -> std::time::Instant + Send + Sync + 'static,
        quiet: std::time::Duration,
    ) -> Self {
        Self {
            compaction: Arc::new(Scheduler::notifying_with_clock(sender, now, quiet)),
            ..Self::default()
        }
    }
    /// Test-only: let a worker waiting on the test clock recompute deadlines.
    pub fn wake_maintenance(&self) {
        self.compaction.wake();
    }
    /// Test-only: no maintenance or derived turn is queued, deferred or running.
    pub fn maintenance_idle(&self, id: ContainerId) -> bool {
        self.compaction.idle(id)
    }
    /// Test-only: as [`Self::notifying_maintenance`], with at most `turns`
    /// derived turns, so a test can stop a build after an acknowledged turn.
    pub fn notifying_derived_turns(
        sender: std::sync::mpsc::Sender<(ContainerId, usize)>,
        turns: usize,
    ) -> Self {
        Self {
            compaction: Arc::new(Scheduler::notifying_with_derived_turns(sender, turns)),
            ..Self::default()
        }
    }
}

/// One native Note page and its local coverage, kept separate from the UI's
/// existing array-only binding.
#[derive(Debug)]
pub struct NoteListPage {
    pub rows: Vec<NoteEntry>,
    pub completeness: Completeness,
}

#[derive(Debug)]
pub enum OwnerError {
    Store(StoreError),
    Open(OpenError),
    Io(std::io::Error),
    Busy,
    Unbound,
    UnknownContainer,
    Changed,
    DuplicateAnchor,
    AnchorMismatch,
    WriterUnavailable,
    /// The log is stopped by a proven contradiction.
    Stopped,
    /// The base is not registered here, so it has no accepted log yet.
    NotRegistered,
    /// The batch does not continue this device's verified progress, or
    /// does not prove itself one verified run ending at its receipt's head.
    InvalidBatch,
    /// Verification cannot run here as configured (a History pinned to
    /// another hosting root than the log's, or local state that does not
    /// reproduce its continuation): `UnavailablePause`, nothing judged.
    Unavailable,
    /// The local note engine could not run. No content or account verdict;
    /// retain exact work and retry without changing verified progress.
    NoteUnavailable,
    /// Not the next account event after the base's copy of the account, or
    /// this device is not active in that copy: nothing to copy.
    CopyRefused,
    /// A container that joined by pairing is not usable before its
    /// bootstrap activated it.
    NotActivated,
    /// The pending update cannot be sealed now; its work stays pending.
    SealRefused(SealRefusal),
}
impl From<StoreError> for OwnerError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NoteUnavailable => Self::NoteUnavailable,
            StoreError::LogStopped => Self::Stopped,
            other => Self::Store(other),
        }
    }
}
impl From<bh_core::note::NoteError> for OwnerError {
    fn from(error: bh_core::note::NoteError) -> Self {
        StoreError::from(error).into()
    }
}
impl From<bh_core::note::WriterError> for OwnerError {
    fn from(error: bh_core::note::WriterError) -> Self {
        match error {
            bh_core::note::WriterError::Update(e) => e.into(),
            _ => StoreError::InvalidUpdate.into(),
        }
    }
}
impl From<HostError> for OwnerError {
    fn from(error: HostError) -> Self {
        match error {
            HostError::Unbound => Self::Unbound,
            HostError::Changed => Self::Changed,
            HostError::Store(e) => e.into(),
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
            loaded.note.state()?.len().max(1)
        } else {
            0
        };
        return Ok((loaded.note, loaded.frontier, weight));
    }
    let (note, frontier) = rebuild_from_writer(database, key)?;
    let weight = if weigh_cold {
        note.state()?.len().max(1)
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
    let mut note = Note::from_ordered(&seed.state)?;
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
            note.apply_update(&delta)?;
            after = id;
        }
    }
    Ok((note, seed.target))
}
/// The ordered updates a loaded note integrated, read without holding the
/// writer across pages, and the frontier they reach.
fn durable_ordered(
    database: &Arc<Mutex<DeviceDatabase>>,
    key: NoteKey,
) -> Result<(OrderedState, i64), StoreError> {
    let pool = database.lock().expect("container writer lock").read_pool();
    if let Some(pool) = pool {
        return pool.note_ordered(key);
    }
    let seed = database
        .lock()
        .expect("container writer lock")
        .note_seed(key)?;
    let mut ordered = seed.state;
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
            ordered.push(delta);
            after = id;
        }
    }
    Ok((ordered, seed.target))
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
    fn anchored(&self, id: ContainerId) -> bool {
        self.registry
            .lock()
            .expect("owner registry lock")
            .containers
            .get(&id)
            .is_some_and(|c| c.anchor.is_some())
    }
    /// Queue committed deliveries in order, atomically with their sequence
    /// numbers. Overflow replaces only committed queued bytes with one
    /// bounded marker, which keeps any reload it replaced; an off-guard
    /// reader hydrates it before delivery. Returns the windows to wake.
    fn enqueue(&self, id: ContainerId, targets: Vec<Delivery>) -> Vec<String> {
        let mut windows = Vec::with_capacity(targets.len());
        let mut queues = self.deliveries.lock().expect("delivery lock");
        for item in targets {
            windows.push(item.window.clone());
            let queue = queues.entry(item.window.clone()).or_default();
            if queue.pending.len() >= DELIVERY_LIMIT
                || queue.bytes.saturating_add(item.update.len()) > DELIVERY_BYTES
            {
                let reload = item.reload || queue.pending.iter().any(|(_, d)| d.reload);
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
                        segments: Vec::new(),
                        reload,
                    },
                ));
            } else {
                queue.bytes = queue.bytes.saturating_add(item.update.len());
                queue.pending.push_back((id, item));
            }
        }
        windows
    }
    fn account_readers(&self, id: ContainerId) -> Result<(Session, Arc<ReadPool>), OwnerError> {
        let registry = self.registry.lock().expect("owner registry lock");
        let container = registry
            .containers
            .get(&id)
            .ok_or(OwnerError::UnknownContainer)?;
        Ok((
            Arc::clone(&container.session),
            Arc::clone(container.readers.as_ref().ok_or(OwnerError::Unbound)?),
        ))
    }
    fn account_session(&self, id: ContainerId) -> Result<Session, OwnerError> {
        let registry = self.registry.lock().expect("owner registry lock");
        Ok(Arc::clone(
            &registry
                .containers
                .get(&id)
                .ok_or(OwnerError::UnknownContainer)?
                .session,
        ))
    }
    /// Remove every route into this container and its queued deliveries.
    /// Call with that container's session guard held.
    fn drop_routes(
        &self,
        id: ContainerId,
        guard: &mut Coordinator<AccountAuthority>,
    ) -> Vec<String> {
        let affected: Vec<_> = {
            let mut registry = self.registry.lock().expect("owner registry lock");
            let affected: Vec<_> = registry
                .windows
                .iter()
                .filter(|(_, route)| route.container == id)
                .map(|(window, _)| window.clone())
                .collect();
            for window in &affected {
                registry.windows.remove(window);
                guard.invalidate(window);
            }
            affected
        };
        self.writers
            .active
            .lock()
            .expect("writer leases")
            .retain(|_, writer| writer.container != id);
        let mut queues = self.deliveries.lock().expect("delivery lock");
        for window in &affected {
            queues.remove(window);
        }
        affected
    }
    /// Native caller supplies the ordinary own BaseId verified by account
    /// admission. This API cannot validate that external proof; it never derives
    /// a base from a filename, account ID or page input. Anchor alone is not note
    /// authority. Reinstalling the same capability keeps windows bound; a new
    /// capability ends every earlier load in this container.
    pub fn authorize(
        &self,
        id: ContainerId,
        capability: Arc<AccountCapability>,
        own_base: [u8; 32],
    ) -> Result<(), OwnerError> {
        let session = self.account_session(id)?;
        let mut guard = session.lock().expect("container session lock");
        let database = guard.shared_database();
        let writer = database.lock().expect("container writer lock");
        if writer.joined()?.is_some_and(|joined| !joined.activated) {
            return Err(OwnerError::NotActivated);
        }
        // Replacing authority would end loads that Quit/update is draining.
        if self
            .registry
            .lock()
            .expect("owner registry lock")
            .all_held
            .is_some()
        {
            return Err(OwnerError::Busy);
        }
        if !capability.is_current()
            || self
                .registry
                .lock()
                .expect("owner registry lock")
                .containers
                .get(&id)
                .and_then(|c| c.anchor)
                != Some(capability.account_id().0)
        {
            return Err(OwnerError::Unbound);
        }
        if guard
            .authority()
            .current()
            .is_some_and(|(base, current)| base == own_base && Arc::ptr_eq(&current, &capability))
        {
            return Ok(());
        }
        self.drop_routes(id, &mut guard);
        *guard.authority_mut() = AccountAuthority::Account {
            capability,
            own_base,
            windows: HashMap::new(),
        };
        Ok(())
    }
    /// Lock may have already revoked the capability. Do not wait for a browser
    /// reply; return the labels whose native pages must reload.
    pub fn deauthorize(&self, id: ContainerId) -> Result<Vec<String>, OwnerError> {
        let session = self.account_session(id)?;
        let mut guard = session.lock().expect("container session lock");
        let affected = self.drop_routes(id, &mut guard);
        *guard.authority_mut() = AccountAuthority::Unbound;
        Ok(affected)
    }
    /// Native routing only: the container a window's note belongs to.
    pub fn bound_container(&self, window: &str) -> Option<ContainerId> {
        let registry = self.registry.lock().expect("owner registry lock");
        let route = registry.windows.get(window)?;
        registry
            .containers
            .get(&route.container)?
            .anchor
            .map(|_| route.container)
    }
    /// Run `write` with the container's own base while its capability is
    /// current, under the session and writer guards that fence replacement.
    fn with_authorized_writer<R>(
        &self,
        id: ContainerId,
        write: impl FnOnce(&mut DeviceDatabase, [u8; 32]) -> Result<R, OwnerError>,
    ) -> Result<R, OwnerError> {
        let session = self.account_session(id)?;
        let guard = session.lock().expect("container session lock");
        let database = guard.shared_database();
        let mut db = database.lock().expect("container writer lock");
        let (base, _) = guard.authority().current().ok_or(OwnerError::Unbound)?;
        write(&mut db, base)
    }
    pub fn create_note(&self, id: ContainerId) -> Result<[u8; 32], OwnerError> {
        let note = self
            .with_authorized_writer(id, |db, base| Ok(db.create_note(base, ORDINARY_AUDIENCE)?))?;
        self.compaction
            .schedule_maintenance(id, &self.shared_database(id)?);
        Ok(note)
    }
    pub fn home_note(&self, id: ContainerId) -> Result<[u8; 32], OwnerError> {
        let note =
            self.with_authorized_writer(id, |db, base| Ok(db.home_note(base, ORDINARY_AUDIENCE)?))?;
        self.compaction
            .schedule_maintenance(id, &self.shared_database(id)?);
        Ok(note)
    }
    /// True only for an ordinary note in this container's authorized own base.
    pub fn has_note(&self, id: ContainerId, note: [u8; 32]) -> Result<bool, OwnerError> {
        self.with_authorized_writer(id, |db, base| {
            Ok(db.note_exists(NoteKey {
                base,
                audience: ORDINARY_AUDIENCE,
                note,
            })?)
        })
    }
    pub fn open_home(&self, window: &str, id: ContainerId) -> Result<[u8; 32], OwnerError> {
        let note = self.home_note(id)?;
        self.show_note(window, id, note)?;
        Ok(note)
    }
    /// Native-only route; a note must exist under the full own-base/zero-audience
    /// key. The window's earlier load stops at once: every open, commit and
    /// delivery checks this route, so another container's stale binding cannot
    /// write or deliver. Its session is not locked here, which could wait for
    /// (or, from a commit hook, deadlock on) that container's save.
    pub fn show_note(
        &self,
        window: &str,
        id: ContainerId,
        note: [u8; 32],
    ) -> Result<(), OwnerError> {
        let session = self.account_session(id)?;
        {
            let mut guard = session.lock().expect("container session lock");
            let database = guard.shared_database();
            let db = database.lock().expect("container writer lock");
            let (base, capability) = guard.authority().current().ok_or(OwnerError::Unbound)?;
            if !db.note_exists(NoteKey {
                base,
                audience: ORDINARY_AUDIENCE,
                note,
            })? {
                return Err(OwnerError::Unbound);
            }
            let mut registry = self.registry.lock().expect("owner registry lock");
            if registry.held(window) {
                return Err(OwnerError::Busy);
            }
            if registry.containers.get(&id).and_then(|c| c.anchor)
                != Some(capability.account_id().0)
            {
                return Err(OwnerError::Unbound);
            }
            registry.windows.insert(
                window.to_owned(),
                WindowRoute {
                    container: id,
                    generation: None,
                },
            );
            guard.invalidate(window);
            if let AccountAuthority::Account { windows, .. } = guard.authority_mut() {
                windows.insert(window.to_owned(), note);
            }
            guard.allow_bound_window(window);
        }
        self.deliveries
            .lock()
            .expect("delivery lock")
            .remove(window);
        Ok(())
    }
    /// The existing native UI consumes only rows. Headless consumers that
    /// need to distinguish a partial list use `list_notes_page` instead.
    pub fn list_notes(
        &self,
        id: ContainerId,
        after: Option<(i64, [u8; 32])>,
        limit: usize,
    ) -> Result<Vec<NoteEntry>, OwnerError> {
        Ok(self.list_notes_page(id, after, limit)?.rows)
    }

    /// The Note-family query on a read-pool connection, with authority checked
    /// before and after. `touched` in these rows is `$changed`: for ordinary
    /// Notes it follows core Note touches; specialised Notes also move up after
    /// typed field changes. Known limit: failed projections lag recency or disappear until repair.
    /// Complete covers this replica's verified progress,
    /// not catch-up to the known head. A future UI claiming "all notes" must
    /// also require Synced or UpdateNeeded sync status.
    pub fn list_notes_page(
        &self,
        id: ContainerId,
        after: Option<(i64, [u8; 32])>,
        limit: usize,
    ) -> Result<NoteListPage, OwnerError> {
        if limit > bh_storage::MAX_NOTE_PAGE {
            return Err(OwnerError::Store(StoreError::InvalidNotePage));
        }
        let (session, pool) = self.account_readers(id)?;
        let (base, capability) = session
            .lock()
            .expect("container session lock")
            .authority()
            .current()
            .ok_or(OwnerError::Unbound)?;
        let scope = Scope {
            base,
            audience: ORDINARY_AUDIENCE,
        };
        let reads = [scope];
        let mut query = Query {
            select: TypeSelect::Family(TypeId::core("note")),
            filter: None,
            sort: vec![SortKey {
                key: KeyRef::Changed,
                desc: true,
            }],
            fields: vec![bh_data::FieldPath::parse("/title").expect("core Note title")],
            follow: vec![],
            text: None,
            limit: limit as u32,
            after: None,
        };
        let result = pool.read_data(|conn| {
            if let Some((changed, note)) = after {
                query.after = Some(
                    query::after_changed(
                        conn,
                        scope,
                        &reads,
                        &Shipped,
                        &query,
                        changed,
                        RecordId(note),
                    )
                    .map_err(|error| bh_data::DataError::Sql(error.to_string()))?,
                );
            }
            query::run(conn, scope, &reads, &Shipped, &query, Budget::INTERACTIVE)
                .map_err(|error| bh_data::DataError::Sql(error.to_string()))
        });
        let current = session
            .lock()
            .expect("container session lock")
            .authority()
            .current()
            .is_some_and(|(b, cap)| b == base && Arc::ptr_eq(&cap, &capability));
        if !current {
            return Err(OwnerError::Unbound);
        }
        let page = result.map_err(|error| OwnerError::Store(StoreError::Data(error)))?;
        let rows = page
            .rows
            .into_iter()
            .map(|row| {
                Ok(NoteEntry {
                    note: row.record.0,
                    title: row
                        .values
                        .get("/title")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(OwnerError::Store(StoreError::InvalidNotePage))?
                        .to_owned(),
                    touched: row
                        .changed
                        .ok_or(OwnerError::Store(StoreError::InvalidNotePage))?,
                })
            })
            .collect::<Result<Vec<_>, OwnerError>>()?;
        Ok(NoteListPage {
            rows,
            completeness: page.completeness,
        })
    }
    /// Consume restart presentation only after authorize. A row never grants
    /// authority: discard non-own-base, non-zero-audience or absent notes and
    /// call show_note again for every chosen destination before any page bind.
    /// `anchor`/`head` are the page's encoded Yjs selection positions (bounded
    /// presentation bytes, not an account): the per-account container and the
    /// current capability and own base supply the authority.
    pub fn take_authorized_view_records(
        &self,
        id: ContainerId,
    ) -> Result<Vec<ViewRecord>, OwnerError> {
        let session = self.account_session(id)?;
        let guard = session.lock().expect("container session lock");
        let database = guard.shared_database();
        let mut writer = database.lock().expect("container writer lock");
        let (base, _) = guard.authority().current().ok_or(OwnerError::Unbound)?;
        let mut applicable = Vec::new();
        for record in writer.take_view_records()? {
            if record.anchor.len() <= MAX_SELECTION_BYTES
                && record.head.len() <= MAX_SELECTION_BYTES
                && record.key.base == base
                && record.key.audience == ORDINARY_AUDIENCE
                && writer.note_exists(record.key)?
            {
                applicable.push(record);
            }
        }
        Ok(applicable)
    }
    /// Hold every window for Quit or update: no new route, load or account
    /// authorization starts, while already accepted writing keeps saving
    /// until each window replies drained.
    pub fn begin_drain(&self) -> Result<DrainFence, OwnerError> {
        let mut registry = self.registry.lock().expect("owner registry lock");
        if registry.all_held.is_some() || !registry.held_windows.is_empty() {
            return Err(OwnerError::Busy);
        }
        let fence = registry.fence();
        registry.all_held = Some(fence.0);
        Ok(fence)
    }
    /// Hold one closing window; other windows and accounts carry on.
    pub fn begin_window_drain(&self, window: &str) -> Result<DrainFence, OwnerError> {
        let mut registry = self.registry.lock().expect("owner registry lock");
        if registry.held(window) {
            return Err(OwnerError::Busy);
        }
        let fence = registry.fence();
        registry.held_windows.insert(window.to_owned(), fence.0);
        Ok(fence)
    }
    /// Ends exactly this fence and its drained marks; a stale one is ignored.
    pub fn end_drain(&self, fence: DrainFence) {
        let mut registry = self.registry.lock().expect("owner registry lock");
        if registry.all_held == Some(fence.0) {
            registry.all_held = None;
        }
        registry.held_windows.retain(|_, held| *held != fence.0);
        registry.drained.retain(|_, held| *held != fence.0);
    }
    fn drained(&self, window: &str) -> bool {
        self.registry
            .lock()
            .expect("owner registry lock")
            .drained
            .contains_key(window)
    }
    /// The page replied that it drained under `fence`. Serialized with COMMIT
    /// under the note lease: a save already inside it finishes first, none
    /// starts after. A loading or note-less surface is fenced the same way.
    /// Returns the note only for an open ordinary own-base load, the one kind
    /// a restart record may name.
    pub fn mark_drained(
        &self,
        window: &str,
        fence: DrainFence,
    ) -> Result<Option<(ContainerId, NoteKey)>, OwnerError> {
        let route = {
            let mut registry = self.registry.lock().expect("owner registry lock");
            if !registry.holds(window, fence) {
                return Err(OwnerError::Unbound);
            }
            match registry.windows.get(window).copied() {
                Some(WindowRoute {
                    container,
                    generation: Some(generation),
                }) => (container, generation),
                _ => {
                    registry.drained.insert(window.to_owned(), fence.0);
                    return Ok(None);
                }
            }
        };
        let Some((id, key)) = self.bound_work_key(window, route.1) else {
            // A closed or revoked load can no longer write: nothing to wait for.
            let mut registry = self.registry.lock().expect("owner registry lock");
            if !registry.holds(window, fence) {
                return Err(OwnerError::Unbound);
            }
            registry.drained.insert(window.to_owned(), fence.0);
            return Ok(None);
        };
        let work = self.work_lock(id, key);
        let _lease = work
            .lock
            .as_ref()
            .unwrap()
            .lock()
            .expect("exclusive note work lock");
        if self.bound_work_key(window, route.1) != Some((id, key)) {
            return Err(OwnerError::Unbound);
        }
        let ordinary = self
            .account_session(id)?
            .lock()
            .expect("container session lock")
            .authority()
            .current()
            .is_some_and(|(base, _)| key.base == base && key.audience == ORDINARY_AUDIENCE);
        let mut registry = self.registry.lock().expect("owner registry lock");
        if !registry.holds(window, fence)
            || registry.windows.get(window)
                != Some(&WindowRoute {
                    container: id,
                    generation: Some(route.1),
                })
        {
            return Err(OwnerError::Unbound);
        }
        registry.drained.insert(window.to_owned(), fence.0);
        Ok(ordinary.then_some((id, key)))
    }
    /// Every anchored container's writer, including those with no open
    /// window, so a restart replaces each one's records. Never a setup file.
    pub fn anchored_databases(&self) -> Vec<(ContainerId, Arc<Mutex<DeviceDatabase>>)> {
        let mut sessions: Vec<_> = {
            let registry = self.registry.lock().expect("owner registry lock");
            registry
                .containers
                .iter()
                .filter(|(_, c)| c.anchor.is_some())
                .map(|(id, c)| (*id, Arc::clone(&c.session)))
                .collect()
        };
        // A stable order, so a partial failure is reproducible.
        sessions.sort_by_key(|(id, _)| id.0);
        sessions
            .into_iter()
            .map(|(id, session)| {
                let database = session
                    .lock()
                    .expect("container session lock")
                    .shared_database();
                (id, database)
            })
            .collect()
    }
    /// Recent bounded maintenance turns for this live container, oldest first.
    /// Read-only local diagnostics; no telemetry or persistent samples.
    pub fn maintenance_stats(&self, id: ContainerId) -> Result<Vec<MaintenanceTurn>, OwnerError> {
        self.shared_database(id)?;
        Ok(self.compaction.maintenance_stats(id))
    }
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
    /// True only for a never-anchored container with no durable account,
    /// pending setup, staged admission or device identity. A caller may reuse
    /// an empty unanchored file left by an interrupted signup.
    pub fn is_empty(&self, id: ContainerId) -> Result<bool, OwnerError> {
        let database = self.shared_database(id)?;
        let db = database.lock().expect("container writer lock");
        let empty = db.account_container_empty()?;
        let registry = self.registry.lock().expect("owner registry lock");
        let container = registry
            .containers
            .get(&id)
            .ok_or(OwnerError::UnknownContainer)?;
        Ok(empty && container.anchor.is_none())
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
        self.install(database, anchor, AccountAuthority::Fixture(authority))
    }

    // An opened file deliberately starts without authority even when it has a
    // stored account. Only anchor() compares the independently verified log.
    fn install(
        &self,
        database: DeviceDatabase,
        anchor: Option<[u8; 32]>,
        authority: AccountAuthority,
    ) -> Result<ContainerId, OwnerError> {
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
        let readers = database.read_pool();
        let session = Coordinator::new(database, authority);
        let writer = session.shared_database();
        registry.containers.insert(
            id,
            Container {
                anchor,
                session: Arc::new(Mutex::new(session)),
                readers,
            },
        );
        drop(registry);
        self.compaction.schedule_backfill(id, &writer);
        self.compaction.schedule_maintenance(id, &writer);
        self.compaction.schedule_derived_if_pending(id, &writer);
        Ok(id)
    }
    /// Setup and fixture routing only. Account routes require show_note's full
    /// key existence and capability check; bind cannot revive an old assignment.
    pub fn bind(&self, window: &str, id: ContainerId) -> Result<(), OwnerError> {
        let new = self.account_session(id)?;
        let old = {
            // Hold the session so authorize cannot install account authority
            // between this check and the route.
            let guard = new.lock().expect("container session lock");
            if matches!(guard.authority(), AccountAuthority::Account { .. }) {
                return Err(OwnerError::Unbound);
            }
            let mut registry = self.registry.lock().expect("owner registry lock");
            if registry.held(window) {
                return Err(OwnerError::Busy);
            }
            registry
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
                })
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
        after_snapshot: impl FnMut(u8),
    ) -> Result<Opened, OwnerError> {
        self.open_mode(window, note, after_snapshot, false, None)
    }
    fn open_mode(
        &self,
        window: &str,
        note: [u8; 32],
        mut after_snapshot: impl FnMut(u8),
        leased: bool,
        retire: Option<[u8; 32]>,
    ) -> Result<Opened, OwnerError> {
        let (id, session, anchor) = self.routed(window)?;
        // Checked before this open advances the window's generation, so a
        // stale or foreign token changes nothing; rechecked under the fences.
        let retiring = retire
            .map(|token| self.retiring_writer(window, id, note, token))
            .transpose()?;
        let generation = self
            .next_generation
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("generation exhausted");
        {
            let mut registry = self.registry.lock().expect("owner registry lock");
            if registry.held(window) {
                return Err(OwnerError::Busy);
            }
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
            // The view integrates the same updates in the same order; a
            // merged state could reopen concurrent text elsewhere.
            let (source, read) = durable_ordered(&database, scope.key)?;
            if read != frontier {
                drop(lease);
                continue;
            }
            let due = {
                database
                    .lock()
                    .expect("container writer lock")
                    .checkpoint_due(scope.key)?
            };
            // Opening tries only one full state, one rebuild. A note that
            // needs more opens from its stored order and is compacted by the
            // background checkpoint scheduled below.
            let checkpoint_state = due.then(|| built.merged()).transpose()?.flatten();
            let state = checkpoint_state.clone().unwrap_or(source);
            let weight = state.segments().iter().map(Vec::len).sum::<usize>().max(1);
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
            // Account lock fences under this writer: recheck authority here,
            // not only in the earlier scope read.
            let mut db = database.lock().expect("container writer lock");
            if let Some(capability) = guard.authority().capability()
                && (!capability.is_current() || !db.note_exists(scope.key)?)
            {
                return Err(OwnerError::Unbound);
            }
            if db.local_frontier(scope.key)? != frontier {
                drop(db);
                drop(guard);
                drop(lease);
                continue;
            }
            if !self.route_current(window, id, generation) {
                return Err(OwnerError::Unbound);
            }
            let active = if leased {
                let cap = guard
                    .authority()
                    .capability()
                    .ok_or(OwnerError::WriterUnavailable)?;
                let principal = (cap.account_id().0, cap.device_id().0);
                let retire = retiring
                    .map(|old| self.recheck_retiring(window, old, scope.key, principal))
                    .transpose()?;
                Some(self.allocate_writer(
                    window, id, generation, &mut db, scope.key, principal, &built, retire,
                )?)
            } else {
                None
            };
            let result = guard.open_with_state(window, note, generation, expected, state);
            drop(db);
            match result {
                Err(HostError::Changed) => {
                    drop(guard);
                    drop(lease);
                    continue;
                }
                other => {
                    let mut opened = other?;
                    if let Some(active) = active {
                        opened.writer = Some(active.lease);
                        self.writers
                            .active
                            .lock()
                            .expect("writer leases")
                            .insert(window.to_owned(), active);
                    }
                    // Reuse the exact owned Note for first save. A checkpoint
                    // gets the state already verified for the view; no second
                    // history replay.
                    let checkpoint = checkpoint_state.and_then(|state| {
                        database
                            .lock()
                            .expect("container writer lock")
                            .prepare_loaded_checkpoint(scope.key, frontier, &state)
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
                    self.compaction.schedule_maintenance(id, &database);
                    self.compaction.schedule_derived_if_pending(id, &database);
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
            self.commit_queued_with_work_hook(window, generation, request, update, NO_HOOKS, None)?;
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
            self.commit_queued_with_work_hook(window, generation, request, update, NO_HOOKS, None)?;
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
        self.commit_queued_with_work_hook(window, generation, request, update, NO_HOOKS, None)
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
        let (ack, targets, _) = self.commit_queued_with_work_hook(
            window,
            generation,
            request,
            update,
            (prepare, noop, noop),
            None,
        )?;
        for target in targets {
            self.drain_surface(&target, &mut deliver);
        }
        Ok(ack)
    }
    /// Test seam after the final session/route check and before the writer.
    #[doc(hidden)]
    pub fn commit_with_writer_hook(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
        before_writer: impl FnOnce(),
    ) -> Result<Ack, OwnerError> {
        self.commit_queued_with_work_hook(
            window,
            generation,
            request,
            update,
            (noop, before_writer, noop),
            None,
        )
        .map(|(ack, _, _)| ack)
    }
    /// Test seam while holding the exact account writer guard, before SQL COMMIT.
    #[doc(hidden)]
    pub fn commit_with_writer_guard_hook(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
        inside_writer: impl FnOnce(),
    ) -> Result<Ack, OwnerError> {
        self.commit_queued_with_work_hook(
            window,
            generation,
            request,
            update,
            (noop, noop, inside_writer),
            None,
        )
        .map(|(ack, _, _)| ack)
    }
    fn commit_queued_with_work_hook(
        &self,
        window: &str,
        generation: u64,
        request: [u8; 16],
        update: &[u8],
        hooks: (impl FnOnce(), impl FnOnce(), impl FnOnce()),
        writer_token: Option<[u8; 32]>,
    ) -> Result<(Ack, Vec<String>, Duration), OwnerError> {
        let (prepare, before_writer, inside_writer) = hooks;
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
            // mark_drained takes this same note lease: a reply either waits
            // for this save or this save sees the reply and writes nothing.
            if self.drained(window) {
                return Err(OwnerError::Unbound);
            }
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
                let guard = session.lock().expect("container session lock");
                let writer = database.lock().expect("container writer lock");
                if guard.bound_scope(window) != Some(scope)
                    || !self.route_current(window, id, generation)
                    || guard
                        .authority()
                        .capability()
                        .is_some_and(|capability| !capability.is_current())
                {
                    return Err(OwnerError::Unbound);
                }
                writer.committed_request(scope.key, request, update)?
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
            let active = writer_token
                .map(|token| self.writer_for(window, id, generation, token, scope.key))
                .transpose()?;
            let (mut working, frontier, weight) = load_working_note(&database, scope.key, true)?;
            let attempt = active
                .map(|active| {
                    let db = database.lock().expect("container writer lock");
                    self.attempt_fence(active, &db, &working)
                })
                .transpose()?;
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
            if let Some(active) = active {
                working.apply_writer_update(update, active.slot.client_id)?;
            } else {
                working.apply_update(update)?;
            }
            // Bounded read of the exclusively owned candidate, committed with
            // its delta; derived before any session or writer guard.
            let title = working.title_preview()?;
            let exhausted = active
                .map(|a| working.writer_end(a.slot.client_id))
                .transpose()?
                .flatten()
                == Some(u32::MAX);
            // Session ownership fences authority replacement until COMMIT; the
            // writer guard fences an account lock. yrs work is already done.
            let guard = session.lock().expect("container session lock");
            if guard.bound_scope(window) != Some(scope)
                || !guard.is_current(window, generation)
                || !self.route_current(window, id, generation)
            {
                return Err(OwnerError::Unbound);
            }
            before_writer();
            let mut writer = database.lock().expect("container writer lock");
            if let Some(capability) = guard.authority().capability()
                && (!capability.is_current() || !writer.note_exists(scope.key)?)
            {
                return Err(OwnerError::Unbound);
            }
            inside_writer();
            // The window may have shown another container's note meanwhile.
            // Do not hold the process registry through COMMIT: other accounts
            // must not wait for this file. A switch after this check still
            // saves writing typed into this exact authorized note.
            if !self.route_current(window, id, generation) || self.drained(window) {
                return Err(OwnerError::Unbound);
            }
            // The only SQLite write section is this scoped CAS and insert.
            // A stale candidate is discarded, never installed or fanned out.
            let (committed, sql_hold) = if let (Some(active), Some(attempt)) = (active, attempt) {
                self.writer_for(window, id, generation, active.lease.token, scope.key)?;
                let cap = guard
                    .authority()
                    .capability()
                    .ok_or(OwnerError::WriterUnavailable)?;
                if active.slot.account != cap.account_id().0
                    || active.slot.device != cap.device_id().0
                {
                    return Err(OwnerError::WriterUnavailable);
                }
                self.final_fence(active, &writer, &working, attempt)?;
                let start = std::time::Instant::now();
                let commit = writer.commit_writer_update_with_title(
                    frontier,
                    anchor,
                    request,
                    update,
                    &active.slot,
                    &title,
                )?;
                let held = start.elapsed();
                // Valid terminal progress leaves no clock: end this producer
                // now. Allocation retires the slot before further authoring.
                if exhausted {
                    self.writers
                        .active
                        .lock()
                        .expect("writer leases")
                        .remove(window);
                }
                (commit, held)
            } else {
                // Raw fixture APIs cannot publish from a real account surface.
                if guard.authority().capability().is_some() {
                    return Err(OwnerError::WriterUnavailable);
                }
                writer.commit_working_update_timed(scope.key, frontier, anchor, request, update)?
            };
            drop(writer);
            drop(guard);
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
                (result, self.enqueue(id, targets))
            };
            Ok((result, windows, database, sql_hold))
        })();
        drop(note_guard);
        drop(work);
        let (result, targets, database, sql_hold) = outcome?;
        self.compaction.schedule(id, scope.key, &database);
        if !result.replayed {
            self.compaction.schedule_local_maintenance(id, &database);
        }
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
            durable_ordered(&database, key)
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
            durable_ordered(&database, key)
        })
    }
    /// Test seam for deterministic snapshot failure. No callback runs under a
    /// writer, coordinator or process-owner guard. False means retry marker.
    #[doc(hidden)]
    pub fn drain_surface_with_snapshot(
        &self,
        window: &str,
        deliver: &mut impl FnMut(Delivery),
        snapshot: impl FnMut(NoteKey) -> Result<(OrderedState, i64), StoreError>,
    ) -> bool {
        self.drain_with_snapshot(window, deliver, false, snapshot)
    }
    fn drain_with_snapshot(
        &self,
        window: &str,
        deliver: &mut impl FnMut(Delivery),
        once: bool,
        mut snapshot: impl FnMut(NoteKey) -> Result<(OrderedState, i64), StoreError>,
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
                        item.segments = state.into_segments()
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
                                if let Some((_, later)) =
                                    queue.pending.iter_mut().find(|(id, d)| {
                                        *id == origin
                                            && d.generation == item.generation
                                            && d.resync
                                            && d.sequence >= item.sequence
                                    })
                                {
                                    // That later marker covers this one.
                                    later.reload |= item.reload;
                                } else {
                                    if let Some((_, last)) = queue.pending.back() {
                                        item.sequence = item.sequence.max(last.sequence);
                                        item.through_update_id =
                                            item.through_update_id.max(last.through_update_id);
                                    }
                                    item.reload |= queue.pending.iter().any(|(_, d)| d.reload);
                                    item.update.clear();
                                    item.segments.clear();
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
        let reload = item.reload || queue.pending.iter().any(|(_, later)| later.reload);
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
                segments: Vec::new(),
                reload,
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
                self.writers
                    .active
                    .lock()
                    .expect("writer leases")
                    .remove(window);
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
            let mut guard = session.lock().expect("container session lock");
            self.writers
                .active
                .lock()
                .expect("writer leases")
                .remove(window);
            guard.invalidate(window);
            guard.authority_mut().forget(window);
        }
    }
}
