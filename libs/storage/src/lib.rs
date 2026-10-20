//! Device-local SQLite ownership and open-time compatibility checks.
//!
//! This adapter stores the device's local note deltas, pending-work references,
//! each sealed pending outbound package and its exact ordered acknowledgement,
//! and the typed opaque account journal (anchor, signed events, head, sticky
//! stop, device identity, pending setup), and incoming sync state: each log's
//! verified progress and each note's accepted state, kept apart from pending
//! local work (see `sync_state`). The native app holds a database when
//! a session installs one; no production session supplies a note binding yet.
//! Pending local work is not an authenticated network event. Authority and
//! rebuildable indexes stay apart.

pub mod account;
mod catalogue;
mod data;
pub mod held_notes;
pub mod joined;
pub mod note_writers;
pub mod own_base;
pub mod retained;
mod runs;
pub mod sync_state;
pub mod typed_outbox;
pub use catalogue::{MAX_NOTE_PAGE, MAX_NOTE_TITLE, NoteEntry};
pub use data::NoteBodyText;
#[cfg(feature = "testkit")]
pub use data::testkit;
mod view_records;
pub use typed_outbox::{
    OutboxCandidate, OutboxOrder, QueuedTyped, StoredTypedPackage, SubmitTypedError, TypedEcho,
    TypedHead, TypedPackageCandidate, TypedPackagePreparation, TypedPackageProgress,
};
pub use view_records::ViewRecord;
mod local_reads;
mod read_pool;
pub use local_reads::{CheckpointJob, NoteSeed, PendingPage};
pub use read_pool::{LoadedNote, ReadPool, ReadResult};

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use bh_core::{
    LOCAL_DATA_VERSION, check_local_data_version,
    note::{Note, OrderedState},
};
use bh_data::text;
use bh_sync::{BodyObject, Commitment, EventId, OpaqueEvent, referenced_body};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenError {
    #[error("local data version {found} requires a newer client (supports {supported})")]
    NewerData { found: u32, supported: u32 },
    #[error("local database could not be opened")]
    Database(#[from] rusqlite::Error),
    #[error("container lock could not be opened: {0}")]
    LockFile(#[from] io::Error),
    #[error("container is owned by another process")]
    Busy,
}

/// One owner for a device-local database. The connection is deliberately private:
/// the UI receives domain operations, never arbitrary SQL or filesystem access.
pub struct DeviceDatabase {
    connection: Connection,
    // Dropped after the SQLite connection; never unlink the lock inode.
    _lock: Option<Arc<File>>,
    readers: Option<Arc<ReadPool>>,
    notes: HashMap<NoteKey, CachedNote>,
    cache_bytes: usize,
    cache_budget: usize,
    tick: u64,
    data_version: u32,
}
// Charge allocated guest linear memory, including its retained high-water mark,
// plus a conservative 256 KiB allowance for each host Store/instance, handles,
// and cache entry. The shared compiled module is not per-note. This is a cache
// policy, NOT measured RSS or a process-memory cap (working Notes are excluded).
const NOTE_CACHE_OVERHEAD: usize = 256 * 1024;
const INLINE_WAL_FRAMES: u32 = 4_000;
const QUIET_WAL_FRAMES: u64 = 256;
fn cache_weight(note: &Note) -> Result<usize, bh_core::note::NoteError> {
    Ok(note.memory_bytes()?.saturating_add(NOTE_CACHE_OVERHEAD))
}
struct CachedNote {
    note: Note,
    frontier: i64,
    // Replay bytes are caller bookkeeping, never a proxy for resident memory.
    encoded_weight: usize,
    weight: usize,
    last: u64,
}

/// Local indexing keys, not an authority assertion or a wire format. Only a
/// trusted future account binding may supply these to the device store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NoteKey {
    pub base: [u8; 32],
    pub audience: [u8; 32],
    pub note: [u8; 32],
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("local database file unavailable")]
    Io(#[from] std::io::Error),
    #[error("local SQLite transaction failed")]
    Database(#[from] rusqlite::Error),
    #[error("invalid note update")]
    InvalidUpdate,
    #[error("local note engine unavailable; durable state retained")]
    NoteUnavailable,
    #[error("note is absent from the ordinary local catalogue")]
    MissingNote,
    #[error("note title exceeds the preview limit")]
    InvalidNoteTitle,
    #[error("note page exceeds the bounded limit or contains a corrupt id")]
    InvalidNotePage,
    #[error("local note touch counter exhausted")]
    NoteCounterExhausted,
    #[error("invalid window view record")]
    InvalidViewRecord,
    #[error("note changed since working projection was loaded")]
    StaleNote,
    #[error("verified account anchor or availability changed")]
    AuthorityChanged,
    #[error("local request id reused with different content")]
    RequestConflict,
    #[error("stored account state is inconsistent")]
    CorruptAccount,
    #[error("account head has no matching stored signed bytes")]
    HeadWithoutBytes,
    #[error("pending update not found")]
    MissingPending,
    #[error("unscoped pending enumeration exceeded its small-fixture budget; use pending_page")]
    PageRequired,
    #[error("invalid sealed package")]
    InvalidPackage,
    #[error("ordered acknowledgement conflicts with stored package or acknowledgement")]
    AckConflict,
    #[error("stored outbox package is inconsistent")]
    CorruptOutbox,
    #[error("a staged account admission already exists")]
    StagedAdmissionExists,
    #[error("staged account admission changed before it could be cleared")]
    StagedAdmissionChanged,
    #[error("staged account admission row is invalid")]
    CorruptStagedAdmission,
    #[error("stored own-base record is inconsistent")]
    CorruptOwnBase,
    #[error("invalid or unavailable writer reservation")]
    InvalidWriter,
    #[error("log is stopped by a proven contradiction")]
    LogStopped,
    #[error("batch does not continue the stored log progress")]
    StaleProgress,
    #[error("stored sync state is inconsistent")]
    CorruptSyncState,
    #[error("log has no registered continuation")]
    MissingProgress,
    #[error("another hosting root is pinned for this log")]
    RootConflict,
    #[error("publishing is stopped by a local alarm")]
    PublishingStopped,
    #[error("typed record storage failed: {0}")]
    Data(#[from] bh_data::DataError),
}

impl From<bh_core::note::NoteError> for StoreError {
    fn from(error: bh_core::note::NoteError) -> Self {
        match error {
            bh_core::note::NoteError::Unavailable => Self::NoteUnavailable,
            _ => Self::InvalidUpdate,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalCommit {
    pub update_id: i64,
    pub replayed: bool,
}

/// Unsent *local* delta, neither encrypted nor signed. Packaging into an
/// authenticated event requires real account authority/keys in a later step.
pub struct PendingNoteUpdate {
    pub update_id: i64,
    pub key: NoteKey,
    pub bytes: Vec<u8>,
    /// Immutable joined proof preimage; None is explicitly legacy/fixture work.
    /// Native packaging verifies derivation and encodes the shared declaration.
    pub writer: Option<note_writers::WriterSlot>,
}
/// Seal `pending` with native authority only after releasing the owner/DB
/// guards, then CAS-persist these exact bytes with publish_note_package.
/// `pending` is the run it covers merged into one update, keyed by the
/// run's last update.
pub struct PackageCandidate {
    pub event_id: EventId,
    pub pending: PendingNoteUpdate,
    /// The pending updates the package covers, oldest first; the last is
    /// `pending.update_id`.
    covers: Vec<i64>,
}
pub enum PackagePreparation {
    Existing(StoredNotePackage),
    Candidate(PackageCandidate),
}

/// Immutable package: retain even after an Ack to reconcile duplicate receipts.
/// Acknowledgement input is a checked, exact `Commitment`; its provenance and
/// current service authority must be established by the caller before using it.
pub struct StoredNotePackage {
    pub event_id: EventId,
    pub descriptor: OpaqueEvent,
    pub body: Vec<u8>,
    pub ack: Option<Commitment>,
}

impl DeviceDatabase {
    /// Open without deleting or replacing existing data on any failure.
    ///
    /// Container locking recognizes native `accounts/*.sqlite` paths only;
    /// aliases (other case or hard links) are a known limit. Production paths
    /// come from native container creation/enumeration, not untrusted input.
    /// Check compatibility before changing journal mode. Recheck while holding
    /// the migration write lock so concurrent openers cannot downgrade a version.
    /// Small schema changes and their version marker commit in one transaction.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let path = path.as_ref();
        if path.extension().is_some_and(|ext| ext == "sqlite")
            && path
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == "accounts")
        {
            return Self::open_container(path);
        }
        Self::open_with_lock(path, None)
    }

    /// Native container entry point. Take the sibling advisory lock before
    /// opening SQLite, and retain it for the lifetime of this shared database.
    pub fn open_container(path: &Path) -> Result<Self, OpenError> {
        let lock_path = path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        Self::lock_and_open(path, lock)
    }

    /// Claim a fresh random name by creating its lock inode exclusively,
    /// then flock before allowing SQLite to create the database. `None` means
    /// the caller should choose another random name.
    pub fn create_container(path: &Path) -> Result<Option<Self>, OpenError> {
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path.with_extension("lock"))
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(None),
            Err(error) => return Err(OpenError::LockFile(error)),
        };
        // Do not overwrite an existing database whose lock inode was lost.
        if path.exists() {
            return Ok(None);
        }
        Self::lock_and_open(path, lock).map(Some)
    }

    fn lock_and_open(path: &Path, lock: File) -> Result<Self, OpenError> {
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| OpenError::Busy)?;
        Self::open_with_lock(path, Some(lock))
    }

    fn open_with_lock(path: &Path, lock: Option<File>) -> Result<Self, OpenError> {
        let lock = lock.map(Arc::new);
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        ensure_supported(version(&connection)?)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        // Autocheckpoint threshold for bursts with no quiet maintenance
        // (including in-memory and test-support writers): roughly 16 MiB at
        // the default page size. It triggers a checkpoint; it does not bound
        // an active WAL, which readers can keep from resetting.
        // journal_size_limit below only trims the file retained after a reset.
        connection.pragma_update(None, "wal_autocheckpoint", INLINE_WAL_FRAMES)?;
        let page_size: i64 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let quiet_wal_limit = 32 + QUIET_WAL_FRAMES as i64 * (page_size + 24);
        connection.pragma_update(None, "journal_size_limit", quiet_wal_limit)?;
        connection.pragma_update(None, "foreign_keys", true)?;

        initialize(&mut connection)?;
        let readers = (path != Path::new(":memory:"))
            .then(|| ReadPool::new(path.to_path_buf(), lock.clone()));
        Ok(Self {
            connection,
            _lock: lock,
            readers,
            notes: HashMap::new(),
            cache_bytes: 0,
            cache_budget: 32 * 1024 * 1024,
            tick: 0,
            data_version: LOCAL_DATA_VERSION,
        })
    }

    /// Checkpoint on a quiet maintenance turn, never waiting for readers.
    /// The writer guard must span this call; FULL commit sync remains unchanged.
    pub fn checkpoint_wal_if_needed(&self) -> Result<i64, StoreError> {
        let Some(path) = self.connection.path() else {
            return Ok(0);
        };
        if path.is_empty() {
            return Ok(0);
        }
        let page_size: i64 = self
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))?;
        let wal = format!("{path}-wal");
        let bytes = match std::fs::metadata(wal) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(StoreError::Io(error)),
        };
        let frames = bytes.saturating_sub(32) / (page_size as u64 + 24);
        if frames <= QUIET_WAL_FRAMES {
            return Ok(0);
        }
        let (_busy, _log, checkpointed): (i64, i64, i64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        Ok(checkpointed.max(0))
    }

    pub fn data_version(&self) -> u32 {
        self.data_version
    }
    pub fn read_pool(&self) -> Option<Arc<ReadPool>> {
        self.readers.clone()
    }
    /// Scoped typed-data host access. Only this database owns the writer.
    pub fn with_data_read<R>(
        &self,
        read: impl FnOnce(&rusqlite::Connection) -> Result<R, bh_data::DataError>,
    ) -> Result<R, bh_data::DataError> {
        read(&self.connection)
    }
    pub fn with_data_write<R>(
        &mut self,
        write: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<R, bh_data::DataError>,
    ) -> Result<R, bh_data::DataError> {
        let tx = self
            .connection
            .transaction()
            .map_err(|e| bh_data::DataError::Sql(e.to_string()))?;
        let result = write(&tx)?;
        tx.commit()
            .map_err(|e| bh_data::DataError::Sql(e.to_string()))?;
        Ok(result)
    }
    /// Probe only durable derived-work markers; opening an idle container does
    /// not scan typed records or replay history.
    pub fn derived_pending(&self) -> Result<bool, StoreError> {
        self.with_data_read(|conn| {
            Ok(bh_data::index::has_pending(conn)?
                || bh_data::text::reprojection_pending(conn)?
                || bh_data::mutation::apply::replay_pending(conn)?)
        })
        .map_err(StoreError::Data)
    }

    /// Advance one index or rebuild batch, committing before the next guarded
    /// section. A newly ready unique index queues a replay pass over its scope's
    /// parked work atomically with readiness; [`Self::derived_replay_step`]
    /// runs that pass in bounded pages, so readiness itself replays nothing.
    pub fn derived_index_step(&mut self, vm_steps: u64) -> Result<(), StoreError> {
        let tx = self.connection.transaction()?;
        let next = bh_data::index::next_pending(&tx).map_err(StoreError::Data)?;
        if next == Some(bh_data::index::TEXT_REBUILD_WORK) {
            if bh_data::index::clearing_pending(&tx).map_err(StoreError::Data)? {
                bh_data::index::clear_step_bounded(&tx, 32, vm_steps).map_err(StoreError::Data)?;
            } else {
                bh_data::text::rebuild_step_bounded(&tx, 32, vm_steps).map_err(StoreError::Data)?;
            }
        } else if let Some(ix) = next {
            let state = bh_data::index::state(&tx, ix).map_err(StoreError::Data)?;
            if state.state == "clearing" {
                bh_data::index::clear_step_bounded(&tx, 32, vm_steps).map_err(StoreError::Data)?;
            } else {
                let progress = bh_data::index::backfill_step_bounded(
                    &tx,
                    ix,
                    bh_data::index::BACKFILL_BATCH,
                    vm_steps,
                )
                .map_err(StoreError::Data)?;
                // Only a unique index can release parked work (uniqueness
                // waits), so other indexes becoming ready queue no pass.
                if state.state == "building" && state.unique && progress.ready {
                    bh_data::mutation::apply::schedule_replay(&tx, state.scope)
                        .map_err(StoreError::Data)?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// One bounded page of a queued parked-work replay pass in its own writer
    /// transaction: the page's verdicts, the own typed packages they decide
    /// and the pass's cursor commit together, so a crash repeats or skips no
    /// row and settles no package twice.
    pub fn derived_replay_step(&mut self, vm_steps: u64) -> Result<(), StoreError> {
        let tx = self.connection.transaction()?;
        data::replay_page(&tx, vm_steps)?;
        tx.commit()?;
        Ok(())
    }

    /// One bounded search-mapping batch in its own writer transaction.
    pub fn derived_reproject_step(&mut self, vm_steps: u64) -> Result<(), StoreError> {
        let tx = self.connection.transaction()?;
        if bh_data::text::reprojection_pending(&tx).map_err(StoreError::Data)? {
            bh_data::text::reproject_step(&tx, &bh_data::catalogue::Shipped, 500, vm_steps)
                .map_err(StoreError::Data)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Canonical Note text for search extraction. File containers have this
    /// read source; an in-memory one does not. Take it under the DB guard,
    /// release the guard, then call [`NoteBodyText::next_batch`]: decoding
    /// needs no writer and must not hold the guard.
    pub fn note_body_source(&self) -> Option<NoteBodyText> {
        self.readers.clone().map(NoteBodyText::for_pool)
    }
    /// One bounded repair turn: each missing projection is re-derived from its
    /// catalogue title in its own short transaction, so no Note is decoded. A
    /// caller may run this while holding the DB guard.
    pub fn repair_projections(&mut self, max_repairs: usize) -> Result<usize, StoreError> {
        data::repair_step(&mut self.connection, max_repairs)
    }
    /// Store one batch decoded by [`NoteBodyText::next_batch`] in one short
    /// transaction. Callers take the source from [`Self::note_body_source`]
    /// under the DB guard, release the guard while decoding, then reacquire it
    /// only for this call. A job whose revision moved while it was decoded
    /// stores nothing and stays queued at its new revision. Returns how many
    /// jobs were attempted and how many were stored; the work limit can leave
    /// later jobs of the batch for a later turn.
    pub fn store_body_batch(
        &mut self,
        batch: &[text::DecodedJob],
        max_vm_steps: u64,
    ) -> Result<text::ExtractOutcome, StoreError> {
        if batch.is_empty() {
            return Ok(text::ExtractOutcome::default());
        }
        let tx = self.connection.transaction()?;
        let outcome =
            text::store_batch_bounded(&tx, batch, max_vm_steps).map_err(StoreError::Data)?;
        tx.commit()?;
        Ok(outcome)
    }
    /// Per-container budget; only durably committed Notes are retained here.
    pub fn set_note_cache_budget(&mut self, bytes: usize) {
        self.cache_budget = bytes;
        self.evict_clean();
    }
    pub fn cached_note_count(&self) -> usize {
        self.notes.len()
    }
    fn evict_clean(&mut self) {
        while self.cache_bytes > self.cache_budget {
            let Some(oldest) = self
                .notes
                .iter()
                .min_by_key(|(_, entry)| entry.last)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.forget_note(oldest);
        }
    }
    fn forget_note(&mut self, key: NoteKey) {
        if let Some(entry) = self.notes.remove(&key) {
            self.cache_bytes = self.cache_bytes.saturating_sub(entry.weight);
        }
    }
    /// Remove a committed canonical Note for exclusive work. No dirty Note is
    /// visible to a read or another writer while this owned value is borrowed.
    pub fn take_cached_note(&mut self, key: NoteKey, frontier: i64) -> Option<(Note, usize)> {
        let entry = self.notes.remove(&key)?;
        self.cache_bytes = self.cache_bytes.saturating_sub(entry.weight);
        (entry.frontier == frontier).then_some((entry.note, entry.encoded_weight))
    }
    /// Only a successfully committed or unchanged Note may re-enter this cache.
    /// Retention is best-effort: a failed host memory query drops the instance,
    /// never changes a committed save into an error or suppresses its Ack.
    pub fn return_committed_note(
        &mut self,
        key: NoteKey,
        note: Note,
        frontier: i64,
        encoded_weight: usize,
    ) {
        self.forget_note(key);
        let Ok(weight) = cache_weight(&note) else {
            return;
        };
        if weight > self.cache_budget {
            return;
        }
        self.tick = self.tick.checked_add(1).expect("LRU counter exhausted");
        self.cache_bytes = self.cache_bytes.saturating_add(weight);
        self.notes.insert(
            key,
            CachedNote {
                note,
                frontier,
                encoded_weight,
                weight,
                last: self.tick,
            },
        );
        self.evict_clean();
    }

    // Reads can allocate too. Reweigh after the operation, before retaining the
    // instance. A metric failure affects caching only, not an already read value
    // or committed write. Failed engine operations separately discard the Note.
    fn refresh_note_charge(&mut self, key: NoteKey) {
        if let Some(entry) = self.notes.get_mut(&key) {
            match cache_weight(&entry.note) {
                Ok(weight) if weight <= self.cache_budget => {
                    self.cache_bytes = self
                        .cache_bytes
                        .saturating_sub(entry.weight)
                        .saturating_add(weight);
                    entry.weight = weight;
                }
                _ => self.forget_note(key),
            }
        }
        self.evict_clean();
    }

    fn load_note(&mut self, key: NoteKey) -> Result<&mut Note, StoreError> {
        if !self.notes.contains_key(&key) {
            let ordered = self.note_ordered(key)?;
            let note = Note::from_ordered(&ordered)?;
            let encoded_weight = ordered.segments().iter().map(Vec::len).sum();
            let weight = cache_weight(&note)?;
            let frontier = self.local_frontier(key)?;
            self.cache_bytes = self.cache_bytes.saturating_add(weight);
            self.notes.insert(
                key,
                CachedNote {
                    note,
                    frontier,
                    encoded_weight,
                    weight,
                    last: self.tick,
                },
            );
        }
        self.tick = self.tick.checked_add(1).expect("LRU counter exhausted");
        let entry = self.notes.get_mut(&key).expect("loaded note");
        entry.last = self.tick;
        Ok(&mut entry.note)
    }

    /// The checkpoint's ordered updates, then every later row: reopening
    /// them in this order gives the note's integrated structure.
    pub fn note_ordered(&self, key: NoteKey) -> Result<OrderedState, StoreError> {
        let checkpoint:Option<(i64,Vec<u8>)>=self.connection.query_row(
            "SELECT local_frontier,encoded_yjs FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",
            params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let (covered, encoded) = checkpoint.unwrap_or((0, Vec::new()));
        let mut ordered = OrderedState::decode(&encoded).map_err(|_| StoreError::InvalidUpdate)?;
        let mut stmt = self.connection.prepare_cached(
            "SELECT delta FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 AND id>?4 ORDER BY id",
        )?;
        let rows = stmt.query_map(
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice(),
                covered
            ],
            |r| r.get::<_, Vec<u8>>(0),
        )?;
        for row in rows {
            ordered.push(row?);
        }
        Ok(ordered)
    }

    pub fn note_state(&mut self, key: NoteKey) -> Result<Vec<u8>, StoreError> {
        let state = self
            .load_note(key)
            .and_then(|note| note.state().map_err(StoreError::from));
        if state.is_err() {
            // A trapped read poisoned the working instance, not its durable
            // prefix. Retry must rebuild rather than keep that dead cache entry.
            self.forget_note(key);
        } else {
            self.refresh_note_charge(key);
        }
        state
    }

    /// The *same local request* can be retried without inserting duplicate work.
    /// This is separate from a future randomly generated encrypted EventId.
    /// The connection and cached note are exclusively borrowed until commit; an
    /// uncommitted mutation is never observable. Discard the cache on *any* error,
    /// even an error while applying an update, then replay committed rows on read.
    pub fn apply_local_update(
        &mut self,
        key: NoteKey,
        request: [u8; 16],
        bytes: &[u8],
    ) -> Result<LocalCommit, StoreError> {
        let result = self.commit_local(key, request, bytes);
        if result.is_err() {
            self.forget_note(key);
        } else {
            self.refresh_note_charge(key);
        }
        result
    }

    pub fn local_frontier(&self, key: NoteKey) -> Result<i64, StoreError> {
        Ok(self.connection.query_row("SELECT COALESCE(MAX(id),0) FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],|r|r.get(0))?)
    }
    /// Compare before any yrs work; replaying this request must never apply
    /// its delta twice or broadcast it again.
    pub fn committed_request(
        &self,
        key: NoteKey,
        request: [u8; 16],
        bytes: &[u8],
    ) -> Result<Option<LocalCommit>, StoreError> {
        if let Some((id, existing)) = self.existing_request(key, request)? {
            if existing != bytes {
                return Err(StoreError::RequestConflict);
            }
            return Ok(Some(LocalCommit {
                update_id: id,
                replayed: true,
            }));
        }
        Ok(None)
    }
    /// Measure the SQL write section *after* the caller obtains the writer
    /// mutex; this excludes yrs apply, cache restore and mutex wait. Native
    /// callers can use it for local opt-in scale measurements (not telemetry).
    pub fn commit_working_update_timed(
        &mut self,
        key: NoteKey,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
    ) -> Result<(LocalCommit, Duration), StoreError> {
        let started = Instant::now();
        let result = self.commit_working_update(key, frontier, anchor, request, bytes)?;
        Ok((result, started.elapsed()))
    }
    /// Short SQLite CAS. Call only after applying the delta on an exclusively
    /// owned Note outside every container/DB guard; restore it only on COMMIT.
    pub fn commit_working_update(
        &mut self,
        key: NoteKey,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
    ) -> Result<LocalCommit, StoreError> {
        self.commit_working_update_inner(key, frontier, anchor, request, bytes, None, None)
    }
    /// Timed catalogue-aware variant for a future guarded owner. The title
    /// must already have been derived outside session and writer guards.
    pub fn commit_working_update_with_title_timed(
        &mut self,
        key: NoteKey,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
        title: &str,
    ) -> Result<(LocalCommit, Duration), StoreError> {
        let started = Instant::now();
        let result =
            self.commit_working_update_with_title(key, frontier, anchor, request, bytes, title)?;
        Ok((result, started.elapsed()))
    }
    /// The caller derives the bounded preview from its working Note outside
    /// the writer guard. This does not establish authority for the row/key.
    pub fn commit_working_update_with_title(
        &mut self,
        key: NoteKey,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
        title: &str,
    ) -> Result<LocalCommit, StoreError> {
        if title.chars().count() > MAX_NOTE_TITLE {
            return Err(StoreError::InvalidNoteTitle);
        }
        self.commit_working_update_inner(key, frontier, anchor, request, bytes, Some(title), None)
    }
    #[allow(clippy::too_many_arguments)] // One atomic delta/catalogue/proof write.
    fn commit_working_update_inner(
        &mut self,
        key: NoteKey,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
        title: Option<&str>,
        writer: Option<&note_writers::WriterSlot>,
    ) -> Result<LocalCommit, StoreError> {
        self.commit_working_update_mode(key, frontier, anchor, request, bytes, title, writer, true)
    }
    /// Measurement-only baseline for the paired commit comparison: the same
    /// atomic save without the derived projection.
    #[cfg(feature = "testkit")]
    #[allow(clippy::too_many_arguments)]
    pub fn commit_working_update_with_title_baseline(
        &mut self,
        key: NoteKey,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
        title: &str,
    ) -> Result<LocalCommit, StoreError> {
        if title.chars().count() > MAX_NOTE_TITLE {
            return Err(StoreError::InvalidNoteTitle);
        }
        self.commit_working_update_mode(
            key,
            frontier,
            anchor,
            request,
            bytes,
            Some(title),
            None,
            false,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn commit_working_update_mode(
        &mut self,
        key: NoteKey,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
        title: Option<&str>,
        writer: Option<&note_writers::WriterSlot>,
        project: bool,
    ) -> Result<LocalCommit, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<(Vec<u8>, bool)> = tx
            .query_row(
                "SELECT anchor,stopped FROM account_state WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        if stored
            .as_ref()
            .is_none_or(|(id, stopped)| id.as_slice() != anchor || *stopped)
        {
            return Err(StoreError::AuthorityChanged);
        }
        let existing:Option<(i64,Vec<u8>)>=tx.query_row("SELECT id,delta FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 AND request=?4",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice(),request.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((id, old)) = existing {
            return if old == bytes {
                Ok(LocalCommit {
                    update_id: id,
                    replayed: true,
                })
            } else {
                Err(StoreError::RequestConflict)
            };
        }
        let actual:i64=tx.query_row("SELECT COALESCE(MAX(id),0) FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],|r|r.get(0))?;
        if actual != frontier {
            return Err(StoreError::StaleNote);
        }
        tx.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice(),
                request.as_slice(),
                bytes
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute("INSERT INTO pending_note_work(update_id) VALUES (?1)", [id])?;
        tx.execute(
            "INSERT INTO pending_scope(update_id,base,audience,note) VALUES (?1,?2,?3,?4)",
            params![
                id,
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice()
            ],
        )?;
        if let Some(writer) = writer {
            if writer.key != key || writer.account != anchor {
                return Err(StoreError::InvalidWriter);
            }
            note_writers::link(&tx, id, writer)?;
        }
        catalogue::touch(&tx, key, title)?;
        if project {
            // An untitled save still changed the body, so the projection follows
            // the catalogue title it already has.
            let title = match title {
                Some(title) => title.to_owned(),
                None => data::catalogued_title(&tx, key)?,
            };
            data::project_note(&tx, key, &title)?;
        }
        tx.commit()?;
        Ok(LocalCommit {
            update_id: id,
            replayed: false,
        })
    }
    fn existing_request(
        &self,
        key: NoteKey,
        request: [u8; 16],
    ) -> Result<Option<(i64, Vec<u8>)>, StoreError> {
        Ok(self.connection.query_row(
            "SELECT id, delta FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 AND request=?4",
            params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice(),request.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?)
    }

    fn commit_local(
        &mut self,
        key: NoteKey,
        request: [u8; 16],
        bytes: &[u8],
    ) -> Result<LocalCommit, StoreError> {
        if let Some((id, existing)) = self.existing_request(key, request)? {
            if existing != bytes {
                return Err(StoreError::RequestConflict);
            }
            return Ok(LocalCommit {
                update_id: id,
                replayed: true,
            });
        }
        self.load_note(key)?.apply_update(bytes)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice(),
                request.as_slice(),
                bytes
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute("INSERT INTO pending_note_work(update_id) VALUES (?1)", [id])?;
        tx.execute(
            "INSERT INTO pending_scope(update_id,base,audience,note) VALUES (?1,?2,?3,?4)",
            params![
                id,
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice()
            ],
        )?;
        catalogue::touch(&tx, key, None)?;
        let title = data::catalogued_title(&tx, key)?;
        data::project_note(&tx, key, &title)?;
        tx.commit()?;
        if let Some(entry) = self.notes.get_mut(&key) {
            entry.frontier = id;
            entry.encoded_weight = entry.encoded_weight.saturating_add(bytes.len());
        }
        Ok(LocalCommit {
            update_id: id,
            replayed: false,
        })
    }

    /// Phase 1: release the database guard after this call. The native issuer
    /// seals immutable bytes outside all DB/owner guards; the prepared id is
    /// never submitted until phase 2 succeeds. The package covers the note's
    /// first bounded uncovered pending run through `update_id`, which
    /// must be one writer's (or a single update); an update already covered
    /// returns its package.
    pub fn prepare_note_package(&self, update_id: i64) -> Result<PackagePreparation, StoreError> {
        if sync_state::publishing_stopped(&self.connection)? {
            return Err(StoreError::PublishingStopped);
        }
        if let Some(existing) = read_package(&self.connection, update_id)? {
            return Ok(PackagePreparation::Existing(existing));
        }
        let key = runs::update_key(&self.connection, update_id)?;
        if let Some(package) = runs::covering(&self.connection, update_id)? {
            let existing = read_package(&self.connection, package)?;
            return existing
                .map(PackagePreparation::Existing)
                .ok_or(StoreError::CorruptOutbox);
        }
        runs::pending_key(&self.connection, update_id)?;
        let run = runs::updates(&self.connection, key, 0, update_id)?;
        if run.last().map(|u| u.id) != Some(update_id) {
            return Err(StoreError::RequestConflict);
        }
        if run.len() > 1
            && run.iter().map(|u| u.delta.len()).sum::<usize>() > runs::RUN_BYTES as usize
        {
            return Err(StoreError::InvalidPackage);
        }
        let covers: Vec<i64> = run.iter().map(|u| u.id).collect();
        let bytes = match <[runs::RunUpdate; 1]>::try_from(run) {
            Ok([only]) => only.delta,
            Err(run) => {
                bh_core::note::merge_updates(&run.into_iter().map(|u| u.delta).collect::<Vec<_>>())?
            }
        };
        Ok(PackagePreparation::Candidate(PackageCandidate {
            event_id: EventId(bh_crypto::random::<32>()),
            pending: PendingNoteUpdate {
                update_id,
                key,
                bytes,
                writer: note_writers::pending_writer(&self.connection, update_id)?,
            },
            covers,
        }))
    }
    /// Phase 2: the short IMMEDIATE CAS rejects a run that changed or whose
    /// work retired. An uncertain duplicate at the same endpoint returns
    /// its persisted attempt; overlapping candidates at other endpoints fail.
    pub fn publish_note_package(
        &mut self,
        candidate: PackageCandidate,
        descriptor: OpaqueEvent,
        body: BodyObject,
    ) -> Result<StoredNotePackage, StoreError> {
        let id = candidate.event_id;
        if id.0 == [0; 32]
            || descriptor.id() != id
            || referenced_body(&descriptor).map_err(|_| StoreError::InvalidPackage)?
                != body.commitment()
        {
            return Err(StoreError::InvalidPackage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if sync_state::publishing_stopped(&tx)? {
            return Err(StoreError::PublishingStopped);
        }
        let update_id = candidate.pending.update_id;
        if let Some(existing) = read_package(&tx, update_id)? {
            return Ok(existing);
        }
        let key = runs::pending_key(&tx, update_id)?;
        if key != candidate.pending.key {
            return Err(StoreError::RequestConflict);
        }
        if runs::covering(&tx, update_id)?.is_some() {
            return Err(StoreError::RequestConflict);
        }
        let run = runs::updates(&tx, key, 0, update_id)?;
        if run
            .iter()
            .map(|u| u.id)
            .ne(candidate.covers.iter().copied())
            || (run.len() == 1 && run[0].delta != candidate.pending.bytes)
        {
            return Err(StoreError::RequestConflict);
        }
        tx.execute(
            "INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES (?1,?2,?3,?4)",
            params![
                update_id,
                id.0.as_slice(),
                descriptor.encode(),
                body.bytes()
            ],
        )?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO note_outbox_members(update_id,package_update_id) VALUES(?1,?2)",
            )?;
            for member in &candidate.covers {
                insert.execute(params![member, update_id])?;
            }
        }
        tx.commit()?;
        Ok(StoredNotePackage {
            event_id: id,
            descriptor,
            body: body.bytes().to_vec(),
            ack: None,
        })
    }
    /// Small single-thread test helper. Native callers with a container mutex
    /// must use prepare/publish above; this closure must never run under that
    /// mutex, even though SQLite itself is unlocked during it.
    pub fn package_note_update(
        &mut self,
        update_id: i64,
        seal: impl FnOnce(EventId, &PendingNoteUpdate) -> Result<(OpaqueEvent, BodyObject), StoreError>,
    ) -> Result<StoredNotePackage, StoreError> {
        match self.prepare_note_package(update_id)? {
            PackagePreparation::Existing(stored) => Ok(stored),
            PackagePreparation::Candidate(candidate) => {
                let (descriptor, body) = seal(candidate.event_id, &candidate.pending)?;
                self.publish_note_package(candidate, descriptor, body)
            }
        }
    }

    /// Match the complete ordered record to the immutable descriptor and
    /// record the position it names. An ordered Ack is not acceptance: the
    /// pending row stays until the verified echo of an accepted package
    /// retires it. A duplicate Ack must match byte-for-byte.
    pub fn acknowledge_note_update(
        &mut self,
        update_id: i64,
        ack: &Commitment,
    ) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = read_package(&tx, update_id)?.ok_or(StoreError::MissingPending)?;
        if ack.base().0
            != tx
                .query_row(
                    "SELECT base FROM note_updates WHERE id=?1",
                    [update_id],
                    |r| r.get::<_, Vec<u8>>(0),
                )?
                .as_slice()
            || ack.verify_body(&stored.descriptor).is_err()
        {
            return Err(StoreError::AckConflict);
        }
        if let Some(existing) = stored.ack {
            return if existing.encode() == ack.encode() {
                Ok(false)
            } else {
                Err(StoreError::AckConflict)
            };
        }
        // This store checks only exact byte identity against its sealed
        // package; the verified echo decides what became of it.
        tx.execute(
            "UPDATE note_outbox SET ack=?2 WHERE update_id=?1",
            params![update_id, ack.encode()],
        )?;
        let position = i64::try_from(ack.head().position).map_err(|_| StoreError::CorruptOutbox)?;
        tx.execute(
            "INSERT INTO note_outbox_progress(update_id,staged,acked_position,outcome) VALUES (?1,1,?2,1)
             ON CONFLICT(update_id) DO UPDATE SET staged=1,
               acked_position=COALESCE(acked_position,excluded.acked_position),
               outcome=COALESCE(outcome,1)",
            params![update_id, position],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// The highest still-pending local update, if there is one: one indexed
    /// lookup over the pending work's primary key, so its cost does not grow
    /// with how many unsent rows there are. Used only for in-memory pacing
    /// hints; the durable queue is unchanged.
    pub fn highest_pending_update(&self) -> Result<Option<i64>, StoreError> {
        Ok(self.connection.query_row(
            "SELECT MAX(update_id) FROM pending_note_work",
            [],
            |row| row.get(0),
        )?)
    }

    /// Legacy small-fixture helper. Production work uses scoped keyset pages;
    /// never allocate an entire offline backlog into one Vec.
    pub fn pending_note_updates(&self) -> Result<Vec<PendingNoteUpdate>, StoreError> {
        let mut stmt = self.connection.prepare("SELECT u.id,u.base,u.audience,u.note,u.delta FROM note_updates u JOIN pending_note_work p ON p.update_id=u.id ORDER BY u.id LIMIT 257")?;
        let rows = stmt.query_map([], |row| {
            let decode = |index| -> rusqlite::Result<[u8; 32]> {
                let bytes: Vec<u8> = row.get(index)?;
                bytes.try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        index,
                        "scope".into(),
                        rusqlite::types::Type::Blob,
                    )
                })
            };
            Ok(PendingNoteUpdate {
                update_id: row.get(0)?,
                key: NoteKey {
                    base: decode(1)?,
                    audience: decode(2)?,
                    note: decode(3)?,
                },
                bytes: row.get(4)?,
                writer: None,
            })
        })?;
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let row = row?;
            bytes = bytes.saturating_add(row.bytes.len());
            if result.len() == 256 || bytes > 256 * 1024 {
                return Err(StoreError::PageRequired);
            }
            let mut row = row;
            row.writer = note_writers::pending_writer(&self.connection, row.update_id)?;
            result.push(row);
        }
        Ok(result)
    }
}

fn read_package(
    connection: &Connection,
    update_id: i64,
) -> Result<Option<StoredNotePackage>, StoreError> {
    let row = connection
        .query_row(
            "SELECT event_id,descriptor,body,ack FROM note_outbox WHERE update_id=?1",
            [update_id],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((id, descriptor, body, ack)) = row else {
        return Ok(None);
    };
    let event_id = EventId(id.try_into().map_err(|_| StoreError::CorruptOutbox)?);
    let descriptor = OpaqueEvent::decode(&descriptor).map_err(|_| StoreError::CorruptOutbox)?;
    let object = BodyObject::new(body).map_err(|_| StoreError::CorruptOutbox)?;
    if descriptor.id() != event_id
        || referenced_body(&descriptor).map_err(|_| StoreError::CorruptOutbox)?
            != object.commitment()
    {
        return Err(StoreError::CorruptOutbox);
    }
    let ack = ack
        .map(|bytes| Commitment::decode(&bytes).map_err(|_| StoreError::CorruptOutbox))
        .transpose()?;
    if ack.is_some_and(|record| record.verify_body(&descriptor).is_err()) {
        return Err(StoreError::CorruptOutbox);
    }
    Ok(Some(StoredNotePackage {
        event_id,
        descriptor,
        body: object.bytes().to_vec(),
        ack,
    }))
}

fn version(connection: &Connection) -> Result<u32, OpenError> {
    Ok(connection.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

fn ensure_supported(found: u32) -> Result<(), OpenError> {
    check_local_data_version(found).map_err(|error| OpenError::NewerData {
        found: error.found,
        supported: error.supported,
    })
}

/// One ordered migration step per layout change, with the target version. Each
/// step and its version marker commit together, so a failed step leaves the
/// prior layout intact. Step `(0, 2)` keeps the original empty/v1 note layout.
type Migration = fn(&rusqlite::Transaction<'_>) -> rusqlite::Result<()>;
const MIGRATIONS: &[(u32, u32, Migration)] = &[
    (0, 2, migrate_v1_to_v2),
    (2, 3, migrate_v2_to_v3),
    (3, 4, migrate_v3_to_v4),
    (4, 5, migrate_v4_to_v5),
    (5, 6, migrate_v5_to_v6),
    (6, 7, migrate_v6_to_v7),
    (7, 8, migrate_v7_to_v8),
    (8, 9, migrate_v8_to_v9),
    (9, 10, note_writers::migrate),
    (10, 11, sync_state::migrate),
    (11, 12, runs::migrate),
    (12, 13, data::migrate),
];

fn initialize(connection: &mut Connection) -> Result<(), OpenError> {
    // `open` already refused newer data before changing the journal mode. Each
    // pass re-reads the version under the write lock: a concurrent opener that
    // advanced the layout is seen here, never by running a step on newer data.
    loop {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = version(&transaction)?;
        ensure_supported(current)?;
        if current >= LOCAL_DATA_VERSION {
            held_notes::ensure_layout(&transaction)?;
            transaction.commit()?;
            return Ok(());
        }
        let Some((_, target, step)) = MIGRATIONS
            .iter()
            .find(|(from, to, _)| *from <= current && current < *to)
        else {
            return Err(OpenError::NewerData {
                found: current,
                supported: LOCAL_DATA_VERSION,
            });
        };
        step(&transaction)?;
        transaction.pragma_update(None, "user_version", *target)?;
        transaction.commit()?;
    }
}

fn migrate_v1_to_v2(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    // v1 contained no content tables. Create both related tables together.
    transaction.execute_batch(
        "CREATE TABLE note_updates (
            id INTEGER PRIMARY KEY,
            base BLOB NOT NULL CHECK(length(base)=32),
            audience BLOB NOT NULL CHECK(length(audience)=32),
            note BLOB NOT NULL CHECK(length(note)=32),
            request BLOB NOT NULL CHECK(length(request)=16),
            delta BLOB NOT NULL,
            UNIQUE(base,audience,note,request)
        );
        CREATE INDEX note_updates_scope ON note_updates(base,audience,note,id);
        CREATE TABLE pending_note_work (
            update_id INTEGER PRIMARY KEY REFERENCES note_updates(id) DEFERRABLE INITIALLY DEFERRED
        );",
    )
}

fn migrate_v2_to_v3(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    // Device-local account journal: typed opaque rows only, no bh-account types.
    transaction.execute_batch(
        "CREATE TABLE account_state (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            anchor BLOB NOT NULL CHECK(length(anchor)=32),
            head_position INTEGER NOT NULL CHECK(head_position>=0),
            head_hash BLOB NOT NULL CHECK(length(head_hash)=32),
            stopped INTEGER NOT NULL CHECK(stopped IN (0,1))
        );
        CREATE TABLE account_events (
            id INTEGER PRIMARY KEY NOT NULL,
            bytes BLOB NOT NULL
        );
        CREATE TABLE account_device (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            handle BLOB NOT NULL CHECK(length(handle)=32),
            signing BLOB NOT NULL CHECK(length(signing)=32),
            control BLOB NOT NULL CHECK(length(control)=32),
            receiving BLOB NOT NULL CHECK(length(receiving)=1216),
            policy INTEGER NOT NULL CHECK(policy BETWEEN 0 AND 255),
            kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 255)
        );
        CREATE TABLE account_pending_setup (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            version INTEGER NOT NULL CHECK(version BETWEEN 0 AND 65535),
            stage INTEGER NOT NULL CHECK(stage BETWEEN 0 AND 255),
            kit_saved INTEGER NOT NULL CHECK(kit_saved IN (0,1)),
            blob BLOB NOT NULL
        );",
    )
}

fn migrate_v3_to_v4(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    // Ordinary bases only. Hidden content must never use these plaintext note
    // tables; its isolated encrypted domain requires a separate migration.
    transaction.execute_batch(
        "CREATE TABLE note_outbox (
        update_id INTEGER PRIMARY KEY REFERENCES note_updates(id),
        event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=32),
        descriptor BLOB NOT NULL,
        body BLOB NOT NULL,
        ack BLOB
    );",
    )
}

fn migrate_v4_to_v5(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute_batch(
        "CREATE TABLE account_staged_admission (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            position INTEGER NOT NULL CHECK(position > 1),
            previous BLOB NOT NULL CHECK(length(previous)=32),
            event BLOB NOT NULL CHECK(length(event)>0),
            delivery BLOB NOT NULL CHECK(length(delivery)>0)
        );",
    )
}

fn migrate_v5_to_v6(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    // Additive; v5 rows stay readable without rewriting a potentially enormous
    // note history at open. Jobs compact a captured prefix in bounded pages.
    transaction.execute_batch(
        "CREATE TABLE note_checkpoints (
            base BLOB NOT NULL CHECK(length(base)=32),
            audience BLOB NOT NULL CHECK(length(audience)=32),
            note BLOB NOT NULL CHECK(length(note)=32),
            generation INTEGER NOT NULL CHECK(generation>0),
            local_frontier INTEGER NOT NULL CHECK(local_frontier>=0),
            materialization_frontier INTEGER NOT NULL DEFAULT 0 CHECK(materialization_frontier>=0),
            encoded_yjs BLOB NOT NULL,
            PRIMARY KEY(base,audience,note)
        );
        CREATE INDEX note_updates_audience_id ON note_updates(base,audience,id);
        CREATE TABLE pending_scope (
            update_id INTEGER PRIMARY KEY REFERENCES note_updates(id),
            base BLOB NOT NULL CHECK(length(base)=32),
            audience BLOB NOT NULL CHECK(length(audience)=32),
            note BLOB NOT NULL CHECK(length(note)=32)
        );
        CREATE INDEX pending_scope_audience ON pending_scope(base,audience,update_id);
        CREATE INDEX pending_scope_note ON pending_scope(base,audience,note,update_id);
        CREATE TABLE pending_scope_backfill (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            last_id INTEGER NOT NULL DEFAULT 0 CHECK(last_id>=0),
            complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1))
        );
        INSERT INTO pending_scope_backfill(id) VALUES (1);",
    )
}

fn migrate_v6_to_v7(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    // No production read uses this index. Keep the shipped v6 schema intact;
    // old databases remove it atomically when they next open.
    transaction.execute_batch("DROP INDEX note_updates_audience_id;")
}

fn migrate_v7_to_v8(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    // Per-container, versioned local presentation only. Account verification
    // and note authority never come from these rows.
    transaction.execute_batch(
        "CREATE TABLE view_records (
        id INTEGER PRIMARY KEY,
        version INTEGER NOT NULL,
        base BLOB NOT NULL CHECK(length(base)=32),
        audience BLOB NOT NULL CHECK(length(audience)=32),
        note BLOB NOT NULL CHECK(length(note)=32),
        anchor BLOB NOT NULL, head BLOB NOT NULL,
        cursor_offset REAL NOT NULL,
        x REAL NOT NULL, y REAL NOT NULL, width REAL NOT NULL, height REAL NOT NULL
    );
    CREATE TABLE note_counter (
        id INTEGER PRIMARY KEY CHECK(id=1),
        value INTEGER NOT NULL CHECK(value>=0)
    );
    INSERT INTO note_counter(id,value) VALUES (1,0);
    CREATE TABLE notes (
        base BLOB NOT NULL CHECK(length(base)=32),
        audience BLOB NOT NULL CHECK(length(audience)=32),
        note BLOB NOT NULL CHECK(length(note)=32),
        touched INTEGER NOT NULL CHECK(touched>0),
        title TEXT NOT NULL CHECK(length(title)<=80),
        PRIMARY KEY(base,audience,note)
    );
    CREATE INDEX notes_recent ON notes(base,audience,touched DESC,note DESC);",
    )
}

fn migrate_v8_to_v9(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute_batch(
        "CREATE TABLE account_projection (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            anchor BLOB NOT NULL CHECK(length(anchor)=32),
            epoch INTEGER NOT NULL CHECK(epoch>0),
            through_position INTEGER NOT NULL CHECK(through_position>=0),
            through_hash BLOB NOT NULL CHECK(length(through_hash)=32),
            summary BLOB NOT NULL
        );
        CREATE TABLE account_devices (
            epoch INTEGER NOT NULL CHECK(epoch>0),
            device BLOB NOT NULL CHECK(length(device)=32),
            keys BLOB NOT NULL CHECK(length(keys)=1280),
            added INTEGER NOT NULL CHECK(added>0),
            removed INTEGER CHECK(removed IS NULL OR removed>added),
            PRIMARY KEY(epoch,device)
        ) WITHOUT ROWID;
        CREATE INDEX account_devices_current ON account_devices(epoch,added) WHERE removed IS NULL;
        CREATE TABLE account_key_use (
            epoch INTEGER NOT NULL CHECK(epoch>0),
            space INTEGER NOT NULL CHECK(space IN (0,1)),
            key BLOB NOT NULL CHECK(length(key)=32),
            added INTEGER NOT NULL CHECK(added>0),
            PRIMARY KEY(epoch,space,key)
        ) WITHOUT ROWID;
        CREATE TABLE account_initial_bootstrap (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            anchor BLOB NOT NULL CHECK(length(anchor)=32),
            head_position INTEGER NOT NULL CHECK(head_position=3),
            head_hash BLOB NOT NULL CHECK(length(head_hash)=32),
            recovery_record BLOB NOT NULL CHECK(length(recovery_record)=242),
            device_seal BLOB NOT NULL CHECK(length(device_seal)=1299),
            recovery_seal BLOB NOT NULL CHECK(length(recovery_seal)=1299)
        );
        CREATE TABLE own_base (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            account BLOB NOT NULL UNIQUE CHECK(length(account)=32),
            base BLOB NOT NULL CHECK(length(base)=32),
            genesis_descriptor BLOB NOT NULL,
            genesis_body BLOB NOT NULL,
            initial_key_package BLOB NOT NULL
        );",
    )
}

#[cfg(test)]
mod cache_tests;
#[cfg(test)]
mod note_cost_tests;
#[cfg(test)]
mod outbox_cost_tests;
#[cfg(test)]
mod outbox_v12_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_requires_full_sync_and_foreign_keys() {
        let database = DeviceDatabase::open(":memory:").unwrap();
        let sync: u32 = database
            .connection
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        let foreign_keys: bool = database
            .connection
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2);
        assert!(foreign_keys);
    }

    #[test]
    fn failed_version_transaction_does_not_advance_version() {
        let mut connection = Connection::open_in_memory().unwrap();
        // query_only allows taking the transaction lock, but refuses its write.
        connection.pragma_update(None, "query_only", true).unwrap();
        assert!(initialize(&mut connection).is_err());
        assert_eq!(version(&connection).unwrap(), 0);
        assert!(connection.is_autocommit());
    }

    #[test]
    fn migration_rechecks_version_under_lock() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.pragma_update(None, "user_version", 999).unwrap();
        assert!(matches!(
            initialize(&mut connection),
            Err(OpenError::NewerData { found: 999, .. })
        ));
        assert_eq!(version(&connection).unwrap(), 999);
    }
}
