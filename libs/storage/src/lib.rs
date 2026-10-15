//! Device-local SQLite ownership and open-time compatibility checks.
//!
//! This adapter stores the device's local note deltas, pending-work references,
//! each sealed pending outbound package and its exact ordered acknowledgement,
//! and the typed opaque account journal (anchor, signed events, head, sticky
//! stop, device identity, pending setup). The native app holds a database when
//! a session installs one; no production session supplies a note binding yet.
//! Pending local work is not an authenticated network event. Authority and
//! rebuildable indexes stay apart.

pub mod account;
mod local_reads;
mod read_pool;
pub use local_reads::{CheckpointJob, NoteSeed, PendingPage};
pub use read_pool::{LoadedNote, ReadPool, ReadResult};

use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use bh_core::{LOCAL_DATA_VERSION, check_local_data_version, note::Note};
use bh_sync::{BodyObject, Commitment, EventId, OpaqueEvent, referenced_body};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpenError {
    #[error("local data version {found} requires a newer client (supports {supported})")]
    NewerData { found: u32, supported: u32 },
    #[error("local database could not be opened")]
    Database(#[from] rusqlite::Error),
}

/// One owner for a device-local database. The connection is deliberately private:
/// the UI receives domain operations, never arbitrary SQL or filesystem access.
pub struct DeviceDatabase {
    connection: Connection,
    readers: Option<Arc<ReadPool>>,
    notes: HashMap<NoteKey, CachedNote>,
    cache_bytes: usize,
    cache_budget: usize,
    tick: u64,
    data_version: u32,
}
// Resident Yrs Notes measured roughly 2.7–3.7x encoded bytes, plus
// ~2.7 KiB per tiny Note. This is an approximate per-container budget,
// not an exact heap cap; borrowed entries carry *unscaled* encoded weight.
const NOTE_CACHE_OVERHEAD: usize = 4 * 1024;
const NOTE_CACHE_ENCODED_MULTIPLIER: usize = 3;
fn cache_weight(encoded: usize) -> usize {
    encoded
        .max(1)
        .saturating_mul(NOTE_CACHE_ENCODED_MULTIPLIER)
        .saturating_add(NOTE_CACHE_OVERHEAD)
}
struct CachedNote {
    note: Note,
    frontier: i64,
    // Encoded-equivalent bytes plus fixed heap overhead, not an exact heap size.
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
    #[error("local SQLite transaction failed")]
    Database(#[from] rusqlite::Error),
    #[error("invalid note update")]
    InvalidUpdate,
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
}
/// Seal `pending` with native authority only after releasing the owner/DB
/// guards, then CAS-persist these exact bytes with publish_note_package.
pub struct PackageCandidate {
    pub event_id: EventId,
    pub pending: PendingNoteUpdate,
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
    /// Check compatibility before changing journal mode. Recheck while holding
    /// the migration write lock so concurrent openers cannot downgrade a version.
    /// Small schema changes and their version marker commit in one transaction.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let path = path.as_ref();
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        ensure_supported(version(&connection)?)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", true)?;

        initialize(&mut connection)?;
        Ok(Self {
            connection,
            readers: (path != Path::new(":memory:")).then(|| ReadPool::new(path.to_path_buf())),
            notes: HashMap::new(),
            cache_bytes: 0,
            cache_budget: 32 * 1024 * 1024,
            tick: 0,
            data_version: LOCAL_DATA_VERSION,
        })
    }

    pub fn data_version(&self) -> u32 {
        self.data_version
    }
    pub fn read_pool(&self) -> Option<Arc<ReadPool>> {
        self.readers.clone()
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
        (entry.frontier == frontier).then(|| {
            (
                entry.note,
                entry.weight.saturating_sub(NOTE_CACHE_OVERHEAD) / NOTE_CACHE_ENCODED_MULTIPLIER,
            )
        })
    }
    /// Only a successfully committed or unchanged Note may re-enter this cache.
    pub fn return_committed_note(
        &mut self,
        key: NoteKey,
        note: Note,
        frontier: i64,
        encoded_weight: usize,
    ) {
        self.forget_note(key);
        self.tick = self.tick.checked_add(1).expect("LRU counter exhausted");
        let weight = cache_weight(encoded_weight);
        self.cache_bytes = self.cache_bytes.saturating_add(weight);
        self.notes.insert(
            key,
            CachedNote {
                note,
                frontier,
                weight,
                last: self.tick,
            },
        );
        self.evict_clean();
    }

    fn load_note(&mut self, key: NoteKey) -> Result<&mut Note, StoreError> {
        if !self.notes.contains_key(&key) {
            let checkpoint:Option<(i64,Vec<u8>)>=self.connection.query_row(
                "SELECT local_frontier,encoded_yjs FROM note_checkpoints WHERE base=?1 AND audience=?2 AND note=?3",
                params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()],
                |r|Ok((r.get(0)?,r.get(1)?)),
            ).optional()?;
            let (covered, encoded) = checkpoint.unwrap_or((0, Vec::new()));
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
            let mut note = Note::new();
            if !encoded.is_empty() {
                note.apply_update(&encoded)
                    .map_err(|_| StoreError::InvalidUpdate)?;
            }
            for row in rows {
                note.apply_update(&row?)
                    .map_err(|_| StoreError::InvalidUpdate)?;
            }
            let weight = cache_weight(note.state().len());
            let frontier = self.local_frontier(key)?;
            self.cache_bytes = self.cache_bytes.saturating_add(weight);
            self.notes.insert(
                key,
                CachedNote {
                    note,
                    frontier,
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

    pub fn note_state(&mut self, key: NoteKey) -> Result<Vec<u8>, StoreError> {
        let state = self.load_note(key)?.state();
        self.evict_clean();
        Ok(state)
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
            self.evict_clean();
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
        self.load_note(key)?
            .apply_update(bytes)
            .map_err(|_| StoreError::InvalidUpdate)?;
        if let Some(entry) = self.notes.get_mut(&key) {
            let growth = bytes.len().saturating_mul(NOTE_CACHE_ENCODED_MULTIPLIER);
            entry.weight = entry.weight.saturating_add(growth);
            self.cache_bytes = self.cache_bytes.saturating_add(growth);
        }
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
        tx.commit()?;
        Ok(LocalCommit {
            update_id: id,
            replayed: false,
        })
    }

    /// Phase 1: release the database guard after this call. The native issuer
    /// seals immutable bytes outside all DB/owner guards; the prepared id is
    /// never submitted until phase 2 succeeds.
    pub fn prepare_note_package(&self, update_id: i64) -> Result<PackagePreparation, StoreError> {
        if let Some(existing) = read_package(&self.connection, update_id)? {
            return Ok(PackagePreparation::Existing(existing));
        }
        let row=self.connection.query_row(
            "SELECT u.base,u.audience,u.note,u.delta FROM note_updates u JOIN pending_note_work p ON p.update_id=u.id WHERE u.id=?1",
            [update_id],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?)),
        ).optional()?.ok_or(StoreError::MissingPending)?;
        Ok(PackagePreparation::Candidate(PackageCandidate {
            event_id: EventId(bh_crypto::random::<32>()),
            pending: PendingNoteUpdate {
                update_id,
                key: NoteKey {
                    base: row.0.try_into().map_err(|_| StoreError::CorruptOutbox)?,
                    audience: row.1.try_into().map_err(|_| StoreError::CorruptOutbox)?,
                    note: row.2.try_into().map_err(|_| StoreError::CorruptOutbox)?,
                },
                bytes: row.3,
            },
        }))
    }
    /// Phase 2: the short IMMEDIATE CAS rejects a retired or changed pending
    /// row, and an uncertain duplicate returns the already-persisted attempt.
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
        if let Some(existing) = read_package(&tx, candidate.pending.update_id)? {
            return Ok(existing);
        }
        let row=tx.query_row(
            "SELECT u.base,u.audience,u.note,u.delta FROM note_updates u JOIN pending_note_work p ON p.update_id=u.id WHERE u.id=?1",
            [candidate.pending.update_id],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?)),
        ).optional()?;
        let Some((base, audience, note, delta)) = row else {
            return Err(StoreError::MissingPending);
        };
        if base != candidate.pending.key.base
            || audience != candidate.pending.key.audience
            || note != candidate.pending.key.note
            || delta != candidate.pending.bytes
        {
            return Err(StoreError::RequestConflict);
        }
        tx.execute(
            "INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES (?1,?2,?3,?4)",
            params![
                candidate.pending.update_id,
                id.0.as_slice(),
                descriptor.encode(),
                body.bytes()
            ],
        )?;
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

    /// Match the complete ordered record to the immutable descriptor before
    /// retiring the pending row. A duplicate Ack must match byte-for-byte.
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
        // The caller verifies the ordered chain and authenticates the receipt;
        // this store checks only exact byte identity against its sealed package.
        tx.execute(
            "UPDATE note_outbox SET ack=?2 WHERE update_id=?1",
            params![update_id, ack.encode()],
        )?;
        tx.execute("DELETE FROM pending_scope WHERE update_id=?1", [update_id])?;
        if tx.execute(
            "DELETE FROM pending_note_work WHERE update_id=?1",
            [update_id],
        )? != 1
        {
            return Err(StoreError::CorruptOutbox);
        }
        tx.commit()?;
        Ok(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_weights_stay_at_three_times_encoded_plus_overhead() {
        let mut db = DeviceDatabase::open(":memory:").unwrap();
        let key = NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [3; 32],
        };
        db.return_committed_note(key, Note::new(), 0, 1024);
        assert_eq!(db.cache_bytes, 3 * 1024 + NOTE_CACHE_OVERHEAD);
        for n in 1..100 {
            let (note, encoded) = db.take_cached_note(key, n - 1).unwrap();
            assert_eq!(encoded, 1024 + (n - 1) as usize);
            assert_eq!(db.cache_bytes, 0);
            db.return_committed_note(key, note, n, encoded + 1);
            assert_eq!(
                db.cache_bytes,
                (1024 + n as usize) * 3 + NOTE_CACHE_OVERHEAD
            );
        }
    }

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
