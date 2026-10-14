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
pub mod coordinator;

use std::{collections::HashMap, path::Path, time::Duration};

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
    notes: HashMap<NoteKey, Note>,
    data_version: u32,
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
    #[error("local request id reused with different content")]
    RequestConflict,
    #[error("stored account state is inconsistent")]
    CorruptAccount,
    #[error("account head has no matching stored signed bytes")]
    HeadWithoutBytes,
    #[error("pending update not found")]
    MissingPending,
    #[error("invalid sealed package")]
    InvalidPackage,
    #[error("ordered acknowledgement conflicts with stored package or acknowledgement")]
    AckConflict,
    #[error("stored outbox package is inconsistent")]
    CorruptOutbox,
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
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        ensure_supported(version(&connection)?)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", true)?;

        initialize(&mut connection)?;
        Ok(Self {
            connection,
            notes: HashMap::new(),
            data_version: LOCAL_DATA_VERSION,
        })
    }

    pub fn data_version(&self) -> u32 {
        self.data_version
    }

    fn load_note(&mut self, key: NoteKey) -> Result<&mut Note, StoreError> {
        if !self.notes.contains_key(&key) {
            let mut stmt = self.connection.prepare_cached(
                "SELECT delta FROM note_updates WHERE base=?1 AND audience=?2 AND note=?3 ORDER BY id",
            )?;
            let rows = stmt.query_map(
                params![
                    key.base.as_slice(),
                    key.audience.as_slice(),
                    key.note.as_slice()
                ],
                |r| r.get::<_, Vec<u8>>(0),
            )?;
            let mut note = Note::new();
            for row in rows {
                note.apply_update(&row?)
                    .map_err(|_| StoreError::InvalidUpdate)?;
            }
            self.notes.insert(key, note);
        }
        Ok(self.notes.get_mut(&key).expect("loaded note"))
    }

    pub fn note_state(&mut self, key: NoteKey) -> Result<Vec<u8>, StoreError> {
        Ok(self.load_note(key)?.state())
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
            self.notes.remove(&key);
        }
        result
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
        tx.commit()?;
        Ok(LocalCommit {
            update_id: id,
            replayed: false,
        })
    }

    /// Reserve a fresh wire identity and seal *once*, while holding the write
    /// lock. The caller supplies real authority/keys to the encoder; it receives
    /// this exact pending row, not an inferred account session. Failed commits
    /// publish no package. Reopening never re-invokes the encoder for this row.
    pub fn package_note_update(
        &mut self,
        update_id: i64,
        seal: impl FnOnce(EventId, &PendingNoteUpdate) -> Result<(OpaqueEvent, BodyObject), StoreError>,
    ) -> Result<StoredNotePackage, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = tx.query_row(
            "SELECT u.base,u.audience,u.note,u.delta FROM note_updates u JOIN pending_note_work p ON p.update_id=u.id WHERE u.id=?1",
            [update_id], |r| Ok((r.get::<_, Vec<u8>>(0)?,r.get::<_, Vec<u8>>(1)?,r.get::<_, Vec<u8>>(2)?,r.get::<_, Vec<u8>>(3)?)),
        ).optional()?;
        let existing = read_package(&tx, update_id)?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let (base, audience, note, bytes) = row.ok_or(StoreError::MissingPending)?;
        let key = NoteKey {
            base: base.try_into().map_err(|_| StoreError::CorruptOutbox)?,
            audience: audience.try_into().map_err(|_| StoreError::CorruptOutbox)?,
            note: note.try_into().map_err(|_| StoreError::CorruptOutbox)?,
        };
        let pending = PendingNoteUpdate {
            update_id,
            key,
            bytes,
        };
        let id = EventId(bh_crypto::random::<32>());
        let (descriptor, body) = seal(id, &pending)?;
        if id.0 == [0; 32]
            || descriptor.id() != id
            || referenced_body(&descriptor).map_err(|_| StoreError::InvalidPackage)?
                != body.commitment()
        {
            return Err(StoreError::InvalidPackage);
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
        tx.commit()?;
        Ok(StoredNotePackage {
            event_id: id,
            descriptor,
            body: body.bytes().to_vec(),
            ack: None,
        })
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

    pub fn pending_note_updates(&self) -> Result<Vec<PendingNoteUpdate>, StoreError> {
        let mut stmt = self.connection.prepare("SELECT u.id,u.base,u.audience,u.note,u.delta FROM note_updates u JOIN pending_note_work p ON p.update_id=u.id ORDER BY u.id")?;
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
        rows.collect::<rusqlite::Result<_>>()
            .map_err(StoreError::from)
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
