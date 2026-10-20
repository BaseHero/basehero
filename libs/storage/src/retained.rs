//! Verified content this build keeps without applying.
//!
//! Two ordered events reach a replica whose executable cannot apply them: a
//! content kind it does not know, and a note event whose writer declaration
//! it cannot read (a newer Note contract). Neither may stop unrelated work,
//! and neither may be dropped: the exact payload is kept with its verified
//! scope, author and log position. A note event also waits only for its own
//! Note: later events for that Note are retained behind it in position order,
//! so the Note never moves past an event this build cannot read, and the Note
//! is marked unavailable while any of its content sits here.
//!
//! An unknown outer content kind is kept only for a newer build to replay. It
//! carries nothing this build models (a future typed-data change uses a new
//! inner payload version inside its own outer kind), so it never makes a Note
//! or a typed listing incomplete; while any row remains, the status line says a
//! newer build is needed.
//!
//! These rows are local continuation evidence, never replicated verdicts.
//! An executable that can read a payload replays the scope's rows oldest
//! first, applies each at its position, deletes it, and clears the record's
//! gap once its last row is gone.
use bh_data::Position;
use rusqlite::{Connection, Transaction, params};

use crate::{DeviceDatabase, NoteKey, StoreError, sync_state::LOG_BASE};

/// One retained verified event: the content payload exactly as its author
/// sealed it, where and by whom it was ordered, and what it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedContent {
    pub log_kind: u8,
    pub log_id: [u8; 32],
    pub audience: [u8; 32],
    pub position: Position,
    /// The outer content kind (the note kind, a kind this build does not
    /// know, or the typed-data kind).
    pub kind: u16,
    /// The Note the event belongs to; `None` for content that names no Note.
    pub note: Option<[u8; 32]>,
    /// The authenticated author: account and device.
    pub author: Option<([u8; 32], [u8; 32])>,
    pub payload: Vec<u8>,
}

pub(crate) fn create_table(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE data_retained (
            log_kind INTEGER NOT NULL CHECK(log_kind IN (1,2)),
            log_id BLOB NOT NULL CHECK(length(log_id)=32),
            position INTEGER NOT NULL CHECK(position>0),
            audience BLOB NOT NULL CHECK(length(audience)=32),
            kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 65535),
            note BLOB CHECK(note IS NULL OR length(note)=32),
            author BLOB CHECK(author IS NULL OR length(author)=64),
            payload BLOB NOT NULL,
            PRIMARY KEY(log_kind,log_id,position)
        ) WITHOUT ROWID;
        CREATE INDEX data_retained_scope ON data_retained(log_id,audience,position);
        CREATE INDEX data_retained_note ON data_retained(log_id,audience,note,position)
            WHERE note IS NOT NULL;",
    )
}

pub(crate) fn insert(tx: &Transaction<'_>, row: &RetainedContent) -> Result<(), StoreError> {
    let note = row.note.as_ref().map(|n| n.as_slice());
    let author = row
        .author
        .map(|(account, device)| [account.as_slice(), device.as_slice()].concat());
    tx.execute(
        "INSERT INTO data_retained(log_kind,log_id,position,audience,kind,note,author,payload)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            row.log_kind,
            row.log_id.as_slice(),
            i64::try_from(row.position.0).map_err(|_| StoreError::CorruptSyncState)?,
            row.audience.as_slice(),
            row.kind,
            note,
            author,
            row.payload
        ],
    )?;
    // The Note cannot show content this build cannot read: ordered decisions
    // about it wait and Note listings stay incomplete until a replay clears it.
    if let Some(note) = row.note {
        crate::data::mark_note_gap(
            tx,
            crate::data::note_scope(NoteKey {
                base: row.log_id,
                audience: row.audience,
                note,
            }),
            note,
        )?;
    }
    Ok(())
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::CorruptSyncState)
}

/// Whether `key`'s Note has any content retained here: one probe through the
/// partial index for Note content.
pub(crate) fn note_has_any(conn: &Connection, key: NoteKey) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_retained INDEXED BY data_retained_note
         WHERE log_id=?1 AND audience=?2 AND note=?3)",
        params![
            key.base.as_slice(),
            key.audience.as_slice(),
            key.note.as_slice()
        ],
        |r| r.get(0),
    )?)
}

impl DeviceDatabase {
    /// Whether this base log holds content only a newer build can apply: an
    /// unknown outer content kind, or an unreadable Note declaration (and its
    /// followers). One probe over the primary key's prefix. Nothing here clears
    /// these rows; a newer build's replay deletes them.
    pub fn needs_newer_build(&self, base: [u8; 32]) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM data_retained WHERE log_kind=?1 AND log_id=?2)
             OR EXISTS(SELECT 1 FROM data_scope s JOIN data_parked p INDEXED BY data_parked_unsupported
                 ON p.scope=s.id WHERE s.base=?2 AND p.reason='\"Unsupported\"')",
            params![LOG_BASE, base.as_slice()],
            |r| r.get(0),
        )?)
    }

    /// Whether this Note is waiting behind content this build cannot read.
    pub fn note_has_retained(&self, key: NoteKey) -> Result<bool, StoreError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM data_retained INDEXED BY data_retained_note
             WHERE log_id=?1 AND audience=?2 AND note=?3)",
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice()
            ],
            |r| r.get(0),
        )?)
    }

    /// One base log's retained content in position order, at most `limit`
    /// rows after `after`. A newer build replays these oldest first at their
    /// positions, deletes each row, and clears the record's gap once the last
    /// row for it is gone.
    pub fn retained_content(
        &self,
        base: [u8; 32],
        audience: [u8; 32],
        after: Option<Position>,
        limit: usize,
    ) -> Result<Vec<RetainedContent>, StoreError> {
        let after = after.map_or(0, |p| p.0);
        type Row = (i64, Vec<u8>, u16, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>);
        let mut query = self.connection.prepare_cached(
            "SELECT position,audience,kind,note,author,payload FROM data_retained
             WHERE log_kind=?1 AND log_id=?2 AND audience=?3 AND position>?4
             ORDER BY position LIMIT ?5",
        )?;
        let rows: Vec<Row> = query
            .query_map(
                params![
                    LOG_BASE,
                    base.as_slice(),
                    audience.as_slice(),
                    i64::try_from(after).map_err(|_| StoreError::CorruptSyncState)?,
                    limit.min(256) as i64
                ],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<_>>()?;
        rows.into_iter()
            .map(|(position, audience, kind, note, author, payload)| {
                let audience: [u8; 32] = array(&audience)?;
                let note = note.map(|n| array(&n)).transpose()?;
                let author = author
                    .map(|a| {
                        if a.len() != 64 {
                            return Err(StoreError::CorruptSyncState);
                        }
                        Ok((array(&a[..32])?, array(&a[32..])?))
                    })
                    .transpose()?;
                Ok(RetainedContent {
                    log_kind: LOG_BASE,
                    log_id: base,
                    audience,
                    position: Position(
                        u64::try_from(position).map_err(|_| StoreError::CorruptSyncState)?,
                    ),
                    kind,
                    note,
                    author,
                    payload,
                })
            })
            .collect()
    }
}
