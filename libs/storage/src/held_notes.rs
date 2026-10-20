//! Verified note candidates awaiting local engine judgment. These rows are
//! local continuation evidence, never replicated refusals or authority grants.
use crate::{
    DeviceDatabase, NoteKey, StoreError,
    sync_state::{CommittedNote, IncomingNote, OwnOutcome},
};
use bh_sync::Commitment;
use rusqlite::{Transaction, TransactionBehavior, params};

#[derive(Clone, Debug)]
pub struct HeldEvent {
    pub ordered: Commitment,
    pub author: Option<([u8; 32], [u8; 32])>,
    /// Account, device and nonce of the verified declaration.
    pub writer: Option<([u8; 32], [u8; 32], [u8; 32])>,
    pub delta: Option<Vec<u8>>,
    pub own_update: Option<i64>,
}

/// Complete the additive, unshipped local layout, including databases opened
/// by an earlier build of this same version. Presence is the extension marker;
/// both the held table and widened outcome domain appear atomically.
pub(crate) fn ensure_layout(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='held_note_event')",
        [],
        |r| r.get(0),
    )?;
    if exists {
        return Ok(());
    }
    tx.execute_batch(
        "CREATE TABLE held_note_event (
        base BLOB NOT NULL CHECK(length(base)=32),
        audience BLOB NOT NULL CHECK(length(audience)=32),
        note BLOB NOT NULL CHECK(length(note)=32),
        position INTEGER NOT NULL CHECK(position>0),
        commitment BLOB NOT NULL,
        author BLOB CHECK(author IS NULL OR length(author)=64),
        writer BLOB CHECK(writer IS NULL OR length(writer)=96),
        delta BLOB,
        own_update INTEGER REFERENCES note_outbox(update_id),
        PRIMARY KEY(base,audience,note,position)
    ) WITHOUT ROWID;
    CREATE TABLE note_outbox_progress_held (
        update_id INTEGER PRIMARY KEY REFERENCES note_outbox(update_id),
        staged INTEGER NOT NULL DEFAULT 0 CHECK(staged IN (0,1)),
        acked_position INTEGER CHECK(acked_position IS NULL OR acked_position>0),
        outcome INTEGER CHECK(outcome IS NULL OR outcome BETWEEN 1 AND 6),
        refusal INTEGER CHECK(refusal IS NULL OR (outcome=3 AND refusal BETWEEN 1 AND 255)),
        CHECK(outcome!=3 OR refusal IS NOT NULL)
    );
    INSERT INTO note_outbox_progress_held SELECT * FROM note_outbox_progress;
    DROP TABLE note_outbox_progress;
    ALTER TABLE note_outbox_progress_held RENAME TO note_outbox_progress;",
    )
}

pub(crate) fn insert(
    tx: &Transaction<'_>,
    key: NoteKey,
    events: &[HeldEvent],
) -> Result<(), StoreError> {
    for event in events {
        let author = event
            .author
            .map(|(a, d)| [a.as_slice(), d.as_slice()].concat());
        let writer = event
            .writer
            .map(|(a, d, n)| [a.as_slice(), d.as_slice(), n.as_slice()].concat());
        tx.execute("INSERT INTO held_note_event(base,audience,note,position,commitment,author,writer,delta,own_update) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![key.base.as_slice(), key.audience.as_slice(), key.note.as_slice(), event.ordered.head().position as i64, event.ordered.encode(), author, writer, event.delta, event.own_update])?;
    }
    if !events.is_empty() {
        // This Note cannot show this content yet: ordered decisions about it
        // wait and Note listings stay incomplete until the hold is released.
        crate::data::mark_note_gap(tx, crate::data::note_scope(key), key.note)?;
    }
    Ok(())
}

impl DeviceDatabase {
    pub fn has_held_notes(&self) -> Result<bool, StoreError> {
        Ok(self
            .connection
            .query_row("SELECT EXISTS(SELECT 1 FROM held_note_event)", [], |r| {
                r.get(0)
            })?)
    }
    pub fn note_is_held(&self, key: NoteKey) -> Result<bool, StoreError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM held_note_event WHERE base=?1 AND audience=?2 AND note=?3)", params![key.base.as_slice(), key.audience.as_slice(), key.note.as_slice()], |r| r.get(0))?)
    }
    /// Bounded cursor over notes, independent of the total held history size.
    pub fn held_notes(
        &self,
        after: Option<NoteKey>,
        limit: usize,
    ) -> Result<Vec<NoteKey>, StoreError> {
        let after = after.unwrap_or(NoteKey {
            base: [0; 32],
            audience: [0; 32],
            note: [0; 32],
        });
        let mut query = self.connection.prepare_cached("SELECT DISTINCT base,audience,note FROM held_note_event WHERE (base,audience,note)>(?1,?2,?3) ORDER BY base,audience,note LIMIT ?4")?;
        query
            .query_map(
                params![
                    after.base.as_slice(),
                    after.audience.as_slice(),
                    after.note.as_slice(),
                    limit.min(256) as i64
                ],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )?
            .map(|row| {
                let (base, audience, note) = row?;
                Ok(NoteKey {
                    base: array(&base)?,
                    audience: array(&audience)?,
                    note: array(&note)?,
                })
            })
            .collect()
    }
    /// Fetch one candidate at a time: held history is not a RAM-sized queue.
    pub fn next_held_event(
        &self,
        key: NoteKey,
        after: u64,
    ) -> Result<Option<HeldEvent>, StoreError> {
        use rusqlite::OptionalExtension;
        type Row = (
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
            i64,
        );
        let row: Option<Row> = self.connection.query_row("SELECT commitment,author,writer,delta,own_update,position FROM held_note_event WHERE base=?1 AND audience=?2 AND note=?3 AND position>?4 ORDER BY position LIMIT 1",params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice(),after as i64], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
        row.map(
            |(commitment, author, writer, delta, own_update, position)| {
                let ordered =
                    Commitment::decode(&commitment).map_err(|_| StoreError::CorruptSyncState)?;
                if ordered.base().0 != key.base || ordered.head().position != position as u64 {
                    return Err(StoreError::CorruptSyncState);
                }
                let author = author
                    .map(|a| {
                        if a.len() != 64 {
                            return Err(StoreError::CorruptSyncState);
                        }
                        Ok((array(&a[..32])?, array(&a[32..])?))
                    })
                    .transpose()?;
                let writer = writer
                    .map(|w| {
                        if w.len() != 96 {
                            return Err(StoreError::CorruptSyncState);
                        }
                        Ok((array(&w[..32])?, array(&w[32..64])?, array(&w[64..])?))
                    })
                    .transpose()?;
                Ok(HeldEvent {
                    ordered,
                    author,
                    writer,
                    delta,
                    own_update,
                })
            },
        )
        .transpose()
    }
    /// Release a judged prefix without changing any log continuation. The
    /// caller holds the note work lock through publication of the result.
    pub fn release_held(
        &mut self,
        note: &IncomingNote,
        through: u64,
        own: &[OwnOutcome],
    ) -> Result<CommittedNote, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Preparation runs without the database lock. A sticky stop may have
        // landed since then; fence it in the same transaction as every write.
        // Unrelated notes may advance this log, so no old-head equality check.
        let progress =
            super::sync_state::read_progress(&tx, super::sync_state::LOG_BASE, note.key.base)?
                .ok_or(StoreError::MissingProgress)?;
        if progress.stopped.is_some() {
            return Err(StoreError::LogStopped);
        }
        for outcome in own {
            super::sync_state::record_own(&tx, note.key.base, outcome)?;
        }
        let created = crate::data::note_projection_missing(&tx, note.key)?;
        let committed = super::sync_state::commit_note(&tx, note)?;
        tx.execute("DELETE FROM held_note_event WHERE base=?1 AND audience=?2 AND note=?3 AND position<=?4",params![note.key.base.as_slice(),note.key.audience.as_slice(),note.key.note.as_slice(),through as i64])?;
        // The commit above projected the Note while these rows still existed,
        // so the record's gap is re-asserted now that they are gone. A created
        // projection or a closed gap is the dependency parked work waits for:
        // replay just that record's queue rather than the whole scope's.
        let scope = crate::data::note_scope(note.key);
        let closed = crate::data::refresh_note_gap(&tx, scope, note.key.note)?;
        if created || closed {
            crate::data::replay_parked_for(&tx, scope, note.key.note)?;
        }
        tx.commit()?;
        self.forget_note(note.key);
        Ok(committed)
    }
}
fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::CorruptSyncState)
}
