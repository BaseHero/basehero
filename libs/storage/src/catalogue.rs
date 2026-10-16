//! Local ordinary-note menu projection. Rows are untrusted indexing data, not
//! base membership, note authority, or an authenticated incoming event.
use crate::{DeviceDatabase, NoteKey, StoreError};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

pub const MAX_NOTE_PAGE: usize = 50;
pub const MAX_NOTE_TITLE: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteEntry {
    pub note: [u8; 32],
    pub title: String,
    pub touched: i64,
}

pub(crate) fn list(
    conn: &Connection,
    base: [u8; 32],
    audience: [u8; 32],
    after: Option<(i64, [u8; 32])>,
    limit: usize,
) -> Result<Vec<NoteEntry>, StoreError> {
    if limit > MAX_NOTE_PAGE {
        return Err(StoreError::InvalidNotePage);
    }
    let sql = if after.is_some() {
        "SELECT note,title,touched FROM notes WHERE base=?1 AND audience=?2 AND (touched,note)<(?3,?4) ORDER BY touched DESC,note DESC LIMIT ?5"
    } else {
        "SELECT note,title,touched FROM notes WHERE base=?1 AND audience=?2 ORDER BY touched DESC,note DESC LIMIT ?5"
    };
    let mut stmt = conn.prepare_cached(sql)?;
    let mut rows = stmt.query(params![
        base.as_slice(),
        audience.as_slice(),
        after.map(|(t, _)| t),
        after.map(|(_, n)| n.to_vec()),
        limit as i64
    ])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let note: Vec<u8> = row.get(0)?;
        let note: [u8; 32] = note.try_into().map_err(|_| StoreError::InvalidNotePage)?;
        result.push(NoteEntry {
            note,
            title: row.get(1)?,
            touched: row.get(2)?,
        });
    }
    Ok(result)
}

pub(crate) fn touch(
    tx: &Transaction<'_>,
    key: NoteKey,
    title: Option<&str>,
) -> Result<(), StoreError> {
    if title.is_some_and(|title| title.chars().count() > MAX_NOTE_TITLE) {
        return Err(StoreError::InvalidNoteTitle);
    }
    tx.execute(
        "UPDATE note_counter SET value=value+1 WHERE id=1 AND value<9223372036854775807",
        [],
    )?;
    if tx.changes() != 1 {
        return Err(StoreError::NoteCounterExhausted);
    }
    if title.is_none() {
        // A v7 note or a direct local writer may not have a catalogue row yet.
        // Index only this touched note; never scan or replay history on open.
        tx.execute("INSERT OR IGNORE INTO notes(base,audience,note,touched,title) VALUES (?1,?2,?3,(SELECT value FROM note_counter WHERE id=1),'')",
            params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()])?;
    }
    let changed = if let Some(title) = title {
        tx.execute("UPDATE notes SET title=?4,touched=(SELECT value FROM note_counter WHERE id=1) WHERE base=?1 AND audience=?2 AND note=?3",
            params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice(),title])?
    } else {
        tx.execute("UPDATE notes SET touched=(SELECT value FROM note_counter WHERE id=1) WHERE base=?1 AND audience=?2 AND note=?3",
            params![key.base.as_slice(),key.audience.as_slice(),key.note.as_slice()])?
    };
    if changed != 1 {
        return Err(StoreError::MissingNote);
    }
    Ok(())
}

impl DeviceDatabase {
    /// Call only with independently established owned-container authority.
    /// The scope arguments and the returned row do not confer authority.
    pub fn create_note(
        &mut self,
        base: [u8; 32],
        audience: [u8; 32],
    ) -> Result<[u8; 32], StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let note = insert_empty(&tx, base, audience)?;
        tx.commit()?;
        Ok(note)
    }
    /// One first row even when two callers race through separate connections.
    pub fn home_note(
        &mut self,
        base: [u8; 32],
        audience: [u8; 32],
    ) -> Result<[u8; 32], StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx.query_row("SELECT note FROM notes WHERE base=?1 AND audience=?2 ORDER BY touched DESC,note DESC LIMIT 1", params![base.as_slice(),audience.as_slice()], |r|r.get(0)).optional()?;
        let note = match existing {
            Some(note) => note.try_into().map_err(|_| StoreError::MissingNote)?,
            None => insert_empty(&tx, base, audience)?,
        };
        tx.commit()?;
        Ok(note)
    }
    pub fn note_exists(&self, key: NoteKey) -> Result<bool, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM notes WHERE base=?1 AND audience=?2 AND note=?3",
                params![
                    key.base.as_slice(),
                    key.audience.as_slice(),
                    key.note.as_slice()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
    /// Live keyset pages: a concurrent touch above the cursor may be missed
    /// until refresh; this is not a snapshot-stable pagination contract.
    pub fn list_notes(
        &self,
        base: [u8; 32],
        audience: [u8; 32],
        after: Option<(i64, [u8; 32])>,
        limit: usize,
    ) -> Result<Vec<NoteEntry>, StoreError> {
        match &self.readers {
            Some(pool) => pool.list_notes(base, audience, after, limit),
            None => list(&self.connection, base, audience, after, limit),
        }
    }
}

fn insert_empty(
    tx: &Transaction<'_>,
    base: [u8; 32],
    audience: [u8; 32],
) -> Result<[u8; 32], StoreError> {
    tx.execute(
        "UPDATE note_counter SET value=value+1 WHERE id=1 AND value<9223372036854775807",
        [],
    )?;
    if tx.changes() != 1 {
        return Err(StoreError::NoteCounterExhausted);
    }
    let note = bh_crypto::random::<32>();
    tx.execute("INSERT INTO notes(base,audience,note,touched,title) VALUES (?1,?2,?3,(SELECT value FROM note_counter WHERE id=1),'')", params![base.as_slice(),audience.as_slice(),note.as_slice()])?;
    Ok(note)
}
