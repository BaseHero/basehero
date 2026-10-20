//! Explicit, immutable membership of local commits in sealed packages.
//! Pre-membership packages are singletons, never inferred ranges. Pending
//! enumeration starts from pending IDs, not years of accepted note history.
use crate::{NoteKey, StoreError};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(crate) const RUN_BYTES: i64 = 256 * 1024;
type Writer = Option<(Vec<u8>, Vec<u8>, i64)>;
pub(crate) struct RunUpdate {
    pub id: i64,
    pub delta: Vec<u8>,
    writer: Writer,
}

/// No historical backfill: an existing outbox primary key retains exactly
/// its v11 singleton meaning. All new packages record every member.
pub(crate) fn migrate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE note_outbox_members (
            update_id INTEGER PRIMARY KEY REFERENCES note_updates(id),
            package_update_id INTEGER NOT NULL REFERENCES note_outbox(update_id)
        );
        CREATE INDEX note_outbox_members_package ON note_outbox_members(package_update_id,update_id);",
    )
}

pub(crate) fn update_key(conn: &Connection, update_id: i64) -> Result<NoteKey, StoreError> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT base,audience,note FROM note_updates WHERE id=?1",
            [update_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (base, audience, note) = row.ok_or(StoreError::MissingPending)?;
    let array = |b: Vec<u8>| b.try_into().map_err(|_| StoreError::CorruptOutbox);
    Ok(NoteKey {
        base: array(base)?,
        audience: array(audience)?,
        note: array(note)?,
    })
}
pub(crate) fn pending_key(conn: &Connection, update_id: i64) -> Result<NoteKey, StoreError> {
    let pending: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pending_note_work WHERE update_id=?1)",
        [update_id],
        |r| r.get(0),
    )?;
    if !pending {
        return Err(StoreError::MissingPending);
    }
    update_key(conn, update_id)
}

/// Two primary-key lookups, independent of the note's size and history.
pub(crate) fn covering(conn: &Connection, update_id: i64) -> Result<Option<i64>, StoreError> {
    Ok(conn.query_row(
        "SELECT COALESCE(
            (SELECT package_update_id FROM note_outbox_members WHERE update_id=?1),
            (SELECT update_id FROM note_outbox WHERE update_id=?1))",
        [update_id],
        |r| r.get(0),
    )?)
}

/// Capture only the first uncovered pending run through `through`. Existing
/// packages/progress before it are skipped; a boundary after it ends the run.
/// CROSS JOIN fixes the driving relation to pending IDs, so accepted history
/// cannot turn a small new run into a history scan. The first oversized update
/// travels alone; even empty deltas consume one unit of the capture budget.
pub(crate) fn updates(
    conn: &Connection,
    key: NoteKey,
    first: i64,
    through: i64,
) -> Result<Vec<RunUpdate>, StoreError> {
    let mut stmt=conn.prepare_cached(
        "SELECT w.update_id,u.delta,s.account,s.device,s.slot,
                m.update_id IS NOT NULL OR o.update_id IS NOT NULL OR p.update_id IS NOT NULL
         FROM pending_note_work w CROSS JOIN note_updates u ON u.id=w.update_id
         LEFT JOIN note_outbox_members m ON m.update_id=w.update_id
         LEFT JOIN note_outbox o ON o.update_id=w.update_id
         LEFT JOIN note_outbox_progress p ON p.update_id=COALESCE(m.package_update_id,o.update_id,w.update_id)
         LEFT JOIN note_update_writer s ON s.update_id=w.update_id
         WHERE w.update_id>=?4 AND w.update_id<=?5 AND u.base=?1 AND u.audience=?2 AND u.note=?3
         ORDER BY w.update_id",
    )?;
    let mut rows = stmt.query(params![key.base, key.audience, key.note, first, through])?;
    let mut run: Vec<RunUpdate> = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        if row.get::<_, bool>(5)? {
            if run.is_empty() {
                continue;
            }
            break;
        }
        let account: Option<Vec<u8>> = row.get(2)?;
        let writer = match account {
            Some(a) => Some((a, row.get(3)?, row.get(4)?)),
            None => None,
        };
        let size = row
            .get_ref(1)?
            .as_blob()
            .map_err(|_| StoreError::CorruptOutbox)?
            .len()
            .max(1);
        if let Some(start) = run.first()
            && (writer != start.writer || bytes.saturating_add(size) > RUN_BYTES as usize)
        {
            break;
        }
        bytes = bytes.saturating_add(size);
        let unlinked = writer.is_none();
        run.push(RunUpdate {
            id: row.get(0)?,
            delta: row.get(1)?,
            writer,
        });
        if unlinked || bytes >= RUN_BYTES as usize {
            break;
        }
    }
    Ok(run)
}

pub(crate) fn run_end(conn: &Connection, key: NoteKey, first: i64) -> Result<i64, StoreError> {
    updates(conn, key, first, i64::MAX)?
        .last()
        .map(|u| u.id)
        .ok_or(StoreError::MissingPending)
}

/// Pending membership only. Mappings are retained after acceptance for
/// historical per-update outcome queries. The singleton fallback is indexed
/// by the package's own primary key, never a predecessor/successor search.
pub(crate) fn covered(conn: &Connection, package: i64) -> Result<Vec<i64>, StoreError> {
    let mut stmt=conn.prepare_cached(
        "SELECT m.update_id FROM note_outbox_members m
         JOIN pending_note_work w ON w.update_id=m.update_id WHERE m.package_update_id=?1
         UNION ALL
         SELECT o.update_id FROM note_outbox o JOIN pending_note_work w ON w.update_id=o.update_id
         WHERE o.update_id=?1 AND NOT EXISTS(SELECT 1 FROM note_outbox_members WHERE package_update_id=?1)
         ORDER BY 1",
    )?;
    Ok(stmt
        .query_map([package], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?)
}
