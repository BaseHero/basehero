//! Building an Undo from this replica's history. Applying it needs only field
//! clocks, so a replica without that history reaches the same verdict.
use rusqlite::{Connection, params};
use serde_json::Value;

use super::ops::{FieldChange, Operation};
use crate::{
    DataError, FieldPath, MutationId, RecordId, Scope,
    store::{corrupt, id, records, sql},
};

/// An Undo restoring each field `target` changed to its earlier value. Undo of
/// a creation (or a restore) is a conditional `UndoRemove`; Undo of a deletion restores the
/// deleted values and the record. A mutation id reused at later positions is
/// applied on its merits, so only its first application here is undone.
pub fn prepare(
    conn: &Connection,
    scope: Scope,
    target: MutationId,
) -> Result<Operation, DataError> {
    let sid = records::lookup_scope(conn, scope)?.ok_or(DataError::NotFound)?;
    let mut stmt = conn
        .prepare_cached(
            "WITH first AS (SELECT h.rec,h.position FROM data_history h JOIN data_record r ON r.id=h.rec
               WHERE h.mutation=?1 AND r.scope=?2 ORDER BY h.position LIMIT 1)
             SELECT r.record,h.path,h.old,h.new,h.position FROM first f
             JOIN data_history h ON h.rec=f.rec AND h.position=f.position
             JOIN data_record r ON r.id=h.rec
             WHERE h.mutation=?1 ORDER BY h.path",
        )
        .map_err(sql)?;
    let rows = stmt
        .query_map(params![target.0.as_slice(), sid], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .map_err(sql)?;
    let mut record = None;
    let mut changes = Vec::new();
    for row in rows {
        let (rec, path, old, new, position) = row.map_err(sql)?;
        record = Some(RecordId(id(rec)?));
        if path.is_empty() {
            if new.as_deref() == Some("true") {
                return Ok(Operation::UndoRemove {
                    target,
                    position: crate::Position(crate::store::unsigned(position)?),
                    record: record.expect("set above"),
                });
            }
            continue;
        }
        let old: Option<Value> = old
            .map(|text| serde_json::from_str(&text).map_err(corrupt))
            .transpose()?;
        changes.push(FieldChange {
            path: FieldPath::parse(&path)?,
            value: old,
        });
    }
    let record = record.ok_or(DataError::NotFound)?;
    Ok(Operation::Undo {
        target,
        record,
        changes,
    })
}
