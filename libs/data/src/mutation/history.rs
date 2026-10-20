//! Field clocks (current attribution, replicated state) and field history
//! (retained old/new values on this replica).
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::eval::RecordPlan;
use crate::{
    Actor, DataError, FieldPath, MutationId, Position, RecordId, Scope,
    store::{actor as actor_store, corrupt, id, integer, records, sql, unsigned},
};

#[derive(Clone, Debug, PartialEq)]
pub struct HistoryEntry {
    pub position: Position,
    pub mutation: MutationId,
    pub actor: Actor,
    /// `None` is the record's existence: `old`/`new` are `true` when it
    /// existed, `false` when deleted, and `old` is absent on creation.
    pub path: Option<FieldPath>,
    pub old: Option<Value>,
    pub new: Option<Value>,
}

/// Keyset for history's `(position DESC, path ASC)` order. `None` is the
/// existence row, stored as the empty path and ordered before named fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryCursor {
    pub position: Position,
    pub path: Option<FieldPath>,
}

impl HistoryEntry {
    pub fn cursor(&self) -> HistoryCursor {
        HistoryCursor {
            position: self.position,
            path: self.path.clone(),
        }
    }
}

/// Newest first, at most `limit` entries, optionally after a history row.
pub fn of(
    conn: &Connection,
    scope: Scope,
    record: RecordId,
    limit: usize,
    before: Option<HistoryCursor>,
) -> Result<Vec<HistoryEntry>, DataError> {
    let row = records::lookup_scope(conn, scope)?
        .map(|sid| records::get(conn, sid, record))
        .transpose()?
        .flatten()
        .ok_or(DataError::NotFound)?;
    let position = before
        .as_ref()
        .map(|cursor| integer(cursor.position.0))
        .transpose()?;
    let path = before.map(|cursor| {
        cursor
            .path
            .map_or_else(String::new, |path| path.as_pointer())
    });
    let mut stmt = conn
        .prepare_cached(
            "SELECT position,mutation,actor,path,old,new FROM data_history
             WHERE rec=?1 AND (?2 IS NULL OR position<?2 OR (position=?2 AND path>?3))
             ORDER BY position DESC,path ASC LIMIT ?4",
        )
        .map_err(sql)?;
    let rows = stmt
        .query_map(
            params![
                row.id,
                position,
                path,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .map_err(sql)?;
    let json = |text: Option<String>| {
        text.map(|t| serde_json::from_str(&t).map_err(corrupt))
            .transpose()
    };
    let mut result = Vec::new();
    for row in rows {
        let (position, mutation, actor, path, old, new) = row.map_err(sql)?;
        result.push(HistoryEntry {
            position: Position(unsigned(position)?),
            mutation: MutationId(id(mutation)?),
            actor: actor_store::get(conn, actor)?,
            path: (!path.is_empty())
                .then(|| FieldPath::parse(&path))
                .transpose()?,
            old: json(old)?,
            new: json(new)?,
        });
    }
    Ok(result)
}

/// Writes the accepted change's field clocks and history rows.
pub(crate) fn record(
    tx: &Transaction<'_>,
    rec: i64,
    position: Position,
    mutation: MutationId,
    actor: &Actor,
    plan: &RecordPlan,
) -> Result<(), DataError> {
    let position = integer(position.0)?;
    let actor = actor_store::intern(tx, actor)?;
    let mut clock = tx
        .prepare_cached(
            "INSERT INTO data_field_clock(rec,path,position,mutation) VALUES(?1,?2,?3,?4)
             ON CONFLICT(rec,path) DO UPDATE SET position=excluded.position,mutation=excluded.mutation",
        )
        .map_err(sql)?;
    let mut history = tx
        .prepare_cached(
            "INSERT INTO data_history(rec,position,mutation,actor,path,old,new) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        )
        .map_err(sql)?;
    let text = |v: &Option<Value>| {
        v.as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(corrupt)
    };
    let mut write = |path: String, old: Option<String>, new: Option<String>| {
        clock
            .execute(params![rec, path, position, mutation.0.as_slice()])
            .map_err(sql)?;
        history
            .execute(params![
                rec,
                position,
                mutation.0.as_slice(),
                actor,
                path,
                old,
                new
            ])
            .map_err(sql)?;
        Ok::<_, DataError>(())
    };
    if let Some((before, after)) = plan.lifecycle {
        write(
            String::new(),
            before.map(|b| b.to_string()),
            Some(after.to_string()),
        )?;
    }
    for change in &plan.changes {
        write(
            change.path.as_pointer(),
            text(&change.old)?,
            text(&change.new)?,
        )?;
    }
    Ok(())
}
