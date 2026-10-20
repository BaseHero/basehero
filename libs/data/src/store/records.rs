use rusqlite::{
    Connection, OptionalExtension, Transaction, params, params_from_iter, types::Value as SqlValue,
};
use serde_json::Value;

use super::{corrupt, id, integer, sql, unsigned};
use crate::{CoreCatalogue, DataError, Position, RecordId, RevisionId, Scope, TypeId, index};

pub fn scope_id(
    tx: &Transaction<'_>,
    scope: Scope,
    core: &dyn CoreCatalogue,
) -> Result<i64, DataError> {
    tx.execute(
        "INSERT INTO data_scope(base,audience) VALUES(?1,?2) ON CONFLICT(base,audience) DO NOTHING",
        params![scope.base.as_slice(), scope.audience.as_slice()],
    )
    .map_err(sql)?;
    let id = lookup_scope(tx, scope)?
        .ok_or_else(|| DataError::Corrupt("inserted scope missing".into()))?;
    let ready: bool = tx
        .query_row("SELECT core_ready FROM data_scope WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .map_err(sql)?;
    if !ready && let Some(note) = core.core_type(TypeId::core("note")) {
        index::ensure(tx, id, &note)?;
        tx.execute("UPDATE data_scope SET core_ready=1 WHERE id=?1", [id])
            .map_err(sql)?;
    }
    Ok(id)
}

pub fn lookup_scope(conn: &Connection, scope: Scope) -> Result<Option<i64>, DataError> {
    conn.query_row(
        "SELECT id FROM data_scope WHERE base=?1 AND audience=?2",
        params![scope.base.as_slice(), scope.audience.as_slice()],
        |r| r.get(0),
    )
    .optional()
    .map_err(sql)
}

/// `accepted` is the ordered state (`None` once a deletion is accepted, or
/// before a local creation is accepted); `doc` overlays this replica's pending
/// work; `deleted` hides the record from this replica's view. A Note the
/// note lifecycle removed stays hidden (the row's `hidden` column, see
/// `note::remove_projection`): [`put`] keeps `deleted` set while it is.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordRow {
    pub id: i64,
    pub scope: i64,
    pub record: RecordId,
    pub type_id: TypeId,
    pub revision: RevisionId,
    pub accepted: Option<Value>,
    pub doc: Option<Value>,
    pub deleted: bool,
    pub pending: bool,
    pub changed_at: Option<Position>,
    pub changed: u64,
    pub text_rev: u64,
}

impl RecordRow {
    pub fn view(&self) -> Option<&Value> {
        self.doc.as_ref().or(self.accepted.as_ref())
    }

    /// Whether ordered state holds this record, deleted or not.
    pub fn exists_accepted(&self) -> bool {
        self.accepted.is_some() || self.changed_at.is_some()
    }
}

/// Whether this scope holds the record, without loading its state.
pub fn exists(conn: &Connection, scope: i64, record: RecordId) -> Result<bool, DataError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_record WHERE scope=?1 AND record=?2)",
        params![scope, record.0.as_slice()],
        |row| row.get(0),
    )
    .map_err(sql)
}

pub fn get(
    conn: &Connection,
    scope: i64,
    record: RecordId,
) -> Result<Option<RecordRow>, DataError> {
    type Raw = (
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<String>,
        Option<String>,
        bool,
        bool,
        Option<i64>,
        i64,
        i64,
    );
    let raw: Option<Raw> = conn.prepare_cached(
        "SELECT id,type,revision,accepted,doc,deleted,pending,changed_at,changed,text_rev FROM data_record WHERE scope=?1 AND record=?2",
    ).map_err(sql)?.query_row(
        params![scope, record.0.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?,
            r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
    ).optional().map_err(sql)?;
    raw.map(
        |(
            id_,
            type_id,
            revision,
            accepted,
            doc,
            deleted,
            pending,
            changed_at,
            changed,
            text_rev,
        )| {
            Ok(RecordRow {
                id: id_,
                scope,
                record,
                type_id: TypeId(id(type_id)?),
                revision: RevisionId(id(revision)?),
                accepted: accepted
                    .map(|s| serde_json::from_str(&s).map_err(corrupt))
                    .transpose()?,
                doc: doc
                    .map(|s| serde_json::from_str(&s).map_err(corrupt))
                    .transpose()?,
                deleted,
                pending,
                changed_at: changed_at.map(|v| unsigned(v).map(Position)).transpose()?,
                changed: unsigned(changed)?,
                text_rev: unsigned(text_rev)?,
            })
        },
    )
    .transpose()
}

pub fn next_seq(tx: &Transaction<'_>) -> Result<u64, DataError> {
    let next: i64 = tx
        .prepare_cached("UPDATE data_seq SET next=next+1 WHERE id=1 RETURNING next-1")
        .map_err(sql)?
        .query_row([], |r| r.get(0))
        .map_err(sql)?;
    unsigned(next)
}

/// The common existing Note projection changes no identity, type, pending or
/// logical-index columns. Keep its record id and all unchanged index keys.
pub fn put_note_in_place(tx: &Transaction<'_>, row: &mut RecordRow) -> Result<(), DataError> {
    row.text_rev = next_seq(tx)?;
    let changed = next_seq(tx)?;
    let accepted = row
        .accepted
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(corrupt)?;
    let doc = row
        .doc
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(corrupt)?;
    let updated = tx.prepare_cached(
        "UPDATE data_record SET accepted=?1,doc=?2,changed=?3,text_rev=?4 WHERE id=?5 AND scope=?6"
    ).map_err(sql)?.execute(params![accepted, doc, integer(changed)?, integer(row.text_rev)?, row.id, row.scope]).map_err(sql)?;
    if updated != 1 {
        return Err(DataError::Corrupt(
            "existing Note projection disappeared".into(),
        ));
    }
    row.changed = changed;
    Ok(())
}

pub fn put(tx: &Transaction<'_>, row: &mut RecordRow) -> Result<i64, DataError> {
    let changed = next_seq(tx)?;
    let accepted = row
        .accepted
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(corrupt)?;
    let doc = row
        .doc
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(corrupt)?;
    let (id, deleted): (i64, bool) = tx.query_row(
        "INSERT INTO data_record(scope,record,type,revision,accepted,doc,deleted,pending,changed_at,changed,text_rev)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(scope,record) DO UPDATE SET type=excluded.type,revision=excluded.revision,
           accepted=excluded.accepted,doc=excluded.doc,deleted=(excluded.deleted OR data_record.hidden),
           pending=excluded.pending,changed_at=excluded.changed_at,changed=excluded.changed,text_rev=excluded.text_rev
         RETURNING id,deleted",
        params![row.scope, row.record.0.as_slice(), row.type_id.0.as_slice(), row.revision.0.as_slice(),
            accepted, doc, row.deleted, row.pending, row.changed_at.map(|p| integer(p.0)).transpose()?,
            integer(changed)?, integer(row.text_rev)?], |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(sql)?;
    row.id = id;
    row.deleted = deleted;
    row.changed = changed;
    Ok(id)
}

pub fn count_type_upto(
    conn: &Connection,
    scope: i64,
    types: &[TypeId],
    cap: u64,
) -> Result<u64, DataError> {
    if types.is_empty() {
        return Ok(0);
    }
    let placeholders = vec!["?"; types.len()].join(",");
    let sql_text = format!(
        "SELECT count(*) FROM (SELECT 1 FROM data_record WHERE scope=? AND type IN ({placeholders}) AND deleted=0 LIMIT ?)"
    );
    let mut args = Vec::with_capacity(types.len() + 2);
    args.push(SqlValue::Integer(scope));
    args.extend(types.iter().map(|ty| SqlValue::Blob(ty.0.to_vec())));
    // SQLite's LIMIT -1 is unbounded, so never allow cap+1 to overflow it.
    let limit = cap.saturating_add(1).min(i64::MAX as u64) as i64;
    args.push(SqlValue::Integer(limit));
    let count: i64 = conn
        .query_row(&sql_text, params_from_iter(args), |r| r.get(0))
        .map_err(sql)?;
    unsigned(count)
}
