//! Scoped, rebuildable indexes over typed records.
mod backfill;
mod entries;
pub mod refs;
pub mod unique;

use crate::{
    CompiledType, CoreCatalogue, DataError, KeyRef, TypeId,
    store::{corrupt, id, integer, registry, sql, unsigned},
};
pub(crate) use backfill::WorkMeter;
pub use backfill::{
    BACKFILL_BATCH, Progress, backfill_step, backfill_step_bounded, begin_rebuild,
    clear_step_bounded, rebuild_all,
};
pub(crate) use entries::encode_key;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexState {
    pub id: i64,
    pub scope: i64,
    pub family: TypeId,
    pub keys: Vec<KeyRef>,
    pub unique: bool,
    pub origin: String,
    pub local_claim: bool,
    pub state: String,
    pub cursor_type: Option<TypeId>,
    pub cursor_id: i64,
    pub built: u64,
    pub estimate: Option<u64>,
}

pub fn state(conn: &Connection, ix: i64) -> Result<IndexState, DataError> {
    type Row = (
        i64,
        Vec<u8>,
        String,
        bool,
        String,
        bool,
        String,
        Option<Vec<u8>>,
        i64,
        i64,
        Option<i64>,
    );
    let row: Row = conn.query_row(
        "SELECT scope,family,keys,unique_,origin,local_claim,state,cursor_type,cursor_id,built,estimate FROM data_index WHERE id=?1",
        [ix], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?)),
    ).optional().map_err(sql)?.ok_or(DataError::NotFound)?;
    Ok(IndexState {
        id: ix,
        scope: row.0,
        family: TypeId(id(row.1)?),
        keys: serde_json::from_str(&row.2).map_err(corrupt)?,
        unique: row.3,
        origin: row.4,
        local_claim: row.5,
        state: row.6,
        cursor_type: row.7.map(|bytes| id(bytes).map(TypeId)).transpose()?,
        cursor_id: row.8,
        built: unsigned(row.9)?,
        estimate: row.10.map(unsigned).transpose()?,
    })
}

/// Reserved work ID for an unfinished text rebuild, not a data_index row.
/// Call `rebuild_all` when present; never pass this ID to `backfill_step`.
pub const TEXT_REBUILD_WORK: i64 = 0;

/// Host probe before scheduling a derived-work turn. It reads the pending
/// markers through their partial index, so idle indexes cost nothing.
pub fn has_pending(conn: &Connection) -> Result<bool, DataError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_index WHERE state IN ('building','retiring','clearing'))
             OR EXISTS(SELECT 1 FROM data_text_rebuild WHERE id=1)",
        [],
        |row| row.get(0),
    )
    .map_err(sql)
}

/// The one work item a host's next derived turn takes, from the pending
/// markers alone: `TEXT_REBUILD_WORK` while a text rebuild is unfinished,
/// else the lowest pending index. [`pending_work`] lists them all.
pub fn next_pending(conn: &Connection) -> Result<Option<i64>, DataError> {
    if conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM data_text_rebuild WHERE id=1)",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?
    {
        return Ok(Some(TEXT_REBUILD_WORK));
    }
    conn.query_row(
        "SELECT id FROM data_index WHERE state IN ('building','retiring','clearing') ORDER BY id LIMIT 1",
        [],
        |r| r.get(0),
    )
    .optional()
    .map_err(sql)
}

/// Whether a rebuild still has indexes to clear before its text phase.
pub fn clearing_pending(conn: &Connection) -> Result<bool, DataError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_index
             WHERE state IN ('building','retiring','clearing') AND state='clearing')",
        [],
        |r| r.get(0),
    )
    .map_err(sql)
}

/// A text rebuild marker is reported first as `TEXT_REBUILD_WORK`; resume it
/// with `rebuild_all`, then refresh this list. Also includes `clearing` indexes,
/// which require `rebuild_all` before calling `backfill_step` on `building` IDs.
pub fn pending_work(conn: &Connection) -> Result<Vec<i64>, DataError> {
    let mut stmt = conn
        .prepare("SELECT id FROM data_index WHERE state IN ('building','retiring','clearing') ORDER BY id")
        .map_err(sql)?;
    let rows = stmt.query_map([], |r| r.get(0)).map_err(sql)?;
    let mut pending = rows
        .map(|r| r.map_err(sql))
        .collect::<Result<Vec<_>, _>>()?;
    let text: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM data_text_rebuild WHERE id=1)",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if text {
        pending.insert(0, TEXT_REBUILD_WORK);
    }
    Ok(pending)
}

pub(super) fn count_family(
    conn: &Connection,
    scope: i64,
    family: TypeId,
) -> Result<u64, DataError> {
    let mut count = 0u64;
    for member in registry::family_members(conn, scope, family)? {
        let rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM data_record WHERE scope=?1 AND type=?2",
                params![scope, member.0.as_slice()],
                |r| r.get(0),
            )
            .map_err(sql)?;
        count = count
            .checked_add(unsigned(rows)?)
            .ok_or_else(|| DataError::Limit("family row count overflow".into()))?;
    }
    Ok(count)
}

fn ensure_one(
    tx: &Transaction<'_>,
    scope: i64,
    family: TypeId,
    keys: &[KeyRef],
    unique: bool,
    origin: &str,
    name: &str,
) -> Result<i64, DataError> {
    if keys.is_empty() || keys.len() > 4 {
        return Err(DataError::Definition(
            "index requires one to four keys".into(),
        ));
    }
    let encoded = serde_json::to_string(keys).map_err(corrupt)?;
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM data_index WHERE scope=?1 AND family=?2 AND keys=?3 AND unique_=?4",
            params![scope, family.0.as_slice(), encoded, unique],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(ix) = existing {
        if origin == "definition" {
            tx.execute(
                "UPDATE data_index SET name=?2 WHERE id=?1 AND name<>?2",
                params![ix, name],
            )
            .map_err(sql)?;
        }
        if origin == "local" {
            tx.execute(
                "UPDATE data_index SET local_claim=1 WHERE id=?1 AND local_claim=0",
                [ix],
            )
            .map_err(sql)?;
        }
        if state(tx, ix)?.state == "retiring" {
            let estimate = count_family(tx, scope, family)?;
            tx.execute("UPDATE data_index SET state=?2,cursor_type=NULL,cursor_id=0,built=0,estimate=?3 WHERE id=?1",params![ix,if estimate==0 {"ready"} else {"building"},integer(estimate)?]).map_err(sql)?;
        }
        return Ok(ix);
    }
    let estimate = count_family(tx, scope, family)?;
    let initial = if estimate == 0 { "ready" } else { "building" };
    tx.execute("INSERT INTO data_index(scope,family,name,keys,unique_,origin,local_claim,state,cursor_type,cursor_id,built,estimate) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,0,0,?9)",params![scope,family.0.as_slice(),name,encoded,unique,origin,origin=="local",initial,integer(estimate)?]).map_err(sql)?;
    Ok(tx.last_insert_rowid())
}

pub fn ensure(tx: &Transaction<'_>, scope: i64, ct: &CompiledType) -> Result<Vec<i64>, DataError> {
    let result = ensure_declarations(tx, scope, ct)?;
    // Other current declarations are relevant only to retirement.
    let mut types = registry::list_types(tx, scope, &CoreWithoutTypes)?;
    types.retain(|other| other.type_id != ct.type_id);
    types.push(ct.clone());
    retire_missing(tx, scope, &types)?;
    Ok(result)
}

fn ensure_declarations(
    tx: &Transaction<'_>,
    scope: i64,
    ct: &CompiledType,
) -> Result<Vec<i64>, DataError> {
    if ct
        .uniques
        .iter()
        .any(|decl| decl.keys.iter().any(|key| matches!(key, KeyRef::Changed)))
    {
        return Err(DataError::Definition(
            "unique keys must be fields; $changed is not supported".into(),
        ));
    }
    let mut result = Vec::new();
    for index in &ct.indexes {
        result.push(ensure_one(
            tx,
            scope,
            index.declared_by,
            &index.keys,
            false,
            "definition",
            &index.name,
        )?)
    }
    for unique in &ct.uniques {
        result.push(ensure_one(
            tx,
            scope,
            unique.declared_by,
            &unique.keys,
            true,
            "definition",
            &unique.name,
        )?)
    }
    Ok(result)
}

// `ensure` also serves first-scope creation, when the shipped Note has not yet
// been persisted. The caller supplies that Note; other current types are read
// from the registry. This catalogue is never consulted for additional types.
struct CoreWithoutTypes;
impl CoreCatalogue for CoreWithoutTypes {
    fn core_type(&self, _: TypeId) -> Option<CompiledType> {
        None
    }
}

fn retire_missing(
    tx: &Transaction<'_>,
    scope: i64,
    types: &[CompiledType],
) -> Result<(), DataError> {
    let mut declared: HashSet<(TypeId, String, bool)> = HashSet::new();
    for ct in types {
        for index in &ct.indexes {
            declared.insert((
                index.declared_by,
                serde_json::to_string(&index.keys).map_err(corrupt)?,
                false,
            ));
        }
        for unique in &ct.uniques {
            declared.insert((
                unique.declared_by,
                serde_json::to_string(&unique.keys).map_err(corrupt)?,
                true,
            ));
        }
    }
    let mut stmt = tx
        .prepare(
            "SELECT id,family,keys,unique_,local_claim FROM data_index WHERE scope=?1 AND origin='definition'",
        )
        .map_err(sql)?;
    let rows = stmt
        .query_map([scope], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })
        .map_err(sql)?;
    for row in rows {
        let (ix, family, keys, unique, local_claim) = row.map_err(sql)?;
        // The shipped core baseline has no data_definition row to join above.
        if family == TypeId::core("note").0
            && !types.is_empty()
            && !types.iter().any(|ct| ct.type_id == TypeId::core("note"))
        {
            continue;
        }
        if !declared.contains(&(TypeId(id(family)?), keys, unique)) {
            if local_claim {
                tx.execute("UPDATE data_index SET origin='local' WHERE id=?1", [ix])
                    .map_err(sql)?;
            } else {
                tx.execute("UPDATE data_index SET state='retiring',built=0,estimate=NULL WHERE id=?1 AND state!='retiring'", [ix]).map_err(sql)?;
            }
        }
    }
    Ok(())
}

/// Invoke after a type's current definition changes, not from ordinary scope
/// lookup. Reconciles all current declarations, including the shipped core.
pub fn on_definitions_changed(
    tx: &Transaction<'_>,
    scope: i64,
    core: &dyn CoreCatalogue,
) -> Result<(), DataError> {
    let types = registry::list_types(tx, scope, core)?;
    for ct in &types {
        ensure_declarations(tx, scope, ct)?;
    }
    retire_missing(tx, scope, &types)
}

pub fn ensure_local(
    tx: &Transaction<'_>,
    scope: i64,
    family: TypeId,
    keys: Vec<KeyRef>,
) -> Result<i64, DataError> {
    let label = format!("local:{}", serde_json::to_string(&keys).map_err(corrupt)?);
    ensure_one(tx, scope, family, &keys, false, "local", &label)
}

pub fn on_record_changed(
    tx: &Transaction<'_>,
    row: &crate::store::records::RecordRow,
    ct: &CompiledType,
) -> Result<(), DataError> {
    entries::on_record_changed(tx, row, ct)
}

/// Maintains only the record's family index entries whose keys `affected`
/// selects; see `entries::on_keys_changed`.
pub(crate) fn on_keys_changed(
    tx: &Transaction<'_>,
    row: &crate::store::records::RecordRow,
    lineage: &[TypeId],
    affected: &dyn Fn(&KeyRef) -> bool,
) -> Result<(), DataError> {
    entries::on_keys_changed(tx, row, lineage, affected)
}
