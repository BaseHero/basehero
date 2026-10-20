use super::{IndexState, refs, state};
use crate::{
    CompiledType, DataError, KeyRef, TypeId,
    store::{corrupt, records::RecordRow, sql},
    value,
};
use rusqlite::{Transaction, params, params_from_iter, types::Value as Sql};
use serde_json::Value;

/// The one SQLite representation for indexed and query-bound JSON keys.
pub(crate) fn encode_key(v: &Value) -> Sql {
    match v {
        Value::Null => Sql::Null,
        Value::Bool(v) => Sql::Integer(i64::from(*v)),
        Value::String(v) => Sql::Text(v.clone()),
        Value::Number(n) if n.is_i64() => Sql::Integer(n.as_i64().expect("i64 number")),
        Value::Number(n) if n.is_u64() && n.as_u64().expect("u64 number") <= i64::MAX as u64 => {
            Sql::Integer(n.as_u64().expect("u64 number") as i64)
        }
        Value::Number(n) => Sql::Real(n.as_f64().expect("JSON number")),
        _ => Sql::Text(value::canonical(v)),
    }
}

pub(super) fn keys(
    keys: &[KeyRef],
    doc: Option<&Value>,
    changed: u64,
) -> Result<([Sql; 4], bool), DataError> {
    let mut out = std::array::from_fn(|_| Sql::Integer(0));
    let mut present = true;
    for (i, key) in keys.iter().enumerate() {
        let v = match key {
            KeyRef::Changed => {
                out[i] = Sql::Integer(i64::try_from(changed).map_err(corrupt)?);
                continue;
            }
            KeyRef::Field(path) => doc.and_then(|d| path.get(d)),
        };
        out[i] = match v {
            None => {
                present = false;
                Sql::Null
            }
            Some(v) => encode_key(v),
        };
    }
    Ok((out, present))
}

pub(super) fn write(
    tx: &Transaction<'_>,
    ix: &IndexState,
    row: &RecordRow,
) -> Result<(), DataError> {
    if row.scope != ix.scope {
        return Err(DataError::Corrupt(
            "index scope differs from record scope".into(),
        ));
    }
    tx.execute(
        "DELETE FROM data_index_entry WHERE ix=?1 AND rec=?2",
        params![ix.id, row.id],
    )
    .map_err(sql)?;
    tx.execute(
        "DELETE FROM data_unique WHERE ix=?1 AND rec=?2",
        params![ix.id, row.id],
    )
    .map_err(sql)?;
    // `deleted` hides the record from this replica's view; uniqueness follows
    // accepted state, which is absent once a deletion is accepted.
    if !row.deleted
        && let Some(doc) = row.view()
    {
        let (k, _) = keys(&ix.keys, Some(doc), row.changed)?;
        tx.execute(
            "INSERT INTO data_index_entry(ix,k1,k2,k3,k4,rec,record) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                ix.id,
                k[0],
                k[1],
                k[2],
                k[3],
                row.id,
                row.record.0.as_slice()
            ],
        )
        .map_err(sql)?;
    }
    if ix.unique
        && let Some(accepted) = row.accepted.as_ref()
    {
        let (k, present) = keys(&ix.keys, Some(accepted), row.changed)?;
        if present {
            tx.execute(
                "INSERT INTO data_unique(ix,k1,k2,k3,k4,rec) VALUES(?1,?2,?3,?4,?5,?6)",
                params![ix.id, k[0], k[1], k[2], k[3], row.id],
            )
            .map_err(sql)?;
        }
    }
    Ok(())
}

pub(super) fn on_record_changed(
    tx: &Transaction<'_>,
    row: &RecordRow,
    ct: &CompiledType,
) -> Result<(), DataError> {
    if row.type_id != ct.type_id {
        return Err(DataError::Corrupt(
            "compiled type differs from record".into(),
        ));
    }
    let actual_scope: i64 = tx
        .query_row("SELECT scope FROM data_record WHERE id=?1", [row.id], |r| {
            r.get(0)
        })
        .map_err(sql)?;
    if actual_scope != row.scope {
        return Err(DataError::Corrupt("record scope mismatch".into()));
    }
    let mut args = vec![Sql::Integer(row.scope)];
    args.extend(ct.lineage.iter().map(|(t, _)| Sql::Blob(t.0.to_vec())));
    let mut stmt = tx.prepare_cached(&format!(
        "SELECT id FROM data_index WHERE scope=? AND state!='retiring' AND family IN ({}) ORDER BY id",
        vec!["?"; ct.lineage.len()].join(",")
    )).map_err(sql)?;
    let ids = stmt
        .query_map(params_from_iter(args), |r| r.get::<_, i64>(0))
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    for id in ids {
        let ix = state(tx, id)?;
        if !ct.is_family_member_of(ix.family) {
            continue;
        }
        if covers(&ix, row) {
            write(tx, &ix, row)?;
        }
    }
    refs::update(tx, row, ct)
}

/// Every record change passes here. Newly registered members sorting before
/// the byte-key cursor are covered inline, never revisited by the forward
/// scan; later members are picked up by backfill.
fn covers(ix: &IndexState, row: &RecordRow) -> bool {
    ix.state == "ready"
        || ix
            .cursor_type
            .is_some_and(|cursor| (row.type_id, row.id) <= (cursor, ix.cursor_id))
}

/// Rewrites only the entries of the record's family indexes whose keys
/// `affected` selects, for a change that leaves every other key and every
/// reference as it was. `lineage` is the record's type and its ancestors.
pub(super) fn on_keys_changed(
    tx: &Transaction<'_>,
    row: &RecordRow,
    lineage: &[TypeId],
    affected: &dyn Fn(&KeyRef) -> bool,
) -> Result<(), DataError> {
    let mut args = vec![Sql::Integer(row.scope)];
    args.extend(lineage.iter().map(|t| Sql::Blob(t.0.to_vec())));
    // The text varies only with the lineage's length, so it stays cached.
    let mut stmt = tx
        .prepare_cached(&format!(
            "SELECT id FROM data_index WHERE scope=? AND state!='retiring' AND family IN ({}) ORDER BY id",
            vec!["?"; lineage.len()].join(",")
        ))
        .map_err(sql)?;
    let ids = stmt
        .query_map(params_from_iter(args), |r| r.get::<_, i64>(0))
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    for id in ids {
        let ix = state(tx, id)?;
        if ix.keys.iter().any(affected) && covers(&ix, row) {
            // A populated non-unique $changed entry keeps its rowid, scope
            // and record key. Missing/backfilling entries use the full write.
            if !ix.unique
                && !row.deleted
                && row.type_id == TypeId::core("note")
                && ix.keys.as_slice() == [KeyRef::Changed]
            {
                let updated = tx
                    .prepare_cached("UPDATE data_index_entry SET k1=?1 WHERE ix=?2 AND rec=?3")
                    .map_err(sql)?
                    .execute(params![
                        i64::try_from(row.changed).map_err(corrupt)?,
                        ix.id,
                        row.id
                    ])
                    .map_err(sql)?;
                if updated == 1 {
                    continue;
                }
            }
            write(tx, &ix, row)?;
        }
    }
    Ok(())
}
