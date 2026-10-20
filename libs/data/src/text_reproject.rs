//! Restartable, scoped search-mapping evolution; source rows stay untouched.
use crate::{
    CompiledType, CoreCatalogue, DataError, RecordId,
    store::{self, records, registry},
    text,
};
use rusqlite::{OptionalExtension, Transaction, params};

pub(crate) fn schedule(
    tx: &Transaction<'_>,
    scope: i64,
    ct: &CompiledType,
) -> Result<(), DataError> {
    let since = records::next_seq(tx)?;
    tx.execute(
        "INSERT INTO data_text_mapping(scope,type,revision,cursor,since) VALUES(?1,?2,?3,0,?4)
        ON CONFLICT(scope,type) DO UPDATE SET revision=excluded.revision,cursor=0",
        params![
            scope,
            ct.type_id.0.as_slice(),
            ct.revision.0.as_slice(),
            store::integer(since)?
        ],
    )
    .map_err(store::sql)?;
    Ok(())
}

/// One writer-queue turn. Returns true when no mapping work remains. The host
/// commits each step and schedules another turn until done. Foreground writes
/// use the same current mapping; restarting a changed mapping resets its cursor.
pub fn step(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    max_rows: usize,
    max_vm_steps: u64,
) -> Result<bool, DataError> {
    let meter = crate::index::WorkMeter::new(tx, max_vm_steps)?;
    let task: Option<(i64, Vec<u8>, Vec<u8>, i64)> = tx
        .query_row(
            "SELECT scope,type,revision,cursor FROM data_text_mapping ORDER BY scope,type LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(store::sql)?;
    let Some((sid, ty, revision, cursor)) = task else {
        return Ok(true);
    };
    let ct = registry::current(tx, sid, crate::TypeId(store::id(ty.clone())?), core)?
        .ok_or_else(|| DataError::Corrupt("mapping definition missing".into()))?;
    if ct.revision.0.as_slice() != revision {
        return Err(DataError::Corrupt(
            "mapping revision differs from current contract".into(),
        ));
    }
    let cap = max_rows.min(500) as i64;
    let mut stmt=tx.prepare_cached("SELECT id,record FROM data_record WHERE scope=?1 AND type=?2 AND id>?3 ORDER BY id LIMIT ?4").map_err(store::sql)?;
    let rows = stmt
        .query_map(params![sid, ty, cursor, cap], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(store::sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(store::sql)?;
    let mut last = cursor;
    for (id, record) in rows {
        if last != cursor && meter.exhausted() {
            break;
        }
        let row =
            records::get(tx, sid, RecordId(store::id(record)?))?.ok_or(DataError::NotFound)?;
        text::on_record_changed(tx, &row, &ct)?;
        last = id;
    }
    tx.execute(
        "UPDATE data_text_mapping SET cursor=?3 WHERE scope=?1 AND type=?2",
        params![sid, ty, last],
    )
    .map_err(store::sql)?;
    let more: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM data_record WHERE scope=?1 AND type=?2 AND id>?3)",
            params![sid, ty, last],
            |r| r.get(0),
        )
        .map_err(store::sql)?;
    if !more && cap > 0 {
        tx.execute(
            "DELETE FROM data_text_mapping WHERE scope=?1 AND type=?2",
            params![sid, ty],
        )
        .map_err(store::sql)?;
    }
    let pending: bool = tx
        .query_row("SELECT EXISTS(SELECT 1 FROM data_text_mapping)", [], |r| {
            r.get(0)
        })
        .map_err(store::sql)?;
    Ok(!pending)
}
