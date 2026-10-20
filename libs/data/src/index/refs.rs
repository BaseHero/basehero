use crate::{
    CompiledType, CoreCatalogue, DataError, FieldKind, FieldPath, RecordId, RecordRef, Scope,
    TypeId,
    store::{
        coverage, id,
        records::{self, RecordRow},
        sql,
    },
};
use rusqlite::{Connection, Transaction, params};

struct NoCore;
impl CoreCatalogue for NoCore {
    fn core_type(&self, _: TypeId) -> Option<CompiledType> {
        None
    }
}

pub(super) fn update(
    tx: &Transaction<'_>,
    row: &RecordRow,
    ct: &CompiledType,
) -> Result<(), DataError> {
    tx.execute("DELETE FROM data_ref WHERE src=?1", [row.id])
        .map_err(sql)?;
    if row.deleted {
        return Ok(());
    }
    let Some(doc) = row.view() else { return Ok(()) };
    let base: Vec<u8> = tx
        .query_row(
            "SELECT base FROM data_scope WHERE id=?1",
            [row.scope],
            |r| r.get(0),
        )
        .map_err(sql)?;
    for field in &ct.fields {
        if !matches!(field.kind, FieldKind::Reference(_)) {
            continue;
        }
        let Some(raw) = field.path.get(doc) else {
            continue;
        };
        if raw.is_null() {
            continue;
        }
        let reference: RecordRef =
            serde_json::from_value(raw.clone()).map_err(|e| DataError::Value(e.to_string()))?;
        let target_scope = match reference.audience {
            None => row.scope,
            Some(audience) => records::scope_id(
                tx,
                Scope {
                    base: id(base.clone())?,
                    audience,
                },
                &NoCore,
            )?,
        };
        tx.execute(
            "INSERT INTO data_ref(src,path,dst_scope,dst,scope) VALUES(?1,?2,?3,?4,?5)",
            params![
                row.id,
                field.path.as_pointer(),
                target_scope,
                reference.record.0.as_slice(),
                row.scope
            ],
        )
        .map_err(sql)?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Referrers {
    pub rows: Vec<(i64, FieldPath)>,
    pub complete: bool,
}

/// Reader-scope completeness gates negative answers. The reference projection
/// is maintained transactionally by `on_record_changed`; a separate projection
/// rebuild must invalidate scope coverage *before* clearing `data_ref`, and
/// restore it only after ref rows have been rebuilt. Index-only `rebuild_all`
/// never clears reference rows.
pub fn referrers(
    conn: &Connection,
    reader_scope: i64,
    target_scope: i64,
    target: RecordId,
    limit: usize,
) -> Result<Referrers, DataError> {
    if !coverage::get(conn, reader_scope)?.complete {
        return Ok(Referrers {
            rows: Vec::new(),
            complete: false,
        });
    }
    let mut stmt=conn.prepare("SELECT src,path FROM data_ref WHERE dst_scope=?1 AND dst=?2 AND scope=?3 ORDER BY src,path LIMIT ?4").map_err(sql)?;
    let rows = stmt
        .query_map(
            params![
                target_scope,
                target.0.as_slice(),
                reader_scope,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
        )
        .map_err(sql)?;
    let rows = rows
        .map(|r| {
            let (src, path) = r.map_err(sql)?;
            Ok((src, FieldPath::parse(&path)?))
        })
        .collect::<Result<Vec<_>, DataError>>()?;
    Ok(Referrers {
        rows,
        complete: true,
    })
}
