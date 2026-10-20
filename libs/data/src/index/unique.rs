use super::entries;
use crate::{
    CompiledType, DataError, RecordId, UniqueDecl,
    store::{coverage, id, sql},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UniqueCheck {
    Free,
    Taken(RecordId),
    Unknown,
}

/// String keys compare as exact UTF-8 bytes, without case folding or normalization.
pub fn check(
    conn: &Connection,
    scope: i64,
    ct: &CompiledType,
    rec: Option<i64>,
    accepted_doc: &Value,
) -> Result<UniqueCheck, DataError> {
    check_decls(conn, scope, &ct.uniques, rec, accepted_doc)
}

/// [`check`] for a subset of a type's unique declarations, against accepted state.
pub fn check_decls(
    conn: &Connection,
    scope: i64,
    decls: &[UniqueDecl],
    rec: Option<i64>,
    accepted_doc: &Value,
) -> Result<UniqueCheck, DataError> {
    if !coverage::get(conn, scope)?.complete {
        return Ok(UniqueCheck::Unknown);
    }
    for decl in decls {
        let Some(ix) = ready_index(conn, scope, decl)? else {
            return Ok(UniqueCheck::Unknown);
        };
        let (k, present) = entries::keys(&decl.keys, Some(accepted_doc), 0)?;
        if !present {
            continue;
        }
        let found:Option<Vec<u8>>=conn.query_row("SELECT r.record FROM data_unique u JOIN data_record r ON r.id=u.rec AND r.scope=?7 WHERE u.ix=?1 AND u.k1 IS ?2 AND u.k2 IS ?3 AND u.k3 IS ?4 AND u.k4 IS ?5 AND u.rec!=?6 LIMIT 1",params![ix,k[0],k[1],k[2],k[3],rec.unwrap_or(-1),scope],|r|r.get(0)).optional().map_err(sql)?;
        if let Some(found) = found {
            return Ok(UniqueCheck::Taken(RecordId(id(found)?)));
        }
    }
    Ok(UniqueCheck::Free)
}

/// Whether another record visible on this replica, accepted or pending,
/// holds the key. Local knowledge only: `Free` proves nothing about the scope.
pub fn check_local(
    conn: &Connection,
    scope: i64,
    decls: &[UniqueDecl],
    rec: Option<i64>,
    view_doc: &Value,
) -> Result<UniqueCheck, DataError> {
    for decl in decls {
        let Some(ix) = ready_index(conn, scope, decl)? else {
            return Ok(UniqueCheck::Unknown);
        };
        let (k, present) = entries::keys(&decl.keys, Some(view_doc), 0)?;
        if !present {
            continue;
        }
        let found:Option<Vec<u8>>=conn.query_row("SELECT r.record FROM data_index_entry e JOIN data_record r ON r.id=e.rec AND r.scope=?7 WHERE e.ix=?1 AND e.k1 IS ?2 AND e.k2 IS ?3 AND e.k3 IS ?4 AND e.k4 IS ?5 AND e.rec!=?6 AND r.deleted=0 LIMIT 1",params![ix,k[0],k[1],k[2],k[3],rec.unwrap_or(-1),scope],|r|r.get(0)).optional().map_err(sql)?;
        if let Some(found) = found {
            return Ok(UniqueCheck::Taken(RecordId(id(found)?)));
        }
    }
    Ok(UniqueCheck::Free)
}

fn ready_index(conn: &Connection, scope: i64, decl: &UniqueDecl) -> Result<Option<i64>, DataError> {
    let encoded =
        serde_json::to_string(&decl.keys).map_err(|e| DataError::Corrupt(e.to_string()))?;
    conn.query_row("SELECT id FROM data_index WHERE scope=?1 AND family=?2 AND keys=?3 AND unique_=1 AND state='ready'",params![scope,decl.declared_by.0.as_slice(),encoded],|r|r.get(0)).optional().map_err(sql)
}
