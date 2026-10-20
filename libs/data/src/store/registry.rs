use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{corrupt, id, integer, sql};
use crate::{
    AppId, CompiledType, CoreCatalogue, DataError, Position, RevisionId, TypeId, evolve::Migration,
};

/// The core contract served without a binding: Note v1, the implicit
/// baseline of every audience. Every other core type is usable in an
/// audience only once an ordered binding names its revision.
fn baseline(core: &dyn CoreCatalogue, type_id: TypeId) -> Option<CompiledType> {
    (type_id == TypeId::core("note"))
        .then(|| core.core_type(type_id))
        .flatten()
}

pub fn store_definition(
    tx: &Transaction<'_>,
    scope: i64,
    compiled: &CompiledType,
    bytes: &[u8],
    at: Position,
) -> Result<(), DataError> {
    let json = serde_json::to_string(compiled).map_err(corrupt)?;
    tx.execute("INSERT INTO data_definition(scope,revision,type,app,bytes,compiled,accepted_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![scope, compiled.revision.0.as_slice(), compiled.type_id.0.as_slice(),
            compiled.app.map(|app| app.0.to_vec()), bytes, json, integer(at.0)?]).map_err(sql)?;
    Ok(())
}

/// Keeps a bound core contract with the audience's definitions, so reads by
/// revision and as of a position treat it like any accepted definition. Core
/// contracts ship with the executable, so the row keeps no definition bytes.
/// Binding a revision again keeps its first acceptance.
pub fn store_core(
    tx: &Transaction<'_>,
    scope: i64,
    compiled: &CompiledType,
    at: Position,
) -> Result<(), DataError> {
    if self::compiled(tx, scope, compiled.revision)?.is_none() {
        store_definition(tx, scope, compiled, &[], at)?;
    }
    Ok(())
}

/// Every revision of `type_id` accepted in this scope, current or not.
pub fn revisions(
    conn: &Connection,
    scope: i64,
    type_id: TypeId,
) -> Result<Vec<RevisionId>, DataError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT revision FROM data_definition WHERE scope=?1 AND type=?2 ORDER BY accepted_at",
        )
        .map_err(sql)?;
    let rows = stmt
        .query_map(params![scope, type_id.0.as_slice()], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(sql)?;
    rows.map(|row| Ok(RevisionId(id(row.map_err(sql)?)?)))
        .collect()
}

/// The declarative migration an accepted revision describes from earlier
/// revisions of its type (empty when it declares none, or for a core contract).
pub fn migration_ops(
    conn: &Connection,
    scope: i64,
    revision: RevisionId,
) -> Result<Vec<Migration>, DataError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT bytes FROM data_definition WHERE scope=?1 AND revision=?2",
            params![scope, revision.0.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    // Accepted bytes were checked on acceptance; only the migration is read.
    #[derive(serde::Deserialize)]
    struct Definition {
        evolution: Evolution,
    }
    #[derive(serde::Deserialize)]
    struct Evolution {
        #[serde(default)]
        migration_ops: Vec<Migration>,
    }
    match bytes {
        Some(bytes) if !bytes.is_empty() => Ok(serde_json::from_slice::<Definition>(&bytes)
            .map_err(corrupt)?
            .evolution
            .migration_ops),
        _ => Ok(Vec::new()),
    }
}

pub fn compiled(
    conn: &Connection,
    scope: i64,
    revision: RevisionId,
) -> Result<Option<CompiledType>, DataError> {
    compiled_before(conn, scope, revision, None)
}

/// Registry reads `…_before(…, Some(p))` see only what was accepted before
/// position `p`, so replaying parked work at `p` reads the rules a fully
/// covered replica read there. `None` reads the latest state.
pub fn compiled_before(
    conn: &Connection,
    scope: i64,
    revision: RevisionId,
    before: Option<Position>,
) -> Result<Option<CompiledType>, DataError> {
    let json: Option<String> = conn
        .query_row(
            "SELECT compiled FROM data_definition WHERE scope=?1 AND revision=?2 AND (?3 IS NULL OR accepted_at<?3)",
            params![scope, revision.0.as_slice(), position(before)?],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    json.map(|text| serde_json::from_str(&text).map_err(corrupt))
        .transpose()
}

pub fn current(
    conn: &Connection,
    scope: i64,
    type_id: TypeId,
    core: &dyn CoreCatalogue,
) -> Result<Option<CompiledType>, DataError> {
    current_before(conn, scope, type_id, core, None)
}

pub fn current_before(
    conn: &Connection,
    scope: i64,
    type_id: TypeId,
    core: &dyn CoreCatalogue,
    before: Option<Position>,
) -> Result<Option<CompiledType>, DataError> {
    match type_state(conn, scope, type_id, before)? {
        Some((revision, _)) => {
            if let Some(definition) = compiled(conn, scope, revision)? {
                return Ok(Some(definition));
            }
            Ok(core.core_type(type_id).filter(|ty| ty.revision == revision))
        }
        None => Ok(baseline(core, type_id)),
    }
}

pub fn permitted(
    conn: &Connection,
    scope: i64,
    type_id: TypeId,
    core: &dyn CoreCatalogue,
) -> Result<Vec<RevisionId>, DataError> {
    permitted_before(conn, scope, type_id, core, None)
}

pub fn permitted_before(
    conn: &Connection,
    scope: i64,
    type_id: TypeId,
    core: &dyn CoreCatalogue,
    before: Option<Position>,
) -> Result<Vec<RevisionId>, DataError> {
    match type_state(conn, scope, type_id, before)? {
        Some((_, json)) => serde_json::from_str(&json).map_err(corrupt),
        None => Ok(baseline(core, type_id)
            .map(|ty| vec![ty.revision])
            .unwrap_or_default()),
    }
}

/// Whether the type's current revision or permitted set changed at or after `at`.
pub fn changed_since(
    conn: &Connection,
    scope: i64,
    type_id: TypeId,
    at: Position,
) -> Result<bool, DataError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_type_at WHERE scope=?1 AND type=?2 AND since>=?3)",
        params![scope, type_id.0.as_slice(), integer(at.0)?],
        |r| r.get(0),
    )
    .map_err(sql)
}

fn type_state(
    conn: &Connection,
    scope: i64,
    type_id: TypeId,
    before: Option<Position>,
) -> Result<Option<(RevisionId, String)>, DataError> {
    let row: Option<(Vec<u8>, String)> = conn
        .query_row(
            "SELECT current,permitted FROM data_type_at WHERE scope=?1 AND type=?2 AND (?3 IS NULL OR since<?3) ORDER BY since DESC LIMIT 1",
            params![scope, type_id.0.as_slice(), position(before)?],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    row.map(|(revision, json)| Ok((RevisionId(id(revision)?), json)))
        .transpose()
}

fn position(at: Option<Position>) -> Result<Option<i64>, DataError> {
    at.map(|p| integer(p.0)).transpose()
}

pub fn set_current(
    tx: &Transaction<'_>,
    scope: i64,
    type_id: TypeId,
    revision: RevisionId,
    permitted: &[RevisionId],
    at: Position,
) -> Result<(), DataError> {
    let definition = compiled(tx, scope, revision)?;
    if definition.as_ref().is_some_and(|ty| ty.type_id != type_id) {
        return Err(DataError::Corrupt("type/revision mismatch".into()));
    }
    let json = serde_json::to_string(permitted).map_err(corrupt)?;
    tx.execute("INSERT INTO data_type(scope,type,current,permitted) VALUES(?1,?2,?3,?4)
        ON CONFLICT(scope,type) DO UPDATE SET current=excluded.current,permitted=excluded.permitted",
        params![scope, type_id.0.as_slice(), revision.0.as_slice(), json]).map_err(sql)?;
    tx.execute("INSERT OR REPLACE INTO data_type_at(scope,type,since,current,permitted) VALUES(?1,?2,?3,?4,?5)",
        params![scope, type_id.0.as_slice(), integer(at.0)?, revision.0.as_slice(), json]).map_err(sql)?;
    if let Some(definition) = definition {
        // Lineage is now established, even if some record payloads remain
        // unsupported. Only this scoped type needs reclassification.
        tx.execute(
            "UPDATE data_parked SET unresolved_type=0 WHERE scope=?1 AND type=?2 AND unresolved_type=1",
            params![scope, type_id.0.as_slice()],
        ).map_err(sql)?;
        tx.execute(
            "DELETE FROM data_family WHERE scope=?1 AND type=?2",
            params![scope, type_id.0.as_slice()],
        )
        .map_err(sql)?;
        for (ancestor, _) in definition.lineage {
            if ancestor != type_id {
                tx.execute(
                    "INSERT INTO data_family(scope,type,ancestor) VALUES(?1,?2,?3)",
                    params![scope, type_id.0.as_slice(), ancestor.0.as_slice()],
                )
                .map_err(sql)?;
            }
        }
    }
    Ok(())
}

pub fn family_members(
    conn: &Connection,
    scope: i64,
    ancestor: TypeId,
) -> Result<Vec<TypeId>, DataError> {
    let mut stmt = conn
        .prepare("SELECT type FROM data_family WHERE scope=?1 AND ancestor=?2 ORDER BY type")
        .map_err(sql)?;
    let members = stmt
        .query_map(params![scope, ancestor.0.as_slice()], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(sql)?;
    let mut result = vec![ancestor];
    for member in members {
        let member = TypeId(id(member.map_err(sql)?)?);
        if member != ancestor {
            result.push(member);
        }
    }
    result.sort_unstable();
    result.dedup();
    Ok(result)
}

pub fn set_app(
    tx: &Transaction<'_>,
    scope: i64,
    app: AppId,
    name: &str,
    active: bool,
    at: Position,
) -> Result<(), DataError> {
    tx.execute("INSERT INTO data_app(scope,app,name,active,changed_at) VALUES(?1,?2,?3,?4,?5)
        ON CONFLICT(scope,app) DO UPDATE SET name=excluded.name,active=excluded.active,changed_at=excluded.changed_at",
        params![scope, app.0.as_slice(), name, active, integer(at.0)?]).map_err(sql)?;
    tx.execute(
        "INSERT OR REPLACE INTO data_app_at(scope,app,since,active) VALUES(?1,?2,?3,?4)",
        params![scope, app.0.as_slice(), integer(at.0)?, active],
    )
    .map_err(sql)?;
    Ok(())
}

/// Records an app's activation at `at`, keeping its name.
pub fn set_app_active(
    tx: &Transaction<'_>,
    scope: i64,
    app: AppId,
    active: bool,
    at: Position,
) -> Result<(), DataError> {
    tx.execute(
        "UPDATE data_app SET active=?3,changed_at=?4 WHERE scope=?1 AND app=?2",
        params![scope, app.0.as_slice(), active, integer(at.0)?],
    )
    .map_err(sql)?;
    tx.execute(
        "INSERT OR REPLACE INTO data_app_at(scope,app,since,active) VALUES(?1,?2,?3,?4)",
        params![scope, app.0.as_slice(), integer(at.0)?, active],
    )
    .map_err(sql)?;
    Ok(())
}

pub fn app_active(conn: &Connection, scope: i64, app: AppId) -> Result<Option<bool>, DataError> {
    app_active_before(conn, scope, app, None)
}

/// `None` when the app was not defined before `before`.
pub fn app_active_before(
    conn: &Connection,
    scope: i64,
    app: AppId,
    before: Option<Position>,
) -> Result<Option<bool>, DataError> {
    conn.query_row(
        "SELECT active FROM data_app_at WHERE scope=?1 AND app=?2 AND (?3 IS NULL OR since<?3) ORDER BY since DESC LIMIT 1",
        params![scope, app.0.as_slice(), position(before)?],
        |r| r.get(0),
    )
    .optional()
    .map_err(sql)
}

pub fn list_types(
    conn: &Connection,
    scope: i64,
    core: &dyn CoreCatalogue,
) -> Result<Vec<CompiledType>, DataError> {
    let mut stmt = conn
        .prepare("SELECT type FROM data_type WHERE scope=?1 ORDER BY type")
        .map_err(sql)?;
    let ids = stmt
        .query_map([scope], |r| r.get::<_, Vec<u8>>(0))
        .map_err(sql)?;
    let mut result = Vec::new();
    for type_id in ids {
        if let Some(ty) = current(conn, scope, TypeId(id(type_id.map_err(sql)?)?), core)? {
            result.push(ty);
        }
    }
    // The baseline catalogue is served without definition rows. The sole
    // reserved core type is note; bindings replace it once they exist.
    let note = TypeId::core("note");
    if !result.iter().any(|ty| ty.type_id == note)
        && let Some(ty) = current(conn, scope, note, core)?
    {
        result.push(ty);
    }
    Ok(result)
}
