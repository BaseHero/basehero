//! Field-targeted record mutations: local pending work, ordered
//! materialization, field history and Undo.
pub mod apply;
mod checks;
mod define;
pub(crate) use define::{effective_change, needs_device};
mod eval;
pub mod history;
pub mod ops;
pub mod pending;
pub mod undo;

use rusqlite::{Connection, Transaction};

use crate::{
    CompiledType, CoreCatalogue, DataError, FieldPath, Position, RejectCode, Rejection, RevisionId,
    TypeId, catalogue, index,
    store::{records::RecordRow, registry},
};

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").expect("writing to String cannot fail");
        out
    })
}

pub(crate) fn rejection(
    code: RejectCode,
    path: Option<FieldPath>,
    detail: impl Into<String>,
) -> Rejection {
    Rejection {
        code,
        path,
        detail: detail.into(),
    }
}

/// Whether `type_id`'s revisions come from executables rather than this log:
/// only the implicit Note baseline's. An unknown revision of such a type may
/// ship in a newer executable, so ordered work waits for it. Every other core
/// type is bound by an ordered `BindCore`, so its revisions, like an app's,
/// are data in the audience's own log.
pub(crate) fn implicit_core(type_id: TypeId) -> bool {
    type_id == TypeId::core("note")
}

/// A revision accepted in this scope before `before` (`None`: ever), or a
/// shipped core contract.
pub(crate) fn definition_at(
    conn: &Connection,
    sid: i64,
    revision: RevisionId,
    core: &dyn CoreCatalogue,
    before: Option<Position>,
) -> Result<Option<CompiledType>, DataError> {
    if let Some(found) = registry::compiled_before(conn, sid, revision, before)? {
        return Ok(Some(found));
    }
    Ok(catalogue::core_types()
        .iter()
        .filter(|ct| ct.revision == revision)
        .find_map(|ct| core.core_type(ct.type_id))
        .filter(|ct| ct.revision == revision))
}

/// Derived state follows every committed change to a record row.
pub(crate) fn hooks(
    tx: &Transaction<'_>,
    row: &RecordRow,
    ct: &CompiledType,
) -> Result<(), DataError> {
    index::on_record_changed(tx, row, ct)?;
    apply::text_hook(tx, row, ct)
}
