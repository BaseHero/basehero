//! Field, revision and constraint checks used by the record rules.
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::{Map, Value};

use super::{
    apply::Key,
    eval::{Change, Ctx, Mode, Park, State, Step, Stop, Verdict, no, wait},
    hex, implicit_core,
    ops::FieldChange,
};
use crate::{
    AppId, CompiledType, DataError, FieldKind, FieldPath, KeyRef, MutationId, RecordId, RejectCode,
    RevisionId, UniqueDecl, Wait, WritePolicy,
    index::unique::{self, UniqueCheck},
    store::{records::RecordRow, sql},
    validate_cache,
};

pub(crate) fn present<'s>(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &'s State,
) -> Step<(&'s RecordRow, &'s Value)> {
    if !state.exists {
        return ctx.missing_record(record);
    }
    match (&state.row, &state.doc) {
        (Some(row), Some(doc)) => Ok((row, doc)),
        _ => no(RejectCode::Deleted, None, "the record is deleted"),
    }
}

pub(crate) fn current_of(ctx: &Ctx<'_, '_>, row: &RecordRow) -> Step<CompiledType> {
    match ctx.current(row.type_id)? {
        Some(ct) => Ok(ct),
        None => ctx.missing_definition(
            Some(row.type_id),
            row.revision,
            implicit_core(row.type_id),
            Key::Record(row.record),
        ),
    }
}

/// A record on a revision a transition retired refuses changes until it is migrated.
pub(crate) fn migrated(ctx: &Ctx<'_, '_>, row: &RecordRow) -> Step<()> {
    if ctx.permitted(row.type_id)?.contains(&row.revision) {
        return Ok(());
    }
    no(
        RejectCode::RevisionNotPermitted,
        None,
        format!(
            "the record is on revision {}, which is no longer permitted; migrate it first",
            hex(&row.revision.0)
        ),
    )
}

pub(crate) fn app_active(ctx: &Ctx<'_, '_>, app: Option<AppId>) -> Step<()> {
    let Some(app) = app else { return Ok(()) };
    if ctx.app_active(app)? == Some(true) {
        return Ok(());
    }
    no(
        RejectCode::AppInactive,
        None,
        format!("app {} is not active in this audience", hex(&app.0)),
    )
}

/// The writer's contract: `None` when it is the current revision. An older
/// permitted revision of the type, or (for edits) a permitted revision of an
/// ancestor, may also write, limited to the fields it declares.
pub(crate) fn writer(
    ctx: &Ctx<'_, '_>,
    ct: &CompiledType,
    revision: RevisionId,
    allow_ancestor: bool,
    park: Key,
) -> Step<Option<CompiledType>> {
    if revision == ct.revision {
        return Ok(None);
    }
    let Some(writer) = ctx.definition(revision)? else {
        // An unknown revision may belong to a core contract when the writer
        // could be any member of a lineage that includes one.
        let core = if allow_ancestor {
            ct.lineage.iter().any(|(t, _)| implicit_core(*t))
        } else {
            implicit_core(ct.type_id)
        };
        return ctx.missing_definition(None, revision, core, park);
    };
    let related = writer.type_id == ct.type_id
        || (allow_ancestor
            && ct
                .lineage
                .iter()
                .skip(1)
                .any(|(ancestor, _)| *ancestor == writer.type_id));
    if !related || !ctx.permitted(writer.type_id)?.contains(&revision) {
        return no(
            RejectCode::RevisionNotPermitted,
            None,
            format!(
                "revision {} is not permitted for this record",
                hex(&revision.0)
            ),
        );
    }
    Ok(Some(writer))
}

pub(crate) fn known(writer: Option<&CompiledType>, path: &FieldPath) -> Step<()> {
    if writer.is_none_or(|w| w.field(path).is_some()) {
        return Ok(());
    }
    no(
        RejectCode::UnknownField,
        Some(path),
        "the writer's revision does not declare this field",
    )
}

/// Write policy always comes from the current type, whatever the writer used.
pub(crate) fn writable(ct: &CompiledType, path: &FieldPath, action: bool) -> Step<()> {
    let Some(field) = ct.field(path) else {
        return no(RejectCode::UnknownField, Some(path), "undeclared field");
    };
    match field.write {
        WritePolicy::Direct => Ok(()),
        WritePolicy::ActionOnly if action => Ok(()),
        WritePolicy::ActionOnly => no(
            RejectCode::ActionOnly,
            Some(path),
            "changed only by a declared app action",
        ),
        WritePolicy::Derived if ct.builtin.is_some() => no(
            RejectCode::DerivedField,
            Some(path),
            "derived from the note body; use the note body edit through the note writer",
        ),
        WritePolicy::Derived => no(
            RejectCode::DerivedField,
            Some(path),
            "derived by the core; not directly writable",
        ),
    }
}

/// Sorted paths place every extension directly after its prefix.
pub(crate) fn overlap(changes: &[FieldChange]) -> Step<()> {
    let mut paths: Vec<_> = changes.iter().map(|c| &c.path).collect();
    paths.sort();
    for pair in paths.windows(2) {
        if pair[0].is_prefix_of(pair[1]) {
            return no(
                RejectCode::Overlap,
                Some(pair[1]),
                format!("overlaps {}", pair[0].as_pointer()),
            );
        }
    }
    Ok(())
}

/// Declared leaf values in a document. Strict mode rejects undeclared keys;
/// otherwise they are skipped, never touched.
pub(crate) fn leaves(
    doc: &Value,
    ct: &CompiledType,
    strict: bool,
) -> Step<Vec<(FieldPath, Value)>> {
    let Some(object) = doc.as_object() else {
        return no(RejectCode::Schema, None, "a record is a JSON object");
    };
    let mut out = Vec::new();
    walk(object, "", ct, strict, &mut out)?;
    Ok(out)
}

pub(crate) fn walk(
    object: &Map<String, Value>,
    prefix: &str,
    ct: &CompiledType,
    strict: bool,
    out: &mut Vec<(FieldPath, Value)>,
) -> Step<()> {
    for (key, value) in object {
        let pointer = format!("{prefix}/{}", key.replace('~', "~0").replace('/', "~1"));
        let field = FieldPath::parse(&pointer)
            .ok()
            .and_then(|path| ct.field(&path).map(|field| (path, field)));
        match field {
            Some((_, field)) if field.kind == FieldKind::Container && value.is_object() => {
                walk(
                    value.as_object().expect("checked object"),
                    &pointer,
                    ct,
                    strict,
                    out,
                )?;
            }
            Some((path, _)) => out.push((path, value.clone())),
            None if strict => {
                return no(
                    RejectCode::UnknownField,
                    FieldPath::parse(&pointer).ok().as_ref(),
                    format!("undeclared field {pointer}"),
                );
            }
            None => {}
        }
    }
    Ok(())
}

pub(crate) fn apply_changes(mut doc: Value, changes: &[FieldChange]) -> Step<(Value, Vec<Change>)> {
    let mut applied = Vec::with_capacity(changes.len());
    for change in changes {
        let old = change.path.get(&doc).cloned();
        match &change.value {
            Some(value) => {
                if change.path.set(&mut doc, value.clone()).is_err() {
                    return no(
                        RejectCode::Schema,
                        Some(&change.path),
                        "a parent of this field is not an object",
                    );
                }
            }
            None => change.path.remove(&mut doc),
        }
        applied.push(Change {
            path: change.path.clone(),
            old,
            new: change.value.clone(),
        });
    }
    Ok((doc, applied))
}

pub(crate) fn validate(ct: &CompiledType, doc: &Value) -> Step<()> {
    // Builtin projections are validated by their trusted adapter. Substitute
    // a fixed valid title for ordered validation: its replica-local bytes and
    // extraction timing must never affect size, work or schema verdicts.
    let mut ordered;
    let doc = if ct.builtin == Some(crate::Builtin::Note) {
        ordered = doc.clone();
        if let Some(object) = ordered.as_object_mut() {
            object.insert("title".into(), Value::String(String::new()));
        }
        &ordered
    } else {
        doc
    };
    for field in &ct.fields {
        if matches!(field.kind, FieldKind::Reference(_))
            && let Some(raw) = field.path.get(doc).filter(|v| !v.is_null())
            && let Err(error) = serde_json::from_value::<crate::RecordRef>(raw.clone())
        {
            return no(RejectCode::Schema, Some(&field.path), error.to_string());
        }
    }
    match validate_cache::shared().get(ct)?.validate(doc) {
        Ok(()) => Ok(()),
        Err(rejection) => Err(Stop::Verdict(Box::new(Verdict::Reject(rejection)))),
    }
}

/// The unique declarations whose keys `touched` changes (all of them when
/// `None`: a create or restore).
pub(crate) fn touched_uniques<'c>(
    ct: &'c CompiledType,
    touched: Option<&[FieldChange]>,
) -> Vec<&'c UniqueDecl> {
    ct.uniques
        .iter()
        .filter(|decl| {
            touched.is_none_or(|changes| {
                decl.keys.iter().any(|key| match key {
                    KeyRef::Field(path) => changes
                        .iter()
                        .any(|c| c.path.is_prefix_of(path) || path.is_prefix_of(&c.path)),
                    KeyRef::Changed => false,
                })
            })
        })
        .collect()
}

/// Uniqueness is checked only for declarations whose keys the operation
/// touches (all of them for a create or restore), so duplicates that predate
/// a later-added constraint stay valid while new ones are refused.
pub(crate) fn unique(
    ctx: &Ctx<'_, '_>,
    ct: &CompiledType,
    rec: Option<i64>,
    post: &Value,
    touched: Option<&[FieldChange]>,
) -> Step<()> {
    if ctx.mode == Mode::Overlay {
        return Ok(());
    }
    let relevant = touched_uniques(ct, touched);
    for decl in &relevant {
        let decls = std::slice::from_ref(*decl);
        let verdict = match unique::check_decls(ctx.tx, ctx.sid, decls, rec, post)? {
            UniqueCheck::Unknown if ctx.ordered() => {
                let declaring = relevant
                    .iter()
                    .map(|d| d.declared_by)
                    .max_by_key(|family| {
                        ct.lineage
                            .iter()
                            .position(|(t, _)| t == family)
                            .unwrap_or(0)
                    })
                    .unwrap_or(ct.type_id);
                return wait(
                    Wait::UniquenessUnknown(ctx.scope),
                    Park {
                        key: Key::Type(declaring),
                        holds: true,
                    },
                );
            }
            UniqueCheck::Unknown => {
                ctx.waiting.set(true);
                unique::check_local(ctx.tx, ctx.sid, decls, rec, post)?
            }
            UniqueCheck::Free if ctx.mode == Mode::Submit => {
                unique::check_local(ctx.tx, ctx.sid, decls, rec, post)?
            }
            other => other,
        };
        if let UniqueCheck::Taken(holder) = verdict {
            let path = decl.keys.iter().find_map(|key| match key {
                KeyRef::Field(path) => Some(path),
                KeyRef::Changed => None,
            });
            return no(
                RejectCode::Unique,
                path,
                format!("unique {} is held by record {}", decl.name, hex(&holder.0)),
            );
        }
    }
    Ok(())
}

/// The app that owns an action: the most ancestral lineage member declaring it.
pub(crate) fn declaring_app(
    ctx: &Ctx<'_, '_>,
    ct: &CompiledType,
    action: &str,
) -> Step<Option<AppId>> {
    for (type_id, revision) in ct.lineage.iter().rev() {
        let contract = if *revision == ct.revision {
            Some(ct.clone())
        } else {
            ctx.definition(*revision)?
        };
        if let Some(contract) = contract
            && contract.type_id == *type_id
            && contract.actions.iter().any(|a| a.name == action)
        {
            return Ok(contract.app);
        }
    }
    Ok(None)
}

/// The mutation that last changed `path` (`""`: the record's existence).
pub(crate) fn clock(
    tx: &Transaction<'_>,
    rec: i64,
    path: &str,
) -> Result<Option<MutationId>, DataError> {
    let found: Option<Vec<u8>> = tx
        .query_row(
            "SELECT mutation FROM data_field_clock WHERE rec=?1 AND path=?2",
            params![rec, path],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    found
        .map(|bytes| crate::store::id(bytes).map(MutationId))
        .transpose()
}
