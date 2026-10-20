//! Content migration after a breaking revision.
//!
//! A breaking revision is accepted defined but inactive. A person's device
//! then orders a `Transition` to it, which makes it the only permitted
//! revision: records still on an older revision stay readable under their
//! own revision, but refuse changes until a `Migrate` moves them to the new
//! one. A revision may declare its migration from earlier revisions as
//! [`Migration`] steps (`evolution.migration_ops`); [`plan`] turns them into
//! `Migrate` operations a batch at a time, and lists records the steps
//! cannot migrate in `Plan::needs_manual`. A hand-written `Migrate` can fix
//! one only by adding ordinary Direct-field edits beyond the declared changes
//! (without overlapping their paths). Declared changes must remain exact;
//! if one is invalid on its own path, or an untouched ActionOnly/Derived field
//! needs correction, a `Migrate` cannot fix it: delete the record or define
//! and transition to a revision with suitable rules/steps. Progress is each
//! record's `revision`, so planning resumes wherever ordered migrations
//! stopped. Steps that reach action-only or derived fields make a revision a
//! rule change, which only a person's own device makes.
//!
//! Records of a specialising type keep their own type's revisions; a
//! transition of the base type does not migrate them.
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CoreCatalogue, DataError, FieldPath, RecordId, RevisionId, Scope, TypeId,
    mutation::{
        hex,
        ops::{FieldChange, Operation},
    },
    store::{corrupt, id, integer, records, registry, sql},
    validate_cache,
};

/// One declarative migration step. Steps apply in order to the record's
/// document; a step whose source value is absent changes nothing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Migration {
    /// Moves the value at `from` to `to`.
    RenameField { from: FieldPath, to: FieldPath },
    /// Sets `path` to `value`.
    SetConstant { path: FieldPath, value: Value },
    /// Removes `path`.
    DropField { path: FieldPath },
    /// Replaces a string value at `path` found in `map` by its mapped value.
    MapEnum {
        path: FieldPath,
        map: BTreeMap<String, String>,
    },
}

impl Migration {
    /// The paths this step may change.
    pub fn paths(&self) -> Vec<&FieldPath> {
        match self {
            Self::RenameField { from, to } => vec![from, to],
            Self::SetConstant { path, .. }
            | Self::DropField { path }
            | Self::MapEnum { path, .. } => {
                vec![path]
            }
        }
    }
}

/// Up to a batch of migrations, and the records the declared steps cannot
/// migrate (they cannot apply, or leave the record invalid under the new
/// revision). A hand-written `Migrate` can repair only ordinary Direct fields
/// outside computed declared changes' paths; it cannot alter a declared result
/// or an untouched ActionOnly/Derived field. If those are the problem, delete the
/// record or define and transition to another revision.
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    pub ops: Vec<Operation>,
    pub needs_manual: Vec<RecordId>,
}

/// The field changes `steps` make to `doc`: the final value at each
/// outermost path a step touched, in path order, leaving out paths whose
/// value ends unchanged. Every replica computes the same changes from the
/// same document. A step that would set a value under something that is not
/// an object cannot apply, and nothing is changed.
pub fn changes(steps: &[Migration], doc: &Value) -> Result<Vec<FieldChange>, DataError> {
    let mut post = doc.clone();
    let mut touched = BTreeSet::new();
    for step in steps {
        match step {
            Migration::RenameField { from, to } => {
                if let Some(value) = from.get(&post).cloned() {
                    from.remove(&mut post);
                    to.set(&mut post, value)?;
                    touched.extend([from.clone(), to.clone()]);
                }
            }
            Migration::SetConstant { path, value } => {
                path.set(&mut post, value.clone())?;
                touched.insert(path.clone());
            }
            Migration::DropField { path } => {
                if path.get(&post).is_some() {
                    path.remove(&mut post);
                    touched.insert(path.clone());
                }
            }
            Migration::MapEnum { path, map } => {
                let mapped = path
                    .get(&post)
                    .and_then(Value::as_str)
                    .and_then(|old| map.get(old))
                    .cloned();
                if let Some(new) = mapped {
                    path.set(&mut post, Value::String(new))?;
                    touched.insert(path.clone());
                }
            }
        }
    }
    let mut out: Vec<FieldChange> = Vec::new();
    let mut outer: Option<FieldPath> = None;
    // Sorted paths place every extension directly after its prefix.
    for path in touched {
        if outer.as_ref().is_some_and(|o| o.is_prefix_of(&path)) {
            continue;
        }
        let value = path.get(&post).cloned();
        if value.as_ref() != path.get(doc) {
            out.push(FieldChange {
                path: path.clone(),
                value,
            });
        }
        outer = Some(path);
    }
    Ok(out)
}

/// Up to `batch` `Migrate` operations, in record order, for records of
/// exactly `type_id` whose accepted revision is no longer permitted, using
/// the migration `to` declares, and every record passed over on the way that
/// the declared steps cannot migrate. A `needs_manual` record is fixable by
/// hand only when extra Direct-field changes outside computed declared
/// changes' paths make it valid; otherwise delete it or define and transition
/// to a revised migration/rule set. `to` must already be permitted (after a
/// transition). Records with local pending work are left for a later call,
/// so calling again before earlier migrations are ordered does not repeat
/// them.
///
/// Cost: one seek per older revision plus the records returned, those with
/// pending work, and those needing a hand-written migration, which every
/// call examines again until they are migrated; never a scan of migrated
/// records.
pub fn plan(
    conn: &Connection,
    scope: Scope,
    core: &dyn CoreCatalogue,
    type_id: TypeId,
    to: RevisionId,
    batch: usize,
) -> Result<Plan, DataError> {
    let mut plan = Plan {
        ops: Vec::new(),
        needs_manual: Vec::new(),
    };
    let Some(sid) = records::lookup_scope(conn, scope)? else {
        return Ok(plan);
    };
    let target = registry::compiled(conn, sid, to)?
        .filter(|ct| ct.type_id == type_id)
        .ok_or_else(|| {
            DataError::Definition(format!("{} is not a revision of this type", hex(&to.0)))
        })?;
    let permitted = registry::permitted(conn, sid, type_id, core)?;
    if !permitted.contains(&to) {
        return Err(DataError::Definition(format!(
            "transition the type to {} before migrating to it",
            hex(&to.0)
        )));
    }
    let steps = registry::migration_ops(conn, sid, to)?;
    let validator = validate_cache::shared().get(&target)?;
    let mut stmt = conn
        .prepare_cached(
            "SELECT id,record,accepted FROM data_record WHERE scope=?1 AND type=?2 AND revision=?3
             AND accepted IS NOT NULL AND pending=0 AND id>?4 ORDER BY id LIMIT ?5",
        )
        .map_err(sql)?;
    for from in registry::revisions(conn, sid, type_id)? {
        if permitted.contains(&from) {
            continue;
        }
        let mut after = 0i64;
        while plan.ops.len() < batch {
            let rows = stmt
                .query_map(
                    params![
                        sid,
                        type_id.0.as_slice(),
                        from.0.as_slice(),
                        after,
                        integer((batch - plan.ops.len()) as u64)?
                    ],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    },
                )
                .map_err(sql)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql)?;
            let Some((last, _, _)) = rows.last() else {
                break;
            };
            after = *last;
            for (_, record, accepted) in rows {
                let record = RecordId(id(record)?);
                let doc: Value = serde_json::from_str(&accepted).map_err(corrupt)?;
                match migrated(&steps, &doc) {
                    Some((changes, post)) if validator.validate(&post).is_ok() => {
                        plan.ops.push(Operation::Migrate {
                            record,
                            from,
                            to,
                            changes,
                        })
                    }
                    _ => plan.needs_manual.push(record),
                }
            }
        }
        if plan.ops.len() >= batch {
            break;
        }
    }
    Ok(plan)
}

/// The declared changes for `doc` and the document they produce, if the
/// steps apply to it.
fn migrated(steps: &[Migration], doc: &Value) -> Option<(Vec<FieldChange>, Value)> {
    let changes = changes(steps, doc).ok()?;
    let mut post = doc.clone();
    for change in &changes {
        match &change.value {
            Some(value) => change.path.set(&mut post, value.clone()).ok()?,
            None => change.path.remove(&mut post),
        }
    }
    Some((changes, post))
}
