use super::{CmpOp, Expr, Gap, QueryError, TypeSelect};
use crate::{
    CompiledType, CoreCatalogue, FieldKind, FieldPath, KeyRef, Scope, TypeId,
    store::{records, registry},
};
use rusqlite::Connection;
use serde_json::Value;

pub(crate) fn members(
    conn: &Connection,
    scope: i64,
    core: &dyn CoreCatalogue,
    select: &TypeSelect,
) -> Result<Vec<CompiledType>, QueryError> {
    let root = registry::current(conn, scope, select.id(), core)?.ok_or(QueryError::UnknownType)?;
    let ids = match select {
        TypeSelect::Exact(_) => vec![root.type_id],
        TypeSelect::Family(_) => registry::family_members(conn, scope, root.type_id)?,
    };
    ids.into_iter()
        .map(|id| registry::current(conn, scope, id, core)?.ok_or(QueryError::UnknownType))
        .collect()
}
pub(crate) fn kind<'a>(
    members: &'a [CompiledType],
    path: &FieldPath,
) -> Result<&'a FieldKind, QueryError> {
    let mut first: Option<&crate::FieldSpec> = None;
    for ty in members {
        let f = ty
            .field(path)
            .ok_or_else(|| QueryError::UnknownField(path.clone()))?;
        if let Some(old) = first
            && (old.kind != f.kind
                || old.declared_by != f.declared_by
                || old.meaning != f.meaning
                || old.unit != f.unit)
        {
            return Err(QueryError::TypeMismatch(path.clone()));
        }
        first = Some(f);
    }
    Ok(&first.expect("nonempty family").kind)
}
pub(crate) fn scalar(members: &[CompiledType], path: &FieldPath) -> Result<(), QueryError> {
    if matches!(
        kind(members, path)?,
        FieldKind::Atomic | FieldKind::Container | FieldKind::Reference(_)
    ) {
        return Err(QueryError::not_queryable(
            Some(path.clone()),
            "atomic, container or reference path is not queryable",
        ));
    }
    Ok(())
}
pub(crate) fn key(members: &[CompiledType], key: &KeyRef) -> Result<(), QueryError> {
    if let KeyRef::Field(path) = key {
        scalar(members, path)
    } else {
        Ok(())
    }
}
pub(crate) fn value(kind: &FieldKind, value: &Value, path: &FieldPath) -> Result<(), QueryError> {
    crate::value::check(value).map_err(|_| QueryError::TypeMismatch(path.clone()))?;
    if value.is_null() {
        return Ok(());
    }
    let valid = match kind {
        FieldKind::String => value.is_string(),
        FieldKind::Enum(choices) => value
            .as_str()
            .is_some_and(|s| choices.iter().any(|c| c == s)),
        FieldKind::Timestamp => value.is_i64(),
        FieldKind::Integer => value.is_i64(),
        FieldKind::Number => value.is_number(),
        FieldKind::Boolean => value.is_boolean(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(QueryError::TypeMismatch(path.clone()))
    }
}
/// Indexed existence probes, not a scan of target queues or records. Targets
/// are declared by readable source contracts and resolved only in readable
/// same-base scopes by the caller. Return no private backlog details.
pub(crate) fn target_gap(
    conn: &Connection,
    sid: i64,
    core: &dyn CoreCatalogue,
    spec: &crate::model::RefSpec,
) -> Result<Option<Gap>, QueryError> {
    let mut types = spec.targets.clone();
    if spec.family {
        for target in &spec.targets {
            types.extend(registry::family_members(conn, sid, *target)?);
        }
    }
    types.sort();
    types.dedup();
    let unknown: bool=conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_parked INDEXED BY data_parked_type WHERE scope=?1 AND type IS NULL)",
        [sid],|r|r.get(0)).map_err(|e|QueryError::Storage(e.to_string()))?;
    if unknown {
        return Ok(Some(Gap::WaitingScope));
    }
    if spec.family {
        let unresolved: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM data_parked INDEXED BY data_parked_unresolved WHERE scope=?1 AND unresolved_type=1)",
            [sid], |r|r.get(0)).map_err(|e| QueryError::Storage(e.to_string()))?;
        if unresolved {
            return Ok(Some(Gap::WaitingScope));
        }
    }
    for target in types {
        // Core is part of the signature so callers use their authoritative
        // catalogue consistently; no unknown definition must be loaded here.
        let _ = core;
        let waiting:bool=conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM data_parked INDEXED BY data_parked_type WHERE scope=?1 AND type=?2)",
            rusqlite::params![sid,target.0.as_slice()],|r|r.get(0))
            .map_err(|e|QueryError::Storage(e.to_string()))?;
        if waiting {
            return Ok(Some(Gap::WaitingScope));
        }
    }
    Ok(None)
}

pub(crate) fn expression(
    conn: &Connection,
    scope_value: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    members: &[CompiledType],
    expr: &Expr,
    in_via: bool,
) -> Result<Vec<Gap>, QueryError> {
    let mut gaps = vec![];
    match expr {
        Expr::Cmp { path, op, value: v } => {
            let k = kind(members, path)?;
            scalar(members, path)?;
            value(k, v, path)?;
            if v.is_null() && !matches!(op, CmpOp::Eq | CmpOp::Ne) {
                return Err(QueryError::TypeMismatch(path.clone()));
            }
        }
        Expr::In { path, values } => {
            if values.len() > 64 {
                return Err(QueryError::not_queryable(
                    Some(path.clone()),
                    "IN accepts at most 64 values",
                ));
            }
            let k = kind(members, path)?;
            scalar(members, path)?;
            for v in values {
                value(k, v, path)?
            }
        }
        Expr::IsNull(path) => {
            if matches!(
                kind(members, path)?,
                FieldKind::Atomic | FieldKind::Container
            ) {
                return Err(QueryError::not_queryable(
                    Some(path.clone()),
                    "atomic or container path is not queryable",
                ));
            }
        }
        Expr::RefersTo { path, .. } => {
            if !matches!(kind(members, path)?, FieldKind::Reference(_)) {
                return Err(QueryError::TypeMismatch(path.clone()));
            }
        }
        Expr::Via { path, filter } => {
            if in_via || contains_via(filter) {
                return Err(QueryError::not_queryable(Some(path.clone()), "nested Via"));
            }
            let FieldKind::Reference(spec) = kind(members, path)? else {
                return Err(QueryError::TypeMismatch(path.clone()));
            };
            for target in &spec.targets {
                let mut found = false;
                for audience in reads.iter().filter(|s| s.base == scope_value.base) {
                    if let Some(s) = records::lookup_scope(conn, *audience)? {
                        if let Some(gap) = target_gap(conn, s, core, spec)? {
                            gaps.push(gap);
                        }
                        let select = if spec.family {
                            TypeSelect::Family(*target)
                        } else {
                            TypeSelect::Exact(*target)
                        };
                        match self::members(conn, s, core, &select) {
                            Ok(types) => {
                                found = true;
                                gaps.extend(expression(
                                    conn, *audience, reads, core, &types, filter, true,
                                )?)
                            }
                            Err(QueryError::UnknownType) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
                if !found {
                    gaps.push(Gap::UnsupportedType(*target));
                }
            }
        }
        Expr::And(parts) | Expr::Or(parts) => {
            for e in parts {
                gaps.extend(expression(
                    conn,
                    scope_value,
                    reads,
                    core,
                    members,
                    e,
                    in_via,
                )?)
            }
        }
        Expr::Not(e) => gaps.extend(expression(
            conn,
            scope_value,
            reads,
            core,
            members,
            e,
            in_via,
        )?),
    }
    let mut unique = Vec::new();
    for gap in gaps {
        if !unique.contains(&gap) {
            unique.push(gap)
        }
    }
    Ok(unique)
}
fn contains_via(expr: &Expr) -> bool {
    match expr {
        Expr::Via { .. } => true,
        Expr::And(parts) | Expr::Or(parts) => parts.iter().any(contains_via),
        Expr::Not(inner) => contains_via(inner),
        _ => false,
    }
}
pub(crate) fn reference_targets(kind: &FieldKind) -> Vec<TypeId> {
    match kind {
        FieldKind::Reference(s) => s.targets.clone(),
        _ => vec![],
    }
}
