use super::{CmpOp, Expr, QueryError, SortKey, TypeSelect};
use crate::{CompiledType, CoreCatalogue, FieldPath, KeyRef, Scope, TypeId, index, store::records};
use rusqlite::{Connection, params, types::Value as Sql};
use serde_json::Value;
/// Shared allowance for fallback sorting and direct-text FTS candidates.
pub(crate) const FALLBACK_SCAN_ROWS: u64 = 2000;
/// Filter-only consumers (aggregates and reference probes) impose no page order.
#[derive(Clone, Copy)]
pub(super) enum Purpose<'a> {
    Page(&'a [SortKey]),
    Filter,
}
impl<'a> Purpose<'a> {
    fn sort(self) -> &'a [SortKey] {
        match self {
            Self::Page(sort) => sort,
            Self::Filter => &[],
        }
    }
}
pub(crate) struct Plan {
    /// The page SELECT: the row columns, cursor keys and order suffix over
    /// `body`.
    pub sql: String,
    /// `FROM ... WHERE ...`, shared by pages and aggregates. The type set and
    /// any index range follow it in `seek_terms`.
    pub body: String,
    pub args: Vec<Sql>,
    /// Cursor keys in page order: exactly the requested sort, or the concrete
    /// type for an unsorted family. Index choice never adds semantic keys.
    pub sort_expr: Vec<String>,
    pub sort_desc: Vec<bool>,
    /// The filter's bounds on the first cursor key, an index slot, kept out of
    /// `body` so a page can let its cursor replace the bound it travels from.
    pub range: Vec<(&'static str, Sql)>,
    /// The selected types.
    pub types: Vec<TypeId>,
    pub id_expr: &'static str,
    pub order_suffix: Vec<String>,
    pub id_desc: bool,
    pub cursor_shape: String,
    pub consulted: Vec<i64>,
}
pub(super) fn bind(v: &Value) -> Sql {
    index::encode_key(v)
}
pub(crate) fn path_sql(alias: &str, path: &FieldPath) -> String {
    let pointer = path.as_pointer();
    let json_path = pointer
        .split('/')
        .skip(1)
        .map(|segment| {
            serde_json::to_string(&segment.replace("~1", "/").replace("~0", "~"))
                .expect("path segment")
        })
        .collect::<Vec<_>>()
        .join(".");
    format!(
        "json_extract(coalesce({alias}.doc,{alias}.accepted), '$.{}')",
        json_path.replace('\'', "''")
    )
}
fn key_sql(alias: &str, key: &KeyRef) -> String {
    match key {
        KeyRef::Field(p) => path_sql(alias, p),
        KeyRef::Changed => format!("{alias}.changed"),
    }
}
fn eq_filters(e: Option<&Expr>, out: &mut Vec<(KeyRef, Sql)>) {
    match e {
        Some(Expr::Cmp {
            path,
            op: CmpOp::Eq,
            value,
        }) if !value.is_null() => out.push((KeyRef::Field(path.clone()), bind(value))),
        Some(Expr::And(es)) => {
            for e in es {
                eq_filters(Some(e), out)
            }
        }
        _ => {}
    }
}
fn range_cmp(e: &Expr) -> Option<(KeyRef, &'static str, Sql)> {
    match e {
        Expr::Cmp { path, op, value }
            if !value.is_null() && matches!(op, CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge) =>
        {
            Some((
                KeyRef::Field(path.clone()),
                match op {
                    CmpOp::Lt => "<",
                    CmpOp::Le => "<=",
                    CmpOp::Gt => ">",
                    CmpOp::Ge => ">=",
                    _ => unreachable!(),
                },
                bind(value),
            ))
        }
        _ => None,
    }
}
pub(super) fn range_filter(e: Option<&Expr>) -> Option<(KeyRef, &'static str, Sql)> {
    match e {
        Some(Expr::And(parts)) => parts.iter().find_map(|e| range_filter(Some(e))),
        Some(e) => range_cmp(e),
        None => None,
    }
}
// Every range on `key` in the filter's top-level conjunction, so a seek gets
// both ends of a two-sided range.
fn ranges_on(e: Option<&Expr>, key: &KeyRef, out: &mut Vec<(&'static str, Sql)>) {
    match e {
        Some(Expr::And(parts)) => {
            for part in parts {
                ranges_on(Some(part), key, out)
            }
        }
        Some(e) => {
            if let Some((k, op, value)) = range_cmp(e)
                && k == *key
            {
                out.push((op, value))
            }
        }
        None => {}
    }
}
fn candidates(
    conn: &Connection,
    scope: i64,
    family: TypeId,
) -> Result<Vec<index::IndexState>, QueryError> {
    let mut st=conn.prepare("SELECT id FROM data_index WHERE scope=?1 AND family=?2 AND state!='retiring' ORDER BY id").map_err(|e|QueryError::Storage(e.to_string()))?;
    let ids = st
        .query_map(params![scope, family.0.as_slice()], |r| r.get::<_, i64>(0))
        .map_err(|e| QueryError::Storage(e.to_string()))?;
    ids.map(|r| {
        Ok(index::state(
            conn,
            r.map_err(|e| QueryError::Storage(e.to_string()))?,
        )?)
    })
    .collect()
}
pub(super) fn choose(
    conn: &Connection,
    scope: i64,
    members: &[CompiledType],
    select: &TypeSelect,
    filter: Option<&Expr>,
    purpose: Purpose<'_>,
) -> Result<(Option<index::IndexState>, Vec<Sql>, usize), QueryError> {
    let sort = purpose.sort();
    // The entry index orders a family by keys then record, not concrete type.
    if matches!(purpose, Purpose::Page([])) && matches!(select, TypeSelect::Family(_)) {
        return Ok((None, vec![], 0));
    }
    let mut equal = vec![];
    eq_filters(filter, &mut equal);
    let range = range_filter(filter);
    let mut best = None;
    let mut pending = None;
    // Match index maintenance's declaring families. Ancestors also admit
    // scope-local indexes.
    let mut families: Vec<TypeId> = match select {
        TypeSelect::Exact(_) => members[0].lineage.iter().map(|(id, _)| *id).collect(),
        TypeSelect::Family(id) => vec![*id],
    };
    for ct in members {
        for declared in ct
            .indexes
            .iter()
            .map(|i| i.declared_by)
            .chain(ct.uniques.iter().map(|u| u.declared_by))
        {
            if matches!(select, TypeSelect::Exact(_)) || declared == select.id() {
                families.push(declared)
            }
        }
    }
    families.sort_unstable();
    families.dedup();
    for family in families {
        for ix in candidates(conn, scope, family)? {
            let mut prefix = vec![];
            for k in &ix.keys {
                if let Some((_, v)) = equal.iter().find(|(ek, _)| ek == k) {
                    prefix.push(v.clone())
                } else {
                    break;
                }
            }
            // A page must consume every nonconstant declared key, even when
            // unsorted: unused composite fields cannot precede the logical ID.
            // Aggregates and reference probes only need a selective filter.
            let sort_fits = matches!(purpose, Purpose::Filter)
                || (prefix.len() + sort.len() == ix.keys.len()
                    && sort
                        .iter()
                        .enumerate()
                        .all(|(i, s)| ix.keys[prefix.len() + i] == s.key));
            let range_matches = sort.is_empty()
                && range
                    .as_ref()
                    .is_some_and(|(key, _, _)| ix.keys.get(prefix.len()) == Some(key));
            let useful = sort_fits && (!sort.is_empty() || !prefix.is_empty() || range_matches);
            if useful {
                if ix.state == "ready" {
                    if best
                        .as_ref()
                        .is_none_or(|(_, p): &(index::IndexState, Vec<Sql>)| p.len() < prefix.len())
                    {
                        best = Some((ix, prefix));
                    }
                } else {
                    pending = Some(ix);
                }
            }
        }
    }
    if let Some((ix, prefix)) = best {
        return Ok((Some(ix), prefix.clone(), prefix.len()));
    }
    // Unsorted fallback and filter-only work use the scoped record path under
    // the VM budget; only explicit sorts need the bounded sorting fallback.
    if sort.is_empty() {
        return Ok((None, vec![], 0));
    }
    let types: Vec<_> = members.iter().map(|t| t.type_id).collect();
    let count = records::count_type_upto(conn, scope, &types, FALLBACK_SCAN_ROWS)?;
    if count > FALLBACK_SCAN_ROWS {
        if let Some(ix) = pending {
            let name: String = conn
                .query_row("SELECT name FROM data_index WHERE id=?1", [ix.id], |r| {
                    r.get(0)
                })
                .map_err(|e| QueryError::Storage(e.to_string()))?;
            return Err(QueryError::IndexBuilding {
                index: name,
                done: ix.built,
                total: ix.estimate.unwrap_or(0),
            });
        }
        return Err(QueryError::TooCostly { work: count });
    }
    Ok((None, vec![], 0))
}
// Other audiences whose coverage bounds a filter's answer. RefersTo reads only
// the source scope's own reference rows. A Via target may live in any readable
// audience; one that is still incomplete may not yet hold the target type's
// definition, so it counts even where that type is unknown.
fn consulted_scopes(
    conn: &Connection,
    source: Scope,
    reads: &[Scope],
    filter: Option<&Expr>,
) -> Result<Vec<i64>, QueryError> {
    fn walk(
        conn: &Connection,
        source: Scope,
        reads: &[Scope],
        expr: &Expr,
        out: &mut Vec<i64>,
    ) -> Result<(), QueryError> {
        match expr {
            Expr::Via { .. } => {
                for readable in reads.iter().filter(|s| s.base == source.base) {
                    if let Some(id) = records::lookup_scope(conn, *readable)? {
                        out.push(id)
                    }
                }
            }
            Expr::And(parts) | Expr::Or(parts) => {
                for part in parts {
                    walk(conn, source, reads, part, out)?
                }
            }
            Expr::Not(part) => walk(conn, source, reads, part, out)?,
            _ => {}
        }
        Ok(())
    }
    let mut ids = vec![];
    if let Some(expr) = filter {
        walk(conn, source, reads, expr, &mut ids)?
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn compile(
    conn: &Connection,
    scope: i64,
    scope_value: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    members: &[CompiledType],
    select: &TypeSelect,
    filter: Option<&Expr>,
    purpose: Purpose<'_>,
) -> Result<Plan, QueryError> {
    let sort = purpose.sort();
    let consulted = consulted_scopes(conn, scope_value, reads, filter)?;
    let mixed = sort.iter().any(|s| s.desc != sort[0].desc);
    if mixed {
        let types: Vec<_> = members.iter().map(|t| t.type_id).collect();
        if records::count_type_upto(conn, scope, &types, FALLBACK_SCAN_ROWS)? > FALLBACK_SCAN_ROWS {
            return Err(QueryError::not_queryable(
                None,
                "mixed-direction sort requires a bounded scan",
            ));
        }
    }
    let reverse =
        super::exec::reverse_source(conn, scope, scope_value, reads, core, members, filter)?;
    let (ix, prefix, prefix_len) = if mixed || reverse.is_some() {
        (None, vec![], 0)
    } else {
        choose(conn, scope, members, select, filter, purpose)?
    };
    let mut args = vec![];
    let mut body = String::new();
    let mut sort_expr = vec![];
    let mut sort_desc = vec![];
    let mut range = vec![];
    let id_desc = !sort.is_empty() && sort.iter().all(|s| s.desc);
    if let Some(ref ix) = ix {
        body.push_str(" FROM data_index_entry e JOIN data_record r ON r.id=e.rec WHERE e.ix=? AND r.scope=? AND r.deleted=0");
        args.push(Sql::Integer(ix.id));
        args.push(Sql::Integer(scope));
        for (i, v) in prefix.iter().enumerate() {
            body.push_str(&format!(" AND e.k{}=?", i + 1));
            args.push(v.clone());
        }
        // The first requested key leads both the seek and page order.
        if let Some(key) = ix.keys.get(prefix_len) {
            ranges_on(filter, key, &mut range)
        }
        // Page keys are exactly the requested order. Filter-only plans also
        // retain these slots so seek_terms can bind their leading range.
        for slot in prefix_len + 1..=ix.keys.len() {
            sort_expr.push(format!("e.k{slot}"));
            sort_desc.push(id_desc);
        }
    } else {
        if let Some((source, source_args)) = reverse {
            body.push_str(&source);
            args.extend(source_args)
        } else {
            body.push_str(" FROM data_record r WHERE r.scope=? AND r.deleted=0");
            args.push(Sql::Integer(scope));
        }
        for key in sort {
            sort_expr.push(key_sql("r", &key.key));
            sort_desc.push(key.desc);
        }
        // An unsorted family page walks (scope,type,record) one type at a time.
        if matches!(purpose, Purpose::Page([])) && matches!(select, TypeSelect::Family(_)) {
            sort_expr.push("r.type".into());
            sort_desc.push(false);
        }
    }
    if let Some(f) = filter {
        body.push_str(" AND (");
        body.push_str(&super::exec::expression(
            conn,
            scope,
            scope_value,
            reads,
            core,
            members,
            f,
            "r",
            &mut args,
        )?);
        body.push(')');
    }
    let id_expr = if ix.is_some() { "e.record" } else { "r.record" };
    // Unused slots are always INTEGER 0. Naming them in ORDER BY lets the
    // ordering index continue through to its logical record-ID tie-breaker.
    let order_suffix = ix
        .as_ref()
        .map(|ix| {
            (ix.keys.len() + 1..=4)
                .map(|slot| format!("e.k{slot}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut sql =
        format!("SELECT {id_expr},r.record,r.type,r.revision,r.pending,coalesce(r.doc,r.accepted)");
    for column in sort_expr.iter().chain(&order_suffix) {
        sql.push(',');
        sql.push_str(column);
    }
    sql.push_str(&body);
    let cursor_shape =
        serde_json::to_string(&(select, sort, ix.as_ref().map(|ix| ix.id), &sort_expr))
            .map_err(|e| QueryError::Storage(e.to_string()))?;
    Ok(Plan {
        sql,
        body,
        args,
        sort_expr,
        sort_desc,
        range,
        types: members.iter().map(|t| t.type_id).collect(),
        id_expr,
        order_suffix,
        id_desc,
        cursor_shape,
        consulted,
    })
}

impl Plan {
    /// The type set and range bounds, as SQL after `body`. After a cursor,
    /// what the cursor branches already imply is left out so the cursor is
    /// where each index seek starts: the unsorted family page's type set,
    /// which each branch names itself, and a range bound on the side the
    /// page travels from. The filter itself still checks every bound.
    pub(super) fn seek_terms(&self, after_cursor: bool) -> (String, Vec<Sql>) {
        let mut sql = String::new();
        let mut args = vec![];
        if !(after_cursor && self.sort_expr.first().is_some_and(|e| e == "r.type")) {
            sql.push_str(&format!(
                " AND r.type IN ({})",
                vec!["?"; self.types.len()].join(",")
            ));
            args.extend(self.types.iter().map(|t| Sql::Blob(t.0.to_vec())));
        }
        for (op, value) in &self.range {
            let lower = op.starts_with('>');
            if after_cursor && lower != self.sort_desc[0] {
                continue;
            }
            sql.push_str(&format!(" AND {} {op} ?", self.sort_expr[0]));
            args.push(value.clone());
        }
        (sql, args)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AppId, FieldKind, FieldSpec, IndexDecl, Position, RecordId, RevisionId, SearchMap,
        TypeDocs, TypeKind, WritePolicy,
        store::{
            self,
            records::{self, RecordRow},
            registry,
        },
    };
    use rusqlite::params_from_iter;
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    struct Core;
    impl CoreCatalogue for Core {
        fn core_type(&self, _: TypeId) -> Option<CompiledType> {
            None
        }
    }
    #[test]
    fn page_work_is_scale_invariant_and_explain_uses_entry_key() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        store::migrate(&tx).unwrap();
        let scope = Scope {
            base: [1; 32],
            audience: [2; 32],
        };
        let sid = records::scope_id(&tx, scope, &Core).unwrap();
        let type_id = TypeId([1; 32]);
        let rev = RevisionId([1; 32]);
        let path = FieldPath::parse("/name").unwrap();
        let ct = CompiledType {
            type_id,
            revision: rev,
            kind: TypeKind::Record,
            app: Some(AppId([1; 32])),
            name: "fixture".into(),
            lineage: vec![(type_id, rev)],
            effective_schema: json!({"type":"object"}),
            resources: vec![],
            fields: vec![FieldSpec {
                path: path.clone(),
                kind: FieldKind::String,
                write: WritePolicy::Direct,
                required: false,
                nullable: false,
                declared_by: type_id,
                meaning: "name".into(),
                unit: None,
                absent: None,
            }],
            indexes: vec![IndexDecl {
                name: "by_name".into(),
                keys: vec![KeyRef::Field(path.clone())],
                declared_by: type_id,
            }],
            uniques: vec![],
            queries: vec![],
            search: SearchMap {
                title: None,
                text: vec![],
                builtin_body: false,
            },
            actions: vec![],
            builtin: None,
            previous: None,
            docs: TypeDocs {
                description: String::new(),
                rationale: vec![],
                examples_valid: vec![],
                examples_invalid: vec![],
                migration: None,
            },
        };
        registry::store_definition(&tx, sid, &ct, b"type", Position(1)).unwrap();
        registry::set_current(&tx, sid, type_id, rev, &[rev], Position(1)).unwrap();
        crate::index::ensure(&tx, sid, &ct).unwrap();
        let mut row = RecordRow {
            id: 0,
            scope: sid,
            record: RecordId([1; 32]),
            type_id,
            revision: rev,
            accepted: Some(json!({"name":"a"})),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        crate::index::on_record_changed(&tx, &row, &ct).unwrap();
        tx.commit().unwrap();
        let filter = Expr::Cmp {
            path: path.clone(),
            op: CmpOp::Ge,
            value: json!("a"),
        };
        let select = TypeSelect::Exact(type_id);
        let sort = [SortKey {
            key: KeyRef::Field(path),
            desc: false,
        }];
        let mut p = compile(
            &conn,
            sid,
            scope,
            &[scope],
            &Core,
            std::slice::from_ref(&ct),
            &select,
            Some(&filter),
            Purpose::Page(&sort),
        )
        .unwrap();
        super::super::exec::page_sql(&mut p, &None, 50).unwrap();
        let explain = format!("EXPLAIN QUERY PLAN {}", p.sql);
        let detail = conn
            .prepare(&explain)
            .unwrap()
            .query_map(params_from_iter(p.args.clone()), |r| r.get::<_, String>(3))
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(detail.contains("data_index_entry_key"), "{detail}");
        assert!(!detail.contains("SCAN r"), "{detail}");
        assert!(!detail.contains("TEMP B-TREE"), "{detail}\nSQL: {}", p.sql);
        let page_sql = p.sql.clone();
        fn insert_to(
            conn: &mut Connection,
            sid: i64,
            type_id: TypeId,
            rev: RevisionId,
            ct: &CompiledType,
            start: u32,
            end: u32,
        ) {
            let tx = conn.transaction().unwrap();
            for n in start..=end {
                let mut record = [0; 32];
                record[..4].copy_from_slice(&(30_000 - n).to_be_bytes());
                let mut row = RecordRow {
                    id: 0,
                    scope: sid,
                    record: RecordId(record),
                    type_id,
                    revision: rev,
                    accepted: Some(json!({"name":"tie"})),
                    doc: None,
                    deleted: false,
                    pending: false,
                    changed_at: None,
                    changed: 0,
                    text_rev: 0,
                };
                records::put(&tx, &mut row).unwrap();
                crate::index::on_record_changed(&tx, &row, ct).unwrap();
            }
            tx.commit().unwrap();
        }
        insert_to(&mut conn, sid, type_id, rev, &ct, 1, 2000);
        fn steps(conn: &Connection, sql: &str, args: &[Sql]) -> u64 {
            let counter = Arc::new(AtomicU64::new(0));
            let measured = counter.clone();
            conn.progress_handler(
                1000,
                Some(move || {
                    measured.fetch_add(1, Ordering::Relaxed);
                    false
                }),
            )
            .unwrap();
            let rows = conn
                .prepare(sql)
                .unwrap()
                .query_map(params_from_iter(args), |r| r.get::<_, Vec<u8>>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            conn.progress_handler(0, None::<fn() -> bool>).unwrap();
            assert_eq!(rows.len(), 51);
            counter.load(Ordering::Relaxed)
        }
        let small = steps(&conn, &page_sql, &p.args);
        insert_to(&mut conn, sid, type_id, rev, &ct, 2001, 20000);
        let large = steps(&conn, &page_sql, &p.args);
        assert!(
            small > 0 && large * 2 <= small * 3,
            "indexed page grew from {small} to {large} progress callbacks"
        );
    }
    fn fixture(
        n: u8,
        parent: Option<u8>,
        fields: &[(&str, FieldKind)],
        indexes: &[&[&str]],
    ) -> CompiledType {
        let root = TypeId([parent.unwrap_or(n); 32]);
        let mut lineage = vec![(TypeId([n; 32]), RevisionId([n; 32]))];
        if let Some(p) = parent {
            lineage.push((TypeId([p; 32]), RevisionId([p; 32])));
        }
        CompiledType {
            type_id: TypeId([n; 32]),
            revision: RevisionId([n; 32]),
            kind: TypeKind::Record,
            app: Some(AppId([1; 32])),
            name: "fixture".into(),
            lineage,
            effective_schema: json!({"type":"object"}),
            resources: vec![],
            fields: fields
                .iter()
                .map(|(p, kind)| FieldSpec {
                    path: FieldPath::parse(p).unwrap(),
                    kind: kind.clone(),
                    write: WritePolicy::Direct,
                    required: false,
                    nullable: true,
                    declared_by: root,
                    meaning: (*p).into(),
                    unit: None,
                    absent: None,
                })
                .collect(),
            indexes: indexes
                .iter()
                .map(|keys| IndexDecl {
                    name: keys.join(","),
                    keys: keys
                        .iter()
                        .map(|k| KeyRef::Field(FieldPath::parse(k).unwrap()))
                        .collect(),
                    declared_by: root,
                })
                .collect(),
            uniques: vec![],
            queries: vec![],
            search: SearchMap {
                title: None,
                text: vec![],
                builtin_body: false,
            },
            actions: vec![],
            builtin: None,
            previous: None,
            docs: TypeDocs {
                description: String::new(),
                rationale: vec![],
                examples_valid: vec![],
                examples_invalid: vec![],
                migration: None,
            },
        }
    }
    #[test]
    fn equality_pages_and_filter_only_composites_seek_without_sorting() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        store::migrate(&tx).unwrap();
        let scope = Scope {
            base: [1; 32],
            audience: [2; 32],
        };
        let sid = records::scope_id(&tx, scope, &Core).unwrap();
        let ct = fixture(
            1,
            None,
            &[("/status", FieldKind::String), ("/due", FieldKind::Integer)],
            &[&["/status", "/due"]],
        );
        registry::store_definition(&tx, sid, &ct, b"type", Position(1)).unwrap();
        registry::set_current(
            &tx,
            sid,
            ct.type_id,
            ct.revision,
            &[ct.revision],
            Position(1),
        )
        .unwrap();
        crate::index::ensure(&tx, sid, &ct).unwrap();
        let mut row = RecordRow {
            id: 0,
            scope: sid,
            record: RecordId([1; 32]),
            type_id: ct.type_id,
            revision: ct.revision,
            accepted: Some(json!({"status":"rare", "due":2})),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        crate::index::on_record_changed(&tx, &row, &ct).unwrap();
        tx.commit().unwrap();
        let status = Expr::Cmp {
            path: FieldPath::parse("/status").unwrap(),
            op: CmpOp::Eq,
            value: json!("rare"),
        };
        for (purpose, filter) in [
            (
                Purpose::Page(&[]),
                Expr::And(vec![
                    status.clone(),
                    Expr::Cmp {
                        path: FieldPath::parse("/due").unwrap(),
                        op: CmpOp::Eq,
                        value: json!(2),
                    },
                ]),
            ),
            (Purpose::Filter, status.clone()),
            (
                Purpose::Filter,
                Expr::Cmp {
                    path: FieldPath::parse("/status").unwrap(),
                    op: CmpOp::Ge,
                    value: json!("rare"),
                },
            ),
            (
                Purpose::Filter,
                Expr::And(vec![
                    status,
                    Expr::Cmp {
                        path: FieldPath::parse("/due").unwrap(),
                        op: CmpOp::Ge,
                        value: json!(2),
                    },
                ]),
            ),
        ] {
            let mut p = compile(
                &conn,
                sid,
                scope,
                &[scope],
                &Core,
                std::slice::from_ref(&ct),
                &TypeSelect::Exact(ct.type_id),
                Some(&filter),
                purpose,
            )
            .unwrap();
            match purpose {
                Purpose::Page(_) => super::super::exec::page_sql(&mut p, &None, 50).unwrap(),
                Purpose::Filter => {
                    let (terms, args) = p.seek_terms(false);
                    p.sql = format!("SELECT count(*){}{terms}", p.body);
                    p.args.extend(args);
                }
            }
            let detail = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {}", p.sql))
                .unwrap()
                .query_map(params_from_iter(&p.args), |r| r.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                detail.contains("SEARCH e USING INDEX data_index_entry_key (ix=? AND k1"),
                "{detail}"
            );
            assert!(
                !detail.contains("TEMP B-TREE") && !detail.contains("SCAN"),
                "{detail}"
            );
            let mut st = conn.prepare(&p.sql).unwrap();
            let rows = st
                .query_map(params_from_iter(&p.args), |r| r.get::<_, Sql>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(rows.len(), 1);
            let steps = st.get_status(rusqlite::StatementStatus::VmStep);
            assert!(steps < 1000, "{steps}: {}", p.sql);
            eprintln!("selective SQL: {steps} VM steps; {detail}");
        }
    }
    #[test]
    fn selective_via_plan_starts_at_target_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        store::migrate(&tx).unwrap();
        let scope = Scope {
            base: [1; 32],
            audience: [2; 32],
        };
        let sid = records::scope_id(&tx, scope, &Core).unwrap();
        let target = fixture(1, None, &[("/status", FieldKind::String)], &[&["/status"]]);
        let source = fixture(
            2,
            None,
            &[(
                "/target",
                FieldKind::Reference(crate::RefSpec {
                    targets: vec![target.type_id],
                    family: false,
                }),
            )],
            &[],
        );
        for ct in [&target, &source] {
            registry::store_definition(&tx, sid, ct, b"type", Position(1)).unwrap();
            registry::set_current(
                &tx,
                sid,
                ct.type_id,
                ct.revision,
                &[ct.revision],
                Position(1),
            )
            .unwrap();
            crate::index::ensure(&tx, sid, ct).unwrap();
        }
        for n in 0..200 {
            let mut record = [0; 32];
            record[..4].copy_from_slice(&(n as u32).to_be_bytes());
            let mut row = RecordRow {
                id: 0,
                scope: sid,
                record: RecordId(record),
                type_id: target.type_id,
                revision: target.revision,
                accepted: Some(json!({"status":if n==0 {"match"} else {"other"}})),
                doc: None,
                deleted: false,
                pending: false,
                changed_at: None,
                changed: 0,
                text_rev: 0,
            };
            records::put(&tx, &mut row).unwrap();
            crate::index::on_record_changed(&tx, &row, &target).unwrap();
        }
        tx.commit().unwrap();
        let filter = Expr::Via {
            path: FieldPath::parse("/target").unwrap(),
            filter: Box::new(Expr::Cmp {
                path: FieldPath::parse("/status").unwrap(),
                op: CmpOp::Eq,
                value: json!("match"),
            }),
        };
        let mut plan = compile(
            &conn,
            sid,
            scope,
            &[scope],
            &Core,
            std::slice::from_ref(&source),
            &TypeSelect::Exact(source.type_id),
            Some(&filter),
            Purpose::Page(&[]),
        )
        .unwrap();
        super::super::exec::page_sql(&mut plan, &None, 50).unwrap();
        let detail = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {}", plan.sql))
            .unwrap()
            .query_map(params_from_iter(plan.args), |r| r.get::<_, String>(3))
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            detail.contains("SEARCH te USING INDEX data_index_entry_key"),
            "{detail}"
        );
        assert!(!detail.contains("SCAN r"), "{detail}");
    }
    #[test]
    fn index_and_family_pages_seek_without_temp_btree() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        store::migrate(&tx).unwrap();
        let scope = Scope {
            base: [1; 32],
            audience: [2; 32],
        };
        let sid = records::scope_id(&tx, scope, &Core).unwrap();
        let fields = [
            ("/status", FieldKind::String),
            ("/due", FieldKind::Integer),
            ("/title", FieldKind::String),
        ];
        let parent = fixture(1, None, &fields, &[&["/status", "/due"], &["/status"]]);
        let child = fixture(2, Some(1), &fields, &[]);
        let wide = fixture(
            3,
            None,
            &fields,
            &[&["/status", "/due", "/title"], &["/status", "/due"]],
        );
        for ct in [&parent, &child, &wide] {
            registry::store_definition(&tx, sid, ct, b"type", Position(1)).unwrap();
            registry::set_current(
                &tx,
                sid,
                ct.type_id,
                ct.revision,
                &[ct.revision],
                Position(1),
            )
            .unwrap();
            crate::index::ensure(&tx, sid, ct).unwrap();
        }
        for n in 1..=30u32 {
            let ct = [&parent, &child, &wide][n as usize % 3];
            let status = ["open", "closed"][n as usize % 2];
            let mut record = [0; 32];
            record[..4].copy_from_slice(&n.to_be_bytes());
            let mut row = RecordRow {
                id: 0,
                scope: sid,
                record: RecordId(record),
                type_id: ct.type_id,
                revision: ct.revision,
                accepted: Some(json!({"status":status,"due":n % 4,"title":format!("t{n}")})),
                doc: None,
                deleted: false,
                pending: false,
                changed_at: None,
                changed: 0,
                text_rev: 0,
            };
            records::put(&tx, &mut row).unwrap();
            crate::index::on_record_changed(&tx, &row, ct).unwrap();
        }
        tx.commit().unwrap();
        let status = || Expr::Cmp {
            path: FieldPath::parse("/status").unwrap(),
            op: CmpOp::Eq,
            value: json!("open"),
        };
        let by = |p: &str, desc: bool| SortKey {
            key: KeyRef::Field(FieldPath::parse(p).unwrap()),
            desc,
        };
        type Case = (
            &'static str,
            TypeSelect,
            Option<Expr>,
            Vec<SortKey>,
            &'static str,
        );
        let cases: Vec<Case> = vec![
            (
                "equality prefix, no sort",
                TypeSelect::Exact(TypeId([1; 32])),
                Some(status()),
                vec![],
                "data_index_entry_key",
            ),
            (
                "sort by leading key",
                TypeSelect::Exact(TypeId([1; 32])),
                None,
                vec![by("/status", false)],
                "data_index_entry_key",
            ),
            (
                "sort by leading key desc",
                TypeSelect::Exact(TypeId([1; 32])),
                None,
                vec![by("/status", true)],
                "data_index_entry_key",
            ),
            (
                "equality then sort, key left over",
                TypeSelect::Exact(TypeId([3; 32])),
                Some(status()),
                vec![by("/due", false)],
                "data_index_entry_key",
            ),
            (
                "indexed family equality, no sort",
                TypeSelect::Family(TypeId([1; 32])),
                Some(status()),
                vec![],
                "data_record_logical",
            ),
            (
                "range only, no sort",
                TypeSelect::Exact(TypeId([1; 32])),
                Some(Expr::Cmp {
                    path: FieldPath::parse("/status").unwrap(),
                    op: CmpOp::Gt,
                    value: json!("a"),
                }),
                vec![],
                "data_record_logical",
            ),
            (
                "range on the sort key",
                TypeSelect::Exact(TypeId([1; 32])),
                Some(Expr::Cmp {
                    path: FieldPath::parse("/status").unwrap(),
                    op: CmpOp::Lt,
                    value: json!("z"),
                }),
                vec![by("/status", false)],
                "data_index_entry_key",
            ),
            (
                "equality, then a range on the sort key desc",
                TypeSelect::Exact(TypeId([3; 32])),
                Some(Expr::And(vec![
                    status(),
                    Expr::Cmp {
                        path: FieldPath::parse("/due").unwrap(),
                        op: CmpOp::Ge,
                        value: json!(1),
                    },
                ])),
                vec![by("/due", true)],
                "data_index_entry_key",
            ),
            (
                "unindexed family, no sort",
                TypeSelect::Family(TypeId([1; 32])),
                None,
                vec![],
                "data_record_logical",
            ),
        ];
        for (name, select, filter, sort, index) in cases {
            let members = super::super::check::members(&conn, sid, &Core, &select).unwrap();
            let plan = || {
                compile(
                    &conn,
                    sid,
                    scope,
                    &[scope],
                    &Core,
                    &members,
                    &select,
                    filter.as_ref(),
                    Purpose::Page(&sort),
                )
                .unwrap()
            };
            let probe = plan();
            // A family page's r.type key is always a selected type.
            let keys = |value: Sql| {
                probe
                    .sort_expr
                    .iter()
                    .map(|e| {
                        if e == "r.type" {
                            Sql::Blob(vec![1; 32])
                        } else {
                            value.clone()
                        }
                    })
                    .collect::<Vec<_>>()
            };
            let key_sets = [
                None,
                Some(keys(Sql::Integer(1))),
                Some(keys(Sql::Null)),
                Some(keys(Sql::Text("open".into()))),
            ];
            for keys in key_sets {
                let mut p = plan();
                let after = keys
                    .map(|k| super::super::cursor::encode(&k, RecordId([1; 32]), &p.cursor_shape));
                super::super::exec::page_sql(&mut p, &after, 50).unwrap();
                let detail = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {}", p.sql))
                    .unwrap()
                    .query_map(params_from_iter(p.args.clone()), |r| r.get::<_, String>(3))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(detail.contains(index), "{name}: {detail}");
                assert!(
                    !detail.contains("TEMP B-TREE") && !detail.contains("SCAN"),
                    "{name}: {detail}\nSQL: {}",
                    p.sql
                );
            }
        }
    }
}
