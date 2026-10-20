use super::{
    Aggregate, AggregateGroup, AggregateResult, Budget, CmpOp, Completeness, Cursor, Expr, Follow,
    FollowRow, Gap, Measure, Page, Query, QueryError, Row, SortKey, TypeSelect, check, cursor,
    plan,
};
use crate::{
    CompiledType, CoreCatalogue, FieldKind, FieldPath, RecordId, RecordRef, RevisionId, Scope,
    TypeId,
    store::{self, coverage, records, registry},
    text,
};
use rusqlite::{Connection, params_from_iter, types::Value as Sql};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
fn sql(e: rusqlite::Error) -> QueryError {
    QueryError::Storage(e.to_string())
}
// A session owns its connection for the query's duration. No prior progress
// handler is restored; dropping the guard clears our handler on every exit.
struct Guard<'a> {
    conn: &'a Connection,
    exceeded: Arc<AtomicBool>,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let _ = self.conn.progress_handler(0, None::<fn() -> bool>);
    }
}
impl<'a> Guard<'a> {
    fn new(conn: &'a Connection, budget: Budget) -> Result<Self, QueryError> {
        let count = Arc::new(AtomicU64::new(0));
        let exceeded = Arc::new(AtomicBool::new(false));
        let a = count.clone();
        let b = exceeded.clone();
        conn.progress_handler(
            1000,
            Some(move || {
                let n = a.fetch_add(1000, Ordering::Relaxed) + 1000;
                if n > budget.vm_steps {
                    b.store(true, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }),
        )
        .map_err(sql)?;
        Ok(Self { conn, exceeded })
    }
    fn map(&self, e: QueryError, budget: Budget) -> QueryError {
        if self.exceeded.load(Ordering::Relaxed) {
            QueryError::TooCostly {
                work: budget.vm_steps.saturating_add(1000),
            }
        } else {
            e
        }
    }
    fn ensure(&self, budget: Budget) -> Result<(), QueryError> {
        if self.exceeded.load(Ordering::Relaxed) {
            Err(QueryError::TooCostly {
                work: budget.vm_steps.saturating_add(1000),
            })
        } else {
            Ok(())
        }
    }
    fn error(&self, e: rusqlite::Error, budget: Budget) -> QueryError {
        if self.exceeded.load(Ordering::Relaxed) {
            QueryError::TooCostly {
                work: budget.vm_steps + 1000,
            }
        } else {
            sql(e)
        }
    }
}
fn ids(conn: &Connection, scope: Scope, reads: &[Scope]) -> Result<i64, QueryError> {
    if !reads.contains(&scope) {
        return Err(QueryError::not_queryable(None, "scope is not readable"));
    }
    Ok(records::lookup_scope(conn, scope)?.unwrap_or(-1))
}
fn projection(doc: &Value, paths: &[FieldPath]) -> BTreeMap<String, Value> {
    paths
        .iter()
        .filter_map(|p| p.get(doc).map(|v| (p.as_pointer(), v.clone())))
        .collect()
}
// Follow fields are checked against every declared target type known in a
// readable audience. A target type no readable audience knows only makes its
// follows `None`; it never fails the page.
fn validate_follows(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    members: &[CompiledType],
    follows: &[Follow],
) -> Result<(), QueryError> {
    for follow in follows {
        let FieldKind::Reference(spec) = check::kind(members, &follow.path)? else {
            return Err(QueryError::TypeMismatch(follow.path.clone()));
        };
        for target in &spec.targets {
            for readable in reads.iter().filter(|s| s.base == scope.base) {
                let Some(sid) = records::lookup_scope(conn, *readable)? else {
                    continue;
                };
                let selected = if spec.family {
                    TypeSelect::Family(*target)
                } else {
                    TypeSelect::Exact(*target)
                };
                match check::members(conn, sid, core, &selected) {
                    Ok(types) => {
                        for path in &follow.fields {
                            check::kind(&types, path)?;
                        }
                    }
                    Err(QueryError::UnknownType) => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(())
}
// Records the audience it read in `consulted`, and a gap when the target is
// in a readable audience not held locally or its type is not installed.
#[allow(clippy::too_many_arguments)]
fn follow(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    doc: &Value,
    request: &Follow,
    reference_kind: &FieldKind,
    consulted: &mut Vec<i64>,
    gaps: &mut Vec<Gap>,
) -> Result<Option<FollowRow>, QueryError> {
    let Some(raw) = request.path.get(doc) else {
        return Ok(None);
    };
    let Ok(reference) = serde_json::from_value::<RecordRef>(raw.clone()) else {
        return Ok(None);
    };
    let dest = Scope {
        base: scope.base,
        audience: reference.audience.unwrap_or(scope.audience),
    };
    if !reads.contains(&dest) {
        return Ok(None);
    }
    let Some(dst) = records::lookup_scope(conn, dest)? else {
        if !gaps.contains(&Gap::NotCovered) {
            gaps.push(Gap::NotCovered)
        }
        return Ok(None);
    };
    if !consulted.contains(&dst) {
        consulted.push(dst)
    }
    if let FieldKind::Reference(spec) = reference_kind
        && let Some(gap) = check::target_gap(conn, dst, core, spec)?
        && !gaps.contains(&gap)
    {
        gaps.push(gap);
    }
    // The destination may have no materialized row or understood type yet.
    // Its exact parked key is relevant even for an exact-type reference.
    let waiting: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_parked INDEXED BY data_parked_record WHERE scope=?1 AND record=?2)",
        rusqlite::params![dst, reference.record.0.as_slice()], |r|r.get(0))
        .map_err(|e| QueryError::Storage(e.to_string()))?;
    if waiting && !gaps.contains(&Gap::WaitingScope) {
        gaps.push(Gap::WaitingScope);
    }
    let Some(row) = records::get(conn, dst, reference.record)? else {
        return Ok(None);
    };
    if row.deleted {
        return Ok(None);
    }
    let Some(ct) = registry::current(conn, dst, row.type_id, core)? else {
        let gap = Gap::UnsupportedType(row.type_id);
        if !gaps.contains(&gap) {
            gaps.push(gap)
        }
        return Ok(None);
    };
    let FieldKind::Reference(spec) = reference_kind else {
        unreachable!("checked follow path")
    };
    if !spec.targets.iter().any(|target| {
        if spec.family {
            ct.is_family_member_of(*target)
        } else {
            row.type_id == *target
        }
    }) {
        return Ok(None);
    }
    for p in &request.fields {
        check::kind(std::slice::from_ref(&ct), p)?;
    }
    Ok(Some(FollowRow {
        record: row.record,
        type_id: row.type_id,
        values: row
            .view()
            .map(|v| projection(v, &request.fields))
            .unwrap_or_default(),
    }))
}
fn completeness(
    conn: &Connection,
    scope: i64,
    consulted: &[i64],
    extra_gaps: &[Gap],
    core: &dyn CoreCatalogue,
    members: &[crate::CompiledType],
    rows: &[Row],
) -> Result<Completeness, QueryError> {
    let mut gaps = extra_gaps.to_vec();
    // A Note gap is the record's, so only a Note-family result is affected: one
    // indexed probe for the scope, whatever the page size.
    let note = TypeId::core("note");
    let selects_notes = members
        .iter()
        .any(|m| m.type_id == note || m.is_family_member_of(note));
    if selects_notes
        && crate::note::any_unavailable(conn, scope)?
        && !gaps.contains(&Gap::NoteUnavailable)
    {
        gaps.push(Gap::NoteUnavailable)
    }
    for sid in std::iter::once(&scope).chain(consulted.iter()) {
        if !coverage::get(conn, *sid)?.complete && !gaps.contains(&Gap::NotCovered) {
            gaps.push(Gap::NotCovered)
        }
    }
    for row in rows {
        if !members
            .iter()
            .any(|t| t.type_id == row.type_id && t.revision == row.revision)
            && registry::compiled(conn, scope, row.revision)?.is_none()
            && !core
                .core_type(row.type_id)
                .is_some_and(|t| t.revision == row.revision)
        {
            let gap = Gap::UnsupportedType(row.type_id);
            if !gaps.contains(&gap) {
                gaps.push(gap)
            }
        }
    }
    // Select relevant types and unknown-type waits through the scoped type
    // index, independently of the returned page. Do not sort the entire
    // parked queue: only the bounded 501 candidates need position ordering.
    let marks = (2..members.len() + 2)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql_text = format!(
        "SELECT position,affects,type,record FROM (SELECT position,affects,type,record FROM data_parked INDEXED BY data_parked_type WHERE scope=?1 AND type IS NULL LIMIT 501) UNION ALL SELECT position,affects,type,record FROM (SELECT position,affects,type,record FROM data_parked INDEXED BY data_parked_type WHERE scope=?1 AND type IN ({marks}) LIMIT 501) LIMIT 501"
    );
    let mut st = conn.prepare(&sql_text).map_err(sql)?;
    let args = std::iter::once(Sql::Integer(scope))
        .chain(members.iter().map(|m| Sql::Blob(m.type_id.0.to_vec())));
    let mut parked = st
        .query_map(params_from_iter(args), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    parked.sort_unstable_by_key(|(position, ..)| *position);
    for (position, (_, affect, type_id, record)) in parked.into_iter().enumerate() {
        if position == 500 {
            if !gaps.contains(&Gap::WaitingScope) {
                gaps.push(Gap::WaitingScope)
            }
            break;
        }
        if affect.as_ref().is_none_or(|s| s.is_empty() || s == "null") {
            if !gaps.contains(&Gap::WaitingScope) {
                gaps.push(Gap::WaitingScope)
            }
            continue;
        }
        if let Some(s) = affect {
            if let (true, Some(record)) = (s.starts_with("r:"), record) {
                if type_id
                    .as_ref()
                    .is_none_or(|type_id| members.iter().any(|m| m.type_id.0.as_slice() == type_id))
                {
                    let gap = Gap::WaitingRecord(RecordId(store::id(record)?));
                    if !gaps.contains(&gap) {
                        gaps.push(gap);
                    }
                }
                continue;
            }
            for row in rows {
                if s.contains(
                    serde_json::to_string(&row.record)
                        .unwrap_or_default()
                        .trim_matches('"'),
                ) {
                    let gap = Gap::WaitingRecord(row.record);
                    if !gaps.contains(&gap) {
                        gaps.push(gap)
                    }
                }
            }
            for m in members {
                if s.contains(
                    serde_json::to_string(&m.type_id)
                        .unwrap_or_default()
                        .trim_matches('"'),
                ) {
                    let gap = Gap::WaitingType(m.type_id);
                    if !gaps.contains(&gap) {
                        gaps.push(gap)
                    }
                }
            }
        }
    }
    if gaps.is_empty() {
        Ok(Completeness::Complete)
    } else {
        Ok(Completeness::Incomplete(gaps))
    }
}
// Rows after a cursor, as disjoint predicates. Each is an equality prefix and
// one seekable bound (SQLite orders NULL first ascending), so every branch
// starts at its position in the index instead of walking from the start.
fn keyset_branches(
    p: &plan::Plan,
    after: &Option<Cursor>,
) -> Result<Vec<(String, Vec<Sql>)>, QueryError> {
    let Some(after) = after else {
        return Ok(vec![(String::new(), vec![])]);
    };
    let (keys, rec) = cursor::decode(after, p.sort_expr.len(), &p.cursor_shape)?;
    let mut branches = vec![];
    for i in 0..=keys.len() {
        let mut prefix = String::new();
        let mut prefix_args = vec![];
        for (j, key) in keys.iter().enumerate().take(i) {
            prefix.push_str(&format!(" AND {} IS ?", p.sort_expr[j]));
            prefix_args.push(key.clone());
        }
        let bounds: Vec<(String, Option<Sql>)> = if i == keys.len() {
            // Binding the constant unused index slots makes the logical ID a seek
            // bound inside a run of equal keys.
            for slot in &p.order_suffix {
                prefix.push_str(&format!(" AND {slot} IS 0"));
            }
            let op = if p.id_desc { "<" } else { ">" };
            vec![(
                format!("{} {op} ?", p.id_expr),
                Some(Sql::Blob(rec.0.to_vec())),
            )]
        } else {
            let col = &p.sort_expr[i];
            if col == "r.type" {
                // Cursor pages carry no type set, so the cursor's type must
                // be one of the selected types.
                let after = match &keys[i] {
                    Sql::Blob(after) if p.types.iter().any(|t| t.0.as_slice() == after) => after,
                    _ => return Err(QueryError::not_queryable(None, "invalid cursor")),
                };
                // A range on r.type is not a seek bound inside a type set;
                // name the later types, which SQLite seeks one by one.
                let later = p
                    .types
                    .iter()
                    .filter(|t| t.0.as_slice() > after.as_slice())
                    .map(|t| Sql::Blob(t.0.to_vec()))
                    .collect::<Vec<_>>();
                if !later.is_empty() {
                    let mut args = prefix_args.clone();
                    let marks = vec!["?"; later.len()].join(",");
                    args.extend(later);
                    branches.push((format!("{prefix} AND {col} IN ({marks})"), args));
                }
                continue;
            }
            match (&keys[i], p.sort_desc[i]) {
                (Sql::Null, false) => vec![(format!("{col} IS NOT NULL"), None)],
                (Sql::Null, true) => vec![],
                (key, false) => vec![(format!("{col} > ?"), Some(key.clone()))],
                // A range on this key excludes NULL.
                (key, true) if i == 0 && !p.range.is_empty() => {
                    vec![(format!("{col} < ?"), Some(key.clone()))]
                }
                (key, true) => vec![
                    (format!("{col} < ?"), Some(key.clone())),
                    (format!("{col} IS NULL"), None),
                ],
            }
        };
        for (bound, value) in bounds {
            let mut args = prefix_args.clone();
            args.extend(value);
            branches.push((format!("{prefix} AND {bound}"), args));
        }
    }
    Ok(branches)
}
// Several branches are one UNION ALL ordered by result column, which SQLite
// merges lazily from each branch's index order.
pub(super) fn page_sql(
    p: &mut plan::Plan,
    after: &Option<Cursor>,
    limit: u32,
) -> Result<(), QueryError> {
    let branches = keyset_branches(p, after)?;
    let (terms, term_args) = p.seek_terms(after.is_some());
    let base = std::mem::take(&mut p.sql);
    let base_args = std::mem::take(&mut p.args);
    for (i, (bound, args)) in branches.into_iter().enumerate() {
        if i > 0 {
            p.sql.push_str(" UNION ALL ");
        }
        p.sql.push_str(&base);
        p.sql.push_str(&terms);
        p.sql.push_str(&bound);
        p.args.extend(base_args.iter().cloned());
        p.args.extend(term_args.iter().cloned());
        p.args.extend(args);
    }
    let direction = |desc: bool| if desc { "DESC" } else { "ASC" };
    let mut order = vec![];
    for (i, desc) in p.sort_desc.iter().enumerate() {
        order.push(format!("{} {}", 7 + i, direction(*desc)));
    }
    for i in 0..p.order_suffix.len() {
        order.push(format!(
            "{} {}",
            7 + p.sort_expr.len() + i,
            direction(p.id_desc)
        ));
    }
    order.push(format!("1 {}", direction(p.id_desc)));
    p.sql
        .push_str(&format!(" ORDER BY {} LIMIT ?", order.join(",")));
    p.args.push(Sql::Integer(i64::from(limit) + 1));
    Ok(())
}
/// Construct a cursor for a native caller that keeps a numeric `$changed`
/// keyset at its boundary. Use the live planner's shape: index readiness can
/// change the serving path and the ordinary decoder will then reject it.
pub(super) fn after_changed(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    q: &Query,
    changed: i64,
    record: RecordId,
) -> Result<Cursor, QueryError> {
    let invalid = || QueryError::not_queryable(None, "invalid cursor");
    if changed < 0
        || q.sort.as_slice()
            != [SortKey {
                key: crate::KeyRef::Changed,
                desc: true,
            }]
        || q.filter.is_some()
        || q.text.is_some()
        || !q.follow.is_empty()
        || q.after.is_some()
    {
        return Err(invalid());
    }
    let sid = ids(conn, scope, reads)?;
    if sid < 0 {
        return Err(invalid());
    }
    let members = check::members(conn, sid, core, &q.select)?;
    check::key(&members, &crate::KeyRef::Changed)?;
    let p = plan::compile(
        conn,
        sid,
        scope,
        reads,
        core,
        &members,
        &q.select,
        None,
        plan::Purpose::Page(&q.sort),
    )?;
    if p.sort_expr.len() != 1 {
        return Err(invalid());
    }
    let result = cursor::encode(&[Sql::Integer(changed)], record, &p.cursor_shape);
    cursor::decode(&result, 1, &p.cursor_shape)?;
    Ok(result)
}

pub(super) fn run(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    q: &Query,
    budget: Budget,
) -> Result<Page, QueryError> {
    let sid = ids(conn, scope, reads)?;
    if q.limit == 0 || q.limit > 200 {
        return Err(QueryError::not_queryable(None, "limit must be 1..=200"));
    }
    if sid < 0 {
        return Ok(Page {
            rows: vec![],
            next: None,
            completeness: Completeness::Incomplete(vec![Gap::NotCovered]),
        });
    }
    let guard = Guard::new(conn, budget)?;
    let members = check::members(conn, sid, core, &q.select).map_err(|e| guard.map(e, budget))?;
    for p in &q.fields {
        check::kind(&members, p)?;
    }
    for sort in &q.sort {
        check::key(&members, &sort.key)?;
    }
    validate_follows(conn, scope, reads, core, &members, &q.follow)
        .map_err(|e| guard.map(e, budget))?;
    let mut query_gaps = if let Some(f) = &q.filter {
        check::expression(conn, scope, reads, core, &members, f, false)
            .map_err(|e| guard.map(e, budget))?
    } else {
        vec![]
    };
    let mut p = plan::compile(
        conn,
        sid,
        scope,
        reads,
        core,
        &members,
        &q.select,
        q.filter.as_ref(),
        plan::Purpose::Page(&q.sort),
    )
    .map_err(|e| guard.map(e, budget))?;
    let mut consulted = p.consulted.clone();
    if let Some(request) = &q.text {
        text_filter(
            conn,
            scope,
            sid,
            reads,
            core,
            &members,
            request,
            &mut p,
            &mut consulted,
            &mut query_gaps,
        )
        .map_err(|e| guard.map(e, budget))?;
    }
    page_sql(&mut p, &q.after, q.limit)?;
    let mut stmt = conn.prepare(&p.sql).map_err(|e| guard.error(e, budget))?;
    let mut cursor_rows = stmt
        .query(params_from_iter(p.args))
        .map_err(|e| guard.error(e, budget))?;
    let mut result = vec![];
    while let Some(r) = cursor_rows.next().map_err(|e| guard.error(e, budget))? {
        let record_key = RecordId(store::id(r.get(0).map_err(sql)?)?);
        let record = RecordId(store::id(r.get(1).map_err(sql)?)?);
        let type_id = TypeId(store::id(r.get(2).map_err(sql)?)?);
        let revision = RevisionId(store::id(r.get(3).map_err(sql)?)?);
        let pending: bool = r.get(4).map_err(sql)?;
        let doc: String = r.get(5).map_err(sql)?;
        let doc: Value =
            serde_json::from_str(&doc).map_err(|e| QueryError::Storage(e.to_string()))?;
        let keys = (0..p.sort_expr.len())
            .map(|i| r.get::<_, Sql>(6 + i).map_err(sql))
            .collect::<Result<Vec<_>, _>>()?;
        result.push((
            record_key,
            Row {
                record,
                changed: if q
                    .sort
                    .first()
                    .is_some_and(|sort| sort.key == crate::KeyRef::Changed)
                {
                    match keys.first() {
                        Some(Sql::Integer(value)) => Some(*value),
                        _ => return Err(QueryError::Storage("invalid $changed sort key".into())),
                    }
                } else {
                    None
                },
                type_id,
                revision,
                values: projection(&doc, &q.fields),
                follows: BTreeMap::new(),
                pending,
            },
            keys,
            doc,
        ));
    }
    let has_more = result.len() > q.limit as usize;
    result.truncate(q.limit as usize);
    let next = if has_more {
        result
            .last()
            .map(|(id, _, keys, _)| cursor::encode(keys, *id, &p.cursor_shape))
    } else {
        None
    };
    let mut rows = vec![];
    for (_, mut row, _, doc) in result {
        for f in &q.follow {
            row.follows.insert(
                f.path.as_pointer(),
                follow(
                    conn,
                    scope,
                    reads,
                    core,
                    &doc,
                    f,
                    check::kind(&members, &f.path)?,
                    &mut consulted,
                    &mut query_gaps,
                )
                .map_err(|e| guard.map(e, budget))?,
            );
        }
        rows.push(row)
    }
    let completeness = completeness(conn, sid, &consulted, &query_gaps, core, &members, &rows)
        .map_err(|e| guard.map(e, budget))?;
    guard.ensure(budget)?;
    Ok(Page {
        rows,
        next,
        completeness,
    })
}
// Keep common combining marks with their base letter, matching unicode61's
// mark categories. This local table is not an exhaustive Unicode M* table;
// uncommon marks can still be split until a Unicode-category dependency is
// available. The FTS tokenizer itself includes all M* categories.
fn is_combining_mark(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036f | 0x0483..=0x0489 | 0x0591..=0x05bd |
        0x05bf | 0x05c1..=0x05c2 | 0x05c4..=0x05c5 |
        0x0610..=0x061a | 0x064b..=0x065f | 0x0670 |
        0x06d6..=0x06ed | 0x0900..=0x0903 | 0x093a..=0x094f |
        0x0981..=0x0983 | 0x0a01..=0x0a4d | 0x0b01..=0x0b4d |
        0x0c00..=0x0c4d | 0x0d00..=0x0d4d | 0x0e31..=0x0e4e |
        0x1ab0..=0x1aff | 0x1dc0..=0x1dff | 0x20d0..=0x20ff |
        0xfe20..=0xfe2f | 0x1e000..=0x1e02a)
}
// Each user term is independently quoted and ANDed across title and body.
// Column names, operators and the scope token cannot be user syntax.
fn literal_terms(terms: &str) -> Result<String, QueryError> {
    if terms.len() > 4096 {
        return Err(QueryError::not_queryable(
            None,
            "text terms must be at most 4096 bytes",
        ));
    }
    // Follow unicode61's default letter/number boundaries rather than
    // treating punctuation inside one input chunk as phrase syntax.
    let words = terms
        .split(|c: char| !c.is_alphanumeric() && !is_combining_mark(c))
        .filter(|term| !term.is_empty())
        .map(|term| format!("\"{term}\""))
        .collect::<Vec<_>>();
    if words.is_empty() {
        return Err(QueryError::not_queryable(
            None,
            "text requires at least one word term",
        ));
    }
    Ok(format!("{{title body}}:({})", words.join(" ")))
}
/// A small authorized FTS hit set is cheaper to sort than to find by walking
/// a broad scalar index. Share the planner's bounded-sort allowance: probe at
/// most FALLBACK_SCAN_ROWS + 1 rowids and sort at most FALLBACK_SCAN_ROWS hits.
/// Larger sets retain the existing index path and unchanged VM budget, which
/// may reject a sparse logical-order walk as TooCostly. Cursor shape remains tied
/// to the same serving index/keys, not this transient candidate decision.
fn selective_text(
    conn: &Connection,
    sid: i64,
    terms: &str,
    p: &mut plan::Plan,
) -> Result<bool, QueryError> {
    let indexed = " FROM data_index_entry e JOIN data_record r ON r.id=e.rec WHERE";
    let records = " FROM data_record r WHERE";
    let before = if p.body.starts_with(indexed) {
        indexed
    } else if p.body.starts_with(records) {
        records
    } else {
        return Ok(false);
    };
    let mut stmt = conn
        .prepare("SELECT rowid FROM data_fts WHERE scope MATCH ?1 AND data_fts MATCH ?2 LIMIT ?3")
        .map_err(sql)?;
    let hits = stmt
        .query_map(
            rusqlite::params![
                text::scope_token(sid),
                terms,
                (plan::FALLBACK_SCAN_ROWS + 1) as i64
            ],
            |r| r.get::<_, i64>(0),
        )
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    if hits.len() as u64 > plan::FALLBACK_SCAN_ROWS {
        return Ok(false);
    }
    if hits.is_empty() {
        p.body.push_str(" AND 0");
        p.sql.push_str(" AND 0");
        return Ok(true);
    }
    // One bounded array binding avoids multiplying up to FALLBACK_SCAN_ROWS
    // parameters by every cursor UNION branch. json_each preserves these i64
    // rowids as SQLite integers; no caller SQL or floating-point IDs are used.
    let driver = " FROM (SELECT value AS rec FROM json_each(?)) matched CROSS JOIN ";
    let after = if before == indexed {
        format!(
            "{driver}data_index_entry e INDEXED BY data_index_entry_rec ON e.rec=matched.rec JOIN data_record r ON r.id=e.rec WHERE"
        )
    } else {
        format!("{driver}data_record r ON r.id=matched.rec WHERE")
    };
    p.body = p.body.replacen(before, &after, 1);
    p.sql = p.sql.replacen(before, &after, 1);
    let candidates =
        serde_json::to_string(&hits).map_err(|e| QueryError::Storage(e.to_string()))?;
    p.args.insert(0, Sql::Text(candidates));
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn text_filter(
    conn: &Connection,
    source: Scope,
    sid: i64,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    members: &[CompiledType],
    request: &super::TextMatch,
    p: &mut plan::Plan,
    consulted: &mut Vec<i64>,
    gaps: &mut Vec<Gap>,
) -> Result<(), QueryError> {
    let match_terms = literal_terms(&request.terms)?;
    let mut targets = vec![];
    let predicate = if let Some(path) = &request.on {
        let FieldKind::Reference(spec) = check::kind(members, path)? else {
            return Err(QueryError::TypeMismatch(path.clone()));
        };
        let mut branches = vec![];
        let mut args = vec![];
        for readable in reads.iter().filter(|s| s.base == source.base) {
            let Some(dst) = records::lookup_scope(conn, *readable)? else {
                if !gaps.contains(&Gap::NotCovered) {
                    gaps.push(Gap::NotCovered)
                }
                continue;
            };
            if let Some(gap) = check::target_gap(conn, dst, core, spec)?
                && !gaps.contains(&gap)
            {
                gaps.push(gap);
            }
            let mut target_types = Vec::new();
            if !consulted.contains(&dst) {
                consulted.push(dst);
            }
            for target in &spec.targets {
                let select = if spec.family {
                    TypeSelect::Family(*target)
                } else {
                    TypeSelect::Exact(*target)
                };
                let types = match check::members(conn, dst, core, &select) {
                    Ok(types) => types,
                    Err(QueryError::UnknownType) => {
                        let gap = Gap::UnsupportedType(*target);
                        if !gaps.contains(&gap) {
                            gaps.push(gap)
                        }
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                target_types.extend(types.iter().map(|t| t.type_id));
                let marks = vec!["?"; types.len()].join(",");
                branches.push(format!("SELECT rr.src FROM data_fts JOIN data_record t ON t.id=data_fts.rowid JOIN data_ref rr INDEXED BY data_ref_dst ON rr.dst_scope=t.scope AND rr.dst=t.record WHERE data_fts.scope MATCH ? AND data_fts MATCH ? AND t.scope=? AND t.deleted=0 AND t.type IN ({marks}) AND rr.scope=? AND rr.path=?"));
                args.extend([
                    Sql::Text(text::scope_token(dst)),
                    Sql::Text(match_terms.clone()),
                    Sql::Integer(dst),
                ]);
                args.extend(types.iter().map(|t| Sql::Blob(t.type_id.0.to_vec())));
                args.extend([Sql::Integer(sid), Sql::Text(path.as_pointer())]);
            }
            targets.push((*readable, target_types));
        }
        if branches.is_empty() {
            " AND 0".to_owned()
        } else {
            p.args.extend(args);
            format!(" AND r.id IN ({})", branches.join(" UNION "))
        }
    } else {
        targets.push((source, members.iter().map(|t| t.type_id).collect()));
        let token = Sql::Text(text::scope_token(sid));
        let terms = Sql::Text(match_terms.clone());
        if selective_text(conn, sid, &match_terms, p)? {
            String::new()
        } else {
            // Keep logical index order. A rowid-constrained FTS probe tests each
            // candidate without materialising/sorting the entire hit set. The
            // query guard bounds sparse candidate walks as well as broad hits.
            p.args.extend([token, terms]);
            " AND EXISTS (SELECT 1 FROM data_fts WHERE rowid=r.id AND scope MATCH ? AND data_fts MATCH ?)"
                .to_owned()
        }
    };
    p.body.push_str(&predicate);
    p.sql.push_str(&predicate);
    // Cursor shape includes the text match (including require_revision). A
    // caller raising its freshness requirement must start a new page sequence.
    p.cursor_shape
        .push_str(&serde_json::to_string(request).map_err(|e| QueryError::Storage(e.to_string()))?);
    for (scope, types) in targets {
        let w = text::watermark_for_types(conn, scope, Some(&types))?;
        if let Some(required) = request.require_revision
            && w.complete_through < required
        {
            return Err(QueryError::TextBehind {
                watermark: w.complete_through,
                required,
            });
        }
        if w.complete_through < w.current {
            let gap = Gap::TextBehind {
                watermark: w.complete_through,
            };
            if !gaps.contains(&gap) {
                gaps.push(gap)
            }
        }
    }
    Ok(())
}
pub(super) fn aggregate(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    q: &Aggregate,
    budget: Budget,
) -> Result<AggregateResult, QueryError> {
    let sid = ids(conn, scope, reads)?;
    if q.max_groups == 0 || q.max_groups > 1000 {
        return Err(QueryError::not_queryable(
            None,
            "max_groups must be 1..=1000",
        ));
    }
    if sid < 0 {
        return Ok(AggregateResult {
            groups: vec![],
            completeness: Completeness::Incomplete(vec![Gap::NotCovered]),
        });
    }
    let guard = Guard::new(conn, budget)?;
    let members = check::members(conn, sid, core, &q.select).map_err(|e| guard.map(e, budget))?;
    if let Some(p) = &q.group_by {
        check::scalar(&members, p)?
    }
    for m in &q.measures {
        if let Measure::Sum(p) = m
            && !matches!(
                check::kind(&members, p)?,
                FieldKind::Integer | FieldKind::Number
            )
        {
            return Err(QueryError::TypeMismatch(p.clone()));
        }
    }
    let query_gaps = if let Some(f) = &q.filter {
        check::expression(conn, scope, reads, core, &members, f, false)
            .map_err(|e| guard.map(e, budget))?
    } else {
        vec![]
    };
    let mut p = plan::compile(
        conn,
        sid,
        scope,
        reads,
        core,
        &members,
        &q.select,
        q.filter.as_ref(),
        plan::Purpose::Filter,
    )
    .map_err(|e| guard.map(e, budget))?;
    let consulted = p.consulted.clone();
    let mut projections = vec![];
    if let Some(g) = &q.group_by {
        projections.push(plan::path_sql("r", g));
    }
    for m in &q.measures {
        projections.push(match m {
            Measure::Count => "count(*)".into(),
            Measure::Sum(path) => format!("sum({})", plan::path_sql("r", path)),
        })
    }
    if projections.is_empty() {
        return Err(QueryError::not_queryable(
            None,
            "aggregate requires measures",
        ));
    }
    let (terms, term_args) = p.seek_terms(false);
    p.sql = format!("SELECT {}{}{terms}", projections.join(","), p.body);
    p.args.extend(term_args);
    if q.group_by.is_some() {
        p.sql.push_str(" GROUP BY 1")
    }
    p.sql.push_str(" LIMIT ?");
    p.args.push(Sql::Integer(i64::from(q.max_groups) + 1));
    let mut st = conn.prepare(&p.sql).map_err(|e| guard.error(e, budget))?;
    let mut cursor = st
        .query(params_from_iter(p.args))
        .map_err(|e| guard.error(e, budget))?;
    let mut rows = vec![];
    while let Some(r) = cursor.next().map_err(|e| guard.error(e, budget))? {
        let start = usize::from(q.group_by.is_some());
        let key = if start > 0 {
            Some(sql_json(r.get(0).map_err(sql)?)?)
        } else {
            None
        };
        let mut values = vec![];
        for i in 0..q.measures.len() {
            values.push(sql_json(r.get(start + i).map_err(sql)?)?);
        }
        rows.push(AggregateGroup { key, values });
    }
    if rows.len() > q.max_groups as usize {
        return Err(QueryError::TooCostly {
            work: rows.len() as u64,
        });
    }
    let completeness = completeness(conn, sid, &consulted, &query_gaps, core, &members, &[])
        .map_err(|e| guard.map(e, budget))?;
    guard.ensure(budget)?;
    Ok(AggregateResult {
        groups: rows,
        completeness,
    })
}
fn sql_json(v: Sql) -> Result<Value, QueryError> {
    use crate::value::MAX_SAFE_INTEGER;
    // SUM can leave the input number profile even when every stored value is
    // valid. Check SQLite numbers before JSON can round them or turn infinity
    // into null, using the same integer-valued real rule as value::check.
    let unsafe_number = match &v {
        Sql::Integer(i) => !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(i),
        Sql::Real(n) => !n.is_finite() || (n.fract() == 0.0 && n.abs() > MAX_SAFE_INTEGER as f64),
        _ => false,
    };
    if unsafe_number {
        return Err(QueryError::not_queryable(
            None,
            "aggregate number outside interoperable range",
        ));
    }
    Ok(match v {
        Sql::Null => Value::Null,
        Sql::Integer(i) => i.into(),
        Sql::Real(n) => serde_json::json!(n),
        Sql::Text(s) => s.into(),
        Sql::Blob(b) => serde_json::json!(b),
    })
}

// Only a small target-index range should drive a Via. Counting at most 601
// entries is bounded regardless of library size; broader matches use the
// source-first page path (and its source sort index when requested).
const VIA_REVERSE_TARGET_LIMIT: i64 = 600;

// Positive conjuncts can supply a candidate set before any source record is
// opened. A backlink is always reverse-index driven; an indexed Via walks
// target entries, then their reverse references. The remaining expression is
// still applied by the caller, including other conjuncts.
#[allow(clippy::too_many_arguments)]
pub(super) fn reverse_source(
    conn: &Connection,
    source_id: i64,
    source: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    members: &[CompiledType],
    filter: Option<&Expr>,
) -> Result<Option<(String, Vec<Sql>)>, QueryError> {
    fn conjuncts<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
        if let Expr::And(parts) = expr {
            for part in parts {
                conjuncts(part, out)
            }
        } else {
            out.push(expr)
        }
    }
    let mut terms = vec![];
    if let Some(filter) = filter {
        conjuncts(filter, &mut terms)
    }
    for term in &terms {
        if let Expr::RefersTo { path, target } = term {
            let dst = target_scope(conn, source, reads, *target)?.unwrap_or(-1);
            return Ok(Some((" FROM data_ref driven INDEXED BY data_ref_dst CROSS JOIN data_record r WHERE driven.dst_scope=? AND driven.dst=? AND driven.scope=? AND driven.path=? AND r.id=driven.src AND r.scope=? AND r.deleted=0".into(),vec![Sql::Integer(dst),Sql::Blob(target.record.0.to_vec()),Sql::Integer(source_id),Sql::Text(path.as_pointer()),Sql::Integer(source_id)])));
        }
    }
    for term in &terms {
        let Expr::Via { path, filter } = term else {
            continue;
        };
        let FieldKind::Reference(spec) = check::kind(members, path)? else {
            unreachable!("checked Via")
        };
        let mut branches = vec![];
        let mut args = vec![];
        let mut matched_targets = 0i64;
        for audience in reads.iter().filter(|s| s.base == source.base) {
            let Some(target_scope) = records::lookup_scope(conn, *audience)? else {
                continue;
            };
            for target in &spec.targets {
                let selected = if spec.family {
                    TypeSelect::Family(*target)
                } else {
                    TypeSelect::Exact(*target)
                };
                let target_types = match check::members(conn, target_scope, core, &selected) {
                    Ok(types) => types,
                    Err(QueryError::UnknownType) => continue,
                    Err(e) => return Err(e),
                };
                let (ix, prefix, prefix_len) = match plan::choose(
                    conn,
                    target_scope,
                    &target_types,
                    &selected,
                    Some(filter),
                    plan::Purpose::Filter,
                ) {
                    Ok((Some(ix), prefix, len)) => (ix, prefix, len),
                    Ok((None, _, _))
                    | Err(QueryError::TooCostly { .. } | QueryError::IndexBuilding { .. }) => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                };
                // Count only the serving index range, not the whole target type.
                // Extra predicates can make the range less selective than the
                // actual filter; in that case source-first is still correct.
                let mut probe = String::from(
                    "SELECT count(*) FROM (SELECT 1 FROM data_index_entry te INDEXED BY data_index_entry_key WHERE te.ix=?",
                );
                let mut probe_args = vec![Sql::Integer(ix.id)];
                for (i, value) in prefix.iter().enumerate() {
                    probe.push_str(&format!(" AND te.k{}=?", i + 1));
                    probe_args.push(value.clone());
                }
                let range = plan::range_filter(Some(filter))
                    .filter(|(key, _, _)| ix.keys.get(prefix_len) == Some(key));
                if let Some((_, op, value)) = &range {
                    probe.push_str(&format!(" AND te.k{} {op} ?", prefix_len + 1));
                    probe_args.push(value.clone());
                }
                probe.push_str(" LIMIT ?) ");
                probe_args.push(Sql::Integer(VIA_REVERSE_TARGET_LIMIT + 1));
                let matches: i64 = conn
                    .query_row(&probe, params_from_iter(probe_args), |r| r.get(0))
                    .map_err(sql)?;
                matched_targets += matches;
                if matched_targets > VIA_REVERSE_TARGET_LIMIT {
                    return Ok(None);
                }
                let mut branch = String::from(
                    "SELECT rr.src FROM data_index_entry te INDEXED BY data_index_entry_key CROSS JOIN data_record t CROSS JOIN data_ref rr INDEXED BY data_ref_dst WHERE te.ix=?",
                );
                args.push(Sql::Integer(ix.id));
                for (i, value) in prefix.iter().enumerate() {
                    branch.push_str(&format!(" AND te.k{}=?", i + 1));
                    args.push(value.clone());
                }
                if let Some((_, op, value)) = range {
                    branch.push_str(&format!(" AND te.k{} {op} ?", prefix_len + 1));
                    args.push(value);
                }
                branch.push_str(" AND t.id=te.rec AND t.scope=? AND t.deleted=0 AND t.type IN (");
                args.push(Sql::Integer(target_scope));
                for (i, t) in target_types.iter().enumerate() {
                    if i > 0 {
                        branch.push(',')
                    }
                    branch.push('?');
                    args.push(Sql::Blob(t.type_id.0.to_vec()));
                }
                branch.push_str(
                    ") AND rr.dst_scope=? AND rr.dst=t.record AND rr.scope=? AND rr.path=? AND (",
                );
                args.push(Sql::Integer(target_scope));
                args.push(Sql::Integer(source_id));
                args.push(Sql::Text(path.as_pointer()));
                branch.push_str(&expression(
                    conn,
                    target_scope,
                    *audience,
                    reads,
                    core,
                    &target_types,
                    filter,
                    "t",
                    &mut args,
                )?);
                branch.push(')');
                branches.push(branch);
            }
        }
        if !branches.is_empty() {
            let sql = format!(
                " FROM ({}) candidates CROSS JOIN data_record r WHERE r.id=candidates.src AND r.scope=? AND r.deleted=0",
                branches.join(" UNION ")
            );
            args.push(Sql::Integer(source_id));
            return Ok(Some((sql, args)));
        }
    }
    Ok(None)
}
fn target_scope(
    conn: &Connection,
    source: Scope,
    reads: &[Scope],
    reference: RecordRef,
) -> Result<Option<i64>, QueryError> {
    let scope = Scope {
        base: source.base,
        audience: reference.audience.unwrap_or(source.audience),
    };
    if !reads.contains(&scope) {
        return Ok(None);
    }
    Ok(records::lookup_scope(conn, scope)?)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn expression(
    conn: &Connection,
    scope: i64,
    scope_value: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    members: &[CompiledType],
    expr: &Expr,
    alias: &str,
    args: &mut Vec<Sql>,
) -> Result<String, QueryError> {
    Ok(match expr {
        Expr::Cmp { path, op, value } => {
            let col = plan::path_sql(alias, path);
            if value.is_null() {
                format!(
                    "{col} IS {}NULL",
                    if matches!(op, CmpOp::Ne) { "NOT " } else { "" }
                )
            } else {
                args.push(plan::bind(value));
                format!(
                    "{col} {} ?",
                    match op {
                        CmpOp::Eq => "=",
                        CmpOp::Ne => "!=",
                        CmpOp::Lt => "<",
                        CmpOp::Le => "<=",
                        CmpOp::Gt => ">",
                        CmpOp::Ge => ">=",
                    }
                )
            }
        }
        Expr::In { path, values } => {
            if values.is_empty() {
                "0".into()
            } else {
                let col = plan::path_sql(alias, path);
                let non_null = values.iter().filter(|v| !v.is_null()).collect::<Vec<_>>();
                args.extend(non_null.iter().map(|v| plan::bind(v)));
                let contains_null = values.iter().any(Value::is_null);
                match (non_null.len(), contains_null) {
                    (0, true) => format!("{col} IS NULL"),
                    (n, true) => {
                        format!("({col} IN ({}) OR {col} IS NULL)", vec!["?"; n].join(","))
                    }
                    (n, false) => format!("{col} IN ({})", vec!["?"; n].join(",")),
                }
            }
        }
        Expr::IsNull(path) => format!("{} IS NULL", plan::path_sql(alias, path)),
        Expr::RefersTo { path, target } => {
            if let Some(dst) = target_scope(conn, scope_value, reads, *target)? {
                args.push(Sql::Integer(dst));
                args.push(Sql::Blob(target.record.0.to_vec()));
                args.push(Sql::Integer(scope));
                args.push(Sql::Text(path.as_pointer()));
                format!(
                    "{alias}.id IN (SELECT src FROM data_ref INDEXED BY data_ref_dst WHERE dst_scope=? AND dst=? AND scope=? AND path=?)"
                )
            } else {
                "0".into()
            }
        }
        Expr::Via { path, filter } => {
            let spec = check::kind(members, path)?;
            let mut parts = vec![];
            for audience in reads.iter().filter(|s| s.base == scope_value.base) {
                let Some(dst) = records::lookup_scope(conn, *audience)? else {
                    continue;
                };
                for target in check::reference_targets(spec) {
                    let select = if let FieldKind::Reference(r) = spec {
                        if r.family {
                            TypeSelect::Family(target)
                        } else {
                            TypeSelect::Exact(target)
                        }
                    } else {
                        unreachable!()
                    };
                    let types = match check::members(conn, dst, core, &select) {
                        Ok(types) => types,
                        Err(QueryError::UnknownType) => continue,
                        Err(e) => return Err(e),
                    };
                    // The source-first path has at most one dereferenced target
                    // per reference. Opening that target by scoped record id
                    // and evaluating its filter is cheaper than also opening
                    // an index entry by rec for each candidate source row.
                    // Keep the reference first: the scoped logical-order index
                    // must not make SQLite scan a target type for each source.
                    let mut local = vec![
                        Sql::Text(path.as_pointer()),
                        Sql::Integer(scope),
                        Sql::Integer(dst),
                        Sql::Integer(dst),
                    ];
                    let mut sub = format!(
                        "EXISTS (SELECT 1 FROM data_ref rf INDEXED BY data_ref_src CROSS JOIN data_record t ON t.record=rf.dst WHERE rf.src={alias}.id AND rf.path=? AND rf.scope=? AND rf.dst_scope=? AND t.scope=? AND t.deleted=0 AND t.type IN ("
                    );
                    for (i, t) in types.iter().enumerate() {
                        if i > 0 {
                            sub.push(',')
                        }
                        sub.push('?');
                        local.push(Sql::Blob(t.type_id.0.to_vec()));
                    }
                    sub.push_str(") AND (");
                    sub.push_str(&expression(
                        conn, dst, *audience, reads, core, &types, filter, "t", &mut local,
                    )?);
                    sub.push_str("))");
                    args.extend(local);
                    parts.push(sub);
                }
            }
            if parts.is_empty() {
                "0".into()
            } else {
                format!("({})", parts.join(" OR "))
            }
        }
        Expr::And(parts) | Expr::Or(parts) => {
            let mut clauses = vec![];
            for p in parts {
                clauses.push(expression(
                    conn,
                    scope,
                    scope_value,
                    reads,
                    core,
                    members,
                    p,
                    alias,
                    args,
                )?)
            }
            format!(
                "({})",
                if clauses.is_empty() {
                    if matches!(expr, Expr::And(_)) {
                        "1".to_string()
                    } else {
                        "0".to_string()
                    }
                } else {
                    clauses.join(if matches!(expr, Expr::And(_)) {
                        " AND "
                    } else {
                        " OR "
                    })
                }
            )
        }
        Expr::Not(e) => format!(
            "NOT ({})",
            expression(
                conn,
                scope,
                scope_value,
                reads,
                core,
                members,
                e,
                alias,
                args
            )?
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_sql_numbers_must_fit_the_json_profile() {
        for value in [
            Sql::Integer(9_007_199_254_740_993),
            Sql::Integer(-9_007_199_254_740_993),
            Sql::Real(9_007_199_254_740_992.0),
            Sql::Real(-9_007_199_254_740_992.0),
            Sql::Real(f64::INFINITY),
            Sql::Real(f64::NEG_INFINITY),
            Sql::Real(f64::NAN),
        ] {
            assert!(matches!(
                sql_json(value),
                Err(QueryError::NotQueryable { .. })
            ));
        }
        for (value, expected) in [
            (
                Sql::Integer(9_007_199_254_740_991),
                serde_json::json!(9_007_199_254_740_991i64),
            ),
            (
                Sql::Real(9_007_199_254_740_991.0),
                serde_json::json!(9_007_199_254_740_991.0),
            ),
            (
                Sql::Real(-9_007_199_254_740_991.0),
                serde_json::json!(-9_007_199_254_740_991.0),
            ),
            (Sql::Real(0.75), serde_json::json!(0.75)),
            (Sql::Null, Value::Null),
        ] {
            assert_eq!(sql_json(value).unwrap(), expected);
        }
    }
}
