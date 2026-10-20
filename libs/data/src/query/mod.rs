//! Live typed queries over the scoped, derived SQLite indexes. Pagination is
//! keyset based but is not snapshot-stable across concurrent edits. A cursor
//! names the access path it was issued for; if a different index serves the
//! query on a later page (one finished building), the cursor is rejected.
//! Requested sort keys are followed by the full logical record ID (descending
//! when all requested keys descend, ascending otherwise), never by local rowid
//! or unused composite-index fields. With no sort, exact types use logical ID
//! ascending; families use concrete type ID then logical ID ascending, including
//! text and reference queries. Local index availability cannot change this order.
//! An index must cover the complete requested order after equality-bound keys;
//! otherwise only small types use the bounded sort fallback. Larger unmatched
//! sorts return `TooCostly` (or `IndexBuilding` for a suitable building index).
//! Exact unsorted pages can seek indexes whose declared keys are all equality
//! bound. Other unsorted filters and broad text walk logical order under the VM
//! budget; sparse matches can return `TooCostly`. Direct-text queries probe at
//! most 2,001 scoped FTS hits and drive/sort at most 2,000 candidates (the shared
//! fallback-sort allowance), before applying the page limit. Larger hit sets
//! retain the guarded logical/index-order walk, never an unbounded candidate
//! sort. Both strategies keep the same order/cursor and unchanged VM budget.
//! Aggregates use selective filter indexes without page-order rules;
//! numeric results outside the interoperable JSON profile return `NotQueryable`.
//! Old integer-tie cursors are invalid; row DTOs and internal join IDs are unchanged.
//! `Ne` and `Not` use SQL three-valued logic: missing fields do not match
//! `!=` or `NOT (=)`. A page currently reads each matching row's whole JSON
//! document even if an Atomic field was not requested; work is page-bounded.
mod ast;
mod check;
mod cursor;
mod exec;
mod plan;
use crate::{CoreCatalogue, RecordId, Scope};
pub use ast::*;
use rusqlite::Connection;
/// Native adapter for a `$changed desc` page whose boundary carries the
/// numeric sort key and logical record ID rather than an opaque cursor.
/// Other query shapes and invalid key values are refused, as are stale cursors
/// when the query plan changes between pages.
pub fn after_changed(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    q: &Query,
    changed: i64,
    record: RecordId,
) -> Result<Cursor, QueryError> {
    exec::after_changed(conn, scope, reads, core, q, changed, record)
}
pub fn run(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    q: &Query,
    budget: Budget,
) -> Result<Page, QueryError> {
    exec::run(conn, scope, reads, core, q, budget)
}
pub fn aggregate(
    conn: &Connection,
    scope: Scope,
    reads: &[Scope],
    core: &dyn CoreCatalogue,
    q: &Aggregate,
    budget: Budget,
) -> Result<AggregateResult, QueryError> {
    exec::aggregate(conn, scope, reads, core, q, budget)
}
