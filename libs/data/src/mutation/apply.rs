//! Ordered materialization: every replica applies the same server-ordered
//! operations and reaches the same accepted state.
//!
//! An operation that cannot be decided yet (a missing definition or record,
//! uniqueness this replica cannot prove) parks in `data_parked` at its
//! position under an *affects key*:
//!
//! - `""`: the whole typed scope;
//! - `a:<app>`: an app's definition state;
//! - `t:<type>`: a type's definitions and rules, or a uniqueness family;
//! - `r:<record>`: one record (`data_parked.type` holds its concrete type when known).
//!
//! While any queue exists, a later operation that overlaps a parked one parks
//! behind it without evaluation (`Waiting(Queued)`), so replaying parked work
//! in position order reproduces the verdicts other replicas reached directly.
//! Each park row also records what the operation touches (`record`, `type`,
//! the unique families in `uniques`, the `app` whose state it reads), whatever
//! key it waits under, and whether it `holds` later definitions; the overlap
//! relation is the table at [`blocked`].
//!
//! Evaluation at position `p` reads only definitions, rules and app states
//! accepted before `p`. Unique indexes are the exception: they follow the
//! latest declarations, so a later definition that retires one would leave an
//! earlier operation waiting on uniqueness unanswerable on replay. A parked
//! operation therefore holds overlapping definitions unless it waits for an
//! unknown core revision (directly, or queued only behind such waits): that
//! wait may outlast this executable, and holding definitions behind it would
//! stall them for as long.
//!
//! A payload this executable cannot read (an unknown version or operation
//! kind) parks with `Waiting(Unsupported)` under the key its header's
//! `affects` names: `r:<record>`, else `t:<type>`, else the whole scope. Its
//! row holds definitions and, for a record, counts as touching every unique
//! family of the record's type (its accepted type here, else any family).
//! Later overlapping operations queue behind it like any parked row, so a
//! newer executable's [`retry_parked`] replays it in order. A malformed
//! payload is rejected and never parked. Known limit: a member who may write
//! to the scope can stall a record, a type or the whole typed scope on every
//! executable that cannot read such a payload, for as long as it cannot (see
//! [`payload`]); the same holds for an unknown core revision.
//!
//! Hex is lowercase. A position at or before the scope's last applied one is
//! a redelivery (`Duplicate`); the host advances coverage, this module does not.
use std::cell::Cell;

use rusqlite::{OptionalExtension, Transaction, params, params_from_iter, types::Value as Sql};

use super::{
    checks::touched_uniques,
    define, definition_at,
    eval::{self, Ctx, DefinitionPlan, Mode, Park, Plan, RecordPlan, State, Verdict},
    hex, history, hooks,
    ops::{FieldChange, Operation},
    pending, rejection,
};
use crate::{
    Actor, AppId, CompiledType, CoreCatalogue, DataError, FieldPath, MutationId, Position,
    RecordId, RejectCode, Rejection, Scope, TypeId, Wait, definition, index,
    payload::{self, Affects, Decoded},
    store::{
        actor as actor_store, corrupt, id, integer,
        records::{self, RecordRow},
        registry, sql, unsigned,
    },
};

pub struct Ordered<'a> {
    pub scope: Scope,
    pub position: Position,
    pub actor: &'a Actor,
    pub mutation: MutationId,
    pub op: &'a Operation,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Accepted {
        record: Option<RecordId>,
        /// Undo paths changed since by later edits and therefore left alone.
        skipped: Vec<FieldPath>,
    },
    Rejected(Rejection),
    Waiting(Wait),
    /// The position was already applied here: a redelivery, with no effect.
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Scope,
    App(AppId),
    Type(TypeId),
    Record(RecordId),
}

impl Key {
    pub fn encode(&self) -> String {
        match self {
            Self::Scope => String::new(),
            Self::App(app) => format!("a:{}", hex(&app.0)),
            Self::Type(type_id) => format!("t:{}", hex(&type_id.0)),
            Self::Record(record) => format!("r:{}", hex(&record.0)),
        }
    }
}

/// Applies the payload ordered at `position` in `scope`: the host's entry
/// point. The exact bytes are kept for parking and for recognising this
/// replica's own pending work. Materialization reads only `scope`. Every
/// outcome other than `Waiting` is final for the position.
pub fn apply_payload(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    position: Position,
    actor: &Actor,
    bytes: &[u8],
) -> Result<Outcome, DataError> {
    apply_payload_with_admission(
        tx,
        core,
        scope,
        position,
        actor,
        bytes,
        &crate::admission::Unavailable,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn apply_payload_with_admission(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    position: Position,
    actor: &Actor,
    bytes: &[u8],
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Outcome, DataError> {
    apply_decoded(
        tx,
        core,
        scope,
        position,
        actor,
        bytes,
        payload::decode(bytes),
        admission,
    )
}

/// [`apply_payload`] with the payload already decoded by the caller.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_decoded(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    position: Position,
    actor: &Actor,
    bytes: &[u8],
    decoded: Decoded,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Outcome, DataError> {
    let sid = records::scope_id(tx, scope, core)?;
    if !advance(tx, sid, position)? {
        return Ok(Outcome::Duplicate);
    }
    settle(
        tx,
        core,
        scope,
        sid,
        position,
        actor,
        bytes,
        decoded,
        admission,
        Blockers::All,
    )
}

/// Applies an operation that is already decoded, as if ordered in the
/// payload [`payload::encode`] produces for it.
pub fn apply_ordered(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    ev: &Ordered<'_>,
) -> Result<Outcome, DataError> {
    apply_ordered_with_admission(tx, core, ev, &crate::admission::Unavailable)
}

pub fn apply_ordered_with_admission(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    ev: &Ordered<'_>,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Outcome, DataError> {
    let bytes = payload::encode(ev.mutation, ev.op)?;
    let sid = records::scope_id(tx, ev.scope, core)?;
    if !advance(tx, sid, ev.position)? {
        return Ok(Outcome::Duplicate);
    }
    queue_or_apply(tx, core, sid, ev, &bytes, admission, Blockers::All)
}

/// Replays every parked row of `scope` in position order and returns the
/// positions and outcomes that reached a final verdict. A row stays parked
/// if it still waits, or overlaps an earlier row that still waits: replaying one queue at a time
/// could reorder operations that sit in two queues. Each row's queue and
/// holds are recomputed as on arrival. The host calls this after a
/// dependency arrives (a definition, coverage, a newer executable) and after
/// an index finishes building. Costs one pass over the scope's parked rows.
pub fn retry_parked(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    retry_parked_with_admission(tx, core, scope, &crate::admission::Unavailable)
}

pub fn retry_parked_with_admission(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    retry_with(tx, core, scope, &payload::decode, admission)
}

/// Whether `scope` has parked ordered work. One probe, for a host that
/// replays parked work only when a batch brought a dependency.
pub fn has_parked(tx: &Transaction<'_>, scope: Scope) -> Result<bool, DataError> {
    let Some(sid) = records::lookup_scope(tx, scope)? else {
        return Ok(false);
    };
    any_parked(tx, sid)
}

/// [`retry_parked`] reading each parked payload with `decode`.
pub(crate) fn retry_with(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    decode: &dyn Fn(&[u8]) -> Decoded,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    let Some(sid) = records::lookup_scope(tx, scope)? else {
        return Ok(Vec::new());
    };
    // Cost: O(parked rows in the scope) per call, every one re-decoded and
    // re-parked if it still waits; exercised by the public scale example.
    let mut rows = tx
        .prepare_cached("DELETE FROM data_parked WHERE scope=?1 RETURNING position,payload,actor")
        .map_err(sql)?
        .query_map([sid], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    rows.sort_unstable_by_key(|(position, _, _)| *position);
    let mut decided = Vec::new();
    for (position, bytes, actor) in rows {
        let actor = actor_store::get(tx, actor)?;
        let position = Position(unsigned(position)?);
        let outcome = settle(
            tx,
            core,
            scope,
            sid,
            position,
            &actor,
            &bytes,
            decode(&bytes),
            admission,
            Blockers::All,
        )?;
        if !matches!(outcome, Outcome::Waiting(_)) {
            decided.push((position, outcome));
        }
    }
    Ok(decided)
}

/// Replays the parked rows of `scope` waiting under `key` only, in position
/// order, and returns the decided positions and outcomes. A host calls this for a
/// dependency that names one record (a Note projection arriving, its gap
/// clearing, its held candidates being released), so the cost is one pass over
/// that record's queue rather than the whole scope's. Ordering and overlap are
/// the same as [`retry_parked`]: a row that still waits, or that overlaps an
/// earlier row still parked, stays parked. If this pass decides anything, it
/// also re-settles queued rows in the scope, in position order: they may have
/// waited behind the keyed row while naming a different dependency.
/// Rows at later positions cannot block an earlier replayed row; unresolved
/// dependencies can still leave it parked until a later trigger or upgrade.
pub fn retry_parked_for(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    key: Key,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    retry_parked_for_with_admission(tx, core, scope, key, &crate::admission::Unavailable)
}

/// Targeted replay with the host's admission evidence for ordered definitions.
pub fn retry_parked_for_with_admission(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    key: Key,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    retry_for_with(tx, core, scope, key, &payload::decode, admission)
}

/// [`retry_parked_for`] reading each parked payload with `decode`.
pub(crate) fn retry_for_with(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    key: Key,
    decode: &dyn Fn(&[u8]) -> Decoded,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    let Some(sid) = records::lookup_scope(tx, scope)? else {
        return Ok(Vec::new());
    };
    // One pass over the rows waiting on this key, through the affects index.
    let mut rows = tx
        .prepare_cached(
            "DELETE FROM data_parked WHERE scope=?1 AND affects=?2
             RETURNING position,payload,actor",
        )
        .map_err(sql)?
        .query_map(params![sid, key.encode()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    rows.sort_unstable_by_key(|(position, _, _)| *position);
    let mut decided = Vec::new();
    for (position, bytes, actor) in rows {
        let actor = actor_store::get(tx, actor)?;
        let position = Position(unsigned(position)?);
        let outcome = settle(
            tx,
            core,
            scope,
            sid,
            position,
            &actor,
            &bytes,
            decode(&bytes),
            admission,
            Blockers::Before(position),
        )?;
        if !matches!(outcome, Outcome::Waiting(_)) {
            decided.push((position, outcome));
        }
    }
    if !decided.is_empty() {
        // Queued is stored as JSON by insert_park. This partial index bounds
        // the extra pass to rows that could have waited behind the keyed row.
        let mut queued = tx
            .prepare_cached(
                "DELETE FROM data_parked INDEXED BY data_parked_queued
                 WHERE scope=?1 AND reason='\"Queued\"'
                 RETURNING position,payload,actor",
            )
            .map_err(sql)?
            .query_map([sid], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        queued.sort_unstable_by_key(|(position, _, _)| *position);
        for (position, bytes, actor) in queued {
            let actor = actor_store::get(tx, actor)?;
            let outcome = settle(
                tx,
                core,
                scope,
                sid,
                Position(unsigned(position)?),
                &actor,
                &bytes,
                decode(&bytes),
                admission,
                Blockers::Before(Position(unsigned(position)?)),
            )?;
            if !matches!(outcome, Outcome::Waiting(_)) {
                decided.push((Position(unsigned(position)?), outcome));
            }
        }
    }
    Ok(decided)
}

/// Bounds for one page of a scope replay pass. A page always settles at least
/// one row; it stops before a row that would take it past `bytes`, and before
/// the next row once `vm_steps` SQLite VM steps are used. A single row can
/// overrun the step bound by its own evaluation: rows are never interrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayLimits {
    pub rows: usize,
    pub bytes: usize,
    pub vm_steps: u64,
}

/// One page of a scope replay pass, committed by the host's transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayPage {
    pub scope: Scope,
    /// Positions this page decided, in position order, for the host to settle
    /// its own outbox in the same transaction.
    pub decided: Vec<(Position, Outcome)>,
    /// Parked rows settled, and their stored payload bytes.
    pub rows: usize,
    pub bytes: usize,
    /// SQLite VM steps counted across the page.
    pub vm_steps: u64,
    /// The scope's pass ended with this page; its marker is gone.
    pub finished: bool,
}

/// Queues a pass over `sid`'s parked rows, ordered no later than the last row
/// parked now, or restarts a queued pass from its first row: a new dependency
/// can unblock rows the pass has already visited. The dependency's own
/// transaction does no replay; [`replay_page_with_admission`] runs the pass in
/// bounded pages. Returns false, queuing nothing, when no row is parked.
pub fn schedule_replay(tx: &Transaction<'_>, sid: i64) -> Result<bool, DataError> {
    let upper: Option<i64> = tx
        .query_row(
            "SELECT max(position) FROM data_parked WHERE scope=?1",
            [sid],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let Some(upper) = upper else {
        return Ok(false);
    };
    tx.execute(
        "INSERT INTO data_replay(scope,cursor,upper,decided) VALUES(?1,-1,?2,0)
         ON CONFLICT(scope) DO UPDATE SET cursor=-1,upper=excluded.upper,decided=0",
        params![sid, upper],
    )
    .map_err(sql)?;
    Ok(true)
}

/// Whether any scope has a queued replay pass (one probe).
pub fn replay_pending(conn: &rusqlite::Connection) -> Result<bool, DataError> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM data_replay)", [], |r| r.get(0))
        .map_err(sql)
}

/// Settles the next page of one queued scope pass, in position order, and
/// advances its durable cursor in the caller's transaction. The pass reaches
/// the verdicts [`retry_parked`] would: a row is blocked only by rows ordered
/// before it, which this pass has already visited, so unvisited later rows
/// never hold it back. A row that still waits stays parked and the cursor
/// moves past it; the pass ends at its captured last row and removes its
/// marker, so a permanent wait does not keep it running. Each pass still
/// scans earlier parked overlaps per row; a large backlog can cost quadratic
/// total work, as in the unpaged whole-scope pass. If the pass decided
/// anything, rows parked after it was queued may have queued behind those
/// decisions, so it extends over them, and again after that extension only
/// if it decided something there. `None` when no pass is queued.
pub fn replay_page_with_admission(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    limits: ReplayLimits,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Option<ReplayPage>, DataError> {
    let marker: Option<(i64, i64, i64, bool)> = tx
        .query_row(
            "SELECT scope,cursor,upper,decided FROM data_replay ORDER BY scope LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((sid, mut cursor, mut upper, mut decided_any)) = marker else {
        return Ok(None);
    };
    let scope = super::pending::scope_of(tx, sid)?;
    // Sizes come from the primary key and stored lengths; payloads are read
    // one row at a time, only for rows this page settles.
    let candidates = tx
        .prepare_cached(
            "SELECT position,length(payload) FROM data_parked
             WHERE scope=?1 AND position>?2 AND position<=?3 ORDER BY position LIMIT ?4",
        )
        .map_err(sql)?
        .query_map(
            params![sid, cursor, upper, limits.rows.max(1) as i64],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    let meter = index::WorkMeter::new(tx, limits.vm_steps)?;
    let mut page = ReplayPage {
        scope,
        decided: Vec::new(),
        rows: 0,
        bytes: 0,
        vm_steps: 0,
        finished: false,
    };
    for (position, len) in candidates {
        let len = usize::try_from(len).map_err(corrupt)?;
        if page.rows > 0 && (page.bytes + len > limits.bytes || meter.exhausted()) {
            break;
        }
        let (bytes, actor): (Vec<u8>, i64) = tx
            .query_row(
                "DELETE FROM data_parked WHERE scope=?1 AND position=?2 RETURNING payload,actor",
                params![sid, position],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(sql)?;
        let actor = actor_store::get(tx, actor)?;
        let at = Position(unsigned(position)?);
        let outcome = settle(
            tx,
            core,
            scope,
            sid,
            at,
            &actor,
            &bytes,
            payload::decode(&bytes),
            admission,
            Blockers::Before(at),
        )?;
        if !matches!(outcome, Outcome::Waiting(_)) {
            page.decided.push((at, outcome));
        }
        page.rows += 1;
        page.bytes += len;
        cursor = position;
    }
    page.vm_steps = meter.used();
    drop(meter);
    decided_any |= !page.decided.is_empty();
    let more: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM data_parked WHERE scope=?1 AND position>?2 AND position<=?3)",
            params![sid, cursor, upper],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let mut extended = false;
    if !more && decided_any {
        let later: Option<i64> = tx
            .query_row(
                "SELECT max(position) FROM data_parked WHERE scope=?1 AND position>?2",
                params![sid, upper],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if let Some(later) = later {
            cursor = upper;
            upper = later;
            decided_any = false;
            extended = true;
        }
    }
    if more || extended {
        tx.execute(
            "UPDATE data_replay SET cursor=?2,upper=?3,decided=?4 WHERE scope=?1",
            params![sid, cursor, upper, decided_any],
        )
        .map_err(sql)?;
    } else {
        tx.execute("DELETE FROM data_replay WHERE scope=?1", [sid])
            .map_err(sql)?;
        page.finished = true;
    }
    Ok(Some(page))
}

/// Records `position` as applied; false if it already was (a redelivery,
/// recognised by log position alone as the host log does; a reused mutation
/// id is applied on its merits).
fn advance(tx: &Transaction<'_>, sid: i64, position: Position) -> Result<bool, DataError> {
    if last_position(tx, sid)?.is_some_and(|last| position <= last) {
        return Ok(false);
    }
    set_last(tx, sid, position)?;
    Ok(true)
}

/// Decides a decoded payload at its position: malformed is rejected,
/// unsupported parks, an operation queues or applies.
#[allow(clippy::too_many_arguments)]
fn settle(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    sid: i64,
    position: Position,
    actor: &Actor,
    bytes: &[u8],
    decoded: Decoded,
    admission: &dyn crate::admission::HostAdmission,
    blockers: Blockers,
) -> Result<Outcome, DataError> {
    match decoded {
        Decoded::Malformed(detail) => Ok(Outcome::Rejected(rejection(
            RejectCode::Schema,
            None,
            format!("malformed payload: {detail}"),
        ))),
        Decoded::Unsupported { affects, .. } => {
            park_unsupported(tx, core, sid, position, actor, bytes, &affects)?;
            Ok(Outcome::Waiting(Wait::Unsupported))
        }
        Decoded::Confirmed(mutation, op, _) | Decoded::Op(mutation, op) => queue_or_apply(
            tx,
            core,
            sid,
            &Ordered {
                scope,
                position,
                actor,
                mutation,
                op: &op,
            },
            bytes,
            admission,
            blockers,
        ),
    }
}

/// Which parked rows can block an operation being settled. Arrival and the
/// existing replays see every parked row (a replay deletes its candidates
/// first, so only rows it already re-parked remain). A paged scope pass
/// leaves its unvisited rows in place, so it counts only rows ordered before
/// the one it settles: exactly the rows a whole-scope pass would have
/// re-parked by then.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Blockers {
    All,
    Before(Position),
}

fn queue_or_apply(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    sid: i64,
    ev: &Ordered<'_>,
    bytes: &[u8],
    admission: &dyn crate::admission::HostAdmission,
    blockers: Blockers,
) -> Result<Outcome, DataError> {
    if let Some(park) = queued(tx, core, sid, ev.op, Some(ev.position), blockers)? {
        park_op(tx, core, sid, ev, bytes, &park, &Wait::Queued)?;
        return Ok(Outcome::Waiting(Wait::Queued));
    }
    apply_at(tx, core, sid, ev, bytes, admission)
}

/// The evaluator never treats a host's device/position attestation as the
/// person's confirmation. Exact prior rules must also be in the signed typed
/// payload. Re-decoding here covers direct delivery and every parked replay.
struct PayloadAdmission<'a> {
    host: &'a dyn crate::admission::HostAdmission,
    prior: Option<crate::admission::PriorRules>,
    position: Position,
    actor: &'a Actor,
}
impl crate::admission::HostAdmission for PayloadAdmission<'_> {
    fn confirms(
        &self,
        request: &crate::admission::Confirmation,
        at: Option<Position>,
    ) -> Result<bool, DataError> {
        if at != Some(self.position)
            || &request.actor != self.actor
            || !matches!(self.actor, Actor::Device { .. })
            || self.prior.as_ref() != Some(&request.prior)
        {
            return Ok(false);
        }
        self.host.confirms(request, at)
    }
    fn may_read_source(
        &self,
        actor: &Actor,
        source: Scope,
        at: Option<Position>,
    ) -> Result<bool, DataError> {
        self.host.may_read_source(actor, source, at)
    }
}

/// Evaluates and commits one operation at its position, skipping the
/// duplicate, position and queue checks.
fn apply_at(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    sid: i64,
    ev: &Ordered<'_>,
    bytes: &[u8],
    admission: &dyn crate::admission::HostAdmission,
) -> Result<Outcome, DataError> {
    let prior = if matches!(
        ev.op,
        Operation::DefineType { .. }
            | Operation::SetAppState { .. }
            | Operation::BindCore { .. }
            | Operation::Transition { .. }
    ) {
        match payload::decode(bytes) {
            Decoded::Confirmed(mutation, ref op, prior)
                if mutation == ev.mutation && op == ev.op =>
            {
                Some(prior)
            }
            _ => None,
        }
    } else {
        None
    };
    let checked = PayloadAdmission {
        host: admission,
        prior,
        position: ev.position,
        actor: ev.actor,
    };
    let ctx = Ctx {
        tx,
        core,
        scope: ev.scope,
        sid,
        actor: ev.actor,
        admission: &checked,
        mode: Mode::Ordered(ev.position),
        waiting: Cell::new(false),
    };
    let verdict = match ev.op.record() {
        None => define::definition(&ctx, ev.op)?,
        Some(record) => {
            let state = State::accepted(records::get(tx, sid, record)?);
            eval::record(&ctx, record, &state, ev.op)?
        }
    };
    Ok(match verdict {
        Verdict::Accept(Plan::Record(plan)) => {
            commit_record(&ctx, ev, bytes, &plan)?;
            Outcome::Accepted {
                record: Some(plan.record),
                skipped: plan.skipped,
            }
        }
        Verdict::Accept(Plan::Definition(plan)) => {
            commit_definition(&ctx, ev, bytes, plan)?;
            Outcome::Accepted {
                record: None,
                skipped: Vec::new(),
            }
        }
        Verdict::Confirm(_) => {
            let denied = rejection(
                RejectCode::Unauthorized,
                None,
                "exact host confirmation required",
            );
            reject_own(&ctx, ev, bytes, &denied)?;
            Outcome::Rejected(denied)
        }
        Verdict::Reject(rejection) => {
            reject_own(&ctx, ev, bytes, &rejection)?;
            Outcome::Rejected(rejection)
        }
        Verdict::Wait(wait, park) => {
            park_op(tx, core, sid, ev, bytes, &park, &wait)?;
            Outcome::Waiting(wait)
        }
    })
}

pub(crate) fn text_hook(
    tx: &Transaction<'_>,
    row: &RecordRow,
    ct: &CompiledType,
) -> Result<(), DataError> {
    crate::text::on_record_changed(tx, row, ct)
}

fn commit_record(
    ctx: &Ctx<'_, '_>,
    ev: &Ordered<'_>,
    bytes: &[u8],
    plan: &RecordPlan,
) -> Result<(), DataError> {
    let mut row = records::get(ctx.tx, ctx.sid, plan.record)?.unwrap_or(RecordRow {
        id: 0,
        scope: ctx.sid,
        record: plan.record,
        type_id: plan.ct.type_id,
        revision: plan.ct.revision,
        accepted: None,
        doc: None,
        deleted: false,
        pending: false,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    });
    row.type_id = plan.ct.type_id;
    row.revision = plan.revision;
    row.accepted = plan.doc.clone();
    row.changed_at = Some(ev.position);
    if row.id == 0 {
        records::put(ctx.tx, &mut row)?;
    }
    history::record(ctx.tx, row.id, ev.position, ev.mutation, ev.actor, plan)?;
    retire_own(ctx.tx, ev, bytes)?;
    pending::refresh(ctx.tx, ctx.core, ctx.scope, ctx.sid, &mut row)?;
    records::put(ctx.tx, &mut row)?;
    // Replayed work was judged by the rules at its position; derived state
    // (indexes, references) follows the type's latest definition.
    if registry::changed_since(ctx.tx, ctx.sid, plan.ct.type_id, ev.position)?
        && let Some(latest) = registry::current(ctx.tx, ctx.sid, plan.ct.type_id, ctx.core)?
    {
        return hooks(ctx.tx, &row, &latest);
    }
    hooks(ctx.tx, &row, &plan.ct)
}

fn commit_definition(
    ctx: &Ctx<'_, '_>,
    ev: &Ordered<'_>,
    bytes: &[u8],
    plan: DefinitionPlan,
) -> Result<(), DataError> {
    match plan {
        DefinitionPlan::App { app, name } => {
            registry::set_app(ctx.tx, ctx.sid, app, &name, true, ev.position)?
        }
        DefinitionPlan::AppState { app, active } => {
            registry::set_app_active(ctx.tx, ctx.sid, app, active, ev.position)?;
            pending::refresh_where(ctx.tx, ctx.core, ctx.scope, ctx.sid, &|ct| {
                ct.app == Some(app)
            })?;
        }
        DefinitionPlan::Type {
            ct,
            bytes,
            permitted,
        } => {
            registry::store_definition(ctx.tx, ctx.sid, &ct, &bytes, ev.position)?;
            if let Some(permitted) = permitted {
                activate(ctx, &ct, &permitted, ev.position)?;
            }
        }
        DefinitionPlan::Rules {
            type_id,
            current,
            permitted,
            core,
        } => {
            if let Some(core) = &core {
                registry::store_core(ctx.tx, ctx.sid, core, ev.position)?;
            }
            let ct = registry::compiled(ctx.tx, ctx.sid, current)?
                .filter(|ct| ct.type_id == type_id)
                .ok_or_else(|| DataError::Corrupt("activated revision missing".into()))?;
            activate(ctx, &ct, &permitted, ev.position)?;
        }
    }
    retire_own(ctx.tx, ev, bytes)?;
    Ok(())
}

/// Makes `ct` its type's current revision with `permitted` writers. Index
/// work follows only a change in declared indexes or uniques, so a
/// documentation-only revision causes none; local overlays of the family's
/// pending work are re-derived under the new rules.
fn activate(
    ctx: &Ctx<'_, '_>,
    ct: &CompiledType,
    permitted: &[crate::RevisionId],
    at: Position,
) -> Result<(), DataError> {
    let previous = registry::current(ctx.tx, ctx.sid, ct.type_id, ctx.core)?;
    registry::set_current(ctx.tx, ctx.sid, ct.type_id, ct.revision, permitted, at)?;
    if previous.as_ref().is_some_and(|p| p.search != ct.search) {
        crate::text_reproject::schedule(ctx.tx, ctx.sid, ct)?;
    } else {
        // A doc-only revision keeps the same mapping and completed cursor,
        // but a pending task must follow the new effective contract identity.
        ctx.tx
            .execute(
                "UPDATE data_text_mapping SET revision=?3 WHERE scope=?1 AND type=?2",
                params![ctx.sid, ct.type_id.0.as_slice(), ct.revision.0.as_slice()],
            )
            .map_err(sql)?;
    }
    if previous.is_none_or(|p| p.indexes != ct.indexes || p.uniques != ct.uniques) {
        index::on_definitions_changed(ctx.tx, ctx.sid, ctx.core)?;
    }
    pending::refresh_family(ctx.tx, ctx.core, ctx.scope, ctx.sid, ct.type_id)
}

/// This replica's own pending work for an ordered operation: the row with the
/// same mutation id, actor and payload bytes, as ordered (never re-encoded).
/// Any other operation using that mutation id is someone else's, and the
/// pending row stays.
const OWN: &str = "mutation=?1 AND actor=?2 AND payload=?3";

fn own(tx: &Transaction<'_>, ev: &Ordered<'_>, bytes: &[u8]) -> Result<[Sql; 3], DataError> {
    Ok([
        Sql::Blob(ev.mutation.0.to_vec()),
        Sql::Integer(actor_store::find(tx, ev.actor)?.unwrap_or(0)),
        Sql::Blob(bytes.to_vec()),
    ])
}

/// This replica's own work that was accepted: it is now part of accepted state.
fn retire_own(tx: &Transaction<'_>, ev: &Ordered<'_>, bytes: &[u8]) -> Result<(), DataError> {
    tx.execute(
        &format!("DELETE FROM data_pending WHERE {OWN}"),
        params_from_iter(own(tx, ev, bytes)?),
    )
    .map_err(sql)?;
    Ok(())
}

/// This replica's own work that lost: kept, with its rejection, for recovery.
fn reject_own(
    ctx: &Ctx<'_, '_>,
    ev: &Ordered<'_>,
    bytes: &[u8],
    rejection: &Rejection,
) -> Result<(), DataError> {
    let mut args = own(ctx.tx, ev, bytes)?.to_vec();
    args.push(Sql::Text(
        serde_json::to_string(rejection).map_err(corrupt)?,
    ));
    let record: Option<Option<Vec<u8>>> = ctx
        .tx
        .query_row(
            &format!(
                "UPDATE data_pending SET state='rejected',rejection=?4 WHERE {OWN} RETURNING rec_id"
            ),
            params_from_iter(args),
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(Some(record)) = record {
        pending::rewrite(ctx.tx, ctx.core, ctx.scope, ctx.sid, RecordId(id(record)?))?;
    }
    Ok(())
}

fn last_position(tx: &Transaction<'_>, sid: i64) -> Result<Option<Position>, DataError> {
    let last: Option<i64> = tx
        .query_row(
            "SELECT position FROM data_ordered WHERE scope=?1",
            [sid],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    last.map(|p| unsigned(p).map(Position)).transpose()
}

fn set_last(tx: &Transaction<'_>, sid: i64, position: Position) -> Result<(), DataError> {
    tx.execute(
        "INSERT INTO data_ordered(scope,position) VALUES(?1,?2)
         ON CONFLICT(scope) DO UPDATE SET position=excluded.position",
        params![sid, integer(position.0)?],
    )
    .map_err(sql)?;
    Ok(())
}

fn any_parked(tx: &Transaction<'_>, sid: i64) -> Result<bool, DataError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_parked WHERE scope=?1)",
        [sid],
        |r| r.get(0),
    )
    .map_err(sql)
}

fn park_op(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    sid: i64,
    ev: &Ordered<'_>,
    bytes: &[u8],
    park: &Park,
    wait: &Wait,
) -> Result<(), DataError> {
    tx.execute(
        &format!("UPDATE data_pending SET state='waiting' WHERE {OWN} AND state='pending'"),
        params_from_iter(own(tx, ev, bytes)?),
    )
    .map_err(sql)?;
    let touch = touch(tx, core, sid, ev.op, Some(ev.position))?;
    // Known limit: the families are those declared at this row's position. A
    // unique added later over a field it changes is not seen as overlapping;
    // that matters only if the row is replayed by a newer executable that
    // knows a revision this one did not (core-version skew).
    insert_park(
        tx,
        &ParkRow {
            sid,
            position: ev.position,
            key: park.key,
            bytes,
            actor: ev.actor,
            wait,
            mutation: Some(ev.mutation),
            type_id: touch.type_id,
            unresolved_type: match touch.type_id {
                Some(ty) => registry::current(tx, sid, ty, core)?.is_none(),
                None => true,
            },
            record: touch.record,
            uniques: touch.record.and(touch.uniques),
            app: touch.reads_app,
            holds: park.holds,
        },
    )
}

/// Parks a payload this executable cannot read under the key its `affects`
/// names. It may change anything there, so a record row counts as touching
/// every unique family of the record's type (any family when that type is
/// unknown here) and reading its app's state, and the row holds definitions.
fn park_unsupported(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    sid: i64,
    position: Position,
    actor: &Actor,
    bytes: &[u8],
    affects: &Affects,
) -> Result<(), DataError> {
    let (key, type_id) = match (affects.record, affects.type_id) {
        (Some(record), Some(type_id)) => (Key::Record(record), Some(type_id)),
        (Some(record), None) => (
            Key::Record(record),
            accepted_type_or_gapped_note(tx, sid, record)?,
        ),
        (None, Some(type_id)) => (Key::Type(type_id), Some(type_id)),
        (None, None) => (Key::Scope, None),
    };
    let ct = match type_id {
        Some(type_id) if affects.record.is_some() => {
            registry::current_before(tx, sid, type_id, core, Some(position))?
        }
        _ => None,
    };
    insert_park(
        tx,
        &ParkRow {
            sid,
            position,
            key,
            bytes,
            actor,
            wait: &Wait::Unsupported,
            mutation: None,
            type_id,
            unresolved_type: match type_id {
                Some(ty) => registry::current(tx, sid, ty, core)?.is_none(),
                None => true,
            },
            record: affects.record,
            uniques: ct.as_ref().map(|ct| unique_families(ct, None)),
            app: ct.and_then(|ct| ct.app),
            holds: true,
        },
    )
}

/// One `data_parked` row; see the module docs and [`blocked`].
struct ParkRow<'a> {
    sid: i64,
    position: Position,
    key: Key,
    bytes: &'a [u8],
    actor: &'a Actor,
    wait: &'a Wait,
    mutation: Option<MutationId>,
    type_id: Option<TypeId>,
    unresolved_type: bool,
    record: Option<RecordId>,
    /// Only for record rows; `None` there means any family.
    uniques: Option<Vec<TypeId>>,
    app: Option<AppId>,
    holds: bool,
}

fn insert_park(tx: &Transaction<'_>, row: &ParkRow<'_>) -> Result<(), DataError> {
    let uniques = row.uniques.as_ref().map(|families| {
        families
            .iter()
            .map(|family| hex(&family.0))
            .collect::<Vec<_>>()
            .join(",")
    });
    tx.execute(
        "INSERT INTO data_parked(scope,position,affects,payload,actor,reason,mutation,type,record,uniques,app,holds,unresolved_type)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            row.sid,
            integer(row.position.0)?,
            row.key.encode(),
            row.bytes,
            actor_store::intern(tx, row.actor)?,
            serde_json::to_string(row.wait).map_err(corrupt)?,
            row.mutation.map(|m| m.0.to_vec()),
            row.type_id.map(|t| t.0.to_vec()),
            row.record.map(|r| r.0.to_vec()),
            uniques,
            row.app.map(|a| a.0.to_vec()),
            row.holds,
            row.unresolved_type,
        ],
    )
    .map_err(sql)?;
    Ok(())
}

/// The unique families whose keys `changed` touches (all of them for `None`).
fn unique_families(ct: &CompiledType, changed: Option<&[FieldChange]>) -> Vec<TypeId> {
    let mut families: Vec<TypeId> = touched_uniques(ct, changed)
        .iter()
        .map(|decl| decl.declared_by)
        .collect();
    families.sort_unstable();
    families.dedup();
    families
}

/// The queue `op` must wait behind, if any; costs one probe when nothing is parked.
pub(crate) fn queued(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    sid: i64,
    op: &Operation,
    before: Option<Position>,
    blockers: Blockers,
) -> Result<Option<Park>, DataError> {
    if !any_parked(tx, sid)? {
        return Ok(None);
    }
    let touch = touch(tx, core, sid, op, before)?;
    Ok(blocked(tx, sid, &touch, blockers)?.map(|holds| Park {
        key: touch.key,
        holds,
    }))
}

/// What an operation reads and changes, as far as queue overlap is concerned,
/// computed before evaluation from the definitions in force at its position.
/// A park row stores the same facts.
struct Touch {
    key: Key,
    /// The record a record operation names.
    record: Option<RecordId>,
    /// A record operation's concrete type, or the type a definition defines.
    type_id: Option<TypeId>,
    /// Types whose definitions the operation reads or changes.
    related: Vec<TypeId>,
    /// Apps whose definitions the operation reads or changes.
    apps: Vec<AppId>,
    /// The one app whose active state a record operation reads.
    reads_app: Option<AppId>,
    /// Unique families a record operation checks or changes keys in; `None`
    /// when its type is not known here (treated as any family).
    uniques: Option<Vec<TypeId>>,
}

/// Only ordered state determines a record's type: a local pending create is
/// not on other replicas, which must store the same parked row. A missing
/// projection with a gap is always a Note, not an unknown type.
fn accepted_type_or_gapped_note(
    tx: &Transaction<'_>,
    sid: i64,
    record: RecordId,
) -> Result<Option<TypeId>, DataError> {
    match records::get(tx, sid, record)? {
        Some(row) => Ok(row.exists_accepted().then_some(row.type_id)),
        None if crate::note::unavailable(tx, sid, record)? => Ok(Some(TypeId::core("note"))),
        None => Ok(None),
    }
}

fn touch(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    sid: i64,
    op: &Operation,
    before: Option<Position>,
) -> Result<Touch, DataError> {
    let mut touch = Touch {
        key: Key::Scope,
        record: op.record(),
        type_id: None,
        related: Vec::new(),
        apps: Vec::new(),
        reads_app: None,
        uniques: None,
    };
    match op {
        Operation::DefineApp { app, .. } | Operation::SetAppState { app, .. } => {
            touch.key = Key::App(*app);
            touch.apps = vec![*app];
        }
        Operation::BindCore { type_id, .. } | Operation::Transition { type_id, .. } => {
            let mut related = vec![*type_id];
            if let Some(ct) = registry::current_before(tx, sid, *type_id, core, before)? {
                related.extend(ct.lineage.iter().map(|(t, _)| *t));
                touch.apps.extend(ct.app);
            }
            related.extend(registry::family_members(tx, sid, *type_id)?);
            related.sort_unstable();
            related.dedup();
            touch.key = Key::Type(*type_id);
            touch.type_id = Some(*type_id);
            touch.related = related;
        }
        Operation::DefineType { bytes } | Operation::Adopt { bytes, .. } => {
            let Ok(def) = definition::parse(bytes) else {
                return Ok(touch);
            };
            let mut related = vec![def.type_id];
            if let Some(parent) = &def.extends {
                match definition_at(tx, sid, parent.revision, core, before)? {
                    Some(base) => related.extend(base.lineage.iter().map(|(t, _)| *t)),
                    None => related.push(parent.type_id),
                }
            }
            related.extend(registry::family_members(tx, sid, def.type_id)?);
            related.sort_unstable();
            related.dedup();
            touch.key = Key::Type(def.type_id);
            touch.type_id = Some(def.type_id);
            touch.related = related;
            touch.apps = def.app.into_iter().collect();
        }
        op => {
            let record = op.record().expect("record operations name a record");
            touch.key = Key::Record(record);
            // A creation or binding names the type the record will have.
            touch.type_id = match op {
                Operation::Create { type_id, .. } | Operation::BindNote { type_id, .. } => {
                    Some(*type_id)
                }
                _ => accepted_type_or_gapped_note(tx, sid, record)?,
            };
            if let Some(type_id) = touch.type_id {
                match registry::current_before(tx, sid, type_id, core, before)? {
                    Some(ct) => {
                        touch.related.extend(ct.lineage.iter().map(|(t, _)| *t));
                        touch.apps.extend(ct.app);
                        if matches!(op, Operation::Create { .. } | Operation::BindNote { .. }) {
                            touch.reads_app = ct.app;
                        }
                        let changed = match op {
                            Operation::Edit { changes, .. }
                            | Operation::Action { changes, .. }
                            | Operation::Migrate { changes, .. } => Some(changes.as_slice()),
                            // Creates, bindings, deletions and undos (which may
                            // restore) touch every key.
                            _ => None,
                        };
                        touch.uniques = Some(unique_families(&ct, changed));
                    }
                    None => touch.related.push(type_id),
                }
            }
            if let Operation::Action { app, .. } = op {
                touch.apps.push(*app);
                touch.reads_app = Some(*app);
            }
        }
    }
    Ok(touch)
}

/// Whether a parked row overlaps `touch`: replaying it later could change
/// this operation's verdict or effects, or this operation could change its.
/// Returns `None` when nothing overlaps, else whether any overlapping row
/// `holds` definitions (a queued row inherits that). A definition row has no
/// `record`.
///
/// | Incoming operation | Waits behind a parked row that…                                  |
/// |--------------------|------------------------------------------------------------------|
/// | record op on R     | is scope-wide (`""`)                                             |
/// |                    | names R (any reason, any key)                                    |
/// |                    | is keyed `t:X` for X in R's type lineage (definitions, uniqueness) |
/// |                    | is keyed `a:A` for an app it reads                               |
/// |                    | is a record op sharing a unique family it touches, or of unknown type |
/// | define type T      | is a definition keyed `""`, or `t:X`/`a:A` for its lineage, family or app |
/// |                    | is a holding record op keyed so, or whose type is in that set or unknown |
/// | define app A       | is a definition keyed `""` or `a:A`                              |
/// |                    | is a holding record op keyed so, or reading A's active state     |
/// | unreadable definition | is any definition                                             |
///
/// A record row holds unless it waits for an unknown core revision, or is
/// queued only behind rows that do. A parked row is replayed against unique
/// indexes, which follow the latest declarations: a definition decided before
/// it could retire the index its replay needs. That includes a row waiting for
/// an app's definition, which backfill may still deliver. Such a wait ends
/// when coverage completes (accepted or `NotFound`), so holding behind it only
/// delays definitions. A core revision may never arrive on this executable,
/// so holding behind it could stall the scope's definitions for good. Known
/// limit: the core row's replay, after an upgrade, may meet indexes a
/// definition decided meanwhile has retired; only core-version skew reaches it.
///
/// A record row of unknown type may turn out to belong to any family once its
/// record arrives, so it holds every type definition. On a partial replica,
/// such as a large shared base's first sync, definition changes can therefore
/// wait until coverage completes. They never diverge.
/// A record op of unknown type on this replica touches no unique family: it
/// waits (missing definition or record) or fails without reading other records.
fn blocked(
    tx: &Transaction<'_>,
    sid: i64,
    touch: &Touch,
    blockers: Blockers,
) -> Result<Option<bool>, DataError> {
    let marks = |n: usize| vec!["?"; n].join(",");
    let mut args: Vec<Sql> = vec![Sql::Integer(sid)];
    let text = match touch.key {
        Key::Record(record) => {
            let mut keys = vec![Key::Scope.encode(), touch.key.encode()];
            keys.extend(touch.apps.iter().map(|app| Key::App(*app).encode()));
            keys.extend(touch.related.iter().map(|t| Key::Type(*t).encode()));
            let mut text = format!("affects IN ({}) OR record=?", marks(keys.len()));
            args.extend(keys.into_iter().map(Sql::Text));
            args.push(Sql::Blob(record.0.to_vec()));
            if let Some(families) = touch.uniques.as_ref().filter(|f| !f.is_empty()) {
                text.push_str(" OR (record IS NOT NULL AND (uniques IS NULL");
                for family in families {
                    text.push_str(" OR instr(uniques,?)>0");
                    args.push(Sql::Text(hex(&family.0)));
                }
                text.push_str("))");
            }
            text
        }
        Key::Scope => "record IS NULL".to_owned(),
        Key::Type(_) | Key::App(_) => {
            let mut keys = vec![Key::Scope.encode()];
            keys.extend(touch.apps.iter().map(|app| Key::App(*app).encode()));
            keys.extend(touch.related.iter().map(|t| Key::Type(*t).encode()));
            let mut text = format!(
                "(affects IN ({}) AND (record IS NULL OR holds)) OR (record IS NOT NULL AND holds AND ",
                marks(keys.len())
            );
            args.extend(keys.into_iter().map(Sql::Text));
            match touch.key {
                Key::App(app) => {
                    text.push_str("app=?)");
                    args.push(Sql::Blob(app.0.to_vec()));
                }
                _ => {
                    text.push_str(&format!(
                        "(type IS NULL OR type IN ({})))",
                        marks(touch.related.len())
                    ));
                    args.extend(touch.related.iter().map(|t| Sql::Blob(t.0.to_vec())));
                }
            }
            text
        }
    };
    let earlier = match blockers {
        Blockers::All => "",
        Blockers::Before(position) => {
            args.push(Sql::Integer(integer(position.0)?));
            " AND position<?"
        }
    };
    tx.query_row(
        &format!("SELECT max(holds) FROM data_parked WHERE scope=? AND ({text}){earlier}"),
        params_from_iter(args),
        |r| r.get(0),
    )
    .map_err(sql)
}
