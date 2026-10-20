//! Local saves: pending work validated against this replica's view, shown as
//! an overlay until its ordered outcome arrives, and kept when it loses.
use std::cell::{Cell, RefCell};

use rusqlite::{Connection, Transaction, params};

use super::{
    apply, define,
    eval::{self, Ctx, Mode, Plan, State, Verdict},
    hooks,
    ops::{FieldChange, Operation},
    rejection,
};
use crate::{
    Actor, CoreCatalogue, DataError, FieldPath, MutationId, RecordId, RejectCode, Rejection, Scope,
    Wait,
    payload::{self, Decoded},
    store::{
        actor as actor_store, corrupt, id,
        records::{self, RecordRow},
        registry, sql, unsigned,
    },
};

#[derive(Clone, Debug, PartialEq)]
pub struct LocalSaved {
    pub mutation: MutationId,
    /// The bytes to publish for ordering.
    pub payload: Vec<u8>,
    /// The record's text revision after the save; search at least this fresh includes it.
    pub content_rev: u64,
    /// Undo paths skipped by this local evaluation; empty for other operations.
    /// The ordered verdict on each replica is authoritative and may skip more
    /// if another edit lands before this mutation is ordered.
    pub skipped: Vec<FieldPath>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RejectedWork {
    pub mutation: MutationId,
    pub record: Option<RecordId>,
    pub attempted: Vec<FieldChange>,
    pub rejection: Rejection,
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("exact host confirmation required")]
    ConfirmationRequired(Box<crate::admission::Confirmation>),
    #[error("rejected: {0:?}")]
    Rejected(Rejection),
    #[error(transparent)]
    Data(#[from] DataError),
}

/// This replica's own saved payload; it always decodes.
fn decode(bytes: &[u8]) -> Result<(MutationId, Operation), DataError> {
    match payload::decode(bytes) {
        Decoded::Op(mutation, op) | Decoded::Confirmed(mutation, op, _) => Ok((mutation, op)),
        other => Err(DataError::Corrupt(format!("saved payload: {other:?}"))),
    }
}

/// Validates `op` against this replica's view with the ordered rules, saves it
/// as pending work and updates the view. Uniqueness counts accepted and local
/// records. Work behind a parked queue, or whose uniqueness cannot be proven
/// yet, is saved and marked `waiting`.
///
/// Known limit: a saved `DefineApp`, `DefineType` or `Adopt` changes the
/// registry only once accepted, so records of a type defined offline can be
/// saved only after that definition's ordered acceptance arrives.
pub fn submit(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    actor: &Actor,
    op: Operation,
) -> Result<LocalSaved, SubmitError> {
    submit_with_admission(tx, core, scope, actor, op, &crate::admission::Unavailable)
}

pub fn submit_with_admission(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    actor: &Actor,
    op: Operation,
    admission: &dyn crate::admission::HostAdmission,
) -> Result<LocalSaved, SubmitError> {
    submit_with_id(tx, core, scope, actor, op, admission, MutationId::random())
}

/// Submit with the mutation identity already bound into a device's signed
/// approval request. The caller must authenticate that request first.
pub fn submit_with_id(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    actor: &Actor,
    op: Operation,
    admission: &dyn crate::admission::HostAdmission,
    mutation: MutationId,
) -> Result<LocalSaved, SubmitError> {
    submit_with_confirmation(tx, core, scope, actor, op, admission, mutation, None)
}

/// A trusted device approval path may bind an explicit signed prior. Generic
/// hosts also publish the prior when their local admission actually confirms
/// the change. In either case the evaluator must require that confirmation;
/// callers cannot supply a confirmation through an operation.
#[allow(clippy::too_many_arguments)]
pub fn submit_with_confirmation(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    actor: &Actor,
    op: Operation,
    admission: &dyn crate::admission::HostAdmission,
    mutation: MutationId,
    confirmation: Option<crate::admission::PriorRules>,
) -> Result<LocalSaved, SubmitError> {
    struct ApprovalCheck<'a> {
        admission: &'a dyn crate::admission::HostAdmission,
        prior: Option<&'a crate::admission::PriorRules>,
        seen: RefCell<Option<crate::admission::PriorRules>>,
    }
    impl crate::admission::HostAdmission for ApprovalCheck<'_> {
        fn confirms(
            &self,
            request: &crate::admission::Confirmation,
            at: Option<crate::Position>,
        ) -> Result<bool, DataError> {
            if self.prior.is_some() && self.prior != Some(&request.prior) {
                return Ok(false);
            }
            let allowed = self.admission.confirms(request, at)?;
            if allowed {
                *self.seen.borrow_mut() = Some(request.prior.clone());
            }
            Ok(allowed)
        }
        fn may_read_source(
            &self,
            actor: &Actor,
            source: Scope,
            at: Option<crate::Position>,
        ) -> Result<bool, DataError> {
            self.admission.may_read_source(actor, source, at)
        }
    }
    let checked = ApprovalCheck {
        admission,
        prior: confirmation.as_ref(),
        seen: RefCell::new(None),
    };
    let sid = records::scope_id(tx, scope, core)?;
    let ctx = Ctx {
        tx,
        core,
        scope,
        sid,
        actor,
        mode: Mode::Submit,
        admission: &checked,
        waiting: Cell::new(false),
    };
    let record = op.record();
    let (verdict, initial_row) = match record {
        None => (define::definition(&ctx, &op)?, None),
        Some(record) => {
            let state = State::local(records::get(tx, sid, record)?);
            // Evaluation borrows the row. Until materialization below, only
            // queue inspection and payload encoding follow; neither writes it.
            let verdict = eval::record(&ctx, record, &state, &op)?;
            (verdict, state.row)
        }
    };
    let plan = match verdict {
        Verdict::Accept(plan) => plan,
        Verdict::Reject(rejection) => return Err(SubmitError::Rejected(rejection)),
        Verdict::Wait(wait, _) => return Err(SubmitError::Rejected(local_wait(&wait))),
        Verdict::Confirm(request) => {
            return Err(SubmitError::ConfirmationRequired(request));
        }
    };
    let waiting = ctx.waiting.get()
        || apply::queued(tx, core, sid, &op, None, apply::Blockers::All)?.is_some();
    // A stale or gratuitous confirmation must never be published as if the
    // person approved an effect that this evaluation did not require.
    if confirmation.is_some() && checked.seen.borrow().is_none() {
        return Err(SubmitError::Rejected(rejection(
            RejectCode::Unauthorized,
            None,
            "confirmation not required for this change",
        )));
    }
    let payload = match payload::encode_with_confirmation(mutation, &op, checked.seen.into_inner())
    {
        Ok(payload) => payload,
        Err(DataError::Limit(detail)) => {
            return Err(SubmitError::Rejected(rejection(
                RejectCode::TooLarge,
                None,
                detail,
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let skipped = match (&op, &plan) {
        (Operation::Undo { .. }, Plan::Record(plan)) => plan.skipped.clone(),
        _ => Vec::new(),
    };
    let mut content_rev = 0;
    if let (Plan::Record(plan), Operation::BindNote { .. }) = (&plan, &op) {
        // A binding changes the record's type, which only its ordered
        // acceptance does: the view keeps the plain Note until then.
        tx.execute(
            "UPDATE data_record SET pending=1 WHERE scope=?1 AND record=?2",
            params![sid, plan.record.0.as_slice()],
        )
        .map_err(sql)?;
    } else if let Plan::Record(plan) = plan {
        let mut row = initial_row.unwrap_or(RecordRow {
            id: 0,
            scope: sid,
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
        let previous_text_rev = row.text_rev;
        row.deleted = plan.doc.is_none();
        row.doc = plan.doc;
        row.pending = true;
        records::put(tx, &mut row)?;
        hooks(tx, &row, &plan.ct)?;
        let updated = text_rev(tx, row.id)?;
        if updated != previous_text_rev {
            content_rev = updated;
        }
    }
    let seq = records::next_seq(tx)?;
    tx.execute(
        "INSERT INTO data_pending(seq,scope,mutation,rec_id,payload,state,actor) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            crate::store::integer(seq)?,
            sid,
            mutation.0.as_slice(),
            record.map(|r| r.0.to_vec()),
            payload,
            if waiting { "waiting" } else { "pending" },
            actor_store::intern(tx, actor)?,
        ],
    )
    .map_err(sql)?;
    Ok(LocalSaved {
        mutation,
        payload,
        content_rev,
        skipped,
    })
}

fn local_wait(wait: &Wait) -> Rejection {
    match wait {
        Wait::MissingRecord(record) => rejection(
            RejectCode::NotFound,
            None,
            format!("record {} is not available here", super::hex(&record.0)),
        ),
        other => rejection(
            RejectCode::RevisionNotPermitted,
            None,
            format!("cannot be checked here yet: {other:?}"),
        ),
    }
}

/// This replica's rejected work in `scope`, oldest first, with what it attempted.
pub fn rejected(conn: &Connection, scope: Scope) -> Result<Vec<RejectedWork>, DataError> {
    let Some(sid) = records::lookup_scope(conn, scope)? else {
        return Ok(Vec::new());
    };
    let mut stmt = conn
        .prepare("SELECT payload,rejection FROM data_pending WHERE scope=?1 AND state='rejected' ORDER BY seq")
        .map_err(sql)?;
    let rows = stmt
        .query_map([sid], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .map_err(sql)?;
    let mut result = Vec::new();
    for row in rows {
        let (payload, json) = row.map_err(sql)?;
        let (mutation, op) = decode(&payload)?;
        let rejection = serde_json::from_str(
            &json.ok_or_else(|| DataError::Corrupt("rejected work without rejection".into()))?,
        )
        .map_err(corrupt)?;
        result.push(RejectedWork {
            mutation,
            record: op.record(),
            attempted: attempted(conn, sid, &op)?,
            rejection,
        });
    }
    Ok(result)
}

/// What the work tried to change. A creation or binding is reported per
/// field: values under a declared container are split into its leaves, as the
/// writer's revision declares them (whole top-level values if it is unknown here).
fn attempted(conn: &Connection, sid: i64, op: &Operation) -> Result<Vec<FieldChange>, DataError> {
    let (Operation::Create { revision, doc, .. } | Operation::BindNote { revision, doc, .. }) = op
    else {
        return Ok(op.changes().to_vec());
    };
    let ct = registry::compiled(conn, sid, *revision)?;
    let mut out = Vec::new();
    if let Some(object) = doc.as_object() {
        split(object, "", ct.as_ref(), &mut out);
    }
    Ok(out)
}

fn split(
    object: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    ct: Option<&crate::CompiledType>,
    out: &mut Vec<FieldChange>,
) {
    for (key, value) in object {
        let pointer = format!("{prefix}/{}", key.replace('~', "~0").replace('/', "~1"));
        let Ok(path) = FieldPath::parse(&pointer) else {
            continue;
        };
        let container = ct
            .and_then(|ct| ct.field(&path))
            .is_some_and(|field| field.kind == crate::FieldKind::Container);
        match value.as_object() {
            Some(children) if container => split(children, &pointer, ct, out),
            _ => out.push(FieldChange {
                path,
                value: Some(value.clone()),
            }),
        }
    }
}

/// Drops pending or rejected work and re-derives its record's view.
pub fn discard(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    mutation: MutationId,
) -> Result<(), DataError> {
    let found: Option<(i64, Option<Vec<u8>>)> =
        rusqlite::OptionalExtension::optional(tx.query_row(
            "DELETE FROM data_pending WHERE mutation=?1 RETURNING scope,rec_id",
            [mutation.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))
        .map_err(sql)?;
    let Some((sid, Some(record))) = found else {
        return Ok(());
    };
    let scope = scope_of(tx, sid)?;
    rewrite(tx, core, scope, sid, RecordId(id(record)?))
}

/// Re-derives the views of records in `type_id`'s family that have local
/// pending work, after that type's current rules changed. Bounded by this
/// replica's pending rows, not by the family's records.
pub(crate) fn refresh_family(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    sid: i64,
    type_id: crate::TypeId,
) -> Result<(), DataError> {
    let members = registry::family_members(tx, sid, type_id)?;
    refresh_types(
        tx,
        core,
        scope,
        sid,
        &|member| Ok(members.contains(&member)),
    )
}

/// Re-derives the views of records with local pending work whose current
/// type satisfies `which`, after rules they read changed (an app's state).
pub(crate) fn refresh_where(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    sid: i64,
    which: &dyn Fn(&crate::CompiledType) -> bool,
) -> Result<(), DataError> {
    refresh_types(tx, core, scope, sid, &|type_id| {
        Ok(registry::current(tx, sid, type_id, core)?.is_some_and(|ct| which(&ct)))
    })
}

fn refresh_types(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    sid: i64,
    which: &dyn Fn(crate::TypeId) -> Result<bool, DataError>,
) -> Result<(), DataError> {
    let mut stmt = tx
        .prepare_cached(
            "SELECT DISTINCT p.rec_id,r.type FROM data_pending p JOIN data_record r ON r.scope=p.scope AND r.record=p.rec_id
             WHERE p.scope=?1 AND p.state IN ('pending','waiting')",
        )
        .map_err(sql)?;
    let rows = stmt
        .query_map([sid], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    for (record, record_type) in rows {
        if which(crate::TypeId(id(record_type)?))? {
            rewrite(tx, core, scope, sid, RecordId(id(record)?))?;
        }
    }
    Ok(())
}

/// Re-derives a record's view from accepted state and remaining pending work,
/// then refreshes its derived rows.
pub(crate) fn rewrite(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    sid: i64,
    record: RecordId,
) -> Result<(), DataError> {
    let Some(mut row) = records::get(tx, sid, record)? else {
        return Ok(());
    };
    refresh(tx, core, scope, sid, &mut row)?;
    records::put(tx, &mut row)?;
    if let Some(ct) = registry::current(tx, sid, row.type_id, core)? {
        hooks(tx, &row, &ct)?;
    }
    Ok(())
}

/// Sets the row's view: accepted state plus this replica's still-pending work
/// for the record, in save order. Work that no longer applies is left out of
/// the view (its ordered outcome is still decided at its own position).
pub(crate) fn refresh(
    tx: &Transaction<'_>,
    core: &dyn CoreCatalogue,
    scope: Scope,
    sid: i64,
    row: &mut RecordRow,
) -> Result<(), DataError> {
    let mut stmt = tx
        .prepare_cached(
            "SELECT payload,actor FROM data_pending WHERE scope=?1 AND rec_id=?2 AND state IN ('pending','waiting') ORDER BY seq",
        )
        .map_err(sql)?;
    let work = stmt
        .query_map(params![sid, row.record.0.as_slice()], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<i64>>(1)?))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    row.pending = !work.is_empty();
    let mut state = State::accepted(Some(row.clone()));
    let mut overlaid = false;
    for (payload, actor) in work {
        let (_, op) = decode(&payload)?;
        // A pending binding shows once accepted (see `submit`).
        if matches!(op, Operation::BindNote { .. }) {
            continue;
        }
        let actor = actor_store::get(
            tx,
            actor.ok_or_else(|| DataError::Corrupt("pending work without actor".into()))?,
        )?;
        let ctx = Ctx {
            tx,
            core,
            scope,
            sid,
            actor: &actor,
            mode: Mode::Overlay,
            admission: &crate::admission::Unavailable,
            waiting: Cell::new(false),
        };
        if let Verdict::Accept(Plan::Record(plan)) = eval::record(&ctx, row.record, &state, &op)? {
            state.exists = true;
            state.doc = plan.doc;
            overlaid = true;
        }
    }
    if overlaid {
        row.deleted = state.doc.is_none();
        row.doc = state.doc;
    } else {
        row.deleted = row.accepted.is_none();
        row.doc = None;
    }
    Ok(())
}

fn text_rev(tx: &Transaction<'_>, rec: i64) -> Result<u64, DataError> {
    let rev: i64 = tx
        .query_row("SELECT text_rev FROM data_record WHERE id=?1", [rec], |r| {
            r.get(0)
        })
        .map_err(sql)?;
    unsigned(rev)
}

pub(crate) fn scope_of(conn: &Connection, sid: i64) -> Result<Scope, DataError> {
    let (base, audience): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT base,audience FROM data_scope WHERE id=?1",
            [sid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql)?;
    Ok(Scope {
        base: id(base)?,
        audience: id(audience)?,
    })
}
