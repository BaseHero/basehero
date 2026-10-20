//! App and type definition rules: owners, authority, pinned dependencies,
//! which audiences a definition may be copied between, and the rule changes
//! only a person's own device makes (app activation, transitions and core
//! bindings).
use std::cell::RefCell;

use crate::admission::{Confirmation, PriorRules};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use super::{
    apply::Key,
    eval::{Ctx, DefinitionPlan, Plan, Step, Verdict, finish, no},
    hex, implicit_core,
    ops::Operation,
};
use crate::{
    AppId, CompiledType, DataError, FieldPath, Position, RejectCode, RevisionId, Scope, TypeId,
    WritePolicy, catalogue, compat,
    compose::{self, ComposeError},
    definition,
    store::registry,
};

pub(crate) fn definition(ctx: &Ctx<'_, '_>, op: &Operation) -> Result<Verdict, DataError> {
    finish(match op {
        Operation::DefineApp { app, name } => define_app(ctx, *app, name),
        Operation::DefineType { bytes } => define_type(ctx, bytes, false, op),
        Operation::Adopt {
            from_audience,
            revision,
            bytes,
        } => adopt(ctx, *from_audience, *revision, bytes),
        Operation::SetAppState { app, active } => set_app_state(ctx, *app, *active),
        Operation::BindCore { type_id, revision } => bind_core(ctx, *type_id, *revision),
        Operation::Transition { type_id, to } => transition(ctx, *type_id, *to),
        _ => Err(DataError::Corrupt("record operation evaluated as a definition".into()).into()),
    })
}

fn type_prior(ctx: &Ctx<'_, '_>, type_id: TypeId) -> Step<PriorRules> {
    Ok(PriorRules::Type {
        revision: ctx.current(type_id)?.map(|ct| ct.revision),
        permitted: ctx.permitted(type_id)?,
    })
}
fn confirm(ctx: &Ctx<'_, '_>, op: &Operation, prior: PriorRules) -> Step<()> {
    let request = Confirmation {
        scope: ctx.scope,
        actor: ctx.actor.clone(),
        operation: op.clone(),
        prior,
    };
    if ctx.admission.confirms(&request, ctx.before())? {
        Ok(())
    } else {
        Err(super::eval::Stop::Verdict(Box::new(Verdict::Confirm(
            Box::new(request),
        ))))
    }
}

/// The longest app name, in UTF-8 bytes.
const MAX_APP_NAME_BYTES: usize = 200;

/// Only a person's own device changes the rules existing records live under.
fn device_only(ctx: &Ctx<'_, '_>, what: &str) -> Step<()> {
    if ctx.is_job() {
        return no(
            RejectCode::DeviceOnly,
            None,
            format!("only a person's device {what}"),
        );
    }
    Ok(())
}

/// Deactivating an app refuses new records of its types and its actions;
/// its definitions, indexes, records and their protections stay, and direct
/// edits those rules permit continue. Reactivating reuses every identity.
/// Core types belong to no app, so this never reaches them.
fn set_app_state(ctx: &Ctx<'_, '_>, app: AppId, active: bool) -> Step<Plan> {
    device_only(ctx, "activates or deactivates an app")?;
    if ctx.app_active(app)?.is_none() {
        return ctx.missing_app(app);
    }
    let since:Option<i64>=ctx.tx.query_row("SELECT max(since) FROM data_app_at WHERE scope=?1 AND app=?2 AND (?3 IS NULL OR since<?3)",
        params![ctx.sid,app.0.as_slice(),ctx.before().map(|p|crate::store::integer(p.0)).transpose()?],|r|r.get(0)).map_err(crate::store::sql)?;
    confirm(
        ctx,
        &Operation::SetAppState { app, active },
        PriorRules::App {
            app,
            since: since.map(crate::store::unsigned).transpose()?.map(Position),
            active: ctx.app_active(app)?,
        },
    )?;
    Ok(Plan::Definition(DefinitionPlan::AppState { app, active }))
}

/// Binds a core contract other than the implicit Note baseline to this
/// audience. A revision this executable does not ship waits (a newer one may ship it): a newer
/// executable never binds anything by itself, and later work on the type
/// queues behind the wait on every replica. Note's own changes cross a
/// separate, versioned boundary. A compatible revision joins the permitted
/// set; any other replaces it, and records then migrate as after a
/// transition.
fn bind_core(ctx: &Ctx<'_, '_>, type_id: TypeId, revision: RevisionId) -> Step<Plan> {
    device_only(ctx, "binds core contracts")?;
    // Core and app type identities never coincide, so a type this audience
    // already holds as an app's is not one. An identity unknown here may be
    // a core type of a newer executable, so it is not refused (known limit:
    // a binding of an identity no executable ships waits for good, holding
    // that identity's definitions).
    if ctx.current(type_id)?.is_some_and(|ct| ct.app.is_some()) {
        return no(
            RejectCode::NotFound,
            None,
            format!(
                "type {} is an app's type, not a core contract",
                hex(&type_id.0)
            ),
        );
    }
    let builtin = |ct: &CompiledType| ct.type_id == type_id && ct.builtin.is_some();
    if catalogue::core_types().iter().any(builtin)
        || ctx.core.core_type(type_id).is_some_and(|ct| builtin(&ct))
    {
        return no(
            RejectCode::NeedsCoreTransition,
            None,
            "the Note contract changes through its own core transition",
        );
    }
    let Some(ct) = ctx
        .core
        .core_type(type_id)
        .filter(|ct| ct.revision == revision)
    else {
        return ctx.missing_definition(Some(type_id), revision, true, Key::Type(type_id));
    };
    let permitted = match ctx.current(type_id)? {
        None => vec![revision],
        Some(previous) if previous.revision == revision => {
            return no(
                RejectCode::Exists,
                None,
                format!("revision {} is already bound", hex(&revision.0)),
            );
        }
        Some(previous) if compat::classify(&previous, &ct).compatible => {
            let mut permitted = ctx.permitted(type_id)?;
            permitted.push(revision);
            permitted
        }
        Some(_) => vec![revision],
    };
    confirm(
        ctx,
        &Operation::BindCore { type_id, revision },
        type_prior(ctx, type_id)?,
    )?;
    Ok(Plan::Definition(DefinitionPlan::Rules {
        type_id,
        current: revision,
        permitted,
        core: Some(Box::new(ct)),
    }))
}

/// Makes an already defined revision of an app type current and the only
/// permitted one. Writers on other revisions are refused, and records on
/// them refuse changes until migrated. Any defined revision may be the
/// target, including an older one or the current one (which then only
/// narrows the permitted set to it).
fn transition(ctx: &Ctx<'_, '_>, type_id: TypeId, to: RevisionId) -> Step<Plan> {
    device_only(ctx, "transitions a type")?;
    if type_id.is_reserved_core() || ctx.core.core_type(type_id).is_some() {
        return no(
            RejectCode::NeedsCoreTransition,
            None,
            "core contracts change through their core binding",
        );
    }
    let Some(target) = ctx.compiled(to)? else {
        return ctx.missing_definition(Some(type_id), to, false, Key::Type(type_id));
    };
    if target.type_id != type_id {
        return no(
            RejectCode::RevisionNotPermitted,
            None,
            format!("revision {} is not a revision of this type", hex(&to.0)),
        );
    }
    confirm(
        ctx,
        &Operation::Transition { type_id, to },
        type_prior(ctx, type_id)?,
    )?;
    Ok(Plan::Definition(DefinitionPlan::Rules {
        type_id,
        current: to,
        permitted: vec![to],
        core: None,
    }))
}

fn define_app(ctx: &Ctx<'_, '_>, app: crate::AppId, name: &str) -> Step<Plan> {
    if name.len() > MAX_APP_NAME_BYTES {
        return no(
            RejectCode::TooLarge,
            None,
            format!("an app name is at most {MAX_APP_NAME_BYTES} bytes"),
        );
    }
    if ctx.app_active(app)?.is_some() {
        return no(
            RejectCode::Exists,
            None,
            format!("app {} is already defined", hex(&app.0)),
        );
    }
    ctx.absence(Key::App(app))?;
    Ok(Plan::Definition(DefinitionPlan::App {
        app,
        name: name.to_owned(),
    }))
}

/// Only the base-wide audience's definitions may be copied, and only into a
/// narrower audience: shared data never depends on a contract some of its
/// readers cannot read.
fn adopt(
    ctx: &Ctx<'_, '_>,
    from_audience: [u8; 32],
    revision: RevisionId,
    bytes: &[u8],
) -> Step<Plan> {
    if RevisionId::of(bytes) != revision {
        return no(
            RejectCode::Schema,
            None,
            "the supplied bytes do not hash to the adopted revision",
        );
    }
    if catalogue::core_types()
        .iter()
        .any(|core| core.revision == revision)
    {
        return no(
            RejectCode::ReservedType,
            None,
            "core contracts ship with the core and are not adopted",
        );
    }
    if !Scope::is_base_wide(&from_audience) || Scope::is_base_wide(&ctx.scope.audience) {
        return no(
            RejectCode::Unauthorized,
            None,
            "only base-wide definitions may be adopted, into a narrower audience",
        );
    }
    let source = Scope {
        base: ctx.scope.base,
        audience: from_audience,
    };
    if !ctx
        .admission
        .may_read_source(ctx.actor, source, ctx.before())?
    {
        return no(
            RejectCode::Unauthorized,
            None,
            "adoption requires verified source readership",
        );
    }
    let parsed = match definition::parse(bytes) {
        Ok(parsed) => parsed,
        Err(error) => return no(RejectCode::Schema, None, error.to_string()),
    };
    let sid = crate::store::records::lookup_scope(ctx.tx, source)?;
    let evidence: Option<(Vec<u8>, i64)> = if let Some(sid) = sid {
        ctx.tx.query_row("SELECT bytes,accepted_at FROM data_definition WHERE scope=?1 AND revision=?2 AND (?3 IS NULL OR accepted_at<?3)",
            params![sid,revision.0.as_slice(),ctx.before().map(|p|crate::store::integer(p.0)).transpose()?],
            |r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(crate::store::sql)?
    } else {
        None
    };
    let proven = if let Some((accepted, at)) = evidence {
        if accepted != bytes || parsed.app.is_none() {
            return no(
                RejectCode::Unauthorized,
                None,
                "adoption source ownership/provenance differs",
            );
        }
        crate::store::registry::app_active_before(
            ctx.tx,
            sid.expect("evidence has scope"),
            parsed.app.expect("checked app"),
            Some(Position(crate::store::unsigned(at)?)),
        )?
        .is_some()
    } else {
        false
    };
    if !proven {
        if sid
            .map(|s| crate::store::coverage::get(ctx.tx, s))
            .transpose()?
            .is_some_and(|c| c.complete)
        {
            return no(
                RejectCode::NotFound,
                None,
                "definition was not accepted in the source before this position",
            );
        }
        return super::eval::wait(
            crate::Wait::Coverage(source),
            super::eval::Park {
                key: Key::Type(parsed.type_id),
                holds: true,
            },
        );
    }
    define_type(
        ctx,
        bytes,
        true,
        &Operation::Adopt {
            from_audience,
            revision,
            bytes: bytes.to_vec(),
        },
    )
}

/// The device-only gate for an existing type's rules; shared with proposals.
pub(crate) fn needs_device(previous_exists: bool, change: &compat::Change) -> bool {
    previous_exists && change.rule_change
}

fn define_type(ctx: &Ctx<'_, '_>, bytes: &[u8], adopted: bool, op: &Operation) -> Step<Plan> {
    if serde_json::from_slice::<Value>(bytes)
        .ok()
        .is_some_and(|doc| doc.get("builtin").is_some_and(|b| !b.is_null()))
    {
        return no(
            RejectCode::ReservedType,
            None,
            "an app cannot define a built-in contract",
        );
    }
    let def = match definition::parse(bytes) {
        Ok(def) => def,
        Err(DataError::Limit(detail)) => return no(RejectCode::TooLarge, None, detail),
        Err(error) => return no(RejectCode::Schema, None, error.to_string()),
    };
    if def.type_id.is_reserved_core() {
        return no(
            RejectCode::ReservedType,
            None,
            "reserved core type identity",
        );
    }
    let app = def
        .app
        .ok_or_else(|| DataError::Corrupt("app definition without app".into()))?;
    if !adopted && ctx.app_active(app)?.is_none() {
        return ctx.missing_app(app);
    }
    let revision = RevisionId::of(bytes);
    if ctx.compiled(revision)?.is_some() {
        return no(
            RejectCode::Exists,
            None,
            format!("revision {} is already defined", hex(&revision.0)),
        );
    }
    let failure = RefCell::new(None);
    let compiled = compose::compile(
        &def,
        revision,
        &|type_id, pinned| match ctx.compiled(pinned) {
            Ok(Some(found)) if found.type_id == type_id => Some(found),
            // Bound core contracts are stored with the audience's
            // definitions; only the implicit baseline is served unbound.
            Ok(_) if implicit_core(type_id) => ctx
                .core
                .core_type(type_id)
                .filter(|core| core.revision == pinned),
            Ok(_) => None,
            Err(error) => {
                failure.borrow_mut().get_or_insert(error);
                None
            }
        },
    );
    if let Some(error) = failure.into_inner() {
        return Err(error.into());
    }
    let ct = match compiled {
        Ok(ct) => ct,
        Err(ComposeError::Missing(type_id, pinned)) => {
            return ctx.missing_definition(
                Some(type_id),
                pinned,
                implicit_core(type_id),
                Key::Type(def.type_id),
            );
        }
        Err(ComposeError::Invalid(error)) => {
            return no(RejectCode::Schema, None, error.to_string());
        }
    };
    let permitted = match ctx.current(def.type_id)? {
        None => {
            ctx.absence(Key::Type(def.type_id))?;
            Some(vec![revision])
        }
        Some(previous) => {
            let change =
                effective_change(ctx.tx, Some(ctx.sid), &def, &ct, &previous, ctx.before())?;
            if ctx.is_job() && needs_device(true, &change) {
                return no(
                    RejectCode::DeviceOnly,
                    None,
                    format!(
                        "only a person's device changes existing rules: {}",
                        change.reasons.join("; ")
                    ),
                );
            }
            if needs_device(true, &change) {
                confirm(ctx, op, type_prior(ctx, def.type_id)?)?;
            }
            if change.compatible {
                let mut permitted = ctx.permitted(def.type_id)?;
                permitted.push(revision);
                Some(permitted)
            } else {
                None
            }
        }
    };
    Ok(Plan::Definition(DefinitionPlan::Type {
        ct: Box::new(ct),
        bytes: bytes.to_vec(),
        permitted,
    }))
}

/// Classifies a new revision exactly as the ordered definition gate does.
/// `before` limits accepted earlier revisions to the ordered position;
/// proposals pass `None` to inspect the current accepted registry.
pub(crate) fn effective_change(
    conn: &Connection,
    scope: Option<i64>,
    def: &definition::Definition,
    ct: &CompiledType,
    previous: &CompiledType,
    before: Option<Position>,
) -> Result<compat::Change, DataError> {
    let mut change = compat::classify(previous, ct);
    if let Some(path) = protected_step(conn, scope, def, ct, before)? {
        change.rule_change = true;
        change.reasons.push(format!(
            "migration changes a protected field: {}",
            path.as_pointer()
        ));
    }
    Ok(change)
}

/// A path a declared migration step changes that is action-only or derived
/// in the new revision or in any earlier revision of the type: a migration
/// may write such fields, so declaring one is a rule change.
fn protected_step(
    conn: &Connection,
    scope: Option<i64>,
    def: &definition::Definition,
    ct: &CompiledType,
    before: Option<Position>,
) -> Result<Option<FieldPath>, DataError> {
    let steps = &def.evolution.migration_ops;
    if steps.is_empty() {
        return Ok(None);
    }
    let mut revisions = vec![ct.clone()];
    if let Some(scope) = scope {
        for revision in registry::revisions(conn, scope, ct.type_id)? {
            // Only revisions accepted before this position.
            revisions.extend(registry::compiled_before(conn, scope, revision, before)?);
        }
    }
    for path in steps.iter().flat_map(|step| step.paths()) {
        let protected = revisions.iter().flat_map(|r| &r.fields).any(|field| {
            field.write != WritePolicy::Direct
                && (path.is_prefix_of(&field.path) || field.path.is_prefix_of(path))
        });
        if protected {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}
