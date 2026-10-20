//! Record rules shared by local saves, pending overlays and ordered materialization.
//!
//! Ordered evaluation reads only this scope's accepted state, so every replica
//! reaches the same verdict at the same position. Local evaluation applies the
//! same rules to this replica's view (accepted state plus pending work).
use std::cell::Cell;

use rusqlite::Transaction;
use serde_json::{Map, Value};

use super::{
    apply::Key,
    checks::{
        app_active, apply_changes, clock, current_of, declaring_app, known, leaves, migrated,
        overlap, present, unique, validate, writable, writer,
    },
    definition_at, hex, implicit_core,
    ops::{FieldChange, Operation},
    rejection,
};
use crate::{
    Actor, AppId, CompiledType, CoreCatalogue, DataError, FieldPath, MutationId, Position,
    RecordId, RejectCode, RevisionId, Scope, TypeId, TypeKind, Wait, WritePolicy, evolve, note,
    store::{coverage, records::RecordRow, registry},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// At an ordered position, against accepted state only, reading only
    /// definitions accepted before that position.
    Ordered(Position),
    /// A new local save, against this replica's view.
    Submit,
    /// Re-deriving the view from accepted state plus pending work; no cross-record checks.
    Overlay,
}

pub(crate) struct Ctx<'a, 't> {
    pub tx: &'a Transaction<'t>,
    pub core: &'a dyn CoreCatalogue,
    pub scope: Scope,
    pub sid: i64,
    pub actor: &'a Actor,
    pub admission: &'a dyn crate::admission::HostAdmission,
    pub mode: Mode,
    /// Set by a local save that cannot know its uniqueness verdict yet.
    pub waiting: Cell<bool>,
}

/// The record as one evaluation sees it.
#[derive(Clone, Debug)]
pub(crate) struct State {
    pub row: Option<RecordRow>,
    /// `None` when the record is absent or deleted.
    pub doc: Option<Value>,
    pub exists: bool,
}

impl State {
    pub fn accepted(row: Option<RecordRow>) -> Self {
        let exists = row.as_ref().is_some_and(RecordRow::exists_accepted);
        let doc = row.as_ref().and_then(|r| r.accepted.clone());
        Self { row, doc, exists }
    }

    pub fn local(row: Option<RecordRow>) -> Self {
        let exists = row
            .as_ref()
            .is_some_and(|r| r.exists_accepted() || !r.deleted);
        let doc = row
            .as_ref()
            .filter(|r| !r.deleted)
            .and_then(|r| r.view().cloned());
        Self { row, doc, exists }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Change {
    pub path: FieldPath,
    pub old: Option<Value>,
    pub new: Option<Value>,
}

/// What an accepted record operation writes.
#[derive(Clone, Debug)]
pub(crate) struct RecordPlan {
    pub record: RecordId,
    /// The record's current type, which derived state follows; the post-image
    /// was validated against it, except a migration's (against `revision`).
    pub ct: CompiledType,
    /// The revision the record is on afterwards.
    pub revision: RevisionId,
    /// `None` when the operation deletes the record.
    pub doc: Option<Value>,
    pub changes: Vec<Change>,
    /// Existence before (`None`: never existed) and after, when it changes.
    pub lifecycle: Option<(Option<bool>, bool)>,
    pub skipped: Vec<FieldPath>,
}

#[derive(Clone, Debug)]
pub(crate) enum DefinitionPlan {
    App {
        app: AppId,
        name: String,
    },
    AppState {
        app: AppId,
        active: bool,
    },
    /// A transition or core binding: the type's current revision and
    /// permitted set change; `core` is a bound core contract to keep.
    Rules {
        type_id: TypeId,
        current: RevisionId,
        permitted: Vec<RevisionId>,
        core: Option<Box<CompiledType>>,
    },
    Type {
        ct: Box<CompiledType>,
        bytes: Vec<u8>,
        /// `Some` activates the revision with this permitted set; `None`
        /// records an incompatible revision without activating it.
        permitted: Option<Vec<RevisionId>>,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum Plan {
    Record(Box<RecordPlan>),
    Definition(DefinitionPlan),
}

/// The ordered queue a waiting operation joins.
#[derive(Clone, Debug)]
pub(crate) struct Park {
    pub key: Key,
    /// Whether the parked row holds overlapping definitions (see
    /// `apply::blocked`); false only for a wait on an unknown core revision,
    /// directly or queued only behind such waits.
    pub holds: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum Verdict {
    Accept(Plan),
    Reject(crate::Rejection),
    Confirm(Box<crate::admission::Confirmation>),
    Wait(Wait, Park),
}

pub(crate) enum Stop {
    Verdict(Box<Verdict>),
    Data(DataError),
}

impl From<DataError> for Stop {
    fn from(error: DataError) -> Self {
        Self::Data(error)
    }
}

pub(crate) type Step<T> = Result<T, Stop>;

pub(crate) fn no<T>(
    code: RejectCode,
    path: Option<&FieldPath>,
    detail: impl Into<String>,
) -> Step<T> {
    Err(Stop::Verdict(Box::new(Verdict::Reject(rejection(
        code,
        path.cloned(),
        detail,
    )))))
}

pub(crate) fn wait<T>(wait: Wait, park: Park) -> Step<T> {
    Err(Stop::Verdict(Box::new(Verdict::Wait(wait, park))))
}

pub(crate) fn finish(step: Step<Plan>) -> Result<Verdict, DataError> {
    match step {
        Ok(plan) => Ok(Verdict::Accept(plan)),
        Err(Stop::Verdict(verdict)) => Ok(*verdict),
        Err(Stop::Data(error)) => Err(error),
    }
}

impl Ctx<'_, '_> {
    pub fn ordered(&self) -> bool {
        matches!(self.mode, Mode::Ordered(_))
    }

    /// Ordered evaluation at `p` reads only definitions and app states
    /// accepted before `p`, so replaying parked work reaches the verdict a
    /// fully covered replica reached there; local evaluation reads the latest.
    pub fn before(&self) -> Option<Position> {
        match self.mode {
            Mode::Ordered(position) => Some(position),
            Mode::Submit | Mode::Overlay => None,
        }
    }

    pub fn definition(&self, revision: RevisionId) -> Result<Option<CompiledType>, DataError> {
        definition_at(self.tx, self.sid, revision, self.core, self.before())
    }

    pub fn compiled(&self, revision: RevisionId) -> Result<Option<CompiledType>, DataError> {
        registry::compiled_before(self.tx, self.sid, revision, self.before())
    }

    pub fn current(&self, type_id: TypeId) -> Result<Option<CompiledType>, DataError> {
        registry::current_before(self.tx, self.sid, type_id, self.core, self.before())
    }

    pub fn permitted(&self, type_id: TypeId) -> Result<Vec<RevisionId>, DataError> {
        registry::permitted_before(self.tx, self.sid, type_id, self.core, self.before())
    }

    pub fn app_active(&self, app: AppId) -> Result<Option<bool>, DataError> {
        registry::app_active_before(self.tx, self.sid, app, self.before())
    }

    fn covered(&self) -> Result<bool, DataError> {
        Ok(coverage::get(self.tx, self.sid)?.complete)
    }

    /// Whether this replica holds a Note identity but cannot show its content:
    /// a held body, content kept for a newer executable, or a missing first
    /// projection. Existence and absence of that record are then undecidable
    /// here, so the decision waits for the record itself, whatever the scope's
    /// coverage.
    fn note_gap(&self, record: RecordId) -> Result<bool, DataError> {
        note::unavailable(self.tx, self.sid, record)
    }

    /// A negative identity check needs verified scope coverage and no Note gap
    /// on the key. Local saves remain durable proposals while ordered work waits
    /// for that evidence.
    pub fn absence(&self, key: Key) -> Step<()> {
        if let Key::Record(record) = key
            && self.note_gap(record)?
        {
            return wait(Wait::MissingRecord(record), Park { key, holds: true });
        }
        if !self.covered()? {
            if self.ordered() {
                return wait(Wait::Coverage(self.scope), Park { key, holds: true });
            }
            self.waiting.set(true);
        }
        Ok(())
    }

    /// An app this rule change names is not defined here: final once this
    /// replica holds the whole scope, else the change waits.
    pub fn missing_app<T>(&self, app: AppId) -> Step<T> {
        if self.ordered() && !self.covered()? {
            return wait(
                Wait::Coverage(self.scope),
                Park {
                    key: Key::App(app),
                    holds: true,
                },
            );
        }
        no(
            RejectCode::NotFound,
            None,
            format!("app {} is not defined in this audience", hex(&app.0)),
        )
    }

    /// Absence is only final when this replica holds the scope's whole state and
    /// can show the record.
    pub fn missing_record<T>(&self, record: RecordId) -> Step<T> {
        if self.ordered() && self.note_gap(record)? {
            return wait(
                Wait::MissingRecord(record),
                Park {
                    key: Key::Record(record),
                    holds: true,
                },
            );
        }
        if self.ordered() && !self.covered()? {
            return wait(
                Wait::MissingRecord(record),
                Park {
                    key: Key::Record(record),
                    holds: true,
                },
            );
        }
        no(
            RejectCode::NotFound,
            None,
            format!("record {} not found", hex(&record.0)),
        )
    }

    /// A definition the operation needs is not usable at its position.
    ///
    /// An unknown core revision (`core`) may ship in a newer executable, so
    /// ordered evaluation waits rather than diverging from newer replicas.
    /// An app's types and revisions are data in this scope's own log: once
    /// this replica holds the whole scope, one missing at this position was
    /// never accepted before it, everywhere, and the operation is refused.
    /// Without that coverage it waits.
    ///
    /// Only the core wait leaves later definitions free: an app's wait ends
    /// when coverage completes, a core one may never end on this executable.
    pub fn missing_definition<T>(
        &self,
        type_id: Option<TypeId>,
        revision: RevisionId,
        core: bool,
        key: Key,
    ) -> Step<T> {
        if self.ordered() && (core || !self.covered()?) {
            return wait(
                Wait::MissingDefinition(revision),
                Park { key, holds: !core },
            );
        }
        if self.ordered() {
            let of = type_id.map_or_else(String::new, |t| format!(" of type {}", hex(&t.0)));
            return no(
                RejectCode::NotFound,
                None,
                format!(
                    "revision {}{of} was not defined in this audience before this change",
                    hex(&revision.0)
                ),
            );
        }
        no(
            RejectCode::RevisionNotPermitted,
            None,
            format!("definition {} is not available", hex(&revision.0)),
        )
    }

    pub fn is_job(&self) -> bool {
        matches!(self.actor, Actor::Job { .. })
    }
}

pub(crate) fn record(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    op: &Operation,
) -> Result<Verdict, DataError> {
    // A plain Note carries no ordered state: it changes only through the
    // note writer, or becomes a specialisation by BindNote. A replica that
    // has not projected the Note refuses such work as missing instead; the
    // codes differ, the state does not. (An empty edit is refused first,
    // the same everywhere.)
    let plain = state
        .row
        .as_ref()
        .is_some_and(|row| row.type_id == TypeId::core("note"));
    let refused = match op {
        Operation::Edit { changes, .. } if !changes.is_empty() => Some(Some(&changes[0].path)),
        Operation::Undo { .. } | Operation::Migrate { .. } | Operation::Action { .. } => Some(None),
        _ => None,
    };
    if plain && let Some(path) = refused {
        return finish(no(
            RejectCode::DerivedField,
            path,
            "a plain Note changes only by the note body edit through the note writer, \
             or becomes a specialisation by BindNote",
        ));
    }
    let plan = match op {
        Operation::Create {
            type_id,
            revision,
            doc,
            ..
        } => create(ctx, record, state, *type_id, *revision, doc),
        Operation::Edit {
            revision, changes, ..
        } => edit(ctx, record, state, *revision, changes),
        Operation::Delete { .. } => delete(ctx, record, state),
        Operation::UndoRemove {
            target, position, ..
        } => undo_remove(ctx, record, state, *target, *position),
        Operation::Undo {
            target, changes, ..
        } => undo(ctx, record, state, *target, changes),
        Operation::Action {
            app,
            action,
            changes,
            ..
        } => run_action(ctx, record, state, *app, action, changes),
        Operation::Migrate {
            from, to, changes, ..
        } => migrate(ctx, record, state, *from, *to, changes),
        Operation::BindNote {
            type_id,
            revision,
            doc,
            ..
        } => bind_note(ctx, record, state, *type_id, *revision, doc),
        Operation::DefineApp { .. }
        | Operation::DefineType { .. }
        | Operation::Adopt { .. }
        | Operation::SetAppState { .. }
        | Operation::BindCore { .. }
        | Operation::Transition { .. } => Err(Stop::Data(DataError::Corrupt(
            "definition operation evaluated as a record operation".into(),
        ))),
    };
    finish(plan.map(|plan| Plan::Record(Box::new(plan))))
}

fn create(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    type_id: TypeId,
    revision: RevisionId,
    doc: &Value,
) -> Step<RecordPlan> {
    let current = ctx.current(type_id)?;
    // Decided before existence: whether this replica holds a Note's
    // projection must not change the verdict.
    if current.as_ref().is_some_and(|ct| ct.builtin.is_some()) {
        return no(
            RejectCode::DerivedField,
            None,
            "create the Note through the note writer, then BindNote",
        );
    }
    if state.exists {
        return no(
            RejectCode::Exists,
            None,
            format!("record {} already exists", hex(&record.0)),
        );
    }
    // A type without a current revision was never defined or bound in this
    // audience before this position (the Note baseline always has one).
    let Some(ct) = current else {
        return ctx.missing_definition(Some(type_id), revision, false, Key::Type(type_id));
    };
    if ct.kind == TypeKind::Value {
        return no(
            RejectCode::RevisionNotPermitted,
            None,
            "a value contract has no records of its own",
        );
    }
    app_active(ctx, ct.app)?;
    let writer = writer(ctx, &ct, revision, false, Key::Type(type_id))?;
    let leaves = leaves(doc, &ct, true)?;
    for (path, _) in &leaves {
        writable(&ct, path, false)?;
        known(writer.as_ref(), path)?;
    }
    validate(&ct, doc)?;
    unique(ctx, &ct, None, doc, None)?;
    ctx.absence(Key::Record(record))?;
    Ok(RecordPlan {
        record,
        doc: Some(doc.clone()),
        changes: leaves
            .into_iter()
            .map(|(path, value)| Change {
                path,
                old: None,
                new: Some(value),
            })
            .collect(),
        lifecycle: Some((None, true)),
        skipped: Vec::new(),
        revision: ct.revision,
        ct,
    })
}

fn edit(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    revision: RevisionId,
    changes: &[FieldChange],
) -> Step<RecordPlan> {
    // Refused before reading the record, so a replica that has not
    // materialised a Note's projection reaches the same verdict.
    if changes.is_empty() {
        return no(
            RejectCode::Schema,
            None,
            "an edit changes at least one field",
        );
    }
    let (row, doc) = present(ctx, record, state)?;
    let ct = current_of(ctx, row)?;
    let writer = writer(ctx, &ct, revision, true, Key::Record(record))?;
    migrated(ctx, row)?;
    overlap(changes)?;
    for change in changes {
        writable(&ct, &change.path, false)?;
        known(writer.as_ref(), &change.path)?;
    }
    let (post, applied) = apply_changes(doc.clone(), changes)?;
    validate(&ct, &post)?;
    unique(ctx, &ct, Some(row.id), &post, Some(changes))?;
    Ok(RecordPlan {
        record,
        doc: Some(post),
        changes: applied,
        lifecycle: None,
        skipped: Vec::new(),
        revision: ct.revision,
        ct,
    })
}

/// The rules a record lives under: its type's current ones, or its own
/// revision's while a transition has retired that revision.
fn own_rules(ctx: &Ctx<'_, '_>, row: &RecordRow, ct: &CompiledType) -> Step<CompiledType> {
    if ctx.permitted(row.type_id)?.contains(&row.revision) {
        return Ok(ct.clone());
    }
    revision_rules(ctx, row)
}

/// Always load the actual revision recorded on the row, including an older
/// revision still permitted under a compatible type change.
fn revision_rules(ctx: &Ctx<'_, '_>, row: &RecordRow) -> Step<CompiledType> {
    match ctx
        .definition(row.revision)?
        .filter(|own| own.type_id == row.type_id)
    {
        Some(own) => Ok(own),
        None => ctx.missing_definition(
            Some(row.type_id),
            row.revision,
            implicit_core(row.type_id),
            Key::Record(row.record),
        ),
    }
}

fn delete(ctx: &Ctx<'_, '_>, record: RecordId, state: &State) -> Step<RecordPlan> {
    let (row, doc) = present(ctx, record, state)?;
    let ct = current_of(ctx, row)?;
    let rules = revision_rules(ctx, row)?;
    if ct.builtin.is_some() || rules.builtin.is_some() {
        return no(
            RejectCode::DerivedField,
            None,
            "delete the Note through the note lifecycle",
        );
    }
    // A rule change cannot remove either revision's protection: Delete
    // touches every field of the record, even optional fields not present.
    let fields = || rules.fields.iter().chain(&ct.fields);
    if let Some(field) = fields().find(|field| field.write == WritePolicy::ActionOnly) {
        return no(
            RejectCode::ActionOnly,
            Some(&field.path),
            "a record with action-only fields is removed by its app's actions",
        );
    }
    if let Some(field) = fields().find(|field| field.write == WritePolicy::Derived) {
        return no(
            RejectCode::DerivedField,
            Some(&field.path),
            "a record with derived fields cannot be deleted directly",
        );
    }
    // The record's own fields, so an Undo can restore it as it was.
    let changes = leaves(doc, &rules, false)?
        .into_iter()
        .map(|(path, value)| Change {
            path,
            old: Some(value),
            new: None,
        })
        .collect();
    Ok(RecordPlan {
        record,
        doc: None,
        changes,
        lifecycle: Some((Some(true), false)),
        skipped: Vec::new(),
        // A deleted record keeps its revision: restoring it restores that.
        revision: row.revision,
        ct,
    })
}

fn undo_remove(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    target: MutationId,
    position: Position,
) -> Step<RecordPlan> {
    let (row, _) = present(ctx, record, state)?;
    if position.0 > i64::MAX as u64 {
        return no(
            RejectCode::Schema,
            None,
            "undo position exceeds the supported range",
        );
    }
    let unchanged: bool = ctx.tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_field_clock WHERE rec=?1 AND path='' AND mutation=?2 AND position=?3)
         AND NOT EXISTS(SELECT 1 FROM data_field_clock WHERE rec=?1 AND (mutation!=?2 OR position!=?3))",
        rusqlite::params![row.id, target.0.as_slice(), crate::store::integer(position.0)?],
        |r| r.get(0)).map_err(crate::store::sql)?;
    if !unchanged || row.changed_at != Some(position) {
        return no(
            RejectCode::NothingToUndo,
            None,
            "record changed since the creation or restoration",
        );
    }
    delete(ctx, record, state)
}

fn undo(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    target: MutationId,
    changes: &[FieldChange],
) -> Step<RecordPlan> {
    if !state.exists {
        return missing_undo_record(ctx, record);
    }
    let row = state.row.as_ref().expect("an existing record has a row");
    let ct = current_of(ctx, row)?;
    overlap(changes)?;
    let undelete = match &state.doc {
        Some(_) => false,
        None if clock(ctx.tx, row.id, "")? == Some(target) => true,
        None => {
            return no(
                RejectCode::Deleted,
                None,
                "the record was deleted by another change",
            );
        }
    };
    // A restored record returns on its own revision, under that revision's
    // rules, even if a transition retired it meanwhile: it is then an
    // ordinary unmigrated record. Any other Undo of one is refused.
    if !undelete {
        migrated(ctx, row)?;
    }
    let rules = own_rules(ctx, row, &ct)?;
    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    for change in changes {
        if clock(ctx.tx, row.id, &change.path.as_pointer())? == Some(target) {
            applied.push(change.clone());
        } else {
            skipped.push(change.path.clone());
        }
    }
    if applied.is_empty() && !undelete {
        let paths: Vec<_> = skipped.iter().map(FieldPath::as_pointer).collect();
        return no(
            RejectCode::NothingToUndo,
            None,
            format!("changed since by later edits: {}", paths.join(", ")),
        );
    }
    for change in &applied {
        writable(&rules, &change.path, false)?;
    }
    let base = state
        .doc
        .clone()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let (post, applied) = apply_changes(base, &applied)?;
    validate(&rules, &post)?;
    let touched: Vec<_> = applied
        .iter()
        .map(|c| FieldChange {
            path: c.path.clone(),
            value: None,
        })
        .collect();
    unique(
        ctx,
        &ct,
        Some(row.id),
        &post,
        (!undelete).then_some(touched.as_slice()),
    )?;
    Ok(RecordPlan {
        record,
        doc: Some(post),
        changes: applied,
        lifecycle: undelete.then_some((Some(false), true)),
        skipped,
        revision: rules.revision,
        ct,
    })
}

/// An Undo names its record. Without it here, the undone mutation was not
/// applied in this audience once this replica holds the whole scope and can
/// show the record; until then the Undo waits behind that record only.
fn missing_undo_record<T>(ctx: &Ctx<'_, '_>, record: RecordId) -> Step<T> {
    if ctx.ordered() && ctx.note_gap(record)? {
        return wait(
            Wait::MissingRecord(record),
            Park {
                key: Key::Record(record),
                holds: true,
            },
        );
    }
    if ctx.ordered() && !ctx.covered()? {
        return wait(
            Wait::Coverage(ctx.scope),
            Park {
                key: Key::Record(record),
                holds: true,
            },
        );
    }
    no(
        RejectCode::NotFound,
        None,
        "the undone mutation was not applied in this audience",
    )
}

fn run_action(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    app: AppId,
    action: &str,
    changes: &[FieldChange],
) -> Step<RecordPlan> {
    if !matches!(ctx.actor, Actor::Job { action: Some(delegated), .. } if delegated == action) {
        return no(
            RejectCode::ActionOnly,
            None,
            format!("action {action} runs only as the job delegated to run it"),
        );
    }
    let (row, doc) = present(ctx, record, state)?;
    let ct = current_of(ctx, row)?;
    app_active(ctx, Some(app))?;
    migrated(ctx, row)?;
    let Some(declared) = ct.actions.iter().find(|a| a.name == action) else {
        return no(
            RejectCode::ActionOnly,
            None,
            format!("action {action} is not declared for this type"),
        );
    };
    if declaring_app(ctx, &ct, action)? != Some(app) {
        return no(
            RejectCode::ActionOnly,
            None,
            format!("action {action} belongs to another app"),
        );
    }
    overlap(changes)?;
    for change in changes {
        if !declared.effects.contains(&change.path) {
            return no(
                RejectCode::ActionOnly,
                Some(&change.path),
                format!("outside the declared effects of {action}"),
            );
        }
        writable(&ct, &change.path, true)?;
    }
    let (post, applied) = apply_changes(doc.clone(), changes)?;
    validate(&ct, &post)?;
    unique(ctx, &ct, Some(row.id), &post, Some(changes))?;
    Ok(RecordPlan {
        record,
        doc: Some(post),
        changes: applied,
        lifecycle: None,
        skipped: Vec::new(),
        revision: ct.revision,
        ct,
    })
}

/// Moves a record off a revision a transition retired. `to` must be
/// permitted and `from` must be the record's revision, no longer permitted.
/// Paths may be declared by either revision. When `to` declares a migration
/// that applies to the accepted document, the changes must include every
/// change it makes, unaltered; those may reach action-only fields (only a
/// person's device declares such steps). Any further change, or every change
/// when no declared migration applies, follows the ordinary write rules, so
/// a record the declared steps leave invalid is fixed by hand in the same
/// migration. The result is validated against `to`.
fn migrate(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    from: RevisionId,
    to: RevisionId,
    changes: &[FieldChange],
) -> Step<RecordPlan> {
    let (row, doc) = present(ctx, record, state)?;
    let ct = current_of(ctx, row)?;
    if row.revision != from {
        return no(
            RejectCode::RevisionNotPermitted,
            None,
            format!("the record is on revision {}", hex(&row.revision.0)),
        );
    }
    let permitted = ctx.permitted(row.type_id)?;
    if !permitted.contains(&to) {
        return no(
            RejectCode::RevisionNotPermitted,
            None,
            format!("revision {} is not permitted; transition first", hex(&to.0)),
        );
    }
    if permitted.contains(&from) {
        return no(
            RejectCode::RevisionNotPermitted,
            None,
            "the record is already on a permitted revision",
        );
    }
    let target = ctx.definition(to)?.filter(|t| t.type_id == row.type_id);
    let source = ctx.definition(from)?.filter(|t| t.type_id == row.type_id);
    let (Some(target), Some(source)) = (target, source) else {
        return no(
            RejectCode::RevisionNotPermitted,
            None,
            "both revisions must be definitions of the record's type",
        );
    };
    overlap(changes)?;
    // The declared migration's changes, when it applies to this document.
    let steps = registry::migration_ops(ctx.tx, ctx.sid, to)?;
    let declared = evolve::changes(&steps, doc).unwrap_or_default();
    for change in &declared {
        if !changes.contains(change) {
            return no(
                RejectCode::Schema,
                Some(&change.path),
                "the changes leave out or alter what the revision's migration does",
            );
        }
    }
    for change in changes {
        let field = target
            .field(&change.path)
            .map(|_| &target)
            .or_else(|| source.field(&change.path).map(|_| &source));
        let Some(declaring) = field else {
            return no(
                RejectCode::UnknownField,
                Some(&change.path),
                "declared by neither revision",
            );
        };
        writable(declaring, &change.path, declared.contains(change))?;
    }
    let (post, applied) = apply_changes(doc.clone(), changes)?;
    validate(&target, &post)?;
    unique(ctx, &target, Some(row.id), &post, Some(changes))?;
    Ok(RecordPlan {
        record,
        doc: Some(post),
        changes: applied,
        lifecycle: None,
        skipped: Vec::new(),
        revision: to,
        ct,
    })
}

/// Makes a projected plain Note a record of `type_id`, a specialisation of
/// the Note: it keeps its identity and derived title, takes the
/// specialisation's current revision and gains the specialisation's own
/// fields from `doc`, validated like a creation's. What the type alone
/// decides comes first, so a replica that has not materialised the Note yet
/// reaches the same refusals. The projection comes from the Note's own log,
/// not this one: until this replica holds it, the binding waits whatever the
/// coverage, and the host replays parked work once it creates the projection.
fn bind_note(
    ctx: &Ctx<'_, '_>,
    record: RecordId,
    state: &State,
    type_id: TypeId,
    revision: RevisionId,
    doc: &Value,
) -> Step<RecordPlan> {
    let note = TypeId::core("note");
    // A record of another type, present or deleted, is ordered state every
    // covered replica holds: it is never a Note, whatever arrives later.
    if let Some(row) = &state.row
        && row.type_id != note
        && !ctx
            .current(row.type_id)?
            .is_some_and(|ct| ct.is_family_member_of(note))
    {
        return no(
            RejectCode::ConcreteTypeChange,
            None,
            format!(
                "record {} is not a Note; its concrete type does not change",
                hex(&record.0)
            ),
        );
    }
    let Some(ct) = ctx.current(type_id)? else {
        return ctx.missing_definition(Some(type_id), revision, false, Key::Type(type_id));
    };
    if ct.type_id == note || ct.kind != TypeKind::Record || !ct.is_family_member_of(note) {
        return no(
            RejectCode::ConcreteTypeChange,
            None,
            format!(
                "type {} is not a specialisation of the Note",
                hex(&type_id.0)
            ),
        );
    }
    app_active(ctx, ct.app)?;
    let writer = writer(ctx, &ct, revision, false, Key::Type(type_id))?;
    let leaves = leaves(doc, &ct, true)?;
    for (path, _) in &leaves {
        if ct
            .field(path)
            .is_some_and(|field| field.declared_by == note)
        {
            return no(
                RejectCode::DerivedField,
                Some(path),
                "the Note's own fields are not bound; use the note body edit through the note writer",
            );
        }
        writable(&ct, path, false)?;
        known(writer.as_ref(), path)?;
    }
    // Ordered evaluation reads accepted state, which a removed (hidden) Note
    // keeps; only a local save sees the removal.
    let (row, base) = match (&state.row, &state.doc) {
        (Some(row), Some(base)) => (row, base),
        _ if ctx.ordered() => {
            return wait(
                Wait::MissingRecord(record),
                Park {
                    key: Key::Record(record),
                    holds: true,
                },
            );
        }
        (Some(_), None) => return no(RejectCode::Deleted, None, "the note was removed"),
        _ => {
            return no(
                RejectCode::NotFound,
                None,
                format!("note {} is not available here", hex(&record.0)),
            );
        }
    };
    if row.type_id == type_id {
        return no(
            RejectCode::Exists,
            None,
            format!("the note is already a {}", ct.name),
        );
    }
    if row.type_id != note {
        return no(
            RejectCode::ConcreteTypeChange,
            None,
            format!(
                "the record is already of type {}; its concrete type does not change",
                hex(&row.type_id.0)
            ),
        );
    }
    let changes: Vec<FieldChange> = leaves
        .into_iter()
        .map(|(path, value)| FieldChange {
            path,
            value: Some(value),
        })
        .collect();
    let (post, applied) = apply_changes(base.clone(), &changes)?;
    validate(&ct, &post)?;
    unique(ctx, &ct, Some(row.id), &post, None)?;
    Ok(RecordPlan {
        record,
        doc: Some(post),
        changes: applied,
        lifecycle: None,
        skipped: Vec::new(),
        revision: ct.revision,
        ct,
    })
}
