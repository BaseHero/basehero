//! An authority-bound typed-data API. The host supplies both verified authority and
//! the SQLite lifecycle; callers must not construct authority from identifiers
//! supplied by an app, page or tool invocation.
use std::cell::RefCell;

use rusqlite::{Connection, Transaction, params};
use serde::Serialize;

use crate::{
    Actor, CompiledType, CoreCatalogue, DataError, KeyRef, MutationId, RecordId, RejectCode,
    Rejection, RevisionId, Scope, TypeId, TypeKind, compat, compose, definition,
    index::{self, IndexState},
    mutation::{
        self,
        history::{self, HistoryCursor, HistoryEntry},
        ops::Operation,
        pending::{self, LocalSaved, RejectedWork, SubmitError},
        undo,
    },
    query::{self, Aggregate, AggregateResult, Budget, Page, Query, QueryError},
    store::{
        records::{self, RecordRow},
        registry, sql,
    },
    validate,
};

/// Implemented by a host from its verified account and delegation state.
/// Never derive it from caller-supplied ids at a page/app boundary.
pub trait Authority {
    fn actor(&self) -> Actor;
    fn reads(&self) -> Vec<Scope>;
    fn write(&self) -> Option<Scope>;
    /// Trusted host evidence for this exact management operation, never a tool flag.
    fn confirm_rule_change(
        &self,
        _request: &crate::admission::Confirmation,
        _at: Option<crate::Position>,
    ) -> Result<bool, DataError> {
        Ok(false)
    }
}
impl<A: Authority> crate::admission::HostAdmission for A {
    fn confirms(
        &self,
        request: &crate::admission::Confirmation,
        at: Option<crate::Position>,
    ) -> Result<bool, DataError> {
        if self.actor() != request.actor || self.write() != Some(request.scope) {
            return Ok(false);
        }
        self.confirm_rule_change(request, at)
    }
    fn may_read_source(
        &self,
        actor: &Actor,
        source: Scope,
        _at: Option<crate::Position>,
    ) -> Result<bool, DataError> {
        Ok(self.actor() == *actor && self.reads().contains(&source))
    }
}

/// The host owns the connection/read pool and adds outbox publication to `write`.
/// Writes must commit on `Ok`, roll back on `Err`, and publish only after commit.
pub trait Store {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError>;
    fn write<R>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError>;
    fn core(&self) -> &dyn CoreCatalogue;
    /// The host may atomically append the typed outbox entry alongside the
    /// pending mutation. The default is the plain-SQLite fixture store.
    fn submit_pending(
        &self,
        scope: Scope,
        actor: &Actor,
        op: Operation,
        admission: &dyn crate::admission::HostAdmission,
        mutation: Option<MutationId>,
    ) -> Result<LocalSaved, SessionError> {
        self.write(|tx| {
            tx.execute_batch("SAVEPOINT bh_data_submit").map_err(sql)?;
            let result = match mutation {
                Some(id) => {
                    pending::submit_with_id(tx, self.core(), scope, actor, op, admission, id)
                }
                None => {
                    pending::submit_with_admission(tx, self.core(), scope, actor, op, admission)
                }
            };
            if result.is_err() {
                tx.execute_batch("ROLLBACK TO bh_data_submit")
                    .map_err(sql)?;
            }
            tx.execute_batch("RELEASE bh_data_submit").map_err(sql)?;
            Ok(result)
        })
        .map_err(SessionError::Data)?
        .map_err(SessionError::from)
    }
}
impl<S: Store + ?Sized> Store for &S {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError> {
        (**self).read(f)
    }
    fn write<R>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError> {
        (**self).write(f)
    }
    fn core(&self) -> &dyn CoreCatalogue {
        (**self).core()
    }
    fn submit_pending(
        &self,
        scope: Scope,
        actor: &Actor,
        op: Operation,
        admission: &dyn crate::admission::HostAdmission,
        mutation: Option<MutationId>,
    ) -> Result<LocalSaved, SessionError> {
        (**self).submit_pending(scope, actor, op, admission, mutation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeRef {
    Current(TypeId),
    Revision(RevisionId),
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("exact host confirmation required")]
    ConfirmationRequired(Box<crate::admission::Confirmation>),
    #[error("rejected: {0:?}")]
    Rejected(Rejection),
    #[error(transparent)]
    Data(#[from] DataError),
}

#[derive(Clone, Debug, Serialize)]
pub struct TypeDescription {
    pub compiled: CompiledType,
    pub docs: crate::TypeDocs,
    pub operations: Vec<String>,
    pub queries: Vec<crate::QueryDecl>,
    pub evolution: Option<RevisionId>,
    pub inherited: Vec<(TypeId, RevisionId)>,
}

/// An inspectable proposal, not a mutation. Its exact bytes remain private to
/// the session API; approval rechecks them rather than trusting client fields.
#[derive(Clone, Debug, Serialize)]
pub struct Proposal {
    pub scope: Scope,
    pub revision: RevisionId,
    #[serde(serialize_with = "serialize_change")]
    pub change: compat::Change,
    pub affected_records: u64,
    pub needs_device: bool,
    pub migration: Option<String>,
    pub summary: String,
    /// Rules used to prepare this impact; the host re-evaluates them before
    /// issuing any approval request. Not itself authority to confirm.
    prior: Option<crate::admission::PriorRules>,
    #[serde(skip)]
    bytes: Vec<u8>,
}

pub struct DataSession<S: Store, A: Authority> {
    store: S,
    authority: A,
    budget: Budget,
}

impl<S: Store, A: Authority> DataSession<S, A> {
    /// Each call checks verified authority; caller-supplied scopes select data,
    /// never grant access to it.
    pub fn new(store: S, authority: A) -> Self {
        Self {
            store,
            authority,
            budget: Budget::INTERACTIVE,
        }
    }

    fn readable(&self, scope: Scope) -> Result<(), DataError> {
        if self.authority.reads().contains(&scope) {
            Ok(())
        } else {
            Err(DataError::Unauthorized)
        }
    }
    fn write_scope(&self) -> Result<Scope, Rejection> {
        self.authority
            .write()
            .ok_or_else(|| reject(RejectCode::Unauthorized, "no write authority"))
    }
    pub fn list_types(&self, scope: Scope) -> Result<Vec<CompiledType>, DataError> {
        self.readable(scope)?;
        self.store
            .read(|conn| match records::lookup_scope(conn, scope)? {
                Some(sid) => registry::list_types(conn, sid, self.store.core()),
                None => Ok(self
                    .store
                    .core()
                    .core_type(TypeId::core("note"))
                    .into_iter()
                    .collect()),
            })
    }
    pub fn describe(&self, scope: Scope, reference: TypeRef) -> Result<TypeDescription, DataError> {
        self.readable(scope)?;
        let ct = self
            .store
            .read(|conn| {
                let sid = records::lookup_scope(conn, scope)?;
                match reference {
                    TypeRef::Current(id) => match sid {
                        Some(sid) => registry::current(conn, sid, id, self.store.core()),
                        None => Ok(self.store.core().core_type(id)),
                    },
                    TypeRef::Revision(rev) => match sid {
                        Some(sid) => registry::compiled(conn, sid, rev),
                        None => Ok(None),
                    },
                }
            })?
            .ok_or(DataError::NotFound)?;
        let docs = ct.docs.clone();
        let queries = ct.queries.clone();
        let inherited = ct.lineage.iter().skip(1).copied().collect();
        let evolution = ct.previous;
        let mut operations = match ct.kind {
            TypeKind::Value => Vec::new(),
            // The note writer owns a Note's body, title and lifecycle; a
            // specialisation is made by binding a Note, and its own fields
            // take ordinary edits.
            TypeKind::Record if ct.builtin.is_some() => {
                let mut operations = vec!["note_body_edit".to_string()];
                if ct.type_id != TypeId::core("note") {
                    operations.push("bind_note".to_string());
                }
                if ct
                    .fields
                    .iter()
                    .any(|f| f.write == crate::WritePolicy::Direct)
                {
                    operations.extend(["edit".to_string(), "undo".to_string()]);
                }
                operations
            }
            TypeKind::Record => vec![
                "create".to_string(),
                "edit".to_string(),
                "delete".to_string(),
                "undo".to_string(),
            ],
        };
        if ct.kind == TypeKind::Record {
            operations.extend(
                ct.actions
                    .iter()
                    .map(|action| format!("action:{}", action.name)),
            );
        }
        Ok(TypeDescription {
            compiled: ct,
            docs,
            operations,
            queries,
            evolution,
            inherited,
        })
    }
    pub fn query(&self, scope: Scope, q: &Query) -> Result<Page, QueryError> {
        if self.readable(scope).is_err() {
            return Err(QueryError::Unauthorized);
        }
        self.store
            .read(|conn| {
                Ok(query::run(
                    conn,
                    scope,
                    &self.authority.reads(),
                    self.store.core(),
                    q,
                    self.budget,
                ))
            })
            .map_err(QueryError::from)?
    }
    pub fn aggregate(&self, scope: Scope, q: &Aggregate) -> Result<AggregateResult, QueryError> {
        if self.readable(scope).is_err() {
            return Err(QueryError::Unauthorized);
        }
        self.store
            .read(|conn| {
                Ok(query::aggregate(
                    conn,
                    scope,
                    &self.authority.reads(),
                    self.store.core(),
                    q,
                    self.budget,
                ))
            })
            .map_err(QueryError::from)?
    }
    pub fn get(&self, scope: Scope, record: RecordId) -> Result<Option<RecordRow>, DataError> {
        self.readable(scope)?;
        self.store.read(|conn| {
            Ok(match records::lookup_scope(conn, scope)? {
                Some(sid) => records::get(conn, sid, record)?.filter(|row| !row.deleted),
                None => None,
            })
        })
    }
    pub fn history(
        &self,
        scope: Scope,
        record: RecordId,
        before: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>, DataError> {
        self.readable(scope)?;
        self.store
            .read(|conn| history::of(conn, scope, record, limit.min(200), before))
    }
    pub fn rejected_work(&self, scope: Scope) -> Result<Vec<RejectedWork>, DataError> {
        self.readable(scope)?;
        self.store.read(|conn| pending::rejected(conn, scope))
    }
    pub fn submit(&self, op: Operation) -> Result<LocalSaved, SessionError> {
        let scope = self.write_scope()?;
        let actor = self.authority.actor();
        self.store
            .submit_pending(scope, &actor, op, &self.authority, None)
    }
    pub fn undo(&self, target: MutationId) -> Result<LocalSaved, SessionError> {
        let scope = self.write_scope()?;
        let operation = self.store.read(|conn| undo::prepare(conn, scope, target))?;
        self.submit(operation)
    }
    /// Checks local rules using the exact submission evaluator, rolling back
    /// every temporary effect (including a successful pending overlay).
    pub fn validate(&self, op: &Operation) -> Result<(), SessionError> {
        let scope = self.write_scope()?;
        let actor = self.authority.actor();
        self.store
            .write(|tx| {
                tx.execute_batch("SAVEPOINT bh_data_validate")
                    .map_err(sql)?;
                let result = pending::submit_with_admission(
                    tx,
                    self.store.core(),
                    scope,
                    &actor,
                    op.clone(),
                    &self.authority,
                );
                tx.execute_batch("ROLLBACK TO bh_data_validate; RELEASE bh_data_validate")
                    .map_err(sql)?;
                Ok(result.map(|_| ()))
            })
            .map_err(SessionError::Data)?
            .map_err(SessionError::from)
    }
    pub fn ensure_index(
        &self,
        scope: Scope,
        family: TypeId,
        keys: Vec<KeyRef>,
    ) -> Result<IndexState, DataError> {
        self.readable(scope)?;
        self.store.write(|tx| {
            let sid = records::lookup_scope(tx, scope)?.ok_or(DataError::NotFound)?;
            let ty = registry::current(tx, sid, family, self.store.core())?
                .ok_or(DataError::NotFound)?;
            if keys
                .iter()
                .any(|k| matches!(k, KeyRef::Field(p) if ty.field(p).is_none()))
            {
                return Err(DataError::Definition(
                    "index key is not declared on family".into(),
                ));
            }
            let id = index::ensure_local(tx, sid, family, keys)?;
            index::state(tx, id)
        })
    }
    pub fn prepare_change(&self, bytes: &[u8]) -> Result<Proposal, DataError> {
        let scope = self.write_scope().map_err(|_| DataError::Unauthorized)?;
        let def = definition::parse(bytes)?;
        let revision = RevisionId::of(bytes);
        self.store.read(|conn| {
            let sid = records::lookup_scope(conn, scope)?;
            let failure = RefCell::new(None);
            let compiled = compose::compile(&def, revision, &|id, rev| {
                let found = match sid {
                    Some(sid) => match registry::compiled(conn, sid, rev) {
                        Ok(found) => found.filter(|ct| ct.type_id == id),
                        Err(error) => {
                            failure.borrow_mut().get_or_insert(error);
                            None
                        }
                    },
                    None => None,
                };
                found.or_else(|| {
                    self.store
                        .core()
                        .core_type(id)
                        .filter(|ct| ct.revision == rev)
                })
            });
            if let Some(error) = failure.into_inner() {
                return Err(error);
            }
            let next = compiled.map_err(|err| DataError::Definition(err.to_string()))?;
            let prev = match sid {
                Some(sid) => registry::current(conn, sid, def.type_id, self.store.core())?,
                None => self.store.core().core_type(def.type_id),
            };
            let change = prev
                .as_ref()
                .map(|old| mutation::effective_change(conn, sid, &def, &next, old, None))
                .transpose()?
                .unwrap_or(compat::Change {
                    compatible: true,
                    rule_change: false,
                    index_change: false,
                    doc_only: false,
                    reasons: vec!["new type".into()],
                });
            let affected_records = match sid {
                Some(sid) => conn
                    .query_row(
                        "SELECT count(*) FROM data_record WHERE scope=?1 AND type=?2 AND deleted=0",
                        params![sid, def.type_id.0.as_slice()],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(sql)? as u64,
                None => 0,
            };
            let needs_device = mutation::needs_device(prev.is_some(), &change);
            let migration =
                (!def.evolution.migration.is_empty()).then(|| def.evolution.migration.clone());
            let summary = change.reasons.join("; ");
            let prior = if needs_device {
                Some(crate::admission::PriorRules::Type {
                    revision: prev.as_ref().map(|ct| ct.revision),
                    permitted: match sid {
                        Some(sid) => {
                            registry::permitted(conn, sid, def.type_id, self.store.core())?
                        }
                        None => prev
                            .as_ref()
                            .map(|ct| vec![ct.revision])
                            .unwrap_or_default(),
                    },
                })
            } else {
                None
            };
            Ok(Proposal {
                scope,
                revision,
                change,
                affected_records,
                needs_device,
                migration,
                summary,
                prior,
                bytes: bytes.to_vec(),
            })
        })
    }
    pub fn approve(&self, proposal: Proposal) -> Result<LocalSaved, SessionError> {
        if self.write_scope()? != proposal.scope {
            return Err(reject(
                RejectCode::Unauthorized,
                "proposal belongs to another scope",
            )
            .into());
        }
        if !matches!(self.authority.actor(), Actor::Device { .. }) {
            return Err(reject(RejectCode::DeviceOnly, "rule approvals require a device").into());
        }
        if RevisionId::of(&proposal.bytes) != proposal.revision {
            return Err(reject(RejectCode::Schema, "proposal bytes and revision differ").into());
        }
        self.submit(Operation::DefineType {
            bytes: proposal.bytes,
        })
    }
    /// Prepared prior rules are private so a caller cannot refresh a stale
    /// proposal merely by changing its displayed fields.
    pub fn proposal_prior(proposal: &Proposal) -> Option<&crate::admission::PriorRules> {
        proposal.prior.as_ref()
    }
    /// Exact proposed definition bytes for a trusted host approval request.
    pub fn proposal_operation(proposal: &Proposal) -> Operation {
        Operation::DefineType {
            bytes: proposal.bytes.clone(),
        }
    }
    pub fn validate_example(
        &self,
        scope: Scope,
        reference: TypeRef,
        example: &serde_json::Value,
    ) -> Result<(), SessionError> {
        let ct = self.describe(scope, reference)?;
        validate::Compiled::new(&ct.compiled.effective_schema, &ct.compiled.resources)?
            .validate(example)
            .map_err(SessionError::Rejected)
    }
}

fn serialize_change<S: serde::Serializer>(
    change: &compat::Change,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde_json::json!({
        "compatible": change.compatible,
        "rule_change": change.rule_change,
        "index_change": change.index_change,
        "doc_only": change.doc_only,
        "reasons": change.reasons,
    })
    .serialize(serializer)
}

fn reject(code: RejectCode, detail: impl Into<String>) -> Rejection {
    Rejection {
        code,
        path: None,
        detail: detail.into(),
    }
}
impl From<Rejection> for SessionError {
    fn from(rejection: Rejection) -> Self {
        Self::Rejected(rejection)
    }
}
impl From<SubmitError> for SessionError {
    fn from(err: SubmitError) -> Self {
        match err {
            SubmitError::ConfirmationRequired(request) => Self::ConfirmationRequired(request),
            SubmitError::Rejected(rejection) => Self::Rejected(rejection),
            SubmitError::Data(error) => Self::Data(error),
        }
    }
}
