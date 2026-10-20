//! Typed data for the currently authorized account's own ordinary audience.
use std::sync::{Arc, Mutex, Weak};

use bh_account::{DevicePublicKeys, owner::AccountCapability};
use bh_data::{
    Actor, DataError, MutationId, RejectCode, Rejection, Scope,
    admission::{Confirmation, HostAdmission, PriorRules},
    catalogue::Shipped,
    mutation::{ops::Operation, pending::LocalSaved},
    session::{Authority, DataSession, Proposal, SessionError, Store},
};
use bh_storage::{DeviceDatabase, ReadPool, SubmitTypedError};
use rusqlite::{Connection, Transaction};

use crate::{
    AccountAuthority, ContainerId, ORDINARY_AUDIENCE, Owner, OwnerError, RecordsWakeSlot,
    Scheduler, Session,
};

const APPROVAL_DOMAIN: &[u8] = b"bh/data-approval/v1\0";

/// A signature request binds a fresh mutation identity, the exact publishable
/// payload and this account generation. It holds the operation; no caller may
/// substitute a different operation after the native signer returns.
pub struct ApprovalRequest {
    scope: Scope,
    actor: Actor,
    head: bh_account::Head,
    capability: Arc<AccountCapability>,
    prior: PriorRules,
    mutation: MutationId,
    operation: Operation,
    payload: Vec<u8>,
    message: Vec<u8>,
}
impl ApprovalRequest {
    pub fn message(&self) -> &[u8] {
        &self.message
    }
    pub fn prior(&self) -> &PriorRules {
        &self.prior
    }
}
fn message(scope: Scope, actor: &Actor, head: bh_account::Head, payload: &[u8]) -> Vec<u8> {
    let Actor::Device { account, device } = actor else {
        unreachable!("only a device requests approval")
    };
    let mut out = Vec::with_capacity(APPROVAL_DOMAIN.len() + 140 + payload.len());
    out.extend_from_slice(APPROVAL_DOMAIN);
    out.extend_from_slice(&scope.base);
    out.extend_from_slice(&scope.audience);
    out.extend_from_slice(account);
    out.extend_from_slice(device);
    out.extend_from_slice(&head.position.to_be_bytes());
    out.extend_from_slice(&head.hash);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn refused(detail: &str) -> Rejection {
    Rejection {
        code: RejectCode::Unauthorized,
        path: None,
        detail: detail.into(),
    }
}
fn session_rejection(error: SessionError) -> Rejection {
    match error {
        SessionError::Rejected(rejection) => rejection,
        SessionError::ConfirmationRequired(_) => refused("approval does not match this change"),
        SessionError::Data(error) => refused(&format!("typed save failed: {error}")),
    }
}

/// The device host alone constructs this from its current account capability.
/// App/page callers may select records or an operation, never their own base,
/// audience, actor or authority. A retained handle stops working on revocation.
pub struct RecordsHandle {
    session: Session,
    capability: Arc<AccountCapability>,
    scope: Scope,
    signing: [u8; 32],
    readers: Option<Arc<ReadPool>>,
    wake: RecordsWakeSlot,
    maintenance: Weak<Scheduler>,
    id: ContainerId,
}
impl Owner {
    pub fn records(&self, id: ContainerId) -> Result<RecordsHandle, OwnerError> {
        let session = self.account_session(id)?;
        let guard = session.lock().expect("container session lock");
        let (base, capability) = guard.authority().current().ok_or(OwnerError::Unbound)?;
        let db = guard.shared_database();
        let db = db.lock().expect("container writer lock");
        let identity = db.device_identity()?.ok_or(OwnerError::Unbound)?;
        let keys = DevicePublicKeys::new(identity.signing, identity.control, identity.receiving)
            .map_err(|_| OwnerError::Unbound)?;
        if keys.id() != capability.device_id() {
            return Err(OwnerError::Unbound);
        }
        let readers = db.read_pool();
        Ok(RecordsHandle {
            session: Arc::clone(&session),
            capability,
            scope: Scope {
                base,
                audience: ORDINARY_AUDIENCE,
            },
            signing: identity.signing,
            readers,
            wake: Arc::clone(&self.records_wake),
            maintenance: Arc::downgrade(&self.compaction),
            id,
        })
    }
    /// Installed by the native sync host. Called only after a durable save;
    /// the callback never runs with a database or container guard held.
    pub fn set_records_wake(&self, wake: Arc<dyn Fn(ContainerId) + Send + Sync>) {
        *self.records_wake.lock().expect("records wake lock") = Some(wake);
    }
}
impl RecordsHandle {
    fn current(&self, guard: &crate::coordinator::Coordinator<AccountAuthority>) -> bool {
        guard
            .authority()
            .current()
            .is_some_and(|(base, capability)| {
                base == self.scope.base && Arc::ptr_eq(&capability, &self.capability)
            })
    }
    pub fn scope(&self) -> Scope {
        self.scope
    }
    /// All ordinary DataSession read/query/validation/tool operations use this
    /// same scoped host store. Submission is overridden to queue typed work.
    /// Native code holding this handle is trusted; page, job and tool adapters
    /// must use this bound session, not raw store closures.
    pub fn session(&self) -> DataSession<&Self, &Self> {
        DataSession::new(self, self)
    }
    pub fn prepare_change(&self, bytes: &[u8]) -> Result<Proposal, DataError> {
        self.session().prepare_change(bytes)
    }
    pub fn submit(&self, op: Operation) -> Result<LocalSaved, SessionError> {
        self.session().submit(op)
    }
    /// Undo with the local evaluator's skipped paths in the saved result.
    pub fn undo(&self, target: MutationId) -> Result<LocalSaved, SessionError> {
        self.session().undo(target)
    }
    pub fn approval_request(&self, proposal: &Proposal) -> Result<ApprovalRequest, Rejection> {
        if !self.capability.is_current() || proposal.scope != self.scope {
            return Err(refused("proposal is outside current account authority"));
        }
        let operation = DataSession::<&Self, &Self>::proposal_operation(proposal);
        let Operation::DefineType { bytes } = &operation else {
            unreachable!()
        };
        if bh_data::RevisionId::of(bytes) != proposal.revision {
            return Err(refused("proposal bytes and revision differ"));
        }
        let request = self.approval_request_operation(operation)?;
        if DataSession::<&Self, &Self>::proposal_prior(proposal) != Some(&request.prior) {
            return Err(refused("proposal rules changed; prepare again"));
        }
        Ok(request)
    }
    /// A management operation must currently require confirmation. The dry
    /// run uses the same evaluator and rolls back any temporary effects.
    pub fn approval_request_operation(
        &self,
        operation: Operation,
    ) -> Result<ApprovalRequest, Rejection> {
        if !self.capability.is_current() {
            return Err(refused("account authority changed"));
        }
        let prior = match self.session().validate(&operation) {
            Err(SessionError::ConfirmationRequired(request))
                if request.scope == self.scope
                    && request.actor == self.actor()
                    && request.operation == operation =>
            {
                request.prior
            }
            _ => {
                return Err(refused(
                    "operation does not require an applicable confirmation",
                ));
            }
        };
        let mutation = MutationId::random();
        let payload =
            bh_data::payload::encode_with_confirmation(mutation, &operation, Some(prior.clone()))
                .map_err(|_| refused("proposal cannot be encoded"))?;
        let actor = self.actor();
        let head = self.capability.head();
        let message = message(self.scope, &actor, head, &payload);
        Ok(ApprovalRequest {
            scope: self.scope,
            actor,
            head,
            capability: Arc::clone(&self.capability),
            prior,
            mutation,
            operation,
            payload,
            message,
        })
    }
    /// Verify the ordinary device key against the bound account capability,
    /// then use a one-operation admission. No signature enters the outbox.
    pub fn approve(
        &self,
        request: ApprovalRequest,
        signature: [u8; 64],
    ) -> Result<LocalSaved, Rejection> {
        if request.scope != self.scope
            || request.actor != self.actor()
            || request.head != self.capability.head()
            || !Arc::ptr_eq(&request.capability, &self.capability)
            || !request.capability.is_current()
            || bh_data::payload::encode_with_confirmation(
                request.mutation,
                &request.operation,
                Some(request.prior.clone()),
            )
            .ok()
            .as_deref()
                != Some(request.payload.as_slice())
            || message(
                request.scope,
                &request.actor,
                request.head,
                &request.payload,
            ) != request.message
            || bh_crypto::verify(&self.signing, &request.message, &signature).is_err()
        {
            return Err(refused("invalid or stale device approval"));
        }
        let admission = LocalApproval {
            scope: self.scope,
            actor: self.actor(),
            operation: request.operation.clone(),
            prior: request.prior.clone(),
        };
        self.submit_checked(
            request.operation,
            &admission,
            Some(request.mutation),
            Some(request.prior),
        )
        .map_err(session_rejection)
    }
    fn submit_checked(
        &self,
        op: Operation,
        admission: &dyn HostAdmission,
        mutation: Option<MutationId>,
        confirmation: Option<PriorRules>,
    ) -> Result<LocalSaved, SessionError> {
        self.submit_to_store(
            self.scope,
            &self.actor(),
            op,
            admission,
            mutation,
            confirmation,
        )
    }
    fn submit_to_store(
        &self,
        scope: Scope,
        actor: &Actor,
        op: Operation,
        admission: &dyn HostAdmission,
        mutation: Option<MutationId>,
        confirmation: Option<PriorRules>,
    ) -> Result<LocalSaved, SessionError> {
        if scope != self.scope || actor != &self.actor() {
            return Err(SessionError::Rejected(refused(
                "outside current account authority",
            )));
        }
        let guard = self.session.lock().expect("container session lock");
        if !self.current(&guard) {
            return Err(SessionError::Rejected(refused("account authority changed")));
        }
        let database: Arc<Mutex<DeviceDatabase>> = guard.shared_database();
        let mut db = database.lock().expect("container writer lock");
        let queued = db
            .submit_typed_checked(
                &Shipped,
                scope,
                actor,
                op,
                admission,
                mutation,
                confirmation,
                || self.current(&guard),
            )
            .map_err(|err| match err {
                SubmitTypedError::Submit(e) => SessionError::from(e),
                SubmitTypedError::Store(e) => SessionError::Data(DataError::Sql(e.to_string())),
            })?;
        drop(db);
        drop(guard);
        if let Some(maintenance) = self.maintenance.upgrade() {
            maintenance.schedule_local_maintenance(self.id, &database);
        }
        let wake = self.wake.lock().expect("records wake lock").clone();
        if let Some(wake) = wake {
            wake(self.id);
        }
        Ok(queued.saved)
    }
}
struct LocalApproval {
    scope: Scope,
    actor: Actor,
    operation: Operation,
    prior: PriorRules,
}
impl HostAdmission for LocalApproval {
    fn confirms(
        &self,
        request: &Confirmation,
        at: Option<bh_data::Position>,
    ) -> Result<bool, DataError> {
        Ok(at.is_none()
            && request.scope == self.scope
            && request.actor == self.actor
            && request.operation == self.operation
            && request.prior == self.prior)
    }
}
/// Trusted-native authority plumbing, not a page/tool capability: native
/// callers with direct Rust access must not forge authority or raw SQL work.
impl Authority for RecordsHandle {
    fn actor(&self) -> Actor {
        Actor::Device {
            account: self.capability.account_id().0,
            device: self.capability.device_id().0,
        }
    }
    fn reads(&self) -> Vec<Scope> {
        self.capability
            .is_current()
            .then_some(self.scope)
            .into_iter()
            .collect()
    }
    fn write(&self) -> Option<Scope> {
        self.capability.is_current().then_some(self.scope)
    }
}
impl Authority for &RecordsHandle {
    fn actor(&self) -> Actor {
        (**self).actor()
    }
    fn reads(&self) -> Vec<Scope> {
        (**self).reads()
    }
    fn write(&self) -> Option<Scope> {
        Authority::write(*self)
    }
}
/// Trusted-native database plumbing. Raw read/write closures can access the
/// entire store and must never be exposed to page, job or tool input.
impl Store for RecordsHandle {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError> {
        let guard = self.session.lock().expect("container session lock");
        if !self.current(&guard) {
            return Err(DataError::Unauthorized);
        }
        let db = guard.shared_database();
        drop(guard);
        // Do not serialize independent read-pool queries through the
        // container session. Check authority again before returning data.
        let result = if let Some(readers) = &self.readers {
            readers.read_data(f)
        } else {
            db.lock().expect("container writer lock").with_data_read(f)
        };
        if !self.current(&self.session.lock().expect("container session lock")) {
            return Err(DataError::Unauthorized);
        }
        result
    }
    fn write<R>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError> {
        let guard = self.session.lock().expect("container session lock");
        if !self.current(&guard) {
            return Err(DataError::Unauthorized);
        }
        let db = guard.shared_database();
        let result = db.lock().expect("container writer lock").with_data_write(f);
        // The write has committed. If the marker probe fails, queue a cheap
        // deduplicated derived turn rather than reporting a retryable failure
        // for an already committed submit.
        let pending = result.is_ok()
            && db
                .lock()
                .expect("container writer lock")
                .derived_pending()
                .unwrap_or(true);
        drop(guard);
        if pending && let Some(maintenance) = self.maintenance.upgrade() {
            maintenance.schedule_derived(self.id, &db);
        }
        result
    }
    fn core(&self) -> &dyn bh_data::CoreCatalogue {
        &Shipped
    }
    fn submit_pending(
        &self,
        scope: Scope,
        actor: &Actor,
        op: Operation,
        _admission: &dyn HostAdmission,
        _mutation: Option<MutationId>,
    ) -> Result<LocalSaved, SessionError> {
        // A caller may compose a DataSession with any Authority implementor.
        // Only this handle's private signed-approval path can opt into
        // management admission; generic sessions and tools cannot.
        self.submit_to_store(
            scope,
            actor,
            op,
            &bh_data::admission::Unavailable,
            None,
            None,
        )
    }
}
