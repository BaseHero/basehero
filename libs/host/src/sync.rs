//! Native sync for each ready account: its client, the client's signer over
//! the account's one native owner, and what its windows are told.
//!
//! The signer holds no owner of its own. Each use borrows the account's one
//! `AccountOwner` from the account registry (`SharedAccountHost::run_lent`)
//! on a native worker, or uses it briefly under the registry lock, and
//! returns it; a prompt on one account never holds the registry or another
//! account. The base roots stay in the account's own base, used in place.
use crate::{
    accounts::{HostKeyStore, Owner, SharedAccountHost},
    confirm::{ActionGate, LIFE},
};
use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, DeviceId, Error as HistoryError, Head as AccountHead,
    VerifiedAccount,
    device_auth::{Context, Proof},
    directory::DirectoryEntry,
    journal::{
        AccountJournal, HistoryCursor, PendingSetupProtector, StagedAdmission, StagedControl,
    },
    owner::{AccountCapability, AccountGeneration, OwnerError, SetupError, staging::Settlement},
    platform::KeyStoreError,
    storage::DeviceJournal,
};
use bh_crypto::Secret;
use bh_device::{
    ContainerId,
    base_keys::{BaseKeyPurpose, SealHeader, prepare_seal},
    control::{InstallError, SealWait, install_sealed_epoch, open_seal_set},
    own_base::{OwnBase, ensure_keyring},
};
use bh_storage::{AlertKind, NewAlert};
use bh_sync::{BaseId, evidence::RecoveryKeyCertificate};
use bh_sync_client::{
    AccountApplyError, BaseControlRequest, Client, ControlSignError, Endpoint, HomeRetryReason,
    HomeSetup, HomeStatus, Identity, OpenedEntries, Signer, SignerError, SyncStatus, TimedOriginal,
    pairing::{Approvals, HttpRelay, Relay},
    transport::{Connector, WsConnector},
};
pub use bh_sync_client::{Presence, RemotePresence, RemoteState};
use futures_util::future::BoxFuture;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};
use tokio::sync::watch;

/// The account as the signer last saw it, for the host and its windows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountState {
    #[default]
    Active,
    /// Authenticated history contradicts this device's: stopped for good.
    Stopped,
    /// Verified history removed this device: its authority has ended.
    Removed,
}

/// What the signer tells the host. No content, ids or keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Notice {
    pub account: AccountState,
    /// A base copy of an account change waits for the person's confirmation.
    pub confirm: bool,
}

/// The client's signer for one ready account.
pub struct HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    accounts: SharedAccountHost<S, P>,
    id: ContainerId,
    capability: Arc<AccountCapability>,
    generation: AccountGeneration,
    own_base: Arc<OwnBase>,
    database: Arc<Mutex<bh_storage::DeviceDatabase>>,
    account: AccountId,
    device: DeviceId,
    genesis: Vec<u8>,
    /// The account at the head the own base's genesis names. Read again,
    /// at that same head, once setup keeps the home's times.
    anchor: RwLock<VerifiedAccount>,
    control_key: [u8; 32],
    /// The account at its verified head, published by the owner after each
    /// commit this signer made. Read-only; never written elsewhere.
    current: RwLock<VerifiedAccount>,
    home: Mutex<Option<HomeSetup>>,
    approvals: Approvals,
    gate: Option<ActionGate>,
    store: S,
    /// The exact account event whose base copy waits for the person.
    waiting_copy: Mutex<Option<Vec<u8>>>,
    notices: watch::Sender<Notice>,
}

fn copy_setup(setup: &HomeSetup) -> HomeSetup {
    HomeSetup {
        prefix: setup.prefix.clone(),
        objects: setup.objects.clone(),
        generation: setup.generation,
    }
}

/// A device's retained signup for its account home, read exactly as kept.
/// `None` only for a device that is not active in the account's original
/// three-event prefix (one added later), found by a bounded read of that
/// prefix. A first device whose record is missing or fails is an error.
pub fn retained_home_setup<S, P>(
    owner: &Owner<S, P>,
    capability: &AccountCapability,
    journal: &DeviceJournal,
    generation: &AccountGeneration,
) -> Result<Option<HomeSetup>, SignerError>
where
    S: bh_account::platform::DeviceKeyStore,
    P: PendingSetupProtector,
{
    if !capability.is_current() {
        return Err(SignerError);
    }
    if journal
        .initial_bootstrap()
        .map_err(|_| SignerError)?
        .is_none()
    {
        let head = owner.verified(capability).map_err(|_| SignerError)?.head();
        let page = journal
            .history_prefix(
                Some(HistoryCursor {
                    anchor: capability.account_id(),
                    cut: head,
                    next_position: 1,
                }),
                3,
            )
            .map_err(|_| SignerError)?
            .ok_or(SignerError)?;
        let (genesis, rest) = page.events.split_first().ok_or(SignerError)?;
        let mut prefix = VerifiedAccount::from_genesis(capability.account_id(), genesis)
            .map_err(|_| SignerError)?;
        for event in rest.iter().take(2) {
            prefix.apply(event).map_err(|_| SignerError)?;
        }
        return if prefix.active_device(capability.device_id()).is_ok() {
            Err(SignerError)
        } else {
            Ok(None)
        };
    }
    let read_at = generation.current();
    let (prefix, objects) = owner
        .initial_bootstrap(capability)
        .map_err(|_| SignerError)?;
    if !capability.is_current() || generation.current() != read_at {
        return Err(SignerError);
    }
    Ok(Some(HomeSetup {
        prefix,
        objects,
        generation: read_at,
    }))
}

impl<S, P> HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    /// The signer of ready account `id`, read from its owner under the
    /// registry lock. Settles a staged addition that verified history
    /// already resolved.
    pub async fn start(
        accounts: SharedAccountHost<S, P>,
        id: ContainerId,
    ) -> Result<Arc<Self>, SignerError> {
        let ready = accounts.ready_parts(id).ok_or(SignerError)?;
        let capability = ready.capability;
        let own_base = ready.own_base;
        let package_head = own_base
            .initial_key_package()
            .ok()
            .and_then(|package| {
                bh_device::base_keys::SealHeader::decode(package.metadata_seal()).ok()
            })
            .ok_or(SignerError)?
            .head;
        let journal = DeviceJournal::from_shared(ready.database.clone());
        let generation = ready.generation.clone();
        let read = generation.clone();
        // Read with the account's one owner, waiting for it like every
        // other use: never from a second owner, never failing on a busy one.
        let (genesis, anchor, current, home) = accounts
            .run_lent(id, &capability, move |owner, capability| {
                Box::pin(async move {
                    let current = owner.verified(&capability).ok()?.clone();
                    let anchor = owner.verified_at(&capability, package_head.position).ok()?;
                    if anchor.head() != package_head {
                        return None;
                    }
                    let genesis = journal
                        .history_prefix(
                            Some(HistoryCursor {
                                anchor: current.id(),
                                cut: current.head(),
                                next_position: 1,
                            }),
                            1,
                        )
                        .ok()??
                        .events
                        .into_iter()
                        .next()?;
                    if owner.staged_admission().is_ok_and(|row| row.is_some()) {
                        let _ = owner.reconcile_staged_admission(None);
                    }
                    let home = retained_home_setup(owner, &capability, &journal, &read).ok();
                    Some((genesis, anchor, current, home))
                })
            })
            .await
            .ok()
            .flatten()
            .ok_or(SignerError)?;
        let control_key = *current
            .active_device(capability.device_id())
            .map_err(|_| SignerError)?
            .control();
        let (notices, _) = watch::channel(Notice::default());
        Ok(Arc::new(Self {
            id,
            account: capability.account_id(),
            device: capability.device_id(),
            capability,
            generation,
            own_base,
            database: ready.database,
            genesis,
            anchor: RwLock::new(anchor),
            control_key,
            current: RwLock::new(current),
            home: Mutex::new(home.flatten()),
            approvals: Approvals::default(),
            gate: ready.store.action_gate(),
            store: ready.store,
            waiting_copy: Mutex::new(None),
            notices,
            accounts,
        }))
    }

    pub fn notices(&self) -> watch::Receiver<Notice> {
        self.notices.subscribe()
    }
    #[cfg(test)]
    pub fn approvals(&self) -> &Approvals {
        &self.approvals
    }
    #[cfg(test)]
    pub fn base(&self) -> BaseId {
        self.own_base.id()
    }
    #[cfg(test)]
    pub fn control_key(&self) -> [u8; 32] {
        self.control_key
    }

    fn current(&self) -> Result<(), SignerError> {
        self.capability
            .is_current()
            .then_some(())
            .ok_or(SignerError)
    }
    fn set_account(&self, state: AccountState) {
        self.notices.send_modify(|notice| notice.account = state);
    }
    fn wait_for_person(&self, copies: Vec<u8>) {
        *self.waiting_copy.lock().expect("waiting copy") = Some(copies);
        self.notices.send_modify(|notice| notice.confirm = true);
    }

    /// The person is approving a device addition now: on a store whose
    /// gate the app enforces, its confirmation will also cover the copy.
    pub fn open_pairing_action(&self) {
        if let Some(gate) = &self.gate
            && self.capability.is_current()
        {
            gate.open(self.control_key, self.account, self.generation.current());
        }
    }
    /// The approval did not stage (cancelled, expired or failed).
    pub fn end_pairing_action(&self) {
        if let Some(gate) = &self.gate {
            gate.revoke(self.control_key);
        }
    }
    /// The armed copy `message` was not signed: its grant, if still there,
    /// ends, and nobody else's.
    fn withdraw(&self, message: &[u8]) {
        if let Some(gate) = &self.gate {
            gate.disarm(self.control_key, message);
        }
    }
    /// History did not take the recovery replacement `staged`. While its
    /// new kit shows, the kit stops showing. Once the person saved it, they
    /// believe the kit changed: a lasting alert on this device, the one
    /// that saved it, says it did not. Kept after the stage is cleared, so
    /// a crash between the two loses the alert.
    fn replacement_not_taken(&self, staged: &StagedControl) {
        if self.accounts.kit_not_changed(self.id) {
            return;
        }
        let position = AccountEvent::decode(&staged.event)
            .ok()
            .map(|event| event.head().position);
        let alert = NewAlert {
            kind: AlertKind::KitNotChanged,
            position,
            subject: None,
            actor: None,
            time_ms: None,
            deadline_ms: None,
        };
        let recorded = self.database.lock().ok().and_then(|mut database| {
            let cursor = database.alert_cursor().ok()?;
            database.record_alerts(cursor, &[alert]).ok()
        });
        if recorded.is_some() {
            self.accounts.deliver_alerts(self.id);
        }
    }

    /// The person asked to finish the base copy that waits for them, after
    /// its earlier approval was lost (a restart or expiry). One fresh owner
    /// confirmation covers exactly that copy, once.
    pub async fn reconfirm(&self) -> Result<(), SignerError> {
        self.current()?;
        let copies = self
            .waiting_copy
            .lock()
            .expect("waiting copy")
            .clone()
            .ok_or(SignerError)?;
        if let Some(gate) = self.gate.clone() {
            let (key, account, generation) =
                (self.control_key, self.account, self.generation.current());
            let mut store = self.store.clone();
            let event = copies.clone();
            tokio::task::spawn_blocking(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| SignerError)?;
                runtime
                    .block_on(gate.reconfirm(
                        key,
                        account,
                        generation,
                        &event,
                        store.confirm_owner(),
                    ))
                    .map_err(|_| SignerError)
            })
            .await
            .map_err(|_| SignerError)??;
        }
        self.current()?;
        self.approvals
            .grant(copies, tokio::time::Instant::now() + LIFE);
        Ok(())
    }

    fn proof(
        &self,
        head: Option<AccountHead>,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        Box::pin(async move {
            self.accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        match head {
                            None => owner.prove_sync_device(&cap, context).await,
                            Some(head) => {
                                if owner.verified_at(&cap, head.position)?.head() != head {
                                    return Err(OwnerError::Invalid(
                                        HistoryError::InvalidCredentials,
                                    ));
                                }
                                owner
                                    .prove_sync_device_at(&cap, head.position, context)
                                    .await
                            }
                        }
                    })
                })
                .await
                .map_err(|_| SignerError)?
                .map_err(|_| SignerError)
        })
    }
}

/// How an account owner judged incoming history, for the client. A failed
/// write of a stop the live owner latched is still a stop.
fn judged<S, P>(
    owner: &Owner<S, P>,
    capability: &AccountCapability,
    error: OwnerError,
) -> AccountApplyError
where
    S: bh_account::platform::DeviceKeyStore,
    P: PendingSetupProtector,
{
    match error {
        OwnerError::Refused(_) => AccountApplyError::Refused,
        OwnerError::Unsupported(_) => AccountApplyError::Unsupported,
        OwnerError::Invalid(HistoryError::Unavailable) => AccountApplyError::Unavailable,
        OwnerError::Invalid(_) | OwnerError::Stopped => AccountApplyError::Stopped,
        _ if matches!(owner.verified(capability), Err(OwnerError::Stopped)) => {
            AccountApplyError::Stopped
        }
        _ => AccountApplyError::Unavailable,
    }
}

impl<S, P> Signer for HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    fn identity(&self) -> Result<Identity, SignerError> {
        Ok(Identity {
            account: self.account,
            device: self.device,
            genesis: self.genesis.clone(),
            anchor: self.anchor.read().expect("creator anchor").clone(),
        })
    }
    fn device_proof(&self, context: Context) -> BoxFuture<'_, Result<Proof, SignerError>> {
        self.proof(None, context)
    }
    fn device_proof_at(
        &self,
        head: AccountHead,
        context: Context,
    ) -> BoxFuture<'_, Result<Proof, SignerError>> {
        self.proof(Some(head), context)
    }
    fn initial_home_setup(&self) -> Result<Option<HomeSetup>, SignerError> {
        self.current()?;
        if let Some(setup) = self.home.lock().expect("home setup").as_ref()
            && setup.generation == self.generation.current()
        {
            return Ok(Some(copy_setup(setup)));
        }
        let journal = DeviceJournal::from_shared(self.database.clone());
        let setup = self
            .accounts
            .with_owner(self.id, &self.capability, |owner| {
                retained_home_setup(owner, &self.capability, &journal, &self.generation)
            })
            .ok_or(SignerError)??;
        *self.home.lock().expect("home setup") = setup.as_ref().map(copy_setup);
        Ok(setup)
    }
    fn confirm_home_ordered(
        &self,
        setup: &HomeSetup,
        evidence: [(ConfirmedTime, Vec<u8>); 2],
    ) -> Result<(), SignerError> {
        // Under the registry lock: nothing locks, stops or lends the owner
        // between this check and the commit.
        self.accounts
            .with_owner(self.id, &self.capability, |owner| {
                if !self.capability.is_current()
                    || self.generation.current() != setup.generation
                    || self.capability.account_id() != setup.prefix.anchor
                {
                    return Err(SignerError);
                }
                match owner.confirm_home_ordered(setup.prefix.head, Some(evidence)) {
                    // Already cleared: the client calls this only after the
                    // home's exact answer for these retained bytes.
                    Ok(()) | Err(SetupError::NotStarted) => {}
                    Err(_) => return Err(SignerError),
                }
                // Both views now carry the setup's times: base copies are
                // judged from the anchor, so refreshing only the current
                // account would leave them untimed.
                let current = owner.verified(&self.capability).map_err(|_| SignerError)?;
                let head = self.anchor.read().expect("creator anchor").head();
                let anchor = owner
                    .verified_at(&self.capability, head.position)
                    .map_err(|_| SignerError)?;
                if anchor.head() != head {
                    return Err(SignerError);
                }
                *self.current.write().expect("current account") = current.clone();
                *self.anchor.write().expect("creator anchor") = anchor;
                Ok(())
            })
            .ok_or(SignerError)?
    }
    fn sign_event(&self, message: Vec<u8>) -> BoxFuture<'_, Result<[u8; 64], SignerError>> {
        Box::pin(async move {
            self.accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move { owner.sign_content(&cap, &message).await })
                })
                .await
                .map_err(|_| SignerError)?
                .map_err(|_| SignerError)
        })
    }
    fn current_account(&self) -> Result<VerifiedAccount, SignerError> {
        self.current()?;
        Ok(self.current.read().expect("current account").clone())
    }
    fn last_verified_account(&self) -> Result<VerifiedAccount, SignerError> {
        // Only ever replaced by a view in which this device was a member.
        Ok(self.current.read().expect("current account").clone())
    }
    fn apply_account_timed(
        &self,
        after: AccountHead,
        originals: Vec<TimedOriginal>,
    ) -> BoxFuture<'_, Result<AccountHead, AccountApplyError>> {
        Box::pin(async move {
            let lent = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        match owner.verified(&cap).map(VerifiedAccount::head) {
                            Ok(head) if head == after => {}
                            Ok(_) => return Err(AccountApplyError::Unavailable),
                            Err(error) => return Err(judged(owner, &cap, error)),
                        }
                        let timed: Vec<_> = originals
                            .iter()
                            .map(|(original, evidence)| (original.as_slice(), evidence.clone()))
                            .collect();
                        let head = owner
                            .apply_incoming_timed(&timed)
                            .map_err(|error| judged(owner, &cap, error))?;
                        // A staged addition this history resolved is settled
                        // now; one still ahead stays as it is.
                        if owner.staged_admission().is_ok_and(|row| row.is_some()) {
                            let _ = owner.reconcile_staged_admission(None);
                        }
                        Ok((head, owner.verified(&cap).ok().cloned()))
                    })
                })
                .await;
            match lent {
                Ok(Ok((head, current))) => {
                    match current {
                        Some(current) => *self.current.write().expect("current account") = current,
                        None => self.set_account(AccountState::Removed),
                    }
                    self.accounts.deliver_alerts(self.id);
                    Ok(head)
                }
                Ok(Err(AccountApplyError::Stopped)) => {
                    self.set_account(AccountState::Stopped);
                    Err(AccountApplyError::Stopped)
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(AccountApplyError::Unavailable),
            }
        })
    }
    fn observe_account_accepted(
        &self,
        head: AccountHead,
        time: ConfirmedTime,
    ) -> Result<(), SignerError> {
        self.accounts
            .with_owner(self.id, &self.capability, |owner| {
                owner
                    .observe_accepted_alerts(&self.capability, head, time)
                    .map_err(|_| SignerError)?;
                let current = owner
                    .verified(&self.capability)
                    .map_err(|_| SignerError)?
                    .clone();
                *self.current.write().expect("current account") = current.clone();
                if self.anchor.read().expect("creator anchor").head() == head {
                    *self.anchor.write().expect("creator anchor") = current;
                }
                Ok(())
            })
            .ok_or(SignerError)??;
        self.accounts.deliver_alerts(self.id);
        Ok(())
    }
    fn sign_base_control(
        &self,
        request: BaseControlRequest,
    ) -> BoxFuture<'_, Result<[u8; 64], ControlSignError>> {
        Box::pin(async move {
            if !self.capability.is_current() {
                return Err(ControlSignError::Unavailable);
            }
            // Only an action the person approved; never a prompt from here.
            if !self.approvals.take(&request.copies) {
                self.wait_for_person(request.copies);
                return Err(ControlSignError::ConfirmationNeeded);
            }
            if let Some(gate) = &self.gate
                && !gate.arm(
                    self.control_key,
                    self.account,
                    self.generation.current(),
                    &request.copies,
                    &request.message,
                )
            {
                self.wait_for_person(request.copies);
                return Err(ControlSignError::ConfirmationNeeded);
            }
            let BaseControlRequest {
                expected_key,
                message,
                copies,
            } = request;
            let armed = message.clone();
            let signed = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(
                        async move { owner.sign_base_control(&cap, &expected_key, &message).await },
                    )
                })
                .await;
            match signed {
                Ok(Ok(signature)) => {
                    *self.waiting_copy.lock().expect("waiting copy") = None;
                    self.notices.send_modify(|notice| notice.confirm = false);
                    Ok(signature)
                }
                // Its grant ended before the owner signed it (another gate
                // use came between): the copy waits for the person.
                Ok(Err(OwnerError::Device(KeyStoreError::Unavailable)))
                    if self.gate.is_some() && self.current().is_ok() =>
                {
                    self.withdraw(&armed);
                    self.wait_for_person(copies);
                    Err(ControlSignError::ConfirmationNeeded)
                }
                _ => {
                    self.withdraw(&armed);
                    Err(ControlSignError::Unavailable)
                }
            }
        })
    }
    fn staged_addition(&self) -> Result<Option<StagedAdmission>, SignerError> {
        self.current()?;
        DeviceJournal::from_shared(self.database.clone())
            .staged_admission()
            .map_err(|_| SignerError)
    }
    fn staged_control(&self) -> Result<Option<StagedControl>, SignerError> {
        self.current()?;
        DeviceJournal::from_shared(self.database.clone())
            .staged_control()
            .map_err(|_| SignerError)
    }
    fn stage_rotation(&self, at_ms: u64) -> BoxFuture<'_, Result<StagedControl, SignerError>> {
        Box::pin(async move {
            self.accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move { owner.stage_rotation(&cap, at_ms).await })
                })
                .await
                .map_err(|_| SignerError)?
                .map_err(|_| SignerError)
        })
    }
    fn settle_staged(&self) -> Result<Option<Settlement>, SignerError> {
        let settled = self
            .accounts
            .with_owner(self.id, &self.capability, |owner| owner.settle_staged())
            .ok_or(SignerError)?
            .map_err(|_| SignerError)?;
        if let Some(settlement) = &settled
            && settlement.staged.kind == REPLACE_RECOVERY
            && settlement.outcome == bh_account::owner::staging::Settled::Lost
        {
            self.replacement_not_taken(&settlement.staged);
        }
        Ok(settled)
    }
    fn discard_staged(&self, expected: &StagedControl) -> Result<(), SignerError> {
        self.accounts
            .with_owner(self.id, &self.capability, |owner| {
                owner.discard_staged(expected)
            })
            .ok_or(SignerError)?
            .map_err(|_| SignerError)?;
        if expected.kind == REPLACE_RECOVERY {
            self.replacement_not_taken(expected);
        }
        Ok(())
    }
    fn accept_rotation(
        &self,
        position: u64,
        raw: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), SignerError>> {
        Box::pin(async move {
            let database = self.database.clone();
            let anchor_head = self.anchor.read().expect("creator anchor").head();
            let (current, anchor) = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        ensure_keyring(owner, cap.clone(), database)
                            .await
                            .map_err(|_| SignerError)?;
                        owner
                            .accept_rotation(&cap, position, &raw)
                            .await
                            .map_err(|_| SignerError)?;
                        let current = owner.verified(&cap).map_err(|_| SignerError)?.clone();
                        let anchor = owner
                            .verified_at(&cap, anchor_head.position)
                            .map_err(|_| SignerError)?;
                        Ok::<_, SignerError>((current, anchor))
                    })
                })
                .await
                .map_err(|_| SignerError)??;
            *self.current.write().expect("current account") = current;
            if anchor.head() == anchor_head {
                *self.anchor.write().expect("creator anchor") = anchor;
            }
            Ok(())
        })
    }
    fn prepare_base_entry(
        &self,
        base: BaseId,
        epoch: [u8; 32],
        server: String,
        version: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>, SignerError>> {
        Box::pin(async move {
            if base != self.own_base.id() {
                return Err(SignerError);
            }
            // Only the epoch's key already open in memory.
            let root = self
                .own_base
                .with_epoch_key(Some(epoch), |_, content| {
                    content.map(|key| Secret::from_slice(key.expose()).expect("32 bytes"))
                })
                .map_err(|_| SignerError)?
                .ok_or(SignerError)?;
            let metadata = self
                .own_base
                .with_metadata_key(|m| Secret::from_slice(m.expose()).expect("32 bytes"))
                .map_err(|_| SignerError)?;
            // The base's original seals of M and the genesis epoch's key,
            // while they are this epoch's and sealed to the current personal
            // key: a device that recovers the account opens the base from
            // exactly them. Any other epoch's are sealed here afresh.
            let original = self
                .own_base
                .initial_key_package()
                .map_err(|_| SignerError)?;
            let original = (
                original.metadata_seal().to_vec(),
                original.content_seal().to_vec(),
            );
            let device = self.device;
            self.accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        let history = owner.verified(&cap).map_err(|_| SignerError)?.clone();
                        let recipient = *history.personal_public().map_err(|_| SignerError)?;
                        let (metadata_seal, current_key_seal) = match original {
                            (m, k)
                                if SealHeader::decode(&k).is_ok_and(|header| {
                                    header.key_id == epoch
                                        && header.recipient == bh_crypto::hash(&recipient)
                                }) =>
                            {
                                (m, k)
                            }
                            _ => {
                                let header = SealHeader {
                                    purpose: BaseKeyPurpose::Metadata,
                                    base,
                                    audience: [0; 32],
                                    key_id: bh_crypto::committed_key_id(&metadata),
                                    recipient: bh_crypto::hash(&recipient),
                                    sender: history.id(),
                                    device,
                                    head: history.head(),
                                };
                                let mut seals = Vec::with_capacity(2);
                                for (header, key) in [
                                    (header, &metadata),
                                    (
                                        SealHeader {
                                            purpose: BaseKeyPurpose::Content,
                                            key_id: epoch,
                                            ..header
                                        },
                                        &root,
                                    ),
                                ] {
                                    let unsigned = prepare_seal(&history, header, &recipient, key)
                                        .map_err(|_| SignerError)?;
                                    let signature = owner
                                        .sign_content(&cap, unsigned.signing_bytes())
                                        .await
                                        .map_err(|_| SignerError)?;
                                    seals
                                        .push(unsigned.finish(signature).map_err(|_| SignerError)?);
                                }
                                let content = seals.pop().ok_or(SignerError)?;
                                (seals.pop().ok_or(SignerError)?, content)
                            }
                        };
                        let entry = DirectoryEntry::Base {
                            base: base.0,
                            server,
                            epoch_id: epoch,
                            current_key_seal,
                            metadata_seal,
                            // The only base this producer writes.
                            own: true,
                        };
                        owner
                            .prepare_directory_entry(&cap, &entry, version)
                            .await
                            .map_err(|_| SignerError)
                    })
                })
                .await
                .map_err(|_| SignerError)?
        })
    }
    fn open_directory_entries(
        &self,
        entries: Vec<Vec<u8>>,
    ) -> BoxFuture<'_, Result<OpenedEntries, SignerError>> {
        Box::pin(async move {
            self.accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
                        owner.open_directory_entries(&cap, &refs).await
                    })
                })
                .await
                .map_err(|_| SignerError)?
                .map_err(|_| SignerError)
        })
    }
    fn directory_state(&self) -> Result<Option<(u64, bool)>, SignerError> {
        self.current()?;
        self.database
            .lock()
            .expect("container writer lock")
            .directory_state()
            .map_err(|_| SignerError)
    }
    fn set_directory_state(&self, version: u64, written: bool) -> Result<(), SignerError> {
        self.current()?;
        self.database
            .lock()
            .expect("container writer lock")
            .set_directory_state(version, written)
            .map_err(|_| SignerError)
    }
    // ---- This device's own directory entries, and what it reads back ----
    fn own_entries(&self) -> BoxFuture<'_, Result<bh_sync_client::OwnEntries, SignerError>> {
        use crate::devices::{CHECK, NAME, copy_check};
        Box::pin(async move {
            self.current()?;
            // Cheap on every pass: only what memory does not know is held
            // under the current key goes to the owner, which opens the key.
            let (key, record) = {
                let account = self.current.read().expect("current account");
                (
                    bh_crypto::hash(account.personal_public().map_err(|_| SignerError)?),
                    account.record_digest().map_err(|_| SignerError)?,
                )
            };
            let device = self.device;
            let due = self
                .accounts
                .with_known(self.id, |known, model| {
                    let name =
                        model
                            .filter(|_| !known.written.contains(&(NAME, key)))
                            .map(|model| DirectoryEntry::DeviceName {
                                device,
                                name: model.to_owned(),
                            });
                    let check = known
                        .check
                        .as_ref()
                        .filter(|held| {
                            held.record_digest == record
                                && held.not_under != Some(key)
                                && !known.written.contains(&(CHECK, key))
                        })
                        .map(|held| DirectoryEntry::PasswordCheck {
                            check: copy_check(&held.check),
                            record_digest: record,
                        });
                    [name.map(|e| (NAME, e)), check.map(|e| (CHECK, e))]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                })
                .ok_or(SignerError)?;
            if due.is_empty() {
                return Ok(Vec::new());
            }
            let prepared = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        let mut out = Vec::new();
                        for (subject, entry) in due {
                            out.push((subject, owner.prepare_own_entry(&cap, &entry, 1).await?));
                        }
                        Ok::<_, OwnerError>(out)
                    })
                })
                .await
                .map_err(|_| SignerError)?
                .map_err(|_| SignerError)?;
            self.accounts
                .with_known(self.id, |known, _| {
                    let mut entries = Vec::new();
                    for (subject, prepared) in prepared {
                        match prepared {
                            None => drop(known.written.insert((subject, key))),
                            Some((id, bytes)) => {
                                known.writing.insert(id, (subject, key));
                                entries.push((1, bytes));
                            }
                        }
                    }
                    entries
                })
                .ok_or(SignerError)
        })
    }
    fn own_entry_held(&self, entry: [u8; 32], version: u64) -> Result<(), SignerError> {
        self.accounts
            .with_owner(self.id, &self.capability, |owner| {
                owner.own_entry_held(entry, version)
            })
            .ok_or(SignerError)?
            .map_err(|_| SignerError)?;
        self.accounts.with_known(self.id, |known, _| {
            if let Some(held) = known.writing.remove(&entry) {
                known.written.insert(held);
            }
        });
        Ok(())
    }
    fn directory_wanted(&self) -> bool {
        self.accounts
            .with_known(self.id, |known, _| std::mem::take(&mut known.wanted))
            .unwrap_or(false)
    }
    fn directory_read(&self, read: bh_sync_client::DirectoryRead) {
        let record = self
            .current
            .read()
            .expect("current account")
            .record_digest()
            .ok();
        self.accounts.with_known(self.id, |known, _| {
            known.names = read.names.into_iter().collect();
            // Only the current record's check opens (`open_entry`).
            if let (Some(check), Some(record_digest)) = (read.password_check, record) {
                known.check = Some(crate::devices::HeldCheck {
                    check,
                    record_digest,
                    not_under: None,
                });
            }
            known.read = true;
            known.reads += 1;
        });
        self.accounts.directory_changed();
        self.accounts.names_answered(self.id);
    }
    fn alerts_written(&self) {
        self.accounts.deliver_alerts(self.id);
    }
    fn directory_unread(&self) {
        self.accounts.names_answered(self.id);
    }
    fn with_metadata_key(
        &self,
        base: BaseId,
        use_key: &mut dyn FnMut(&Secret<32>),
    ) -> Result<(), SignerError> {
        if base != self.own_base.id() {
            return Err(SignerError);
        }
        // No lock of ours is held: the closure takes the Owner's own.
        self.own_base
            .with_metadata_key(|metadata| use_key(metadata))
            .map_err(|_| SignerError)
    }
    fn with_epoch_keys(
        &self,
        base: BaseId,
        epoch: Option<[u8; 32]>,
        use_keys: &mut dyn FnMut(&Secret<32>, Option<&Secret<32>>),
    ) -> Result<(), SignerError> {
        if base != self.own_base.id() {
            return Err(SignerError);
        }
        // Only keys the own base already holds in memory; no lock of ours
        // is held while the closure takes the Owner's own.
        self.own_base
            .with_epoch_key(epoch, |metadata, content| use_keys(metadata, content))
            .map_err(|_| SignerError)
    }
    fn install_epoch(
        &self,
        wait: SealWait,
        set: Vec<u8>,
    ) -> BoxFuture<'_, Result<(), InstallError>> {
        Box::pin(async move {
            if wait.base != self.own_base.id().0 {
                return Err(InstallError::Invalid);
            }
            let opened = self
                .own_base
                .with_metadata_key(|metadata| open_seal_set(&wait, metadata, &set))
                .map_err(|_| InstallError::Unavailable)??;
            // The personal key is opened and used by the account's one owner,
            // lent to a native worker; no database guard is held meanwhile.
            let database = self.database.clone();
            let content = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        install_sealed_epoch(owner, cap, database, &wait, &opened).await
                    })
                })
                .await
                .map_err(|_| InstallError::Unavailable)??;
            // Kept in the keyring already: a failure here leaves the key for
            // the base's next open.
            self.own_base
                .remember_epoch(content)
                .map_err(|_| InstallError::Unavailable)
        })
    }
}

// ---- One client per ready account, and what its windows are told ----

/// The build's sync endpoint (`crate::endpoint_config`).
// One per host, read once: its size, with the recovery key's certificate,
// costs nothing worth an indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Configured {
    /// No endpoint in this build: notes stay on this device.
    Missing,
    /// An endpoint this build cannot use: sync never starts.
    Invalid,
    Ready(Endpoint),
}

impl Configured {
    /// The endpoint an app build carries, from its checked endpoint file
    /// (`crate::endpoint`). Synthetic appraisal only with this crate's
    /// `synthetic-attestation` feature.
    pub fn from_text(text: &str) -> Self {
        let synthetic = cfg!(feature = "synthetic-attestation");
        match crate::endpoint::parse(text, synthetic) {
            Ok(None) => Self::Missing,
            Err(_) => Self::Invalid,
            Ok(Some(fields)) => {
                let appraisal = if fields.synthetic {
                    #[cfg(feature = "synthetic-attestation")]
                    {
                        bh_sync_client::Appraisal::Synthetic
                    }
                    #[cfg(not(feature = "synthetic-attestation"))]
                    {
                        return Self::Invalid;
                    }
                } else {
                    bh_sync_client::Appraisal::Hardware
                };
                // Recovery seals to this key only if the endpoint's own root
                // signed it.
                let Ok(recovery_key) = RecoveryKeyCertificate::decode(&fields.recovery_key) else {
                    return Self::Invalid;
                };
                if recovery_key.verify(&fields.hosting_root).is_err() {
                    return Self::Invalid;
                }
                Self::Ready(Endpoint {
                    edge_url: fields.edge_url,
                    hosting_root: fields.hosting_root,
                    app_root: fields.app_root,
                    policy: fields.policy,
                    policy_signature: fields.policy_signature,
                    limits: bh_confidential_policy::Limits {
                        max_lifetime_secs: fields.max_lifetime_secs,
                        max_uncertainty_secs: fields.max_uncertainty_secs,
                    },
                    build_floor: fields.build_floor,
                    appraisal,
                    device_clock: Arc::new(bh_sync_client::SystemDeviceClock),
                    recovery_key,
                })
            }
        }
    }
}

/// The `sync://status` message: counts and fixed reasons only, never
/// content, ids or keys. Local saving is acknowledged by the editor
/// separately; this is the network's view.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusView {
    /// The host's publication order, set when it publishes (0 before): a
    /// newer status always has a larger revision, so a page keeps the newest
    /// whether it was pushed or asked for.
    pub revision: u64,
    pub state: &'static str,
    /// Local updates not yet accepted from their verified echo.
    pub pending: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<u64>,
    /// "on", or "off" for a build without an endpoint, or "unsupported".
    pub network: &'static str,
    /// The first device's account-home setup, on its own: "pending",
    /// "retrying", "done" or "not-needed".
    pub home: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_reason: Option<&'static str>,
    /// "active", "stopped" or "removed".
    pub account: &'static str,
    /// A base copy of an account change waits for the person to confirm.
    pub confirm: bool,
}

pub fn state_name(status: SyncStatus) -> &'static str {
    match status {
        SyncStatus::SavedLocal { .. } => "saved-local",
        SyncStatus::Syncing { .. } => "syncing",
        SyncStatus::Synced => "synced",
        SyncStatus::UpdateNeeded => "update-needed",
        SyncStatus::WaitingNetwork => "waiting-network",
        SyncStatus::WaitingAuthorization => "waiting-authorization",
        SyncStatus::HistoryMissing => "history-missing",
        SyncStatus::Unsupported => "unsupported",
        SyncStatus::Stopped => "stopped",
        SyncStatus::PublishingStopped => "publishing-stopped",
        SyncStatus::NotAccepted { .. } => "not-accepted",
        SyncStatus::ControlNotAccepted => "control-not-accepted",
        SyncStatus::Protecting => "protecting",
    }
}

impl StatusView {
    pub fn of(
        status: Option<SyncStatus>,
        home: Option<HomeStatus>,
        notice: Notice,
        pending: u64,
    ) -> Self {
        let (home, home_reason) = match home {
            None => (None, None),
            Some(HomeStatus::Pending) => (Some("pending"), None),
            Some(HomeStatus::Done) => (Some("done"), None),
            Some(HomeStatus::NotNeeded) => (Some("not-needed"), None),
            Some(HomeStatus::Retrying(reason)) => (
                Some("retrying"),
                Some(match reason {
                    HomeRetryReason::Unavailable => "unavailable",
                    HomeRetryReason::Refused => "refused",
                    HomeRetryReason::SetupNotReady => "setup-not-ready",
                    HomeRetryReason::Other => "other",
                }),
            ),
        };
        let account = match notice.account {
            AccountState::Active => "active",
            AccountState::Stopped => "stopped",
            AccountState::Removed => "removed",
        };
        let status = status.unwrap_or(SyncStatus::SavedLocal { pending });
        let state = match notice.account {
            AccountState::Stopped => "stopped",
            _ => state_name(status),
        };
        Self {
            revision: 0,
            state,
            pending,
            notes: match status {
                SyncStatus::NotAccepted { notes } => Some(notes),
                _ => None,
            },
            network: "on",
            home,
            home_reason,
            account,
            confirm: notice.confirm,
        }
    }
    fn local(pending: u64, network: &'static str) -> Self {
        Self {
            state: if network == "unsupported" {
                "unsupported"
            } else {
                "saved-local"
            },
            network,
            ..Self::of(None, None, Notice::default(), pending)
        }
    }
}

/// The windows of the app, as the sync host reaches them.
pub trait StatusWindows: Send + Sync + 'static {
    /// Tell every window now bound to `container` (and only those, each on
    /// its current page) the account's status.
    fn post_status(&self, container: ContainerId, view: &StatusView);
    /// Remote changes committed for `window`: run the note delivery.
    fn wake_delivery(&self, window: String);
    /// The account's authority ended (removed or stopped) and `windows`
    /// lost their routes: they reload into the account's own screen.
    fn authority_ended(&self, container: ContainerId, windows: Vec<String>);
}

/// What pairing needs from a ready account's signer, without its types.
pub trait AccountOps: Send + Sync {
    fn account(&self) -> AccountId;
    fn device(&self) -> DeviceId;
    fn is_current(&self) -> bool;
    /// Stage a pairing approval with the account's lent owner (its one
    /// confirmation), granting the copy approval. `None` if the owner
    /// could not be lent, which ends the session.
    fn stage(
        &self,
        showing: bh_sync_client::pairing::ShowingPairing,
    ) -> BoxFuture<
        '_,
        (
            Option<bh_sync_client::pairing::ShowingPairing>,
            Result<(), bh_sync_client::pairing::PairingError>,
        ),
    >;
    /// The person asked to finish a copy that waits for them.
    fn reconfirm(&self) -> BoxFuture<'_, Result<(), SignerError>>;
    /// Sign `control` with this device's second key and stage it for the
    /// trust lane. Its one confirmation also covers the control's copy into
    /// the own base. Returns the account position it is staged for. While
    /// another control is staged, `Busy` before any prompt.
    fn stage_control(&self, control: TrustControl) -> BoxFuture<'_, Result<u64, StageRefused>>;
    /// The account at the head this device verified, even while its owner
    /// is lent to a native prompt.
    fn verified(&self) -> Option<VerifiedAccount>;
    /// Replace the recovery kit under `password`: sign the replacement with
    /// the second key (its one confirmation also covers its base copy) and
    /// stage it with the new kit kept until the person saves it. Returns
    /// the new kit's text, a check of `password` and the digest of the
    /// recovery record it belongs with. While another control is staged,
    /// `Busy` before any prompt.
    fn replace_recovery(&self, password: String) -> BoxFuture<'_, Result<NewKit, StageRefused>>;
    /// Remove `target` at once, cosigned: the recovery key signs its half
    /// from `keys`, which the home's check released, then this device's
    /// second key signs its own (its one confirmation also covers the base
    /// copy), and it is staged. `keys` are dropped once used. Returns the
    /// account position it is staged for; `Busy` before any prompt while
    /// another control is staged.
    fn remove_now(
        &self,
        target: DeviceId,
        keys: bh_account::recovery::RecoveryKeys,
    ) -> BoxFuture<'_, Result<u64, StageRefused>>;
}

/// Why a control the person asked for was not staged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageRefused {
    /// Another control is staged and history has not settled it: nothing
    /// was asked of the person.
    Busy,
    /// The confirmation was refused or failed, or the account is
    /// unavailable.
    NotSigned,
}

impl From<SignerError> for StageRefused {
    fn from(_: SignerError) -> Self {
        Self::NotSigned
    }
}

/// `Busy` for a stage that already holds another control.
fn stage_refused(error: &OwnerError) -> StageRefused {
    match error {
        OwnerError::Journal(bh_account::journal::JournalError::StagedControlExists) => {
            StageRefused::Busy
        }
        _ => StageRefused::NotSigned,
    }
}

/// The tag of a recovery replacement in `event`.
const REPLACE_RECOVERY: u8 = 8;

/// A staged recovery replacement's new kit, and the check of its password.
pub struct NewKit {
    pub code: String,
    pub check: bh_account::recovery::PasswordCheck,
    pub record_digest: [u8; 32],
}

/// A trust control the person asks for on Your devices.
#[derive(Clone, Copy)]
pub enum TrustControl {
    RequestRemoval(DeviceId),
    Cancel(u64),
    RemoveSelf,
}

impl TrustControl {
    /// Its tag in `event`.
    pub fn kind(self) -> u8 {
        match self {
            Self::RemoveSelf => 2,
            Self::RequestRemoval(_) => 5,
            Self::Cancel(_) => 7,
        }
    }
}

impl<S, P> AccountOps for HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    fn account(&self) -> AccountId {
        self.account
    }
    fn device(&self) -> DeviceId {
        self.device
    }
    fn is_current(&self) -> bool {
        self.capability.is_current()
    }
    fn stage(
        &self,
        mut showing: bh_sync_client::pairing::ShowingPairing,
    ) -> BoxFuture<
        '_,
        (
            Option<bh_sync_client::pairing::ShowingPairing>,
            Result<(), bh_sync_client::pairing::PairingError>,
        ),
    > {
        use bh_sync_client::pairing::PairingError;
        Box::pin(async move {
            let first_device = DeviceJournal::from_shared(self.database.clone())
                .initial_bootstrap()
                .is_ok_and(|row| row.is_some());
            let joined = self
                .database
                .lock()
                .expect("container writer lock")
                .joined()
                .ok()
                .flatten();
            let approvals = self.approvals.clone();
            self.open_pairing_action();
            let staged = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move {
                        let personal = match (first_device, joined) {
                            (true, _) => owner.open_personal(&cap).await,
                            (false, Some(joined)) => match (joined.delivery, joined.added_at) {
                                (Some(delivery), Some(added_at)) => {
                                    owner
                                        .open_delivered_personal(&cap, &delivery, added_at)
                                        .await
                                }
                                _ => Err(OwnerError::NotActive),
                            },
                            (false, None) => Err(OwnerError::NotActive),
                        };
                        let result = match personal {
                            Ok(personal) => showing.stage(owner, &cap, &personal, &approvals).await,
                            Err(error) => Err(PairingError::Owner(error)),
                        };
                        (showing, result)
                    })
                })
                .await;
            match staged {
                Ok((showing, Ok(()))) => (Some(showing), Ok(())),
                Ok((showing, Err(error))) => {
                    self.end_pairing_action();
                    (Some(showing), Err(error))
                }
                Err(_) => {
                    self.end_pairing_action();
                    (None, Err(PairingError::Local))
                }
            }
        })
    }
    fn reconfirm(&self) -> BoxFuture<'_, Result<(), SignerError>> {
        Box::pin(HostSigner::reconfirm(self))
    }
    fn verified(&self) -> Option<VerifiedAccount> {
        self.current_account().ok()
    }
    fn replace_recovery(&self, password: String) -> BoxFuture<'_, Result<NewKit, StageRefused>> {
        Box::pin(async move {
            self.current()?;
            let password = bh_account::recovery::Password::new(&password)
                .map_err(|_| StageRefused::NotSigned)?;
            self.open_pairing_action();
            let staged = self
                .accounts
                .run_lent(self.id, &self.capability, move |owner, cap| {
                    Box::pin(async move { owner.stage_recovery_replacement(&cap, &password).await })
                })
                .await;
            let (staged, code, check) = match staged {
                Ok(Ok(staged)) => staged,
                failed => {
                    self.end_pairing_action();
                    return Err(match failed {
                        Ok(Err(error)) => stage_refused(&error),
                        _ => StageRefused::NotSigned,
                    });
                }
            };
            self.approvals
                .grant(staged.event, tokio::time::Instant::now() + LIFE);
            let record = staged.body.ok_or(StageRefused::NotSigned)?;
            let record_digest = bh_account::recovery::record_checks(&record)
                .map_err(|_| StageRefused::NotSigned)?
                .digest;
            Ok(NewKit {
                code: code.to_kit_text(),
                check,
                record_digest,
            })
        })
    }
    fn stage_control(&self, control: TrustControl) -> BoxFuture<'_, Result<u64, StageRefused>> {
        Box::pin(self.stage_signed(move |owner, cap, view| {
            Box::pin(async move {
                let device = cap.device_id();
                let request = match control {
                    TrustControl::RequestRemoval(target) => view.request_removal(device, target),
                    TrustControl::Cancel(request) => view.cancel_removal(device, request),
                    TrustControl::RemoveSelf => view.remove_self(device),
                }
                .map_err(OwnerError::Invalid)?;
                owner.sign_control(&cap, &request).await
            })
        }))
    }
    fn remove_now(
        &self,
        target: DeviceId,
        keys: bh_account::recovery::RecoveryKeys,
    ) -> BoxFuture<'_, Result<u64, StageRefused>> {
        let (gate, key) = (self.gate.clone(), self.control_key);
        Box::pin(self.stage_signed(move |owner, cap, view| {
            Box::pin(async move {
                let request = view
                    .remove_now(cap.device_id(), target)
                    .map_err(OwnerError::Invalid)?;
                let recovery = request.sign_recovery(&keys);
                drop(keys);
                let event = owner.sign_cosigned(&cap, &request, recovery).await?;
                // The person confirmed this device's half: that one
                // confirmation also covers the whole control's base copy.
                if let Some(gate) = gate {
                    gate.cosigned(
                        key,
                        &request.device_signing_bytes(),
                        &recovery,
                        event.as_bytes(),
                    );
                }
                Ok(event)
            })
        }))
    }
}

impl<S, P> HostSigner<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone + Send + Sync + 'static,
{
    /// Sign a trust control with `sign` on the lent owner, at the history
    /// it verified, and stage it; see `AccountOps::stage_control`.
    async fn stage_signed(
        &self,
        sign: impl for<'a> FnOnce(
            &'a mut Owner<S, P>,
            Arc<AccountCapability>,
            VerifiedAccount,
        ) -> futures_util::future::LocalBoxFuture<
            'a,
            Result<AccountEvent, OwnerError>,
        > + Send
        + 'static,
    ) -> Result<u64, StageRefused> {
        self.current()?;
        // On a gated store the control's fresh confirmation becomes the
        // grant its base copy is signed under, as a pairing addition's.
        self.open_pairing_action();
        let staged = self
            .accounts
            .run_lent(self.id, &self.capability, move |owner, cap| {
                Box::pin(async move {
                    // Nothing is asked while another control waits.
                    if owner.staged_control()?.is_some() {
                        return Err(bh_account::journal::JournalError::StagedControlExists.into());
                    }
                    let view = owner.verified(&cap)?.clone();
                    let event = sign(&mut *owner, cap.clone(), view).await?;
                    owner.stage_control(&cap, event.as_bytes(), None, None, None)?;
                    Ok::<_, OwnerError>((event.as_bytes().to_vec(), event.head().position))
                })
            })
            .await;
        match staged {
            Ok(Ok((event, position))) => {
                self.approvals
                    .grant(event, tokio::time::Instant::now() + LIFE);
                Ok(position)
            }
            failed => {
                self.end_pairing_action();
                Err(match failed {
                    Ok(Err(error)) => stage_refused(&error),
                    _ => StageRefused::NotSigned,
                })
            }
        }
    }
}

/// The build's transport, for a device joining before it has a client.
pub struct Transport {
    pub endpoint: Endpoint,
    pub connector: Arc<dyn Connector>,
    pub relay: Arc<dyn Relay>,
    pub owner: Arc<bh_device::Owner>,
}

/// One account's running client, as pairing borrows it. Holding it does not
/// keep the client running: when the account's sync stops, the client stops
/// all the same and `stopping` turns true.
#[derive(Clone)]
pub struct SyncHandle {
    pub client: Arc<Client>,
    pub ops: Arc<dyn AccountOps>,
    pub relay: Arc<dyn Relay>,
    /// Becomes true when the account's sync stops.
    pub stopping: watch::Receiver<bool>,
}

struct Running {
    handle: SyncHandle,
    #[cfg(any(test, feature = "test-support"))]
    signer: Arc<dyn Signer>,
    capability: Arc<AccountCapability>,
    /// This device's preset hue among the account's active devices, chosen
    /// once per client; the host shows its own caret and its other devices'
    /// in these colours.
    colour: Option<u8>,
    stopping: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// A container's client, or the one start that may make it.
enum Slot {
    /// Later starts wait for this one (`started` ends with it).
    Starting {
        token: u64,
        started: watch::Receiver<()>,
    },
    Running(Running),
}

/// Host work a verified removal triggers once no client runs for the account:
/// the account registry erases the container and reports its final screen.
pub type EraseHook =
    Arc<dyn Fn(ContainerId) -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>;

struct SyncInner {
    configured: Configured,
    owner: Arc<bh_device::Owner>,
    connector: Option<Arc<dyn Connector>>,
    relay: Option<Arc<dyn Relay>>,
    /// At most one start or client per container. Held only briefly, never
    /// across an await.
    running: Mutex<HashMap<ContainerId, Slot>>,
    /// Set once by the app that owns both this host and the account registry.
    erase: Mutex<Option<EraseHook>>,
    starts: std::sync::atomic::AtomicU64,
    /// Accounts without a client (no endpoint): their windows still hear
    /// their local status.
    local: Mutex<HashMap<ContainerId, Arc<dyn StatusWindows>>>,
    views: Mutex<Published>,
    /// Woken whenever an account's status is published.
    published: tokio::sync::Notify,
}

/// Each account's last published status, and the host's newest revision:
/// one counter for the life of the host, whichever client published.
#[derive(Default)]
struct Published {
    views: HashMap<ContainerId, StatusView>,
    revision: u64,
}

impl SyncInner {
    fn slots(&self) -> std::sync::MutexGuard<'_, HashMap<ContainerId, Slot>> {
        self.running.lock().expect("sync clients")
    }
}

/// One start's claim on its container's slot. Dropped, by failure or by
/// its caller giving up, it frees the slot if it still holds it.
struct Start {
    inner: Arc<SyncInner>,
    id: ContainerId,
    token: u64,
    _started: watch::Sender<()>,
}
impl Start {
    fn holds(&self, slots: &HashMap<ContainerId, Slot>) -> bool {
        matches!(slots.get(&self.id), Some(Slot::Starting { token, .. }) if *token == self.token)
    }
}
impl Drop for Start {
    fn drop(&mut self) {
        let mut slots = self.inner.slots();
        if self.holds(&slots) {
            slots.remove(&self.id);
        }
    }
}

/// Every ready account's sync. One client per anchored container, started
/// once its account is ready and stopped when its authority ends.
#[derive(Clone)]
pub struct SyncHost(Arc<SyncInner>);

impl SyncHost {
    pub fn new(configured: Configured, owner: Arc<bh_device::Owner>) -> Self {
        let host = Self(Arc::new(SyncInner {
            configured,
            owner,
            connector: None,
            relay: None,
            running: Mutex::default(),
            erase: Mutex::default(),
            starts: Default::default(),
            local: Mutex::default(),
            views: Mutex::default(),
            published: tokio::sync::Notify::new(),
        }));
        host.install_records_wake();
        host
    }
    /// Set the erasure this host runs after a check verifies this device's
    /// removal. It is called only once no client runs for the account (a
    /// running one is stopped first), so the count it freezes is
    /// authoritative.
    pub fn set_erase(&self, erase: EraseHook) {
        *self.0.erase.lock().expect("erase hook") = Some(erase);
    }

    fn erase_hook(&self) -> Option<EraseHook> {
        self.0.erase.lock().expect("erase hook").clone()
    }

    fn install_records_wake(&self) {
        let weak = Arc::downgrade(&self.0);
        self.0.owner.set_records_wake(Arc::new(move |id| {
            if let Some(inner) = weak.upgrade() {
                Self(inner).wake(id);
            }
        }));
    }
    /// As `new`, over another transport to the same edge routes.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_transport(
        configured: Configured,
        owner: Arc<bh_device::Owner>,
        connector: Arc<dyn Connector>,
        relay: Arc<dyn Relay>,
    ) -> Self {
        let host = Self::new(configured, owner);
        let mut inner = Arc::try_unwrap(host.0).ok().expect("new host");
        inner.connector = Some(connector);
        inner.relay = Some(relay);
        let host = Self(Arc::new(inner));
        host.install_records_wake();
        host
    }

    /// The edge and roots this build syncs with, if any.
    pub fn transport(&self) -> Option<Transport> {
        let Configured::Ready(endpoint) = &self.0.configured else {
            return None;
        };
        Some(Transport {
            endpoint: endpoint.clone(),
            connector: self
                .0
                .connector
                .clone()
                .unwrap_or_else(|| WsConnector::new(&endpoint.edge_url)),
            relay: self
                .0
                .relay
                .clone()
                .unwrap_or_else(|| HttpRelay::new(&endpoint.edge_url)),
            owner: self.0.owner.clone(),
        })
    }

    /// Start (or keep) ready account `id`'s client. Without an endpoint,
    /// its windows still hear that their work is saved on this device.
    ///
    /// One start per container at a time: a second waits for the first
    /// (holding no lock) and keeps what it made. A start installs its
    /// client only while its authority is still the account's current one;
    /// one that fails, or whose caller stops waiting, leaves nothing behind.
    /// Other accounts' starts never wait for this one.
    pub async fn ensure_started<S, P>(
        &self,
        accounts: &SharedAccountHost<S, P>,
        id: ContainerId,
        windows: Arc<dyn StatusWindows>,
    ) where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        let (start, replaced, endpoint) = loop {
            let Some(parts) = accounts.ready_parts(id) else {
                return;
            };
            let endpoint = match &self.0.configured {
                Configured::Ready(endpoint) => endpoint.clone(),
                Configured::Missing | Configured::Invalid => {
                    let network = match self.0.configured {
                        Configured::Missing => "off",
                        _ => "unsupported",
                    };
                    self.0
                        .local
                        .lock()
                        .expect("local windows")
                        .insert(id, windows.clone());
                    let view = StatusView::local(self.pending(id), network);
                    self.publish(id, view, windows.as_ref());
                    return;
                }
            };
            let claimed = {
                let mut slots = self.0.slots();
                match slots.get(&id) {
                    Some(Slot::Running(current))
                        if Arc::ptr_eq(&current.capability, &parts.capability)
                            && current.capability.is_current() =>
                    {
                        return;
                    }
                    Some(Slot::Starting { started, .. }) => Err(started.clone()),
                    _ => {
                        let token = self
                            .0
                            .starts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let (claim, started) = watch::channel(());
                        let replaced = slots.insert(id, Slot::Starting { token, started });
                        Ok((token, claim, replaced))
                    }
                }
            };
            match claimed {
                Ok((token, claim, replaced)) => {
                    let start = Start {
                        inner: self.0.clone(),
                        id,
                        token,
                        _started: claim,
                    };
                    break (start, replaced, endpoint);
                }
                // Ends when that start installs its client or gives up.
                Err(mut started) => {
                    let _ = started.changed().await;
                }
            }
        };
        // A client of an earlier authority stops before this one starts.
        if let Some(Slot::Running(old)) = replaced {
            stop_running(old).await;
        }
        let Ok(signer) = HostSigner::start(accounts.clone(), id).await else {
            return;
        };
        let capability = signer.capability.clone();
        if !accounts
            .ready_parts(id)
            .is_some_and(|now| Arc::ptr_eq(&now.capability, &capability))
        {
            return;
        }
        let connector = self
            .0
            .connector
            .clone()
            .unwrap_or_else(|| WsConnector::new(&endpoint.edge_url));
        let relay = self
            .0
            .relay
            .clone()
            .unwrap_or_else(|| HttpRelay::new(&endpoint.edge_url));
        // The initial count is a snapshot; status reports update it later.
        // Never hold the all-accounts slots lock during a container SQLite read.
        let pending = self.pending(id);
        let mut slots = self.0.slots();
        // Stopped or locked meanwhile: nothing is installed after it.
        if !start.holds(&slots) || !capability.is_current() {
            return;
        }
        // The account's active-device order fixes this device's hue, the same
        // on every screen. A later addition may shift it only on restart.
        let colour = signer.current_account().ok().and_then(|account| {
            account
                .active_devices()
                .ok()?
                .position(|keys| keys.id() == capability.device_id())
                .map(|index| (index % 6) as u8)
        });
        let (status, status_rx) = watch::channel(SyncStatus::SavedLocal { pending });
        let client = Arc::new(Client::start_with(
            endpoint,
            connector,
            self.0.owner.clone(),
            id,
            signer.clone(),
            status,
        ));
        let (stopping, stopping_rx) = watch::channel(false);
        #[cfg(any(test, feature = "test-support"))]
        let handle_signer: Arc<dyn Signer> = signer.clone();
        let wakes = client.window_wakes();
        let wake_windows = windows.clone();
        let forward_wakes = tokio::spawn(async move {
            loop {
                for window in wakes.next().await {
                    wake_windows.wake_delivery(window);
                }
            }
        });
        let report = tokio::spawn(report(
            Arc::downgrade(&self.0),
            id,
            capability.clone(),
            status_rx,
            client.home_status(),
            signer.notices(),
            client.removal_verdict(),
            windows,
        ));
        let handle = SyncHandle {
            client,
            ops: signer,
            relay,
            stopping: stopping_rx,
        };
        slots.insert(
            id,
            Slot::Running(Running {
                #[cfg(any(test, feature = "test-support"))]
                signer: handle_signer,
                handle,
                capability,
                colour,
                stopping,
                tasks: vec![forward_wakes, report],
            }),
        );
        drop(slots);
        drop(start);
    }

    fn pending(&self, id: ContainerId) -> u64 {
        self.0
            .owner
            .shared_database(id)
            .ok()
            .and_then(|db| db.lock().ok()?.outbox_summary().ok())
            .map_or(0, |summary| summary.unaccepted_notes)
    }

    fn publish(&self, id: ContainerId, view: StatusView, windows: &dyn StatusWindows) {
        publish(&self.0, id, view, windows);
    }

    fn running_handle(&self, id: ContainerId) -> Option<SyncHandle> {
        match self.0.slots().get(&id)? {
            Slot::Running(running) => Some(running.handle.clone()),
            Slot::Starting { .. } => None,
        }
    }

    /// Local note work committed in `id`: look for it now, and tell its
    /// windows what is still unsaved to the network.
    pub fn wake(&self, id: ContainerId) {
        if let Some(handle) = self.running_handle(id) {
            handle.client.wake();
            return;
        }
        let windows = self
            .0
            .local
            .lock()
            .expect("local windows")
            .get(&id)
            .cloned();
        if let Some(windows) = windows {
            let network = match self.0.configured {
                Configured::Invalid => "unsupported",
                _ => "off",
            };
            self.publish(
                id,
                StatusView::local(self.pending(id), network),
                windows.as_ref(),
            );
        }
    }

    /// The account's current status, for a window (re)binding to it.
    pub fn view(&self, id: ContainerId) -> Option<StatusView> {
        self.0
            .views
            .lock()
            .expect("sync views")
            .views
            .get(&id)
            .cloned()
    }

    /// Wait until account `id` holds no unsent local work. `false` once its
    /// client is no longer running: the work waits for a later start.
    pub async fn sent(&self, id: ContainerId) -> bool {
        if let Some(handle) = self.handle(id) {
            handle.client.wake();
        }
        loop {
            let published = self.0.published.notified();
            tokio::pin!(published);
            published.as_mut().enable();
            let unsent = self
                .0
                .owner
                .shared_database(id)
                .ok()
                .and_then(|db| db.lock().ok()?.unsent_count().ok());
            match unsent {
                Some(0) => return true,
                Some(_) if self.handle(id).is_some() => {}
                _ => return false,
            }
            published.await;
        }
    }

    pub fn handle(&self, id: ContainerId) -> Option<SyncHandle> {
        self.running_handle(id)
            .filter(|handle| handle.ops.is_current())
    }
    /// This container's own-device presence handle, if its client is current.
    /// The caller configures it once, reports selections, and clears a window
    /// when it closes or navigates.
    pub fn presence(&self, id: ContainerId) -> Option<Presence> {
        self.handle(id).map(|handle| handle.client.presence())
    }
    /// This device's preset hue in `id`, from its position among the
    /// account's active devices when the client started.
    pub fn presence_colour(&self, id: ContainerId) -> Option<u8> {
        match self.0.slots().get(&id)? {
            Slot::Running(running) => running.colour,
            Slot::Starting { .. } => None,
        }
    }
    /// The remote carets this device shows for `id`. Each published value is
    /// the whole bounded state, so a reader can miss a change but never a
    /// removal.
    pub fn remote_presence(&self, id: ContainerId) -> Option<watch::Receiver<RemoteState>> {
        self.presence(id).map(|presence| presence.subscribe())
    }
    /// Pause or quit: every running account announces that it has nothing to
    /// show and closes its presence join. Best effort and nonblocking.
    pub fn leave_presence(&self) {
        for slot in self.0.slots().values() {
            if let Slot::Running(running) = slot {
                running.handle.client.presence().leave();
            }
        }
    }
    /// Android resumed: presence opens its join again and resends each
    /// window's kept selection.
    pub fn resume_presence(&self) {
        for slot in self.0.slots().values() {
            if let Slot::Running(running) = slot {
                running.handle.client.presence().foreground(true);
            }
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn client(&self, id: ContainerId) -> Option<Arc<Client>> {
        self.handle(id).map(|handle| handle.client)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn signer(&self, id: ContainerId) -> Option<Arc<dyn Signer>> {
        match self.0.slots().get(&id)? {
            Slot::Running(running) => Some(running.signer.clone()),
            Slot::Starting { .. } => None,
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn running(&self, id: ContainerId) -> bool {
        matches!(self.0.slots().get(&id), Some(Slot::Running(_)))
    }

    /// Lock every account, then stop every client and start: the one way
    /// an account lock reaches sync. Holders of a handle do not delay it.
    pub async fn lock_accounts<S, P>(&self, accounts: &SharedAccountHost<S, P>)
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        accounts.lock().stop_accounts();
        self.shutdown_all().await;
    }
    /// Quit: stop every client and start. Their exact bytes are already kept.
    pub async fn shutdown_all(&self) {
        let all: Vec<_> = self.0.slots().drain().map(|(_, slot)| slot).collect();
        futures_util::future::join_all(all.into_iter().filter_map(|slot| match slot {
            Slot::Running(running) => Some(stop_running(running)),
            Slot::Starting { .. } => None,
        }))
        .await;
    }
}

/// Send `view` to the account's windows if its status changed, under the
/// host's next revision. Posts may reach a page out of order; the page keeps
/// the larger revision, and the stored view is always the newest.
fn publish(inner: &SyncInner, id: ContainerId, mut view: StatusView, windows: &dyn StatusWindows) {
    inner.published.notify_waiters();
    {
        let mut published = inner.views.lock().expect("sync views");
        if let Some(current) = published.views.get(&id) {
            view.revision = current.revision;
            if *current == view {
                return;
            }
        }
        published.revision += 1;
        view.revision = published.revision;
        published.views.insert(id, view.clone());
    }
    windows.post_status(id, &view);
}

/// Stop one client: tell its borrowers, end its report and wake forwarding,
/// then stop the client itself, however many hold it. It runs to the end in
/// its own task, so a caller that stops waiting cannot leave it half done.
async fn stop_running(running: Running) {
    let Running {
        handle,
        stopping,
        tasks,
        ..
    } = running;
    let _ = stopping.send(true);
    for task in &tasks {
        task.abort();
    }
    let stopped = tokio::spawn(async move {
        for task in tasks {
            let _ = task.await;
        }
        handle.client.shutdown().await;
    });
    let _ = stopped.await;
}

impl SyncHost {
    /// The last start found these accounts no longer holding this device
    /// active (`SharedAccountHost::removed_members`), so no client runs for
    /// them. Check each one's public evidence once, from its last member
    /// view. Only a verified removal erases, through the hook; any other
    /// answer, or none, leaves the account as it is.
    pub async fn check_removed<S, P>(&self, accounts: &SharedAccountHost<S, P>)
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        let Configured::Ready(endpoint) = &self.0.configured else {
            return;
        };
        let erase = self.erase_hook();
        for (id, device, last) in accounts.removed_members() {
            let Ok(database) = self.0.owner.shared_database(id) else {
                continue;
            };
            let genesis = DeviceJournal::from_shared(database)
                .history_prefix(
                    Some(HistoryCursor {
                        anchor: last.id(),
                        cut: last.head(),
                        next_position: 1,
                    }),
                    1,
                )
                .ok()
                .flatten()
                .and_then(|page| page.events.into_iter().next());
            let Some(genesis) = genesis else {
                continue;
            };
            let connector = self
                .0
                .connector
                .clone()
                .unwrap_or_else(|| WsConnector::new(&endpoint.edge_url));
            let checked = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                bh_sync_client::check_removal(
                    endpoint.clone(),
                    connector,
                    self.0.owner.clone(),
                    id,
                    device,
                    genesis,
                    last,
                ),
            )
            .await;
            match checked {
                Ok(Some(bh_sync_client::RemovalVerdict::Removed { .. })) => {
                    if let Some(erase) = &erase {
                        erase(id).await;
                    }
                }
                Ok(Some(bh_sync_client::RemovalVerdict::Refused)) => accounts.deliver_alerts(id),
                _ => {}
            }
        }
    }

    /// The client verified this device's removal (`RemovalVerdict::Removed`;
    /// nothing else may call this). Stop it first, so no local work moves
    /// under the frozen count, then end its routes while retaining their
    /// labels for the UI. Erase through the app's hook before reloading those
    /// windows; other accounts stay running.
    async fn after_removal(
        &self,
        id: ContainerId,
        capability: &Arc<AccountCapability>,
        windows: &dyn StatusWindows,
    ) {
        let running = {
            let mut slots = self.0.slots();
            match slots.get(&id) {
                Some(Slot::Running(running)) if Arc::ptr_eq(&running.capability, capability) => {
                    slots.remove(&id)
                }
                _ => None,
            }
        };
        if let Some(Slot::Running(running)) = running {
            stop_running(running).await;
        }
        // The real erase hook deauthorizes again and may delete the container.
        // Retain the labels now, while also revoking writers before it freezes
        // the unsent count. The callback must wait for its final screen.
        let routed = self.0.owner.deauthorize(id).unwrap_or_default();
        if let Some(erase) = self.erase_hook() {
            erase(id).await;
        }
        windows.authority_ended(id, routed);
    }
}

/// Follow one client's note status, home status and account notices, and
/// tell the account's windows. When the account's authority ends, end its
/// windows' routes and stop the client.
#[expect(
    clippy::too_many_arguments,
    reason = "one client's independent watch channels and its windows"
)]
async fn report(
    host: std::sync::Weak<SyncInner>,
    id: ContainerId,
    capability: Arc<AccountCapability>,
    mut status: watch::Receiver<SyncStatus>,
    mut home: watch::Receiver<HomeStatus>,
    mut notices: watch::Receiver<Notice>,
    mut removal: watch::Receiver<bh_sync_client::RemovalVerdict>,
    windows: Arc<dyn StatusWindows>,
) {
    // Whether the client was asked to check this device's removal, and
    // published an answer since.
    let (mut asked, mut answered) = (false, false);
    loop {
        let Some(inner) = host.upgrade() else { return };
        let notice = *notices.borrow_and_update();
        let current = *status.borrow_and_update();
        let home_now = *home.borrow_and_update();
        let verdict = *removal.borrow_and_update();
        let pending = SyncHost(inner.clone()).pending(id);
        let view = StatusView::of(Some(current), Some(home_now), notice, pending);
        publish(&inner, id, view, windows.as_ref());
        if matches!(verdict, bh_sync_client::RemovalVerdict::Removed { .. }) {
            // Detached: stopping this client aborts `report` itself, so it
            // must not be the task that waits for that stop and then erases.
            tokio::spawn(async move {
                SyncHost(inner)
                    .after_removal(id, &capability, windows.as_ref())
                    .await;
            });
            return;
        }
        // The owner no longer holds this device a member: its removal, or a
        // lock racing an account apply. Only the client's own check of the
        // public evidence may erase, so ask it, and stop on an answer that
        // does not remove; a pending one waits for its deadline.
        if notice.account == AccountState::Removed && !asked {
            (asked, answered) = (true, false);
            if let Some(Slot::Running(running)) = inner.slots().get(&id)
                && Arc::ptr_eq(&running.capability, &capability)
            {
                running.handle.client.check_removal();
            }
        }
        let waiting = notice.account == AccountState::Removed
            && (!answered || matches!(verdict, bh_sync_client::RemovalVerdict::Pending { .. }));
        if notice.account != AccountState::Active && !waiting {
            let routed = inner.owner.deauthorize(id).unwrap_or_default();
            windows.authority_ended(id, routed);
            // Only this client: a newer start or client stays.
            let running = {
                let mut slots = inner.slots();
                match slots.get(&id) {
                    Some(Slot::Running(running))
                        if Arc::ptr_eq(&running.capability, &capability) =>
                    {
                        slots.remove(&id)
                    }
                    _ => None,
                }
            };
            drop(inner);
            if let Some(Slot::Running(running)) = running {
                tokio::spawn(stop_running(running));
            }
            return;
        }
        drop(inner);
        tokio::select! {
            changed = status.changed() => if changed.is_err() { return },
            changed = home.changed() => if changed.is_err() { return },
            changed = notices.changed() => if changed.is_err() { return },
            changed = removal.changed() => {
                if changed.is_err() { return }
                answered = asked;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounts::{SharedAccountHost, ready_test_host},
        test_support::{FakeStore, PlainProtector},
    };
    use bh_account::owner::staging::Settled;
    use bh_account::{
        DevicePublicKeys,
        crypto::{KemKey, SigningKey},
        journal::AccountJournal,
        storage::DeviceJournal,
    };
    use bh_sync_client::{AccountApplyError, BaseControlRequest, ControlSignError, Signer};
    use std::{path::Path, sync::Arc};

    type Host = SharedAccountHost<FakeStore, PlainProtector>;
    const COPY_MESSAGE: &[u8] = b"bh/original-envelope/v1\0exact copy";

    struct Fixture {
        _dir: tempfile::TempDir,
        owner: Arc<bh_device::Owner>,
        host: Host,
        store: FakeStore,
        id: ContainerId,
        cap: Arc<AccountCapability>,
    }

    async fn fixture(store: FakeStore) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = ready_test_host(&owner, dir.path(), store.clone()).await;
        let (id, cap) = host.ready_authority().unwrap();
        Fixture {
            _dir: dir,
            owner,
            host,
            store,
            id,
            cap,
        }
    }

    /// A signup whose home answered: later account history may follow. A
    /// legacy home leaves the setup prefix untimed.
    async fn completed(store: FakeStore) -> Fixture {
        let f = fixture(store).await;
        f.host
            .with_owner(f.id, &f.cap, |owner| {
                let head = owner.setup_status().unwrap().unwrap().head;
                owner
                    .confirm_home_ordered(head, Some(setup_evidence()))
                    .unwrap();
            })
            .unwrap();
        f
    }

    fn real_keys() -> DevicePublicKeys {
        DevicePublicKeys::new(
            SigningKey::generate().public(),
            SigningKey::generate().public(),
            KemKey::generate().public(),
        )
        .unwrap()
    }

    /// A device addition this account's control key signs, not applied.
    async fn signed_addition(f: &Fixture, keys: DevicePublicKeys) -> Vec<u8> {
        f.host
            .run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move {
                    let request = owner.prepare_add_device(&cap, keys).unwrap();
                    owner
                        .sign_control(&cap, &request)
                        .await
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                })
            })
            .await
            .unwrap()
    }

    /// Stage an addition with its delivery, as pairing's approval does.
    async fn staged_addition(f: &Fixture, keys: DevicePublicKeys) -> Vec<u8> {
        f.host
            .run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move {
                    let personal = owner.open_personal(&cap).await.unwrap();
                    let request = owner.prepare_add_device(&cap, keys.clone()).unwrap();
                    let event = owner.sign_control(&cap, &request).await.unwrap();
                    let delivery = owner
                        .seal_personal_for_device(&cap, &personal, &keys, &event)
                        .await
                        .unwrap();
                    owner
                        .stage_signed_admission(&cap, &keys, event.as_bytes(), &delivery)
                        .unwrap();
                    event.as_bytes().to_vec()
                })
            })
            .await
            .unwrap()
    }

    fn raw(path: &Path) -> rusqlite::Connection {
        let file = std::fs::read_dir(path.join("accounts"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
            .unwrap();
        rusqlite::Connection::open(file).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_is_the_base_genesis_account_and_current_follows_the_owner() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let identity = signer.identity().unwrap();
        assert!(identity.account == f.cap.account_id());
        assert!(identity.device == f.cap.device_id());
        assert_eq!(
            identity.anchor.head().position,
            3,
            "the base genesis's head"
        );
        let database = f.owner.shared_database(f.id).unwrap();
        let journal = DeviceJournal::from_shared(database);
        assert_eq!(
            identity.genesis,
            journal.load().unwrap().unwrap().history[0]
        );
        let head = signer.current_account().unwrap().head();
        assert_eq!(head, f.cap.head());
        let addition = signed_addition(&f, real_keys()).await;
        let applied = signer
            .apply_account_timed(head, vec![timed(addition, 30)])
            .await
            .unwrap();
        assert_eq!(applied.position, 4);
        assert_eq!(signer.current_account().unwrap().head(), applied);
        assert_eq!(identity.anchor.head().position, 3, "identity is unchanged");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn account_follow_keeps_refused_unsupported_stopped_and_unavailable_apart() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let addition = signed_addition(&f, real_keys()).await;
        // Not the owner's head: nothing applied.
        let mut elsewhere = head;
        elsewhere.position += 1;
        assert_eq!(
            signer
                .apply_account_timed(elsewhere, vec![timed(addition.clone(), 30)])
                .await,
            Err(AccountApplyError::Unavailable)
        );
        // Not this account's next verified history: refused, no stop.
        let mut forged = addition.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            signer
                .apply_account_timed(head, vec![timed(forged, 30)])
                .await,
            Err(AccountApplyError::Refused)
        );
        assert_eq!(
            signer
                .apply_account_timed(head, vec![timed(b"junk".to_vec(), 30)])
                .await,
            Err(AccountApplyError::Refused)
        );
        assert_eq!(signer.current_account().unwrap().head(), head);
        assert!(f.cap.is_current());
        assert_eq!(*signer.notices().borrow(), Notice::default());
        // An authenticated fork stops the account.
        let (taken, fork) = fork_pair(&f).await;
        let at = signer
            .apply_account_timed(head, vec![timed(taken, 30)])
            .await
            .unwrap();
        assert_eq!(
            signer.apply_account_timed(at, vec![timed(fork, 40)]).await,
            Err(AccountApplyError::Stopped)
        );
        assert_eq!(signer.notices().borrow().account, AccountState::Stopped);
        assert!(signer.current_account().is_err());
        assert!(signer.sign_event(b"after".to_vec()).await.is_err());
    }

    /// Two signed successors of the current head, and an event extending
    /// the second: the owner applies the first, then gets the third.
    async fn fork_pair(f: &Fixture) -> (Vec<u8>, Vec<u8>) {
        let device = f.cap.device_id();
        f.host
            .run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move {
                    let taken = owner.prepare_add_device(&cap, real_keys()).unwrap();
                    let taken = owner.sign_control(&cap, &taken).await.unwrap();
                    let other = owner.prepare_add_device(&cap, real_keys()).unwrap();
                    let other = owner.sign_control(&cap, &other).await.unwrap();
                    let mut branch = owner.verified(&cap).unwrap().clone();
                    branch
                        .apply_timed(other.as_bytes(), timed(Vec::new(), 30).1.map(|e| e.0))
                        .unwrap();
                    let next = branch.add_device(device, real_keys()).unwrap();
                    let next = owner.sign_control(&cap, &next).await.unwrap();
                    (taken.as_bytes().to_vec(), next.as_bytes().to_vec())
                })
            })
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_stop_write_is_still_a_stop() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let (taken, fork) = fork_pair(&f).await;
        let at = signer
            .apply_account_timed(head, vec![timed(taken, 30)])
            .await
            .unwrap();
        raw(f._dir.path())
            .execute_batch(
                "CREATE TRIGGER fail_stop BEFORE UPDATE ON account_state \
                 BEGIN SELECT RAISE(FAIL, 'no space'); END;",
            )
            .unwrap();
        assert_eq!(
            signer.apply_account_timed(at, vec![timed(fork, 40)]).await,
            Err(AccountApplyError::Stopped),
            "the live owner latched its stop"
        );
        assert!(!f.cap.is_current());
        assert_eq!(signer.notices().borrow().account, AccountState::Stopped);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_removed_device_is_reported_and_its_authority_ends() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let removal = f
            .host
            .run_lent(f.id, &f.cap, |owner, cap| {
                Box::pin(async move {
                    let request = owner.prepare_remove_self(&cap).unwrap();
                    owner
                        .sign_control(&cap, &request)
                        .await
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                })
            })
            .await
            .unwrap();
        assert!(
            signer
                .apply_account_timed(head, vec![timed(removal, 30)])
                .await
                .is_ok()
        );
        assert_eq!(signer.notices().borrow().account, AccountState::Removed);
        assert!(!f.cap.is_current());
        assert!(signer.current_account().is_err());
        let mut used = false;
        assert!(
            signer
                .with_metadata_key(signer.base(), &mut |_| used = true)
                .is_err()
        );
        assert!(
            signer
                .with_epoch_keys(signer.base(), None, &mut |_, _| used = true)
                .is_err()
        );
        assert!(!used);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_staged_addition_settles_once_its_account_event_applies() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let event = staged_addition(&f, real_keys()).await;
        let staged = signer.staged_addition().unwrap().unwrap();
        assert_eq!((staged.position, staged.event.clone()), (4, event.clone()));
        signer
            .apply_account_timed(head, vec![timed(event, 30)])
            .await
            .unwrap();
        assert!(signer.staged_addition().unwrap().is_none(), "admitted");

        // Another event at the staged position: not added, row settled.
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let head = signer.current_account().unwrap().head();
        let _ = staged_addition(&f, real_keys()).await;
        let competitor = f
            .host
            .run_lent(f.id, &f.cap, |owner, cap| {
                Box::pin(async move {
                    let view = owner.verified(&cap).unwrap().clone();
                    let request = view.add_device(cap.device_id(), real_keys()).unwrap();
                    owner
                        .sign_control(&cap, &request)
                        .await
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                })
            })
            .await
            .unwrap();
        signer
            .apply_account_timed(head, vec![timed(competitor, 30)])
            .await
            .unwrap();
        assert!(signer.staged_addition().unwrap().is_none(), "not added");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_first_devices_home_setup_is_its_retained_signup_or_an_error() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let setup = signer.initial_home_setup().unwrap().expect("first device");
        assert_eq!(setup.prefix.head.position, 3);
        assert!(setup.prefix.anchor == f.cap.account_id());
        let journal = DeviceJournal::from_shared(f.owner.shared_database(f.id).unwrap());
        let retained = journal.initial_bootstrap().unwrap().unwrap();
        assert!(setup.objects.record == retained.recovery_record);
        // Missing retained signup on a first device: an error, never None.
        raw(f._dir.path())
            .execute_batch("DELETE FROM account_initial_bootstrap")
            .unwrap();
        let again = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        assert!(again.initial_home_setup().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_device_added_later_has_no_home_obligation() {
        let f = fixture(FakeStore::default()).await;
        // A second container whose device the first adds at position 4.
        let id = f.owner.create_container(f._dir.path()).unwrap();
        let database = f.owner.shared_database(id).unwrap();
        let mut journal = DeviceJournal::from_shared(database.clone());
        let identity = bh_account::pairing::scanner_identity(
            &mut journal,
            &mut f.store.clone(),
            bh_account::platform::ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        )
        .await
        .unwrap();
        let addition = signed_addition(&f, identity.keys.clone()).await;
        let first = DeviceJournal::from_shared(f.owner.shared_database(f.id).unwrap());
        let mut history = first.load().unwrap().unwrap().history;
        history.push(addition);
        let refs: Vec<&[u8]> = history.iter().map(Vec::as_slice).collect();
        let generation = bh_account::owner::AccountGeneration::new();
        let mut joined = Owner::new(
            DeviceJournal::from_shared(database),
            f.store.clone(),
            PlainProtector,
            generation.clone(),
        );
        joined.adopt_joined(f.cap.account_id(), &refs).unwrap();
        let bh_account::owner::AccountLoad::Active(cap) = joined.activate().await.unwrap() else {
            panic!("joined device active");
        };
        assert!(
            retained_home_setup(&joined, &cap, &journal, &generation)
                .unwrap()
                .is_none()
        );
    }

    /// `original` with a confirmation at `at`, as the client verified it.
    fn timed(original: Vec<u8>, at: u64) -> TimedOriginal {
        let time = ConfirmedTime {
            earliest_ms: at,
            latest_ms: at + 2,
        };
        (
            original,
            Some((time, format!("proof at {at}").into_bytes())),
        )
    }

    /// The home's confirmations of setup positions 2 and 3, as the client
    /// verified them.
    fn setup_evidence() -> [(ConfirmedTime, Vec<u8>); 2] {
        [
            (
                ConfirmedTime {
                    earliest_ms: 10,
                    latest_ms: 12,
                },
                b"record proof".to_vec(),
            ),
            (
                ConfirmedTime {
                    earliest_ms: 20,
                    latest_ms: 22,
                },
                b"key proof".to_vec(),
            ),
        ]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn home_times_reach_the_current_account_and_the_creator_anchor() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let device = f.cap.device_id();
        assert_eq!(signer.identity().unwrap().anchor.added_at(device), None);
        let setup = signer.initial_home_setup().unwrap().unwrap();
        signer
            .confirm_home_ordered(&setup, setup_evidence())
            .unwrap();
        let database = f.owner.shared_database(f.id).unwrap();
        let row = database.lock().unwrap().confirmation(3).unwrap().unwrap();
        assert_eq!(row.bytes, b"key proof");
        assert_eq!(signer.current_account().unwrap().added_at(device), Some(12));
        let anchor = signer.identity().unwrap().anchor;
        assert_eq!(anchor.head(), setup.prefix.head, "the same creator head");
        assert_eq!(anchor.added_at(device), Some(12));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn home_confirmation_is_fenced_by_generation_and_account() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let setup = signer.initial_home_setup().unwrap().unwrap();
        let journal = DeviceJournal::from_shared(f.owner.shared_database(f.id).unwrap());
        let mut stale = signer.initial_home_setup().unwrap().unwrap();
        stale.generation += 1;
        assert!(
            signer
                .confirm_home_ordered(&stale, setup_evidence())
                .is_err()
        );
        let mut other = signer.initial_home_setup().unwrap().unwrap();
        other.prefix.anchor = bh_account::AccountId([9; 32]);
        assert!(
            signer
                .confirm_home_ordered(&other, setup_evidence())
                .is_err()
        );
        assert!(journal.pending_setup().unwrap().is_some());
        signer
            .confirm_home_ordered(&setup, setup_evidence())
            .unwrap();
        assert!(journal.pending_setup().unwrap().is_none());
        // Already cleared: the same exact acknowledged setup completes again.
        signer
            .confirm_home_ordered(&setup, setup_evidence())
            .unwrap();
        assert!(journal.initial_bootstrap().unwrap().is_some(), "retained");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_base_control_without_the_persons_approval_never_prompts() {
        let f = fixture(FakeStore::gated()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let addition = signed_addition(&f, real_keys()).await;
        let prompts = f.store.prompts();
        let request = || BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition.clone(),
        };
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert!(signer.notices().borrow().confirm, "the person is asked");
        // Approved copy, but no confirmation it can reuse: still no prompt.
        signer
            .approvals()
            .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert_eq!(
            f.store.prompts(),
            prompts,
            "nothing prompted in the background"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_pairing_confirmation_signs_the_addition_and_exactly_its_copy() {
        let f = fixture(FakeStore::gated()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let before = f.store.prompts();
        signer.open_pairing_action();
        let addition = signed_addition(&f, real_keys()).await;
        assert_eq!(f.store.prompts(), before + 1, "the addition's confirmation");
        signer
            .approvals()
            .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
        let request = |copies: &[u8]| BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: copies.to_vec(),
        };
        let mut other = addition.clone();
        other[10] ^= 1;
        assert_eq!(
            signer.sign_base_control(request(&other)).await,
            Err(ControlSignError::ConfirmationNeeded),
            "another event's copy"
        );
        let signature = signer.sign_base_control(request(&addition)).await.unwrap();
        assert!(
            bh_account::crypto::verify(&signer.control_key(), COPY_MESSAGE, &signature).is_ok()
        );
        assert_eq!(
            f.store.prompts(),
            before + 1,
            "no second prompt for the copy"
        );
        assert!(!signer.notices().borrow().confirm);
        // Used once: the same copy again needs the person again.
        assert_eq!(
            signer.sign_base_control(request(&addition)).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert_eq!(f.store.prompts(), before + 1);
    }

    /// An armed copy whose grant another gate use ends before the owner
    /// signs it (`revoke`: a failed pairing; `open`: another approval)
    /// waits for the person; it never prompts from the background.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_armed_copy_that_loses_its_grant_waits_and_never_prompts() {
        for another_pairing in [false, true] {
            let f = fixture(FakeStore::gated()).await;
            let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
            signer.open_pairing_action();
            let addition = signed_addition(&f, real_keys()).await;
            signer
                .approvals()
                .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
            // The owner is busy, so the armed copy waits for it.
            let (release, held) = tokio::sync::oneshot::channel::<()>();
            let busy = tokio::spawn({
                let (host, id, cap) = (f.host.clone(), f.id, f.cap.clone());
                async move {
                    host.run_lent(id, &cap, move |_, _| {
                        Box::pin(async move {
                            let _ = held.await;
                        })
                    })
                    .await
                }
            });
            while f.host.with_owner(f.id, &f.cap, |_| ()).is_some() {
                tokio::task::yield_now().await;
            }
            let prompts = f.store.prompts();
            let mut copy = Box::pin(signer.sign_base_control(BaseControlRequest {
                expected_key: signer.control_key(),
                message: COPY_MESSAGE.to_vec(),
                copies: addition.clone(),
            }));
            assert!(
                futures_util::poll!(&mut copy).is_pending(),
                "armed, waiting"
            );
            if another_pairing {
                signer.open_pairing_action();
            } else {
                signer.end_pairing_action();
            }
            release.send(()).unwrap();
            busy.await.unwrap().unwrap();
            assert_eq!(copy.await, Err(ControlSignError::ConfirmationNeeded));
            assert_eq!(f.store.prompts(), prompts, "no background prompt");
            assert!(signer.notices().borrow().confirm, "the person is asked");
            // A deliberate control still asks for its fresh confirmation.
            signed_addition(&f, real_keys()).await;
            assert_eq!(f.store.prompts(), prompts + 1);
        }
    }

    #[tokio::test]
    async fn pairing_reconfirmation_ipc_operation_future_stays_below_64_kib() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let future = signer.reconfirm();
        eprintln!(
            "raw reconfirm future: {} bytes",
            std::mem::size_of_val(&future)
        );
        assert!(std::mem::size_of_val(&future) < 64 * 1024);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_a_restart_the_copy_waits_for_an_explicit_fresh_confirmation() {
        let f = fixture(FakeStore::gated()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        signer.open_pairing_action();
        let addition = signed_addition(&f, real_keys()).await;
        drop(signer);
        // The host restarted: the approval and its confirmation are gone.
        f.store.gate.as_ref().unwrap().clear();
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let request = || BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition.clone(),
        };
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        assert!(signer.notices().borrow().confirm);
        // A cancelled confirmation grants nothing.
        f.store
            .refuse_prompts
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(signer.reconfirm().await.is_err());
        assert_eq!(
            signer.sign_base_control(request()).await,
            Err(ControlSignError::ConfirmationNeeded)
        );
        f.store
            .refuse_prompts
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let prompts = f.store.prompts();
        signer.reconfirm().await.unwrap();
        assert_eq!(f.store.prompts(), prompts + 1, "one fresh confirmation");
        signer.sign_base_control(request()).await.unwrap();
        assert_eq!(f.store.prompts(), prompts + 1);
        assert!(!signer.notices().borrow().confirm);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_platform_bound_store_never_signs_a_copy_without_approval() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let addition = signed_addition(&f, real_keys()).await;
        let request = BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition,
        };
        assert_eq!(
            signer.sign_base_control(request).await,
            Err(ControlSignError::ConfirmationNeeded),
            "no background signature without the person's approval"
        );
        assert!(signer.notices().borrow().confirm);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_platform_bound_store_signs_an_approved_copy_with_its_own_check() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let addition = signed_addition(&f, real_keys()).await;
        signer
            .approvals()
            .grant(addition.clone(), tokio::time::Instant::now() + LIFE);
        let request = BaseControlRequest {
            expected_key: signer.control_key(),
            message: COPY_MESSAGE.to_vec(),
            copies: addition,
        };
        assert!(signer.sign_base_control(request).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_locked_account_refuses_every_signer_use() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        assert!(signer.sign_event(b"before".to_vec()).await.is_ok());
        let genesis = genesis_epoch(&signer);
        let mut keys_used = (false, false);
        // The client's lock order: the owner's own writer lock is free while
        // the keys are in use.
        let free = || f.owner.shared_database(f.id).unwrap().try_lock().is_ok();
        signer
            .with_metadata_key(signer.base(), &mut |_| keys_used.0 = free())
            .unwrap();
        signer
            .with_epoch_keys(signer.base(), Some(genesis), &mut |_, k| {
                keys_used.1 = k.is_some() && free()
            })
            .unwrap();
        assert_eq!(keys_used, (true, true));
        assert!(
            signer
                .with_metadata_key(bh_sync::BaseId([7; 32]), &mut |_| {})
                .is_err(),
            "only the own base"
        );
        assert!(
            signer
                .with_epoch_keys(bh_sync::BaseId([7; 32]), None, &mut |_, _| {})
                .is_err(),
            "only the own base"
        );
        f.host.lock().stop_accounts();
        assert!(signer.current_account().is_err());
        assert!(signer.sign_event(b"after".to_vec()).await.is_err());
        assert!(signer.initial_home_setup().is_err());
        assert!(
            signer
                .with_metadata_key(signer.base(), &mut |_| {})
                .is_err()
        );
        assert!(
            signer
                .with_epoch_keys(signer.base(), Some(genesis), &mut |_, _| {})
                .is_err()
        );
    }

    /// Another device of the account added, then removed by itself: a
    /// rotation is due from `left_at`.
    async fn removed_other<S, P>(signer: &HostSigner<S, P>, f: &Fixture, left_at: u64)
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        let control = SigningKey::generate();
        let other = DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let addition = signed_addition(f, other.clone()).await;
        let head = signer.current_account().unwrap().head();
        signer
            .apply_account_timed(head, vec![timed(addition, left_at - 1_000)])
            .await
            .unwrap();
        let account = signer.current_account().unwrap();
        let request = account.remove_self(other.id()).unwrap();
        let leave = request
            .finish(control.sign(request.signing_bytes()))
            .unwrap();
        signer
            .apply_account_timed(
                account.head(),
                vec![timed(leave.as_bytes().to_vec(), left_at)],
            )
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rotation_is_staged_settled_and_accepted_through_the_lent_owner() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        removed_other(&signer, &f, 2_000).await;
        let before = *signer.current_account().unwrap().personal_public().unwrap();
        let staged = signer.stage_rotation(2_002).await.unwrap();
        assert_eq!(staged.kind, 9);
        assert_eq!(signer.staged_control().unwrap(), Some(staged.clone()));
        assert_eq!(signer.settle_staged().unwrap(), None);
        // Ordered and followed: settled, then accepted from its raw body.
        let head = signer.current_account().unwrap().head();
        signer
            .apply_account_timed(head, vec![timed(staged.event.clone(), 3_000)])
            .await
            .unwrap();
        let settled = signer.settle_staged().unwrap().unwrap();
        let Settled::Accepted { position, .. } = settled.outcome else {
            panic!("{:?}", settled.outcome);
        };
        assert_eq!(signer.staged_control().unwrap(), None);
        // A padded or altered body is never accepted.
        let raw = staged.body.clone().unwrap();
        let mut altered = raw.clone();
        altered[0] ^= 1;
        assert!(signer.accept_rotation(position, altered).await.is_err());
        signer.accept_rotation(position, raw).await.unwrap();
        let now = *signer.current_account().unwrap().personal_public().unwrap();
        assert_ne!(now, before);
        let accepted = f
            .host
            .run_lent(f.id, &f.cap, |owner, cap| {
                Box::pin(async move { owner.open_current_personal(&cap).await.unwrap().public() })
            })
            .await
            .unwrap();
        assert_eq!(accepted, now);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stage_is_discarded_only_as_read() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        removed_other(&signer, &f, 2_000).await;
        let staged = signer.stage_rotation(2_002).await.unwrap();
        let other = StagedControl {
            event: b"other bytes".to_vec(),
            ..staged.clone()
        };
        assert!(signer.discard_staged(&other).is_err());
        assert_eq!(signer.staged_control().unwrap(), Some(staged.clone()));
        signer.discard_staged(&staged).unwrap();
        assert_eq!(signer.staged_control().unwrap(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_own_base_entry_carries_only_a_held_epoch_key() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let epoch = bh_device::base_keys::SealHeader::decode(
            signer
                .own_base
                .initial_key_package()
                .unwrap()
                .content_seal(),
        )
        .unwrap()
        .key_id;
        let bytes = signer
            .prepare_base_entry(signer.base(), epoch, "https://edge.example".into(), 3)
            .await
            .unwrap();
        let opened = signer.open_directory_entries(vec![bytes]).await.unwrap();
        let opened = opened[0].as_ref().ok().unwrap();
        assert_eq!(opened.version, 3);
        assert!(matches!(
            &opened.entry,
            DirectoryEntry::Base { base, epoch_id, server, own: true, .. }
                if *base == signer.base().0 && *epoch_id == epoch && server == "https://edge.example"
        ));
        // At the genesis epoch, under the personal key the base was made
        // with: the base's original seals of M and of that epoch's key.
        let original = signer.own_base.initial_key_package().unwrap();
        assert!(matches!(
            &opened.entry,
            DirectoryEntry::Base { current_key_seal, metadata_seal, .. }
                if current_key_seal == original.content_seal()
                    && metadata_seal == original.metadata_seal()
        ));
        // Another base, or an epoch whose key is not held, is refused.
        assert!(
            signer
                .prepare_base_entry(BaseId([9; 32]), epoch, String::new(), 3)
                .await
                .is_err()
        );
        assert!(
            signer
                .prepare_base_entry(signer.base(), [7; 32], String::new(), 3)
                .await
                .is_err()
        );
        assert_eq!(signer.directory_state().unwrap(), None);
        signer.set_directory_state(3, false).unwrap();
        signer.set_directory_state(3, true).unwrap();
        assert_eq!(signer.directory_state().unwrap(), Some((3, true)));
        assert_eq!(state_name(SyncStatus::Protecting), "protecting");
    }

    /// A rekey's seal set for this account's own base, carrying a new
    /// content key sealed to this device's accepted personal key, and the
    /// durable wait its accepted control leaves: another device joins and
    /// leaves, this device rotates the personal key for it (not accepted),
    /// and prepares the rekey. Returns the wait, the set and the new key.
    async fn seeded_seal_wait<S, P>(
        f: &Fixture,
        signer: &HostSigner<S, P>,
    ) -> (SealWait, Vec<u8>, Secret<32>)
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        use bh_device::base_keys::{BaseKeyPurpose, SealHeader, prepare_seal};
        use bh_sync::evidence::{ConfirmationClaim, OrderingConfirmation, TimeBounds};
        let sign = |message: Vec<u8>| {
            f.host.run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move { owner.sign_content(&cap, &message).await.unwrap() })
            })
        };
        let control = SigningKey::generate();
        let other = DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let addition = signed_addition(f, other.clone()).await;
        let head = signer.current_account().unwrap().head();
        signer
            .apply_account_timed(head, vec![timed(addition, 1_000)])
            .await
            .unwrap();
        let account = signer.current_account().unwrap();
        let request = account.remove_self(other.id()).unwrap();
        let leave = request
            .finish(control.sign(request.signing_bytes()))
            .unwrap();
        signer
            .apply_account_timed(
                account.head(),
                vec![timed(leave.as_bytes().to_vec(), 2_000)],
            )
            .await
            .unwrap();
        let account = signer.current_account().unwrap();
        let next = bh_account::personal::PersonalKey::generate();
        let prepared =
            bh_account::personal::prepare_rotation(&account.advanced(2_002), &next).unwrap();
        let request = account
            .rotate_personal(
                f.cap.device_id(),
                leave.head().position,
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .unwrap();
        let signature = sign(request.signing_bytes().to_vec()).await.unwrap();
        let rotation = request.finish(signature).unwrap();
        let sync_head = |h: AccountHead| bh_sync::Head {
            position: h.position,
            hash: bh_sync::Digest(h.hash),
        };
        let key = SigningKey::generate();
        let confirmation = OrderingConfirmation::sign(
            &key,
            &bh_sync::permit::certify(&SigningKey::generate(), key.public()),
            ConfirmationClaim {
                log: bh_sync::permit::LogId {
                    kind: bh_sync::permit::LogKind::Account,
                    id: [0x64; 32],
                },
                original: bh_sync::evidence::original_digest(rotation.as_bytes()),
                original_previous: sync_head(account.head()),
                original_head: sync_head(rotation.head()),
                body: None,
                ordered: sync_head(rotation.head()),
                bounds: TimeBounds {
                    earliest_ms: 3_000,
                    latest_ms: 3_000,
                },
            },
        )
        .encode()
        .to_vec();
        // The new key, sealed to the personal key this device holds now.
        let personal = f
            .host
            .run_lent(f.id, &f.cap, |owner, cap| {
                Box::pin(async move { owner.open_current_personal(&cap).await.unwrap().public() })
            })
            .await
            .unwrap();
        let root = Secret::<32>::random();
        let base = signer.base();
        let header = SealHeader {
            purpose: BaseKeyPurpose::Content,
            base,
            audience: [0; 32],
            key_id: bh_crypto::committed_key_id(&root),
            recipient: bh_crypto::hash(&personal),
            sender: account.id(),
            device: f.cap.device_id(),
            head: account.head(),
        };
        let unsigned = prepare_seal(&account, header, &personal, &root).unwrap();
        let signature = sign(unsigned.signing_bytes().to_vec()).await.unwrap();
        let seal = unsigned.finish(signature).unwrap();
        let metadata = signer
            .own_base
            .with_metadata_key(|m| Secret::from_slice(m.expose()).unwrap())
            .unwrap();
        let rekey = bh_event::rekey::prepare_rekey(
            base,
            &account,
            f.cap.device_id(),
            &metadata,
            bh_event::Seen {
                head: bh_sync::Head {
                    position: 1,
                    hash: bh_sync::Digest([1; 32]),
                },
                control: [0; 32],
                account: account.head(),
            },
            [0; bh_sync::receipt::RECEIPT_LEN],
            rotation.as_bytes(),
            &confirmation,
            &root,
            &[seal],
        )
        .unwrap();
        let set_bytes = rekey.seal_set.bytes().to_vec();
        let signature = sign(rekey.control.signing_bytes().to_vec()).await.unwrap();
        let control = rekey.control.finish(signature).unwrap();
        let set =
            bh_event::rekey::rekey_seal_set(base, &control.descriptor, &control.body, &metadata)
                .unwrap()
                .unwrap();
        let wait = SealWait {
            base: base.0,
            key_id: set.key_id,
            position: 2,
            event_id: set.event_id.0,
            count: set.count,
            commitment: set.commitment.0,
        };
        // The wait the feed keeps for an accepted rekey.
        raw(f._dir.path())
            .execute(
                "INSERT INTO base_seal_wait(base,key_id,position,event_id,count,commitment)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    wait.base.as_slice(),
                    wait.key_id.as_slice(),
                    wait.position as i64,
                    wait.event_id.as_slice(),
                    wait.count,
                    wait.commitment.as_slice()
                ],
            )
            .unwrap();
        (wait, set_bytes, root)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_installed_epoch_key_is_used_from_memory_without_reopening() {
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let (wait, set, root) = seeded_seal_wait(&f, &signer).await;
        let epoch = bh_crypto::committed_key_id(&root);
        let held = |signer: &HostSigner<_, _>| {
            let mut held = None;
            signer
                .with_epoch_keys(signer.base(), Some(epoch), &mut |_, k| {
                    held = Some(k.map(bh_crypto::committed_key_id))
                })
                .unwrap();
            held.unwrap()
        };
        assert_eq!(held(&signer), None);
        signer.install_epoch(wait, set).await.unwrap();
        // The same signer, its own base not reopened, uses the key now.
        assert_eq!(held(&signer), Some(epoch));
        assert!(f.owner.seal_waits(f.id).unwrap().is_empty());
        let database = f.owner.shared_database(f.id).unwrap();
        let rows = database.lock().unwrap().epoch_keys(wait.base).unwrap();
        assert!(rows.iter().any(|row| row.epoch_id == epoch));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rotated_epochs_entry_after_a_personal_rotation_seals_m_and_its_key_afresh() {
        use bh_device::base_keys::{BaseKeyPurpose, SealHeader, open_seal};
        let f = completed(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        // A rekeyed epoch is held, and then the personal key rotates to P′.
        let (wait, set, root) = seeded_seal_wait(&f, &signer).await;
        let epoch = bh_crypto::committed_key_id(&root);
        signer.install_epoch(wait, set).await.unwrap();
        let before = *signer.current_account().unwrap().personal_public().unwrap();
        let staged = signer.stage_rotation(2_002).await.unwrap();
        let head = signer.current_account().unwrap().head();
        signer
            .apply_account_timed(head, vec![timed(staged.event.clone(), 3_000)])
            .await
            .unwrap();
        let Settled::Accepted { position, .. } = signer.settle_staged().unwrap().unwrap().outcome
        else {
            panic!("not accepted");
        };
        signer
            .accept_rotation(position, staged.body.clone().unwrap())
            .await
            .unwrap();
        let rotated = *signer.current_account().unwrap().personal_public().unwrap();
        assert_ne!(rotated, before);

        let bytes = signer
            .prepare_base_entry(signer.base(), epoch, String::new(), 5)
            .await
            .unwrap();
        let opened = signer.open_directory_entries(vec![bytes]).await.unwrap();
        let DirectoryEntry::Base {
            epoch_id,
            current_key_seal,
            metadata_seal,
            own: true,
            ..
        } = opened.into_iter().next().unwrap().ok().unwrap().entry
        else {
            panic!("the own base's entry")
        };
        assert_eq!(epoch_id, epoch);
        let original = signer.own_base.initial_key_package().unwrap();
        assert_ne!(metadata_seal, original.metadata_seal());
        let mut metadata = None;
        signer
            .with_metadata_key(signer.base(), &mut |m| {
                metadata = Some(bh_crypto::committed_key_id(m))
            })
            .unwrap();
        // Both seals are fresh, to P′, and open under it to M and the
        // epoch's key.
        let m = SealHeader::decode(&metadata_seal).unwrap();
        let k = SealHeader::decode(&current_key_seal).unwrap();
        assert_eq!(m.purpose, BaseKeyPurpose::Metadata);
        assert_eq!(k.purpose, BaseKeyPurpose::Content);
        assert_eq!(Some(m.key_id), metadata);
        assert_eq!(k.key_id, epoch);
        for header in [m, k] {
            assert_eq!(header.recipient, bh_crypto::hash(&rotated));
        }
        let (m_id, k_id) = f
            .host
            .run_lent(f.id, &f.cap, move |owner, cap| {
                Box::pin(async move {
                    let personal = owner.open_current_personal(&cap).await.unwrap();
                    let at = owner.verified_at(&cap, m.head.position).unwrap();
                    let open = |header, seal| {
                        bh_crypto::committed_key_id(
                            &open_seal(&at, header, seal, &personal).unwrap(),
                        )
                    };
                    (open(&m, &metadata_seal), open(&k, &current_key_seal))
                })
            })
            .await
            .unwrap();
        assert_eq!(Some(m_id), metadata);
        assert_eq!(k_id, epoch);
    }

    /// The own base's genesis content key id, from its key package.
    fn genesis_epoch<S, P>(signer: &HostSigner<S, P>) -> [u8; 32]
    where
        S: HostKeyStore,
        P: PendingSetupProtector + Clone + Send + Sync + 'static,
    {
        let package = signer.own_base.initial_key_package().unwrap();
        bh_device::base_keys::SealHeader::decode(package.content_seal())
            .unwrap()
            .key_id
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_epoch_has_only_its_own_key_and_m_never_waits_for_one() {
        let f = fixture(FakeStore::default()).await;
        let signer = HostSigner::start(f.host.clone(), f.id).await.unwrap();
        let base = signer.base();
        let genesis = genesis_epoch(&signer);
        let mut metadata = None;
        signer
            .with_metadata_key(base, &mut |m| {
                metadata = Some(bh_crypto::committed_key_id(m))
            })
            .unwrap();
        assert!(metadata.is_some());
        let held = |epoch| {
            let mut held = None;
            signer
                .with_epoch_keys(base, epoch, &mut |m, k| {
                    held = Some((
                        bh_crypto::committed_key_id(m),
                        k.map(bh_crypto::committed_key_id),
                    ))
                })
                .unwrap();
            held.unwrap()
        };
        assert_eq!(held(Some(genesis)), (metadata.unwrap(), Some(genesis)));
        // Nothing stands in for an epoch whose key is not held, or a closed
        // one: M alone, never another epoch's key.
        assert_eq!(held(Some([9; 32])), (metadata.unwrap(), None));
        assert_eq!(held(None), (metadata.unwrap(), None));
        // Bytes that are not the set a durable wait names install nothing,
        // and another base's wait is refused outright.
        let wait = SealWait {
            base: base.0,
            key_id: [8; 32],
            position: 5,
            event_id: [6; 32],
            count: 1,
            commitment: [4; 32],
        };
        assert_eq!(
            signer.install_epoch(wait, vec![0; 4096]).await,
            Err(InstallError::Invalid)
        );
        assert_eq!(
            signer
                .install_epoch(
                    SealWait {
                        base: [7; 32],
                        ..wait
                    },
                    vec![0; 4096]
                )
                .await,
            Err(InstallError::Invalid)
        );
        assert_eq!(held(Some([8; 32])), (metadata.unwrap(), None));
    }

    /// Real account erasure consumes the owner's routes before the UI callback.
    /// An erased or incomplete screen must be in place when exactly those
    /// formerly bound note windows are asked to reload; another account stays open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_erasure_reloads_only_removed_account_windows_after_final_screen() {
        use crate::accounts::{Screen, two_ready_test_host};
        use std::sync::atomic::Ordering;

        type Reload = (ContainerId, Vec<String>, Option<Screen>);
        struct Ended {
            host: Host,
            calls: std::sync::Mutex<Vec<Reload>>,
        }
        impl StatusWindows for Ended {
            fn post_status(&self, _: ContainerId, _: &StatusView) {}
            fn wake_delivery(&self, _: String) {}
            fn authority_ended(&self, id: ContainerId, mut labels: Vec<String>) {
                labels.sort();
                self.calls
                    .lock()
                    .unwrap()
                    .push((id, labels, self.host.screen()));
            }
        }

        for (fail_erase, final_screen) in [
            (false, Screen::Erased { unsent: 0 }),
            (true, Screen::EraseIncomplete { failed: 1 }),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let owner = Arc::new(bh_device::Owner::default());
            let store = FakeStore::default();
            let (host, [removed, other]) =
                two_ready_test_host(&owner, dir.path(), store.clone()).await;
            for id in [removed, other] {
                let ready = host.ready_parts(id).unwrap();
                owner
                    .authorize(id, ready.capability, ready.own_base.id().0)
                    .unwrap();
            }
            owner.open_home("removed-note", removed).unwrap();
            owner.open_home("removed-second-note", removed).unwrap();
            owner.open_home("other-note", other).unwrap();
            store.fail_erase.store(fail_erase, Ordering::SeqCst);
            let seen = Ended {
                host: host.clone(),
                calls: Default::default(),
            };
            let sync = SyncHost::new(Configured::Missing, owner.clone());
            sync.set_erase({
                let host = host.clone();
                Arc::new(move |id| {
                    let host = host.clone();
                    Box::pin(async move {
                        let _ = host.erase_removed(id).await;
                    })
                })
            });
            let cap = host.ready_parts(removed).unwrap().capability;
            sync.after_removal(removed, &cap, &seen).await;
            assert_eq!(host.screen(), Some(final_screen.clone()));
            assert_eq!(
                *seen.calls.lock().unwrap(),
                vec![(
                    removed,
                    vec!["removed-note".into(), "removed-second-note".into()],
                    Some(final_screen),
                )]
            );
            assert_eq!(owner.bound_container("removed-note"), None);
            assert_eq!(owner.bound_container("removed-second-note"), None);
            assert_eq!(owner.bound_container("other-note"), Some(other));
            assert!(
                owner
                    .open_leased("other-note", owner.bound_note("other-note").unwrap())
                    .is_ok()
            );
        }
    }

    /// A lock racing the account follow advances the owner's generation
    /// between its apply and its re-check, so the signer reports Removed
    /// with nothing removed. That notice may stop the client; only the
    /// client's verified removal verdict may erase.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lock_racing_an_account_apply_erases_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Default)]
        struct Ended(
            std::sync::Mutex<Vec<ContainerId>>,
            std::sync::Mutex<Vec<String>>,
        );
        impl StatusWindows for Ended {
            fn post_status(&self, _: ContainerId, view: &StatusView) {
                self.1.lock().unwrap().push(view.account.to_owned());
            }
            fn wake_delivery(&self, _: String) {}
            fn authority_ended(&self, container: ContainerId, _: Vec<String>) {
                self.0.lock().unwrap().push(container);
            }
        }
        async fn until(what: &str, mut done: impl FnMut() -> bool) {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            while !done() {
                assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        let store = FakeStore::default();
        let f = completed(store.clone()).await;
        let id = f.id;
        let signer = HostSigner::start(f.host.clone(), id).await.unwrap();
        let sync = SyncHost::new(Configured::Missing, f.owner.clone());
        let erasures = Arc::new(AtomicUsize::new(0));
        sync.set_erase({
            let (host, erasures) = (f.host.clone(), erasures.clone());
            Arc::new(move |removed| {
                let (host, erasures) = (host.clone(), erasures.clone());
                Box::pin(async move {
                    erasures.fetch_add(1, Ordering::SeqCst);
                    let _ = host.erase_removed(removed).await;
                })
            })
        });
        let (_status, status) = watch::channel(SyncStatus::Synced);
        let (_home, home) = watch::channel(HomeStatus::Done);
        let (verdict, removal) = watch::channel(bh_sync_client::RemovalVerdict::Active);
        let windows = Arc::new(Ended::default());
        let reported = tokio::spawn(report(
            Arc::downgrade(&sync.0),
            id,
            f.cap.clone(),
            status,
            home,
            signer.notices(),
            removal,
            windows.clone(),
        ));
        // The lock stops the account while its follow applies; the apply's
        // re-check then finds the owner stale and reports the account gone.
        f.host.lock().stop_accounts();
        signer.set_account(AccountState::Removed);
        until("the notice reported", || {
            windows.1.lock().unwrap().iter().any(|a| a == "removed")
        })
        .await;
        // The check the host asked for reads public evidence that removes
        // nothing.
        verdict.send_replace(bh_sync_client::RemovalVerdict::Active);
        tokio::time::timeout(std::time::Duration::from_secs(20), reported)
            .await
            .expect("report ended")
            .unwrap();
        until("windows ended", || windows.0.lock().unwrap().contains(&id)).await;
        assert_eq!(erasures.load(Ordering::SeqCst), 0, "no erasure was asked");
        assert!(!store.keys.lock().unwrap().is_empty(), "keys kept");
        let database = std::fs::read_dir(f._dir.path().join("accounts"))
            .unwrap()
            .any(|e| e.unwrap().path().extension().is_some_and(|x| x == "sqlite"));
        assert!(database, "database kept");
        assert!(
            !matches!(
                f.host.screen(),
                Some(
                    crate::accounts::Screen::Erased { .. }
                        | crate::accounts::Screen::EraseIncomplete { .. }
                )
            ),
            "no erasure screen"
        );
    }
}
