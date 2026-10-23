//! Accounts on this device: the registry of account containers and their
//! one native account owner each, first-device signup and its kit, startup,
//! joining by QR, and lending a ready account's owner to native work.
//!
//! The app's windows bind to this through thin commands; headless tests call
//! the same operations. Pages never supply a container, path, key or account.
//!
//! The native container owner owns files. `ContainerOwner` keeps the app's
//! real, file-locked owner behind a narrow testable adapter.
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use bh_account::{
    DeviceId, VerifiedAccount,
    journal::PendingSetupProtector,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner, SetupError},
    platform::{ControlKeyPolicy, DeviceKeyStore},
    recovery::{Password, RecoveryCode},
    storage::DeviceJournal,
};
use bh_device::{ContainerId, OwnerError};
use bh_storage::{DeviceDatabase, OpenError};
use serde::Serialize;

/// What the account host needs from its platform key store besides the
/// account owner's own use of it.
pub trait HostKeyStore: DeviceKeyStore + Clone + Send + Sync + 'static {
    /// The control policy this platform asks for when a device joins by QR.
    const JOIN_POLICY: ControlKeyPolicy;
    /// The process's action gate for a store whose control confirmation the
    /// app enforces (`crate::confirm`): one confirmation of a pairing
    /// addition also covers its one copy. `None` where the platform binds
    /// the key to its own per-use authentication.
    fn action_gate(&self) -> Option<crate::confirm::ActionGate> {
        None
    }
    /// A fresh owner confirmation that signs nothing, on a store with a gate.
    fn confirm_owner(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), bh_account::platform::KeyStoreError>> {
        async { Err(bh_account::platform::KeyStoreError::Unavailable) }
    }
    /// Delete every native item of this device's keys. Removing an already
    /// absent item succeeds, so a resumed erasure is idempotent; a store that
    /// cannot delete says so instead of pretending the keys are gone.
    fn erase_keys(
        &mut self,
        _handle: bh_account::platform::KeyHandle,
    ) -> impl std::future::Future<Output = Result<(), bh_account::platform::KeyStoreError>> {
        async { Err(bh_account::platform::KeyStoreError::Unavailable) }
    }
}

/// Per-account container files belong to their owner. Never open a container
/// with `DeviceDatabase::open` outside this owner in app code; it holds the
/// OS-exclusive file lock taken before SQLite opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenIssue {
    Busy,
    NewerData,
    Corrupt,
}

type OpenedContainers = Vec<(String, Result<ContainerId, OwnerError>)>;

pub trait ContainerOwner: Send + Sync {
    fn create_container(&self, dir: &Path) -> Result<ContainerId, OwnerError>;
    fn open_containers(&self, dir: &Path) -> Result<OpenedContainers, OwnerError>;
    fn is_empty(&self, id: ContainerId) -> Result<bool, OwnerError>;
    fn shared_database(
        &self,
        id: ContainerId,
    ) -> Result<Arc<std::sync::Mutex<DeviceDatabase>>, OwnerError>;
    /// The single check-and-anchor point. A checked projection is bound to
    /// signed history here; the page never supplies one.
    fn anchor(&self, id: ContainerId, verified: &VerifiedAccount) -> Result<(), OwnerError>;
    /// End every window route and writer lease into `id`, so no further
    /// commit can be admitted before a frozen count. Returns the labels whose
    /// pages must reload.
    fn deauthorize(&self, id: ContainerId) -> Result<Vec<String>, OwnerError>;
    /// The stable filename stem of `id`, which its removal marker names.
    fn container_name(&self, id: ContainerId) -> Result<String, OwnerError>;
    /// Delete `id`'s database and sidecars after its authority ended.
    fn remove_container(&self, id: ContainerId) -> Result<(), OwnerError>;
    /// `id` holds a recovery that did not finish: the account it adopted
    /// from recovery (a join with no pairing hint) is not activated, or its
    /// own base's copy record is short of this device's addition. An
    /// activated one with no copy record, or none that reads, is finished.
    /// Its password and kit finish it (`Screen::Recover`).
    fn recovery_unfinished(&self, _id: ContainerId) -> bool {
        false
    }
}

/// Screen state only. No account id, container id, key handle or code leaves
/// here except the recovery code, which the person must save.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "screen", rename_all = "snake_case")]
pub enum Screen {
    /// No account here: join one from another device by QR, or recover it
    /// with its password and recovery kit (`AccountOperation::Recover`).
    Welcome,
    Return,
    Retry,
    Update,
    Kit {
        code: String,
    },
    Ready,
    Unavailable,
    /// Authenticated history contradicted this device's: the account
    /// stopped. Its verified state stays on this device.
    Stopped,
    /// This device is joining an account by QR; `ticket` follows it.
    Joining {
        ticket: String,
    },
    /// A verified removal erased the account on this device. `unsent` is the
    /// authoritative count frozen at the destructive step.
    Erased {
        unsent: u64,
    },
    /// Erasure stopped at a durable step; the marker stays and it resumes on
    /// the next start. `failed` is that step.
    EraseIncomplete {
        failed: u8,
    },
    /// A new recovery kit to save, after a password and kit change; the
    /// existing kit-save screen. Shown again on restart until saved.
    NewKit {
        code: String,
    },
    /// The removal a cancel named had already taken effect.
    CancelTookEffect,
    /// A recovery on this device did not finish: its password and kit
    /// finish it.
    Recover,
    /// The home did not open the account with this password and kit:
    /// `not_recognised` (no such kit; no try used), `password` (a try used;
    /// `tries_left`, and `next_try_ms` once none are left), `wait` (no try
    /// before `next_try_ms`) or `unreachable` (asking again resumes).
    RecoverRefused {
        reason: &'static str,
        tries_left: Option<u8>,
        next_try_ms: Option<u64>,
    },
    /// The account is open on this device: it was added and its notes
    /// downloaded.
    Recovered,
}

/// What a container holds, before any native key is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    Empty,
    /// Only a journaled scanner identity: a join that never got its hint.
    Scanner,
    /// A join with its hint or admission kept, not yet activated.
    Joining,
    Account,
    Unreadable,
}

fn held(database: &DeviceDatabase) -> Held {
    let (Ok(state), Ok(device), Ok(joined), Ok(pending)) = (
        database.account_state(),
        database.device_identity(),
        database.joined(),
        database.pending_setup(),
    ) else {
        return Held::Unreadable;
    };
    match (state, device, joined, pending) {
        (_, _, Some(joined), None) if !joined.activated => Held::Joining,
        (None, None, None, None) => Held::Empty,
        (None, Some(_), None, None) => Held::Scanner,
        _ => Held::Account,
    }
}

pub struct Session<C, S, P> {
    containers: C,
    directory: PathBuf,
    store: S,
    protector: P,
    classify_open_issue: fn(&OwnerError) -> OpenIssue,
    generations: HashMap<ContainerId, AccountGeneration>,
    capabilities: HashMap<ContainerId, Arc<AccountCapability>>,
    own_bases: HashMap<ContainerId, Arc<bh_device::own_base::OwnBase>>,
    opened: Option<Vec<(String, Result<ContainerId, OwnerError>)>>,
    retry_open: bool,
    screen: Option<Screen>,
    current: Option<(ContainerId, AccountOwner<DeviceJournal, S, P>)>,
    others: HashMap<ContainerId, AccountOwner<DeviceJournal, S, P>>,
    /// Ready accounts whose one owner is lent to a native worker. Their
    /// routing, capability and own base stay here meanwhile.
    lent: HashMap<ContainerId, Lent>,
    /// Marked erasures that could not finish on this start, by stable name.
    incomplete_erasures: HashMap<String, u8>,
    /// Accounts whose own verified history no longer holds this device
    /// active: its id and the last view in which it was a member, from which
    /// the public evidence of that removal is checked. No authority.
    removed: HashMap<ContainerId, (DeviceId, VerifiedAccount)>,
    /// What each account's directory holds, as far as this run knows.
    pub(crate) known: HashMap<ContainerId, crate::devices::Known>,
}

/// Where a lent owner returns, and whether its account stopped meanwhile.
struct Lent {
    current: bool,
    stopped: bool,
}

pub type Owner<S, P> = AccountOwner<DeviceJournal, S, P>;

impl<C, S, P> Session<C, S, P>
where
    C: ContainerOwner + Clone,
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    pub fn new(
        containers: C,
        directory: impl Into<PathBuf>,
        store: S,
        protector: P,
        classify_open_issue: fn(&OwnerError) -> OpenIssue,
    ) -> Self {
        Self {
            containers,
            directory: directory.into(),
            store,
            protector,
            classify_open_issue,
            generations: HashMap::new(),
            capabilities: HashMap::new(),
            own_bases: HashMap::new(),
            opened: None,
            retry_open: false,
            screen: None,
            current: None,
            others: HashMap::new(),
            lent: HashMap::new(),
            incomplete_erasures: HashMap::new(),
            removed: HashMap::new(),
            known: HashMap::new(),
        }
    }

    /// The routed account, whether or not its owner is lent right now.
    pub fn current_id(&self) -> Option<ContainerId> {
        self.current.as_ref().map(|(id, _)| *id).or_else(|| {
            self.lent
                .iter()
                .find_map(|(id, lent)| lent.current.then_some(*id))
        })
    }

    /// Lend Ready account `id`'s one owner to a native worker, leaving its
    /// routing, capability and own base in place.
    fn lend(&mut self, id: ContainerId) -> Option<Owner<S, P>> {
        if self.lent.contains_key(&id) || !self.capabilities.contains_key(&id) {
            return None;
        }
        let (owner, current) = if self.current.as_ref().is_some_and(|(c, _)| *c == id) {
            (self.current.take().expect("matched").1, true)
        } else {
            (self.others.remove(&id)?, false)
        };
        self.lent.insert(
            id,
            Lent {
                current,
                stopped: false,
            },
        );
        Some(owner)
    }

    /// Put a lent owner back where it was. One stopped meanwhile is locked
    /// and no longer routed.
    fn give_back(&mut self, id: ContainerId, mut owner: Owner<S, P>) {
        let Some(lent) = self.lent.remove(&id) else {
            let _ = owner.lock();
            return;
        };
        if lent.stopped {
            let _ = owner.lock();
            self.others.insert(id, owner);
        } else if lent.current && self.current.is_none() {
            self.current = Some((id, owner));
        } else {
            self.others.insert(id, owner);
        }
    }

    /// Move only the requested account into a native worker. All unrelated
    /// owners, capabilities and routes remain in the registry during its prompt.
    fn take_work(&mut self, id: Option<ContainerId>) -> Self {
        let mut work = Self::new(
            self.containers.clone(),
            self.directory.clone(),
            self.store.clone(),
            self.protector.clone(),
            self.classify_open_issue,
        );
        work.generations = self.generations.clone();
        if let Some(id) = id {
            work.opened = Some(vec![("account".into(), Ok(id))]);
            if self
                .current
                .as_ref()
                .is_some_and(|(current, _)| *current == id)
            {
                work.current = self.current.take();
                work.screen = self.screen.take();
            } else if let Some(owner) = self.others.remove(&id) {
                work.current = Some((id, owner));
            }
            if let Some(cap) = self.capabilities.remove(&id) {
                work.capabilities.insert(id, cap);
            }
            if let Some(base) = self.own_bases.remove(&id) {
                work.own_bases.insert(id, base);
            }
        } else {
            work.opened = self.opened.take();
            work.retry_open = self.retry_open;
            work.screen = self.screen.take();
        }
        work
    }
    fn restore_work(&mut self, mut work: Self) {
        self.generations.extend(work.generations);
        self.capabilities.extend(work.capabilities);
        self.own_bases.extend(work.own_bases);
        self.others.extend(work.others);
        self.removed.extend(work.removed);
        for (id, known) in work.known {
            let kept = self.known.entry(id).or_default();
            if known.check.is_some() {
                kept.check = known.check;
            }
        }
        if self.opened.is_none() {
            self.opened = work.opened.take();
        }
        // A current account out on a worker is still the routed one: its
        // screen stays, whatever another account's work ended on.
        let current_lent = self.lent.values().any(|lent| lent.current);
        if self.current.is_none() && !current_lent {
            self.current = work.current.take();
            self.screen = work.screen.take();
            self.retry_open = work.retry_open;
        } else if let Some((id, owner)) = work.current.take() {
            self.others.insert(id, owner);
        }
    }
    fn blank_hint(&self, id: ContainerId) -> Result<bool, OwnerError> {
        self.containers.is_empty(id)
    }

    fn owner(&mut self, id: ContainerId) -> Result<AccountOwner<DeviceJournal, S, P>, OwnerError> {
        let database = self.containers.shared_database(id)?;
        let generation = self.generations.entry(id).or_default().clone();
        Ok(AccountOwner::new(
            DeviceJournal::from_shared(database),
            self.store.clone(),
            self.protector.clone(),
            generation,
        ))
    }

    /// Resume on launch: open every container, resume any interrupted setup on
    /// the kit screen, otherwise activate and anchor. A container that cannot
    /// activate is left untouched and a retry is offered.
    pub async fn startup(&mut self) -> Screen {
        if let Some(screen) = self.cached_screen() {
            return screen;
        }
        if self.screen == Some(Screen::Ready) {
            // A cached screen is not current authority. Drop only this account's
            // stale roots/capability before retrying native activation.
            if let Some((id, _)) = &self.current {
                self.own_bases.remove(id);
                self.capabilities.remove(id);
            }
            self.screen = None;
        }
        // A second open on the same Owner reports its own live files Busy.
        // Retry the key prompt using the retained handles, not a new open.
        if self.opened.is_none()
            || (self.retry_open
                && self
                    .opened
                    .as_ref()
                    .is_some_and(|files| files.iter().all(|(_, r)| r.is_err())))
        {
            self.retry_open = false;
            self.opened = match self.containers.open_containers(&self.directory) {
                Ok(files) => Some(files),
                Err(_) => {
                    self.screen = Some(Screen::Retry);
                    return Screen::Retry;
                }
            };
        }
        // An interrupted erasure finishes before any account is offered. The
        // containers are open now, so a remaining file keeps its stable name.
        // A stuck one is recorded for its container only.
        let erased = self.resume_erasure().await;
        let mut retry = false;
        let mut busy = false;
        let mut newer = false;
        let mut corrupt = false;
        let mut stopped = false;
        let mut joining = false;
        let mut recovering = false;
        let mut ids = Vec::new();
        for (_, result) in self.opened.as_ref().expect("opened once") {
            match result {
                Ok(id) => ids.push(*id),
                Err(error) => match (self.classify_open_issue)(error) {
                    OpenIssue::Busy => busy = true,
                    OpenIssue::NewerData => newer = true,
                    OpenIssue::Corrupt => corrupt = true,
                },
            }
        }
        let mut pending = Vec::new();
        for id in ids {
            if matches!(self.blank_hint(id), Ok(true)) {
                continue;
            }
            // An unfinished recovery asks for its password and kit again;
            // it is not offered as an account before it finishes.
            if self.containers.recovery_unfinished(id) {
                recovering = true;
                continue;
            }
            // A join in progress resumes as a join; it is never activated
            // as a usable account before its bootstrap.
            let holds = self
                .containers
                .shared_database(id)
                .ok()
                .and_then(|db| db.lock().ok().map(|db| held(&db)));
            match holds {
                Some(Held::Joining) => {
                    joining = true;
                    continue;
                }
                Some(Held::Scanner) => continue,
                _ => {}
            }
            // Defer an unsaved setup without opening its native-protected code.
            // It cannot displace another available account.
            let saved = self
                .containers
                .shared_database(id)
                .ok()
                .and_then(|db| db.lock().ok().and_then(|db| db.pending_setup().ok()));
            match saved {
                Some(Some(record)) if !record.kit_saved => {
                    pending.push(id);
                    continue;
                }
                None => {
                    retry = true;
                    continue;
                }
                _ => {}
            }
            let mut owner = if self
                .current
                .as_ref()
                .is_some_and(|(current, _)| *current == id)
            {
                self.current.take().expect("matched").1
            } else {
                match self
                    .others
                    .remove(&id)
                    .map(Ok)
                    .unwrap_or_else(|| self.owner(id))
                {
                    Ok(owner) => owner,
                    Err(_) => {
                        retry = true;
                        continue;
                    }
                }
            };
            match owner.setup_status() {
                Ok(Some(status)) if status.kit_saved => {
                    if owner.confirm_kit_saved().is_err() {
                        self.others.insert(id, owner);
                        retry = true;
                        continue;
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    self.others.insert(id, owner);
                    retry = true;
                    continue;
                }
            }
            match activate(&self.containers, id, &mut owner).await {
                Ok(Some((capability, base))) => {
                    self.capabilities.insert(id, capability);
                    self.own_bases.insert(id, base);
                    self.remember_signup_check(id, &mut owner);
                    // A changed kit not saved yet is shown again until it is.
                    let screen = match owner.staged_kit_code() {
                        Ok(Some(code)) => Screen::NewKit {
                            code: code.to_kit_text(),
                        },
                        _ => Screen::Ready,
                    };
                    self.current = Some((id, owner));
                    self.screen = Some(screen.clone());
                    return screen;
                }
                Ok(_) => {
                    corrupt = true;
                    if let Ok(Some(member)) = owner.last_member_view() {
                        self.removed.insert(id, member);
                    }
                }
                Err(bh_account::owner::OwnerError::Stopped) => stopped = true,
                Err(_) => retry = true,
            }
            self.others.insert(id, owner);
        }
        for id in pending {
            let mut owner = match self.owner(id) {
                Ok(owner) => owner,
                Err(_) => {
                    retry = true;
                    continue;
                }
            };
            match owner.pending_kit_code() {
                Ok(code) => {
                    let screen = Screen::Kit {
                        code: code.to_kit_text(),
                    };
                    self.current = Some((id, owner));
                    self.screen = Some(screen.clone());
                    return screen;
                }
                Err(_) => {
                    self.others.insert(id, owner);
                    retry = true;
                }
            }
        }
        if let Some(screen) = erased {
            self.keep_screen(screen)
        } else if !self.incomplete_erasures.is_empty() {
            let step = self
                .incomplete_erasures
                .values()
                .copied()
                .min()
                .unwrap_or(0);
            self.keep_screen(Screen::EraseIncomplete { failed: step })
        } else if newer {
            Screen::Update
        } else if joining {
            Screen::Joining {
                ticket: String::new(),
            }
        } else if recovering {
            Screen::Recover
        } else if stopped {
            Screen::Stopped
        } else if retry || busy {
            self.retry_open = true;
            self.screen = Some(Screen::Retry);
            Screen::Retry
        } else if corrupt {
            Screen::Return
        } else {
            self.screen = Some(Screen::Welcome);
            Screen::Welcome
        }
    }

    /// Only an explicit user action releases a failed unlock's retry gate.
    pub async fn retry(&mut self) -> Screen {
        if self.screen == Some(Screen::Retry) {
            self.screen = None;
        }
        self.startup().await
    }

    /// Create one account. A retry never starts a second genesis: the pending
    /// setup in the existing container is resumed instead.
    pub async fn create(&mut self, password: &str) -> Screen {
        // A container already in setup resumes rather than duplicating an account.
        let startup = self.startup().await;
        if self.opened.is_none() {
            return Screen::Unavailable;
        }
        match startup {
            Screen::Kit { code } => return Screen::Kit { code },
            Screen::Ready => return Screen::Ready,
            Screen::Welcome => {}
            other => return other,
        }
        let Some(files) = &self.opened else {
            return Screen::Unavailable;
        };
        // A transient activation failure, orphan identity or unopenable file
        // must never turn this install into a second personal account.
        let mut reusable = None;
        for (_, result) in files {
            let Ok(id) = result else { return Screen::Retry };
            match self.containers.is_empty(*id) {
                Ok(true) => {
                    reusable = Some(*id);
                }
                Ok(false) | Err(_) => return Screen::Retry,
            }
        }
        let Ok(password) = Password::new(password) else {
            return Screen::Unavailable;
        };
        let id = match reusable.or_else(|| self.containers.create_container(&self.directory).ok()) {
            Some(id) => id,
            None => return Screen::Unavailable,
        };
        if reusable.is_none() {
            self.opened
                .as_mut()
                .expect("startup called")
                .push(("new".into(), Ok(id)));
        }
        let mut owner = match self.owner(id) {
            Ok(owner) => owner,
            Err(_) => return Screen::Unavailable,
        };
        match owner
            .begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password)
            .await
        {
            Ok(_) => {}
            Err(SetupError::AlreadyStarted) => {}
            Err(_) => return Screen::Unavailable,
        }
        let Ok(code) = owner.pending_kit_code() else {
            return Screen::Unavailable;
        };
        self.current = Some((id, owner));
        let screen = Screen::Kit {
            code: code.to_kit_text(),
        };
        self.screen = Some(screen.clone());
        screen
    }

    /// Stop every account generation while holding its own database mutex.
    /// A slow unrelated account never shares the lock used by another.
    pub fn stop(&mut self) {
        if let Some((_, mut owner)) = self.current.take() {
            let _ = owner.lock();
        }
        for (_, mut owner) in self.others.drain() {
            let _ = owner.lock();
        }
        // A lent owner is fenced as its own lock would: the generation
        // advances under its container's writer guard. It locks on return.
        for (id, lent) in self.lent.iter_mut() {
            lent.stopped = true;
            lent.current = false;
            if let (Some(generation), Ok(database)) = (
                self.generations.get(id),
                self.containers.shared_database(*id),
            ) {
                let _guard = database
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                generation.advance();
            }
        }
        self.capabilities.clear();
        self.own_bases.clear();
        self.removed.clear();
        self.screen = None;
    }

    /// Erase an account whose removal was independently verified. The caller
    /// stops the account's client first, so this count is the frozen truth at
    /// the destructive step. A durable marker beside the container (never
    /// inside the data being removed) records the unsent count, the retained
    /// key handle and the step reached, so an interrupted erasure resumes.
    pub async fn erase_removed(&mut self, id: ContainerId) -> Screen {
        let name = match self.containers.container_name(id) {
            Ok(name) => name,
            Err(_) => return self.keep_screen(Screen::EraseIncomplete { failed: 0 }),
        };
        self.stop_account(id);
        // End routes and writer leases before the count, so no commit admitted
        // by an editor can be deleted uncounted.
        if self.containers.deauthorize(id).is_err() {
            return self.keep_screen(Screen::EraseIncomplete { failed: 0 });
        }
        let (unsent, identity) = {
            let Ok(database) = self.containers.shared_database(id) else {
                return self.keep_screen(Screen::EraseIncomplete { failed: 0 });
            };
            let Ok(database) = database.lock() else {
                return self.keep_screen(Screen::EraseIncomplete { failed: 0 });
            };
            match (database.unsent_count(), database.device_identity()) {
                (Ok(unsent), Ok(identity)) => (unsent, identity),
                // A failed read is not proof that the keys are absent.
                _ => return self.keep_screen(Screen::EraseIncomplete { failed: 0 }),
            }
        };
        let handle = identity.map(|record| bh_account::platform::KeyHandle(record.handle));
        let erasing = Erasing {
            unsent,
            step: 0,
            handle,
        };
        if write_marker(&self.directory, &name, erasing.clone()).is_err() {
            return self.keep_screen(Screen::EraseIncomplete { failed: 0 });
        }
        let screen = match self.run_erasure(&name, Some(id), erasing).await {
            Ok(()) => Screen::Erased { unsent },
            Err(step) => Screen::EraseIncomplete { failed: step },
        };
        self.keep_screen(screen)
    }

    /// Keep the final screen for `screen()`, including when no account is
    /// current any more.
    fn keep_screen(&mut self, screen: Screen) -> Screen {
        self.screen = Some(screen.clone());
        screen
    }

    /// Forget this start's record of a container whose files were removed.
    fn forget_container(&mut self, id: ContainerId) {
        if let Some(files) = self.opened.as_mut() {
            files.retain(|(_, opened)| opened.as_ref().ok() != Some(&id));
            // An empty enumeration is not an open directory: the next start
            // must find the accounts that remain.
            if files.is_empty() {
                self.opened = None;
            }
        }
        self.generations.remove(&id);
        self.removed.remove(&id);
    }

    /// Stop this account's writers and drop its owners, capability, own base
    /// and routes. Unrelated accounts keep theirs.
    fn stop_account(&mut self, id: ContainerId) {
        if let Some((current, mut owner)) = self.current.take() {
            if current == id {
                let _ = owner.lock();
            } else {
                self.current = Some((current, owner));
            }
        }
        if let Some(mut owner) = self.others.remove(&id) {
            let _ = owner.lock();
        }
        if let (Some(generation), Ok(database)) = (
            self.generations.get(&id),
            self.containers.shared_database(id),
        ) {
            let _guard = database
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            generation.advance();
        }
        self.lent.remove(&id);
        self.capabilities.remove(&id);
        self.own_bases.remove(&id);
        if let Some(files) = self.opened.as_mut() {
            files.retain(|(_, opened)| opened.as_ref().ok() != Some(&id));
        }
        if self.current_id().is_none() {
            self.screen = None;
        }
    }

    /// Run erasure's durable steps in order. Each step records its progress
    /// in the marker, so a crash resumes rather than repeating trust.
    async fn run_erasure(
        &mut self,
        name: &str,
        id: Option<ContainerId>,
        mut erasing: Erasing,
    ) -> Result<(), u8> {
        if erasing.step < 1 {
            if let Some(handle) = erasing.handle.clone()
                && self.store.erase_keys(handle).await.is_err()
            {
                return Err(1);
            }
            erasing.step = 1;
            if write_marker(&self.directory, name, erasing.clone()).is_err() {
                return Err(1);
            }
        }
        if erasing.step < 2 {
            let removed = match id {
                Some(id) => self.containers.remove_container(id),
                // The container's file was already gone on this start.
                None => Ok(()),
            };
            if removed.is_err() {
                return Err(2);
            }
            erasing.step = 2;
            if write_marker(&self.directory, name, erasing.clone()).is_err() {
                return Err(2);
            }
        }
        self.generations.remove(&id.unwrap_or_default());
        if remove_marker(&self.directory, name).is_err() {
            return Err(2);
        }
        Ok(())
    }

    /// Finish any erasure a previous run left marked, before offering the
    /// account again. A marker's key handle is enough to resume even after
    /// the database is gone. One stuck erasure is recorded for its own
    /// container and never hides the other accounts.
    async fn resume_erasure(&mut self) -> Option<Screen> {
        let directory = self.directory.join("accounts");
        let files = match std::fs::read_dir(&directory) {
            Ok(entries) => entries
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .collect::<Vec<_>>(),
            Err(_) => return None,
        };
        // A crash before its rename leaves a marker's temp, never a marker.
        for temp in files.iter().filter(|name| name.ends_with(".erasing.tmp")) {
            let _ = std::fs::remove_file(directory.join(temp));
        }
        let names = files
            .iter()
            .filter_map(|name| name.strip_suffix(".erasing").map(str::to_owned))
            .collect::<Vec<_>>();
        let mut screen = None;
        for name in names {
            let id = self.opened.as_ref().and_then(|files| {
                files.iter().find_map(|(stem, opened)| {
                    (stem == &name)
                        .then(|| opened.as_ref().ok().copied())
                        .flatten()
                })
            });
            // A marked account is never offered again, whether or not its
            // erasure can finish on this start.
            if let Some(id) = id {
                self.stop_account(id);
            }
            // A verified intent has no frozen count or handle yet; like an
            // unreadable marker, it resumes only if both can be read from
            // the still-present database.
            let erasing = match read_marker(&self.directory, &name) {
                Some(erasing) => erasing,
                None => match id.and_then(|id| self.reread_erasing(id)) {
                    Some(erasing) => erasing,
                    None => {
                        self.incomplete_erasures.insert(name, 0);
                        continue;
                    }
                },
            };
            if id.is_none() && directory.join(format!("{name}.sqlite")).exists() {
                // Its file is present but this start could not open it.
                self.incomplete_erasures.insert(name, erasing.step.max(2));
                continue;
            }
            if let Some(id) = id
                && self.containers.deauthorize(id).is_err()
            {
                self.incomplete_erasures.insert(name, 0);
                continue;
            }
            let unsent = erasing.unsent;
            match self.run_erasure(&name, id, erasing).await {
                Ok(()) => {
                    self.incomplete_erasures.remove(&name);
                    screen = Some(Screen::Erased { unsent });
                }
                Err(failed) => {
                    self.incomplete_erasures.insert(name, failed);
                }
            }
        }
        screen
    }

    /// An erasure's starting record, read again from its still-present
    /// database. Any failed read is `None`, never an absent key handle.
    fn reread_erasing(&self, id: ContainerId) -> Option<Erasing> {
        let database = self.containers.shared_database(id).ok()?;
        let database = database.lock().ok()?;
        let unsent = database.unsent_count().ok()?;
        let identity = database.device_identity().ok()?;
        Some(Erasing {
            unsent,
            step: 0,
            handle: identity.map(|record| bh_account::platform::KeyHandle(record.handle)),
        })
    }

    /// The code the person must keep while setup is incomplete.
    pub fn pending_code(&mut self) -> Option<RecoveryCode> {
        self.current
            .as_mut()
            .and_then(|(_, owner)| owner.pending_kit_code().ok())
    }

    /// Explicit saved-kit confirmation, then local use of the account. The
    /// code and recovery private material are forgotten here (the protector
    /// retires its per-setup wrapping key first).
    pub async fn confirm_kit(&mut self) -> Screen {
        let Some((id, mut owner)) = self.current.take() else {
            return Screen::Unavailable;
        };
        // Completion can durably retire the code even when a later step fails.
        self.screen = None;
        if owner.confirm_kit_saved().is_err() {
            self.current = Some((id, owner));
            return Screen::Unavailable;
        }
        let screen = match activate(&self.containers, id, &mut owner).await {
            Ok(Some((capability, base))) => {
                self.capabilities.insert(id, capability);
                self.own_bases.insert(id, base);
                self.remember_signup_check(id, &mut owner);
                Screen::Ready
            }
            Ok(_) => Screen::Return,
            Err(_) => Screen::Retry,
        };
        self.current = Some((id, owner));
        // A failed activation is retried from durable setup state only when
        // the person presses Try again; passive refresh must not re-prompt.
        self.screen = matches!(screen, Screen::Ready | Screen::Retry).then(|| screen.clone());
        screen
    }

    /// Signup's password check, while its pending setup still holds it. The
    /// setup is cleared once the home orders it, before the directory can
    /// take the check, so from here until that write it is kept in memory.
    fn remember_signup_check(&mut self, id: ContainerId, owner: &mut Owner<S, P>) {
        if let Ok(Some((check, record_digest))) = owner.pending_password_check() {
            self.known.entry(id).or_default().check = Some(crate::devices::HeldCheck {
                check,
                record_digest,
                not_under: None,
            });
        }
    }

    /// Shared by the native IPC fast path and the worker. Cached Ready is only
    /// usable while both the account capability and scoped base keys are live.
    fn cached_screen(&self) -> Option<Screen> {
        let screen = self.screen.as_ref()?;
        (*screen != Screen::Ready || self.bound_container().is_some()).then(|| screen.clone())
    }

    /// The container this window's note should bind to, once native account
    /// authority holds. Native routing only; never a page-supplied value.
    pub fn bound_container(&self) -> Option<ContainerId> {
        if self.screen != Some(Screen::Ready) {
            return None;
        }
        let id = self.current_id()?;
        // Live base authority, not a content key: notes stay usable while a
        // new epoch's key is pending or the epoch is closed.
        self.own_bases.get(&id)?.with_metadata_key(|_| ()).ok()?;
        self.capabilities
            .get(&id)
            .filter(|cap| cap.is_current())
            .map(|_| id)
    }

    /// What the device owner needs to authorize notes: the routed container,
    /// its current capability and the verified own base. Native only.
    pub fn note_authority(&self) -> Option<NoteAuthority> {
        let id = self.bound_container()?;
        let base = self.own_bases.get(&id)?.id().0;
        Some((id, Arc::clone(self.capabilities.get(&id)?), base))
    }

    /// Native-only verified session. Never serialize the capability or key.
    pub fn verified_session(&self) -> Option<(&AccountCapability, &VerifiedAccount)> {
        let id = self.bound_container()?;
        let capability = self.capabilities.get(&id)?;
        let owner = &self.current.as_ref()?.1;
        Some((capability, owner.verified(capability).ok()?))
    }
}

/// Durable progress of one account's erasure: its frozen unsent count, the
/// step reached, and the retained native key handle needed after its database
/// is gone. Written beside the container, never inside the data it removes.
#[derive(Clone)]
struct Erasing {
    unsent: u64,
    step: u8,
    handle: Option<bh_account::platform::KeyHandle>,
}

fn marker_path(directory: &Path, name: &str) -> PathBuf {
    directory.join("accounts").join(format!("{name}.erasing"))
}

/// Write and fsync the marker and its directory before the destructive step
/// it authorizes. An existing marker is replaced in place.
fn write_marker(directory: &Path, name: &str, erasing: Erasing) -> std::io::Result<()> {
    let handle = erasing.handle.map_or_else(String::new, |handle| {
        handle.0.iter().map(|byte| format!("{byte:02x}")).collect()
    });
    let body = format!(
        "unsent {}\nstep {}\nhandle {}\n",
        erasing.unsent, erasing.step, handle
    );
    write_marker_body(directory, name, &body)
}

/// A verified removal may wait for a native worker. Its unsent count and key
/// handle cannot be frozen until that owner returns; startup rereads both
/// from the still-present database before doing any destructive work.
fn write_erase_intent(directory: &Path, name: &str) -> std::io::Result<()> {
    write_marker_body(directory, name, "verified\n")
}

fn write_marker_body(directory: &Path, name: &str, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    let path = marker_path(directory, name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Temp + fsync + rename: a crash mid-update leaves the previous marker
    // intact, never a truncated one.
    let temp = path.with_extension("erasing.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, &path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn read_marker(directory: &Path, name: &str) -> Option<Erasing> {
    let body = std::fs::read_to_string(marker_path(directory, name)).ok()?;
    let mut unsent = None;
    let mut step = None;
    let mut handle = None;
    for line in body.lines() {
        if let Some(value) = line.strip_prefix("unsent ") {
            unsent = value.parse().ok();
        } else if let Some(value) = line.strip_prefix("step ") {
            step = value.parse().ok();
        } else if let Some(value) = line.strip_prefix("handle ") {
            if value.len() == 64 {
                let mut bytes = [0u8; 32];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
                }
                handle = Some(bh_account::platform::KeyHandle(bytes));
            } else if !value.is_empty() {
                return None;
            }
        }
    }
    Some(Erasing {
        unsent: unsent?,
        step: step?,
        handle,
    })
}

fn remove_marker(directory: &Path, name: &str) -> std::io::Result<()> {
    let path = marker_path(directory, name);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

type ReadyAccount = (Arc<AccountCapability>, Arc<bh_device::own_base::OwnBase>);
pub type NoteAuthority = (ContainerId, Arc<AccountCapability>, [u8; 32]);

/// Establish the real signup base before publishing native readiness or anchoring
/// the container. Admission outcomes remain distinct from retryable failures.
async fn activate<C, S, P>(
    containers: &C,
    id: ContainerId,
    owner: &mut AccountOwner<DeviceJournal, S, P>,
) -> Result<Option<ReadyAccount>, bh_account::owner::OwnerError>
where
    C: ContainerOwner,
    S: HostKeyStore,
    P: PendingSetupProtector,
{
    use bh_account::{journal::JournalError, owner::OwnerError as AccountError};
    let capability = match owner.activate().await? {
        AccountLoad::Active(capability) => capability,
        // A latched stop is shown as such, never as a lost account.
        AccountLoad::Stopped => return Err(AccountError::Stopped),
        _ => return Ok(None),
    };
    let capability = Arc::new(capability);
    let database = containers
        .shared_database(id)
        .map_err(|_| AccountError::Journal(JournalError::Storage))?;
    let base = bh_device::own_base::create_or_open(owner, capability.clone(), database)
        .await
        .map_err(|e| match e {
            bh_device::own_base::OwnBaseError::Account(e) => e,
            bh_device::own_base::OwnBaseError::Stale => AccountError::Stale,
            bh_device::own_base::OwnBaseError::Storage => {
                AccountError::Journal(JournalError::Storage)
            }
            _ => AccountError::Journal(JournalError::Corrupt),
        })?;
    let verified = owner.verified(&capability)?;
    containers
        .anchor(id, verified)
        .map_err(|_| AccountError::Journal(JournalError::Storage))?;
    owner.verified(&capability)?;
    Ok(Some((capability, Arc::new(base))))
}

/// Real native container owner; the same shared database retains its file lock
/// across the journal and future note coordinator lifetimes.
#[derive(Clone)]
pub struct Containers {
    owner: Arc<bh_device::Owner>,
}

impl ContainerOwner for Containers {
    fn create_container(&self, dir: &Path) -> Result<ContainerId, OwnerError> {
        self.owner.create_container(dir)
    }
    fn open_containers(&self, dir: &Path) -> Result<OpenedContainers, OwnerError> {
        self.owner.open_containers(dir)
    }
    fn is_empty(&self, id: ContainerId) -> Result<bool, OwnerError> {
        self.owner.is_empty(id)
    }
    fn shared_database(
        &self,
        id: ContainerId,
    ) -> Result<Arc<std::sync::Mutex<DeviceDatabase>>, OwnerError> {
        self.owner.shared_database(id)
    }
    fn anchor(&self, id: ContainerId, verified: &VerifiedAccount) -> Result<(), OwnerError> {
        self.owner.anchor(id, verified)
    }
    fn deauthorize(&self, id: ContainerId) -> Result<Vec<String>, OwnerError> {
        self.owner.deauthorize(id)
    }
    fn container_name(&self, id: ContainerId) -> Result<String, OwnerError> {
        self.owner.container_name(id)
    }
    fn remove_container(&self, id: ContainerId) -> Result<(), OwnerError> {
        self.owner.remove_container(id)
    }
    fn recovery_unfinished(&self, id: ContainerId) -> bool {
        use bh_sync::permit::{LogId, LogKind};
        let Ok(Some(joined)) = self.owner.joined(id) else {
            return false;
        };
        if !joined.hint.is_empty() {
            return false;
        }
        if !joined.activated {
            return true;
        }
        let base = self
            .owner
            .shared_database(id)
            .ok()
            .and_then(|db| db.lock().ok()?.own_base().ok().flatten());
        let (Some(added_at), Some(base)) = (joined.added_at, base) else {
            return false;
        };
        let log = LogId {
            kind: LogKind::Base,
            id: base.base,
        };
        // Only a copy record short of the addition is evidence: with none,
        // or a read that fails, the account opens as it is.
        self.owner
            .verified_copy(id, log)
            .ok()
            .flatten()
            .is_some_and(|copy| copy.account.0 < added_at)
    }
}

pub struct AccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    session: Option<Session<Containers, S, P>>,
    suggested: Option<String>,
    in_flight: std::collections::HashSet<Option<ContainerId>>,
    /// Committed joins still owned by their bootstrap until ready or suspended.
    bootstrapping: std::collections::HashSet<ContainerId>,
    /// This device's model name, as the app gives it ("MacBook Pro"): the
    /// name it writes for itself in each account's directory.
    model: Option<String>,
}

impl<S, P> AccountHost<S, P>
where
    S: HostKeyStore + Clone + Default,
    P: PendingSetupProtector + Clone + Default,
{
    /// Accounts under `directory`, or none yet (`None`): without a durable
    /// home no identity is created in a temporary place.
    pub fn new(owner: Arc<bh_device::Owner>, directory: Option<PathBuf>) -> Self {
        Self {
            session: directory.map(|directory| real_session(owner, directory)),
            suggested: None,
            in_flight: std::collections::HashSet::new(),
            bootstrapping: std::collections::HashSet::new(),
            model: None,
        }
    }
    /// Attach the accounts directory once it is known (Android resolves it
    /// at app setup).
    pub fn attach_directory(&mut self, owner: Arc<bh_device::Owner>, directory: PathBuf) {
        if self.session.is_none() {
            self.session = Some(real_session(owner, directory));
        }
    }
}

// One store per process: its clones share any action gate it holds.
fn real_session<S, P>(owner: Arc<bh_device::Owner>, directory: PathBuf) -> Session<Containers, S, P>
where
    S: HostKeyStore + Clone + Default,
    P: PendingSetupProtector + Clone + Default,
{
    Session::new(
        Containers { owner },
        directory,
        S::default(),
        P::default(),
        classify_owner_error,
    )
}

impl<S, P> Drop for AccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    fn drop(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.stop();
        }
    }
}

impl<S, P> AccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    pub fn into_state(self) -> SharedAccountHost<S, P> {
        SharedAccountHost(Arc::new(Registry {
            host: std::sync::Mutex::new(self),
            returned: tokio::sync::Notify::new(),
            alerts: tokio::sync::watch::channel(Vec::new()).0,
            directory: tokio::sync::Notify::new(),
        }))
    }
}

/// How a container that did not open is shown: busy and retryable, newer
/// data, or unreadable.
pub fn classify_owner_error(error: &OwnerError) -> OpenIssue {
    match error {
        OwnerError::Busy
        | OwnerError::NoteUnavailable
        | OwnerError::Store(bh_storage::StoreError::NoteUnavailable)
        | OwnerError::Open(OpenError::Busy)
        | OwnerError::Io(_)
        | OwnerError::Open(OpenError::LockFile(_)) => OpenIssue::Busy,
        OwnerError::Open(OpenError::NewerData { .. }) => OpenIssue::NewerData,
        _ => OpenIssue::Corrupt,
    }
}

/// The account registry: a short, synchronous lock. A guard is never held
/// across an await (it is not `Send`, so a command future holding one does
/// not compile), a prompt or the network.
pub struct SharedAccountHost<S, P>(Arc<Registry<S, P>>)
where
    S: HostKeyStore + Clone,
    P: PendingSetupProtector + Clone;

pub struct Registry<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    host: std::sync::Mutex<AccountHost<S, P>>,
    /// Woken whenever a lent owner returns to the registry.
    returned: tokio::sync::Notify,
    /// Every alert delivered in this run, newest first.
    alerts: tokio::sync::watch::Sender<Vec<crate::devices::DeliveredAlert>>,
    /// Woken whenever a directory read finished.
    directory: tokio::sync::Notify,
}

impl<S, P> Clone for SharedAccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S, P> SharedAccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    pub fn lock(&self) -> std::sync::MutexGuard<'_, AccountHost<S, P>> {
        self.0
            .host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// The same short lock, for setup code that runs outside any executor.
    pub fn blocking_lock(&self) -> std::sync::MutexGuard<'_, AccountHost<S, P>> {
        self.lock()
    }
}

/// What a ready account's signer is built from. Native only.
pub struct ReadyParts<S> {
    pub capability: Arc<AccountCapability>,
    pub own_base: Arc<bh_device::own_base::OwnBase>,
    pub generation: AccountGeneration,
    pub database: Arc<std::sync::Mutex<DeviceDatabase>>,
    pub store: S,
}

impl<S, P> AccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    /// Lock every account, lent ones included (fenced at once, locked on
    /// return), as at quit.
    pub fn stop_accounts(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.stop();
        }
    }
}

impl<S, P> SharedAccountHost<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    /// The screen this registry now shows, if it has one. A verified erasure
    /// leaves `Erased` or, when a step failed, `EraseIncomplete`.
    pub fn screen(&self) -> Option<Screen> {
        self.lock().session.as_ref()?.screen.clone()
    }

    /// This device's model name ("MacBook Pro", "Pixel 10 Pro Fold"), from
    /// the app: written once as this device's name in each account's
    /// directory. No hostname and no rename in this build.
    pub fn set_device_model(&self, model: impl Into<String>) {
        self.lock().model = Some(model.into());
    }

    /// Security alerts as they are delivered: every one delivered in this
    /// run, newest first, each with a container-local `id`. An alert is delivered
    /// once, across restarts; while nobody watches, none is marked shown.
    pub fn alerts(&self) -> tokio::sync::watch::Receiver<Vec<crate::devices::DeliveredAlert>> {
        let watching = self.0.alerts.subscribe();
        if let Some(id) = self.routed() {
            self.deliver_alerts(id);
        }
        watching
    }
    pub(crate) fn directory_changed(&self) {
        self.0.directory.notify_waiters();
    }
    /// Wait until account `id` finished a directory read after its
    /// `after`th.
    pub(crate) async fn read_after(&self, id: ContainerId, after: u64) {
        loop {
            let changed = self.0.directory.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .with_known(id, |known, _| known.reads > after)
                .unwrap_or(true)
            {
                return;
            }
            changed.await;
        }
    }
    /// The routed account and its current capability while it shows a
    /// changed kit not saved yet: its notes wait, so it is not "bound".
    pub(crate) fn showing_new_kit(&self) -> Option<(ContainerId, Arc<AccountCapability>)> {
        let host = self.lock();
        let session = host.session.as_ref()?;
        if !matches!(session.screen, Some(Screen::NewKit { .. })) {
            return None;
        }
        let id = session.current_id()?;
        let capability = session.capabilities.get(&id)?;
        capability
            .is_current()
            .then(|| (id, Arc::clone(capability)))
    }
    /// Account `id`'s staged recovery replacement settled lost or refused:
    /// a new kit still showing for it no longer shows, and saving it says
    /// the kit did not change. False when no new kit showed for it: its kit
    /// was already saved.
    pub(crate) fn kit_not_changed(&self, id: ContainerId) -> bool {
        let mut host = self.lock();
        let Some(session) = host.session.as_mut() else {
            return false;
        };
        if session.current_id() != Some(id)
            || !matches!(session.screen, Some(Screen::NewKit { .. }))
        {
            return false;
        }
        session.screen = Some(Screen::Ready);
        session.known.entry(id).or_default().kit_not_changed = true;
        true
    }
    /// Show `screen` for account `id` while it is the routed one.
    pub(crate) fn show(&self, id: ContainerId, screen: Screen) {
        let mut host = self.lock();
        if let Some(session) = host.session.as_mut()
            && session.current_id() == Some(id)
        {
            session.screen = Some(screen);
        }
    }

    /// The final screen of an erasure, once one shows.
    pub(crate) async fn erased(&self) -> Screen {
        loop {
            let returned = self.0.returned.notified();
            tokio::pin!(returned);
            returned.as_mut().enable();
            if let Some(screen @ (Screen::Erased { .. } | Screen::EraseIncomplete { .. })) =
                self.screen()
            {
                return screen;
            }
            returned.await;
        }
    }
    pub(crate) fn alerts_watched(&self) -> bool {
        self.0.alerts.receiver_count() > 0
    }
    pub(crate) fn publish_alerts(&self, mut new: Vec<crate::devices::DeliveredAlert>) {
        new.reverse();
        self.0.alerts.send_modify(|delivered| {
            new.append(delivered);
            *delivered = std::mem::take(&mut new);
        });
    }

    /// A note window may control only the account it is bound to, not the
    /// registry's most recently routed (possibly different) account.
    pub fn controls_account(&self, container: ContainerId) -> bool {
        self.routed() == Some(container)
    }

    /// The routed account's container, ready or not.
    pub(crate) fn routed(&self) -> Option<ContainerId> {
        self.lock().session.as_ref()?.current_id()
    }
    /// The routed ready account, this device and its verified history.
    pub(crate) fn routed_account(&self) -> Option<(ContainerId, DeviceId, VerifiedAccount)> {
        let host = self.lock();
        let session = host.session.as_ref()?;
        let (capability, account) = session.verified_session()?;
        Some((
            session.bound_container()?,
            capability.device_id(),
            account.clone(),
        ))
    }
    pub(crate) fn database(
        &self,
        id: ContainerId,
    ) -> Option<Arc<std::sync::Mutex<DeviceDatabase>>> {
        self.lock()
            .session
            .as_ref()?
            .containers
            .shared_database(id)
            .ok()
    }
    /// A short use of what this run knows of account `id`'s directory, with
    /// this device's model name.
    pub(crate) fn with_known<R>(
        &self,
        id: ContainerId,
        use_known: impl FnOnce(&mut crate::devices::Known, Option<&str>) -> R,
    ) -> Option<R> {
        let mut host = self.lock();
        let host = &mut *host;
        let session = host.session.as_mut()?;
        Some(use_known(
            session.known.entry(id).or_default(),
            host.model.as_deref(),
        ))
    }

    /// The stable filename stem of `id`, which its files and removal marker
    /// keep across restarts.
    pub fn container_name(&self, id: ContainerId) -> Option<String> {
        self.lock()
            .session
            .as_ref()?
            .containers
            .container_name(id)
            .ok()
    }

    /// The routed ready account and its current capability.
    pub fn ready_authority(&self) -> Option<(ContainerId, Arc<AccountCapability>)> {
        let host = self.lock();
        let session = host.session.as_ref()?;
        let id = session.bound_container()?;
        Some((id, Arc::clone(session.capabilities.get(&id)?)))
    }
    /// The routed account's container, capability and own base, as notes
    /// are authorized with them.
    pub fn note_authority(&self) -> Option<NoteAuthority> {
        self.lock().session.as_ref()?.note_authority()
    }
    /// The accounts the last start found no longer holding this device
    /// active: each container, this device's id and the last account view in
    /// which it was a member. Only a starting point for checking the public
    /// evidence of its removal.
    pub fn removed_members(&self) -> Vec<(ContainerId, DeviceId, VerifiedAccount)> {
        self.lock()
            .session
            .as_ref()
            .map_or_else(Vec::new, |session| {
                session
                    .removed
                    .iter()
                    .map(|(id, (device, view))| (*id, *device, view.clone()))
                    .collect()
            })
    }
    /// The parts of ready account `id` its signer holds.
    pub fn ready_parts(&self, id: ContainerId) -> Option<ReadyParts<S>> {
        let host = self.lock();
        let session = host.session.as_ref()?;
        let capability = Arc::clone(session.capabilities.get(&id)?);
        if !capability.is_current() {
            return None;
        }
        Some(ReadyParts {
            capability,
            own_base: Arc::clone(session.own_bases.get(&id)?),
            generation: session.generations.get(&id)?.clone(),
            database: session.containers.shared_database(id).ok()?,
            store: session.store.clone(),
        })
    }
}

impl<S, P> SharedAccountHost<S, P>
where
    S: HostKeyStore + Send + 'static,
    P: PendingSetupProtector + Clone + Send + 'static,
{
    /// Erase account `id` after its removal was independently verified. The
    /// account's client must already be stopped; this moves its owner onto a
    /// worker (a native key prompt may need its own executor), runs the
    /// durable steps, and returns the final screen. Other accounts keep their
    /// owners and routes.
    pub async fn erase_removed(&self, id: ContainerId) -> Option<Screen> {
        let mut work = loop {
            let returned = self.0.returned.notified();
            tokio::pin!(returned);
            returned.as_mut().enable();
            {
                let mut host = self.lock();
                // Stopping the client cancels its tasks, but a native signing
                // worker it lent may still be finishing. Moving the account
                // without its owner would silently skip this erasure.
                if let Some(session) = host.session.as_ref()
                    && session.lent.contains_key(&id)
                {
                    // The public removal is already verified. Persist that
                    // verdict while the owner's prompt is still outstanding;
                    // only after it returns can we freeze the count and key
                    // handle. A restart rereads them before erasing.
                    if let Ok(name) = session.containers.container_name(id)
                        && !marker_path(&session.directory, &name).exists()
                    {
                        // If the intent cannot be written, still wait for the
                        // owner: the normal erasure will report the failure
                        // rather than silently abandon this verified removal.
                        let _ = write_erase_intent(&session.directory, &name);
                    }
                } else {
                    if !host.in_flight.insert(Some(id)) {
                        return None;
                    }
                    match host
                        .session
                        .as_mut()
                        .map(|session| session.take_work(Some(id)))
                    {
                        Some(work) => break work,
                        None => {
                            host.in_flight.remove(&Some(id));
                            return None;
                        }
                    }
                }
            }
            returned.await;
        };
        let joined = tokio::task::spawn_blocking(move || {
            // A platform prompt may need its own current-thread executor. If
            // one cannot be built, the owner still returns to the registry.
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => {
                    let screen = runtime.block_on(work.erase_removed(id));
                    (work, screen)
                }
                Err(_) => (work, Screen::EraseIncomplete { failed: 0 }),
            }
        })
        .await;
        let Ok((work, screen)) = joined else {
            self.lock().in_flight.remove(&Some(id));
            return None;
        };
        {
            let mut host = self.lock();
            host.in_flight.remove(&Some(id));
            let session = host.session.as_mut()?;
            // The worker kept its final screen; it returns only where the
            // erased account was the routed one.
            session.restore_work(work);
            session.forget_container(id);
        }
        self.0.returned.notify_waiters();
        Some(screen)
    }
}

/// A ready account on a real container owner, as signup leaves it, for
/// tests of what is built on the account host.
#[cfg(any(test, feature = "test-support"))]
pub async fn ready_test_host<S>(
    owner: &Arc<bh_device::Owner>,
    dir: &Path,
    store: S,
) -> SharedAccountHost<S, crate::test_support::PlainProtector>
where
    S: HostKeyStore + Send + 'static,
{
    let mut session = Session::new(
        Containers {
            owner: Arc::clone(owner),
        },
        dir,
        store,
        crate::test_support::PlainProtector,
        classify_owner_error,
    );
    assert!(matches!(
        session.create("ripple amber horizon nectar willow").await,
        Screen::Kit { .. }
    ));
    assert_eq!(session.confirm_kit().await, Screen::Ready);
    AccountHost {
        session: Some(session),
        suggested: None,
        in_flight: std::collections::HashSet::new(),
        bootstrapping: std::collections::HashSet::new(),
        model: None,
    }
    .into_state()
}

/// A device's account registry after its first startup, and that screen.
#[cfg(any(test, feature = "test-support"))]
pub async fn fresh_test_host<S>(
    owner: &Arc<bh_device::Owner>,
    dir: &Path,
    store: S,
) -> (
    SharedAccountHost<S, crate::test_support::PlainProtector>,
    Screen,
)
where
    S: HostKeyStore + Send + 'static,
{
    let mut session = Session::new(
        Containers {
            owner: Arc::clone(owner),
        },
        dir,
        store,
        crate::test_support::PlainProtector,
        classify_owner_error,
    );
    let screen = session.startup().await;
    let host = AccountHost {
        session: Some(session),
        suggested: None,
        in_flight: std::collections::HashSet::new(),
        bootstrapping: std::collections::HashSet::new(),
        model: None,
    }
    .into_state();
    (host, screen)
}

/// Two ready accounts in one registry: the routed one, then another a
/// worker activated beside it.
#[cfg(any(test, feature = "test-support"))]
pub async fn two_ready_test_host<S>(
    owner: &Arc<bh_device::Owner>,
    dir: &Path,
    store: S,
) -> (
    SharedAccountHost<S, crate::test_support::PlainProtector>,
    [ContainerId; 2],
)
where
    S: HostKeyStore + Send + 'static,
{
    let host = ready_test_host(owner, dir, store).await;
    let (first, second) = {
        let mut guard = host.lock();
        let session = guard.session.as_mut().expect("session");
        let first = session.current_id().expect("ready");
        (
            first,
            session.containers.create_container(dir).expect("container"),
        )
    };
    let mut account = host
        .lock()
        .session
        .as_mut()
        .expect("session")
        .owner(second)
        .unwrap();
    account
        .begin_first_device(
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            &Password::new("copper lantern velvet river pebble").unwrap(),
        )
        .await
        .unwrap();
    account.confirm_kit_saved().unwrap();
    drop(account);
    let mut work = host
        .lock()
        .session
        .as_mut()
        .expect("session")
        .take_work(Some(second));
    assert_eq!(work.startup().await, Screen::Ready);
    host.lock()
        .session
        .as_mut()
        .expect("session")
        .restore_work(work);
    (host, [first, second])
}

/// One container lent to a QR join: its one account owner, until the join
/// commits it as the account (`finish_join`) or gives it back.
pub struct JoinLease<S, P>
where
    S: HostKeyStore,
    P: PendingSetupProtector + Clone,
{
    pub id: ContainerId,
    pub owner: Owner<S, P>,
    pub store: S,
    pub database: Arc<std::sync::Mutex<DeviceDatabase>>,
    /// The kept hint or admission of an interrupted join on this container.
    pub joined: Option<bh_storage::joined::JoinedRecord>,
}

/// Why this device cannot join by QR now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinRefused {
    /// This device already holds an account (ready or in setup).
    AccountExists,
    /// Account files are not open yet, or another account task runs.
    Busy,
    Unavailable,
}

impl<S, P> SharedAccountHost<S, P>
where
    S: HostKeyStore + Clone + Send + 'static,
    P: PendingSetupProtector + Clone + Send + 'static,
{
    /// Lend the container a QR join uses: an interrupted join's (resumed,
    /// never replaced), else one holding only a scanner identity, else an
    /// empty one, else a new one. Refused beside any account, an unfinished
    /// recovery included.
    pub fn begin_join(&self) -> Result<JoinLease<S, P>, JoinRefused> {
        self.begin_lease(false)
    }

    /// Lend the container a recovery uses: an unfinished recovery's
    /// (resumed, never replaced), else as `begin_join` chooses. Refused
    /// beside any account or a join by QR this device kept.
    pub(crate) fn begin_recovery(&self) -> Result<JoinLease<S, P>, JoinRefused> {
        self.begin_lease(true)
    }

    /// A recovery on `id` ended before it finished: while no account is
    /// routed, the setup window asks for the password and kit again
    /// (`Recover`), as the next start does.
    pub(crate) fn recovery_left(&self, id: ContainerId) {
        let mut host = self.lock();
        if let Some(session) = host.session.as_mut()
            && session.current_id().is_none()
            && session.containers.recovery_unfinished(id)
        {
            session.screen = Some(Screen::Recover);
        }
    }

    /// Another owner of lent container `id`, on its generation: it proves
    /// possession of the device's keys while the lease's owner recovers.
    /// It only reads the journal and signs proofs (`prove_joining`); it
    /// never writes the journal, so the lease's owner stays its one writer.
    pub(crate) fn proving_owner(&self, id: ContainerId) -> Option<Owner<S, P>> {
        self.lock().session.as_mut()?.owner(id).ok()
    }

    fn begin_lease(&self, recovery: bool) -> Result<JoinLease<S, P>, JoinRefused> {
        let mut host = self.lock();
        let host = &mut *host;
        let session = host.session.as_mut().ok_or(JoinRefused::Unavailable)?;
        if !host.in_flight.is_empty() || !session.lent.is_empty() {
            return Err(JoinRefused::Busy);
        }
        if session.current.is_some() || !session.capabilities.is_empty() {
            return Err(JoinRefused::AccountExists);
        }
        let files = session.opened.as_ref().ok_or(JoinRefused::Busy)?;
        let mut choice: Option<(Held, ContainerId)> = None;
        for (_, file) in files {
            let Ok(id) = file else {
                return Err(JoinRefused::Busy);
            };
            let database = session
                .containers
                .shared_database(*id)
                .map_err(|_| JoinRefused::Unavailable)?;
            let holds = held(&*database.lock().map_err(|_| JoinRefused::Unavailable)?);
            let rank = |held| match held {
                Held::Joining => 0,
                Held::Scanner => 1,
                _ => 2,
            };
            // A recovery resumes only its own unfinished container, and a
            // join by QR only its own kept join.
            let holds = match (recovery, session.containers.recovery_unfinished(*id), holds) {
                (true, true, _) => Held::Joining,
                (false, true, _) | (true, false, Held::Joining) => Held::Account,
                (_, _, holds) => holds,
            };
            match holds {
                Held::Account => return Err(JoinRefused::AccountExists),
                Held::Unreadable => return Err(JoinRefused::Unavailable),
                _ if choice.is_none_or(|(best, _)| rank(holds) < rank(best)) => {
                    choice = Some((holds, *id));
                }
                _ => {}
            }
        }
        let id = match choice {
            Some((_, id)) => id,
            None => {
                let id = session
                    .containers
                    .create_container(&session.directory)
                    .map_err(|_| JoinRefused::Unavailable)?;
                session
                    .opened
                    .as_mut()
                    .expect("opened")
                    .push(("join".into(), Ok(id)));
                id
            }
        };
        let owner = match session.others.remove(&id) {
            Some(owner) => owner,
            None => session.owner(id).map_err(|_| JoinRefused::Unavailable)?,
        };
        let database = session
            .containers
            .shared_database(id)
            .map_err(|_| JoinRefused::Unavailable)?;
        let joined = database
            .lock()
            .map_err(|_| JoinRefused::Unavailable)?
            .joined()
            .map_err(|_| JoinRefused::Unavailable)?;
        host.in_flight.insert(Some(id));
        Ok(JoinLease {
            id,
            owner,
            store: session.store.clone(),
            database,
            joined,
        })
    }

    /// A join that did not commit: its owner returns, unrouted.
    pub fn return_join(&self, lease: JoinLease<S, P>) {
        {
            let mut host = self.lock();
            if let Some(session) = host.session.as_mut() {
                session.others.insert(lease.id, lease.owner);
            }
            host.in_flight.remove(&Some(lease.id));
        }
        self.0.returned.notify_waiters();
    }

    /// The join committed its admission: the container's owner becomes the
    /// routed account with this authority and own base. It is not Ready
    /// until its bootstrap activates it (`join_ready`).
    pub fn finish_join(
        &self,
        lease: JoinLease<S, P>,
        capability: Arc<AccountCapability>,
        own_base: Arc<bh_device::own_base::OwnBase>,
    ) {
        {
            let mut host = self.lock();
            if let Some(session) = host.session.as_mut() {
                session.capabilities.insert(lease.id, capability);
                session.own_bases.insert(lease.id, own_base);
                match session.current {
                    None => session.current = Some((lease.id, lease.owner)),
                    Some(_) => drop(session.others.insert(lease.id, lease.owner)),
                }
                // Whatever the window showed before, it now follows the join.
                session.screen = None;
            }
            host.in_flight.remove(&Some(lease.id));
            host.bootstrapping.insert(lease.id);
        }
        self.0.returned.notify_waiters();
    }

    /// A recovery finished on the lease's container, activated with its own
    /// base downloaded: it is the routed account, Ready with this authority
    /// and own base. False if that authority is no longer live: the next
    /// start opens it as it is.
    pub(crate) fn finish_recovery(
        &self,
        lease: JoinLease<S, P>,
        capability: Arc<AccountCapability>,
        own_base: Arc<bh_device::own_base::OwnBase>,
    ) -> bool {
        let ready = {
            let mut host = self.lock();
            let host = &mut *host;
            host.in_flight.remove(&Some(lease.id));
            let Some(session) = host.session.as_mut() else {
                return false;
            };
            let id = lease.id;
            session.capabilities.insert(id, capability);
            session.own_bases.insert(id, own_base);
            match session.current {
                None => session.current = Some((id, lease.owner)),
                Some(_) => drop(session.others.insert(id, lease.owner)),
            }
            session.screen = Some(Screen::Ready);
            let ready = session.bound_container() == Some(id);
            if !ready {
                session.screen = None;
            }
            ready
        };
        self.0.returned.notify_waiters();
        ready
    }

    /// The joined container's bootstrap activated it: the account is ready.
    pub fn join_ready(&self, id: ContainerId) -> bool {
        let mut host = self.lock();
        let Some(session) = host.session.as_mut() else {
            return false;
        };
        if session.current_id() != Some(id) {
            return false;
        }
        session.screen = Some(Screen::Ready);
        let ready = session.bound_container() == Some(id);
        if ready {
            host.bootstrapping.remove(&id);
        }
        ready
    }

    /// A committed join under `capability` ended before it was ready (its
    /// signer or bootstrap failed, or it was cancelled). Its container goes
    /// back to the kept, not yet activated join it is on disk: locked and
    /// unrouted, so the next start resumes exactly that join, never another
    /// identity. A container whose join was activated meanwhile starts as an
    /// account instead.
    pub fn suspend_join(&self, id: ContainerId, capability: &Arc<AccountCapability>) {
        {
            let mut host = self.lock();
            let host = &mut *host;
            let Some(session) = host.session.as_mut() else {
                return;
            };
            if !session
                .capabilities
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, capability))
            {
                return;
            }
            host.bootstrapping.remove(&id);
            let holds = session
                .containers
                .shared_database(id)
                .ok()
                .and_then(|db| db.lock().ok().map(|db| held(&db)));
            if holds != Some(Held::Joining) {
                return;
            }
            session.capabilities.remove(&id);
            session.own_bases.remove(&id);
            if session
                .current
                .as_ref()
                .is_some_and(|(current, _)| *current == id)
            {
                let (_, mut owner) = session.current.take().expect("matched");
                let _ = owner.lock();
                session.others.insert(id, owner);
            } else if let Some(owner) = session.others.get_mut(&id) {
                let _ = owner.lock();
            } else if let Some(lent) = session.lent.get_mut(&id) {
                // Fenced as `stop` fences a lent owner; it locks on return.
                lent.stopped = true;
                lent.current = false;
                if let (Some(generation), Ok(database)) = (
                    session.generations.get(&id),
                    session.containers.shared_database(id),
                ) {
                    let _guard = database
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    generation.advance();
                }
            }
            session.screen = None;
        }
        self.0.returned.notify_waiters();
    }
}

/// The account cannot lend its owner now: not Ready under this capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

impl<S, P> SharedAccountHost<S, P>
where
    S: HostKeyStore + Clone + Send + 'static,
    P: PendingSetupProtector + Clone + Send + 'static,
{
    /// Borrow Ready account `id`'s one owner, waiting (holding no lock)
    /// while another worker has it. Refused unless `capability` is still
    /// the account's current authority.
    pub async fn lend(
        &self,
        id: ContainerId,
        capability: &Arc<AccountCapability>,
    ) -> Result<Owner<S, P>, Unavailable> {
        loop {
            let returned = self.0.returned.notified();
            tokio::pin!(returned);
            returned.as_mut().enable();
            {
                let mut host = self.lock();
                let host = &mut *host;
                let session = host.session.as_mut().ok_or(Unavailable)?;
                if !capability.is_current()
                    || !session
                        .capabilities
                        .get(&id)
                        .is_some_and(|current| Arc::ptr_eq(current, capability))
                {
                    return Err(Unavailable);
                }
                if !host.in_flight.contains(&Some(id))
                    && let Some(owner) = session.lend(id)
                {
                    host.in_flight.insert(Some(id));
                    return Ok(owner);
                }
                if !host.in_flight.contains(&Some(id)) && !session.lent.contains_key(&id) {
                    return Err(Unavailable);
                }
            }
            returned.await;
        }
    }

    /// Return a lent owner and wake anyone waiting for it.
    pub fn give_back(&self, id: ContainerId, owner: Owner<S, P>) {
        {
            let mut host = self.lock();
            match host.session.as_mut() {
                Some(session) => session.give_back(id, owner),
                None => drop(owner),
            }
            host.in_flight.remove(&Some(id));
        }
        self.0.returned.notify_waiters();
    }

    /// A short synchronous use of Ready account `id`'s owner under the
    /// registry lock, the account's authority lock: nothing can lock,
    /// stop or lend it meanwhile. `None` at once if it is lent or not
    /// current; it never waits for a prompt.
    pub fn with_owner<R>(
        &self,
        id: ContainerId,
        capability: &Arc<AccountCapability>,
        use_owner: impl FnOnce(&mut Owner<S, P>) -> R,
    ) -> Option<R> {
        let mut host = self.lock();
        let session = host.session.as_mut()?;
        if !capability.is_current()
            || !session
                .capabilities
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, capability))
        {
            return None;
        }
        let owner = match session.current.as_mut() {
            Some((current, owner)) if *current == id => owner,
            _ => session.others.get_mut(&id)?,
        };
        Some(use_owner(owner))
    }

    /// Run `operation` on the lent owner in a native worker with its own
    /// current-thread executor (a platform prompt may hold a context that
    /// cannot move between threads). The owner returns when it finishes,
    /// even if the caller stopped waiting; a panic locks the account.
    pub async fn run_lent<R: Send + 'static>(
        &self,
        id: ContainerId,
        capability: &Arc<AccountCapability>,
        operation: impl for<'a> FnOnce(
            &'a mut Owner<S, P>,
            Arc<AccountCapability>,
        ) -> futures_util::future::LocalBoxFuture<'a, R>
        + Send
        + 'static,
    ) -> Result<R, Unavailable> {
        let mut owner = self.lend(id, capability).await?;
        let host = self.clone();
        let capability = Arc::clone(capability);
        tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("account worker runtime");
                runtime.block_on(operation(&mut owner, capability))
            }));
            if result.is_err() {
                let _ = owner.lock();
                host.lock()
                    .session
                    .as_mut()
                    .map(|session| session.capabilities.remove(&id));
            }
            host.give_back(id, owner);
            result.map_err(|_| Unavailable)
        })
        .await
        .map_err(|_| Unavailable)?
    }
}

/// One account operation that may use a native key store, which may prompt.
/// The account's own screens run through `SharedAccountHost::run`; those on
/// Your devices need its sync and run through `devices::run`.
pub enum AccountOperation {
    Startup,
    Retry,
    Create(String),
    ConfirmKit,
    /// Recover the account with its password and recovery kit, from a
    /// fresh install's Welcome or an unfinished recovery's `Recover`.
    Recover {
        password: String,
        code: String,
    },
    /// Ask to remove another device after the removal wait.
    RequestRemoval {
        device: [u8; 32],
    },
    /// Cancel the pending removal ordered at account position `request`.
    CancelRemoval {
        request: u64,
    },
    /// Remove another device at once, cosigned with the recovery kit.
    RemoveNow {
        device: [u8; 32],
        password: String,
        code: String,
    },
    /// Remove this device, sending its unsent work first unless told not to.
    RemoveSelf {
        without_sync: bool,
    },
    /// A new recovery kit, and a new password unless `new` is `None`.
    /// `code` is the current kit, needed when no password check is known.
    ChangePassword {
        current: String,
        new: Option<String>,
        code: Option<String>,
    },
    /// The person saved the new kit `NewKit` showed.
    ConfirmNewKit,
}

impl AccountOperation {
    /// Whether it acts on Your devices (`devices::run`).
    pub fn on_devices(&self) -> bool {
        !matches!(
            self,
            Self::Startup | Self::Retry | Self::Create(_) | Self::ConfirmKit | Self::Recover { .. }
        )
    }
}

impl<S, P> SharedAccountHost<S, P>
where
    S: HostKeyStore + Clone + Send + 'static,
    P: PendingSetupProtector + Clone + Send + 'static,
{
    /// Run `operation` on a dedicated worker with its own current-thread
    /// executor: a platform prompt may hold a context that cannot move
    /// between threads. The short registry lock is released before the
    /// prompt; the shared SQLite mutex is taken only inside synchronous
    /// journal calls. Restoring the account belongs to the worker, not the
    /// caller, so a caller that stops waiting cannot strand it.
    ///
    /// Windows reach it through `PairingHost::setup_screen`, which follows a
    /// running join instead (the join owns its account until it ends).
    pub(crate) async fn run(&self, operation: AccountOperation) -> Result<Screen, &'static str> {
        // Recovery needs the build's transport: `PairingHost::setup_screen`.
        if operation.on_devices() || matches!(operation, AccountOperation::Recover { .. }) {
            return Err("not an account screen operation");
        }
        let (mut session, target) = {
            let mut host = self.lock();
            let registry = host.session.as_ref().ok_or("account unavailable")?;
            if matches!(operation, AccountOperation::Startup)
                && let Some(screen) = registry.cached_screen()
            {
                return Ok(screen);
            }
            let target = registry.current_id();
            // Another window cannot take a committed join from its bootstrap.
            if target.is_some_and(|id| host.bootstrapping.contains(&id)) {
                return Err("account busy");
            }
            if target.is_none() && !host.in_flight.is_empty() {
                return Err("account busy");
            }
            if !host.in_flight.insert(target) {
                return Err("account busy");
            }
            (
                host.session.as_mut().expect("checked").take_work(target),
                target,
            )
        };
        let restore = self.clone();
        let completed = tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("account worker runtime");
                runtime.block_on(async {
                    match operation {
                        AccountOperation::Startup => session.startup().await,
                        AccountOperation::Retry => session.retry().await,
                        AccountOperation::Create(password) => session.create(&password).await,
                        AccountOperation::ConfirmKit => session.confirm_kit().await,
                        _ => Screen::Unavailable,
                    }
                })
            }));
            if result.is_err() {
                session.stop();
            }
            let mut host = restore.lock();
            if let Some(registry) = host.session.as_mut() {
                registry.restore_work(session);
            }
            host.in_flight.remove(&target);
            drop(host);
            restore.0.returned.notify_waiters();
            result
        })
        .await
        .map_err(|_| "account unavailable")?;
        completed.map_err(|_| "account unavailable")
    }

    /// The code the person must keep while setup is incomplete.
    pub fn pending_code(&self) -> Option<RecoveryCode> {
        self.lock().session.as_mut().and_then(Session::pending_code)
    }
    /// The password last suggested on the password screen.
    pub fn suggested(&self) -> Option<String> {
        self.lock().suggested.clone()
    }
    pub fn set_suggested(&self, suggested: Option<String>) {
        self.lock().suggested = suggested;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex as StdMutex};

    use crate::test_support::{FakeStore, PlainProtector};
    use bh_account::{
        crypto::{self, SecretBytes, SigningKey},
        journal::{PendingSetupProtector, ProtectorError},
    };

    /// Stands in for the real container owner: one SQLite file per container in a
    /// directory, opened by the owner, never by app code.
    #[derive(Clone, Default)]
    struct FakeContainers {
        state: Arc<StdMutex<FakeState>>,
    }

    #[derive(Default)]
    struct FakeState {
        ids: Vec<ContainerId>,
        files: HashMap<ContainerId, PathBuf>,
        handles: HashMap<ContainerId, Arc<StdMutex<DeviceDatabase>>>,
        anchor_calls: Vec<ContainerId>,
        open_errors: Vec<(String, OwnerError)>,
        open_calls: usize,
        fail_open: bool,
        fail_remove: bool,
        is_empty_calls: usize,
    }

    impl ContainerOwner for FakeContainers {
        fn create_container(&self, dir: &Path) -> Result<ContainerId, OwnerError> {
            let mut state = self.state.lock().unwrap();
            let id = loop {
                let candidate = ContainerId(crypto::random());
                if !state.files.contains_key(&candidate) {
                    break candidate;
                }
            };
            let path = dir.join(format!("container-{}.sqlite", state.ids.len() + 1));
            std::fs::create_dir_all(dir).unwrap();
            let db = DeviceDatabase::open(&path).unwrap();
            state.ids.push(id);
            state.files.insert(id, path);
            state.handles.insert(id, Arc::new(StdMutex::new(db)));
            Ok(id)
        }
        fn open_containers(
            &self,
            _: &Path,
        ) -> Result<Vec<(String, Result<ContainerId, OwnerError>)>, OwnerError> {
            let mut state = self.state.lock().unwrap();
            state.open_calls += 1;
            if state.fail_open {
                return Err(OwnerError::UnknownContainer);
            }
            let mut opened: Vec<_> = state
                .ids
                .iter()
                .enumerate()
                .map(|(index, id)| (format!("container-{}", index + 1), Ok(*id)))
                .collect();
            opened.extend(
                std::mem::take(&mut state.open_errors)
                    .into_iter()
                    .map(|(name, error)| (name, Err(error))),
            );
            Ok(opened)
        }
        fn is_empty(&self, id: ContainerId) -> Result<bool, OwnerError> {
            self.state.lock().unwrap().is_empty_calls += 1;
            let db = self.shared_database(id)?;
            let db = db.lock().map_err(|_| OwnerError::UnknownContainer)?;
            Ok(db.account_state()?.is_none()
                && db.pending_setup()?.is_none()
                && db.device_identity()?.is_none())
        }
        fn shared_database(
            &self,
            id: ContainerId,
        ) -> Result<Arc<StdMutex<DeviceDatabase>>, OwnerError> {
            self.state
                .lock()
                .unwrap()
                .handles
                .get(&id)
                .cloned()
                .ok_or(OwnerError::UnknownContainer)
        }
        fn anchor(&self, id: ContainerId, _: &VerifiedAccount) -> Result<(), OwnerError> {
            self.state.lock().unwrap().anchor_calls.push(id);
            Ok(())
        }
        fn deauthorize(&self, _: ContainerId) -> Result<Vec<String>, OwnerError> {
            Ok(Vec::new())
        }
        fn container_name(&self, id: ContainerId) -> Result<String, OwnerError> {
            self.state
                .lock()
                .unwrap()
                .files
                .get(&id)
                .and_then(|path| path.file_stem())
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
                .ok_or(OwnerError::UnknownContainer)
        }
        fn remove_container(&self, id: ContainerId) -> Result<(), OwnerError> {
            let mut state = self.state.lock().unwrap();
            if state.fail_remove {
                return Err(OwnerError::Io(std::io::Error::other(
                    "injected removal failure",
                )));
            }
            state.handles.remove(&id);
            if let Some(path) = state.files.remove(&id) {
                for file in [
                    path.clone(),
                    PathBuf::from(format!("{}-wal", path.display())),
                    PathBuf::from(format!("{}-shm", path.display())),
                    path.with_extension("lock"),
                ] {
                    match std::fs::remove_file(&file) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(OwnerError::Io(error)),
                    }
                }
                state.ids.retain(|other| *other != id);
            }
            Ok(())
        }
    }

    fn classify_fake_owner_error(error: &OwnerError) -> OpenIssue {
        match error {
            OwnerError::Unbound => OpenIssue::Busy,
            OwnerError::Changed => OpenIssue::NewerData,
            _ => OpenIssue::Corrupt,
        }
    }

    struct Harness {
        dir: tempfile::TempDir,
        containers: FakeContainers,
        store: FakeStore,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                containers: FakeContainers::default(),
                store: FakeStore::default(),
            }
        }
        fn session(&self) -> Session<FakeContainers, FakeStore, PlainProtector> {
            Session::new(
                self.containers.clone(),
                self.dir.path(),
                self.store.clone(),
                PlainProtector,
                classify_fake_owner_error,
            )
        }
        fn sessions(&self) -> usize {
            self.containers.state.lock().unwrap().ids.len()
        }
        fn anchors(&self) -> usize {
            self.containers.state.lock().unwrap().anchor_calls.len()
        }
    }

    fn real_session(
        dir: &std::path::Path,
        store: FakeStore,
    ) -> Session<Containers, FakeStore, PlainProtector> {
        Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir,
            store,
            PlainProtector,
            classify_owner_error,
        )
    }

    #[derive(Clone, Default)]
    struct RetirementFailure(Arc<std::sync::atomic::AtomicBool>);
    impl PendingSetupProtector for RetirementFailure {
        fn seal(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ProtectorError> {
            PlainProtector.seal(bytes)
        }
        fn open(&mut self, bytes: &[u8]) -> Result<SecretBytes, ProtectorError> {
            PlainProtector.open(bytes)
        }
        fn reseal_without_code(
            &mut self,
            _: &[u8],
            bytes: &[u8],
        ) -> Result<Vec<u8>, ProtectorError> {
            self.seal(bytes)
        }
        fn retire_kit_key(&mut self, _: &[u8]) -> Result<(), ProtectorError> {
            if self.0.swap(false, std::sync::atomic::Ordering::SeqCst) {
                Err(ProtectorError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn ready_requires_persisted_own_base_and_worker_transfer_keeps_scoped_keys() {
        let h = Harness::new();
        let mut session = h.session();
        assert!(matches!(
            session.create("synthetic initial base password").await,
            Screen::Kit { .. }
        ));
        let id = session.current.as_ref().unwrap().0;
        let path = h.containers.state.lock().unwrap().files[&id].clone();
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch("CREATE TRIGGER fail_base BEFORE INSERT ON own_base BEGIN SELECT RAISE(FAIL,'transient base write'); END;").unwrap();
        assert_eq!(session.confirm_kit().await, Screen::Retry);
        assert!(session.bound_container().is_none());
        assert!(session.verified_session().is_none());
        assert_eq!(h.anchors(), 0, "anchor alone cannot publish Ready");
        let prefix = session
            .current
            .as_mut()
            .unwrap()
            .1
            .setup_status()
            .unwrap()
            .unwrap()
            .submission;
        raw.execute_batch("DROP TRIGGER fail_base").unwrap();
        assert_eq!(session.retry().await, Screen::Ready);
        let export = session.own_bases[&id]
            .bootstrap_export(&session.current.as_ref().unwrap().1)
            .unwrap();
        assert_eq!(export.account.events, prefix);
        assert_eq!(export.account.head.position, 3);
        let roots = session.own_bases[&id]
            .with_keys(|m, k| (*m.expose(), *k.expose()))
            .unwrap();
        let work = session.take_work(Some(id));
        assert!(session.own_bases.is_empty());
        assert_eq!(
            work.own_bases[&id]
                .with_keys(|m, k| (*m.expose(), *k.expose()))
                .unwrap(),
            roots
        );
        session.restore_work(work);
        assert_eq!(session.bound_container(), Some(id));
        assert!(
            session.own_bases[&id]
                .bootstrap_export(&session.current.as_ref().unwrap().1)
                .unwrap()
                == export
        );
        session.stop();
        assert!(session.own_bases.is_empty());
        assert!(session.verified_session().is_none());
        let mut fresh = h.session();
        assert_eq!(fresh.startup().await, Screen::Ready);
        assert!(
            fresh.own_bases[&id]
                .bootstrap_export(&fresh.current.as_ref().unwrap().1)
                .unwrap()
                == export
        );
    }

    #[tokio::test]
    async fn stale_ready_cache_reopens_own_base_with_fresh_capability() {
        let h = Harness::new();
        let mut session = h.session();
        let _ = session.create("synthetic initial base password").await;
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        let id = session.bound_container().unwrap();
        let old = session.capabilities[&id].clone();
        let original = session.own_bases[&id]
            .bootstrap_export(&session.current.as_ref().unwrap().1)
            .unwrap();
        assert_eq!(session.cached_screen(), Some(Screen::Ready));
        session.generations[&id].advance();
        assert!(session.bound_container().is_none());
        assert!(
            session.cached_screen().is_none(),
            "the native IPC fast path must not return stale Ready"
        );
        assert_eq!(session.startup().await, Screen::Ready);
        assert!(!old.is_current());
        assert_eq!(session.bound_container(), Some(id));
        assert!(
            session.own_bases[&id]
                .bootstrap_export(&session.current.as_ref().unwrap().1)
                .unwrap()
                == original
        );
    }

    #[tokio::test]
    async fn notes_stay_bound_while_the_base_epoch_is_closed() {
        let h = Harness::new();
        let mut session = h.session();
        let _ = session.create("synthetic initial base password").await;
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        let id = session.bound_container().unwrap();
        let base = session.own_bases[&id].id();
        let package = session.own_bases[&id]
            .initial_key_package()
            .unwrap()
            .metadata_seal()
            .to_vec();
        let metadata_id = bh_device::base_keys::SealHeader::decode(&package)
            .unwrap()
            .key_id;
        // Verified history closed the content epoch (a removal applied).
        let genesis = bh_sync::canonical::CanonicalCommitment::order(
            base,
            bh_sync::OrderState::EMPTY,
            bh_sync::Digest(base.0),
            bh_sync::Route::Control,
        )
        .unwrap();
        let path = h.containers.state.lock().unwrap().files[&id].clone();
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO log_progress(log_kind,log_id,position,head_hash,control_digest,hosting_root,account_position,account_hash,metadata_id,epoch_id,floor,order_format,opening,floor_opening)
                 VALUES(1,?1,1,?2,?3,zeroblob(32),3,zeroblob(32),?4,NULL,1,2,?5,?6)",
                rusqlite::params![base.0.as_slice(), genesis.head().hash.0.as_slice(), base.0.as_slice(), metadata_id.as_slice(), genesis.after().encode().as_slice(), bh_sync::OrderState::EMPTY.encode().as_slice()],
            )
            .unwrap();
        session.generations[&id].advance();
        assert_eq!(session.startup().await, Screen::Ready);
        // No content key is current, yet the account's notes stay bound:
        // their writes wait for a new epoch, the notes themselves do not.
        assert!(session.own_bases[&id].with_keys(|_, _| ()).is_err());
        assert_eq!(session.bound_container(), Some(id));
    }

    #[tokio::test]
    async fn retirement_failure_retries_in_the_same_session_without_reshowing_code() {
        let h = Harness::new();
        let protector = RetirementFailure::default();
        let mut session = Session::new(
            h.containers.clone(),
            h.dir.path(),
            h.store.clone(),
            protector.clone(),
            classify_fake_owner_error,
        );
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        let id = session.current.as_ref().unwrap().0;
        protector.0.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(session.confirm_kit().await, Screen::Unavailable);
        assert!(session.screen.is_none());
        assert!(session.pending_code().is_none());
        assert_eq!(session.startup().await, Screen::Ready);
        assert_eq!(session.bound_container(), Some(id));
        assert_eq!(h.sessions(), 1);
    }

    #[tokio::test]
    async fn successful_file_save_recovers_same_setup_after_crash() {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::default();
        let mut first = real_session(dir.path(), store.clone());
        let Screen::Kit { code } = first.create("ripple amber horizon nectar willow").await else {
            panic!("kit required")
        };
        assert_eq!(first.pending_code().unwrap().to_kit_text(), code);
        let id = first.current.as_ref().unwrap().0;
        let staged = first
            .current
            .as_mut()
            .unwrap()
            .1
            .setup_status()
            .unwrap()
            .unwrap();
        let db = first.containers.shared_database(id).unwrap();
        // Simulate a successful native save followed by a failed local commit.
        let filename = std::fs::read_dir(dir.path().join("accounts"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| e.path().extension().is_some_and(|x| x == "sqlite"))
            .unwrap()
            .path();
        let conn = rusqlite::Connection::open(filename).unwrap();
        conn.execute_batch("CREATE TRIGGER fail_local BEFORE INSERT ON account_events BEGIN SELECT RAISE(FAIL,'disk full'); END;").unwrap();
        assert_eq!(first.confirm_kit().await, Screen::Unavailable);
        assert!(first.pending_code().is_none());
        conn.execute_batch("DROP TRIGGER fail_local").unwrap();
        assert_eq!(first.startup().await, Screen::Ready);
        assert!(first.pending_code().is_none());
        assert!(first.verified_session().unwrap().0.account_id() == staged.anchor);
        drop(db);
        drop(first);
        let mut reopened = real_session(dir.path(), store);
        assert_eq!(reopened.startup().await, Screen::Ready);
        assert!(reopened.verified_session().unwrap().0.account_id() == staged.anchor);
        assert_eq!(
            reopened
                .containers
                .shared_database(reopened.current.as_ref().unwrap().0)
                .unwrap()
                .lock()
                .unwrap()
                .account_history()
                .unwrap(),
            staged.submission
        );
        assert_eq!(
            reopened
                .containers
                .shared_database(reopened.current.as_ref().unwrap().0)
                .unwrap()
                .lock()
                .unwrap()
                .account_history()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            std::fs::read_dir(dir.path().join("accounts"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "sqlite"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn mac_gated_first_device_signs_three_events_with_one_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::gated();
        let mut session = real_session(dir.path(), store.clone());
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        assert_eq!(store.prompts(), 1);
        let setup = session
            .current
            .as_mut()
            .unwrap()
            .1
            .setup_status()
            .unwrap()
            .unwrap();
        assert_eq!(setup.submission.len(), 3);
        assert_eq!(setup.head.position, 3);
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        assert_eq!(
            store.prompts(),
            1,
            "saving the kit does not confirm another control action"
        );
    }

    #[tokio::test]
    async fn saved_pending_reopen_reads_only_setup_prefix_and_current_membership() {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::default();
        let mut session = real_session(dir.path(), store.clone());
        session.create("ripple amber horizon nectar willow").await;
        session
            .current
            .as_mut()
            .unwrap()
            .1
            .mark_home_pending()
            .unwrap();
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        let id = session.current.as_ref().unwrap().0;
        let setup = session
            .current
            .as_mut()
            .unwrap()
            .1
            .setup_status()
            .unwrap()
            .unwrap();
        // Until its home answers, the saved setup takes no later history.
        {
            let cap = &session.capabilities[&id];
            let owner = &mut session.current.as_mut().unwrap().1;
            let keys = bh_account::DevicePublicKeys::new([7; 32], [8; 32], [9; 1216]).unwrap();
            let request = owner.prepare_add_device(cap, keys).unwrap();
            let add = owner.sign_control(cap, &request).await.unwrap();
            assert!(matches!(
                owner.apply_incoming(&[add.as_bytes()]),
                Err(bh_account::owner::OwnerError::Invalid(
                    bh_account::Error::Unavailable
                ))
            ));
        }
        drop(session);
        let mut session = real_session(dir.path(), store.clone());
        assert_eq!(session.startup().await, Screen::Ready);
        let id = session.current.as_ref().unwrap().0;
        assert_eq!(
            session
                .current
                .as_mut()
                .unwrap()
                .1
                .setup_status()
                .unwrap()
                .unwrap()
                .submission,
            setup.submission
        );
        session
            .current
            .as_mut()
            .unwrap()
            .1
            .confirm_home_ordered(setup.head, None)
            .unwrap();
        for i in 0..140u32 {
            let control = SigningKey::generate();
            let mut receiving = [88; 1216];
            receiving[..4].copy_from_slice(&i.to_be_bytes());
            let keys = bh_account::DevicePublicKeys::new(
                SigningKey::generate().public(),
                control.public(),
                receiving,
            )
            .unwrap();
            let cap = &session.capabilities[&id];
            let owner = &mut session.current.as_mut().unwrap().1;
            let request = owner.prepare_add_device(cap, keys.clone()).unwrap();
            let add = owner.sign_control(cap, &request).await.unwrap();
            owner.apply_incoming(&[add.as_bytes()]).unwrap();
            let request = owner.verified(cap).unwrap().remove_self(keys.id()).unwrap();
            let remove = request
                .finish(control.sign(request.signing_bytes()))
                .unwrap();
            owner.apply_incoming(&[remove.as_bytes()]).unwrap();
        }
        let path = std::fs::read_dir(dir.path().join("accounts"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| e.path().extension().is_some_and(|x| x == "sqlite"))
            .unwrap()
            .path();
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints=ON;
            UPDATE account_events SET bytes=42 WHERE id>3 AND id<(SELECT MAX(id) FROM account_events);
            UPDATE account_devices SET keys=42 WHERE removed IS NOT NULL;").unwrap();
        drop(session);
        let mut reopened = real_session(dir.path(), store);
        assert_eq!(reopened.startup().await, Screen::Ready);
        let cap = reopened.verified_session().unwrap().0;
        assert!(cap.account_id() == setup.anchor);
        assert_eq!(cap.head().position, 283);
    }

    async fn ready_on(
        owner: &Arc<bh_device::Owner>,
        dir: &Path,
    ) -> Session<Containers, FakeStore, PlainProtector> {
        let mut session = Session::new(
            Containers {
                owner: Arc::clone(owner),
            },
            dir,
            FakeStore::default(),
            PlainProtector,
            classify_owner_error,
        );
        session.create("ripple amber horizon nectar willow").await;
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        session
    }

    fn into_host(
        session: Session<Containers, FakeStore, PlainProtector>,
    ) -> SharedAccountHost<FakeStore, PlainProtector> {
        AccountHost {
            session: Some(session),
            suggested: None,
            in_flight: std::collections::HashSet::new(),
            bootstrapping: std::collections::HashSet::new(),
            model: None,
        }
        .into_state()
    }

    /// The ready account and a second account activated beside it, as a
    /// worker leaves an unrelated account it opened.
    async fn two_ready(
        owner: &Arc<bh_device::Owner>,
        dir: &Path,
    ) -> SharedAccountHost<FakeStore, PlainProtector> {
        let mut session = ready_on(owner, dir).await;
        let second = session.containers.create_container(dir).unwrap();
        {
            let mut account = session.owner(second).unwrap();
            account
                .begin_first_device(
                    ControlKeyPolicy::AppEnforcedOwnerConfirmation,
                    &Password::new("copper lantern velvet river pebble").unwrap(),
                )
                .await
                .unwrap();
            account.confirm_kit_saved().unwrap();
        }
        let mut work = session.take_work(Some(second));
        assert_eq!(work.startup().await, Screen::Ready);
        session.restore_work(work);
        assert!(session.others.contains_key(&second));
        into_host(session)
    }

    fn authority(
        host: &SharedAccountHost<FakeStore, PlainProtector>,
    ) -> Vec<(ContainerId, Arc<AccountCapability>)> {
        let guard = host.lock();
        let session = guard.session.as_ref().unwrap();
        let mut all: Vec<_> = session
            .capabilities
            .iter()
            .map(|(id, cap)| (*id, Arc::clone(cap)))
            .collect();
        let current = session.current_id();
        all.sort_by_key(|(id, _)| Some(*id) != current);
        all
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lent_owner_keeps_its_routing_and_returns_to_its_place() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = into_host(ready_on(&owner, dir.path()).await);
        let (id, cap) = authority(&host).remove(0);
        let lent = host.lend(id, &cap).await.unwrap();
        {
            let guard = host.lock();
            let session = guard.session.as_ref().unwrap();
            assert_eq!(session.bound_container(), Some(id), "routing stays");
            assert!(session.note_authority().is_some());
            assert!(session.current.is_none(), "the one owner is lent");
        }
        // A second borrower waits without holding the registry.
        let waiting = tokio::spawn({
            let (host, cap) = (host.clone(), Arc::clone(&cap));
            async move {
                host.lend(id, &cap).await.is_ok_and(|owner| {
                    host.give_back(id, owner);
                    true
                })
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());
        assert!(host.0.host.try_lock().is_ok(), "no registry lock is held");
        host.give_back(id, lent);
        assert!(waiting.await.unwrap());
        let guard = host.lock();
        let session = guard.session.as_ref().unwrap();
        assert_eq!(session.current.as_ref().map(|(i, _)| *i), Some(id));
        assert!(session.verified_session().is_some());
        assert!(guard.in_flight.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopping_while_lent_fences_it_and_locks_the_returned_owner() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = into_host(ready_on(&owner, dir.path()).await);
        let (id, cap) = authority(&host).remove(0);
        let lent = host.lend(id, &cap).await.unwrap();
        host.lock().session.as_mut().unwrap().stop();
        assert!(!cap.is_current(), "stop fences a lent account too");
        assert!(lent.verified(&cap).is_err());
        host.give_back(id, lent);
        assert!(host.lend(id, &cap).await.is_err());
        let guard = host.lock();
        let session = guard.session.as_ref().unwrap();
        assert_eq!(session.bound_container(), None);
        assert!(session.lent.is_empty());
        assert!(guard.in_flight.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_superseded_capability_cannot_borrow_the_owner() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = into_host(ready_on(&owner, dir.path()).await);
        let (id, old) = authority(&host).remove(0);
        {
            let mut guard = host.lock();
            let session = guard.session.as_mut().unwrap();
            session.generations[&id].advance();
            session.capabilities.remove(&id);
        }
        let mut work = {
            let mut guard = host.lock();
            guard.session.as_mut().unwrap().take_work(Some(id))
        };
        assert_eq!(work.startup().await, Screen::Ready);
        host.lock().session.as_mut().unwrap().restore_work(work);
        let (_, fresh) = authority(&host).remove(0);
        assert!(!Arc::ptr_eq(&old, &fresh));
        assert!(host.lend(id, &old).await.is_err(), "stale authority");
        let lent = host.lend(id, &fresh).await.unwrap();
        host.give_back(id, lent);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_held_prompt_on_one_account_does_not_block_another() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = two_ready(&owner, dir.path()).await;
        let mut accounts = authority(&host);
        let (second, second_cap) = accounts.remove(1);
        let (first, first_cap) = accounts.remove(0);
        let (release, held) = tokio::sync::oneshot::channel::<()>();
        let prompt = tokio::spawn({
            let host = host.clone();
            async move {
                host.run_lent(first, &first_cap, move |account, cap| {
                    Box::pin(async move {
                        let _ = held.await;
                        account
                            .sign_content(&cap, b"after a long prompt")
                            .await
                            .is_ok()
                    })
                })
                .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let other = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            host.run_lent(second, &second_cap, |account, cap| {
                Box::pin(async move { account.sign_content(&cap, b"meanwhile").await.is_ok() })
            }),
        )
        .await
        .expect("the other account is not blocked");
        assert_eq!(other, Ok(true));
        assert!(!prompt.is_finished());
        assert!(host.0.host.try_lock().is_ok());
        release.send(()).unwrap();
        assert_eq!(prompt.await.unwrap(), Ok(true));
        assert!(host.lock().in_flight.is_empty());
    }

    fn real(
        dir: &Path,
        owner: &Arc<bh_device::Owner>,
    ) -> Session<Containers, FakeStore, PlainProtector> {
        Session::new(
            Containers {
                owner: Arc::clone(owner),
            },
            dir,
            FakeStore::default(),
            PlainProtector,
            classify_owner_error,
        )
    }

    /// A new process's session over `dir`. The earlier owner's background
    /// compaction may hold its files a moment after it is dropped; a new
    /// process never shares them.
    async fn reopened(
        dir: &Path,
        store: &FakeStore,
    ) -> (
        Arc<bh_device::Owner>,
        Session<Containers, FakeStore, PlainProtector>,
        Screen,
    ) {
        for _ in 0..400 {
            let owner = Arc::new(bh_device::Owner::default());
            let mut session = real(dir, &owner);
            session.store = store.clone();
            let screen = session.startup().await;
            if screen != Screen::Retry {
                return (owner, session, screen);
            }
            drop((session, owner));
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("the earlier owner never released its files");
    }

    /// A container holding only a journaled scanner identity, and maybe a
    /// kept join hint, as an interrupted join leaves it.
    async fn scanner_container(
        owner: &Arc<bh_device::Owner>,
        dir: &Path,
        store: &FakeStore,
        hint: bool,
    ) -> ContainerId {
        let id = owner.create_container(dir).unwrap();
        let database = owner.shared_database(id).unwrap();
        bh_account::pairing::scanner_identity(
            &mut DeviceJournal::from_shared(database),
            &mut store.clone(),
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        )
        .await
        .unwrap();
        if hint {
            owner
                .record_join_hint(id, bh_account::AccountId([4; 32]), b"opened hint")
                .unwrap();
        }
        id
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_interrupted_scan_is_welcome_and_its_identity_is_reused_to_join() {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::default();
        let scanner = {
            let owner = Arc::new(bh_device::Owner::default());
            scanner_container(&owner, dir.path(), &store, false).await
        };
        let (owner, session, screen) = reopened(dir.path(), &store).await;
        assert_eq!(screen, Screen::Welcome);
        let host = into_host(session);
        let lease = host.begin_join().unwrap();
        let database = owner.shared_database(lease.id).unwrap();
        assert!(
            database
                .lock()
                .unwrap()
                .device_identity()
                .unwrap()
                .is_some()
        );
        assert_eq!(
            host.lock()
                .session
                .as_ref()
                .unwrap()
                .opened
                .as_ref()
                .unwrap()
                .len(),
            1,
            "the interrupted scan's container, no new one"
        );
        assert!(lease.joined.is_none());
        let _ = scanner;
        host.return_join(lease);
        assert!(host.lock().in_flight.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kept_join_resumes_joining_and_is_never_ready_or_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::default();
        {
            let owner = Arc::new(bh_device::Owner::default());
            scanner_container(&owner, dir.path(), &store, true).await;
        }
        let (_owner, session, screen) = reopened(dir.path(), &store).await;
        assert!(matches!(screen, Screen::Joining { .. }), "{screen:?}");
        assert!(session.bound_container().is_none());
        let host = into_host(session);
        let lease = host.begin_join().unwrap();
        assert!(lease.joined.is_some(), "resumes the kept hint");
        host.return_join(lease);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn joining_is_refused_beside_an_existing_account() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let host = into_host(ready_on(&owner, dir.path()).await);
        assert!(host.begin_join().is_err(), "a ready account");
        // An account in setup, before its kit is saved, is not replaced either.
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let mut session = real(dir.path(), &owner);
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        let host = into_host(session);
        assert!(host.begin_join().is_err(), "an account in setup");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stopped_account_shows_its_stop_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let session = ready_on(&owner, dir.path()).await;
        let id = session.bound_container().unwrap();
        let file = {
            let mut found = None;
            for entry in std::fs::read_dir(dir.path().join("accounts")).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|x| x == "sqlite") {
                    found = Some(path);
                }
            }
            found.unwrap()
        };
        drop(session);
        drop(owner);
        let _ = id;
        rusqlite::Connection::open(file)
            .unwrap()
            .execute_batch("UPDATE account_state SET stopped = 1")
            .unwrap();
        let (_owner, session, screen) = reopened(dir.path(), &FakeStore::default()).await;
        assert_eq!(screen, Screen::Stopped);
        assert!(session.bound_container().is_none());
    }

    #[test]
    fn unavailable_note_engine_is_retryable_not_a_corrupt_account() {
        let error = OwnerError::from(bh_storage::StoreError::NoteUnavailable);
        assert_eq!(classify_owner_error(&error), OpenIssue::Busy);
        // A missing/mismatched verified continuation is still a different error.
        assert_eq!(
            classify_owner_error(&OwnerError::Unavailable),
            OpenIssue::Corrupt
        );
        let wrapped = OwnerError::Store(bh_storage::StoreError::NoteUnavailable);
        assert_eq!(classify_owner_error(&wrapped), OpenIssue::Busy);
    }

    #[test]
    fn transient_native_container_io_is_retryable_not_a_lost_identity() {
        assert_eq!(
            classify_owner_error(&OwnerError::Io(std::io::Error::other(
                "temporary file failure"
            ))),
            OpenIssue::Busy
        );
        assert_eq!(
            classify_owner_error(&OwnerError::Open(OpenError::NewerData {
                found: 10,
                supported: 9
            })),
            OpenIssue::NewerData
        );
        assert_eq!(
            classify_owner_error(&OwnerError::Open(OpenError::Database(
                rusqlite::Error::InvalidQuery
            ))),
            OpenIssue::Corrupt
        );
    }

    #[tokio::test]
    async fn real_newer_container_never_starts_another_identity() {
        let dir = tempfile::tempdir().unwrap();
        let accounts = dir.path().join("accounts");
        std::fs::create_dir_all(&accounts).unwrap();
        let path = accounts.join("11111111111111111111111111111111.sqlite");
        let newer_version = DeviceDatabase::open(":memory:").unwrap().data_version() + 1;
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", newer_version)
            .unwrap();
        let mut session = real_session(dir.path(), FakeStore::default());
        assert_eq!(session.startup().await, Screen::Update);
        assert_eq!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Update
        );
        assert_eq!(
            std::fs::read_dir(accounts)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "sqlite"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn cancelled_owner_prompt_is_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let store = FakeStore::default();
        let mut first = real_session(dir.path(), store.clone());
        assert!(matches!(
            first.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        assert_eq!(first.confirm_kit().await, Screen::Ready);
        drop(first);
        let path = std::fs::read_dir(dir.path().join("accounts"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.path().extension().is_some_and(|ext| ext == "sqlite"))
            .unwrap()
            .path();
        // Simulate a worker retaining the database after the old session drops.
        // Without the lock-free gate, Busy masks the cancelled prompt.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let held = loop {
            match DeviceDatabase::open(&path) {
                Ok(db) => break db,
                Err(OpenError::Busy) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(error) => panic!("container did not open: {error:?}"),
            }
        };
        let holder = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(held);
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match DeviceDatabase::open(&path) {
                Ok(db) => {
                    drop(db);
                    break;
                }
                Err(OpenError::Busy) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(error) => panic!("container lock did not become free: {error:?}"),
            }
        }
        holder.join().unwrap();
        store
            .cancel_next_load
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut reopened = real_session(dir.path(), store.clone());
        assert_eq!(reopened.startup().await, Screen::Retry);
        assert!(
            !store
                .cancel_next_load
                .load(std::sync::atomic::Ordering::SeqCst),
            "first startup must consume the cancelled prompt, not fail on a busy file"
        );
        assert_eq!(
            reopened.startup().await,
            Screen::Retry,
            "passive refresh cannot retry Keychain"
        );
        assert_eq!(reopened.retry().await, Screen::Ready);
        assert_eq!(
            std::fs::read_dir(dir.path().join("accounts"))
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "sqlite"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn failed_first_activation_waits_for_explicit_retry() {
        let h = Harness::new();
        let mut session = h.session();
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        h.store
            .fail_next_load
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(session.confirm_kit().await, Screen::Retry);
        assert_eq!(session.startup().await, Screen::Retry);
        assert_eq!(session.retry().await, Screen::Ready);
    }

    #[tokio::test]
    async fn per_file_open_errors_do_not_block_other_accounts_or_repeat_directory_open() {
        let h = Harness::new();
        let mut first = h.session();
        let _ = first.create("ripple amber horizon nectar willow").await;
        assert_eq!(first.confirm_kit().await, Screen::Ready);
        {
            let mut state = h.containers.state.lock().unwrap();
            state.open_errors.extend([
                ("busy".into(), OwnerError::Unbound),
                ("newer".into(), OwnerError::Changed),
                ("corrupt".into(), OwnerError::UnknownContainer),
            ]);
        }
        let mut reopened = h.session();
        assert_eq!(reopened.startup().await, Screen::Ready);
        assert_eq!(reopened.startup().await, Screen::Ready);
        assert_eq!(
            h.containers.state.lock().unwrap().open_calls,
            2,
            "one open per Owner: first session and reopened session"
        );
        assert!(reopened.bound_container().is_some());
    }

    #[tokio::test]
    async fn empty_container_is_reused_and_newer_data_is_not_adopted() {
        let h = Harness::new();
        let empty = h.containers.create_container(h.dir.path()).unwrap();
        let mut session = h.session();
        assert_eq!(session.startup().await, Screen::Welcome);
        assert_eq!(h.containers.state.lock().unwrap().is_empty_calls, 1);
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        assert!(
            session.bound_container().is_none(),
            "setup cannot bind a note"
        );
        assert_eq!(h.containers.state.lock().unwrap().ids[0], empty);
        assert_eq!(h.containers.state.lock().unwrap().is_empty_calls, 2);
        assert_eq!(
            h.sessions(),
            1,
            "reuse the empty container, do not leave an orphan file"
        );
        let newer = Harness::new();
        newer
            .containers
            .state
            .lock()
            .unwrap()
            .open_errors
            .push(("newer".into(), OwnerError::Changed));
        let mut reopened = newer.session();
        assert_eq!(reopened.startup().await, Screen::Update);
        assert!(reopened.bound_container().is_none());

        let busy = Harness::new();
        busy.containers
            .state
            .lock()
            .unwrap()
            .open_errors
            .push(("busy".into(), OwnerError::Unbound));
        let mut session = busy.session();
        assert_eq!(session.startup().await, Screen::Retry);
        assert_eq!(
            session.retry().await,
            Screen::Welcome,
            "explicit retry opens the directory again"
        );
    }

    #[tokio::test]
    async fn first_launch_offers_creation_and_resumes_its_kit_without_a_second_account() {
        let h = Harness::new();
        let mut session = h.session();
        assert_eq!(session.startup().await, Screen::Welcome);

        let Screen::Kit { code } = session.create("ripple amber horizon nectar willow").await
        else {
            panic!("expected the kit screen");
        };
        assert_eq!(code.len(), 34, "{code}");
        assert_eq!(h.sessions(), 1);
        assert!(
            session.bound_container().is_none(),
            "no note before kit confirmation and anchor"
        );
        let displayed = session
            .pending_code()
            .expect("code while setup is incomplete");
        assert_eq!(displayed.to_kit_text(), code);

        // Quitting and reopening resumes on the same kit with the same code.
        let mut resumed = h.session();
        assert_eq!(resumed.startup().await, Screen::Kit { code: code.clone() });
        assert_eq!(h.sessions(), 1, "a resume never creates another account");
        assert_eq!(
            resumed.create("ripple amber horizon nectar willow").await,
            Screen::Kit { code }
        );
        assert_eq!(
            h.sessions(),
            1,
            "repeating create resumes, never duplicates"
        );
    }

    #[tokio::test]
    async fn startup_completes_no_code_local_commit_after_interrupted_save() {
        let h = Harness::new();
        let mut setup = h.session();
        let _ = setup.create("ripple amber horizon nectar willow").await;
        let id = h.containers.state.lock().unwrap().ids[0];
        let path = h.containers.state.lock().unwrap().files[&id].clone();
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch("CREATE TRIGGER fail_local BEFORE INSERT ON account_events BEGIN SELECT RAISE(FAIL,'disk full'); END;").unwrap();
        assert_eq!(setup.confirm_kit().await, Screen::Unavailable);
        assert!(
            setup.pending_code().is_none(),
            "saved kit cannot reveal its code"
        );
        assert_eq!(h.anchors(), 0);
        raw.execute_batch("DROP TRIGGER fail_local").unwrap();
        drop(setup);
        let mut reopened = h.session();
        assert_eq!(reopened.startup().await, Screen::Ready);
        assert_eq!(reopened.bound_container(), Some(id));
        assert_eq!(h.sessions(), 1);
        assert_eq!(h.anchors(), 1);
    }

    #[tokio::test]
    async fn kit_confirmation_anchors_once_and_reopening_goes_straight_to_the_account() {
        let h = Harness::new();
        let mut session = h.session();
        let _ = session.create("ripple amber horizon nectar willow").await;
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        assert_eq!(
            session.bound_container(),
            h.containers.state.lock().unwrap().ids.first().copied()
        );
        assert_eq!(h.anchors(), 1);

        let mut reopened = h.session();
        assert_eq!(reopened.startup().await, Screen::Ready);
        assert_eq!(
            h.anchors(),
            2,
            "each activation anchors its checked projection"
        );
    }

    #[tokio::test]
    async fn transient_key_storage_failure_retries_without_readmission_or_new_identity() {
        let h = Harness::new();
        let mut first = h.session();
        first.create("ripple amber horizon nectar willow").await;
        assert_eq!(first.confirm_kit().await, Screen::Ready);
        let id = first.bound_container().unwrap();
        h.store
            .fail_next_load
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut reopened = h.session();
        assert_eq!(reopened.startup().await, Screen::Retry);
        assert!(reopened.verified_session().is_none());
        assert_eq!(reopened.retry().await, Screen::Ready);
        assert_eq!(reopened.bound_container(), Some(id));
        assert_eq!(h.sessions(), 1);
    }

    #[tokio::test]
    async fn unroutable_container_reports_the_return_route_and_keeps_its_rows() {
        let h = Harness::new();
        let mut session = h.session();
        let _ = session.create("ripple amber horizon nectar willow").await;
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        let id = session.bound_container().unwrap();
        drop(session);
        // The native device identity is lost: activation must not adopt or wipe.
        let path = h.containers.state.lock().unwrap().files[&id].clone();
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute("DELETE FROM account_device", []).unwrap();
        let before = raw
            .query_row("SELECT COUNT(*) FROM account_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        drop(raw);
        let anchors = h.anchors();
        let mut reopened = h.session();
        assert_eq!(reopened.startup().await, Screen::Return);
        assert_eq!(before, 3, "nothing is wiped");
        assert_eq!(h.anchors(), anchors, "a failed activation anchors nothing");
    }

    #[tokio::test]
    async fn retry_after_saved_kit_rechecks_activation_without_creating_an_account() {
        let h = Harness::new();
        let mut session = h.session();
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        let id = h.containers.state.lock().unwrap().ids[0];
        let keys = std::mem::take(&mut *h.store.keys.lock().unwrap());
        assert_eq!(session.confirm_kit().await, Screen::Return);
        *h.store.keys.lock().unwrap() = keys;
        assert_eq!(session.startup().await, Screen::Ready);
        assert_eq!(session.bound_container(), Some(id));
        assert_eq!(h.sessions(), 1);
        assert_eq!(
            h.containers
                .shared_database(id)
                .unwrap()
                .lock()
                .unwrap()
                .account_history()
                .unwrap()
                .len(),
            3,
            "retry must not commit a second history"
        );
    }

    #[tokio::test]
    async fn activation_failure_cannot_create_a_second_account() {
        let h = Harness::new();
        let mut first = h.session();
        let _ = first.create("ripple amber horizon nectar willow").await;
        assert_eq!(first.confirm_kit().await, Screen::Ready);
        let id = first.bound_container().unwrap();
        h.store.keys.lock().unwrap().clear();
        let mut reopened = h.session();
        assert_eq!(reopened.startup().await, Screen::Return);
        assert_eq!(
            reopened.create("ripple amber horizon nectar willow").await,
            Screen::Return
        );
        assert_eq!(h.sessions(), 1);
        assert!(h.containers.state.lock().unwrap().ids.contains(&id));
    }

    #[tokio::test]
    async fn stale_welcome_hint_cannot_start_another_genesis() {
        let h = Harness::new();
        let mut first = h.session();
        let _ = first.create("ripple amber horizon nectar willow").await;
        assert_eq!(first.confirm_kit().await, Screen::Ready);
        let id = first.bound_container().unwrap();
        // A stale Welcome is only a hint, never proof that this file is empty.
        let mut stale = h.session();
        stale.opened = Some(vec![("existing".into(), Ok(id))]);
        stale.screen = Some(Screen::Welcome);
        assert_eq!(
            stale.create("ripple amber horizon nectar willow").await,
            Screen::Retry
        );
        assert_eq!(h.sessions(), 1);
    }

    #[tokio::test]
    async fn failed_directory_open_never_creates_a_container() {
        let h = Harness::new();
        h.containers.state.lock().unwrap().fail_open = true;
        let mut session = h.session();
        assert_eq!(session.startup().await, Screen::Retry);
        assert_eq!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Unavailable
        );
        assert_eq!(h.sessions(), 0);
        h.containers.state.lock().unwrap().fail_open = false;
        assert_eq!(session.retry().await, Screen::Welcome);
    }

    #[tokio::test]
    async fn unfinished_setup_does_not_leave_an_existing_account_unanchored() {
        let h = Harness::new();
        let mut first = h.session();
        let _ = first.create("ripple amber horizon nectar willow").await;
        assert_eq!(first.confirm_kit().await, Screen::Ready);
        let second_id = h.containers.create_container(h.dir.path()).unwrap();
        let mut setup = h.session().owner(second_id).unwrap();
        setup
            .begin_first_device(
                ControlKeyPolicy::AppEnforcedOwnerConfirmation,
                &Password::new("copper lantern velvet river pebble").unwrap(),
            )
            .await
            .unwrap();
        let mut reopened = h.session();
        assert_eq!(reopened.startup().await, Screen::Ready);
        assert_eq!(
            h.anchors(),
            2,
            "ready account must be anchored while the new kit is pending"
        );
    }

    #[tokio::test]
    async fn startup_publishes_first_available_account_without_prompting_unrelated_accounts() {
        let h = Harness::new();
        let mut first = h.session();
        let _ = first.create("ripple amber horizon nectar willow").await;
        assert_eq!(first.confirm_kit().await, Screen::Ready);
        let second_id = h.containers.create_container(h.dir.path()).unwrap();
        let mut second = h.session().owner(second_id).unwrap();
        second
            .begin_first_device(
                ControlKeyPolicy::AppEnforcedOwnerConfirmation,
                &Password::new("copper lantern velvet river pebble").unwrap(),
            )
            .await
            .unwrap();
        second.confirm_kit_saved().unwrap();
        let handle = h
            .containers
            .shared_database(second_id)
            .unwrap()
            .lock()
            .unwrap()
            .device_identity()
            .unwrap()
            .unwrap()
            .handle;
        *h.store.delayed_handle.lock().unwrap() = Some(handle);
        let mut reopened = h.session();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(100), reopened.startup())
                .await
                .unwrap(),
            Screen::Ready
        );
        assert_eq!(h.anchors(), 2, "unrelated account remains lazy");
        let selected = reopened.bound_container();
        let mut worker = reopened.take_work(Some(second_id));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), worker.startup())
                .await
                .is_err()
        );
        assert_eq!(reopened.bound_container(), selected);
        assert!(reopened.verified_session().is_some());
        *h.store.delayed_handle.lock().unwrap() = None;
        assert_eq!(worker.startup().await, Screen::Ready);
        reopened.restore_work(worker);
        assert_eq!(reopened.bound_container(), selected);
        assert_eq!(h.sessions(), 2);
        let generations: Vec<_> = reopened.generations.values().cloned().collect();
        assert_eq!(generations.len(), 2);
        assert!(
            generations
                .iter()
                .all(|generation| generation.current() == 0)
        );
        reopened.stop();
        assert!(
            generations
                .iter()
                .all(|generation| generation.current() == 1),
            "stop fences every account under its own file guard"
        );
    }

    #[test]
    fn separate_account_files_have_independent_writer_guards() {
        let h = Harness::new();
        let first = h.containers.create_container(h.dir.path()).unwrap();
        let second = h.containers.create_container(h.dir.path()).unwrap();
        let first_database = h.containers.shared_database(first).unwrap();
        let first_guard = first_database.lock().unwrap();
        let second_database = h.containers.shared_database(second).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let db = second_database.lock().unwrap();
            tx.send(db.account_state().is_ok()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap(),
            "the second account must not wait for the first account's writer guard"
        );
        drop(first_guard);
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn several_containers_do_not_block_each_other_and_only_one_is_routed() {
        let h = Harness::new();
        let mut first = h.session();
        let Screen::Kit { code } = first.create("ripple amber horizon nectar willow").await else {
            panic!("expected kit");
        };
        let id = h.containers.state.lock().unwrap().ids[0];
        // A second, unrelated account container that is still in setup.
        let mut owner = h
            .session()
            .owner(h.containers.create_container(h.dir.path()).unwrap())
            .unwrap();
        assert!(owner.setup_status().unwrap().is_none(), "still empty");
        assert!(
            owner
                .begin_first_device(
                    ControlKeyPolicy::AppEnforcedOwnerConfirmation,
                    &Password::new("copper lantern velvet river pebble").unwrap(),
                )
                .await
                .is_ok()
        );
        assert_eq!(h.sessions(), 2, "two accounts, two files");
        assert_ne!(h.containers.state.lock().unwrap().ids[1], id);
        // A fresh session resumes whichever is in setup without duplicating or
        // wiping the other container.
        let mut resumed = h.session();
        assert!(matches!(resumed.startup().await, Screen::Kit { .. }));
        assert_eq!(h.sessions(), 2);
        assert_eq!(code.len(), 34);
    }

    #[tokio::test]
    async fn verified_erasure_removes_keys_files_and_marker_and_freezes_its_count() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let accounts = ready_test_host(&owner, dir.path(), store.clone()).await;
        let id = {
            let guard = accounts.lock();
            guard.session.as_ref().unwrap().current_id().unwrap()
        };
        let name = {
            let guard = accounts.lock();
            guard
                .session
                .as_ref()
                .unwrap()
                .containers
                .container_name(id)
                .unwrap()
        };
        let database = dir.path().join("accounts").join(format!("{name}.sqlite"));
        assert!(database.exists());
        assert!(!store.keys.lock().unwrap().is_empty());
        assert_eq!(
            accounts.erase_removed(id).await,
            Some(Screen::Erased { unsent: 0 })
        );
        assert!(!database.exists(), "the container's data is gone");
        assert!(
            !dir.path()
                .join("accounts")
                .join(format!("{name}.erasing"))
                .exists(),
            "the marker is cleared only after every step"
        );
        assert!(store.keys.lock().unwrap().is_empty(), "the keys are gone");
        // A later start finds no account: nothing was left half-erased.
        let mut resumed = Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir.path(),
            store,
            PlainProtector,
            classify_owner_error,
        );
        assert_eq!(resumed.startup().await, Screen::Welcome);
    }

    #[tokio::test]
    async fn failed_container_removal_keeps_the_marker_and_resumes_from_it() {
        let h = Harness::new();
        let mut session = h.session();
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        let id = session.current_id().unwrap();
        let name = session.containers.container_name(id).unwrap();
        let marker = h
            .dir
            .path()
            .join("accounts")
            .join(format!("{name}.erasing"));
        h.containers.state.lock().unwrap().fail_remove = true;
        assert_eq!(
            session.erase_removed(id).await,
            Screen::EraseIncomplete { failed: 2 }
        );
        assert!(marker.exists(), "a failed step keeps its marker");
        assert!(
            h.store.keys.lock().unwrap().is_empty(),
            "the keys step completed before the container step failed"
        );
        h.containers.state.lock().unwrap().fail_remove = false;
        let mut resumed = h.session();
        assert_eq!(resumed.startup().await, Screen::Erased { unsent: 0 });
        assert!(!marker.exists());
        assert_eq!(h.sessions(), 0, "the container is gone");
    }

    #[tokio::test]
    async fn failed_key_erasure_keeps_step_zero_and_never_reports_erased() {
        let h = Harness::new();
        let mut session = h.session();
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        let id = session.current_id().unwrap();
        let name = session.containers.container_name(id).unwrap();
        let marker = h
            .dir
            .path()
            .join("accounts")
            .join(format!("{name}.erasing"));
        h.store
            .fail_erase
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            session.erase_removed(id).await,
            Screen::EraseIncomplete { failed: 1 }
        );
        assert!(marker.exists());
        assert_eq!(h.sessions(), 1, "the container is untouched");
        let mut resumed = h.session();
        assert_eq!(resumed.startup().await, Screen::Erased { unsent: 0 });
        assert!(!marker.exists());
        assert_eq!(h.sessions(), 0);
    }

    #[tokio::test]
    async fn resumed_erasure_uses_the_retained_handle_after_the_database_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let accounts = ready_test_host(&owner, dir.path(), store.clone()).await;
        let (id, database, handle) = {
            let guard = accounts.lock();
            let session = guard.session.as_ref().unwrap();
            let id = session.current_id().unwrap();
            let name = session.containers.container_name(id).unwrap();
            let database = dir.path().join("accounts").join(format!("{name}.sqlite"));
            let handle = session
                .containers
                .shared_database(id)
                .unwrap()
                .lock()
                .unwrap()
                .device_identity()
                .unwrap()
                .unwrap()
                .handle;
            (name, database, bh_account::platform::KeyHandle(handle))
        };
        let _ = id;
        // A crash after the marker was written and the database removed: only
        // the marker's retained handle can finish erasing the keys.
        assert!(
            write_marker(
                dir.path(),
                &id,
                Erasing {
                    unsent: 7,
                    step: 0,
                    handle: Some(handle),
                },
            )
            .is_ok()
        );
        for file in [
            database.clone(),
            PathBuf::from(format!("{}-wal", database.display())),
            PathBuf::from(format!("{}-shm", database.display())),
            database.with_extension("lock"),
        ] {
            let _ = std::fs::remove_file(file);
        }
        drop(accounts);
        let mut resumed = Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir.path(),
            store.clone(),
            PlainProtector,
            classify_owner_error,
        );
        assert_eq!(resumed.startup().await, Screen::Erased { unsent: 7 });
        assert!(store.keys.lock().unwrap().is_empty());
        assert!(
            !dir.path()
                .join("accounts")
                .join(format!("{id}.erasing"))
                .exists()
        );
    }

    #[tokio::test]
    async fn erasing_one_account_leaves_another_usable() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let (accounts, [first, second]) =
            two_ready_test_host(&owner, dir.path(), store.clone()).await;
        assert_eq!(
            accounts.erase_removed(first).await,
            Some(Screen::Erased { unsent: 0 })
        );
        {
            let guard = accounts.lock();
            let session = guard.session.as_ref().unwrap();
            assert!(!session.capabilities.contains_key(&first));
            assert!(
                session.capabilities.contains_key(&second),
                "the unrelated account keeps its authority"
            );
        }
        let _ = second;
        drop(accounts);
        // The previous process's file locks must be gone before a new Owner
        // opens the container again.
        drop(owner);
        // A new start opens what remains: one account file, still Ready.
        let mut resumed = Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir.path(),
            store,
            PlainProtector,
            classify_owner_error,
        );
        assert_eq!(resumed.startup().await, Screen::Ready);
        let files = std::fs::read_dir(dir.path().join("accounts"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".sqlite"))
            })
            .count();
        assert_eq!(files, 1, "only the unrelated account remains");
    }

    /// The marker beside container `name`, under `dir`.
    fn marker(dir: &Path, name: &str) -> PathBuf {
        dir.join("accounts").join(format!("{name}.erasing"))
    }

    /// A ready account in the harness and its marker's stable name.
    async fn harness_ready(h: &Harness) -> (ContainerId, String, KeyHandleBytes) {
        let mut session = h.session();
        assert!(matches!(
            session.create("ripple amber horizon nectar willow").await,
            Screen::Kit { .. }
        ));
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        let id = session.current_id().unwrap();
        let name = session.containers.container_name(id).unwrap();
        let handle = session
            .containers
            .shared_database(id)
            .unwrap()
            .lock()
            .unwrap()
            .device_identity()
            .unwrap()
            .unwrap()
            .handle;
        (id, name, handle)
    }
    type KeyHandleBytes = [u8; 32];

    #[tokio::test]
    async fn a_resumed_erasure_keeps_its_final_screen_after_restart() {
        let h = Harness::new();
        let (_, name, handle) = harness_ready(&h).await;
        // A crash right after the marker was written.
        write_marker(
            h.dir.path(),
            &name,
            Erasing {
                unsent: 4,
                step: 0,
                handle: Some(bh_account::platform::KeyHandle(handle)),
            },
        )
        .unwrap();
        let mut resumed = h.session();
        assert_eq!(resumed.startup().await, Screen::Erased { unsent: 4 });
        // A window asking again, as the page does on load, still sees it.
        assert_eq!(resumed.screen, Some(Screen::Erased { unsent: 4 }));
        assert_eq!(resumed.startup().await, Screen::Erased { unsent: 4 });
    }

    #[tokio::test]
    async fn an_unreadable_marker_resumes_from_its_database() {
        let h = Harness::new();
        let (_, name, _) = harness_ready(&h).await;
        // A marker cut short, as no atomic update can leave it but a damaged
        // disk might: the count and handle are read again from the database.
        std::fs::create_dir_all(h.dir.path().join("accounts")).unwrap();
        std::fs::write(marker(h.dir.path(), &name), "unsent 3\nst").unwrap();
        let mut resumed = h.session();
        assert_eq!(resumed.startup().await, Screen::Erased { unsent: 0 });
        assert!(h.store.keys.lock().unwrap().is_empty(), "keys erased");
        assert_eq!(h.sessions(), 0, "the container is gone");
        assert!(!marker(h.dir.path(), &name).exists());
    }

    #[tokio::test]
    async fn an_unreadable_marker_without_its_database_never_claims_erased() {
        let h = Harness::new();
        let (id, name, _) = harness_ready(&h).await;
        // The database went first; then the marker was damaged. Its retained
        // key handle is unknown, so nothing may report the keys erased.
        h.containers.remove_container(id).unwrap();
        std::fs::create_dir_all(h.dir.path().join("accounts")).unwrap();
        std::fs::write(marker(h.dir.path(), &name), "unsent 3\nst").unwrap();
        let mut resumed = h.session();
        assert_eq!(
            resumed.startup().await,
            Screen::EraseIncomplete { failed: 0 }
        );
        assert!(marker(h.dir.path(), &name).exists(), "the marker stays");
    }

    #[tokio::test]
    async fn a_marked_account_whose_erasure_cannot_resume_is_never_offered() {
        let h = Harness::new();
        let (_, name, _) = harness_ready(&h).await;
        std::fs::create_dir_all(h.dir.path().join("accounts")).unwrap();
        std::fs::write(marker(h.dir.path(), &name), "unsent 3\nst").unwrap();
        // Its count can no longer be read either, so the erasure cannot start
        // again; the verified removal still stands.
        let conn = rusqlite::Connection::open(h.dir.path().join(format!("{name}.sqlite"))).unwrap();
        conn.execute_batch("DROP TABLE data_pending;").unwrap();
        drop(conn);
        let mut resumed = h.session();
        assert_eq!(
            resumed.startup().await,
            Screen::EraseIncomplete { failed: 0 }
        );
        assert_eq!(resumed.bound_container(), None);
        assert!(
            resumed.capabilities.is_empty(),
            "no authority was activated"
        );
    }

    #[test]
    fn a_marker_update_replaces_the_file_rather_than_rewriting_it() {
        let dir = tempfile::tempdir().unwrap();
        let first = Erasing {
            unsent: 2,
            step: 0,
            handle: Some(bh_account::platform::KeyHandle([7; 32])),
        };
        write_marker(dir.path(), "account", first).unwrap();
        // A second name for the old marker's bytes: an in-place rewrite would
        // change them, and a crash midway would leave them cut short.
        let kept = dir.path().join("kept");
        std::fs::hard_link(marker(dir.path(), "account"), &kept).unwrap();
        let before = std::fs::read(&kept).unwrap();
        write_marker(
            dir.path(),
            "account",
            Erasing {
                unsent: 2,
                step: 1,
                handle: Some(bh_account::platform::KeyHandle([7; 32])),
            },
        )
        .unwrap();
        assert_eq!(std::fs::read(&kept).unwrap(), before);
        assert_eq!(read_marker(dir.path(), "account").unwrap().step, 1);
    }

    #[tokio::test]
    async fn an_identity_read_error_stops_erasure_before_any_destructive_step() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let accounts = ready_test_host(&owner, dir.path(), store.clone()).await;
        let (id, _, _) = accounts.note_authority().unwrap();
        let name = accounts.container_name(id).unwrap();
        let database = dir.path().join("accounts").join(format!("{name}.sqlite"));
        let conn = rusqlite::Connection::open(&database).unwrap();
        conn.execute_batch(
            "PRAGMA ignore_check_constraints=ON;
             UPDATE account_device SET handle=x'00' WHERE id=1;",
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            accounts.erase_removed(id).await,
            Some(Screen::EraseIncomplete { failed: 0 })
        );
        assert!(!marker(dir.path(), &name).exists(), "no marker was written");
        assert!(!store.keys.lock().unwrap().is_empty(), "keys untouched");
        assert!(database.exists(), "the container is untouched");
    }

    #[tokio::test]
    async fn an_editor_commit_racing_erasure_is_refused_or_counted() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let accounts = ready_test_host(&owner, dir.path(), store.clone()).await;
        let (id, cap, base) = accounts.note_authority().unwrap();
        owner.authorize(id, cap, base).unwrap();
        owner.open_home("main", id).unwrap();
        let note = owner.bound_note("main").unwrap();
        let opened = owner.open_leased("main", note).unwrap();
        let lease = opened.writer.unwrap();
        let mut author = bh_device::Owner::core_author(&opened).unwrap();
        let delta = author.try_append_paragraph("saved before").unwrap();
        owner
            .commit_leased("main", opened.generation, lease.token, [1; 16], &delta)
            .unwrap();
        // An editor still holding its lease commits while the keys are erased,
        // after the count and before the container goes.
        let committed = Arc::new(StdMutex::new(None));
        *store.during_erase.lock().unwrap() = Some(Box::new({
            let (owner, committed) = (Arc::clone(&owner), Arc::clone(&committed));
            let generation = opened.generation;
            move || {
                let delta = author.try_append_paragraph("typed during erasure").unwrap();
                let result = owner.commit_leased("main", generation, lease.token, [2; 16], &delta);
                *committed.lock().unwrap() = Some(result.is_ok());
            }
        }));
        let screen = accounts.erase_removed(id).await;
        let during = committed.lock().unwrap().expect("the editor tried");
        assert_eq!(
            screen,
            Some(Screen::Erased {
                unsent: 1 + u64::from(during)
            }),
            "a commit the erasure deletes must be in its count"
        );
        assert!(!during, "routes ended before the count");
    }

    #[tokio::test]
    async fn erasing_another_account_keeps_the_current_one_routed() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let (accounts, [first, second]) =
            two_ready_test_host(&owner, dir.path(), store.clone()).await;
        assert_eq!(accounts.screen(), Some(Screen::Ready));
        assert_eq!(
            accounts.erase_removed(second).await,
            Some(Screen::Erased { unsent: 0 })
        );
        assert_eq!(accounts.screen(), Some(Screen::Ready));
        let guard = accounts.lock();
        let session = guard.session.as_ref().unwrap();
        assert_eq!(session.bound_container(), Some(first));
    }

    /// A native signing worker can still hold the removed account's owner
    /// after sync has stopped. Its erasure must wait for that owner to return,
    /// not silently skip the only erasure attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verified_erasure_waits_for_a_lent_owner_and_shows_failed_key_erasure() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let accounts = ready_test_host(&owner, dir.path(), store.clone()).await;
        let (id, cap) = accounts.ready_authority().unwrap();
        let (entered, lent) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let lending = tokio::spawn({
            let accounts = accounts.clone();
            async move {
                accounts
                    .run_lent(id, &cap, move |_, _| {
                        Box::pin(async move {
                            let _ = entered.send(());
                            let _ = released.await;
                        })
                    })
                    .await
            }
        });
        lent.await.unwrap();
        store
            .fail_erase
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let erasing = accounts.erase_removed(id);
        tokio::pin!(erasing);
        assert!(
            matches!(
                futures_util::poll!(erasing.as_mut()),
                std::task::Poll::Pending
            ),
            "a lent owner must not make verified erasure return early"
        );
        release.send(()).unwrap();
        lending.await.unwrap().unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(20), erasing)
                .await
                .expect("erasure completes when the owner returns"),
            Some(Screen::EraseIncomplete { failed: 1 })
        );
        assert_eq!(
            accounts.screen(),
            Some(Screen::EraseIncomplete { failed: 1 })
        );
        assert!(!store.keys.lock().unwrap().is_empty(), "keys retained");
    }

    /// A verified removal must survive a quit during an outstanding native
    /// prompt even when another account takes the Ready screen on restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verified_removal_during_lent_owner_resumes_beside_a_healthy_account() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let (accounts, [healthy, removed]) =
            two_ready_test_host(&owner, dir.path(), store.clone()).await;
        let name = accounts.container_name(removed).unwrap();
        let healthy_name = accounts.container_name(healthy).unwrap();
        let removed_handle = accounts
            .lock()
            .session
            .as_ref()
            .unwrap()
            .containers
            .shared_database(removed)
            .unwrap()
            .lock()
            .unwrap()
            .device_identity()
            .unwrap()
            .unwrap()
            .handle;
        let cap = accounts.ready_parts(removed).unwrap().capability;
        let (entered, lent) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let lending = tokio::spawn({
            let accounts = accounts.clone();
            async move {
                accounts
                    .run_lent(removed, &cap, move |_, _| {
                        Box::pin(async move {
                            let _ = entered.send(());
                            let _ = released.await;
                        })
                    })
                    .await
            }
        });
        lent.await.unwrap();
        {
            let erasing = accounts.erase_removed(removed);
            tokio::pin!(erasing);
            assert!(matches!(
                futures_util::poll!(erasing.as_mut()),
                std::task::Poll::Pending
            ));
            assert!(
                marker(dir.path(), &name).exists(),
                "verified intent is durable"
            );
            assert!(store.keys.lock().unwrap().contains_key(&removed_handle));
            // The caller is gone before the native worker gives the owner back.
        }
        release.send(()).unwrap();
        lending.await.unwrap().unwrap();
        drop(accounts);
        drop(owner);
        let mut resumed = Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir.path(),
            store.clone(),
            PlainProtector,
            classify_owner_error,
        );
        assert_eq!(resumed.startup().await, Screen::Ready);
        assert_eq!(
            resumed
                .current_id()
                .and_then(|id| resumed.containers.container_name(id).ok()),
            Some(healthy_name)
        );
        assert!(
            !dir.path()
                .join("accounts")
                .join(format!("{name}.sqlite"))
                .exists()
        );
        assert!(!marker(dir.path(), &name).exists());
        assert!(!store.keys.lock().unwrap().contains_key(&removed_handle));
    }

    #[tokio::test]
    async fn erasing_another_account_while_the_current_one_is_lent_keeps_it_routed() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let (accounts, [first, second]) =
            two_ready_test_host(&owner, dir.path(), store.clone()).await;
        let (routed, cap) = accounts.ready_authority().unwrap();
        assert_eq!(routed, first);
        // The current account's owner is out on a worker for the whole
        // erasure of the other account.
        let (arrived, lent) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let lending = tokio::spawn({
            let accounts = accounts.clone();
            async move {
                accounts
                    .run_lent(first, &cap, move |_, _| {
                        Box::pin(async move {
                            let _ = arrived.send(());
                            let _ = released.await;
                        })
                    })
                    .await
            }
        });
        lent.await.unwrap();
        assert_eq!(
            accounts.erase_removed(second).await,
            Some(Screen::Erased { unsent: 0 })
        );
        release.send(()).unwrap();
        lending.await.unwrap().unwrap();
        assert_eq!(accounts.screen(), Some(Screen::Ready));
        let guard = accounts.lock();
        let session = guard.session.as_ref().unwrap();
        assert_eq!(session.bound_container(), Some(first));
    }

    #[tokio::test]
    async fn one_stuck_erasure_leaves_the_other_account_usable() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let (accounts, [first, second]) =
            two_ready_test_host(&owner, dir.path(), store.clone()).await;
        let stuck = accounts.container_name(first).unwrap();
        let usable = accounts.container_name(second).unwrap();
        let handle = {
            let guard = accounts.lock();
            let session = guard.session.as_ref().unwrap();
            session
                .containers
                .shared_database(first)
                .unwrap()
                .lock()
                .unwrap()
                .device_identity()
                .unwrap()
                .unwrap()
                .handle
        };
        write_marker(
            dir.path(),
            &stuck,
            Erasing {
                unsent: 0,
                step: 0,
                handle: Some(bh_account::platform::KeyHandle(handle)),
            },
        )
        .unwrap();
        drop(accounts);
        drop(owner);
        // The platform refuses the stuck account's key deletion this start.
        store
            .fail_erase
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut resumed = Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir.path(),
            store,
            PlainProtector,
            classify_owner_error,
        );
        assert_eq!(resumed.startup().await, Screen::Ready);
        let current = resumed.current_id().unwrap();
        assert_eq!(resumed.containers.container_name(current).unwrap(), usable);
        assert!(marker(dir.path(), &stuck).exists(), "its marker stays");
        assert_eq!(resumed.incomplete_erasures.get(&stuck), Some(&1));
        // The next start finishes it from the marker and still opens the other.
        let store = resumed.store.clone();
        drop(resumed);
        let mut again = Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir.path(),
            store,
            PlainProtector,
            classify_owner_error,
        );
        assert_eq!(again.startup().await, Screen::Ready);
        assert!(!marker(dir.path(), &stuck).exists());
        let stuck_file = dir.path().join("accounts").join(format!("{stuck}.sqlite"));
        assert!(!stuck_file.exists(), "the stuck account's data is gone");
    }

    #[tokio::test]
    async fn a_leftover_marker_temp_is_removed_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let store = FakeStore::default();
        let accounts = ready_test_host(&owner, dir.path(), store.clone()).await;
        let (id, _) = accounts.ready_authority().unwrap();
        let name = accounts.container_name(id).unwrap();
        // A crash between writing a marker update and renaming it over the
        // marker leaves only the temp, which is never a marker.
        let temp = dir
            .path()
            .join("accounts")
            .join(format!("{name}.erasing.tmp"));
        std::fs::write(&temp, "unsent 0\nstep 1\nhandle \n").unwrap();
        drop(accounts);
        drop(owner);
        let mut resumed = Session::new(
            Containers {
                owner: Arc::new(bh_device::Owner::default()),
            },
            dir.path(),
            store,
            PlainProtector,
            classify_owner_error,
        );
        assert_eq!(resumed.startup().await, Screen::Ready);
        assert!(!temp.exists(), "the temp is cleaned");
        assert!(!marker(dir.path(), &name).exists());
        assert_eq!(
            resumed
                .containers
                .container_name(resumed.current_id().unwrap())
                .unwrap(),
            name
        );
    }
}
