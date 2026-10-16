//! Native first-account orchestration for the bundled client.
//!
//! The page sends only a password and receives screen state. This module owns
//! the container directory, the account owner, the native key stores and the
//! kit destinations; no WebView value names a container, path, key or account.
//!
//! The native container owner owns files. `ContainerOwner` keeps the app's
//! real, file-locked owner behind a narrow testable adapter.
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use bh_account::{
    VerifiedAccount,
    journal::PendingSetupProtector,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner, SetupError},
    platform::{ControlKeyPolicy, DeviceKeyStore},
    recovery::{Password, RecoveryCode},
    storage::DeviceJournal,
};
use bh_device::{ContainerId, OwnerError};
use bh_storage::{DeviceDatabase, OpenError};
use serde::Serialize;

#[cfg(not(target_os = "macos"))]
use crate::account_stub::{Destination, KitProtector, LoginStore, email_kit, save_kit_file};
#[cfg(target_os = "macos")]
use crate::native::bridge::{Destination, KitProtector, LoginStore, email_kit, save_kit_file};

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
}

/// Screen state only. No account id, container id, key handle or code leaves
/// here except the recovery code, which the person must save.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "screen", rename_all = "snake_case")]
pub enum Screen {
    Welcome,
    Return,
    Retry,
    Update,
    Kit { code: String },
    Ready,
    Unavailable,
}

struct Session<C, S, P> {
    containers: C,
    directory: PathBuf,
    store: S,
    protector: P,
    classify_open_issue: fn(&OwnerError) -> OpenIssue,
    generations: HashMap<ContainerId, AccountGeneration>,
    capabilities: HashMap<ContainerId, Arc<AccountCapability>>,
    own_bases: HashMap<ContainerId, bh_device::own_base::OwnBase>,
    opened: Option<Vec<(String, Result<ContainerId, OwnerError>)>>,
    retry_open: bool,
    screen: Option<Screen>,
    current: Option<(ContainerId, AccountOwner<DeviceJournal, S, P>)>,
    others: HashMap<ContainerId, AccountOwner<DeviceJournal, S, P>>,
}

impl<C, S, P> Session<C, S, P>
where
    C: ContainerOwner + Clone,
    S: DeviceKeyStore + Clone,
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
        if self.opened.is_none() {
            self.opened = work.opened.take();
        }
        if self.current.is_none() {
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
        let mut retry = false;
        let mut busy = false;
        let mut newer = false;
        let mut corrupt = false;
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
                    self.current = Some((id, owner));
                    self.screen = Some(Screen::Ready);
                    return Screen::Ready;
                }
                Ok(_) => corrupt = true,
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
        if newer {
            Screen::Update
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
        self.capabilities.clear();
        self.own_bases.clear();
        self.screen = None;
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
        let id = self.current.as_ref()?.0;
        self.own_bases.get(&id)?.with_keys(|_, _| ()).ok()?;
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "native session seam for incoming sync")
    )]
    pub fn verified_session(&self) -> Option<(&AccountCapability, &VerifiedAccount)> {
        let id = self.bound_container()?;
        let capability = self.capabilities.get(&id)?;
        let owner = &self.current.as_ref()?.1;
        Some((capability, owner.verified(capability).ok()?))
    }
}

type ReadyAccount = (Arc<AccountCapability>, bh_device::own_base::OwnBase);
type NoteAuthority = (ContainerId, Arc<AccountCapability>, [u8; 32]);

/// What `window` shows after activation, and the windows to reopen.
pub(crate) struct Restored {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the shown note, checked by tests")
    )]
    pub note: [u8; 32],
    pub main: Option<crate::note_host::Restore>,
    pub others: Vec<crate::note_host::Restore>,
}
/// Install this account's authority (unchanged if already current), then show
/// the first restart record's note in `window` (else its home note). Records
/// are consumed once, only after this fresh authority, and are never it: each
/// note is shown through the owner's capability, anchor and catalogue checks.
fn open_account_notes(
    owner: &bh_device::Owner,
    window: &str,
    (id, capability, own_base): NoteAuthority,
) -> Result<Restored, OwnerError> {
    owner.authorize(id, capability, own_base)?;
    let mut plan = owner
        .take_authorized_view_records(id)
        .map(crate::note_host::plan_restore)
        .unwrap_or_default()
        .into_iter();
    while let Some(main) = plan.next() {
        if owner.show_note(window, id, main.note).is_ok() {
            return Ok(Restored {
                note: main.note,
                main: Some(main),
                others: plan.collect(),
            });
        }
    }
    Ok(Restored {
        note: owner.open_home(window, id)?,
        main: None,
        others: Vec::new(),
    })
}

/// Establish the real signup base before publishing native readiness or anchoring
/// the container. Admission outcomes remain distinct from retryable failures.
async fn activate<C, S, P>(
    containers: &C,
    id: ContainerId,
    owner: &mut AccountOwner<DeviceJournal, S, P>,
) -> Result<Option<ReadyAccount>, bh_account::owner::OwnerError>
where
    C: ContainerOwner,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    use bh_account::{journal::JournalError, owner::OwnerError as AccountError};
    let AccountLoad::Active(capability) = owner.activate().await? else {
        return Ok(None);
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
    Ok(Some((capability, base)))
}

// ---- Tauri command surface ----

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
}

pub struct AccountHost {
    session: Option<Session<Containers, LoginStore, KitProtector>>,
    suggested: Option<String>,
    in_flight: std::collections::HashSet<Option<ContainerId>>,
}

impl AccountHost {
    pub fn with_owner(owner: Arc<bh_device::Owner>) -> Self {
        // Without the user's durable home, do not create an identity in /tmp.
        let session = directory_for_home(std::env::var_os("HOME")).map(|directory| {
            Session::new(
                Containers { owner },
                directory,
                LoginStore,
                KitProtector,
                classify_real_owner_error,
            )
        });
        Self {
            session,
            suggested: None,
            in_flight: std::collections::HashSet::new(),
        }
    }
}

impl Drop for AccountHost {
    fn drop(&mut self) {
        if let Some(session) = self.session.as_mut() {
            session.stop();
        }
    }
}

impl AccountHost {
    pub fn into_state(self) -> SharedAccountHost {
        Arc::new(tokio::sync::Mutex::new(self))
    }
}

fn classify_real_owner_error(error: &OwnerError) -> OpenIssue {
    match error {
        OwnerError::Busy
        | OwnerError::Open(OpenError::Busy)
        | OwnerError::Io(_)
        | OwnerError::Open(OpenError::LockFile(_)) => OpenIssue::Busy,
        OwnerError::Open(OpenError::NewerData { .. }) => OpenIssue::NewerData,
        _ => OpenIssue::Corrupt,
    }
}

/// The container owner appends `accounts/` beneath this app-data directory.
fn directory_for_home(home: Option<std::ffi::OsString>) -> Option<PathBuf> {
    home.filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .map(|base| {
            base.join("Library/Application Support")
                .join(crate::APP_IDENTIFIER)
        })
}

pub type SharedAccountHost = Arc<tokio::sync::Mutex<AccountHost>>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordScreen {
    screen: &'static str,
    suggested: String,
    error: Option<&'static str>,
}

enum AccountOperation {
    Startup,
    Retry,
    Create(String),
    ConfirmKit,
}

/// Run the native-store future on a dedicated worker with its own current-
/// thread executor. LocalAuthentication retains a !Send Objective-C context
/// across its await, so it cannot be an ordinary Tauri Send command future.
/// The short registry lock is released before the prompt; the shared SQLite
/// mutex is acquired only inside synchronous DeviceJournal calls.
async fn run_account(
    state: &tauri::State<'_, SharedAccountHost>,
    operation: AccountOperation,
) -> Result<Screen, String> {
    let (mut session, target) = {
        let mut host = state.lock().await;
        let registry = host.session.as_ref().ok_or("account unavailable")?;
        if matches!(operation, AccountOperation::Startup)
            && let Some(screen) = registry.cached_screen()
        {
            return Ok(screen);
        }
        let target = registry.current.as_ref().map(|(id, _)| *id);
        if target.is_none() && !host.in_flight.is_empty() {
            return Err("account busy".into());
        }
        if !host.in_flight.insert(target) {
            return Err("account busy".into());
        }
        (
            host.session.as_mut().expect("checked").take_work(target),
            target,
        )
    };
    // Restoration belongs to the worker, not the awaiting IPC future: closing
    // the WebView during a Keychain prompt must not strand the one session.
    let restore = Arc::clone(state.inner());
    let completed = tauri::async_runtime::spawn_blocking(move || {
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
                }
            })
        }));
        if result.is_err() {
            session.stop();
        }
        let mut host = restore.blocking_lock();
        if let Some(registry) = host.session.as_mut() {
            registry.restore_work(session);
        }
        host.in_flight.remove(&target);
        result
    })
    .await
    .map_err(|_| "account unavailable".to_owned())?;
    completed.map_err(|_| "account unavailable".to_owned())
}

fn setup_allowed(label: &str, note_bound: bool) -> bool {
    label == "main" && !note_bound
}
fn ensure_setup_window(
    window: &tauri::WebviewWindow,
    notes: &tauri::State<'_, crate::note_host::NoteHost>,
) -> Result<(), &'static str> {
    setup_allowed(window.label(), notes.has_binding(window.label()))
        .then_some(())
        .ok_or("setup unavailable")
}

#[tauri::command]
pub async fn account_screen(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<Screen, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let screen = run_account(&state, AccountOperation::Startup).await?;
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    Ok(screen)
}

#[tauri::command]
pub async fn account_retry(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<Screen, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    run_account(&state, AccountOperation::Retry).await
}

#[tauri::command]
pub async fn account_suggest_password(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<PasswordScreen, &'static str> {
    ensure_setup_window(&window, &notes)?;
    let suggested = crate::passwords::suggest();
    state.lock().await.suggested = Some(suggested.clone());
    Ok(PasswordScreen {
        screen: "password",
        suggested,
        error: None,
    })
}

/// A weak custom password is refused with the decided explanation, never with
/// arbitrary character-class rules. The password itself is not retained here.
#[tauri::command]
pub async fn account_create(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
    password: String,
) -> Result<serde_json::Value, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let mut host = state.lock().await;
    if host.suggested.as_deref() != Some(&password) && !crate::passwords::acceptable(&password) {
        let suggested = host
            .suggested
            .clone()
            .unwrap_or_else(crate::passwords::suggest);
        host.suggested = Some(suggested.clone());
        return Ok(serde_json::json!(PasswordScreen {
            screen: "password",
            suggested,
            error: Some(
                "That password is too easy to guess. Try a longer phrase, or use the suggested one."
            ),
        }));
    }
    drop(host);
    let screen = run_account(&state, AccountOperation::Create(password)).await?;
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    if matches!(screen, Screen::Kit { .. } | Screen::Ready) {
        state.lock().await.suggested = None;
    }
    Ok(serde_json::json!(screen))
}

#[tauri::command]
pub async fn account_confirm_kit(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<Screen, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    run_account(&state, AccountOperation::ConfirmKit).await
}

#[tauri::command]
pub fn account_return(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
) -> Result<Screen, &'static str> {
    ensure_setup_window(&window, &notes)?;
    Ok(Screen::Return)
}

/// `saved` means the person really has the code. `opened` means a destination
/// appeared but nothing proves it was kept, so the screens ask afterwards.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteResult {
    result: &'static str,
    route: &'static str,
}

fn kit_route(result: Result<Destination, ()>, route: &'static str) -> RouteResult {
    RouteResult {
        result: match result {
            Ok(Destination::Saved) => "saved",
            Ok(Destination::Opened) => "opened",
            Ok(Destination::Cancelled) => "cancelled",
            Err(()) => "failed",
        },
        route,
    }
}

/// Run a destination with the code held only in native memory. No path,
/// address or kit text crosses the IPC boundary, and the page supplies only
/// which destination to use. The code exists only while setup is incomplete.
async fn kit_result(
    window: &tauri::WebviewWindow,
    notes: &tauri::State<'_, crate::note_host::NoteHost>,
    state: &tauri::State<'_, SharedAccountHost>,
    route: &'static str,
    action: fn(&RecoveryCode) -> Result<Destination, ()>,
) -> Result<RouteResult, String> {
    ensure_setup_window(window, notes).map_err(str::to_owned)?;
    let mut host = state.lock().await;
    let code = host.session.as_mut().and_then(Session::pending_code);
    drop(host);
    let Some(code) = code else {
        return Ok(RouteResult {
            result: "cancelled",
            route,
        });
    };
    let result = tauri::async_runtime::spawn_blocking(move || action(&code))
        .await
        .map_err(|_| "kit destination unavailable".to_owned())?;
    Ok(kit_route(result, route))
}

#[tauri::command]
pub async fn account_print_kit(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<RouteResult, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let code_available = state
        .lock()
        .await
        .session
        .as_mut()
        .and_then(Session::pending_code)
        .is_some();
    if !code_available {
        return Ok(kit_route(Ok(Destination::Cancelled), "print"));
    }
    #[cfg(target_os = "macos")]
    {
        // The kit is already visible only on the setup page. WKWebView's own
        // dialog offers Print and Save as PDF; no other application receives it.
        window.print().map_err(|_| "print unavailable".to_owned())?;
        Ok(kit_route(Ok(Destination::Opened), "print"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(kit_route(Ok(Destination::Cancelled), "print"))
    }
}

#[tauri::command]
pub async fn account_email_kit(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<RouteResult, String> {
    kit_result(&window, &notes, &state, "email", email_kit).await
}

#[tauri::command]
pub async fn account_save_kit_file(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<RouteResult, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let mut host = state.lock().await;
    let code = host.session.as_mut().and_then(Session::pending_code);
    drop(host);
    let Some(code) = code else {
        return Ok(RouteResult {
            result: "cancelled",
            route: "file",
        });
    };
    let saved = save_kit_file(&code).await;
    if matches!(saved, Ok(Destination::Saved)) {
        ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
        // The OS write succeeded. Confirm natively before the IPC response so
        // a page navigation after file success cannot abandon the saved kit.
        let same_setup = state
            .lock()
            .await
            .session
            .as_mut()
            .and_then(Session::pending_code)
            .is_some_and(|pending| pending.to_kit_text() == code.to_kit_text());
        if !same_setup {
            return Err("account changed during kit save".into());
        }
        let screen = run_account(&state, AccountOperation::ConfirmKit).await?;
        if !matches!(screen, Screen::Ready | Screen::Retry) {
            return Err("saved kit needs a retry".into());
        }
    }
    Ok(kit_route(saved, "file"))
}

/// Bind this window's note to the container the native account host routed.
/// The page never names a container; Tauri derives the calling window.
#[tauri::command]
pub async fn account_open_note(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, SharedAccountHost>,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
) -> Result<(), &'static str> {
    ensure_setup_window(&window, &notes)?;
    let authority = state
        .lock()
        .await
        .session
        .as_ref()
        .and_then(Session::note_authority)
        .ok_or("no verified account")?;
    let owner = Arc::clone(notes.owner());
    let label = window.label().to_owned();
    let id = authority.0;
    let restored =
        tauri::async_runtime::spawn_blocking(move || open_account_notes(&owner, &label, authority))
            .await
            .map_err(|_| "note unavailable")?
            .map_err(|_| "note unavailable")?;
    crate::note_host::restore_windows(&notes, &window, id, restored.main, restored.others);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex as StdMutex};

    use bh_account::{
        crypto::{self, KemKey, Secret, SecretBytes, SigningKey},
        journal::{PendingSetupProtector, ProtectorError},
        platform::{KeyHandle, KeyStoreError, StoredDevice},
    };

    #[derive(Clone, Default)]
    struct PlainProtector;

    impl PendingSetupProtector for PlainProtector {
        fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
            Ok(plaintext.to_vec())
        }
        fn open(&mut self, blob: &[u8]) -> Result<SecretBytes, ProtectorError> {
            SecretBytes::from_parts(&[blob]).map_err(|_| ProtectorError::Failed)
        }
        fn reseal_without_code(
            &mut self,
            _: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ProtectorError> {
            self.seal(plaintext)
        }
        fn retire_kit_key(&mut self, _: &[u8]) -> Result<(), ProtectorError> {
            Ok(())
        }
    }

    type FakeKeyMap = HashMap<[u8; 32], (SigningKey, SigningKey, KemKey)>;
    #[derive(Clone, Default)]
    struct FakeStore {
        keys: Arc<StdMutex<FakeKeyMap>>,
        cancel_next_load: Arc<std::sync::atomic::AtomicBool>,
        fail_next_load: Arc<std::sync::atomic::AtomicBool>,
        delayed_handle: Arc<StdMutex<Option<[u8; 32]>>>,
    }

    impl FakeStore {
        fn find(&self, handle: &KeyHandle) -> Option<(SigningKey, SigningKey, KemKey)> {
            self.keys
                .lock()
                .unwrap()
                .get(&handle.0)
                .map(|(ordinary, control, receiver)| {
                    (
                        SigningKey::from_seed(&ordinary.export_seed()),
                        SigningKey::from_seed(&control.export_seed()),
                        KemKey::from_seed(&receiver.export_seed()),
                    )
                })
        }
    }

    impl DeviceKeyStore for FakeStore {
        async fn create(
            &mut self,
            policy: ControlKeyPolicy,
        ) -> Result<StoredDevice, KeyStoreError> {
            if policy != ControlKeyPolicy::AppEnforcedOwnerConfirmation {
                return Err(KeyStoreError::Unavailable);
            }
            let ordinary = SigningKey::generate();
            let control = SigningKey::generate();
            let receiver = KemKey::generate();
            let handle = KeyHandle(crypto::random());
            let keys = bh_account::DevicePublicKeys::new(
                ordinary.public(),
                control.public(),
                receiver.public(),
            )
            .unwrap();
            self.keys
                .lock()
                .unwrap()
                .insert(handle.0, (ordinary, control, receiver));
            Ok(StoredDevice {
                handle,
                keys,
                policy,
                kind: bh_account::platform::DeviceKeyStoreKind::MacLoginKeychainV1,
            })
        }
        async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
            if *self.delayed_handle.lock().unwrap() == Some(handle.0) {
                std::future::pending::<()>().await;
            }
            if self
                .fail_next_load
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(KeyStoreError::StorageFailure);
            }
            if self
                .cancel_next_load
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(KeyStoreError::AuthenticationCancelled);
            }
            let (ordinary, control, receiver) =
                self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
            Ok(StoredDevice {
                handle,
                keys: bh_account::DevicePublicKeys::new(
                    ordinary.public(),
                    control.public(),
                    receiver.public(),
                )
                .unwrap(),
                policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
                kind: bh_account::platform::DeviceKeyStoreKind::MacLoginKeychainV1,
            })
        }
        async fn sign_control(
            &mut self,
            handle: KeyHandle,
            message: Vec<u8>,
        ) -> Result<[u8; 64], KeyStoreError> {
            let (_, control, _) = self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
            Ok(control.sign(&message))
        }
        async fn sign_content(
            &mut self,
            handle: KeyHandle,
            message: Vec<u8>,
        ) -> Result<[u8; 64], KeyStoreError> {
            let (ordinary, _, _) = self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
            Ok(ordinary.sign(&message))
        }
        async fn decapsulate(
            &mut self,
            handle: KeyHandle,
            ciphertext: [u8; 1120],
        ) -> Result<Secret<32>, KeyStoreError> {
            let (_, _, receiver) = self.find(&handle).ok_or(KeyStoreError::Invalidated)?;
            crypto::decapsulate(&receiver, &ciphertext).map_err(|_| KeyStoreError::WrongKey)
        }
    }

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
            classify_real_owner_error,
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
        assert_eq!(
            reopened
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
        reopened
            .current
            .as_mut()
            .unwrap()
            .1
            .confirm_home_ordered(setup.head)
            .unwrap();
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
            classify_real_owner_error,
        );
        session.create("ripple amber horizon nectar willow").await;
        assert_eq!(session.confirm_kit().await, Screen::Ready);
        session
    }

    #[tokio::test]
    async fn verified_session_binds_home_note_and_lists_creates_and_shows_own_notes() {
        use crate::note_host::{create_bound, list_bound, new_window_note, show_bound};
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let session = ready_on(&owner, dir.path()).await;
        let authority = session
            .note_authority()
            .expect("ready session has note authority");
        let id = session.bound_container().unwrap();
        assert_eq!(authority.0, id);
        assert_eq!(authority.2, session.own_bases[&id].id().0);
        assert!(
            list_bound(&owner, "main", None).is_err(),
            "setup window has no notes"
        );
        let home = open_account_notes(&owner, "main", authority.clone())
            .unwrap()
            .note;
        assert_eq!(owner.bound_note("main"), Some(home));
        // A second open, e.g. after a retry, reuses the authority and the window.
        assert_eq!(
            open_account_notes(&owner, "main", authority).unwrap().note,
            home
        );
        let rows = list_bound(&owner, "main", None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].note, home.to_vec());
        assert_eq!(rows[0].title, "");
        let created = create_bound(&owner, "main").unwrap();
        let notes: Vec<_> = list_bound(&owner, "main", None)
            .unwrap()
            .into_iter()
            .map(|row| row.note)
            .collect();
        assert_eq!(notes, vec![created.clone(), home.to_vec()]);
        let first = list_bound(&owner, "main", None).unwrap().remove(0);
        let after = crate::note_host::After {
            touched: first.touched,
            note: first.note.clone(),
        };
        assert_eq!(
            list_bound(&owner, "main", Some(after)).unwrap()[0].note,
            home.to_vec()
        );
        show_bound(&owner, "main", created.clone()).unwrap();
        assert_eq!(
            owner.bound_note("main").map(|n| n.to_vec()),
            Some(created.clone())
        );
        assert!(show_bound(&owner, "main", vec![9; 32]).is_err());
        assert!(show_bound(&owner, "main", vec![9; 31]).is_err());
        assert_eq!(
            new_window_note(&owner, "main", home.to_vec()).unwrap(),
            (id, home)
        );
        assert!(new_window_note(&owner, "main", vec![9; 32]).is_err());
        assert!(new_window_note(&owner, "note-7", home.to_vec()).is_err());
        let host = crate::note_host::NoteHost::with_owner(Arc::clone(&owner));
        host.remember_window("note-2", id, home);
        owner.invalidate("note-2"); // the new window's first page load starts
        assert_eq!(host.bind_window_intent("note-2"), Ok(true));
        assert_eq!(owner.bound_note("note-2"), Some(home));
        assert_eq!(
            host.bind_window_intent("note-2"),
            Ok(false),
            "an intent binds once"
        );
        host.remember_window("note-3", id, home);
        host.forget_window_intent("note-3"); // destroyed before loading
        assert_eq!(host.bind_window_intent("note-3"), Ok(false));
        assert_eq!(owner.bound_note("note-3"), None);
        // A window first loading while Quit or update holds every window
        // keeps its intent; a later binding revalidates and shows it.
        host.remember_window("note-4", id, home);
        let fence = owner.begin_drain().unwrap();
        assert_eq!(host.bind_window_intent("note-4"), Err(()));
        assert_eq!(host.bind_window_intent("note-4"), Err(()), "still kept");
        owner.end_drain(fence);
        assert_eq!(host.bind_window_intent("note-4"), Ok(true));
        assert_eq!(owner.bound_note("note-4"), Some(home));
        // A navigated or destroyed page keeps no route to list or create from.
        owner.invalidate("main");
        assert!(list_bound(&owner, "main", None).is_err());
        assert!(create_bound(&owner, "main").is_err());
    }

    #[tokio::test]
    async fn activation_restores_quit_windows_once_from_selection_bytes_not_account_ids() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let session = ready_on(&owner, dir.path()).await;
        let authority = session.note_authority().unwrap();
        let (id, base) = (authority.0, authority.2);
        let db = owner.shared_database(id).unwrap();
        let first = db.lock().unwrap().create_note(base, [0; 32]).unwrap();
        let second = db.lock().unwrap().create_note(base, [0; 32]).unwrap();
        let record = |note, selection: u8, scroll, x| bh_storage::ViewRecord {
            version: 1,
            key: bh_storage::NoteKey {
                base,
                audience: [0; 32],
                note,
            },
            // Encoded Yjs relative positions, as a page's view() returns.
            anchor: vec![1, selection, 3],
            head: vec![1, selection, 4],
            cursor_offset: scroll,
            frame: [x, 30.0, 900.0, 700.0],
        };
        db.lock()
            .unwrap()
            .replace_view_records(&[
                record(first, 7, 64.5, 10.0),
                record(second, 8, -120.0, 400.0),
            ])
            .unwrap();
        let restored = open_account_notes(&owner, "main", authority.clone()).unwrap();
        assert_eq!(restored.note, first);
        assert_eq!(owner.bound_note("main"), Some(first));
        let main = restored.main.unwrap();
        assert_eq!(
            (main.view.anchor, main.view.head, main.view.cursor_offset),
            (vec![1, 7, 3], vec![1, 7, 4], 64.5)
        );
        assert_eq!(main.frame, Some([10.0, 30.0, 900.0, 700.0]));
        assert_eq!(restored.others.len(), 1);
        assert_eq!(restored.others[0].note, second);
        assert_eq!(restored.others[0].view.anchor, vec![1, 8, 3]);
        assert_eq!(
            restored.others[0].view.cursor_offset, -120.0,
            "a cursor above the visible area"
        );
        // A second activation (a reload) restores nothing again.
        let again = open_account_notes(&owner, "main", authority).unwrap();
        assert!(again.main.is_none() && again.others.is_empty());
        assert_ne!(again.note, first, "back to the home note");
    }

    #[test]
    fn restored_frames_are_clamped_and_offscreen_positions_dropped() {
        use crate::note_host::{on_screen, restore_frame};
        assert_eq!(
            restore_frame([5.0, 6.0, 100.0, 50_000.0]),
            Some([5.0, 6.0, 320.0, 8000.0])
        );
        assert_eq!(restore_frame([0.0, 0.0, f64::NAN, 10.0]), None);
        let screens = [[0.0, 0.0, 1440.0, 900.0], [1440.0, 0.0, 1920.0, 1080.0]];
        assert!(on_screen([100.0, 40.0, 900.0, 700.0], &screens));
        assert!(on_screen([2000.0, 100.0, 900.0, 700.0], &screens));
        assert!(!on_screen([-5000.0, 40.0, 900.0, 700.0], &screens));
        assert!(!on_screen([100.0, 2000.0, 900.0, 700.0], &screens));
    }

    #[tokio::test]
    async fn stale_capability_and_other_accounts_notes_are_refused_natively() {
        use crate::note_host::{list_bound, show_bound};
        let owner = Arc::new(bh_device::Owner::default());
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut a = ready_on(&owner, a_dir.path()).await;
        let b = ready_on(&owner, b_dir.path()).await;
        let a_home = open_account_notes(&owner, "main", a.note_authority().unwrap())
            .unwrap()
            .note;
        let b_home = open_account_notes(&owner, "note-1", b.note_authority().unwrap())
            .unwrap()
            .note;
        assert!(show_bound(&owner, "main", b_home.to_vec()).is_err());
        assert!(show_bound(&owner, "note-1", a_home.to_vec()).is_err());
        assert_eq!(owner.bound_note("main"), Some(a_home));
        let old = a.note_authority().unwrap();
        let id = old.0;
        a.generations[&id].advance();
        assert!(a.note_authority().is_none());
        assert!(list_bound(&owner, "main", None).is_err());
        assert!(open_account_notes(&owner, "main", old).is_err());
        // Account B is untouched by A's revocation.
        assert_eq!(list_bound(&owner, "note-1", None).unwrap().len(), 1);
        assert_eq!(a.startup().await, Screen::Ready);
        let fresh = open_account_notes(&owner, "main", a.note_authority().unwrap())
            .unwrap()
            .note;
        assert_eq!(fresh, a_home, "a fresh capability reopens the same notes");
    }

    #[test]
    fn missing_mac_home_never_creates_an_ephemeral_account() {
        assert!(directory_for_home(None).is_none());
        assert_eq!(
            directory_for_home(Some(std::ffi::OsString::from("/opt/example-home"))),
            Some(
                std::path::Path::new("/opt/example-home/Library/Application Support")
                    .join(crate::APP_IDENTIFIER)
            )
        );
        if crate::APP_IDENTIFIER == "app.basehero.client" {
            assert_eq!(
                directory_for_home(Some(std::ffi::OsString::from("/opt/example-home"))),
                Some(std::path::PathBuf::from(
                    "/opt/example-home/Library/Application Support/app.basehero.client"
                ))
            );
        }
    }

    #[test]
    fn transient_native_container_io_is_retryable_not_a_lost_identity() {
        assert_eq!(
            classify_real_owner_error(&OwnerError::Io(std::io::Error::other(
                "temporary file failure"
            ))),
            OpenIssue::Busy
        );
        assert_eq!(
            classify_real_owner_error(&OwnerError::Open(OpenError::NewerData {
                found: 10,
                supported: 9
            })),
            OpenIssue::NewerData
        );
        assert_eq!(
            classify_real_owner_error(&OwnerError::Open(OpenError::Database(
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

    #[test]
    fn kit_screen_is_never_authorized_for_a_note_bound_or_other_window() {
        assert!(setup_allowed("main", false));
        assert!(!setup_allowed("main", true));
        assert!(!setup_allowed("note-2", false));
        assert!(!setup_allowed("note-2", true));
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
}
