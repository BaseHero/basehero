use crate::error::CommandError;
use crate::notes::NoteSessions;
use crate::views::AppEvent;
use crate::{commands, kit_store, secrets};
use bh_core::hero::{Hero, HeroEvent};
use bh_core::{
    AccountEvent, AccountId, Approval, ApprovalId, Base, BaseId, BaseSummary, Core, CoreConfig,
    OpenAppRequest, OpenRequest, PendingSignIn, Url,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

/// Where app events go: every window, or a test's capture.
pub type Sink = Arc<dyn Fn(AppEvent) + Send + Sync>;
type Listener = (tauri::async_runtime::JoinHandle<()>, Arc<()>);
type Listeners = Arc<Mutex<HashMap<AccountId, Listener>>>;

fn any_hidden_open(accounts: impl IntoIterator<Item = Vec<BaseSummary>>) -> bool {
    accounts.into_iter().flatten().any(|base| base.hidden)
}

pub(crate) fn sync_hidden_recents(core: &Core) {
    let open = any_hidden_open(
        core.accounts()
            .into_iter()
            .filter_map(|account| core.account(account.id).ok())
            .map(|account| account.bases()),
    );
    crate::recents::set_hidden_open(open);
}

/// Retains the new device's exchange between commands; interruption wakes a pending wait.
pub struct ActiveApproval {
    pub handle: tokio::sync::Mutex<Approval>,
    pub interrupted: AtomicBool,
    pub interrupt: tokio::sync::Notify,
}

impl ActiveApproval {
    pub fn new(handle: Approval) -> Self {
        Self {
            handle: tokio::sync::Mutex::new(handle),
            interrupted: AtomicBool::new(false),
            interrupt: tokio::sync::Notify::new(),
        }
    }
    pub fn stop(&self) {
        self.interrupted.store(true, Ordering::Release);
        // A permit survives the race between a wait's flag check and registration.
        self.interrupt.notify_one();
    }
}

/// One per process: the core, the server new accounts use, and the sink.
pub struct AppState {
    pub core: Core,
    listener_core: Arc<Core>,
    pub server: Url,
    pub sink: Sink,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub pending: Arc<Mutex<HashMap<String, Arc<PendingSignIn>>>>,
    pub approvals: Arc<Mutex<HashMap<String, Arc<ActiveApproval>>>>,
    pub open_requests: Mutex<HashMap<(AccountId, ApprovalId), OpenRequest>>,
    pub open_app_requests: Mutex<HashMap<(AccountId, ApprovalId), OpenAppRequest>>,
    pub active_pending: Arc<Mutex<HashSet<String>>>,
    pub starting_approvals: Mutex<HashSet<String>>,
    pub pending_lifetime: Duration,
    listeners: Listeners,
    pub notes: Arc<NoteSessions>,
    bases: Arc<Mutex<HashMap<(AccountId, BaseId), CachedBase>>>,
    heroes: Arc<Mutex<HashMap<AccountId, CachedHero>>>,
}

struct CachedHero {
    hero: Hero,
    forwarder: tauri::async_runtime::JoinHandle<()>,
}

impl Drop for CachedHero {
    fn drop(&mut self) {
        self.forwarder.abort();
    }
}

struct CachedBase {
    base: Base,
    forwarder: tauri::async_runtime::JoinHandle<()>,
}

impl Drop for CachedBase {
    fn drop(&mut self) {
        self.forwarder.abort();
    }
}

impl AppState {
    pub fn open(config: CoreConfig, server: Url, sink: Sink) -> Result<AppState, CommandError> {
        let cache_dir = config.data_dir.join("cache");
        Self::open_with_cache(config, server, sink, cache_dir)
    }

    pub fn open_with_cache(
        config: CoreConfig,
        server: Url,
        sink: Sink,
        cache_dir: PathBuf,
    ) -> Result<AppState, CommandError> {
        Self::open_with_cleanup(config, server, sink, cache_dir, kit_store::delete_all)
    }

    fn open_with_cleanup(
        config: CoreConfig,
        server: Url,
        sink: Sink,
        cache_dir: PathBuf,
        cleanup: impl FnOnce() -> Result<(), CommandError> + Send + 'static,
    ) -> Result<AppState, CommandError> {
        // Delete old Android entries once per process, even if opening the account fails.
        // Google Play services must never delay or prevent the app from opening.
        tauri::async_runtime::spawn_blocking(move || {
            let _ = cleanup();
        });
        crate::commands::files::clear_open_copies(&cache_dir)?;
        let data_dir = config.data_dir.clone();
        let core = Core::open(config)?;
        let state = Self {
            listener_core: Arc::new(core.clone()),
            core,
            server,
            sink,
            data_dir,
            cache_dir,
            pending: Arc::default(),
            approvals: Arc::default(),
            open_requests: Mutex::default(),
            open_app_requests: Mutex::default(),
            active_pending: Arc::default(),
            starting_approvals: Mutex::default(),
            pending_lifetime: Duration::from_secs(10 * 60),
            listeners: Arc::default(),
            notes: Arc::new(NoteSessions::default()),
            bases: Arc::new(Mutex::new(HashMap::new())),
            heroes: Arc::default(),
        };
        for account in state.core.accounts() {
            state.listen(account.id)?;
        }
        sync_hidden_recents(&state.core);
        Ok(state)
    }

    pub fn expire_pending(&self, id: String) {
        let pending = Arc::downgrade(&self.pending);
        let approvals = Arc::downgrade(&self.approvals);
        let active = Arc::downgrade(&self.active_pending);
        let lifetime = self.pending_lifetime;
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(lifetime).await;
            let unfinished = active
                .upgrade()
                .is_some_and(|active| active.lock().unwrap().remove(&id));
            if let Some(pending) = pending.upgrade() {
                pending.lock().unwrap().remove(&id);
            }
            if let Some(approvals) = approvals.upgrade() {
                let entry = { approvals.lock().unwrap().remove(&id) };
                if let Some(entry) = entry
                    && unfinished
                {
                    entry.stop();
                    let _ = entry.handle.lock().await.cancel().await;
                }
            }
        });
    }

    /// Subscribe before returning a newly opened account so no events are missed.
    pub fn listen(&self, id: AccountId) -> Result<(), CommandError> {
        let mut listeners = self.listeners.lock().unwrap();
        if listeners.contains_key(&id) {
            return Ok(());
        }
        let mut events = self.core.account(id)?.events();
        let core = Arc::downgrade(&self.listener_core);
        let sink = self.sink.clone();
        let active = Arc::downgrade(&self.listeners);
        let bases = Arc::downgrade(&self.bases);
        let notes = Arc::downgrade(&self.notes);
        let cache_dir = self.cache_dir.clone();
        let heroes = Arc::downgrade(&self.heroes);
        let token = Arc::new(());
        let task_token = token.clone();
        let task = tauri::async_runtime::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        let removed = matches!(event, AccountEvent::Removed);
                        if removed && let Some(active) = active.upgrade() {
                            let mut active = active.lock().unwrap();
                            if active
                                .get(&id)
                                .is_some_and(|(_, token)| Arc::ptr_eq(token, &task_token))
                            {
                                active.remove(&id);
                            }
                        }
                        if matches!(event, AccountEvent::BasesChanged)
                            && let (Some(bases), Some(notes), Some(core)) =
                                (bases.upgrade(), notes.upgrade(), core.upgrade())
                            && let Ok(account_handle) = core.account(id)
                        {
                            let listed: HashSet<_> = account_handle
                                .bases()
                                .into_iter()
                                .map(|base| base.id)
                                .collect();
                            retain_listed_bases(&bases, &notes, &cache_dir, id, &listed);
                        }
                        if removed {
                            if let Some(bases) = bases.upgrade() {
                                bases.lock().unwrap().retain(|(owner, base), _| {
                                    if *owner != id {
                                        return true;
                                    }
                                    let _ = crate::commands::files::clear_open_copies_for_base(
                                        &cache_dir, *base,
                                    );
                                    false
                                });
                            }
                            if let Some(notes) = notes.upgrade() {
                                notes.close_account(id);
                            }
                            if let Some(heroes) = heroes.upgrade() {
                                heroes.lock().unwrap().remove(&id);
                            }
                        }
                        if matches!(event, AccountEvent::BasesChanged | AccountEvent::Removed)
                            && let Some(core) = core.upgrade()
                        {
                            sync_hidden_recents(&core);
                        }
                        sink(AppEvent::Account { account: id, event });
                        if removed {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
        listeners.insert(id, (task, token));
        Ok(())
    }

    pub fn stop_listening(&self, id: AccountId) {
        let removed = self.listeners.lock().unwrap().remove(&id);
        if let Some((task, _)) = removed {
            task.abort();
            (self.sink)(AppEvent::Account {
                account: id,
                event: AccountEvent::Removed,
            });
        }
    }

    /// Retain one handle and event forwarder per base for this process.
    pub fn base(&self, r: &crate::views::BaseRef) -> Result<Base, CommandError> {
        // A retained handle must not outlive this device's signed-in account. Check it
        // under the cache lock, so forget_account can't run between check and insert.
        let mut bases = self.bases.lock().unwrap_or_else(|e| e.into_inner());
        let account_handle = self.core.account(r.account)?;
        if let Some(cached) = bases.get(&(r.account, r.base)) {
            // A lock removes the base from the core before its event is delivered.
            account_handle.base(r.base)?;
            return Ok(cached.base.clone());
        }
        let base = account_handle.base(r.base)?;
        let mut events = base.events();
        let sink = self.sink.clone();
        let account = r.account;
        let id = r.base;
        let forwarder = tauri::async_runtime::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => sink(AppEvent::Base {
                        account,
                        base: id,
                        event,
                    }),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        bases.insert(
            (account, id),
            CachedBase {
                base: base.clone(),
                forwarder,
            },
        );
        Ok(base)
    }

    /// Drop cached handles and every window's sessions after a base disappears.
    pub fn reconcile_bases(&self, account: AccountId) -> Result<(), CommandError> {
        let listed: HashSet<_> = self
            .core
            .account(account)?
            .bases()
            .into_iter()
            .map(|base| base.id)
            .collect();
        retain_listed_bases(&self.bases, &self.notes, &self.cache_dir, account, &listed);
        Ok(())
    }

    /// Retain the account's Hero and forward its events to every window.
    pub fn hero(&self, account: AccountId) -> Result<Hero, CommandError> {
        let mut heroes = self.heroes.lock().unwrap();
        let account_handle = self.core.account(account)?;
        if let Some(cached) = heroes.get(&account) {
            return Ok(cached.hero.clone());
        }
        let hero = account_handle.hero();
        let mut events = hero.events();
        let sink = self.sink.clone();
        let forwarder = tauri::async_runtime::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        let (base, chat) = match &event {
                            HeroEvent::Changed { base, chat }
                            | HeroEvent::Text { base, chat, .. } => (*base, *chat),
                        };
                        sink(AppEvent::Hero {
                            account,
                            base,
                            chat,
                            event,
                        });
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        heroes.insert(
            account,
            CachedHero {
                hero: hero.clone(),
                forwarder,
            },
        );
        Ok(hero)
    }

    /// Release this account's bases and stop their event forwarders. Call it after the
    /// core has removed the account, so no later `base()` call can cache one again.
    pub fn forget_account(&self, account: AccountId) {
        self.heroes.lock().unwrap().remove(&account);
        self.bases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(owner, base), _| {
                if *owner != account {
                    return true;
                }
                let _ = crate::commands::files::clear_open_copies_for_base(&self.cache_dir, *base);
                false
            });
    }
}

fn retain_listed_bases(
    bases: &Mutex<HashMap<(AccountId, BaseId), CachedBase>>,
    notes: &NoteSessions,
    cache_dir: &std::path::Path,
    account: AccountId,
    listed: &HashSet<BaseId>,
) {
    let mut bases = bases.lock().unwrap_or_else(|e| e.into_inner());
    bases.retain(|(owner, base), _| {
        if *owner == account && !listed.contains(base) {
            // Plain open copies must disappear before the cached Base is dropped.
            if let Err(error) = crate::commands::files::clear_open_copies_for_base(cache_dir, *base)
            {
                eprintln!("Could not clear open copies: {}", error.message);
            }
            notes.close_base(account, *base);
            false
        } else {
            true
        }
    });
}

impl Drop for AppState {
    fn drop(&mut self) {
        for (_, (handle, _)) in self.listeners.lock().unwrap().drain() {
            handle.abort();
        }
    }
}

/// What startup left: the open state, or why it couldn't open, which every
/// command then returns, so the UI shows the key error screen.
pub struct Startup {
    reset_allowed: bool,
    opened: OnceLock<AppState>,
    error: Mutex<CommandError>,
    resetting: Mutex<()>,
}

impl Startup {
    fn from_result(result: Result<AppState, CommandError>) -> Self {
        let reset_allowed = matches!(&result, Err(error) if error.kind == "KeyUnavailable");
        let opened = OnceLock::new();
        let error = match result {
            Ok(state) => {
                let _ = opened.set(state);
                CommandError::key_unavailable("not opened")
            }
            Err(error) => error,
        };
        Self {
            reset_allowed,
            opened,
            error: Mutex::new(error),
            resetting: Mutex::new(()),
        }
    }

    pub fn open(app: &AppHandle) -> Startup {
        let opened = open(app);
        if let Err(error) = &opened {
            eprintln!("BaseHero couldn't open: {}: {}", error.kind, error.message);
        }
        Self::from_result(opened)
    }

    pub fn state(&self) -> Result<&AppState, CommandError> {
        self.opened
            .get()
            .ok_or_else(|| self.error.lock().unwrap().clone())
    }

    pub fn reset(&self, app: &AppHandle) -> Result<(), CommandError> {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|e| storage_error(e.to_string()))?;
        self.reset_with(&data_dir, || secrets::delete_master_key(app), || open(app))
    }

    fn reset_with(
        &self,
        data_dir: &std::path::Path,
        delete_key: impl FnOnce() -> Result<(), CommandError>,
        reopen: impl FnOnce() -> Result<AppState, CommandError>,
    ) -> Result<(), CommandError> {
        let _guard = self.resetting.lock().unwrap();
        if self.opened.get().is_some() {
            return Err(storage_error("a Core is already open".into()));
        }
        if !self.reset_allowed {
            return Err(storage_error("reset requires a device key error".into()));
        }
        // Refuse a redirected data root. Each child is removed with symlink_metadata,
        // so even a symlink replacing accounts/secrets is unlinked, never traversed.
        match std::fs::symlink_metadata(data_dir) {
            Ok(meta) if !meta.file_type().is_dir() => {
                return Err(storage_error(
                    "app data directory is not a directory".into(),
                ));
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(storage_error(e.to_string())),
        }
        // A key store that can't delete the key, such as a locked Keychain, couldn't
        // have given it either: erasing would lose unsynced changes and gain nothing.
        delete_key()?;
        // The old device remains in the account's device list until removed from
        // another device: its token is unreadable, so it cannot remove itself.
        // Known limit: the core's lock isn't checked, so a second BaseHero running on
        // this directory would lose its data; the Mac and Android run one instance.
        // Secrets go last, so an interrupted reset still fails with a key error and
        // offers reset again.
        for name in ["accounts", ".lock", "secrets"] {
            let path = data_dir.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(meta) => {
                    let result = if meta.file_type().is_dir() {
                        std::fs::remove_dir_all(&path)
                    } else {
                        std::fs::remove_file(&path)
                    };
                    result.map_err(|e| storage_error(e.to_string()))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(storage_error(e.to_string())),
            }
        }
        match reopen() {
            Ok(state) => {
                let _ = self.opened.set(state);
                Ok(())
            }
            Err(error) => {
                *self.error.lock().unwrap() = error.clone();
                Err(error)
            }
        }
    }
}

fn storage_error(message: String) -> CommandError {
    CommandError {
        kind: "Storage".into(),
        message,
    }
}

/// Loads the master key, builds the secret store, checks its canary and
/// opens the core.
fn open(app: &AppHandle) -> Result<AppState, CommandError> {
    let storage = |message: String| CommandError {
        kind: "Storage".into(),
        message,
    };
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| storage(e.to_string()))?;
    #[cfg(any(target_os = "macos", target_os = "android"))]
    let master = Some(secrets::master_key(app)?);
    #[cfg(not(any(target_os = "macos", target_os = "android")))]
    let master = None;
    let secrets = secrets::store(&data_dir, master)?;
    secrets::check_canary(&*secrets)?;
    let server = commands::app_info()
        .server
        .parse::<Url>()
        .map_err(|e| storage(e.to_string()))?;
    let cache_dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| storage(e.to_string()))?;
    let app = app.clone();
    let sink: Sink = Arc::new(move |event| {
        let _ = app.emit("bh:event", event);
    });
    AppState::open_with_cache(CoreConfig { data_dir, secrets }, server, sink, cache_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::account;
    use crate::commands::base::{self, ItemKind, NewItem};
    use crate::views::BaseRef;
    use bh_core::{FileSecretStore, SignUp};
    use bh_testkit::{LocalServer, TEST_PASSWORD, invite, note};
    use std::time::Duration;

    #[test]
    fn recents_suppression_follows_any_unlocked_hidden_base_across_accounts() {
        let base = |hidden| bh_core::BaseSummary {
            id: BaseId::random(),
            name: "base".into(),
            mode: bh_core::Mode::ReadWrite,
            hidden,
        };
        assert!(!any_hidden_open([vec![], vec![base(false)]]));
        assert!(any_hidden_open([vec![base(false)], vec![base(true)]]));
        assert!(!any_hidden_open([vec![base(false)], vec![]]));
    }

    fn test_open(data_dir: &std::path::Path) -> Result<AppState, CommandError> {
        let secrets = secrets::store(data_dir, None)?;
        secrets::check_canary(&*secrets)?;
        AppState::open(
            CoreConfig {
                data_dir: data_dir.to_owned(),
                secrets,
            },
            "https://dev-api.basehero.com".parse().unwrap(),
            Arc::new(|_| {}),
        )
    }

    #[test]
    fn reset_erases_only_local_app_data_and_reopens_empty() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("app");
        let sibling = root.path().join("outside");
        std::fs::write(&sibling, b"keep").unwrap();
        let state = test_open(&data).unwrap();
        drop(state);
        std::fs::write(data.join("secrets").join("unused"), b"secret").unwrap();
        std::fs::write(data.join("accounts").join("unused"), b"core").unwrap();
        let startup = Startup::from_result(Err(CommandError::key_unavailable("key lost")));
        startup
            .reset_with(&data, || Ok(()), || test_open(&data))
            .unwrap();
        assert!(startup.state().unwrap().core.accounts().is_empty());
        assert!(!data.join("secrets").join("unused").exists());
        assert!(!data.join("accounts").join("unused").exists());
        assert_eq!(std::fs::read(sibling).unwrap(), b"keep");
    }

    #[test]
    fn reset_refuses_to_erase_when_core_is_open() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("app");
        let startup = Startup::from_result(Ok(test_open(&data).unwrap()));
        let marker = data.join("marker");
        std::fs::write(&marker, b"keep").unwrap();
        assert!(
            startup
                .reset_with(&data, || panic!("key deleted"), || panic!("reopened"))
                .is_err()
        );
        assert_eq!(std::fs::read(marker).unwrap(), b"keep");
    }

    #[test]
    fn mismatched_canary_can_be_reset_and_reopened() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("app");
        let a = secrets::store(&data, Some(zeroize::Zeroizing::new([1; 32]))).unwrap();
        secrets::check_canary(&*a).unwrap();
        let b = secrets::store(&data, Some(zeroize::Zeroizing::new([2; 32]))).unwrap();
        let error = secrets::check_canary(&*b).unwrap_err();
        assert_eq!(error.kind, "KeyUnavailable");
        drop((a, b));
        let startup = Startup::from_result(Err(error));
        startup
            .reset_with(&data, || Ok(()), || test_open(&data))
            .unwrap();
        assert!(startup.state().unwrap().core.accounts().is_empty());
    }

    #[test]
    fn a_key_store_that_cannot_delete_the_key_erases_nothing() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("app");
        std::fs::create_dir_all(data.join("accounts")).unwrap();
        let marker = data.join("accounts").join("unsynced");
        std::fs::write(&marker, b"keep").unwrap();
        let startup = Startup::from_result(Err(CommandError::key_unavailable("locked")));
        let error = startup
            .reset_with(
                &data,
                || Err(CommandError::key_unavailable("Keychain status -25308")),
                || panic!("reopened"),
            )
            .unwrap_err();
        assert_eq!(error.kind, "KeyUnavailable");
        assert_eq!(std::fs::read(marker).unwrap(), b"keep");
    }

    #[test]
    fn unrelated_startup_failure_does_not_allow_erasing_data() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("app");
        std::fs::create_dir_all(&data).unwrap();
        let marker = data.join("accounts");
        std::fs::write(&marker, b"keep").unwrap();
        let startup = Startup::from_result(Err(storage_error("disk busy".into())));
        assert!(
            startup
                .reset_with(&data, || panic!("key deleted"), || panic!("reopened"))
                .is_err()
        );
        assert_eq!(std::fs::read(marker).unwrap(), b"keep");
    }

    #[test]
    fn failed_restart_can_be_retried_from_the_error_screen() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("app");
        let startup = Startup::from_result(Err(CommandError::key_unavailable("key lost")));
        assert!(
            startup
                .reset_with(&data, || Ok(()), || Err(storage_error("disk busy".into())))
                .is_err()
        );
        startup
            .reset_with(&data, || Ok(()), || test_open(&data))
            .unwrap();
        assert!(startup.state().unwrap().core.accounts().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn reset_does_not_follow_symlinks_outside_data_dir() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("app");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"safe").unwrap();
        std::os::unix::fs::symlink(&outside, data.join("accounts")).unwrap();
        let startup = Startup::from_result(Err(CommandError::key_unavailable("key lost")));
        startup
            .reset_with(&data, || Ok(()), || test_open(&data))
            .unwrap();
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"safe");
        assert!(startup.state().is_ok());
    }

    #[tokio::test]
    async fn startup_deletes_old_block_store_entries_and_ignores_failure() {
        let server = LocalServer::shared();
        let dir = tempfile::tempdir().unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let state = AppState::open_with_cleanup(
            CoreConfig {
                data_dir: dir.path().to_path_buf(),
                secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
            },
            server.url(),
            Arc::new(|_| {}),
            dir.path().join("cache"),
            move || {
                let _ = sent.send(());
                Err(storage_error("Google Play services unavailable".into()))
            },
        );
        assert!(state.is_ok(), "cleanup must not block startup");
        tokio::time::timeout(Duration::from_secs(5), received)
            .await
            .expect("cleanup was not called")
            .expect("cleanup task was dropped");
    }

    #[tokio::test]
    async fn sign_out_releases_cached_bases_and_closes_note_sessions() {
        let server = LocalServer::shared();
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap());
        let state = AppState::open(
            CoreConfig {
                data_dir: dir.path().to_path_buf(),
                secrets,
            },
            server.url(),
            Arc::new(|_| {}),
        )
        .unwrap();
        let (account, _) = state
            .core
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: TEST_PASSWORD.to_owned().into(),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        let id = account.id();
        let base = base::create_base(&state, id, "Personal").await.unwrap();
        let base_ref = BaseRef {
            account: id,
            base: base.id,
        };
        let cached = state.base(&base_ref).unwrap();
        let note_id = cached.create(note()).unwrap();
        let opened = state
            .notes
            .open("window", id, &cached, note_id, Box::new(|_| {}))
            .unwrap();
        assert!(state.bases.lock().unwrap().contains_key(&(id, base.id)));

        state.hero(id).unwrap();
        assert!(state.heroes.lock().unwrap().contains_key(&id));
        account::sign_out(&state, id).await.unwrap();
        assert!(!state.heroes.lock().unwrap().contains_key(&id));
        assert!(
            state
                .bases
                .lock()
                .unwrap()
                .keys()
                .all(|(owner, _)| *owner != id)
        );
        assert_eq!(
            state.notes.apply(opened.session, &[]).unwrap_err().kind,
            "NotFound"
        );
    }

    #[tokio::test]
    async fn remote_removal_closes_cached_notes_and_bases() {
        let server = LocalServer::shared();
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let state = AppState::open(
            CoreConfig {
                data_dir: dir.path().to_path_buf(),
                secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
            },
            server.url(),
            Arc::new(move |event| {
                let _ = tx.send(event);
            }),
        )
        .unwrap();
        let (account, kit) = state
            .core
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: TEST_PASSWORD.to_owned().into(),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        state.listen(account.id()).unwrap();
        let base = base::create_base(&state, account.id(), "Personal")
            .await
            .unwrap();
        let base_ref = BaseRef {
            account: account.id(),
            base: base.id,
        };
        let cached = state.base(&base_ref).unwrap();
        let note = cached.create(note()).unwrap();
        let opened = state
            .notes
            .open("window", account.id(), &cached, note, Box::new(|_| {}))
            .unwrap();
        let other = bh_testkit::device("other")
            .sign_in(bh_testkit::signin_for(&account))
            .await
            .unwrap()
            .with_kit(&kit.display())
            .await
            .unwrap();
        other.remove_device(account.device_id()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if matches!(
                    rx.recv().await,
                    Some(AppEvent::Account {
                        event: AccountEvent::Removed,
                        ..
                    })
                ) {
                    break;
                }
            }
        })
        .await
        .expect("remote removal event");
        assert!(
            state
                .bases
                .lock()
                .unwrap()
                .keys()
                .all(|(owner, _)| *owner != account.id())
        );
        assert_eq!(
            state.notes.apply(opened.session, &[]).unwrap_err().kind,
            "NotFound"
        );
    }

    #[tokio::test]
    async fn hero_events_forward_and_account_removal_releases_hero() {
        let server = LocalServer::shared();
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let state = AppState::open(
            CoreConfig {
                data_dir: dir.path().to_path_buf(),
                secrets,
            },
            server.url(),
            Arc::new(move |event| {
                let _ = tx.send(event);
            }),
        )
        .unwrap();
        let (account, _) = state
            .core
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: TEST_PASSWORD.to_owned().into(),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        let id = account.id();
        state.listen(id).unwrap();
        let base = base::create_base(&state, id, "Personal").await.unwrap();
        let hero = state.hero(id).unwrap();
        let chat = hero.new_chat(base.id).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(rx.recv().await, Some(AppEvent::Hero { account, base: event_base, chat: event_chat, .. })
                    if account == id && event_base == base.id && event_chat == chat) { break; }
            }
        }).await.expect("hero event not forwarded");
        account.sign_out().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !state.heroes.lock().unwrap().contains_key(&id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("removed account retained Hero");
        assert!(state.hero(id).is_err());
    }

    #[tokio::test]
    async fn signed_in_shell_releases_hero_on_remote_removal() {
        let server = LocalServer::shared();
        let owner_dir = tempfile::tempdir().unwrap();
        let owner = AppState::open(
            CoreConfig {
                data_dir: owner_dir.path().to_path_buf(),
                secrets: Arc::new(FileSecretStore::new(owner_dir.path().join("secrets")).unwrap()),
            },
            server.url(),
            Arc::new(|_| {}),
        )
        .unwrap();
        let signed = account::sign_up(
            &owner,
            crate::views::SignUpForm {
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: TEST_PASSWORD.to_owned().into(),
                device_name: "mac".into(),
            },
        )
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let shell = AppState::open(
            CoreConfig {
                data_dir: dir.path().to_path_buf(),
                secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
            },
            server.url(),
            Arc::new(move |event| {
                let _ = tx.send(event);
            }),
        )
        .unwrap();
        let pending = account::sign_in_start(
            &shell,
            crate::views::SignInForm {
                email: signed.account.email,
                password: TEST_PASSWORD.to_owned().into(),
                device_name: "fold".into(),
            },
        )
        .await
        .unwrap();
        let installed = account::sign_in_with_kit(&shell, &pending, &signed.kit)
            .await
            .unwrap();
        let base = shell.core.account(installed.id).unwrap().bases()[0].id;
        crate::hero::chats(&shell, installed.id, base).unwrap();
        assert!(shell.heroes.lock().unwrap().contains_key(&installed.id));
        let signed_in = shell.core.account(installed.id).unwrap();
        bh_testkit::wait_for(|| signed_in.test_request_count("v1/approvals/live") > 0).await;
        owner
            .core
            .account(installed.id)
            .unwrap()
            .remove_device(signed_in.device_id())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if matches!(
                    rx.recv().await,
                    Some(AppEvent::Account {
                        account: id,
                        event: AccountEvent::Removed,
                    }) if id == installed.id
                ) {
                    break;
                }
            }
        })
        .await
        .expect("signed-in shell did not hear remote removal");
        assert!(!shell.heroes.lock().unwrap().contains_key(&installed.id));
        assert_eq!(
            crate::hero::chats(&shell, installed.id, base)
                .unwrap_err()
                .kind,
            "NotFound"
        );
    }

    #[tokio::test]
    async fn forgetting_account_drops_cached_bases_and_ends_forwarders() {
        let server = LocalServer::start();
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap());
        let (sink_tx, mut sink_rx) = tokio::sync::mpsc::unbounded_channel();
        let state = AppState::open(
            CoreConfig {
                data_dir: dir.path().to_path_buf(),
                secrets,
            },
            server.url(),
            Arc::new(move |event| {
                let _ = sink_tx.send(event);
            }),
        )
        .unwrap();
        let (account, _kit) = state
            .core
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(&server),
                email: format!("{}@example.test", AccountId::random()),
                password: TEST_PASSWORD.to_owned().into(),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        let account = account.id();
        let first = base::create_base(&state, account, "Personal")
            .await
            .unwrap();
        let second = base::create_base(&state, account, "Travel").await.unwrap();
        let first_ref = BaseRef {
            account,
            base: first.id,
        };
        let second_ref = BaseRef {
            account,
            base: second.id,
        };
        let first_handle = state.base(&first_ref).unwrap();
        state.base(&second_ref).unwrap();
        let object = base::create_object(
            &state,
            &first_ref,
            NewItem {
                kind: ItemKind::Folder,
                parent: None,
                after: None,
                name: Some("Trips".into()),
            },
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(sink_rx.recv().await, Some(AppEvent::Base { base, .. }) if base == first.id) { break; }
            }
        }).await.expect("forwarder did not run before cleanup");

        state.forget_account(account);
        assert!(
            state
                .bases
                .lock()
                .unwrap()
                .keys()
                .all(|(id, _)| *id != account)
        );
        tokio::task::yield_now().await;
        while sink_rx.try_recv().is_ok() {} // Discard events queued before cleanup.
        first_handle.delete(object).unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if matches!(sink_rx.recv().await, Some(AppEvent::Base { base, event: bh_core::BaseEvent::ObjectsChanged(ids), .. })
                    if base == first.id && ids.contains(&object)) { break; }
            }
        }).await.is_err(), "forgotten account still forwarded base events");
    }
}
