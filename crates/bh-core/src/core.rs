//! `Core`, sign-up and sign-in.

use crate::account::{self, Account, AccountSummary, AppCredentials, DeviceKind};
use crate::client::Api;
use crate::envelope;
use crate::keys::{self, DEFAULT_KDF, PasswordSecret, RecoveryKit};
use crate::secrets::SecretStore;
use crate::store::{AccountDb, AccountRow};
use crate::{Clock, Error};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_crypto::Secret;
use bh_proto::{
    AccountId, ActivateRequest, Bytes, DeviceId, LoginParamsResponse, LoginRequest, SignupRequest,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

/// Local storage and secret provider for one core. Only one open core may use
/// a data directory at a time.
pub struct CoreConfig {
    /// Directory for encrypted account and base stores.
    pub data_dir: PathBuf,
    /// Storage for device keys and tokens, separate from the databases.
    pub secrets: Arc<dyn SecretStore>,
}

/// Details for creating a full-device account; the password is zeroized on drop.
pub struct SignUp {
    /// Cloud endpoint for this account.
    pub server: Url,
    /// Invite code accepted by that endpoint.
    pub invite: String,
    /// Account email address.
    pub email: String,
    /// Account password, kept in zeroizing memory.
    pub password: Zeroizing<String>,
    /// Display name of this device.
    pub device_name: String,
}

/// Details for signing in a full device; the password is zeroized on drop.
pub struct SignIn {
    /// Cloud endpoint where the account lives.
    pub server: Url,
    /// Existing account email address.
    pub email: String,
    /// Account password, kept in zeroizing memory.
    pub password: Zeroizing<String>,
    /// Display name of this device.
    pub device_name: String,
}

/// The core's runtime. Stopping it, by [`Core::shutdown`] or when the last
/// handle drops, waits up to five seconds for its threads to finish their current
/// step. Stopping never blocks the runtime's own threads, so a `Core` may be
/// dropped inside any executor; exit still waits for any store in use (see
/// [`crate::store::Pass`]), so a process may exit right after.
struct Runtime {
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    threads: Arc<Threads>,
}

/// How many of a runtime's threads are running.
#[derive(Default)]
struct Threads {
    running: Mutex<usize>,
    changed: Condvar,
}

thread_local! {
    /// The runtime this thread belongs to, if it is one of a core's threads.
    static CORE_RUNTIME: Cell<usize> = const { Cell::new(0) };
}

/// How long starting or stopping waits for the runtime's threads.
const STOP_WAIT: Duration = Duration::from_secs(5);

/// The runtime's worker threads.
const WORKERS: usize = 2;

impl Runtime {
    fn build() -> Result<Runtime, Error> {
        let threads = Arc::new(Threads::default());
        let id = Arc::as_ptr(&threads) as usize;
        let (started, stopped) = (threads.clone(), threads.clone());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKERS)
            .thread_name("bh-core")
            .on_thread_start(move || {
                CORE_RUNTIME.set(id);
                *started.running.lock().unwrap_or_else(|e| e.into_inner()) += 1;
                started.changed.notify_all();
            })
            .on_thread_stop(move || {
                *stopped.running.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
                stopped.changed.notify_all();
            })
            .enable_all()
            .build()?;
        // Count the workers before anything can stop the runtime, so stopping
        // never misses a worker that hasn't started yet.
        let running = threads.running.lock().unwrap_or_else(|e| e.into_inner());
        drop(
            threads
                .changed
                .wait_timeout_while(running, STOP_WAIT, |n| *n < WORKERS),
        );
        Ok(Runtime {
            runtime: Mutex::new(Some(runtime)),
            threads,
        })
    }

    fn handle(&self) -> tokio::runtime::Handle {
        let runtime = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
        runtime.as_ref().expect("a new runtime").handle().clone()
    }

    fn stop(&self) {
        let Some(runtime) = self
            .runtime
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return;
        };
        runtime.shutdown_background();
        if CORE_RUNTIME.get() == Arc::as_ptr(&self.threads) as usize {
            return;
        }
        let running = self
            .threads
            .running
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = self
            .threads
            .changed
            .wait_timeout_while(running, STOP_WAIT, |n| *n > 0);
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What a `Core` and its accounts share. Accounts hold this, not the `Core`,
/// so the `Core`'s account list doesn't keep itself alive.
pub(crate) struct Shared {
    pub data_dir: PathBuf,
    pub secrets: Arc<dyn SecretStore>,
    pub handle: tokio::runtime::Handle,
    #[allow(dead_code, reason = "used by the approval exchange")]
    pub clock: Clock,
    pub(crate) accounts: Mutex<Weak<Mutex<BTreeMap<AccountId, Account>>>>,
    pub(crate) document_folders: Mutex<Option<Arc<dyn crate::DocumentFolders>>>,
    /// Serializes the account check, local writes and failure cleanup across sign-ins.
    install_lock: tokio::sync::Mutex<()>,
    runtime: Runtime,
    /// Held while this core is open, so no other process uses its stores.
    _lock: std::fs::File,
    #[cfg(feature = "test-support")]
    test: Mutex<TestDevice>,
    #[cfg(feature = "test-support")]
    pub faults: crate::client::Faults,
    #[cfg(feature = "test-support")]
    pub(crate) fail_next_erase: std::sync::atomic::AtomicBool,
    #[cfg(feature = "test-support")]
    pub(crate) hold_erase: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    #[cfg(feature = "test-support")]
    approval_post_pause: crate::client::ApprovalPostPause,
}

#[cfg(feature = "test-support")]
#[derive(Default)]
struct TestDevice {
    name: Option<String>,
    guards: Vec<Box<dyn std::any::Any + Send + Sync>>,
}

impl Shared {
    /// Runs `future` on the core's runtime, so callers may use any executor.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T, Error>> + Send + 'static,
    ) -> Result<T, Error> {
        match self.handle.spawn(future).await {
            Ok(result) => result,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(_) => Err(Error::Network("the core is shutting down".into())),
        }
    }

    /// A client for this core's requests.
    pub(crate) fn api(&self, server: Url, token: Option<String>) -> Api {
        let api = Api::new(server, token);
        #[cfg(feature = "test-support")]
        let api = api.with_faults(self.faults.clone(), self.approval_post_pause.clone());
        api
    }

    fn api_secret(&self, server: Url, token: Option<Zeroizing<String>>) -> Api {
        let api = Api::new_secret(server, token);
        #[cfg(feature = "test-support")]
        let api = api.with_faults(self.faults.clone(), self.approval_post_pause.clone());
        api
    }

    pub(crate) fn account_dir(&self, id: AccountId) -> PathBuf {
        self.data_dir.join("accounts").join(id.to_string())
    }

    pub(crate) fn secret(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.secrets
            .get(name)?
            .ok_or_else(|| Error::Storage(format!("missing secret {name}")))
    }
}

/// Owns local accounts and background sync. Clones share its runtime and stores;
/// dropping the last handle stops the runtime.
#[derive(Clone)]
pub struct Core {
    pub(crate) shared: Arc<Shared>,
    accounts: Arc<Mutex<BTreeMap<AccountId, Account>>>,
}

impl Core {
    /// Registers the host's document-tree opener for backup destinations.
    pub fn set_document_folders(&self, folders: Arc<dyn crate::DocumentFolders>) {
        *self.shared.document_folders.lock().unwrap() = Some(folders);
    }

    /// Opens a saved backup destination.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] when no document opener is registered.
    pub fn open_folder(
        &self,
        location: &crate::BackupLocation,
    ) -> Result<Arc<dyn crate::BackupFolder>, Error> {
        self.shared.open_folder(location)
    }

    /// Opens the core on `config.data_dir`, which one core at a time may use:
    /// a second open, in this process or another, fails until the first core
    /// and its accounts and bases are dropped.
    ///
    /// # Errors
    /// Returns [`Error::Storage`] for an occupied or unreadable directory or
    /// secret store, [`Error::Crypto`] for unreadable keys, or [`Error::Network`]
    /// if the runtime cannot start.
    pub fn open(config: CoreConfig) -> Result<Core, Error> {
        Self::open_with_clock(config, Clock::system())
    }

    /// Stops the core's background work, such as sync, and waits up to five
    /// seconds for it to finish its current step, so the process can exit
    /// cleanly. Call it as an app quits; the core can't sync afterwards.
    /// Dropping the last handle to the core does the same.
    pub fn shutdown(&self) {
        self.shared.runtime.stop();
    }

    /// Opens a core with an explicit clock, for controlled time in tests.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::open`].
    pub fn open_with_clock(config: CoreConfig, clock: Clock) -> Result<Core, Error> {
        std::fs::create_dir_all(&config.data_dir)?;
        let lock = std::fs::File::create(config.data_dir.join(".lock"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(Error::Storage("data directory in use".into()));
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        // Clean only after taking the exclusive lock: another core may be restoring.
        let restore = config.data_dir.join("restore");
        if restore.exists() {
            std::fs::remove_dir_all(restore)?;
        }
        let runtime = Runtime::build()?;
        let shared = Arc::new(Shared {
            data_dir: config.data_dir,
            secrets: config.secrets,
            handle: runtime.handle(),
            clock,
            accounts: Mutex::new(Weak::new()),
            document_folders: Mutex::new(None),
            install_lock: tokio::sync::Mutex::new(()),
            runtime,
            _lock: lock,
            #[cfg(feature = "test-support")]
            test: Mutex::default(),
            #[cfg(feature = "test-support")]
            faults: Default::default(),
            #[cfg(feature = "test-support")]
            fail_next_erase: Default::default(),
            #[cfg(feature = "test-support")]
            hold_erase: Default::default(),
            #[cfg(feature = "test-support")]
            approval_post_pause: Default::default(),
        });
        let accounts = Arc::new(Mutex::new(BTreeMap::new()));
        *shared.accounts.lock().unwrap() = Arc::downgrade(&accounts);
        let dir = shared.data_dir.join("accounts");
        std::fs::create_dir_all(&dir)?;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().and_then(|name| {
                name.parse::<AccountId>()
                    .ok()
                    .filter(|id| id.to_string() == name)
            }) else {
                continue;
            };
            let path = entry.path().join("account.sqlite");
            let key = shared.secrets.get(&format!("acct.{id}.dbkey"))?;
            let erasing = entry.path().join(".erasing").exists() || key.is_none();
            if erasing {
                let bases = if let Some(key) = key.as_ref().filter(|_| path.exists()) {
                    let _pass = crate::store::Pass::new();
                    AccountDb::open(&path, key)?
                        .bases()?
                        .into_iter()
                        .map(|b| b.id)
                        .collect()
                } else {
                    Vec::new()
                };
                account::erase_disk(&shared, id, &bases)?;
                continue;
            }
            if !path.exists() {
                continue;
            }
            let db = AccountDb::open(&path, &key.unwrap())?;
            let account = Account::load(shared.clone(), db)?;
            accounts.lock().unwrap().insert(id, account);
        }
        Ok(Core { shared, accounts })
    }

    /// Lists locally installed accounts without contacting the network.
    pub fn accounts(&self) -> Vec<AccountSummary> {
        let mut list: Vec<_> = self
            .accounts
            .lock()
            .unwrap()
            .values()
            .map(Account::summary)
            .collect();
        list.sort_by(|a, b| a.email.cmp(&b.email).then(a.id.cmp(&b.id)));
        list
    }

    /// Returns an installed account by ID, without contacting the network.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if this core has not installed the account.
    pub fn account(&self, id: AccountId) -> Result<Account, Error> {
        self.accounts
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// Installs credentials returned by a full device's app connection. Needs
    /// the network to fetch only the bases this app was granted.
    ///
    /// Save the granted base IDs before moving the credentials; they appear in
    /// the same order as the grants in the connection request.
    ///
    /// ```no_run
    /// use bh_core::{AppCredentials, Core, CoreConfig, Error};
    /// async fn install(core: &Core, credentials_json: &str) -> Result<(), Error> {
    ///     let credentials: AppCredentials = serde_json::from_str(credentials_json)
    ///         .map_err(|e| Error::Invalid(e.to_string()))?;
    ///     let bases = credentials.bases.clone();
    ///     let account = core.install_app(credentials).await?;
    ///     let first_base = account.base(bases[0])?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for malformed credentials or an already
    /// installed account, [`Error::Forbidden`] if they do not identify an app
    /// device, [`Error::Network`] on connection failure, and errors from the
    /// server ([`Error::Unauthorized`], [`Error::Revoked`], [`Error::NeedsUpdate`])
    /// or the local store ([`Error::Storage`], [`Error::Crypto`]).
    pub async fn install_app(&self, creds: AppCredentials) -> Result<Account, Error> {
        self.install_app_with_seed(creds, None).await
    }

    pub(crate) async fn install_app_with_seed(
        &self,
        creds: AppCredentials,
        pending_seed: Option<bh_crypto::Secret<32>>,
    ) -> Result<Account, Error> {
        let core = self.clone();
        self.shared
            .run(async move {
                // Like a sign-in, an app install checks, writes and inserts under one lock.
                let _install = core.shared.install_lock.lock().await;
                if core
                    .accounts
                    .lock()
                    .unwrap()
                    .contains_key(&creds.account_id)
                {
                    return Err(Error::invalid("already signed in"));
                }
                let app_key = Zeroizing::new(
                    URL_SAFE_NO_PAD
                        .decode(creds.app_key.as_bytes())
                        .map_err(|_| Error::invalid("app key"))?,
                );
                let key =
                    Secret::<32>::from_slice(&app_key).map_err(|_| Error::invalid("app key"))?;
                let api = core
                    .shared
                    .api_secret(creds.server.clone(), Some(creds.token.clone()));
                let me = api.me().await?;
                if (me.account_id, me.device_id, me.kind)
                    != (creds.account_id, creds.device_id, bh_proto::DeviceKind::App)
                {
                    return Err(Error::Forbidden);
                }
                let id = creds.account_id;
                let secrets = &core.shared.secrets;
                let seed = match pending_seed {
                    Some(seed) if creds.kem_seed.is_none() => seed,
                    Some(_) => return Err(Error::invalid("unexpected app key pair seed")),
                    None => match &creds.kem_seed {
                        Some(encoded) => {
                            let bytes = Zeroizing::new(
                                URL_SAFE_NO_PAD
                                    .decode(encoded.as_bytes())
                                    .map_err(|_| Error::invalid("key pair seed"))?,
                            );
                            bh_crypto::Secret::<32>::from_slice(&bytes)
                                .map_err(|_| Error::invalid("key pair seed"))?
                        }
                        None => bh_crypto::Secret::<32>::random(),
                    },
                };
                let installed = async {
                    secrets.put(&format!("acct.{id}.kem"), seed.expose())?;
                    let ring = crate::rotation::KeyRing::from_key(creds.epoch, key)?;
                    secrets.put(&format!("acct.{id}.appkey"), &ring.to_bytes())?;
                    secrets.put(&format!("acct.{id}.token"), creds.token.as_bytes())?;
                    let db_key = Zeroizing::new(bh_crypto::random::<32>().to_vec());
                    secrets.put(&format!("acct.{id}.dbkey"), &db_key)?;
                    let db = AccountDb::open(
                        &core.shared.account_dir(id).join("account.sqlite"),
                        &db_key,
                    )?;
                    {
                        let _pass = crate::store::Pass::new();
                        db.set_account(&AccountRow {
                            id,
                            email: creds.email,
                            server: creds.server,
                            kind: DeviceKind::App,
                            device_id: creds.device_id,
                        })?;
                    }
                    let account = Account::load(core.shared.clone(), db)?;
                    account.refresh().await?;
                    Ok::<Account, Error>(account)
                }
                .await;
                match installed {
                    Ok(account) => {
                        core.accounts.lock().unwrap().insert(id, account.clone());
                        Ok(account)
                    }
                    Err(error) => {
                        // Never restore an incomplete install on the next open.
                        for suffix in ["appkey", "token", "dbkey", "kem"] {
                            secrets.delete(&format!("acct.{id}.{suffix}"))?;
                        }
                        match std::fs::remove_dir_all(core.shared.account_dir(id)) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.into()),
                        }
                        Err(error)
                    }
                }
            })
            .await
    }

    /// Creates a full account and installs it locally; needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for bad input, [`Error::Conflict`] for a used
    /// invite or email, [`Error::Network`] for a connection failure, or
    /// [`Error::Storage`] / [`Error::Crypto`] for local key or store failures.
    pub async fn sign_up(&self, req: SignUp) -> Result<(Account, RecoveryKit), Error> {
        let core = self.clone();
        self.shared
            .run(async move { core.sign_up_here(req).await })
            .await
    }

    /// Checks a full device's password and starts sign-in; needs the network.
    /// Finish via [`PendingSignIn::with_kit`] or an approval request.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for bad input, [`Error::BadCredentials`] for
    /// an incorrect password, [`Error::Network`] for connection failure, or
    /// [`Error::Storage`] for a local store error.
    pub async fn sign_in(&self, req: SignIn) -> Result<PendingSignIn, Error> {
        let core = self.clone();
        self.shared
            .run(async move { core.sign_in_here(req).await })
            .await
    }

    async fn sign_up_here(self, req: SignUp) -> Result<(Account, RecoveryKit), Error> {
        let device_name = self.device_name(&req.device_name)?;
        let email = normalize_email(&req.email)?;
        if req.password.is_empty() {
            return Err(Error::invalid("password"));
        }
        let account_id = AccountId::random();
        let device_id = DeviceId::random();
        let salt = bh_crypto::random::<16>();
        let password = derive(req.password, salt, DEFAULT_KDF).await?;
        let kit = RecoveryKit::generate();
        let account_key = Secret::<32>::random();
        let envelope = envelope::seal(
            &password.wrap_key(&kit),
            &keys::account_key_aad(&account_id, 1),
            account_key.expose(),
        );
        let envelope_hash = account::envelope_hash(&envelope);
        let activation_hash = bh_crypto::sha256(keys::activation(&account_key).expose());
        let response = self
            .shared
            .api(req.server.clone(), None)
            .signup(&SignupRequest {
                invite: req.invite.trim().to_uppercase(),
                email: email.clone(),
                account_id,
                salt: Bytes(salt.to_vec()),
                kdf: DEFAULT_KDF,
                login_key: Bytes(password.login_key().to_vec()),
                account_key_envelope: Bytes(envelope.clone()),
                activation_hash: Bytes(activation_hash.to_vec()),
                device_id,
            })
            .await?;
        let _install = self.shared.install_lock.lock().await;
        let account = match self.install(
            AccountRow {
                id: account_id,
                email,
                server: req.server,
                kind: DeviceKind::Full,
                device_id,
            },
            Zeroizing::new(response.token),
            &account_key,
            1,
        ) {
            Ok(account) => account,
            Err(error) => {
                self.remove_partial_install(account_id, device_id)?;
                return Err(error);
            }
        };
        // The account exists now, so a local backup-cache failure must not hide the kit.
        let _ = account.remember_backup_credentials(envelope.clone(), salt);
        // The account exists now, so the kit must reach the user: an unnamed
        // device is the lesser loss if the name can't be written.
        let copy = kit.clone();
        let _ = account
            .update_data(move |data| {
                account::set_device_name(data, device_id, &device_name);
                account::set_kit(data, &copy, false, &envelope_hash, &salt);
            })
            .await;
        Ok((account, kit))
    }

    async fn sign_in_here(self, req: SignIn) -> Result<PendingSignIn, Error> {
        let device_name = self.device_name(&req.device_name)?;
        let email = normalize_email(&req.email)?;
        let api = self.shared.api(req.server.clone(), None);
        let params = api.login_params(&email).await?;
        let salt = login_salt(&params)?;
        let password = derive(req.password, salt, params.kdf).await?;
        let device_id = DeviceId::random();
        let response = api
            .login(&LoginRequest {
                email: email.clone(),
                login_key: Bytes(password.login_key().to_vec()),
                device_id,
            })
            .await?;
        if self
            .accounts
            .lock()
            .unwrap()
            .contains_key(&response.account_id)
        {
            return Err(Error::invalid("already signed in"));
        }
        Ok(PendingSignIn {
            account_id: response.account_id,
            device_id,
            device_name,
            api: self.shared.api(req.server.clone(), Some(response.token)),
            core: self,
            email,
            server: req.server,
            password: Arc::new(password),
            salt,
            envelope: Arc::new(response.account_key_envelope.0),
            completion: Arc::new(tokio::sync::Mutex::new(false)),
        })
    }

    fn device_name(&self, requested: &str) -> Result<String, Error> {
        let name = requested.trim();
        #[cfg(feature = "test-support")]
        if name.is_empty()
            && let Some(name) = self.shared.test.lock().unwrap().name.clone()
        {
            return Ok(name);
        }
        if name.is_empty() {
            return Err(Error::invalid("device name"));
        }
        Ok(name.to_string())
    }

    /// Stores a newly active device's secrets, then its account database,
    /// which is what `Core::open` looks for.
    fn install(
        &self,
        row: AccountRow,
        token: Zeroizing<String>,
        account_key: &Secret<32>,
        epoch: u32,
    ) -> Result<Account, Error> {
        let id = row.id;
        if self.accounts.lock().unwrap().contains_key(&id) {
            return Err(Error::invalid("already signed in"));
        }
        let secrets = &self.shared.secrets;
        let ring =
            crate::rotation::KeyRing::from_key(epoch, Secret::from_slice(account_key.expose())?)?;
        secrets.put(&format!("acct.{id}.key"), &ring.to_bytes())?;
        if secrets.get(&format!("acct.{id}.kem"))?.is_none() {
            secrets.put(
                &format!("acct.{id}.kem"),
                bh_crypto::Secret::<32>::random().expose(),
            )?;
        }
        secrets.put(&format!("acct.{id}.token"), token.as_bytes())?;
        let db_key = match secrets.get(&format!("acct.{id}.dbkey"))? {
            Some(key) => key,
            None => {
                let key = Zeroizing::new(bh_crypto::random::<32>().to_vec());
                secrets.put(&format!("acct.{id}.dbkey"), &key)?;
                key
            }
        };
        let db = AccountDb::open(&self.shared.account_dir(id).join("account.sqlite"), &db_key)?;
        {
            let _pass = crate::store::Pass::new();
            db.set_account(&row)?;
        }
        let account = Account::load(self.shared.clone(), db)?;
        self.accounts.lock().unwrap().insert(id, account.clone());
        Ok(account)
    }

    /// Removes an incomplete sign-in install only if this attempt owns the local account.
    fn remove_partial_install(&self, id: AccountId, device_id: DeviceId) -> Result<(), Error> {
        let mut accounts = self.accounts.lock().unwrap();
        if accounts
            .get(&id)
            .is_some_and(|account| account.device_id() != device_id)
        {
            return Ok(());
        }
        accounts.remove(&id);
        let secrets = &self.shared.secrets;
        let mut failure = None;
        for suffix in ["key", "token", "dbkey", "kem"] {
            if let Err(error) = secrets.delete(&format!("acct.{id}.{suffix}")) {
                failure.get_or_insert(error);
            }
        }
        match std::fs::remove_dir_all(self.shared.account_dir(id)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                failure.get_or_insert(error.into());
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Test kit only: names the device when a sign-up or sign-in leaves the name empty.
    #[cfg(feature = "test-support")]
    pub fn set_test_device_name(&self, name: &str) {
        self.shared.test.lock().unwrap().name = Some(name.to_string());
    }

    /// Test kit only: injects `fault` into this core's requests.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_erase(&self) -> Arc<tokio::sync::Semaphore> {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *self.shared.hold_erase.lock().unwrap() = Some(gate.clone());
        gate
    }

    #[cfg(feature = "test-support")]
    /// Test-only fault that makes the next local erasure fail.
    pub fn test_fail_next_erase(&self) {
        self.shared
            .fail_next_erase
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "test-support")]
    /// Test-only fault injected into the core's next matching HTTP requests.
    pub fn inject_fault(&self, fault: crate::client::Fault) {
        self.shared.faults.lock().unwrap().push(fault);
    }

    /// Test kit only: hold the next approval post until the caller releases it.
    #[cfg(feature = "test-support")]
    pub fn test_hold_approval_post(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.shared.approval_post_pause.lock().unwrap() = Some(crate::client::ApprovalPostGate {
            entered: entered_tx,
            release: release_rx,
        });
        (entered_rx, release_tx)
    }

    /// Test kit only: keeps `guard` (such as a temporary directory) alive as long as the core.
    #[cfg(feature = "test-support")]
    pub fn keep_alive(&self, guard: impl std::any::Any + Send + Sync) {
        self.shared
            .test
            .lock()
            .unwrap()
            .guards
            .push(Box::new(guard));
    }
}

fn normalize_email(email: &str) -> Result<String, Error> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') {
        return Err(Error::invalid("email"));
    }
    Ok(email)
}

pub(crate) fn login_salt(params: &LoginParamsResponse) -> Result<[u8; 16], Error> {
    params
        .salt
        .0
        .as_slice()
        .try_into()
        .map_err(|_| Error::Network("malformed login parameters".into()))
}

/// Argon2id is slow on purpose; keep it off the runtime's worker threads.
pub(crate) async fn derive(
    password: Zeroizing<String>,
    salt: [u8; 16],
    kdf: keys::Kdf,
) -> Result<PasswordSecret, Error> {
    tokio::task::spawn_blocking(move || PasswordSecret::derive(&password, &salt, kdf))
        .await
        .map_err(|_| Error::Storage("key derivation stopped".into()))?
}

/// A sign-in that has passed the password step and waits for the kit (or,
/// in the device approval plan, for another device's approval).
pub struct PendingSignIn {
    pub(crate) account_id: AccountId,
    pub(crate) device_id: DeviceId,
    pub(crate) device_name: String,
    pub(crate) api: Api,
    core: Core,
    email: String,
    server: Url,
    password: Arc<PasswordSecret>,
    salt: [u8; 16],
    envelope: Arc<Vec<u8>>,
    /// True once a `finish` has succeeded; held across `finish` so only one activates.
    completion: Arc<tokio::sync::Mutex<bool>>,
}

impl std::fmt::Debug for PendingSignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingSignIn")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl PendingSignIn {
    /// The account being signed into; available after the password step without
    /// making an approval request or contacting the network.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub(crate) fn clock(&self) -> Clock {
        self.core.shared.clock.clone()
    }

    pub(crate) async fn is_complete(&self) -> bool {
        *self.completion.lock().await
    }

    /// Opens the account key with the kit and activates this device. A wrong
    /// kit leaves the sign-in usable; after success this returns
    /// `Err(Error::Invalid("signed in"))`. Needs the network to activate the device.
    ///
    /// # Errors
    /// Returns [`Error::BadKit`] for a wrong kit, [`Error::Invalid`] if already
    /// signed in, [`Error::Network`] for connection failure, and server or store
    /// errors including [`Error::Revoked`], [`Error::Storage`] and [`Error::Crypto`].
    pub async fn with_kit(&self, kit: &str) -> Result<Account, Error> {
        if *self.completion.lock().await {
            return Err(Error::invalid("signed in"));
        }
        let kit = RecoveryKit::parse(kit)?;
        let account_key = envelope::open(
            &self.password.wrap_key(&kit),
            &keys::account_key_aad(
                &self.account_id,
                envelope::epoch(&self.envelope).ok_or(Error::Crypto)?,
            ),
            &self.envelope,
        )
        .map_err(|e| match e {
            Error::Crypto => Error::BadKit,
            other => other,
        })?;
        let account_key = Secret::<32>::from_slice(&account_key).map_err(|_| Error::BadKit)?;
        let account = self.snapshot().finish(account_key).await?;
        // Activation succeeded: a local backup-cache failure must not hide the account.
        let _ = account.remember_backup_credentials(self.envelope.to_vec(), self.salt);
        // Activation succeeded: failing to record the typed kit must not hide
        // the installed account. The person still has the kit they just used.
        let copy = kit.clone();
        let salt = self.salt;
        let opened_hash = account::envelope_hash(&self.envelope);
        let _ = account
            .update_data_with_envelope(move |data, current_hash| {
                // A rotation between this GET and the data PUT remains a small race.
                if current_hash != opened_hash {
                    return false;
                }
                let current = data
                    .get("kit")
                    .filter(|v| {
                        v.get("envelope").and_then(serde_json::Value::as_str) == Some(current_hash)
                    })
                    .and_then(|v| v.get("code"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|text| RecoveryKit::parse(text).ok());
                if current.as_ref() != Some(&copy)
                    || data.get("kit").and_then(|v| v.get("salt")).is_none()
                {
                    account::set_kit(data, &copy, true, current_hash, &salt);
                    true
                } else {
                    false
                }
            })
            .await;
        Ok(account)
    }

    pub(crate) fn snapshot(&self) -> PendingSignIn {
        PendingSignIn {
            account_id: self.account_id,
            device_id: self.device_id,
            device_name: self.device_name.clone(),
            api: self.api.clone(),
            core: self.core.clone(),
            email: self.email.clone(),
            server: self.server.clone(),
            password: self.password.clone(),
            salt: self.salt,
            envelope: self.envelope.clone(),
            completion: self.completion.clone(),
        }
    }

    /// Activates the device with the account key, stores `acct.<id>.key` and
    /// the account database, and writes the device's name into account data.
    /// Safe to retry after a failure part way.
    pub(crate) async fn finish(self, account_key: Secret<32>) -> Result<Account, Error> {
        let epoch = envelope::epoch(&self.envelope).ok_or(Error::Crypto)?;
        self.finish_at(account_key, epoch).await
    }

    pub(crate) async fn finish_at(
        self,
        account_key: Secret<32>,
        epoch: u32,
    ) -> Result<Account, Error> {
        let shared = self.core.shared.clone();
        shared
            .run(async move {
                let mut done = self.completion.clone().lock_owned().await;
                if *done {
                    return Err(Error::invalid("signed in"));
                }
                let account = self.complete(&account_key, epoch).await?;
                *done = true;
                Ok(account)
            })
            .await
    }

    async fn complete(self, account_key: &Secret<32>, epoch: u32) -> Result<Account, Error> {
        let activation = keys::activation(account_key);
        match self
            .api
            .activate(&ActivateRequest {
                activation: Bytes(activation.expose().to_vec()),
            })
            .await
        {
            Ok(_) => {}
            // An earlier attempt activated the device but stopped before the rest.
            Err(Error::Forbidden)
                if self
                    .api
                    .me()
                    .await
                    .is_ok_and(|me| me.device_id == self.device_id) => {}
            Err(e) => return Err(e),
        }
        let core = self.core.clone();
        let id = self.account_id;
        // Keep this lock until either the install and name write finish, or
        // their cleanup does. No competing attempt may touch these files.
        let _install = core.shared.install_lock.lock().await;
        // A different pending sign-in may have installed this account while we
        // waited for approval. Keep its local credentials and database; write
        // this activated device's name through that account before refusing a
        // second local installation.
        if let Ok(existing) = core.account(id)
            && existing.device_id() != self.device_id
        {
            let (device_id, name) = (self.device_id, self.device_name);
            existing
                .update_data(move |data| account::set_device_name(data, device_id, &name))
                .await?;
            return Err(Error::invalid("already signed in"));
        }
        let install = async {
            let token = self.api.token().ok_or(Error::Unauthorized)?;
            let account = core.install(
                AccountRow {
                    id,
                    email: self.email,
                    server: self.server,
                    kind: DeviceKind::Full,
                    device_id: self.device_id,
                },
                token,
                account_key,
                epoch,
            )?;
            let (device_id, name) = (self.device_id, self.device_name);
            account
                .update_data(move |data| account::set_device_name(data, device_id, &name))
                .await?;
            Ok(account)
        }
        .await;
        if install.is_err() {
            core.remove_partial_install(id, self.device_id)?;
        }
        install
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::FileSecretStore;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;

    /// Spawns a synchronous step, like a store write, and waits until it begins.
    fn step_in_progress(runtime: &Runtime) -> Arc<AtomicBool> {
        let finished = Arc::new(AtomicBool::new(false));
        let (started, begun) = mpsc::channel();
        let done = finished.clone();
        runtime.handle().spawn(async move {
            started.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            done.store(true, Ordering::SeqCst);
        });
        begun.recv_timeout(Duration::from_secs(30)).unwrap();
        finished
    }

    #[test]
    fn a_new_runtime_counts_its_workers_and_stopping_waits_for_all() {
        let runtime = Runtime::build().unwrap();
        let threads = runtime.threads.clone();
        assert_eq!(*threads.running.lock().unwrap(), WORKERS);
        drop(runtime);
        assert_eq!(*threads.running.lock().unwrap(), 0);
    }

    #[test]
    fn stopping_waits_for_a_step_in_progress() {
        let runtime = Runtime::build().unwrap();
        let finished = step_in_progress(&runtime);
        drop(runtime);
        assert!(finished.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn stopping_from_an_async_context_also_waits() {
        let runtime = Runtime::build().unwrap();
        let finished = step_in_progress(&runtime);
        drop(runtime);
        assert!(finished.load(Ordering::SeqCst));
    }

    #[test]
    fn a_core_thread_can_drop_the_last_handle() {
        let runtime = Arc::new(Runtime::build().unwrap());
        let (hand_over, take) = mpsc::channel::<Arc<Runtime>>();
        let (dropped, done) = mpsc::channel();
        runtime.handle().spawn(async move {
            let last = loop {
                if let Ok(last) = take.try_recv() {
                    break last;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            let started = std::time::Instant::now();
            drop(last);
            dropped.send(started.elapsed()).unwrap();
        });
        hand_over.send(runtime).unwrap();
        let waited = done.recv_timeout(Duration::from_secs(30)).unwrap();
        assert!(
            waited < Duration::from_secs(1),
            "a core thread waited {waited:?} on itself"
        );
    }

    const EXIT_CHILD: &str = "BH_CORE_EXIT_CHILD";
    const STORE_CHILD: &str = "BH_CORE_STORE_EXIT_CHILD";
    const PAGES: &str = "CREATE TABLE pages (payload BLOB)";

    /// An encrypted store large enough that reading it takes a while.
    fn pages(dir: &std::path::Path) {
        let db = crate::store::open_encrypted(&dir.join("pages.sqlite"), &[1; 32]).unwrap();
        db.execute(PAGES, []).unwrap();
        for _ in 0..128 {
            db.execute("INSERT INTO pages VALUES (?)", [vec![42u8; 8192]])
                .unwrap();
        }
    }

    /// Runs `test` in 12 child processes with `child` set to `dir`, and lists
    /// the runs that didn't exit cleanly within 30 s.
    fn children(test: &str, child: &str, dir: &std::path::Path) -> Vec<String> {
        (0..12)
            .filter_map(|run| {
                let mut process = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", test])
                    .env(child, dir)
                    .spawn()
                    .unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                let status = loop {
                    if let Some(status) = process.try_wait().unwrap() {
                        break status.to_string();
                    }
                    if std::time::Instant::now() > deadline {
                        process.kill().unwrap();
                        process.wait().unwrap();
                        break "hung".to_string();
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                (status != "exit status: 0").then(|| format!("run {run}: {status}"))
            })
            .collect()
    }

    /// The symptom behind this rule: a process that drops its core and exits while
    /// a core thread is reading an encrypted store must not crash.
    #[test]
    fn exiting_right_after_dropping_the_core_is_safe() {
        if let Some(dir) = std::env::var_os(EXIT_CHILD) {
            exit_while_reading(std::path::Path::new(&dir));
        }
        let dir = tempfile::tempdir().unwrap();
        pages(dir.path());
        let failed = children(
            "core::tests::exiting_right_after_dropping_the_core_is_safe",
            EXIT_CHILD,
            dir.path(),
        );
        assert!(failed.is_empty(), "children exited badly: {failed:?}");
    }

    /// Exit waits for a store in use on any thread, such as a core thread that
    /// dropped the last handle, so it couldn't wait for itself, or an app command.
    #[test]
    fn exiting_while_any_thread_uses_a_store_is_safe() {
        if let Some(dir) = std::env::var_os(STORE_CHILD) {
            exit_while_in_use(std::path::Path::new(&dir));
        }
        let dir = tempfile::tempdir().unwrap();
        pages(dir.path());
        let failed = children(
            "core::tests::exiting_while_any_thread_uses_a_store_is_safe",
            STORE_CHILD,
            dir.path(),
        );
        assert!(failed.is_empty(), "children exited badly: {failed:?}");
    }

    const LATE_CHILD: &str = "BH_CORE_LATE_EXIT_CHILD";

    /// Once exit has begun, dropping a store on any thread, or using one on the
    /// exiting thread, as a later exit handler might, never hangs.
    #[test]
    fn stores_dropped_or_used_while_exiting_never_hang() {
        if let Some(dir) = std::env::var_os(LATE_CHILD) {
            let dir = std::path::Path::new(&dir);
            let here = crate::store::AccountDb::open(&dir.join("here.sqlite"), &[1; 32]).unwrap();
            let there = crate::store::AccountDb::open(&dir.join("there.sqlite"), &[1; 32]).unwrap();
            crate::store::test_begin_exit();
            std::thread::spawn(move || drop(there)).join().unwrap();
            drop(here);
            drop(crate::store::Pass::new());
            std::process::exit(0);
        }
        let dir = tempfile::tempdir().unwrap();
        let failed = children(
            "core::tests::stores_dropped_or_used_while_exiting_never_hang",
            LATE_CHILD,
            dir.path(),
        );
        assert!(failed.is_empty(), "children exited badly: {failed:?}");
    }

    fn exit_while_in_use(dir: &std::path::Path) -> ! {
        let db = crate::store::open_encrypted(&dir.join("pages.sqlite"), &[1; 32]).unwrap();
        db.execute_batch("PRAGMA cache_size = 2").unwrap();
        let db = Arc::new(Mutex::new(db));
        let (started, begun) = mpsc::channel();
        std::thread::spawn(move || {
            let mut started = Some(started);
            let read = |db: &rusqlite::Connection| -> rusqlite::Result<()> {
                let mut read = db.prepare("SELECT payload FROM pages")?;
                let mut rows = read.query([])?;
                while rows.next()?.is_some() {}
                Ok(())
            };
            loop {
                // A failed read means exit freed SQLCipher's state under it. The
                // exit status can't show a panic on this thread, so abort.
                if read(&crate::store::in_use(&db)).is_err() {
                    std::process::abort();
                }
                if let Some(started) = started.take() {
                    started.send(()).unwrap();
                }
            }
        });
        begun.recv_timeout(Duration::from_secs(30)).unwrap();
        std::process::exit(0);
    }

    fn exit_while_reading(dir: &std::path::Path) -> ! {
        let core = Core::open(CoreConfig {
            data_dir: dir.join("core"),
            secrets: Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap()),
        })
        .unwrap();
        let path = dir.join("pages.sqlite");
        let (started, begun) = mpsc::channel();
        core.shared.handle.spawn(async move {
            let db = crate::store::open_encrypted(&path, &[1; 32]).unwrap();
            db.execute_batch("PRAGMA cache_size = 2").unwrap();
            let mut started = Some(started);
            loop {
                {
                    let mut read = db.prepare("SELECT payload FROM pages").unwrap();
                    let mut rows = read.query([]).unwrap();
                    while rows.next().unwrap().is_some() {}
                }
                if let Some(started) = started.take() {
                    started.send(()).unwrap();
                }
                tokio::task::yield_now().await;
            }
        });
        begun.recv_timeout(Duration::from_secs(30)).unwrap();
        drop(core);
        std::process::exit(0);
    }
}
