//! `Core`, sign-up and sign-in.

use crate::account::{self, Account, AccountSummary, DeviceKind};
use crate::client::Api;
use crate::envelope;
use crate::keys::{self, DEFAULT_KDF, PasswordSecret, RecoveryKit};
use crate::secrets::SecretStore;
use crate::store::{AccountDb, AccountRow};
use crate::{Clock, Error};
use bh_crypto::Secret;
use bh_proto::{
    AccountId, ActivateRequest, Bytes, DeviceId, LoginParamsResponse, LoginRequest, SignupRequest,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use url::Url;
use zeroize::Zeroizing;

pub struct CoreConfig {
    pub data_dir: PathBuf,
    pub secrets: Arc<dyn SecretStore>,
}

pub struct SignUp {
    pub server: Url,
    pub invite: String,
    pub email: String,
    pub password: Zeroizing<String>,
    pub device_name: String,
}

pub struct SignIn {
    pub server: Url,
    pub email: String,
    pub password: Zeroizing<String>,
    pub device_name: String,
}

/// Shuts the runtime down without blocking, so a `Core` may be dropped inside
/// any executor, including its own.
struct Runtime(Option<tokio::runtime::Runtime>);

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
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
    _runtime: Runtime,
    /// Held while this core is open, so no other process uses its stores.
    _lock: std::fs::File,
    #[cfg(feature = "test-support")]
    test: Mutex<TestDevice>,
    #[cfg(feature = "test-support")]
    faults: crate::client::Faults,
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
        let api = api.with_faults(self.faults.clone());
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

#[derive(Clone)]
pub struct Core {
    shared: Arc<Shared>,
    accounts: Arc<Mutex<BTreeMap<AccountId, Account>>>,
}

impl Core {
    /// Opens the core on `config.data_dir`, which one core at a time may use:
    /// a second open, in this process or another, fails until the first core
    /// and its accounts and bases are dropped.
    pub fn open(config: CoreConfig) -> Result<Core, Error> {
        Self::open_with_clock(config, Clock::system())
    }

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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("bh-core")
            .enable_all()
            .build()?;
        let shared = Arc::new(Shared {
            data_dir: config.data_dir,
            secrets: config.secrets,
            handle: runtime.handle().clone(),
            clock,
            accounts: Mutex::new(Weak::new()),
            _runtime: Runtime(Some(runtime)),
            _lock: lock,
            #[cfg(feature = "test-support")]
            test: Mutex::default(),
            #[cfg(feature = "test-support")]
            faults: Default::default(),
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
            let Some(key) = shared.secrets.get(&format!("acct.{id}.dbkey"))? else {
                continue;
            };
            if !path.exists() {
                continue;
            }
            let db = AccountDb::open(&path, &key)?;
            let account = Account::load(shared.clone(), db)?;
            accounts.lock().unwrap().insert(id, account);
        }
        Ok(Core { shared, accounts })
    }

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

    pub fn account(&self, id: AccountId) -> Result<Account, Error> {
        self.accounts
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(Error::NotFound)
    }

    pub async fn sign_up(&self, req: SignUp) -> Result<(Account, RecoveryKit), Error> {
        let core = self.clone();
        self.shared
            .run(async move { core.sign_up_here(req).await })
            .await
    }

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
            &keys::account_key_aad(&account_id),
            account_key.expose(),
        );
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
                account_key_envelope: Bytes(envelope),
                activation_hash: Bytes(activation_hash.to_vec()),
                device_id,
            })
            .await?;
        let account = self.install(
            AccountRow {
                id: account_id,
                email,
                server: req.server,
                kind: DeviceKind::Full,
                device_id,
            },
            Zeroizing::new(response.token),
            &account_key,
        )?;
        // The account exists now, so the kit must reach the user: an unnamed
        // device is the lesser loss if the name can't be written.
        let _ = account
            .update_data(move |data| account::set_device_name(data, device_id, &device_name))
            .await;
        Ok((account, kit))
    }

    async fn sign_in_here(self, req: SignIn) -> Result<PendingSignIn, Error> {
        let device_name = self.device_name(&req.device_name)?;
        let email = normalize_email(&req.email)?;
        let api = self.shared.api(req.server.clone(), None);
        let params = api.login_params(&email).await?;
        let password = derive(req.password, login_salt(&params)?, params.kdf).await?;
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
    ) -> Result<Account, Error> {
        let id = row.id;
        let secrets = &self.shared.secrets;
        secrets.put(&format!("acct.{id}.key"), account_key.expose())?;
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
        db.set_account(&row)?;
        let account = Account::load(self.shared.clone(), db)?;
        self.accounts.lock().unwrap().insert(id, account.clone());
        Ok(account)
    }

    /// Test kit only: names the device when a sign-up or sign-in leaves the name empty.
    #[cfg(feature = "test-support")]
    pub fn set_test_device_name(&self, name: &str) {
        self.shared.test.lock().unwrap().name = Some(name.to_string());
    }

    /// Test kit only: injects `fault` into this core's requests.
    #[cfg(feature = "test-support")]
    pub fn inject_fault(&self, fault: crate::client::Fault) {
        self.shared.faults.lock().unwrap().push(fault);
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
    /// Opens the account key with the kit and activates this device. A wrong
    /// kit leaves the sign-in usable; after success this returns
    /// `Err(Error::Invalid("signed in"))`.
    pub async fn with_kit(&self, kit: &str) -> Result<Account, Error> {
        if *self.completion.lock().await {
            return Err(Error::invalid("signed in"));
        }
        let kit = RecoveryKit::parse(kit)?;
        let account_key = envelope::open(
            &self.password.wrap_key(&kit),
            &keys::account_key_aad(&self.account_id),
            &self.envelope,
        )
        .map_err(|e| match e {
            Error::Crypto => Error::BadKit,
            other => other,
        })?;
        let account_key = Secret::<32>::from_slice(&account_key).map_err(|_| Error::BadKit)?;
        self.snapshot().finish(account_key).await
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
            envelope: self.envelope.clone(),
            completion: self.completion.clone(),
        }
    }

    /// Activates the device with the account key, stores `acct.<id>.key` and
    /// the account database, and writes the device's name into account data.
    /// Safe to retry after a failure part way.
    pub(crate) async fn finish(self, account_key: Secret<32>) -> Result<Account, Error> {
        let shared = self.core.shared.clone();
        shared
            .run(async move {
                let mut done = self.completion.clone().lock_owned().await;
                if *done {
                    return Err(Error::invalid("signed in"));
                }
                let account = self.complete(&account_key).await?;
                *done = true;
                Ok(account)
            })
            .await
    }

    async fn complete(self, account_key: &Secret<32>) -> Result<Account, Error> {
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
        let token = self.api.token().ok_or(Error::Unauthorized)?;
        let account = self.core.install(
            AccountRow {
                id: self.account_id,
                email: self.email,
                server: self.server,
                kind: DeviceKind::Full,
                device_id: self.device_id,
            },
            token,
            account_key,
        )?;
        let (device_id, name) = (self.device_id, self.device_name);
        account
            .update_data(move |data| account::set_device_name(data, device_id, &name))
            .await?;
        Ok(account)
    }
}
