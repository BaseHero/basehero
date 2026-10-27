//! `Account`: one signed-in device of one account.

use crate::approval::ApprovalRequest;
use crate::client::Api;
use crate::client::ApprovalLive;
use crate::core::{Shared, derive, login_salt};
use crate::envelope;
use crate::keys::{self, DEFAULT_KDF, RecoveryKit};
use crate::store::AccountDb;
use crate::{EndReason, Error};
use bh_crypto::Secret;
use bh_proto::ApprovalId;
use bh_proto::{AccountDataRequest, AccountId, Bytes, CredentialsRequest, DeviceId};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use ts_rs::TS;
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum DeviceKind {
    Full,
    App,
}

impl DeviceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::App => "app",
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "full" => Ok(Self::Full),
            "app" => Ok(Self::App),
            _ => Err(Error::Storage("unknown device kind".into())),
        }
    }
}

impl From<bh_proto::DeviceKind> for DeviceKind {
    fn from(kind: bh_proto::DeviceKind) -> Self {
        match kind {
            bh_proto::DeviceKind::Full => Self::Full,
            bh_proto::DeviceKind::App => Self::App,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct AccountSummary {
    #[ts(type = "string")]
    pub id: AccountId,
    pub email: String,
    pub kind: DeviceKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct DeviceSummary {
    #[ts(type = "string")]
    pub id: DeviceId,
    pub kind: DeviceKind,
    pub name: String,
    pub status: String,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub last_seen_at: i64,
    pub this_device: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum AccountEvent {
    BasesChanged,
    DevicesChanged,
    Removed,
    ApprovalRequested(ApprovalRequest),
    ApprovalClosed(ApprovalId),
}

/// Account data, `{ "v": 1, "devices": { "<deviceId>": { "name": "…" } }, "apps": {} }`,
/// sealed under `kdf(AK, "bhacdat1", 1)`. Edits keep fields this version doesn't know.
type Data = Map<String, Value>;

fn new_data() -> Data {
    let Value::Object(data) = json!({ "v": 1, "devices": {}, "apps": {} }) else {
        unreachable!()
    };
    data
}

fn parse_data(json: &[u8]) -> Result<Data, Error> {
    let data: Data = serde_json::from_slice(json)
        .map_err(|_| Error::Storage("malformed account data".into()))?;
    match data.get("v").and_then(Value::as_u64) {
        Some(1) => Ok(data),
        Some(v) if v > 1 => Err(Error::NeedsUpdate),
        _ => Err(Error::Storage("malformed account data".into())),
    }
}

fn entry<'a>(data: &'a mut Data, key: &str) -> &'a mut Data {
    let value = data.entry(key).or_insert_with(|| json!({}));
    if !value.is_object() {
        *value = json!({});
    }
    value.as_object_mut().unwrap()
}

pub(crate) fn set_device_name(data: &mut Data, device: DeviceId, name: &str) {
    let devices = entry(data, "devices");
    let device = devices
        .entry(device.to_string())
        .or_insert_with(|| json!({}));
    if !device.is_object() {
        *device = json!({});
    }
    device["name"] = Value::String(name.to_string());
}

fn device_name(data: &Data, device: DeviceId) -> String {
    let id = device.to_string();
    ["devices", "apps"]
        .iter()
        .find_map(|map| data.get(*map)?.get(&id)?.get("name")?.as_str())
        .unwrap_or_default()
        .to_string()
}

#[derive(Clone)]
pub struct Account {
    inner: Arc<Inner>,
}

struct Inner {
    shared: Arc<Shared>,
    id: AccountId,
    device_id: DeviceId,
    email: String,
    kind: DeviceKind,
    server: Url,
    api: Api,
    db: Mutex<AccountDb>,
    events: broadcast::Sender<AccountEvent>,
    listener: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Inner {
    fn stop_listener(&self) -> Option<tokio::task::JoinHandle<()>> {
        let task = self.listener.lock().unwrap().take();
        if let Some(task) = &task {
            task.abort();
        }
        task
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop_listener();
    }
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.inner.id)
            .field("device_id", &self.inner.device_id)
            .field("kind", &self.inner.kind)
            .finish_non_exhaustive()
    }
}

impl Account {
    pub(crate) fn load(shared: Arc<Shared>, db: AccountDb) -> Result<Account, Error> {
        let row = db.account()?;
        let token = shared.secret(&format!("acct.{}.token", row.id))?;
        let token = String::from_utf8(token.to_vec())
            .map_err(|_| Error::Storage("unreadable token".into()))?;
        let account = Account {
            inner: Arc::new(Inner {
                api: shared.api(row.server.clone(), Some(token)),
                shared,
                id: row.id,
                device_id: row.device_id,
                email: row.email,
                kind: row.kind,
                server: row.server,
                db: Mutex::new(db),
                events: broadcast::channel(64).0,
                listener: Mutex::new(None),
            }),
        };
        if account.kind() == DeviceKind::Full {
            let api = account.inner.api.clone();
            let events = account.inner.events.clone();
            let clock = account.inner.shared.clock.clone();
            *account.inner.listener.lock().unwrap() = Some(
                account
                    .inner
                    .shared
                    .handle
                    .spawn(async move { listen_approvals(api, events, clock).await }),
            );
        }
        Ok(account)
    }

    pub fn id(&self) -> AccountId {
        self.inner.id
    }

    pub fn device_id(&self) -> DeviceId {
        self.inner.device_id
    }

    pub fn email(&self) -> String {
        self.inner.email.clone()
    }

    pub fn kind(&self) -> DeviceKind {
        self.inner.kind
    }

    pub(crate) fn summary(&self) -> AccountSummary {
        AccountSummary {
            id: self.id(),
            email: self.email(),
            kind: self.kind(),
        }
    }

    #[cfg(feature = "test-support")]
    pub fn test_request_count(&self, path: &str) -> usize {
        self.inner.api.count(path)
    }

    pub fn events(&self) -> broadcast::Receiver<AccountEvent> {
        self.inner.events.subscribe()
    }

    /// Removes this device's local account and stops its live listener.
    pub async fn sign_out(&self) -> Result<(), Error> {
        if let Some(task) = self.inner.stop_listener() {
            let _ = task.await; // Abort drops the socket and the sender before sign-out returns.
        }
        if let Some(accounts) = self.inner.shared.accounts.lock().unwrap().upgrade() {
            accounts.lock().unwrap().remove(&self.inner.id);
        }
        for suffix in ["key", "appkey", "token", "dbkey"] {
            self.inner
                .shared
                .secrets
                .delete(&format!("acct.{}.{suffix}", self.inner.id))?;
        }
        let dir = self.inner.shared.account_dir(self.inner.id);
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        let _ = self.inner.events.send(AccountEvent::Removed);
        Ok(())
    }

    /// Lists requests without answering them or sending any message to the new device.
    pub async fn approval_requests(&self) -> Result<Vec<ApprovalRequest>, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let api = self.inner.api.clone();
        self.inner
            .shared
            .run(async move {
                Ok(api
                    .approvals()
                    .await?
                    .approvals
                    .into_iter()
                    .map(|r| ApprovalRequest {
                        id: r.approval_id,
                        device_id: r.device_id,
                        created_at: r.created_at,
                        expires_at: r.expires_at,
                    })
                    .collect())
            })
            .await
    }

    pub async fn decline(&self, id: ApprovalId) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let api = self.inner.api.clone();
        self.inner
            .shared
            .run(async move {
                match api.approval_end(id, EndReason::Declined).await {
                    Err(Error::NotFound) => Ok(()),
                    other => other,
                }
            })
            .await
    }

    /// The account's devices, named from account data.
    pub async fn devices(&self) -> Result<Vec<DeviceSummary>, Error> {
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let response = this.inner.api.account().await?;
                let data = match &response.data {
                    Some(sealed) => {
                        let data = this.open_data(&sealed.ciphertext.0)?;
                        this.cache(sealed.version, &data)?;
                        data
                    }
                    None => new_data(),
                };
                Ok(response
                    .devices
                    .into_iter()
                    .map(|d| DeviceSummary {
                        name: device_name(&data, d.device_id),
                        this_device: d.device_id == this.inner.device_id,
                        id: d.device_id,
                        kind: d.kind.into(),
                        status: d.status,
                        created_at: d.created_at,
                        last_seen_at: d.last_seen_at,
                    })
                    .collect())
            })
            .await
    }

    /// Replaces the recovery kit. The old kit stops working.
    pub async fn new_kit(&self, password: &str) -> Result<RecoveryKit, Error> {
        let this = self.clone();
        let password = Zeroizing::new(password.to_string());
        self.inner
            .shared
            .run(async move {
                let api = &this.inner.api;
                let params = api.login_params(&this.inner.email).await?;
                let salt = login_salt(&params)?;
                let secret = derive(password, salt, params.kdf.clone()).await?;
                let account_key = this.account_key()?;
                let kit = RecoveryKit::generate();
                let envelope = envelope::seal(
                    &secret.wrap_key(&kit),
                    &keys::account_key_aad(&this.inner.id),
                    account_key.expose(),
                );
                let login_key = Bytes(secret.login_key().to_vec());
                let request = CredentialsRequest {
                    current_login_key: login_key.clone(),
                    login_key,
                    salt: Bytes(salt.to_vec()),
                    kdf: params.kdf,
                    account_key_envelope: Bytes(envelope),
                };
                match api.put_credentials(&request).await {
                    Ok(_) => {}
                    // The server may have saved the new kit before the reply was
                    // lost. Repeating the same request is harmless; if that fails
                    // too, neither kit is known to work.
                    Err(Error::Network(_)) => {
                        api.put_credentials(&request).await.map_err(|_| {
                            Error::Network(
                                "the new kit may not have been saved: make a new kit".into(),
                            )
                        })?;
                    }
                    Err(e) => return Err(e),
                }
                Ok(kit)
            })
            .await
    }

    /// Changes the password. The kit is needed to re-wrap the account key. The
    /// current envelope must open with `current` and `kit` to the account key
    /// this device holds, so a mistyped kit can't replace the real one; a wrong
    /// password or kit gives `BadKit`, as the two can't be told apart.
    pub async fn change_password(
        &self,
        current: &str,
        kit: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        if new_password.is_empty() {
            return Err(Error::invalid("password"));
        }
        let kit = RecoveryKit::parse(kit)?;
        let this = self.clone();
        let current = Zeroizing::new(current.to_string());
        let new_password = Zeroizing::new(new_password.to_string());
        self.inner
            .shared
            .run(async move {
                let api = &this.inner.api;
                let account_key = this.account_key()?;
                let sealed = api.account().await?.account_key_envelope;
                let params = api.login_params(&this.inner.email).await?;
                let current = derive(current, login_salt(&params)?, params.kdf).await?;
                let opened = envelope::open(
                    &current.wrap_key(&kit),
                    &keys::account_key_aad(&this.inner.id),
                    &sealed.0,
                )
                .map_err(|e| match e {
                    Error::Crypto => Error::BadKit,
                    other => other,
                })?;
                if !bh_crypto::constant_time_eq(&opened, account_key.expose()) {
                    return Err(Error::BadKit);
                }
                let salt = bh_crypto::random::<16>();
                let next = derive(new_password, salt, DEFAULT_KDF).await?;
                let envelope = envelope::seal(
                    &next.wrap_key(&kit),
                    &keys::account_key_aad(&this.inner.id),
                    account_key.expose(),
                );
                api.put_credentials(&CredentialsRequest {
                    current_login_key: Bytes(current.login_key().to_vec()),
                    login_key: Bytes(next.login_key().to_vec()),
                    salt: Bytes(salt.to_vec()),
                    kdf: DEFAULT_KDF,
                    account_key_envelope: Bytes(envelope),
                })
                .await?;
                Ok(())
            })
            .await
    }

    /// Reads account data, applies `edit` and writes it back, retrying when
    /// another device wrote first. Runs on the core's runtime.
    pub(crate) async fn update_data(
        &self,
        edit: impl Fn(&mut Data) + Send + 'static,
    ) -> Result<(), Error> {
        let api = &self.inner.api;
        for _ in 0..5 {
            let (version, mut data) = match api.account().await?.data {
                Some(sealed) => (sealed.version, self.open_data(&sealed.ciphertext.0)?),
                None => (0, new_data()),
            };
            edit(&mut data);
            let json = Zeroizing::new(serde_json::to_vec(&data).expect("JSON map"));
            let ciphertext = envelope::seal(
                &keys::account_data_key(&self.account_key()?),
                &keys::account_data_aad(&self.inner.id),
                &json,
            );
            match api
                .put_account_data(&AccountDataRequest {
                    ciphertext: Bytes(ciphertext),
                    expected_version: version,
                })
                .await
            {
                Ok(response) => return self.cache(response.version, &data),
                Err(Error::Conflict(code)) if code == "version_conflict" => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict("version_conflict".into()))
    }

    fn open_data(&self, ciphertext: &[u8]) -> Result<Data, Error> {
        let json = envelope::open(
            &keys::account_data_key(&self.account_key()?),
            &keys::account_data_aad(&self.inner.id),
            ciphertext,
        )?;
        parse_data(&json)
    }

    fn cache(&self, version: u64, data: &Data) -> Result<(), Error> {
        let json = Zeroizing::new(serde_json::to_string(data).expect("JSON map"));
        self.inner
            .db
            .lock()
            .unwrap()
            .set_account_data(version, &json)
    }

    fn account_key(&self) -> Result<Secret<32>, Error> {
        if self.inner.kind != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let key = self
            .inner
            .shared
            .secret(&format!("acct.{}.key", self.inner.id))?;
        Ok(Secret::from_slice(&key)?)
    }

    #[allow(dead_code, reason = "for the Hero plan's gateway")]
    pub(crate) fn server(&self) -> Url {
        self.inner.server.clone()
    }

    #[allow(dead_code, reason = "for the Hero and device approval plans")]
    pub(crate) fn token(&self) -> Result<Zeroizing<String>, Error> {
        let token = self
            .inner
            .shared
            .secret(&format!("acct.{}.token", self.inner.id))?;
        String::from_utf8(token.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| Error::Storage("unreadable token".into()))
    }

    /// `kdf(AK, context, 1)` on full devices and `kdf(APK, context, 1)` on app devices.
    #[allow(dead_code, reason = "for the Hero plan")]
    pub(crate) fn derive_secret(&self, context: &[u8; 8]) -> Result<Secret<32>, Error> {
        let name = match self.inner.kind {
            DeviceKind::Full => format!("acct.{}.key", self.inner.id),
            DeviceKind::App => format!("acct.{}.appkey", self.inner.id),
        };
        let key = Secret::<32>::from_slice(&self.inner.shared.secret(&name)?)?;
        Ok(bh_crypto::kdf(&key, context, 1))
    }

    #[allow(dead_code, reason = "for the Hero plan")]
    pub(crate) fn runtime(&self) -> tokio::runtime::Handle {
        self.inner.shared.handle.clone()
    }

    /// Test kit only: the secret store this account's device uses.
    #[cfg(feature = "test-support")]
    pub fn test_secrets(&self) -> Arc<dyn crate::SecretStore> {
        self.inner.shared.secrets.clone()
    }
}

/// Socket notifications are hints: on every connection reconcile the list;
/// after a requested hint fetch the list once, not on a polling loop.
async fn listen_approvals(api: Api, events: broadcast::Sender<AccountEvent>, clock: crate::Clock) {
    let mut seen = HashMap::<ApprovalId, ApprovalRequest>::new();
    let mut backoff = Duration::from_millis(500);
    loop {
        if let Ok(mut socket) = api.approvals_live().await
            && reconcile_approvals(&api, &events, &mut seen).await.is_ok()
        {
            let connected_at = clock.now_ms();
            let mut ping = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = ping.tick() => {
                        if socket.send(tokio_tungstenite::tungstenite::Message::Ping(Vec::new().into())).await.is_err() { break; }
                    }
                    message = socket.next() => {
                        let Some(Ok(message)) = message else { break; };
                        if let tokio_tungstenite::tungstenite::Message::Close(Some(frame)) = &message
                            && u16::from(frame.code) == 4001 { return; }
                        if let tokio_tungstenite::tungstenite::Message::Text(text) = message
                            && let Ok(live) = serde_json::from_str::<ApprovalLive>(&text)
                            && live.t == "approval" {
                            if live.state == "requested" {
                                if reconcile_approvals(&api, &events, &mut seen).await.is_err() { break; }
                            } else if seen.contains_key(&live.approval_id)
                                && reconcile_approvals(&api, &events, &mut seen).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            // Short-lived connections must not reset the backoff on every attempt.
            if clock.now_ms().saturating_sub(connected_at) >= 30_000 {
                backoff = Duration::from_millis(500);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn reconcile_approvals(
    api: &Api,
    events: &broadcast::Sender<AccountEvent>,
    seen: &mut HashMap<ApprovalId, ApprovalRequest>,
) -> Result<(), Error> {
    let list = api.approvals().await?.approvals;
    let mut current = HashMap::new();
    for row in list {
        let request = ApprovalRequest {
            id: row.approval_id,
            device_id: row.device_id,
            created_at: row.created_at,
            expires_at: row.expires_at,
        };
        if !seen.contains_key(&request.id) {
            let _ = events.send(AccountEvent::ApprovalRequested(request.clone()));
        }
        current.insert(request.id, request);
    }
    for id in seen.keys() {
        if !current.contains_key(id) {
            let _ = events.send(AccountEvent::ApprovalClosed(*id));
        }
    }
    *seen = current;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Core, CoreConfig, FileSecretStore, SignIn, SignUp};
    use bh_testkit::{LocalServer, invite};

    const PASSWORD: &str = "unit test password";

    fn core(dir: &std::path::Path) -> Core {
        Core::open(CoreConfig {
            data_dir: dir.join("data"),
            secrets: Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap()),
        })
        .unwrap()
    }

    #[test]
    fn account_data_edits_keep_unknown_fields() {
        let mut data = parse_data(br#"{"v":1,"devices":{},"apps":{},"later":{"x":1}}"#).unwrap();
        let device = DeviceId([1; 16]);
        set_device_name(&mut data, device, "mac");
        assert_eq!(device_name(&data, device), "mac");
        assert_eq!(data["later"], json!({ "x": 1 }));
        assert_eq!(parse_data(br#"{"v":2}"#), Err(Error::NeedsUpdate));
    }

    #[tokio::test]
    async fn app_account_cannot_list_approval_requests() {
        let server = LocalServer::from_env();
        crate::client::set_test_bypass(server.operator_token());
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = core(&tmp.path().join("full"))
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "full".into(),
            })
            .await
            .unwrap();
        let db = AccountDb::open(&tmp.path().join("app.sqlite"), &[3; 32]).unwrap();
        db.set_account(&crate::store::AccountRow {
            id: full.id(),
            email: full.email(),
            server: server.url(),
            kind: DeviceKind::App,
            device_id: full.device_id(),
        })
        .unwrap();
        let app = Account::load(full.inner.shared.clone(), db).unwrap();
        assert_eq!(app.approval_requests().await.unwrap_err(), Error::Forbidden);
        assert_eq!(app.test_request_count("v1/approvals"), 0);
    }

    #[tokio::test]
    async fn crate_private_account_helpers_and_finish_work() {
        let server = LocalServer::from_env();
        crate::client::set_test_bypass(server.operator_token());
        let tmp = tempfile::tempdir().unwrap();
        let email = format!("{}@example.test", AccountId::random());
        let (a, kit) = core(&tmp.path().join("a"))
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: email.clone(),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "unit".into(),
            })
            .await
            .unwrap();

        assert_eq!(a.server(), server.url());
        let me = Api::new(a.server(), Some(a.token().unwrap().to_string()))
            .me()
            .await
            .unwrap();
        assert_eq!((me.account_id, me.device_id), (a.id(), a.device_id()));

        let first = a.derive_secret(b"bhtest01").unwrap();
        assert_eq!(
            first.expose(),
            a.derive_secret(b"bhtest01").unwrap().expose()
        );
        assert_ne!(
            first.expose(),
            a.derive_secret(b"bhtest02").unwrap().expose()
        );
        assert_eq!(a.runtime().spawn(async { 42 }).await.unwrap(), 42);

        let pending = core(&tmp.path().join("b"))
            .sign_in(SignIn {
                server: server.url(),
                email,
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "second".into(),
            })
            .await
            .unwrap();
        assert_eq!(pending.api.me().await, Err(Error::Pending));
        assert_eq!(pending.account_id, a.id());
        assert_eq!(pending.device_name, "second");
        let device_id = pending.device_id;
        let b = pending.with_kit(&kit.display()).await.unwrap();
        assert_eq!(b.device_id(), device_id);
        assert_eq!(pending.api.me().await.unwrap().device_id, device_id);
        assert!(Arc::ptr_eq(
            &pending.api.tls(),
            &crate::client::tls_config()
        ));
    }

    #[tokio::test]
    async fn finish_activates_once_and_is_safe_to_repeat_after_activation() {
        let server = LocalServer::from_env();
        crate::client::set_test_bypass(server.operator_token());
        let tmp = tempfile::tempdir().unwrap();
        let email = format!("{}@example.test", AccountId::random());
        let (a, _) = core(&tmp.path().join("a"))
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: email.clone(),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "unit".into(),
            })
            .await
            .unwrap();
        let pending = core(&tmp.path().join("b"))
            .sign_in(SignIn {
                server: server.url(),
                email,
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "second".into(),
            })
            .await
            .unwrap();
        let key = || a.account_key().unwrap();
        let (one, two) = tokio::join!(
            pending.snapshot().finish(key()),
            pending.snapshot().finish(key())
        );
        let results = [one.is_ok(), two.is_ok()];
        assert_eq!(
            results.iter().filter(|ok| **ok).count(),
            1,
            "exactly one finish succeeds"
        );
        for result in [&one, &two] {
            if let Err(e) = result {
                assert_eq!(e, &Error::Invalid("signed in".into()));
            }
        }
        assert_eq!(
            pending
                .with_kit("0000-0000-0000-0000-0000-0000-00")
                .await
                .unwrap_err(),
            Error::Invalid("signed in".into())
        );
    }
}
