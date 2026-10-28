//! `Account`: one signed-in device of one account.

use crate::approval::connect::{
    AppChoice, AppOffer, DEFAULT_APP_CAP_MICRO_USD, OldConnection, OpenAppRequest, WEEK_MS,
    device_name as app_device_name,
};
use crate::approval::protocol::{AppHello, ApproverSide, Digits, Exchange, TTL_MS, email_scope};
use crate::approval::{self, ApprovalRequest, OpenRequest};
use crate::base::{BaseKey, BaseWeak, EPOCH};
use crate::client::Api;
use crate::client::ApprovalLive;
use crate::core::{Shared, derive, login_salt};
use crate::envelope;
use crate::hidden::{self, HiddenKey};
use crate::keys::{self, DEFAULT_KDF, RecoveryKit};
use crate::store::{AccountDb, BaseRow};
use crate::{Base, BaseSummary, EndReason, Error, Mode, UsageRow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_crypto::Secret;
use bh_proto::{
    AccountDataRequest, AccountId, AppDeviceKind, ApprovalId, ApprovalKind, BaseId, BasesRequest,
    Bytes, CredentialsRequest, DeviceId, DevicesRequest, GrantMode, GrantRequest,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, broadcast};
use ts_rs::TS;
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
/// Device capability: full devices manage the account; app devices use only
/// explicitly granted bases.
pub enum DeviceKind {
    /// A signed-in account device.
    Full,
    /// An app installed with its own credentials and base grants.
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
/// A locally installed account; listing these does not contact the server.
pub struct AccountSummary {
    /// Account identifier.
    #[ts(type = "string")]
    pub id: AccountId,
    /// Account email address.
    pub email: String,
    /// Capability of this installation.
    pub kind: DeviceKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
/// One account device, with its name from encrypted account data.
pub struct DeviceSummary {
    /// Device identifier.
    #[ts(type = "string")]
    pub id: DeviceId,
    /// Full or app device.
    pub kind: DeviceKind,
    /// Display name, if available.
    pub name: String,
    /// Server-reported status.
    pub status: String,
    /// Creation time in Unix milliseconds.
    #[ts(type = "number")]
    pub created_at: i64,
    /// Last activity in Unix milliseconds.
    #[ts(type = "number")]
    pub last_seen_at: i64,
    /// Whether this is the current device.
    pub this_device: bool,
    /// An app device's monthly model spending cap in micro-dollars; `None` for full devices.
    #[ts(type = "number | null")]
    pub cap_micro_usd: Option<u64>,
}

/// Usage attributed by random ID, named only from this device's decrypted lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct AccountUsage {
    /// Each month's rows, including months before breakdowns existed.
    pub months: Vec<UsageRow>,
    /// The selected month's UTC days.
    pub days: Vec<UsageRow>,
    /// Names available locally for base IDs; absent IDs need a fallback label.
    #[ts(type = "Record<string, string>")]
    pub base_names: BTreeMap<BaseId, String>,
    /// Names available from decrypted account data; absent IDs are removed devices.
    #[ts(type = "Record<string, string>")]
    pub device_names: BTreeMap<DeviceId, String>,
}

/// A base selected for an app; a new base is created before registering the app device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseGrantRequest {
    /// Grant an existing base.
    Existing {
        /// Existing base identifier.
        base: BaseId,
        /// Requested access mode.
        mode: Mode,
    },
    /// Create and grant a new base.
    New {
        /// Name of the new base.
        name: String,
        /// Requested access mode.
        mode: Mode,
    },
}

/// Connection request from a full device. Empty grants reuse `replaces`' grants.
#[derive(Clone, Debug)]
pub struct AppRequest {
    /// The local display name, never sent in readable form to the server.
    pub app_name: String,
    /// Caller identity used to recognize a reconnecting app.
    pub app_id: Option<String>,
    /// Bases in the order requested by the caller.
    pub bases: Vec<BaseGrantRequest>,
    /// The old app device to remove after a successful connection.
    pub replaces: Option<DeviceId>,
}

/// One base granted to an app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct AppGrant {
    /// The granted base.
    #[ts(type = "string")]
    pub base: BaseId,
    /// Whether this app may change the base.
    pub mode: Mode,
}

/// An app known to this full device from encrypted local account data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct AppSummary {
    /// Its device ID.
    #[ts(type = "string")]
    pub device_id: DeviceId,
    /// Its local display name.
    pub name: String,
    /// Its caller identity, when supplied.
    pub app_id: Option<String>,
    /// Its granted bases, in connection order.
    pub bases: Vec<AppGrant>,
}

/// Credentials for installing an app device. Serialized JSON only gains fields;
/// deserializers ignore unknown fields. Keep the token and key out of logs.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppCredentials {
    /// Server for the app device.
    pub server: Url,
    /// Account email.
    pub email: String,
    /// Account ID.
    pub account_id: AccountId,
    /// Newly registered app device ID.
    pub device_id: DeviceId,
    /// Bearer token; secret.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub token: Zeroizing<String>,
    /// Base64url-encoded app key; secret.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub app_key: Zeroizing<String>,
    /// Granted base IDs in requested order.
    pub bases: Vec<BaseId>,
}

fn serialize_secret<S: serde::Serializer>(
    secret: &Zeroizing<String>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(secret.as_str())
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

impl std::fmt::Debug for AppCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppCredentials")
            .field("server", &self.server)
            .field("email", &self.email)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("token", &"…")
            .field("app_key", &"…")
            .field("bases", &self.bases)
            .finish()
    }
}

/// Changes to an account's bases, devices or approval requests. Subscribe
/// before waiting for a change; reload state if the receiver lags.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum AccountEvent {
    /// Granted bases changed.
    BasesChanged,
    /// Known devices changed.
    DevicesChanged,
    /// This account was removed locally.
    Removed,
    /// A device requested approval.
    ApprovalRequested(ApprovalRequest),
    /// An approval exchange ended.
    ApprovalClosed(ApprovalId),
}

/// Account data, `{ "v": 1, "devices": {}, "apps": {},
/// "kit": { "code": "…", "saved": false, "at": <Unix ms>, "envelope": "<sha256 hex>" } }`,
/// sealed under `kdf(AK, "bhacdat1", 1)`. Edits keep fields this version doesn't know.
/// Erasure is best effort: JSON map strings and WebView display copies of the
/// kit can remain in process memory even when serialized buffers are zeroized.
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

pub(crate) fn envelope_hash(envelope: &[u8]) -> String {
    bh_crypto::sha256(envelope)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn set_kit(data: &mut Data, kit: &RecoveryKit, saved: bool, envelope: &str) {
    let code = Zeroizing::new(kit.display());
    data.insert(
        "kit".into(),
        json!({ "code": code.as_str(), "saved": saved, "at": now_ms(), "envelope": envelope }),
    );
}

/// Whether a full device knows the kit and whether its owner has saved it.
/// No kit code is included in this status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct KitStatus {
    /// Whether encrypted account data holds a kit.
    pub known: bool,
    /// Whether the person has saved that kit.
    pub saved: bool,
    /// Time the kit was made, in Unix milliseconds, when known.
    #[ts(type = "number | null")]
    pub made_at: Option<i64>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn device_name(data: &Data, device: DeviceId) -> String {
    let id = device.to_string();
    ["devices", "apps"]
        .iter()
        .find_map(|map| data.get(*map)?.get(&id)?.get("name")?.as_str())
        .unwrap_or_default()
        .to_string()
}

/// One installed account on this device. Clones share local stores and
/// network sync; an app installation can open only its granted bases.
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
    /// Shared local stop barrier for requests on this account handle and its clones.
    declined_approvals: tokio::sync::Mutex<HashSet<ApprovalId>>,
    /// The open bases, each with its sync task: one per base in this process.
    bases: Mutex<HashMap<BaseId, BaseWeak>>,
    /// Async gate serializes password work, creation and locking for this account.
    hidden_gate: tokio::sync::Mutex<()>,
    /// Synchronous listing cannot block on an async mutex inside an async caller.
    hidden: Mutex<HashMap<BaseId, Base>>,
    #[cfg(feature = "test-support")]
    held_hidden_open: Mutex<
        Option<(
            Arc<tokio::sync::Semaphore>,
            Arc<std::sync::atomic::AtomicBool>,
        )>,
    >,
    #[cfg(feature = "test-support")]
    synthetic_readers: Mutex<HashMap<BaseId, std::collections::BTreeSet<DeviceId>>>,
    listener: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 0 active, 1 erasing, 2 erased, 3 blocked after failed erase.
    removal: Arc<AtomicU8>,
    removal_done: Notify,
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

/// Delete keys before files; safe to repeat after a partial erase.
pub(crate) fn erase_disk(shared: &Shared, id: AccountId, bases: &[BaseId]) -> Result<(), Error> {
    for base in bases {
        shared.secrets.delete(&format!("base.{base}.dbkey"))?;
    }
    for suffix in ["key", "appkey", "token", "dbkey"] {
        shared.secrets.delete(&format!("acct.{id}.{suffix}"))?;
    }
    #[cfg(feature = "test-support")]
    if shared.fail_next_erase.swap(false, Ordering::SeqCst) {
        return Err(Error::Storage("injected erase failure".into()));
    }
    let dir = shared.account_dir(id);
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
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
        let row = {
            let _pass = crate::store::Pass::new();
            db.account()?
        };
        let token = shared.secret(&format!("acct.{}.token", row.id))?;
        let token = String::from_utf8(token.to_vec())
            .map_err(|_| Error::Storage("unreadable token".into()))?;
        let account = Account {
            inner: Arc::new_cyclic(|weak: &std::sync::Weak<Inner>| {
                let weak = weak.clone();
                let api = shared
                    .api(row.server.clone(), Some(token))
                    .with_revocation(move || {
                        if let Some(inner) = weak.upgrade() {
                            let handle = inner.shared.handle.clone();
                            handle.spawn(async move {
                                let _ = (Account { inner }).sign_out().await;
                            });
                        }
                    });
                Inner {
                    api,
                    shared,
                    id: row.id,
                    device_id: row.device_id,
                    email: row.email,
                    kind: row.kind,
                    server: row.server,
                    db: Mutex::new(db),
                    events: broadcast::channel(64).0,
                    declined_approvals: tokio::sync::Mutex::new(HashSet::new()),
                    bases: Mutex::new(HashMap::new()),
                    hidden_gate: tokio::sync::Mutex::new(()),
                    hidden: Mutex::new(HashMap::new()),
                    #[cfg(feature = "test-support")]
                    held_hidden_open: Mutex::new(None),
                    #[cfg(feature = "test-support")]
                    synthetic_readers: Mutex::new(HashMap::new()),
                    listener: Mutex::new(None),
                    removal: Arc::new(AtomicU8::new(0)),
                    removal_done: Notify::new(),
                }
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

    /// Stable account identifier.
    pub fn id(&self) -> AccountId {
        self.inner.id
    }

    /// Identifier of this installed device.
    pub fn device_id(&self) -> DeviceId {
        self.inner.device_id
    }

    /// Account email address from local data.
    pub fn email(&self) -> String {
        self.inner.email.clone()
    }

    /// Whether this installation is a full or app device.
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
    /// Test-only count of requests to the given endpoint path.
    pub fn test_request_count(&self, path: &str) -> usize {
        self.inner.api.count(path)
    }

    /// Test only: pause the next account GET until a permit is added.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_account_get(&self) -> Arc<tokio::sync::Semaphore> {
        self.inner.api.hold_next_account_get()
    }

    /// Test only: pause the next hidden unlock inside the gate before it opens a base.
    /// The returned flag signals when the gate is held; add a permit to release it.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_hidden_open(
        &self,
    ) -> (
        Arc<tokio::sync::Semaphore>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *self.inner.held_hidden_open.lock().unwrap() = Some((release.clone(), entered.clone()));
        (release, entered)
    }

    #[cfg(feature = "test-support")]
    async fn wait_for_test_hidden_open(&self) {
        let hold = self.inner.held_hidden_open.lock().unwrap().take();
        if let Some((release, entered)) = hold {
            entered.store(true, Ordering::SeqCst);
            release.acquire().await.expect("test release").forget();
        }
    }

    /// Subscribes to local account changes; no network call is made.
    pub fn events(&self) -> broadcast::Receiver<AccountEvent> {
        self.inner.events.subscribe()
    }

    fn db(&self) -> crate::store::InUse<'_, AccountDb> {
        crate::store::in_use(&self.inner.db)
    }

    /// Lists ordinary bases, then currently unlocked hidden bases, by name.
    /// Locked hidden bases have no entry. Listing opens ordinary bases locally
    /// and starts their background sync; it does not wait for the network.
    pub fn bases(&self) -> Vec<BaseSummary> {
        let rows = self.db().bases().unwrap_or_default();
        let mut list: Vec<_> = rows
            .into_iter()
            .filter_map(|row| {
                let base = self.base(row.id).ok()?;
                Some(BaseSummary {
                    id: row.id,
                    name: base.name(),
                    mode: row.mode,
                    hidden: false,
                })
            })
            .collect();
        list.sort_by_cached_key(|s| (s.name.to_lowercase(), s.id));
        let handles: Vec<_> = self
            .inner
            .hidden
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        let mut hidden: Vec<_> = handles
            .iter()
            .map(|base| BaseSummary {
                id: base.id(),
                name: base.name(),
                mode: base.mode(),
                hidden: true,
            })
            .collect();
        hidden.sort_by_cached_key(|s| (s.name.to_lowercase(), s.id));
        list.extend(hidden);
        list
    }

    /// App device IDs with a local grant for this base, without a network call.
    pub(crate) fn app_readers(&self, base: BaseId) -> BTreeSet<DeviceId> {
        #[cfg(feature = "test-support")]
        if let Some(readers) = self.inner.synthetic_readers.lock().unwrap().get(&base) {
            return readers.clone();
        }
        self.apps()
            .into_iter()
            .filter(|app| app.bases.iter().any(|grant| grant.base == base))
            .map(|app| app.device_id)
            .collect()
    }

    /// Apps known from the encrypted local account data; never contacts the server.
    pub fn apps(&self) -> Vec<AppSummary> {
        if self.kind() != DeviceKind::Full {
            return Vec::new();
        }
        let Some((_, json)) = self.db().account_data().ok().flatten() else {
            return Vec::new();
        };
        let Ok(data) = parse_data(json.as_bytes()) else {
            return Vec::new();
        };
        let Some(entries) = data.get("apps").and_then(Value::as_object) else {
            return Vec::new();
        };
        entries
            .iter()
            .filter_map(|(device, entry)| {
                let device_id = device.parse().ok()?;
                let grants = entry.get("bases")?.as_object()?;
                let mut bases: Vec<_> = grants
                    .iter()
                    .filter_map(|(id, mode)| {
                        Some(AppGrant {
                            base: id.parse().ok()?,
                            mode: match mode.as_str()? {
                                "rw" => Mode::ReadWrite,
                                "ro" => Mode::ReadOnly,
                                _ => return None,
                            },
                        })
                    })
                    .collect();
                if let Some(order) = entry.get("baseOrder").and_then(Value::as_array) {
                    bases.sort_by_key(|grant| {
                        order
                            .iter()
                            .position(|id| id.as_str() == Some(&grant.base.to_string()))
                            .unwrap_or(usize::MAX)
                    });
                }
                Some(AppSummary {
                    device_id,
                    name: entry.get("name")?.as_str()?.to_string(),
                    app_id: entry
                        .get("appId")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    bases,
                })
            })
            .collect()
    }

    /// Permission answers are keyed by both the chat's base and its object ID.
    /// Missing or unreadable account data does not authorize another base.
    pub(crate) fn hero_permissions(
        &self,
        base: BaseId,
        chat: crate::ObjectId,
    ) -> (Vec<BaseId>, Vec<BaseId>) {
        let data = self.kit_data().ok();
        let permissions = data
            .as_ref()
            .and_then(|data| data.get("heroPermissions"))
            .and_then(|bases| bases.get(base.to_string()))
            .and_then(|chats| chats.get(chat.to_string()));
        let ids = |key| {
            permissions
                .and_then(|p| p.get(key))
                .and_then(|value| serde_json::from_value(value.clone()).ok())
                .unwrap_or_default()
        };
        (ids("allowed"), ids("denied"))
    }

    pub(crate) async fn set_hero_permission(
        &self,
        base: BaseId,
        chat: crate::ObjectId,
        requested: BaseId,
        allow: bool,
    ) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        self.update_data(move |data| {
            let chats = entry(entry(data, "heroPermissions"), &base.to_string());
            let permission = entry(chats, &chat.to_string());
            let key = if allow { "allowed" } else { "denied" };
            let mut ids: Vec<BaseId> = permission
                .get(key)
                .and_then(|value| serde_json::from_value(value.clone()).ok())
                .unwrap_or_default();
            if !ids.contains(&requested) {
                ids.push(requested);
            }
            permission.insert(key.into(), json!(ids));
        })
        .await
    }

    /// Reads the kit from cached encrypted account data without the network.
    /// Accounts created by older versions, or whose initial data write failed,
    /// return `None` until a new kit is made or a kit sign-in records one.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on app devices, [`Error::Storage`] for
    /// unreadable cached data, or [`Error::BadKit`] for a malformed stored kit.
    pub fn recovery_kit(&self) -> Result<Option<RecoveryKit>, Error> {
        let data = self.kit_data()?;
        self.current_kit(&data)?
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .map(RecoveryKit::parse)
            .transpose()
    }

    /// Reads whether the kit is known and saved, from cached account data;
    /// never contacts the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on app devices or [`Error::Storage`] for
    /// unreadable cached data.
    pub fn kit_status(&self) -> Result<KitStatus, Error> {
        let data = self.kit_data()?;
        let kit = self.current_kit(&data)?;
        Ok(KitStatus {
            known: kit
                .and_then(|v| v.get("code"))
                .and_then(Value::as_str)
                .is_some(),
            saved: kit
                .and_then(|v| v.get("saved"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            made_at: kit.and_then(|v| v.get("at")).and_then(Value::as_i64),
        })
    }

    fn current_kit<'a>(&self, data: &'a Data) -> Result<Option<&'a Value>, Error> {
        let hash = self.db().envelope_hash()?;
        Ok(data.get("kit").filter(|kit| {
            hash.as_deref()
                .is_some_and(|current| kit.get("envelope").and_then(Value::as_str) == Some(current))
        }))
    }

    fn kit_data(&self) -> Result<Data, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        self.db()
            .account_data()?
            .map(|(_, json)| parse_data(json.as_bytes()))
            .transpose()
            .map(|data| data.unwrap_or_else(new_data))
    }

    /// Marks the kit actually shown or saved as saved in encrypted account data.
    /// Needs the network; retries a concurrent edit rather than losing it.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on app devices, [`Error::NotFound`] if
    /// this account has no stored kit, [`Error::Conflict`] if it is not the
    /// current kit, or network, crypto and storage errors from the update.
    pub async fn set_kit_saved(&self, kit: &RecoveryKit) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let expected = kit.clone();
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stale = changed.clone();
                let missing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let absent = missing.clone();
                this.update_data_with_envelope(move |data, current_hash| {
                    let stored = data.get("kit");
                    let current = stored
                        .filter(|v| v.get("envelope").and_then(Value::as_str) == Some(current_hash))
                        .and_then(|v| v.get("code"))
                        .and_then(Value::as_str)
                        .and_then(|text| RecoveryKit::parse(text).ok());
                    if current.as_ref() == Some(&expected) {
                        data["kit"]["saved"] = Value::Bool(true);
                        true
                    } else {
                        if stored.is_none() {
                            absent.store(true, Ordering::Relaxed);
                        } else {
                            stale.store(true, Ordering::Relaxed);
                        }
                        false
                    }
                })
                .await?;
                if changed.load(Ordering::Relaxed) {
                    Err(Error::Conflict("kit_changed".into()))
                } else if missing.load(Ordering::Relaxed) {
                    Err(Error::NotFound)
                } else {
                    Ok(())
                }
            })
            .await
    }

    /// Connects an app as its own device. Needs the network and a full account.
    /// A failed grant removes the new device before returning; an old device is
    /// removed only after all new grants succeed. The returned credentials
    /// contain the granted base IDs in request order, even when reusing grants.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] for an app account, [`Error::Invalid`]
    /// for an empty or overlong name, missing grants or duplicate bases,
    /// [`Error::NotFound`] for an unknown replacement/base, [`Error::Network`]
    /// on connection failure, or server/storage errors including
    /// [`Error::Revoked`], [`Error::Conflict`] and [`Error::Storage`].
    pub async fn connect_app(&self, req: AppRequest) -> Result<AppCredentials, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                this.connect_app_with(req, DeviceId::random(), DEFAULT_APP_CAP_MICRO_USD)
                    .await
            })
            .await
    }

    /// Registers `device_id` as an app device with `cap_micro_usd` and grants it.
    async fn connect_app_with(
        &self,
        req: AppRequest,
        device_id: DeviceId,
        cap_micro_usd: u64,
    ) -> Result<AppCredentials, Error> {
        let name = req.app_name.trim();
        if name.is_empty() || name.chars().count() > 60 {
            return Err(Error::invalid("app name"));
        }
        let requested = if req.bases.is_empty() {
            let old = req.replaces.ok_or_else(|| Error::invalid("app bases"))?;
            let previous = self
                .apps()
                .into_iter()
                .find(|app| app.device_id == old)
                .ok_or(Error::NotFound)?;
            previous
                .bases
                .into_iter()
                .map(|grant| BaseGrantRequest::Existing {
                    base: grant.base,
                    mode: grant.mode,
                })
                .collect()
        } else {
            req.bases.clone()
        };
        // Reject malformed requests before creating bases or registering a device.
        let mut seen = HashSet::new();
        for grant in &requested {
            if let BaseGrantRequest::Existing { base, .. } = grant {
                if !seen.insert(*base) {
                    return Err(Error::invalid("duplicate base"));
                }
                if self
                    .db()
                    .hidden_wrappers()?
                    .iter()
                    .any(|(id, _, _)| id == base)
                {
                    return Err(Error::Forbidden);
                }
                self.base(*base)?;
            }
        }
        if let Some(old) = req.replaces
            && !self.apps().iter().any(|app| app.device_id == old)
        {
            return Err(Error::NotFound);
        }
        let mut grants = Vec::with_capacity(requested.len());
        for grant in requested {
            match grant {
                BaseGrantRequest::Existing { base, mode } => grants.push((base, mode)),
                BaseGrantRequest::New { name, mode } => {
                    grants.push((self.create_base(&name).await?.id(), mode))
                }
            }
        }
        seen.clear();
        if grants.iter().any(|(base, _)| !seen.insert(*base)) {
            return Err(Error::invalid("duplicate base"));
        }
        let app_key = Secret::<32>::random();
        let key = Zeroizing::new(URL_SAFE_NO_PAD.encode(app_key.expose()));
        let token = match self
            .inner
            .api
            .add_device(&DevicesRequest {
                device_id,
                kind: AppDeviceKind::App,
                cap_micro_usd: Some(cap_micro_usd),
            })
            .await
        {
            Ok(response) => response.token,
            Err(error) => {
                // A lost reply can follow registration. The ID is known even
                // without the token, so revoke it before another attempt.
                if matches!(error, Error::Network(_)) {
                    match self.inner.api.delete_device(device_id).await {
                        Ok(_) | Err(Error::NotFound) => {}
                        Err(_) => {
                            return Err(Error::Network(
                                "failed to remove an interrupted app device".into(),
                            ));
                        }
                    }
                }
                return Err(error);
            }
        };
        let result = self
            .grant_new_app(device_id, req, &key, &app_key, &grants)
            .await;
        match result {
            Ok(()) => Ok(AppCredentials {
                server: self.inner.server.clone(),
                email: self.email(),
                account_id: self.id(),
                device_id,
                token: Zeroizing::new(token),
                app_key: key,
                bases: grants.iter().map(|(base, _)| *base).collect(),
            }),
            Err(error) => {
                // Revoke first: even an ambiguous grant reply may have installed a grant.
                let removed = self.inner.api.delete_device(device_id).await;
                if removed.is_ok() || matches!(removed, Err(Error::NotFound)) {
                    self.update_data(move |data| {
                        entry(data, "apps").remove(&device_id.to_string());
                    })
                    .await?;
                    Err(error)
                } else {
                    Err(Error::Network(
                        "failed to remove an interrupted app device".into(),
                    ))
                }
            }
        }
    }

    async fn grant_new_app(
        &self,
        device_id: DeviceId,
        req: AppRequest,
        key: &str,
        app_key: &Secret<32>,
        grants: &[(BaseId, Mode)],
    ) -> Result<(), Error> {
        let mut bases = Map::new();
        for (id, mode) in grants {
            bases.insert(
                id.to_string(),
                json!(match mode {
                    Mode::ReadWrite => "rw",
                    Mode::ReadOnly => "ro",
                }),
            );
        }
        let order: Vec<String> = grants.iter().map(|(id, _)| id.to_string()).collect();
        let key = Zeroizing::new(key.to_owned());
        let replaces = req.replaces;
        self.update_data(move |data| {
            entry(data, "apps").insert(
                device_id.to_string(),
                json!({
                    "name": req.app_name.trim(), "appId": req.app_id, "key": key.as_str(), "bases": bases, "baseOrder": order
                }),
            );
        })
        .await?;
        for (base, mode) in grants {
            let row = self
                .db()
                .bases()?
                .into_iter()
                .find(|row| row.id == *base)
                .ok_or(Error::NotFound)?;
            let base_key = self.base_key(&row)?;
            let wrapper = envelope::seal(
                &bh_crypto::kdf(app_key, b"bhbasew1", 1),
                &keys::app_wrapper_aad(base, &device_id, row.epoch),
                base_key.secret().expose(),
            );
            self.inner
                .api
                .grant(
                    *base,
                    device_id,
                    &GrantRequest {
                        mode: match mode {
                            Mode::ReadWrite => GrantMode::ReadWrite,
                            Mode::ReadOnly => GrantMode::ReadOnly,
                        },
                        epoch: row.epoch,
                        wrapper: Bytes(wrapper),
                    },
                )
                .await?;
        }
        if let Some(old) = replaces {
            self.inner.api.delete_device(old).await?;
            self.update_data(move |data| {
                entry(data, "apps").remove(&old.to_string());
            })
            .await?;
        }
        Ok(())
    }

    /// Revokes a device and removes its app listing. Removing this device also
    /// erases it locally. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] when an app removes another device,
    /// [`Error::Network`] if revocation fails, [`Error::NotFound`] for an
    /// unknown device, or [`Error::Storage`] if local erasure fails.
    pub async fn remove_device(&self, id: DeviceId) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full && self.device_id() != id {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let removed = this.inner.api.delete_device(id).await;
                if id == this.device_id() {
                    if let Err(error) = removed {
                        // A failed DELETE may or may not have revoked us. Only a
                        // subsequent authenticated 401 revoked confirms erasure.
                        if !matches!(this.inner.api.me().await, Err(Error::Revoked)) {
                            return Err(error);
                        }
                    }
                    this.sign_out().await?;
                } else if this.kind() == DeviceKind::Full {
                    removed?;
                    this.update_data(move |data| {
                        entry(data, "apps").remove(&id.to_string());
                    })
                    .await?;
                }
                Ok(())
            })
            .await
    }

    /// Synthetic app grants for Hero's access tests.
    #[cfg(feature = "test-support")]
    pub fn test_set_app_readers(
        &self,
        base: BaseId,
        readers: std::collections::BTreeSet<DeviceId>,
    ) {
        self.inner
            .synthetic_readers
            .lock()
            .unwrap()
            .insert(base, readers);
    }

    fn version_device_name(&self, id: DeviceId) -> Option<String> {
        if self.kind() == DeviceKind::App {
            return None;
        }
        self.db()
            .account_data()
            .ok()
            .flatten()
            .and_then(|(_, json)| parse_data(json.as_bytes()).ok())
            .and_then(|data| {
                data.get("devices")?
                    .get(id.to_string())?
                    .get("name")?
                    .as_str()
                    .map(str::to_owned)
            })
            .filter(|name| !name.is_empty())
    }

    fn attach_version_names(&self, base: &Base) {
        let weak = Arc::downgrade(&self.inner);
        base.set_version_device_name(move |id| {
            let inner = weak.upgrade()?;
            Account { inner }.version_device_name(id)
        });
    }

    pub(crate) fn app_reader_name(&self, id: DeviceId) -> String {
        self.db()
            .account_data()
            .ok()
            .flatten()
            .and_then(|(_, json)| parse_data(json.as_bytes()).ok())
            .map(|data| device_name(&data, id))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.to_string())
    }

    pub(crate) fn check_active(&self) -> Result<(), Error> {
        if self.inner.removal.load(Ordering::SeqCst) != 0 {
            Err(Error::Revoked)
        } else {
            Ok(())
        }
    }

    /// The open base `id`, the same one on every call in this process.
    /// A locked hidden base is not openable by ID; use [`Self::unlock_hidden`].
    /// Opening uses local data; its background sync may then use the network.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] for a base not granted to this device,
    /// [`Error::Revoked`] after local removal, [`Error::NeedsUpdate`] for
    /// unsupported data, or [`Error::Storage`] for a local store failure.
    pub fn base(&self, id: BaseId) -> Result<Base, Error> {
        let mut open = self
            .inner
            .bases
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.inner.removal.load(Ordering::SeqCst) != 0 {
            return Err(Error::Revoked);
        }
        if let Some(base) = self.inner.hidden.lock().unwrap().get(&id) {
            return Ok(base.clone());
        }
        let row = self
            .db()
            .bases()?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or(Error::NotFound)?;
        let key = self.base_key(&row).map_err(|e| match e {
            Error::Crypto => Error::NotFound,
            other => other,
        })?;
        if let Some(base) = open.get(&id).and_then(BaseWeak::upgrade) {
            return Ok(base);
        }
        let path = self
            .inner
            .shared
            .account_dir(self.inner.id)
            .join("bases")
            .join(format!("{id}.sqlite"));
        let base = Base::open(
            &path,
            &*self.inner.shared.secrets,
            id,
            key,
            row.mode,
            Some(self.inner.device_id),
            Some(self.inner.removal.clone()),
        )?;
        base.set_full(self.kind() == DeviceKind::Full);
        self.attach_version_names(&base);
        base.start_sync(
            self.inner.api.clone(),
            &self.inner.shared.handle,
            self.inner.shared.clock.clone(),
        );
        open.insert(id, base.downgrade());
        Ok(base)
    }

    /// Opens a hidden base without ever creating an account-key-only store secret.
    pub(crate) fn open_base_with_key(
        &self,
        id: BaseId,
        key: BaseKey,
        store_key: &Secret<32>,
        mode: Mode,
    ) -> Result<Base, Error> {
        self.check_active()?;
        let path = self
            .inner
            .shared
            .account_dir(self.id())
            .join("bases")
            .join(format!("{id}.sqlite"));
        let base = Base::open_store(
            &path,
            store_key.expose(),
            id,
            key,
            mode,
            Some(self.device_id()),
        )?;
        base.set_removal(self.inner.removal.clone());
        base.set_full(self.kind() == DeviceKind::Full);
        self.attach_version_names(&base);
        base.start_sync(
            self.inner.api.clone(),
            &self.inner.shared.handle,
            self.inner.shared.clock.clone(),
        );
        self.inner.hidden.lock().unwrap().insert(id, base.clone());
        Ok(base)
    }

    /// Opens a base key's wrapper: the account's on full devices, the app's own on app devices.
    fn base_key(&self, row: &BaseRow) -> Result<BaseKey, Error> {
        let aad = match self.inner.kind {
            DeviceKind::Full => keys::account_wrapper_aad(&row.id, row.epoch),
            DeviceKind::App => keys::app_wrapper_aad(&row.id, &self.inner.device_id, row.epoch),
        };
        let key = envelope::open(&self.derive_secret(b"bhbasew1")?, &aad, &row.wrapper)?;
        BaseKey::new(&key)
    }

    /// Creates a base named `name`, with a new key that only this account's
    /// key opens. Full devices only. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for an empty name, [`Error::Forbidden`] on
    /// an app device, [`Error::Revoked`] for a removed device, [`Error::Network`]
    /// for connection failure, [`Error::Conflict`] if a key conflicts, or
    /// [`Error::Storage`] for a local store failure.
    pub async fn create_base(&self, name: &str) -> Result<Base, Error> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(Error::invalid("base name"));
        }
        if self.inner.removal.load(Ordering::SeqCst) != 0 {
            return Err(Error::Revoked);
        }
        if self.inner.kind != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let id = BaseId::random();
                let key = Secret::<32>::random();
                let wrapper = envelope::seal(
                    &this.derive_secret(b"bhbasew1")?,
                    &keys::account_wrapper_aad(&id, EPOCH),
                    key.expose(),
                );
                let request = BasesRequest {
                    base_id: id,
                    epoch: EPOCH,
                    wrapper: Bytes(wrapper.clone()),
                };
                let api = &this.inner.api;
                match api.create_base(&request).await {
                    Ok(_) => {}
                    // The first request may have been stored before its reply
                    // was lost; then the base's key is the one just sent.
                    Err(Error::Network(_)) => match api.create_base(&request).await {
                        Ok(_) => {}
                        Err(Error::Conflict(code)) if code == "exists" => {
                            if api.base_key(id).await?.wrapper.0 != wrapper {
                                return Err(Error::Conflict(code));
                            }
                        }
                        Err(e) => return Err(e),
                    },
                    Err(e) => return Err(e),
                }
                let db = this.db();
                if this.inner.removal.load(Ordering::SeqCst) != 0 {
                    return Err(Error::Revoked);
                }
                db.put_base(
                    &BaseRow {
                        id,
                        epoch: EPOCH,
                        wrapper,
                        mode: Mode::ReadWrite,
                    },
                    now_ms(),
                )?;
                drop(db);
                let base = this.base(id)?;
                base.write_info(&name)?;
                let _ = this.inner.events.send(AccountEvent::BasesChanged);
                Ok(base)
            })
            .await
    }

    /// Creates a hidden base sealed under the account key and extra password.
    /// Needs the network to create the base on the server; after creation it
    /// opens the base locally, starts sync and announces `BasesChanged`. Only
    /// full devices may create one. The password is never sent to the server.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on app devices, [`Error::Invalid`] for an
    /// empty name or password, [`Error::Revoked`] after device removal,
    /// [`Error::Network`] when the server is unreachable, [`Error::Conflict`]
    /// on a conflicting server key, [`Error::Storage`] for a local store or
    /// password-derivation failure, [`Error::Crypto`] for invalid local key
    /// material, or [`Error::NeedsUpdate`] for an unsupported store format.
    pub async fn create_hidden_base(
        &self,
        name: &str,
        password: Zeroizing<String>,
    ) -> Result<Base, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(Error::invalid("base name"));
        }
        if password.is_empty() {
            return Err(Error::invalid("password"));
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                // Known limit: creation holds this gate during server calls. A
                // lock requested meanwhile cannot hide already-open hidden
                // bases until the call returns or times out.
                let _gate = this.inner.hidden_gate.lock().await;
                this.check_active()?;
                let account_key = this.account_key()?;
                let hidden_key =
                    tokio::task::spawn_blocking(move || HiddenKey::derive(&account_key, &password))
                        .await
                        .map_err(|_| Error::Storage("hidden key derivation failed".into()))??;
                let id = BaseId::random();
                let raw_key = Zeroizing::new(bh_crypto::random::<32>());
                let key = BaseKey::new(&*raw_key)?;
                let wrapper = hidden_key.wrap(this.id(), id, EPOCH, &key);
                let request = BasesRequest {
                    base_id: id,
                    epoch: EPOCH,
                    wrapper: Bytes(wrapper.clone()),
                };
                let api = &this.inner.api;
                match api.create_base(&request).await {
                    Ok(_) => {}
                    Err(Error::Network(_)) => match api.create_base(&request).await {
                        Ok(_) => {}
                        Err(Error::Conflict(code)) if code == "exists" => {
                            if api.base_key(id).await?.wrapper.0 != wrapper {
                                return Err(Error::Conflict(code));
                            }
                        }
                        Err(e) => return Err(e),
                    },
                    Err(e) => return Err(e),
                }
                this.check_active()?;
                this.db().remember_hidden(id, EPOCH, &wrapper)?;
                let store_key = hidden::store_key(&key);
                let base = this.open_base_with_key(id, key, &store_key, Mode::ReadWrite)?;
                base.write_info(&name)?;
                let _ = this.inner.events.send(AccountEvent::BasesChanged);
                Ok(base)
            })
            .await
    }

    /// Tests one extra password against every local hidden wrapper, opening
    /// every matching base and returning summaries including already-open ones.
    /// Works offline and makes no network request; opened bases start background
    /// sync when connectivity is available. Runs one Argon2id even if the index
    /// is empty. Announces `BasesChanged` if any base opens, even if a later
    /// matching store cannot open.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on app devices, [`Error::Invalid`] for an
    /// empty password, [`Error::NothingUnlocked`] if no wrapper matches,
    /// [`Error::Revoked`] after device removal, [`Error::Storage`] for a local
    /// store or password-derivation failure, [`Error::Crypto`] for invalid local
    /// key material, or [`Error::NeedsUpdate`] for an unsupported store format.
    pub async fn unlock_hidden(
        &self,
        password: Zeroizing<String>,
    ) -> Result<Vec<BaseSummary>, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let _gate = this.inner.hidden_gate.lock().await;
                this.check_active()?;
                #[cfg(feature = "test-support")]
                this.wait_for_test_hidden_open().await;
                let account_key = this.account_key()?;
                let key =
                    tokio::task::spawn_blocking(move || HiddenKey::derive(&account_key, &password))
                        .await
                        .map_err(|_| Error::Storage("hidden key derivation failed".into()))??;
                let wrappers = this.db().hidden_wrappers()?;
                let mut found = Vec::new();
                let mut added = false;
                for (id, epoch, wrapper) in wrappers {
                    if let Some(base_key) = key.open(this.id(), id, epoch, &wrapper) {
                        let base = if let Some(base) = this.inner.hidden.lock().unwrap().get(&id) {
                            base.clone()
                        } else {
                            let store_key = hidden::store_key(&base_key);
                            match this.open_base_with_key(id, base_key, &store_key, Mode::ReadWrite)
                            {
                                Ok(base) => {
                                    added = true;
                                    base
                                }
                                Err(err) => {
                                    if added {
                                        let _ = this.inner.events.send(AccountEvent::BasesChanged);
                                    }
                                    return Err(err);
                                }
                            }
                        };
                        found.push(BaseSummary {
                            id,
                            name: base.name(),
                            mode: base.mode(),
                            hidden: true,
                        });
                    }
                }
                if found.is_empty() {
                    return Err(Error::NothingUnlocked);
                }
                if added {
                    let _ = this.inner.events.send(AccountEvent::BasesChanged);
                }
                Ok(found)
            })
            .await
    }

    /// Once it acquires the hidden-base gate, removes an unlocked hidden base
    /// from account navigation, then tries to flush its edits for up to two
    /// seconds before stopping sync and closing
    /// its store and handles. Flushing uses the network if online, but locking
    /// does not require connectivity. Once started, locking continues if the
    /// caller drops its future. A create stalled on the network can delay the
    /// gate (and thus hiding an already-open base). Previously queued subscriber
    /// updates may still be read after locking.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if `id` is not an unlocked hidden base, or
    /// [`Error::Network`] if the core's runtime is shutting down before the
    /// operation starts. Flush failures are ignored; unsent edits stay local.
    pub async fn lock_hidden(&self, id: BaseId) -> Result<(), Error> {
        let this = self.clone();
        self.inner
            .shared
            .run(async move { this.lock_hidden_here(Some(id)).await })
            .await
    }

    /// Locks every unlocked hidden base, including ones opened by an in-progress
    /// unlock or create. All bases share one two-second deadline for flushing
    /// pending edits. Flushes use the network if online, but locking does not
    /// need connectivity. Once started, the lock continues if the caller drops
    /// its future. A create stalled on the network can delay the gate, leaving
    /// already-open bases visible until it returns. Already-queued subscriber
    /// updates may still be read after locking.
    pub async fn lock_all_hidden(&self) {
        let this = self.clone();
        let _ = self
            .inner
            .shared
            .run(async move { this.lock_hidden_here(None).await })
            .await;
    }

    async fn lock_hidden_here(&self, id: Option<BaseId>) -> Result<(), Error> {
        // Take the gate before selecting bases: an unlock or create already in
        // progress must not leave a newly opened base behind after lock-all.
        let _gate = self.inner.hidden_gate.lock().await;
        let bases: Vec<Base> = {
            let mut hidden = self.inner.hidden.lock().unwrap();
            match id {
                Some(id) => vec![hidden.remove(&id).ok_or(Error::NotFound)?],
                None => hidden.drain().map(|(_, base)| base).collect(),
            }
        };
        for _ in &bases {
            let _ = self.inner.events.send(AccountEvent::BasesChanged);
        }
        // The account event is a fallback; locking must itself await every turn
        // before flushing or closing the base's store.
        for base in &bases {
            crate::hero::cancel_account_base(self, base).await;
        }
        // Already queued subscriber updates can still be read after locking.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let _ = tokio::time::timeout_at(
            deadline,
            futures_util::future::join_all(bases.iter().map(Base::flush)),
        )
        .await;
        for base in bases {
            base.close().await;
        }
        Ok(())
    }

    /// Blocks writes, stops background work, then erases secrets and stores.
    /// Repeated calls, including simultaneous revocation notifications, are no-ops.
    /// Does not need the network (stops local background work).
    ///
    /// # Errors
    /// Returns [`Error::Storage`] if local erasure fails, or [`Error::Revoked`]
    /// after an earlier erasure failed.
    pub async fn sign_out(&self) -> Result<(), Error> {
        // Serialize the transition with base(): a base must not start sync
        // after we've collected the tasks to stop.
        {
            let _bases = self.inner.bases.lock().unwrap();
            if self
                .inner
                .removal
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                drop(_bases);
                loop {
                    let notified = self.inner.removal_done.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    match self.inner.removal.load(Ordering::SeqCst) {
                        1 => notified.await,
                        2 => return Ok(()),
                        _ => return Err(Error::Revoked),
                    }
                }
            }
            if let Some(accounts) = self.inner.shared.accounts.lock().unwrap().upgrade() {
                accounts.lock().unwrap().remove(&self.inner.id);
            }
        }
        let result = self.erase_local().await;
        self.inner
            .removal
            .store(if result.is_ok() { 2 } else { 3 }, Ordering::SeqCst);
        self.inner.removal_done.notify_waiters();
        result
    }

    async fn erase_local(&self) -> Result<(), Error> {
        let dir = self.inner.shared.account_dir(self.inner.id);
        // The marker precedes all cleanup. A crash or failed deletion is resumed
        // at Core::open and the account is never offered as signed in again.
        std::fs::File::create(dir.join(".erasing"))?;
        #[cfg(feature = "test-support")]
        {
            let gate = self.inner.shared.hold_erase.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.acquire().await.expect("erase gate open").forget();
            }
        }
        // Drain writes already inside the account store before collecting base IDs.
        let base_ids: Vec<_> = self.db().bases()?.into_iter().map(|base| base.id).collect();
        if let Some(task) = self.inner.stop_listener() {
            let _ = task.await;
        }
        crate::hero::stop_account_turns(self).await;
        let bases: Vec<_> = self
            .inner
            .bases
            .lock()
            .unwrap()
            .values()
            .filter_map(BaseWeak::upgrade)
            .collect();
        for base in bases {
            base.stop_sync().await;
            // A writer already in the store lock finishes before deletion.
            drop(base.db());
        }
        // Sign-out shares the gate with unlock/create, so it cannot drain
        // before an in-progress unlock registers its base.
        let _gate = self.inner.hidden_gate.lock().await;
        let hidden: Vec<_> = self
            .inner
            .hidden
            .lock()
            .unwrap()
            .drain()
            .map(|(_, base)| base)
            .collect();
        for base in hidden {
            base.close().await;
        }
        erase_disk(&self.inner.shared, self.inner.id, &base_ids)?;
        let _ = self.inner.events.send(AccountEvent::Removed);
        Ok(())
    }

    /// Lists requests without answering them or sending any message to the new device.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device, [`Error::Network`]
    /// on connection failure, or server errors such as [`Error::Revoked`].
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
                        kind: r.kind.into(),
                    })
                    .collect())
            })
            .await
    }

    /// Opens a listed request on explicit user action and waits for its reveal.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device,
    /// [`Error::ApprovalEnded`] if expired, declined or already answered,
    /// [`Error::Network`] for connection failure, or [`Error::Storage`] for
    /// a local claim failure.
    pub async fn open_request(&self, id: ApprovalId) -> Result<OpenRequest, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move { this.open_request_here(id).await })
            .await
    }

    async fn open_request_here(&self, id: ApprovalId) -> Result<OpenRequest, Error> {
        let (device_id, side, deadline) = self.open_here(id, Exchange::Device).await?;
        Ok(OpenRequest {
            id,
            device_id,
            side: Some(side),
            api: self.inner.api.clone(),
            clock: self.inner.shared.clock.clone(),
            deadline,
            handle: self.inner.shared.handle.clone(),
        })
    }

    /// Opens an app's request on explicit user action and waits for its reveal.
    /// It reads "An app wants to connect" until [`OpenAppRequest::check_digits`]
    /// matches. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device, [`Error::Invalid`] for a
    /// device's request, [`Error::ApprovalEnded`] if expired, declined or already
    /// answered, [`Error::Network`] for connection failure, or [`Error::Storage`]
    /// for a local claim failure.
    pub async fn open_app_request(&self, id: ApprovalId) -> Result<OpenAppRequest, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let (device_id, side, deadline) = this.open_here(id, Exchange::App).await?;
                Ok(OpenAppRequest {
                    id,
                    device_id,
                    side: Some(side),
                    account: this,
                    deadline,
                    checked: None,
                })
            })
            .await
    }

    /// Registers the app's device with the chosen bases and cap, then sends it
    /// its credentials under the exchange's key. Registers nothing once the two
    /// minutes have passed, and removes the device again if the credentials
    /// can't be sent. Needs the network.
    ///
    /// Returns the new device and whether the requested old connection was removed.
    /// A failed removal does not undo the already transferred connection.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] for another device's request or a hidden
    /// base, [`Error::Invalid`] before the digits matched or for a bad choice,
    /// [`Error::ApprovalEnded`] for an ended exchange, or network and server
    /// errors from registering the device.
    pub async fn approve_app(
        &self,
        mut request: OpenAppRequest,
        choice: AppChoice,
    ) -> Result<(DeviceId, bool), Error> {
        if self.kind() != DeviceKind::Full
            || (request.account.id(), request.account.device_id()) != (self.id(), self.device_id())
        {
            return Err(Error::Forbidden);
        }
        let Some(offer) = request.checked.clone() else {
            return Err(Error::invalid("digits not checked"));
        };
        // Only the connection this offer names as the app's old one may be removed.
        if choice
            .replaces
            .is_some_and(|d| offer.old.as_ref().map(|o| o.device_id) != Some(d))
        {
            return Err(Error::invalid("replaces is not this app's old connection"));
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let side = request
                    .side
                    .take()
                    .ok_or(Error::ApprovalEnded(EndReason::Cancelled))?;
                let api = &this.inner.api;
                let (id, device) = (request.id, request.device_id);
                let clock = this.clock();
                if clock.now_ms() >= request.deadline {
                    let _ = api.approval_end(id, EndReason::Expired).await;
                    return Err(Error::ApprovalEnded(EndReason::Expired));
                }
                if this.inner.declined_approvals.lock().await.contains(&id) {
                    return Err(Error::ApprovalEnded(EndReason::Declined));
                }
                match api.approval(id).await {
                    Ok(Some(state)) if state.state == "ended" => {
                        return Err(Error::ApprovalEnded(
                            state.end_reason.unwrap_or(EndReason::BadMessage),
                        ));
                    }
                    Ok(_) => {}
                    Err(e) => {
                        let _ = api.approval_end(id, EndReason::BadMessage).await;
                        return Err(e);
                    }
                }
                let req = AppRequest {
                    app_name: offer.device_name,
                    app_id: Some(offer.app_id),
                    bases: choice.bases,
                    replaces: None,
                };
                let credentials = match this
                    .connect_app_with(req, device, choice.cap_micro_usd)
                    .await
                {
                    Ok(credentials) => credentials,
                    Err(e) => {
                        let _ = api.approval_end(id, EndReason::BadMessage).await;
                        return Err(e);
                    }
                };
                let sent = async {
                    let payload = Zeroizing::new(
                        serde_json::to_vec(&credentials)
                            .map_err(|_| Error::ApprovalEnded(EndReason::BadMessage))?,
                    );
                    let transfer = side.seal_payload(&payload, clock.now_ms())?;
                    // As for a device: a decline wins before the transfer, or follows it.
                    let declined = this.inner.declined_approvals.lock().await;
                    if declined.contains(&id) {
                        return Err(Error::ApprovalEnded(EndReason::Declined));
                    }
                    api.approval_transfer(id, Bytes(transfer)).await
                }
                .await;
                if let Err(e) = sent {
                    let _ = this.remove_device(device).await;
                    let _ = api.approval_end(id, EndReason::BadMessage).await;
                    return Err(e);
                }
                let removed = if let Some(old) = choice.replaces {
                    // The app already has its new credentials: a failed removal
                    // must not revoke its new device.
                    this.remove_device(old).await.is_ok()
                } else {
                    false
                };
                Ok((device, removed))
            })
            .await
    }

    /// What a checked app request starts with: the last active connection's
    /// available bases and cap, or the first ordinary base and the default cap.
    pub(crate) async fn app_offer(&self, hello: AppHello) -> Result<AppOffer, Error> {
        // devices() refreshes the encrypted app listing before apps() reads it.
        let devices = self.devices().await?;
        let order = self.inner.api.account().await?.bases;
        let ordinary: HashSet<BaseId> = self.db().bases()?.iter().map(|r| r.id).collect();
        let old = self
            .apps()
            .into_iter()
            .filter(|app| app.app_id.as_deref() == Some(&hello.app_id))
            .filter_map(|app| {
                devices
                    .iter()
                    .find(|device| {
                        device.id == app.device_id
                            && device.kind == DeviceKind::App
                            && device.status == "active"
                    })
                    .map(|device| (app, device))
            })
            .max_by_key(|(_, device)| device.last_seen_at);
        let (old, bases, cap_micro_usd, remove_old) = if let Some((app, device)) = old {
            (
                Some(OldConnection {
                    device_id: device.id,
                    name: app.name,
                    last_seen_at: device.last_seen_at,
                }),
                app.bases
                    .into_iter()
                    .filter(|grant| ordinary.contains(&grant.base) && self.base(grant.base).is_ok())
                    .collect(),
                device.cap_micro_usd.unwrap_or(DEFAULT_APP_CAP_MICRO_USD),
                device.last_seen_at == device.created_at
                    || now_ms().saturating_sub(device.last_seen_at) > WEEK_MS,
            )
        } else {
            (
                None,
                order
                    .into_iter()
                    .find(|id| ordinary.contains(id))
                    .map(|base| AppGrant {
                        base,
                        mode: Mode::ReadWrite,
                    })
                    .into_iter()
                    .collect(),
                DEFAULT_APP_CAP_MICRO_USD,
                false,
            )
        };
        let name = hello.name.trim().to_string();
        Ok(AppOffer {
            device_name: app_device_name(&self.email(), &name),
            name,
            app_id: hello.app_id,
            bases,
            cap_micro_usd,
            old,
            remove_old,
        })
    }

    /// Answers a listed request of `exchange`'s kind, returning its new device,
    /// this side and its deadline once the other side has revealed.
    async fn open_here(
        &self,
        id: ApprovalId,
        exchange: Exchange,
    ) -> Result<(DeviceId, ApproverSide, u64), Error> {
        if self.inner.declined_approvals.lock().await.contains(&id) {
            return Err(Error::ApprovalEnded(EndReason::Declined));
        }
        let api = &self.inner.api;
        match api.approval(id).await? {
            None => return Err(Error::ApprovalEnded(EndReason::Expired)),
            Some(state) if state.state == "ended" => {
                let reason = state.end_reason.unwrap_or(EndReason::BadMessage);
                return Err(Error::ApprovalEnded(if reason == EndReason::WrongDigits {
                    EndReason::AlreadyAnswered
                } else {
                    reason
                }));
            }
            Some(state) if state.state != "requested" => {
                return Err(Error::ApprovalEnded(EndReason::AlreadyAnswered));
            }
            _ => {}
        }
        let row = api
            .approvals()
            .await?
            .approvals
            .into_iter()
            .find(|r| r.approval_id == id)
            .ok_or(Error::ApprovalEnded(EndReason::AlreadyAnswered))?;
        let scope = match (exchange, row.kind) {
            (Exchange::Device, ApprovalKind::Device) => self.id(),
            (Exchange::App, ApprovalKind::App) => email_scope(&self.email()),
            (Exchange::Device, ApprovalKind::App) => return Err(Error::invalid("app request")),
            (Exchange::App, ApprovalKind::Device) => return Err(Error::invalid("device request")),
        };
        let clock = self.inner.shared.clock.clone();
        let (mut side, response) = ApproverSide::respond_as(
            exchange,
            scope,
            self.device_id(),
            id,
            &row.request.0,
            clock.now_ms(),
        )?;
        if row.device_id != side.new_device() {
            return Err(Error::ApprovalEnded(EndReason::BadMessage));
        }
        if !self
            .inner
            .db
            .lock()
            .unwrap()
            .claim_approval(&side.commitment(), clock.now_ms())?
        {
            return Err(Error::ApprovalEnded(EndReason::AlreadyAnswered));
        }
        match api.approval_respond(id, Bytes(response)).await {
            Ok(()) => {}
            Err(Error::Conflict(code)) if code == "exists" || code == "version_conflict" => {
                return Err(Error::ApprovalEnded(EndReason::AlreadyAnswered));
            }
            Err(e) => {
                let _ = api.approval_end(id, EndReason::BadMessage).await;
                return Err(e);
            }
        }
        let deadline = clock.now_ms().saturating_add(TTL_MS);
        let result = async {
            let state = approval::follow(api, id, &clock, deadline, |s| s.reveal.is_some()).await?;
            let reveal = state
                .reveal
                .ok_or(Error::ApprovalEnded(EndReason::BadMessage))?;
            side.on_reveal(&reveal.0, clock.now_ms())
        }
        .await;
        match result {
            Ok(()) => {
                if self.inner.declined_approvals.lock().await.contains(&id) {
                    return Err(Error::ApprovalEnded(EndReason::Declined));
                }
                Ok((row.device_id, side, deadline))
            }
            Err(e) => {
                let reason = match e {
                    Error::ApprovalEnded(reason) => reason,
                    _ => EndReason::BadMessage,
                };
                if !matches!(
                    reason,
                    EndReason::Cancelled | EndReason::Declined | EndReason::WrongDigits
                ) {
                    let _ = api.approval_end(id, reason).await;
                }
                Err(e)
            }
        }
    }

    /// Checks typed digits and sends the account key only if they match.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] for the wrong account/device,
    /// [`Error::ApprovalEnded`] for incorrect digits or an ended exchange,
    /// [`Error::Network`] for connection failure, or [`Error::Storage`] for
    /// a local key failure.
    pub async fn approve(
        &self,
        mut request: OpenRequest,
        typed_digits: &Digits,
    ) -> Result<DeviceId, Error> {
        if self.kind() != DeviceKind::Full || request.api.token() != self.inner.api.token() {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        let typed = typed_digits.clone();
        self.inner
            .shared
            .run(async move {
                let side = request
                    .side
                    .take()
                    .ok_or(Error::ApprovalEnded(EndReason::Cancelled))?;
                if this
                    .inner
                    .declined_approvals
                    .lock()
                    .await
                    .contains(&request.id)
                {
                    return Err(Error::ApprovalEnded(EndReason::Declined));
                }
                let state = match request.api.approval(request.id).await {
                    Ok(state) => state,
                    Err(e) => {
                        let _ = request
                            .api
                            .approval_end(request.id, EndReason::BadMessage)
                            .await;
                        return Err(e);
                    }
                };
                if let Some(state) = state
                    && state.state == "ended"
                {
                    return Err(Error::ApprovalEnded(
                        state.end_reason.unwrap_or(EndReason::BadMessage),
                    ));
                }
                let key = match this.account_key() {
                    Ok(key) => key,
                    Err(e) => {
                        let _ = request
                            .api
                            .approval_end(request.id, EndReason::BadMessage)
                            .await;
                        return Err(e);
                    }
                };
                let transfer = match side.confirm(&typed, &key, request.clock.now_ms()) {
                    Ok(transfer) => transfer,
                    Err(e) => {
                        let reason = match e {
                            Error::ApprovalEnded(reason) => reason,
                            _ => EndReason::BadMessage,
                        };
                        let _ = request.api.approval_end(request.id, reason).await;
                        return Err(e);
                    }
                };
                // Check the local clock again: no transfer after two minutes, even if
                // reading the account key or relay state took time.
                if request.clock.now_ms() >= request.deadline {
                    let _ = request
                        .api
                        .approval_end(request.id, EndReason::Expired)
                        .await;
                    return Err(Error::ApprovalEnded(EndReason::Expired));
                }
                // Hold the local barrier through the POST: a decline either wins
                // before the transfer, or follows a transfer already in flight.
                let declined = this.inner.declined_approvals.lock().await;
                if declined.contains(&request.id) {
                    return Err(Error::ApprovalEnded(EndReason::Declined));
                }
                let device = request.device_id;
                if let Err(e) = request
                    .api
                    .approval_transfer(request.id, Bytes(transfer))
                    .await
                {
                    let state = request.api.approval(request.id).await?;
                    if let Some(state) = state
                        && state.state == "ended"
                    {
                        return Err(Error::ApprovalEnded(
                            state.end_reason.unwrap_or(EndReason::BadMessage),
                        ));
                    }
                    let _ = request
                        .api
                        .approval_end(request.id, EndReason::BadMessage)
                        .await;
                    return Err(e);
                }
                Ok(device)
            })
            .await
    }

    /// Learns of bases added on other devices, and asks every open base to
    /// catch up. Needs the network to fetch grants; sync then continues in
    /// the background.
    ///
    /// # Errors
    /// Returns [`Error::Network`] on connection failure,
    /// [`Error::NeedsUpdate`] for unsupported granted data, [`Error::Revoked`]
    /// if removed, or [`Error::Storage`] for local data failures.
    pub async fn refresh(&self) -> Result<(), Error> {
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                let listed = this.inner.api.me().await?.bases;
                let data_error = if this.kind() == DeviceKind::Full {
                    match this.refresh_account_data().await {
                        Err(Error::Revoked) => return Err(Error::Revoked),
                        other => other.err(),
                    }
                } else {
                    None
                };
                let mut known: HashSet<BaseId> = this.db().bases()?.iter().map(|r| r.id).collect();
                known.extend(
                    this.db()
                        .hidden_wrappers()?
                        .into_iter()
                        .map(|(id, _, _)| id),
                );
                let mut added = false;
                let mut needs_update = false;
                for id in listed.into_iter().filter(|id| !known.contains(id)) {
                    let key = this.inner.api.base_key(id).await?;
                    let row = BaseRow {
                        id,
                        epoch: key.epoch,
                        wrapper: key.wrapper.0,
                        mode: match key.mode {
                            GrantMode::ReadWrite => Mode::ReadWrite,
                            GrantMode::ReadOnly => Mode::ReadOnly,
                        },
                    };
                    // An unopened wrapper is indexed without a name, mode or key.
                    match this.base_key(&row) {
                        Ok(_) => {}
                        Err(Error::Crypto) => {
                            this.db().remember_hidden(id, row.epoch, &row.wrapper)?;
                            continue;
                        }
                        Err(Error::NeedsUpdate) => {
                            needs_update = true;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                    this.db().put_base(&row, now_ms())?;
                    added = true;
                }
                // Collected first: `base` locks the account store too.
                let all: Vec<BaseId> = this.db().bases()?.iter().map(|r| r.id).collect();
                for id in all {
                    match this.base(id) {
                        Ok(base) => {
                            base.catch_up();
                        }
                        Err(Error::NotFound) => continue,
                        Err(Error::NeedsUpdate) => needs_update = true,
                        Err(e) => return Err(e),
                    }
                }
                let hidden: Vec<_> = this
                    .inner
                    .hidden
                    .lock()
                    .unwrap()
                    .values()
                    .cloned()
                    .collect();
                for base in hidden {
                    base.catch_up();
                }
                if added {
                    let _ = this.inner.events.send(AccountEvent::BasesChanged);
                }
                if needs_update {
                    Err(Error::NeedsUpdate)
                } else if let Some(error) = data_error {
                    Err(error)
                } else {
                    Ok(())
                }
            })
            .await
    }

    /// Declines a request before or after opening it. Needs the network to
    /// notify the other device; the local rejection remains even if that fails.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device or [`Error::Network`]
    /// if the server cannot be reached.
    pub async fn decline(&self, id: ApprovalId) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                // Local rejection survives even a failed DELETE or dishonest relay.
                this.inner.declined_approvals.lock().await.insert(id);
                match this.inner.api.approval_end(id, EndReason::Declined).await {
                    Err(Error::NotFound) => Ok(()),
                    other => other,
                }
            })
            .await
    }

    /// Refreshes encrypted account data before a Hero turn makes access decisions.
    pub(crate) async fn refresh_account_data(&self) -> Result<(), Error> {
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                if this.kind() != DeviceKind::Full {
                    return Ok(());
                }
                let record = this.inner.api.account().await?;
                this.cache_envelope(&record.account_key_envelope.0)?;
                match record.data {
                    Some(sealed) => {
                        let data = this.open_data(&sealed.ciphertext.0)?;
                        this.cache(sealed.version, &data)
                    }
                    None => this.cache(0, &new_data()),
                }
            })
            .await
    }

    /// The account's devices, named from account data. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Network`] on connection failure,
    /// [`Error::NeedsUpdate`] for newer account data, [`Error::Crypto`] for
    /// unreadable account data, or [`Error::Storage`] on a local cache error.
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
                        cap_micro_usd: d.cap_micro_usd,
                    })
                    .collect())
            })
            .await
    }

    /// Changes an active app device's monthly model cap. Needs the network.
    /// Emits [`AccountEvent::DevicesChanged`] after the server accepts it.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] for an app account, [`Error::NotFound`]
    /// if the target is not an active app device, or a server/network error.
    pub async fn set_app_cap(&self, device: DeviceId, cap_micro_usd: u64) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                this.inner.api.set_app_cap(device, cap_micro_usd).await?;
                let _ = this.inner.events.send(AccountEvent::DevicesChanged);
                Ok(())
            })
            .await
    }

    /// Reads account usage, naming IDs only from this device's decrypted lists.
    /// Needs the network; days and months are UTC, costs are whole micro-dollars.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device, [`Error::Invalid`] for a
    /// malformed month, or network/account-data errors from the server.
    pub async fn usage(&self, month: Option<&str>) -> Result<AccountUsage, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        if month.is_some_and(|value| {
            let bytes = value.as_bytes();
            bytes.len() != 7
                || bytes[4] != b'-'
                || !bytes[..4].iter().chain(&bytes[5..]).all(u8::is_ascii_digit)
                || !(bytes[5] == b'0' && (b'1'..=b'9').contains(&bytes[6])
                    || bytes[5] == b'1' && (b'0'..=b'2').contains(&bytes[6]))
        }) {
            return Err(Error::invalid("month must be YYYY-MM"));
        }
        let this = self.clone();
        let month = month.map(str::to_owned);
        self.inner
            .shared
            .run(async move {
                let response = this.inner.api.usage(month.as_deref()).await?;
                let base_names = this
                    .bases()
                    .into_iter()
                    .map(|base| (base.id, base.name))
                    .collect();
                let device_names = this
                    .devices()
                    .await?
                    .into_iter()
                    .filter(|device| !device.name.is_empty())
                    .map(|device| (device.id, device.name))
                    .collect();
                Ok(AccountUsage {
                    months: response.months.into_iter().map(Into::into).collect(),
                    days: response.days.into_iter().map(Into::into).collect(),
                    base_names,
                    device_names,
                })
            })
            .await
    }

    /// Replaces the recovery kit. The old kit stops working. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::BadCredentials`] if the password is wrong,
    /// [`Error::Network`] on connection failure, [`Error::NeedsUpdate`] for
    /// unsupported credentials, or [`Error::Storage`] / [`Error::Crypto`]
    /// for local key failures.
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
                // Credentials rotate first. A failed account-data write still
                // returns the kit, so the person can keep the only working copy.
                let hash = envelope_hash(&request.account_key_envelope.0);
                this.inner.db.lock().unwrap().set_envelope_hash(&hash)?;
                let copy = kit.clone();
                let _ = this
                    .update_data(move |data| set_kit(data, &copy, false, &hash))
                    .await;
                Ok(kit)
            })
            .await
    }

    /// Changes the password. The kit is needed to re-wrap the account key. The
    /// current envelope must open with `current` and `kit` to the account key
    /// this device holds, so a mistyped kit can't replace the real one; a wrong
    /// password or kit gives `BadKit`, as the two can't be told apart.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for an empty new password,
    /// [`Error::BadKit`] for the wrong password or kit, [`Error::Network`]
    /// for connection failure, or [`Error::Storage`] / [`Error::Crypto`]
    /// for local key failures.
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
                let old_hash = envelope_hash(&sealed.0);
                let salt = bh_crypto::random::<16>();
                let next = derive(new_password, salt, DEFAULT_KDF).await?;
                let envelope = envelope::seal(
                    &next.wrap_key(&kit),
                    &keys::account_key_aad(&this.inner.id),
                    account_key.expose(),
                );
                let hash = envelope_hash(&envelope);
                api.put_credentials(&CredentialsRequest {
                    current_login_key: Bytes(current.login_key().to_vec()),
                    login_key: Bytes(next.login_key().to_vec()),
                    salt: Bytes(salt.to_vec()),
                    kdf: DEFAULT_KDF,
                    account_key_envelope: Bytes(envelope),
                })
                .await?;
                this.inner.db.lock().unwrap().set_envelope_hash(&hash)?;
                // The same verified kit still opens the new envelope. Keep its
                // acknowledgement and creation time when rebinding account data.
                this.update_data_with_envelope(move |data, current_hash| {
                    let Some(stored) = data.get_mut("kit") else {
                        return false;
                    };
                    if current_hash != hash
                        || stored.get("envelope").and_then(Value::as_str) != Some(&old_hash)
                        || stored
                            .get("code")
                            .and_then(Value::as_str)
                            .and_then(|text| RecoveryKit::parse(text).ok())
                            .as_ref()
                            != Some(&kit)
                    {
                        return false;
                    }
                    stored["envelope"] = Value::String(hash.clone());
                    true
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
        self.update_data_with_envelope(move |data, _| {
            edit(data);
            true
        })
        .await
    }

    /// The envelope hash belongs to the same server snapshot as the data being edited.
    pub(crate) async fn update_data_with_envelope(
        &self,
        edit: impl Fn(&mut Data, &str) -> bool + Send + 'static,
    ) -> Result<(), Error> {
        let api = &self.inner.api;
        for _ in 0..5 {
            let record = api.account().await?;
            let hash = envelope_hash(&record.account_key_envelope.0);
            self.db().set_envelope_hash(&hash)?;
            let (version, mut data) = match record.data {
                Some(sealed) => (sealed.version, self.open_data(&sealed.ciphertext.0)?),
                None => (0, new_data()),
            };
            if !edit(&mut data, &hash) {
                return Ok(());
            }
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

    fn cache_envelope(&self, envelope: &[u8]) -> Result<(), Error> {
        self.db().set_envelope_hash(&envelope_hash(envelope))
    }

    fn open_data(&self, ciphertext: &[u8]) -> Result<Data, Error> {
        let json = Zeroizing::new(envelope::open(
            &keys::account_data_key(&self.account_key()?),
            &keys::account_data_aad(&self.inner.id),
            ciphertext,
        )?);
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
    pub(crate) fn derive_secret(&self, context: &[u8; 8]) -> Result<Secret<32>, Error> {
        let name = match self.inner.kind {
            DeviceKind::Full => format!("acct.{}.key", self.inner.id),
            DeviceKind::App => format!("acct.{}.appkey", self.inner.id),
        };
        let key = Secret::<32>::from_slice(&self.inner.shared.secret(&name)?)?;
        Ok(bh_crypto::kdf(&key, context, 1))
    }

    pub(crate) fn clock(&self) -> crate::Clock {
        self.inner.shared.clock.clone()
    }

    pub(crate) fn api(&self) -> Api {
        self.inner.api.clone()
    }

    /// Runs `future` on the core's runtime.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T, Error>> + Send + 'static,
    ) -> Result<T, Error> {
        self.inner.shared.run(future).await
    }

    pub(crate) fn runtime(&self) -> tokio::runtime::Handle {
        self.inner.shared.handle.clone()
    }

    /// Test kit only: injects `fault` into this device's requests.
    #[cfg(feature = "test-support")]
    pub fn test_inject_fault(&self, fault: crate::client::Fault) {
        self.inner.shared.faults.lock().unwrap().push(fault);
    }

    /// Test kit only: replaces a cached wrapper to simulate a base becoming hidden.
    #[cfg(feature = "test-support")]
    pub fn test_replace_base_wrapper(&self, id: BaseId, wrapper: Vec<u8>) -> Result<(), Error> {
        let mut row = self
            .db()
            .bases()?
            .into_iter()
            .find(|row| row.id == id)
            .ok_or(Error::NotFound)?;
        row.wrapper = wrapper;
        self.db().put_base(&row, now_ms())
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
                            && u16::from(frame.code) == 4001 {
                            // A close alone is not proof of account revocation.
                            // Check the server so a device without an open base
                            // also erases itself after a real 401 revoked.
                            if matches!(api.approvals().await, Err(Error::Revoked)) { return; }
                            break;
                        }
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
            kind: row.kind.into(),
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
        let mut data = parse_data(br#"{"v":1,"devices":{},"apps":{},"later":{"x":1},"kit":{"code":"0000-0000-0000-0000-0000-0000-00","saved":false,"at":123}}"#).unwrap();
        let device = DeviceId([1; 16]);
        set_device_name(&mut data, device, "mac");
        assert_eq!(device_name(&data, device), "mac");
        assert_eq!(data["later"], json!({ "x": 1 }));
        assert_eq!(
            data["kit"],
            json!({ "code": "0000-0000-0000-0000-0000-0000-00", "saved": false, "at": 123 })
        );
        assert_eq!(parse_data(br#"{"v":2}"#), Err(Error::NeedsUpdate));
    }

    #[tokio::test]
    async fn kit_record_without_an_envelope_is_unknown() {
        let server = LocalServer::from_env();
        let tmp = tempfile::tempdir().unwrap();
        let (account, _) = core(tmp.path())
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "first".into(),
            })
            .await
            .unwrap();
        account
            .update_data(|data| {
                data["kit"].as_object_mut().unwrap().remove("envelope");
            })
            .await
            .unwrap();
        assert_eq!(account.recovery_kit().unwrap(), None);
        assert_eq!(
            account.kit_status().unwrap(),
            KitStatus {
                known: false,
                saved: false,
                made_at: None
            }
        );
    }

    #[tokio::test]
    async fn newer_account_data_still_discovers_readable_bases() {
        let server = LocalServer::from_env();
        let tmp = tempfile::tempdir().unwrap();
        let email = format!("{}@example.test", AccountId::random());
        let (a, kit) = core(&tmp.path().join("a"))
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: email.clone(),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "first".into(),
            })
            .await
            .unwrap();
        let b = core(&tmp.path().join("b"))
            .sign_in(SignIn {
                server: server.url(),
                email,
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "second".into(),
            })
            .await
            .unwrap()
            .with_kit(&kit.display())
            .await
            .unwrap();
        let base = a.create_base("Readable").await.unwrap();
        a.update_data(|data| {
            data.insert("v".into(), json!(2));
        })
        .await
        .unwrap();
        assert_eq!(b.refresh().await, Err(Error::NeedsUpdate));
        assert!(b.bases().iter().any(|known| known.id == base.id()));
        assert_eq!(b.base(base.id()).unwrap().mode(), Mode::ReadWrite);
    }

    #[tokio::test]
    async fn app_readers_list_only_devices_granted_that_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = core(tmp.path())
            .sign_up(SignUp {
                server: LocalServer::from_env().url(),
                invite: invite(LocalServer::from_env()),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "full".into(),
            })
            .await
            .unwrap();
        let granted = BaseId::random();
        let other = BaseId::random();
        let device = DeviceId::random();
        full.update_data(move |data| {
            entry(data, "apps").insert(device.to_string(), json!({
                "name": "Health", "appId": "dev:health", "key": "private", "bases": { granted.to_string(): "rw" }
            }));
        }).await.unwrap();
        assert_eq!(full.app_readers(granted), [device].into());
        assert!(full.app_readers(other).is_empty());
        let (version, _) = full.db().account_data().unwrap().unwrap();
        assert!(version > 0);
        // A GET started before the grant must not replace its newer cached readers.
        full.cache(version - 1, &new_data()).unwrap();
        assert_eq!(full.app_readers(granted), [device].into());
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
