//! `Account`: one signed-in device of one account.

use crate::approval::connect::{
    AppChoice, AppOffer, DEFAULT_APP_CAP_MICRO_USD, OldConnection, OpenAppRequest, WEEK_MS,
    device_name as app_device_name,
};
use crate::approval::protocol::{AppHello, ApproverSide, Digits, Exchange, TTL_MS, email_scope};
use crate::approval::{self, ApprovalRequest, OpenRequest};
use crate::base::{BaseKey, BaseWeak, EPOCH, KeySource};
use crate::basekeys::BaseKeys;
use crate::client::Api;
use crate::client::ApprovalLive;
use crate::core::{Shared, derive, login_salt};
use crate::envelope;
use crate::grants;
use crate::hidden::{self, HiddenKey};
use crate::keys::{self, DEFAULT_KDF, RecoveryKit};
use crate::rotation::{DeliveryContext, KeyRing, seal_previous};
use crate::store::{AccountDb, BaseRow};
use crate::{Base, BaseEvent, BaseSummary, EndReason, Error, Mode, Mount, UsageRow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_crypto::{KemKey, Secret, XWING_PUBLIC_BYTES};
use bh_proto::{
    AccountData, AccountDataRequest, AccountId, AppDeviceKind, AppWrapper, ApprovalId,
    ApprovalKind, BaseId, BaseKeyResponse, BasesRequest, Bytes, CredentialsRequest,
    DeleteDeviceRequest, DeviceId, DevicesRequest, GrantMode, GrantRequest, ObjectId, RekeyRequest,
};
use futures_util::{SinkExt, StreamExt, future::BoxFuture};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{Notify, broadcast, watch};
use ts_rs::TS;
use url::Url;
use zeroize::Zeroizing;

mod rekey;
pub use rekey::{Removal, RemovalOutcome};

fn notice_request(notice: [u8; 32]) -> DeleteDeviceRequest {
    DeleteDeviceRequest {
        notice: Some(Bytes(notice.to_vec())),
        ..Default::default()
    }
}

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
    /// See [`Account::signed_out_by_server`]; a window opened after the
    /// [`AccountEvent::SignedOutByServer`] event reads it here.
    pub signed_out_by_server: bool,
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
    /// Revoked access is still being removed from ordinary bases.
    pub pending_removal: bool,
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

/// A base or folder selected for an app; a new base, or a folder's first base,
/// is made before registering the app device.
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
    /// Grant a folder or project. Its first grant makes it a base underneath,
    /// moving its contents in; the app sees that base and nothing beside it.
    Folder {
        /// The base the folder is in.
        base: BaseId,
        /// The folder or project.
        folder: ObjectId,
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
    /// Account epoch at which this app key was issued (old credentials are epoch 1).
    #[serde(default = "app_credential_epoch")]
    pub epoch: u32,
    /// Base64url-encoded X-Wing seed for credentials made by a full device.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret",
        deserialize_with = "deserialize_optional_secret"
    )]
    pub kem_seed: Option<Zeroizing<String>>,
    /// Granted base IDs in requested order.
    pub bases: Vec<BaseId>,
}

fn app_credential_epoch() -> u32 {
    1
}

fn serialize_secret<S: serde::Serializer>(
    secret: &Zeroizing<String>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(secret.as_str())
}

fn serialize_optional_secret<S: serde::Serializer>(
    secret: &Option<Zeroizing<String>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(value) => s.serialize_some(value.as_str()),
        None => s.serialize_none(),
    }
}

fn deserialize_optional_secret<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(d).map(|s| s.map(Zeroizing::new))
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
            .field("kem_seed", &self.kem_seed.as_ref().map(|_| "…"))
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
    /// The server refused this device without a removal notice from one of the
    /// person's devices: sync stopped and the local copy and keys stay.
    SignedOutByServer,
    /// A device requested approval.
    ApprovalRequested(ApprovalRequest),
    /// An approval exchange ended.
    ApprovalClosed(ApprovalId),
}

/// Account data, `{ "v": 1, "devices": {}, "apps": {},
/// "kit": { "code": "…", "saved": false, "at": <Unix ms>, "envelope": "<sha256 hex>", "salt": "<hex>" } }`,
/// sealed under `kdf(AK, "bhacdat1", 1)`. Edits keep fields this version doesn't know.
/// `mounts` and each app's `bases` and `was` are read by `grants`.
/// Erasure is best effort: JSON map strings and WebView display copies of the
/// kit can remain in process memory even when serialized buffers are zeroized.
pub(crate) type Data = Map<String, Value>;

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

/// Account data's version as its sealing epoch.
fn data_epoch(version: u64) -> Result<u32, Error> {
    u32::try_from(version).map_err(|_| Error::Crypto)
}

pub(crate) fn entry<'a>(data: &'a mut Data, key: &str) -> &'a mut Data {
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

pub(crate) fn set_kit(
    data: &mut Data,
    kit: &RecoveryKit,
    saved: bool,
    envelope: &str,
    salt: &[u8; 16],
) {
    let code = Zeroizing::new(kit.display());
    data.insert(
        "kit".into(),
        json!({ "code": code.as_str(), "saved": saved, "at": now_ms(), "envelope": envelope, "salt": salt_hex(salt) }),
    );
}

fn salt_hex(salt: &[u8; 16]) -> String {
    salt.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn kit_salt(data: &Data, hash: &str) -> Option<[u8; 16]> {
    let kit = data.get("kit")?;
    if kit.get("envelope")?.as_str()? != hash {
        return None;
    }
    let hex = kit.get("salt")?.as_str()?;
    if hex.len() != 32 {
        return None;
    }
    let bytes = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    bytes.try_into().ok()
}

/// Server credentials retained locally, checked only when account data binds the envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Server's account-key envelope bytes.
    pub envelope: Vec<u8>,
    /// Login salt paired with this envelope.
    pub salt: [u8; 16],
    /// Whether encrypted account data bound this envelope to the kit and salt.
    pub checked: bool,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("envelope", &"…")
            .field("salt", &"…")
            .field("checked", &self.checked)
            .finish()
    }
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
    ["devices", "apps", "pendingRemovals"]
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

struct AccountKeySource(Weak<Inner>);

impl KeySource for AccountKeySource {
    fn reload(&self, base: BaseId) -> BoxFuture<'static, Result<BaseKeys, Error>> {
        let owner = self.0.clone();
        Box::pin(async move {
            let inner = owner
                .upgrade()
                .ok_or_else(|| Error::Network("account closed".into()))?;
            Account { inner }.reload_base_key(base).await
        })
    }
}

struct HiddenRekeyTask {
    cancel: watch::Sender<bool>,
    token: Arc<()>,
}

/// Clears only this task's marker, never a newer unlock's marker.
struct HiddenRekeyGuard {
    owner: Weak<Inner>,
    id: BaseId,
    token: Arc<()>,
}

impl Drop for HiddenRekeyGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.owner.upgrade() {
            let mut active = inner.hidden_rekeys.lock().unwrap();
            if active
                .get(&self.id)
                .is_some_and(|task| Arc::ptr_eq(&task.token, &self.token))
            {
                active.remove(&self.id);
            }
        }
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone)]
struct HeldHiddenRekey {
    id: BaseId,
    release: Arc<tokio::sync::Semaphore>,
    entered: Arc<tokio::sync::Semaphore>,
}

/// A background worker's non-owning account reference.
#[derive(Clone)]
pub(crate) struct AccountWeak(std::sync::Weak<Inner>);

impl AccountWeak {
    pub(crate) fn upgrade(&self) -> Option<Account> {
        self.0.upgrade().map(|inner| Account { inner })
    }
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
    /// Password-derived keys exist only while their base is unlocked.
    hidden_keys: Mutex<HashMap<BaseId, HiddenKey>>,
    /// One active re-key per open hidden base; lock cancels it without a network wait.
    hidden_rekeys: Mutex<HashMap<BaseId, HiddenRekeyTask>>,
    /// Runs one move between bases at a time in this process.
    moves: tokio::sync::Mutex<()>,
    /// Serializes ordinary re-keys across callers and the background finisher.
    rekeys: tokio::sync::Mutex<()>,
    /// Only one detached finisher runs per account; requests while it runs
    /// trigger another pass before it stops.
    rekey_running: AtomicBool,
    rekey_requested: AtomicU64,
    /// Abort and join the finisher before erasing the account store.
    rekey_task: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Serializes grant reconciliation across this account's clones.
    grants: tokio::sync::Mutex<()>,
    backup_lock: tokio::sync::Mutex<()>,
    backup_stop_generation: AtomicU64,
    backup_signal: Arc<Notify>,
    backup_schedule: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "test-support")]
    held_hidden_open: Mutex<
        Option<(
            Arc<tokio::sync::Semaphore>,
            Arc<std::sync::atomic::AtomicBool>,
        )>,
    >,
    #[cfg(feature = "test-support")]
    held_hidden_rekey: Mutex<Option<HeldHiddenRekey>>,
    #[cfg(feature = "test-support")]
    held_hidden_cancel: Mutex<Option<HeldHiddenRekey>>,
    #[cfg(feature = "test-support")]
    held_app_credentials: Mutex<Option<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>)>>,
    #[cfg(feature = "test-support")]
    synthetic_readers: Mutex<HashMap<BaseId, std::collections::BTreeSet<DeviceId>>>,
    listener: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 0 active, 1 erasing, 2 erased, 3 blocked after failed erase.
    removal: Arc<AtomicU8>,
    removal_done: Notify,
    /// Refused by the server without a valid removal notice: sync stopped, nothing
    /// erased. Not stored, so the next start tries again.
    signed_out_by_server: AtomicBool,
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
    for suffix in ["key", "appkey", "token", "dbkey", "kem"] {
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
        if let Some(task) = self.backup_schedule.lock().unwrap().take() {
            task.abort();
        }
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
                let api =
                    shared
                        .api(row.server.clone(), Some(token))
                        .with_revocation(move |notice| {
                            if let Some(inner) = weak.upgrade() {
                                (Account { inner }).revoked(notice);
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
                    hidden_keys: Mutex::new(HashMap::new()),
                    hidden_rekeys: Mutex::new(HashMap::new()),
                    moves: tokio::sync::Mutex::new(()),
                    rekeys: tokio::sync::Mutex::new(()),
                    rekey_running: AtomicBool::new(false),
                    rekey_requested: AtomicU64::new(0),
                    rekey_task: Mutex::new(None),
                    grants: tokio::sync::Mutex::new(()),
                    backup_lock: tokio::sync::Mutex::new(()),
                    backup_stop_generation: AtomicU64::new(0),
                    backup_signal: Arc::new(Notify::new()),
                    backup_schedule: Mutex::new(None),
                    #[cfg(feature = "test-support")]
                    held_hidden_open: Mutex::new(None),
                    #[cfg(feature = "test-support")]
                    held_hidden_rekey: Mutex::new(None),
                    #[cfg(feature = "test-support")]
                    held_hidden_cancel: Mutex::new(None),
                    #[cfg(feature = "test-support")]
                    held_app_credentials: Mutex::new(None),
                    #[cfg(feature = "test-support")]
                    synthetic_readers: Mutex::new(HashMap::new()),
                    listener: Mutex::new(None),
                    removal: Arc::new(AtomicU8::new(0)),
                    removal_done: Notify::new(),
                    signed_out_by_server: AtomicBool::new(false),
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
            signed_out_by_server: self.signed_out_by_server(),
        }
    }

    /// Test only: whether an ordinary base still has an open handle.
    #[cfg(feature = "test-support")]
    pub fn test_base_is_open(&self, id: BaseId) -> bool {
        self.inner
            .bases
            .lock()
            .unwrap()
            .get(&id)
            .and_then(BaseWeak::upgrade)
            .is_some()
    }

    /// Test only: schedule work on this device's sync runtime.
    #[cfg(feature = "test-support")]
    pub fn test_runtime_handle(&self) -> tokio::runtime::Handle {
        self.inner.shared.handle.clone()
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

    #[cfg(feature = "test-support")]
    /// Test only: pause the next grant PUT before it reaches the server.
    pub fn test_hold_next_grant(&self) -> Arc<tokio::sync::Semaphore> {
        self.inner.api.hold_next_grant()
    }

    /// Test only: pause a base-key response after it has reached the server.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_base_key_reply(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        self.inner.api.hold_next_base_key_reply()
    }

    /// Test only: hold a successful removal's reply after the server commits.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_delete_reply(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        self.inner.api.hold_next_delete_reply()
    }

    /// Test only: synchronize concurrent removal requests after they have chosen epochs.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_delete_send(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        self.inner.api.hold_next_delete_send()
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

    /// Test only: hold hidden re-keys immediately before their network request.
    #[cfg(feature = "test-support")]
    pub fn test_hold_hidden_rekey(
        &self,
        id: BaseId,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        *self.inner.held_hidden_rekey.lock().unwrap() = Some(HeldHiddenRekey {
            id,
            release: release.clone(),
            entered: entered.clone(),
        });
        (release, entered)
    }

    /// Test only: hold a canceled re-key before its in-flight marker is dropped.
    #[cfg(feature = "test-support")]
    pub fn test_hold_canceled_hidden_rekey(
        &self,
        id: BaseId,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        *self.inner.held_hidden_cancel.lock().unwrap() = Some(HeldHiddenRekey {
            id,
            release: release.clone(),
            entered: entered.clone(),
        });
        (release, entered)
    }

    /// Test only: report whether the detached ordinary re-key worker is still active.
    #[cfg(feature = "test-support")]
    pub fn test_background_rekey_running(&self) -> bool {
        self.inner.rekey_running.load(Ordering::Acquire)
    }

    /// Test only: hold the reply after the server commits a hidden re-key.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_hidden_rekey_reply(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        self.inner.api.hold_next_rekey_reply()
    }

    /// Test only: pause after the app's account-data commit and grant settle,
    /// before returning its credentials. The second semaphore signals arrival.
    #[cfg(feature = "test-support")]
    pub fn test_hold_next_app_credentials(
        &self,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        *self.inner.held_app_credentials.lock().unwrap() = Some((release.clone(), entered.clone()));
        (release, entered)
    }

    #[cfg(feature = "test-support")]
    async fn wait_for_test_app_credentials(&self) {
        let hold = self.inner.held_app_credentials.lock().unwrap().take();
        if let Some((release, entered)) = hold {
            entered.add_permits(1);
            release.acquire().await.expect("test release").forget();
        }
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
        let mounts = self
            .cached_data()
            .map(|data| grants::mounts(&data))
            .unwrap_or_default();
        let mut list: Vec<_> = rows
            .into_iter()
            .filter_map(|row| {
                let base = self.base(row.id).ok()?;
                Some(BaseSummary {
                    id: row.id,
                    name: base.name(),
                    mode: row.mode,
                    hidden: false,
                    mount: mounts.get(&row.id).copied(),
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
                mount: None,
            })
            .collect();
        hidden.sort_by_cached_key(|s| (s.name.to_lowercase(), s.id));
        list.extend(hidden);
        list
    }

    /// Cached account data on full devices; `None` on app devices or when unreadable.
    pub(crate) fn cached_data(&self) -> Option<Data> {
        if self.kind() != DeviceKind::Full {
            return None;
        }
        let (_, json) = self.db().account_data().ok().flatten()?;
        parse_data(json.as_bytes()).ok()
    }

    /// App device IDs that can read this base, with grants from the bases it's
    /// mounted in and any change still pending, without a network call.
    pub(crate) fn app_readers(&self, base: BaseId) -> BTreeSet<DeviceId> {
        #[cfg(feature = "test-support")]
        if let Some(readers) = self.inner.synthetic_readers.lock().unwrap().get(&base) {
            return readers.clone();
        }
        self.cached_data()
            .map(|data| grants::readers(&data, base))
            .unwrap_or_default()
    }

    /// Test only: the app devices Hero counts as readers of `base`.
    #[cfg(feature = "test-support")]
    pub fn test_app_readers(&self, base: BaseId) -> BTreeSet<DeviceId> {
        self.app_readers(base)
    }

    /// Bases shown in folders of other bases, from cached account data; empty
    /// on app devices. Never contacts the server.
    pub fn mounts(&self) -> Vec<Mount> {
        self.cached_data()
            .map(|data| grants::mounts(&data).into_values().collect())
            .unwrap_or_default()
    }

    /// Renames an object in `base`. A granted folder's base takes the name
    /// too, and stays open while its name is sent in the background (at most
    /// 10 seconds), so its apps see it. The call itself never waits for the server.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for a note, whose title comes from its body,
    /// or for a name its type refuses, [`Error::NotFound`] for an unknown base
    /// or object, or the errors of [`Base::set_fields`].
    pub fn rename(&self, base: BaseId, id: ObjectId, name: &str) -> Result<(), Error> {
        let open = self.base(base)?;
        let object = open.get(id)?.ok_or(Error::NotFound)?;
        if object.ty.name == crate::types::NOTE {
            return Err(Error::invalid("a note's title comes from its body"));
        }
        open.set_fields(id, Map::from_iter([("name".into(), Value::from(name))]))?;
        match self
            .mounts()
            .into_iter()
            .find(|m| (m.parent, m.folder) == (base, id))
        {
            Some(mount) => {
                let mounted = self.base(mount.base)?;
                mounted.set_name(name)?;
                // A base's sync stops with its last handle. Keep this one until
                // the name is sent, without making the synchronous call wait.
                self.inner.shared.handle.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(10), mounted.flush()).await;
                });
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Apps known from the encrypted local account data; never contacts the server.
    pub fn apps(&self) -> Vec<AppSummary> {
        let Some(data) = self.cached_data() else {
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
                this.connect_app_with(req, DeviceId::random(), DEFAULT_APP_CAP_MICRO_USD, None)
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
        app_public: Option<String>,
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
            match grant {
                BaseGrantRequest::Existing { base, .. } => {
                    if !seen.insert(*base) {
                        return Err(Error::invalid("duplicate base"));
                    }
                    self.check_grantable(*base)?;
                }
                BaseGrantRequest::Folder { base, .. } => self.check_grantable(*base)?,
                BaseGrantRequest::New { .. } => {}
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
                BaseGrantRequest::Folder { base, folder, mode } => {
                    grants.push((self.grant_folder(base, folder).await?, mode))
                }
            }
        }
        seen.clear();
        if grants.iter().any(|(base, _)| !seen.insert(*base)) {
            return Err(Error::invalid("duplicate base"));
        }
        // The approval exchange carries only the requesting app's public half.
        // CLI credentials instead carry a seed generated by this full device.
        let kem_seed = if app_public.is_none() {
            Some(Secret::<32>::random())
        } else {
            None
        };
        let public = match (&app_public, &kem_seed) {
            (Some(encoded), _) => {
                let bytes = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| Error::invalid("app public key"))?;
                if bytes.len() != XWING_PUBLIC_BYTES {
                    return Err(Error::invalid("app public key"));
                }
                encoded.clone()
            }
            (None, Some(seed)) => URL_SAFE_NO_PAD.encode(KemKey::from_seed(seed).public()),
            _ => unreachable!(),
        };
        let app_key = Secret::<32>::random();
        let key = Zeroizing::new(URL_SAFE_NO_PAD.encode(app_key.expose()));
        // Removing an app that never got its credentials still sends its notice.
        let notice = keys::removal_notice(
            &bh_crypto::kdf(&app_key, keys::REMOVAL, 1),
            &self.inner.id,
            &device_id,
        );
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
                    match self
                        .inner
                        .api
                        .delete_device(device_id, &notice_request(notice))
                        .await
                    {
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
            .grant_new_app(device_id, req, &key, &grants, public)
            .await;
        #[cfg(feature = "test-support")]
        if result.is_ok() {
            self.wait_for_test_app_credentials().await;
        }
        match result {
            Ok(issued_epoch) => Ok(AppCredentials {
                server: self.inner.server.clone(),
                email: self.email(),
                account_id: self.id(),
                device_id,
                token: Zeroizing::new(token),
                app_key: key,
                epoch: issued_epoch,
                kem_seed: kem_seed
                    .map(|seed| Zeroizing::new(URL_SAFE_NO_PAD.encode(seed.expose()))),
                bases: grants.iter().map(|(base, _)| *base).collect(),
            }),
            Err(error) => {
                // Revoke first: even an ambiguous grant reply may have installed a grant.
                let removed = self
                    .inner
                    .api
                    .delete_device(device_id, &notice_request(notice))
                    .await;
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

    /// A hidden base is never granted; any other base must be known here.
    pub(crate) fn check_grantable(&self, base: BaseId) -> Result<(), Error> {
        if self.is_hidden(base)? {
            return Err(Error::Forbidden);
        }
        self.base(base).map(|_| ())
    }

    /// Whether `base` is a hidden base known here, locked or not.
    pub(crate) fn is_hidden(&self, base: BaseId) -> Result<bool, Error> {
        Ok(self
            .db()
            .hidden_wrappers()?
            .iter()
            .any(|row| row.id == base))
    }

    async fn grant_new_app(
        &self,
        device_id: DeviceId,
        req: AppRequest,
        key: &str,
        grants: &[(BaseId, Mode)],
        public: String,
    ) -> Result<u32, Error> {
        let bases: grants::Grants = grants.iter().copied().collect();
        let order: Vec<String> = grants.iter().map(|(id, _)| id.to_string()).collect();
        let key = Zeroizing::new(key.to_owned());
        let replaces = req.replaces;
        // A new app's grants are a pending change from none until the server has them.
        let issued_epoch = self.update_data_with_envelope_at(move |data, _, _| {
            grants::edit(data, |data| {
                entry(data, "apps").insert(
                    device_id.to_string(),
                    json!({
                        "name": req.app_name.trim(), "appId": req.app_id, "key": key.as_str(), "public": public,
                        "bases": grants::to_value(&bases), "baseOrder": order
                    }),
                );
            });
            true
        }).await?.ok_or(Error::Crypto)?;
        self.settle_app(device_id).await?;
        if let Some(old) = replaces {
            let notice = self.removal_notice_for(old).await?;
            self.inner
                .api
                .delete_device(old, &notice_request(notice))
                .await?;
            self.update_data(move |data| {
                entry(data, "apps").remove(&old.to_string());
            })
            .await?;
        }
        Ok(issued_epoch)
    }

    /// Grants an app another base, or changes its mode on one it has; `New`
    /// creates the base first. Returns the granted base. The change is kept in
    /// account data first, so a later [`Self::refresh`] finishes it if this
    /// stops midway. Full devices only. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device or for a hidden base,
    /// [`Error::NotFound`] for an unknown app or base, [`Error::Invalid`] for
    /// an empty name, [`Error::Network`] on connection failure, or server and
    /// storage errors.
    pub async fn add_app_grant(
        &self,
        device: DeviceId,
        grant: BaseGrantRequest,
    ) -> Result<BaseId, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                if !this.apps().iter().any(|app| app.device_id == device) {
                    return Err(Error::NotFound);
                }
                let (base, mode) = match grant {
                    BaseGrantRequest::Existing { base, mode } => {
                        this.check_grantable(base)?;
                        (base, mode)
                    }
                    BaseGrantRequest::New { name, mode } => {
                        (this.create_base(&name).await?.id(), mode)
                    }
                    BaseGrantRequest::Folder { base, folder, mode } => {
                        (this.grant_folder(base, folder).await?, mode)
                    }
                };
                this.edit_app(device, move |app| {
                    entry(app, "bases").insert(base.to_string(), json!(grants::mode_text(mode)));
                    let order = app.entry("baseOrder").or_insert_with(|| json!([]));
                    if let Some(order) = order.as_array_mut()
                        && !order
                            .iter()
                            .any(|id| id.as_str() == Some(&base.to_string()))
                    {
                        order.push(json!(base.to_string()));
                    }
                })
                .await?;
                this.settle_grants().await?;
                Ok(base)
            })
            .await
    }

    /// Removes an app's grant on `base`, and the server's grants that came only
    /// from it. The app erases a base it can no longer read when it next
    /// refreshes. As with [`Self::add_app_grant`], a later [`Self::refresh`]
    /// finishes a change that stopped midway. Full devices only. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device, [`Error::NotFound`] for an
    /// unknown app, [`Error::Network`] on connection failure, or server and
    /// storage errors.
    pub async fn remove_app_grant(&self, device: DeviceId, base: BaseId) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                if !this.apps().iter().any(|app| app.device_id == device) {
                    return Err(Error::NotFound);
                }
                this.update_data_at(move |data, version| {
                    let before =
                        grants::effective(&grants::direct(data, device), &grants::mounts(data));
                    let previous = grants::was(data, device).unwrap_or_default();
                    grants::edit(data, |data| {
                        if let Some(app) = data
                            .get_mut("apps")
                            .and_then(|apps| apps.get_mut(device.to_string()))
                            .and_then(Value::as_object_mut)
                        {
                            entry(app, "bases").remove(&base.to_string());
                            if let Some(order) =
                                app.get_mut("baseOrder").and_then(Value::as_array_mut)
                            {
                                order.retain(|id| id.as_str() != Some(&base.to_string()));
                            }
                        }
                    });
                    let after =
                        grants::effective(&grants::direct(data, device), &grants::mounts(data));
                    let affected: BTreeSet<_> = before
                        .keys()
                        .chain(previous.keys())
                        .filter(|id| !after.contains_key(id))
                        .copied()
                        .collect();
                    if !affected.is_empty() {
                        rekey::pending_removal(data, device, affected, version);
                    }
                })
                .await?;
                // First revoke the old server grants; the re-key drops its wrapper.
                // If this fails, refresh will settle and finish the pending list.
                if this.settle_grants().await.is_ok() {
                    let _ = this.finish_rekeys().await;
                }
                Ok(())
            })
            .await
    }

    /// Changes one app's entry in account data, marking the change pending.
    async fn edit_app(
        &self,
        device: DeviceId,
        change: impl Fn(&mut Data) + Send + 'static,
    ) -> Result<(), Error> {
        self.update_data(move |data| {
            grants::edit(data, |data| {
                if let Some(app) = data
                    .get_mut("apps")
                    .and_then(|apps| apps.get_mut(device.to_string()))
                    .and_then(Value::as_object_mut)
                {
                    change(app);
                }
            })
        })
        .await
    }

    /// Brings the server's grants in step with each pending change in cached
    /// account data.
    pub(crate) async fn settle_grants(&self) -> Result<(), Error> {
        let _one = self.inner.grants.lock().await;
        self.refresh_account_data().await?;
        let pending = self
            .cached_data()
            .map(|data| grants::pending(&data))
            .unwrap_or_default();
        // Each app settles on its own, so one that fails doesn't hold up the rest.
        let mut first = None;
        for device in pending {
            if let Err(error) = self.settle_app_locked(device).await {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Grants every base `device` can read now, revokes the bases it could read
    /// only before, then marks the change done if no edit came meanwhile. A base
    /// this device doesn't know yet is left for a later call.
    async fn settle_app(&self, device: DeviceId) -> Result<(), Error> {
        let _one = self.inner.grants.lock().await;
        self.refresh_account_data().await?;
        self.settle_app_locked(device).await
    }

    async fn settle_app_locked(&self, device: DeviceId) -> Result<(), Error> {
        for _ in 0..3 {
            match self.settle_app_once(device).await {
                Err(Error::Conflict(code)) if code == "stale_grant" || code == "epoch_conflict" => {
                    self.refresh_account_data().await?;
                }
                result => return result,
            }
        }
        Err(Error::Conflict("stale_grant".into()))
    }

    async fn settle_app_once(&self, device: DeviceId) -> Result<(), Error> {
        let Some((version, json)) = self.db().account_data()? else {
            return Ok(());
        };
        let data = parse_data(json.as_bytes())?;
        let Some(was) = grants::was(&data, device) else {
            return Ok(());
        };
        let effective = grants::effective(&grants::direct(&data, device), &grants::mounts(&data));
        let app_key = data
            .get("apps")
            .and_then(|apps| apps.get(device.to_string()))
            .and_then(|app| app.get("key"))
            .and_then(Value::as_str)
            .and_then(|key| URL_SAFE_NO_PAD.decode(key).ok())
            .map(Zeroizing::new)
            .ok_or_else(|| Error::Storage("unreadable app key".into()))?;
        let wrap_key = bh_crypto::kdf(&Secret::<32>::from_slice(&app_key)?, b"bhbasew1", 1);
        let rows = self.db().bases()?;
        let mut complete = true;
        for (&base, &mode) in &effective {
            let Some(row) = rows.iter().find(|row| row.id == base) else {
                complete = false;
                continue;
            };
            let wrapper = envelope::seal(
                &wrap_key,
                &keys::app_wrapper_aad(&base, &device, row.epoch),
                self.base_key(row)?.current().1.secret().expose(),
            );
            let request = GrantRequest {
                mode: match mode {
                    Mode::ReadWrite => GrantMode::ReadWrite,
                    Mode::ReadOnly => GrantMode::ReadOnly,
                },
                epoch: row.epoch,
                wrapper: Bytes(wrapper),
                account_epoch: self.verified_keys()?.newest().0,
                data_version: version,
            };
            match self.inner.api.grant(base, device, &request).await {
                Err(Error::Conflict(code)) if code == "epoch_conflict" => {
                    self.reload_base_key(base).await?;
                    return Err(Error::Conflict(code));
                }
                // The server has no such active app: it was removed, so forget it.
                Err(Error::NotFound) => {
                    return self
                        .update_data(move |data| {
                            entry(data, "apps").remove(&device.to_string());
                        })
                        .await;
                }
                result => result?,
            }
        }
        for &base in was.keys().filter(|base| !effective.contains_key(base)) {
            self.inner.api.revoke(base, device).await?;
        }
        if !complete {
            return Ok(());
        }
        self.update_data_with_envelope(move |data, _| {
            let unchanged = grants::was(data, device).as_ref() == Some(&was)
                && grants::effective(&grants::direct(data, device), &grants::mounts(data))
                    == effective;
            let app = data
                .get_mut("apps")
                .and_then(|apps| apps.get_mut(device.to_string()))
                .and_then(Value::as_object_mut);
            match app {
                Some(app) if unchanged => app.remove("was").is_some(),
                _ => false,
            }
        })
        .await
    }

    /// Closes and deletes a base this app device can no longer read.
    async fn erase_base(&self, id: BaseId) -> Result<(), Error> {
        let open = self.inner.bases.lock().unwrap().remove(&id);
        if let Some(base) = open.and_then(|weak| weak.upgrade()) {
            base.close().await;
        }
        let path = self
            .inner
            .shared
            .account_dir(self.id())
            .join("bases")
            .join(format!("{id}.sqlite"));
        for file in ["sqlite", "sqlite-wal", "sqlite-shm"] {
            match std::fs::remove_file(path.with_extension(file)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        match std::fs::remove_dir_all(crate::files::part_root(&path)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        self.inner
            .shared
            .secrets
            .delete(&format!("base.{id}.dbkey"))?;
        self.db().forget_base(id)
    }

    /// Revokes a device and removes its app listing. Removing this device also
    /// erases it locally. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] when an app removes another device,
    /// [`Error::Network`] if revocation fails, [`Error::NotFound`] for an
    /// unknown device, or [`Error::Storage`] if local erasure fails.
    pub async fn remove_device(
        &self,
        id: DeviceId,
        removal: Removal,
    ) -> Result<RemovalOutcome, Error> {
        if self.kind() != DeviceKind::Full && self.device_id() != id {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                if id != this.device_id() && this.kind() == DeviceKind::Full {
                    let record = this.inner.api.account().await?;
                    if record
                        .devices
                        .iter()
                        .any(|d| d.device_id == id && d.kind == bh_proto::DeviceKind::Full)
                    {
                        return match removal {
                            Removal::Full { password, lost } => {
                                this.remove_full(id, password, lost).await
                            }
                            Removal::Plain => Err(Error::invalid("password")),
                        };
                    }
                }
                if id != this.device_id() && this.kind() == DeviceKind::Full {
                    return this.remove_app(id).await;
                }
                let notice = this.removal_notice_for(id).await?;
                let removed = this
                    .inner
                    .api
                    .delete_device(id, &notice_request(notice))
                    .await;
                if id == this.device_id() {
                    if let Err(error) = removed
                        && !matches!(this.inner.api.me().await, Err(Error::Revoked))
                    {
                        return Err(error);
                    }
                    this.sign_out().await?;
                }
                Ok(RemovalOutcome {
                    new_kit: None,
                    pending: false,
                })
            })
            .await
    }

    /// The notice that makes `id` erase itself, keyed from the key it holds: this
    /// device's own, an app's key from account data, or else the account key.
    async fn removal_notice_for(&self, id: DeviceId) -> Result<[u8; 32], Error> {
        let key = if id == self.device_id() {
            self.derive_secret(keys::REMOVAL)?
        } else {
            let app_key = |data: Data| {
                data.get("apps")?
                    .get(id.to_string())?
                    .get("key")?
                    .as_str()
                    .and_then(|key| URL_SAFE_NO_PAD.decode(key).ok())
                    .map(Zeroizing::new)
            };
            // An app connected from another device may not be in this one's copy yet.
            let mut found = self.cached_data().and_then(app_key);
            if found.is_none() {
                self.refresh_account_data().await?;
                found = self.cached_data().and_then(app_key);
            }
            match found {
                Some(app_key) => {
                    bh_crypto::kdf(&Secret::<32>::from_slice(&app_key)?, keys::REMOVAL, 1)
                }
                None => self.derive_secret(keys::REMOVAL)?,
            }
        };
        Ok(keys::removal_notice(&key, &self.inner.id, &id))
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

    /// True once the server refused this device without a removal notice from one of
    /// the person's devices. Sync has stopped; the local copy and keys stay until the
    /// person signs out. Not stored: after a restart the device tries again.
    pub fn signed_out_by_server(&self) -> bool {
        self.inner.signed_out_by_server.load(Ordering::SeqCst)
    }

    /// The server's `revoked` answer: erase only if `notice` is this device's own,
    /// made with its key by one of the person's devices; otherwise stop syncing.
    /// Decides before returning, so a caller that sees [`Error::Revoked`] can wait
    /// for an erasure with [`Self::settle_removal`].
    fn revoked(&self, notice: Option<&[u8]>) {
        if self.inner.removal.load(Ordering::SeqCst) != 0 {
            return;
        }
        let genuine = notice.is_some_and(|notice| {
            self.derive_secret(keys::REMOVAL).is_ok_and(|key| {
                let expected = keys::removal_notice(&key, &self.inner.id, &self.inner.device_id);
                bh_crypto::constant_time_eq(&expected, notice)
            })
        });
        let this = self.clone();
        if genuine {
            if self.begin_removal() {
                self.inner.shared.handle.spawn(async move {
                    let _ = this.finish_removal().await;
                });
            }
        } else if !self.inner.signed_out_by_server.swap(true, Ordering::SeqCst) {
            self.inner.shared.handle.spawn(async move {
                this.stop_for_server().await;
            });
        }
    }

    /// Stops sync and the approvals listener, keeping every store and key.
    async fn stop_for_server(&self) {
        if let Some(task) = self.inner.stop_listener() {
            let _ = task.await;
        }
        let bases: Vec<_> = self
            .inner
            .bases
            .lock()
            .unwrap()
            .values()
            .filter_map(BaseWeak::upgrade)
            .collect();
        // Hidden bases open under this gate, after checking the flag set above.
        let _gate = self.inner.hidden_gate.lock().await;
        let hidden: Vec<_> = self
            .inner
            .hidden
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for base in bases.into_iter().chain(hidden) {
            base.set_sync_stopped();
            base.stop_sync().await;
        }
        // Erasing meanwhile, at the person's request, says Removed instead.
        if self.inner.removal.load(Ordering::SeqCst) == 0 {
            let _ = self.inner.events.send(AccountEvent::SignedOutByServer);
        }
    }

    /// Waits for an erasure that a removal notice started; returns at once otherwise.
    ///
    /// # Errors
    /// Returns [`Error::Revoked`] if that erasure failed; it finishes at the next start.
    pub async fn settle_removal(&self) -> Result<(), Error> {
        if self.inner.removal.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
        self.wait_for_removal().await
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
            BaseKey::new(key.current().1.secret().expose())?,
            row.mode,
            Some(self.inner.device_id),
            Some(self.inner.removal.clone()),
        )?;
        base.install_keys(key);
        base.set_key_source(Arc::new(AccountKeySource(Arc::downgrade(&self.inner))));
        base.set_full(self.kind() == DeviceKind::Full);
        base.set_backup_signal(self.inner.backup_signal.clone());
        self.attach_version_names(&base);
        if self.signed_out_by_server() {
            base.set_sync_stopped();
        } else {
            base.start_sync(
                self.inner.api.clone(),
                &self.inner.shared.handle,
                self.inner.shared.clock.clone(),
            );
        }
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
        base.set_key_source(Arc::new(AccountKeySource(Arc::downgrade(&self.inner))));
        base.set_full(self.kind() == DeviceKind::Full);
        base.set_backup_signal(self.inner.backup_signal.clone());
        self.attach_version_names(&base);
        if self.signed_out_by_server() {
            base.set_sync_stopped();
        } else {
            base.start_sync(
                self.inner.api.clone(),
                &self.inner.shared.handle,
                self.inner.shared.clock.clone(),
            );
        }
        self.inner.hidden.lock().unwrap().insert(id, base.clone());
        self.backup_changed();
        // The unlock can be offline. Watch the base's own reconnect event in a
        // separate task, never blocking its sync task or the local lock path.
        // The server's rekey_needed fence holds sends until the re-key succeeds.
        let mut events = base.events();
        let owner = Arc::downgrade(&self.inner);
        self.inner.shared.handle.spawn(async move {
            let mut online = false;
            loop {
                match events.recv().await {
                    Ok(BaseEvent::Sync(state)) => {
                        if state.online && !online {
                            let Some(inner) = owner.upgrade() else { break };
                            let _ = (Account { inner }).rekey_hidden(id).await;
                        }
                        online = state.online;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                    _ => {}
                }
            }
        });
        Ok(base)
    }

    /// Opens a base key's wrapper: the account's on full devices, the app's own on app devices.
    fn verified_keys(&self) -> Result<KeyRing, Error> {
        let name = match self.kind() {
            DeviceKind::Full => format!("acct.{}.key", self.id()),
            DeviceKind::App => format!("acct.{}.appkey", self.id()),
        };
        KeyRing::parse(&self.inner.shared.secret(&name)?)
    }

    fn adopt_keys(
        &self,
        epoch: u32,
        deliveries: &[bh_proto::DeviceKeyDelivery],
    ) -> Result<(), Error> {
        let mut ring = self.verified_keys()?;
        if ring.newest().0 == epoch && deliveries.is_empty() {
            return Ok(());
        }
        let seed = self
            .inner
            .shared
            .secret(&format!("acct.{}.kem", self.id()))?;
        let kem = KemKey::from_seed(&Secret::<32>::from_slice(&seed)?);
        ring.adopt(
            &kem,
            &DeliveryContext {
                account: self.id(),
                device: self.device_id(),
                kind: match self.kind() {
                    DeviceKind::Full => bh_proto::DeviceKind::Full,
                    DeviceKind::App => bh_proto::DeviceKind::App,
                },
                from_epoch: ring.newest().0,
            },
            epoch,
            deliveries,
        )?;
        let suffix = if self.kind() == DeviceKind::Full {
            "key"
        } else {
            "appkey"
        };
        self.inner
            .shared
            .secrets
            .put(&format!("acct.{}.{suffix}", self.id()), &ring.to_bytes())
    }

    /// Opens a base wrapper using verified keys plus historical keys in authenticated data.
    fn device_keys(&self) -> Result<KeyRing, Error> {
        let mut ring = self.verified_keys()?;
        if self.kind() == DeviceKind::Full
            && let Some(data) = self
                .cached_data()
                .and_then(|data| data.get("keys").cloned())
        {
            let keys = data.as_object().ok_or(Error::Crypto)?;
            for (epoch, key) in keys {
                let epoch = epoch.parse().map_err(|_| Error::Crypto)?;
                let key = key.as_str().ok_or(Error::Crypto)?;
                ring.insert(
                    epoch,
                    Secret::from_slice(&URL_SAFE_NO_PAD.decode(key).map_err(|_| Error::Crypto)?)?,
                )?;
            }
        }
        Ok(ring)
    }

    fn base_key(&self, row: &BaseRow) -> Result<BaseKeys, Error> {
        let aad = match self.kind() {
            DeviceKind::Full => keys::account_wrapper_aad(&row.id, row.epoch),
            DeviceKind::App => keys::app_wrapper_aad(&row.id, &self.inner.device_id, row.epoch),
        };
        let ring = self.device_keys()?;
        if row.account_epoch > ring.newest().0 {
            return Err(Error::Network("waiting for account key".into()));
        }
        for (_, key) in ring.iter_newest_first() {
            match envelope::open(&bh_crypto::kdf(key, b"bhbasew1", 1), &aad, &row.wrapper) {
                Ok(bytes) => {
                    return BaseKeys::from_chain(
                        row.epoch,
                        BaseKey::new(&bytes)?,
                        &row.chain,
                        &row.id,
                    );
                }
                Err(Error::NeedsUpdate) => return Err(Error::NeedsUpdate),
                Err(Error::Crypto) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::Crypto)
    }

    /// Loads a hidden wrapper without exposing the password-derived key outside the unlocked base.
    async fn reload_hidden_key(&self, id: BaseId) -> Result<BaseKeys, Error> {
        // The base's own wrapper still names the old account epoch when the
        // server fences sends, so fetch the account's newer key first.
        self.refresh_account_data().await?;
        let (keys, account_epoch) = self.load_hidden_key(id).await?;
        if account_epoch < self.device_keys()?.newest().0 {
            // A refused send runs inside this base's sync task. Re-key in a
            // separate task: waiting here would await our own sync task.
            let account = self.clone();
            self.inner.shared.handle.spawn(async move {
                let _ = account.rekey_hidden(id).await;
            });
        }
        Ok(keys)
    }

    async fn load_hidden_key(&self, id: BaseId) -> Result<(BaseKeys, u32), Error> {
        let response = self.inner.api.base_key(id).await?;
        if response.account_epoch > self.device_keys()?.newest().0 {
            self.refresh_account_data().await?;
        }
        let row = Self::base_row(id, response);
        let ring = self.device_keys()?;
        let account_keys: Vec<_> = ring.iter_newest_first().map(|(_, key)| key).collect();
        let keys = {
            let hidden = self.inner.hidden_keys.lock().unwrap();
            let key = hidden.get(&id).ok_or(Error::NotFound)?;
            let (current, _) = key
                .open_any(&account_keys, self.id(), id, row.epoch, &row.wrapper)
                .ok_or(Error::Crypto)?;
            BaseKeys::from_chain(row.epoch, current, &row.chain, &id)?
        };
        self.db()
            .remember_hidden(id, row.epoch, &row.wrapper, &row.chain, row.account_epoch)?;
        Ok((keys, row.account_epoch))
    }

    /// Advances an unlocked hidden base; never produces app wrappers.
    async fn rekey_hidden(&self, id: BaseId) -> Result<(), Error> {
        let (mut canceled, _guard) = {
            // Same order as lock: a lock cannot remove the key between the
            // check and registering the task that it must cancel.
            let keys = self.inner.hidden_keys.lock().unwrap();
            if !keys.contains_key(&id) {
                return Ok(());
            }
            let mut active = self.inner.hidden_rekeys.lock().unwrap();
            if active.contains_key(&id) {
                return Ok(());
            }
            let (send, recv) = watch::channel(false);
            let token = Arc::new(());
            active.insert(
                id,
                HiddenRekeyTask {
                    cancel: send,
                    token: token.clone(),
                },
            );
            (
                recv,
                HiddenRekeyGuard {
                    owner: Arc::downgrade(&self.inner),
                    id,
                    token,
                },
            )
        };
        let before_send = canceled.clone();
        tokio::select! {
            biased;
            _ = canceled.changed() => {
                #[cfg(feature = "test-support")]
                let hold = self.inner.held_hidden_cancel.lock().unwrap().clone();
                #[cfg(feature = "test-support")]
                if let Some(hold) = hold
                    && hold.id == id
                {
                    hold.entered.add_permits(1);
                    hold.release.acquire().await.expect("test release").forget();
                }
                Ok(())
            },
            result = self.rekey_hidden_once(id, before_send) => result,
        }
    }

    async fn rekey_hidden_once(
        &self,
        id: BaseId,
        canceled: watch::Receiver<bool>,
    ) -> Result<(), Error> {
        self.refresh_account_data().await?;
        let (version, _) = self.db().account_data()?.ok_or(Error::Crypto)?;
        let response = self.inner.api.base_key(id).await?;
        let row = Self::base_row(id, response);
        let ring = self.device_keys()?;
        let (account_epoch, account_key) = ring.newest();
        let account_keys: Vec<_> = ring.iter_newest_first().map(|(_, key)| key).collect();
        let (old, needs_rekey, wrapper) = {
            let hidden = self.inner.hidden_keys.lock().unwrap();
            let key = hidden.get(&id).ok_or(Error::NotFound)?;
            let (old, used) = key
                .open_any(&account_keys, self.id(), id, row.epoch, &row.wrapper)
                .ok_or(Error::Crypto)?;
            let needs_rekey =
                row.account_epoch < account_epoch || (account_epoch > 1 && used != Some(0));
            let next_epoch = row.epoch.checked_add(1).ok_or(Error::Crypto)?;
            let next = BaseKey::new(Secret::<32>::random().expose())?;
            let wrapper = key.wrap_v2(account_key, self.id(), id, next_epoch, &next);
            (old, needs_rekey, (next, wrapper))
        };
        if needs_rekey {
            let (next, wrapper) = wrapper;
            #[cfg(feature = "test-support")]
            let hold = self.inner.held_hidden_rekey.lock().unwrap().clone();
            #[cfg(feature = "test-support")]
            if let Some(hold) = hold
                && hold.id == id
            {
                hold.entered.add_permits(1);
                hold.release.acquire().await.expect("test release").forget();
            }
            // A lock may have happened while preparing the request or waiting
            // for test synchronization; never initiate a new send after it.
            if *canceled.borrow() {
                return Ok(());
            }
            let result = self
                .inner
                .api
                .rekey(
                    id,
                    &RekeyRequest {
                        from: row.epoch,
                        wrapper: Bytes(wrapper),
                        previous: Bytes(seal_previous(&next, &id, row.epoch, &old)),
                        apps: vec![],
                        account_epoch,
                        data_version: version,
                    },
                )
                .await;
            if let Err(error) = result {
                let retry = self.inner.api.base_key(id).await?;
                if retry.account_epoch < account_epoch {
                    return Err(error);
                }
            }
        }
        let (keys, _) = self.load_hidden_key(id).await?;
        if let Some(base) = self.inner.hidden.lock().unwrap().get(&id) {
            base.install_keys(keys);
        }
        Ok(())
    }

    async fn reload_base_key(&self, id: BaseId) -> Result<BaseKeys, Error> {
        if self.inner.hidden_keys.lock().unwrap().contains_key(&id) {
            return self.reload_hidden_key(id).await;
        }
        let key = self.inner.api.base_key(id).await?;
        if key.account_epoch > self.device_keys()?.newest().0 && self.kind() == DeviceKind::Full {
            self.refresh_account_data().await?;
        }
        let row = Self::base_row(id, key);
        let keys = self.base_key(&row)?;
        self.db().put_base(&row, now_ms())?;
        Ok(keys)
    }

    /// Advances one ordinary base and all currently authorized app wrappers.
    #[cfg(feature = "test-support")]
    pub(crate) async fn rekey_base(&self, id: BaseId) -> Result<(), Error> {
        self.rekey_base_to(id, None).await
    }

    /// Recheck the server key immediately before re-keying: another device may
    /// have completed the same pending removal since our first read.
    pub(crate) async fn rekey_base_to(
        &self,
        id: BaseId,
        required: Option<(u32, u64)>,
    ) -> Result<(), Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        // Use the authenticated account snapshot before awaiting the base key.
        // Later key adoption cannot mix a new account key with old app keys.
        let record = self
            .inner
            .api
            .account_after(self.verified_keys()?.newest().0)
            .await?;
        self.adopt_keys(record.epoch, &record.device_keys)?;
        let ring = self.device_keys()?;
        if ring.newest().0 != record.epoch {
            return Err(Error::Conflict("epoch_conflict".into()));
        }
        let (version, data, _) = self.accept_data(record.data.as_ref())?;
        let current = Self::base_row(id, self.inner.api.base_key(id).await?);
        if required.is_some_and(|(epoch, floor)| {
            current.account_epoch >= epoch && current.data_floor >= floor
        }) {
            return Ok(());
        }
        let old = self.base_key(&current)?;
        let next_epoch = current.epoch.checked_add(1).ok_or(Error::Crypto)?;
        let next = BaseKey::new(Secret::<32>::random().expose())?;
        let wrapper = envelope::seal(
            &bh_crypto::kdf(ring.newest().1, b"bhbasew1", 1),
            &keys::account_wrapper_aad(&id, next_epoch),
            next.secret().expose(),
        );
        let mut apps = Vec::new();
        if let Some(entries) = data.get("apps").and_then(Value::as_object) {
            for (device, entry) in entries {
                let device: DeviceId = device.parse().map_err(|_| Error::Crypto)?;
                let effective =
                    grants::effective(&grants::direct(&data, device), &grants::mounts(&data));
                if !effective.contains_key(&id) {
                    continue;
                }
                let app_key = entry
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or(Error::Crypto)?;
                let app_key = Secret::<32>::from_slice(
                    &URL_SAFE_NO_PAD.decode(app_key).map_err(|_| Error::Crypto)?,
                )?;
                apps.push(AppWrapper {
                    device_id: device,
                    wrapper: Bytes(envelope::seal(
                        &bh_crypto::kdf(&app_key, b"bhbasew1", 1),
                        &keys::app_wrapper_aad(&id, &device, next_epoch),
                        next.secret().expose(),
                    )),
                });
            }
        }
        let sent_epoch = ring.newest().0;
        let sent_version = version;
        let result = self
            .inner
            .api
            .rekey(
                id,
                &RekeyRequest {
                    from: current.epoch,
                    wrapper: Bytes(wrapper),
                    previous: Bytes(seal_previous(&next, &id, current.epoch, old.current().1)),
                    apps,
                    account_epoch: sent_epoch,
                    data_version: version,
                },
            )
            .await;
        if let Err(error) = result {
            let key = self.inner.api.base_key(id).await?;
            if key.account_epoch < sent_epoch || key.data_floor < sent_version {
                return Err(error);
            }
        }
        // Fetch the authoritative chain, including races with another re-key.
        let keys = self.reload_base_key(id).await?;
        if let Ok(base) = self.base(id) {
            base.install_keys(keys);
        }
        Ok(())
    }

    /// Exercises key delivery through an atomic removal in local integration tests.
    #[cfg(feature = "test-support")]
    pub async fn test_rotate_account(&self, remove: Option<DeviceId>) -> Result<(), Error> {
        if let Some(device) = remove {
            return self
                .remove_device(
                    device,
                    Removal::Full {
                        password: Zeroizing::new("correct horse battery staple".into()),
                        lost: false,
                    },
                )
                .await
                .map(|_| ());
        }
        use crate::rotation::seal_for_device;
        use bh_proto::{DeviceKeyEntry, RotationRequest};
        if self.kind() != DeviceKind::Full || remove == Some(self.device_id()) {
            return Err(Error::Forbidden);
        }
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                this.refresh_account_data().await?;
                let (target, disposable_key) = match remove {
                    Some(id) => (id, None),
                    None => {
                        let id = DeviceId::random();
                        let key = Secret::<32>::random();
                        this.inner
                            .api
                            .add_device(&DevicesRequest {
                                device_id: id,
                                kind: AppDeviceKind::App,
                                cap_micro_usd: None,
                            })
                            .await?;
                        (id, Some(key))
                    }
                };
                let record = this.inner.api.account().await?;
                let old = this.account_key()?;
                let next = Secret::<32>::random();
                let next_epoch = this
                    .verified_keys()?
                    .newest()
                    .0
                    .checked_add(1)
                    .ok_or(Error::Crypto)?;
                let (version, mut data, _) = this.accept_data(record.data.as_ref())?;
                let pins = this.pin_publics(&data)?;
                let kit = this.recovery_kit()?.ok_or(Error::BadKit)?;
                let params = this.inner.api.login_params(&this.inner.email).await?;
                let salt = login_salt(&params)?;
                let password = derive(
                    Zeroizing::new("correct horse battery staple".to_owned()),
                    salt,
                    params.kdf,
                )
                .await?;
                let envelope = envelope::seal(
                    &password.wrap_key(&kit),
                    &keys::account_key_aad(&this.id(), next_epoch),
                    next.expose(),
                );
                let hash = envelope_hash(&envelope);
                let saved = data
                    .get("kit")
                    .and_then(|v| v.get("saved"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                set_kit(&mut data, &kit, saved, &hash, &salt);
                let old_epoch = next_epoch - 1;
                entry(&mut data, "keys").insert(
                    old_epoch.to_string(),
                    json!(URL_SAFE_NO_PAD.encode(old.expose())),
                );
                let mut deliveries = Vec::new();
                for device in record
                    .devices
                    .iter()
                    .filter(|d| d.status == "active" && d.device_id != target)
                {
                    let public: [u8; XWING_PUBLIC_BYTES] = pins
                        .get(&device.device_id)
                        .ok_or(Error::Crypto)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Crypto)?;
                    let (previous, next_key) = match device.kind {
                        bh_proto::DeviceKind::Full => (
                            Secret::from_slice(old.expose())?,
                            Secret::from_slice(next.expose())?,
                        ),
                        bh_proto::DeviceKind::App => {
                            let app = data
                                .get_mut("apps")
                                .and_then(|v| v.get_mut(device.device_id.to_string()))
                                .ok_or(Error::Crypto)?;
                            let previous = Secret::from_slice(
                                &URL_SAFE_NO_PAD
                                    .decode(
                                        app.get("key")
                                            .and_then(Value::as_str)
                                            .ok_or(Error::Crypto)?,
                                    )
                                    .map_err(|_| Error::Crypto)?,
                            )?;
                            let new = Secret::<32>::random();
                            app["key"] = json!(URL_SAFE_NO_PAD.encode(new.expose()));
                            (previous, new)
                        }
                    };
                    deliveries.push(DeviceKeyEntry {
                        device_id: device.device_id,
                        sealed: Bytes(seal_for_device(
                            &public,
                            &DeliveryContext {
                                account: this.id(),
                                device: device.device_id,
                                kind: device.kind.clone(),
                                from_epoch: old_epoch,
                            },
                            &previous,
                            &next_key,
                        )?),
                    });
                }
                let json = Zeroizing::new(serde_json::to_vec(&data).map_err(|_| Error::Crypto)?);
                let ciphertext = envelope::seal(
                    &keys::account_data_key(&next),
                    &keys::account_data_aad(&this.id(), data_epoch(version + 1)?),
                    &json,
                );
                let notice = match disposable_key {
                    Some(key) => keys::removal_notice(
                        &bh_crypto::kdf(&key, keys::REMOVAL, 1),
                        &this.id(),
                        &target,
                    ),
                    None => this.removal_notice_for(target).await?,
                };
                this.inner
                    .api
                    .delete_device(
                        target,
                        &DeleteDeviceRequest {
                            notice: Some(Bytes(notice.to_vec())),
                            data: Some(AccountDataRequest {
                                ciphertext: Bytes(ciphertext),
                                expected_version: version,
                                account_epoch: next_epoch,
                            }),
                            rotation: Some(RotationRequest {
                                epoch: next_epoch,
                                login_key: Bytes(password.login_key().to_vec()),
                                account_key_envelope: Bytes(envelope),
                                activation_hash: Bytes(
                                    bh_crypto::sha256(keys::activation(&next).expose()).to_vec(),
                                ),
                                device_keys: deliveries,
                            }),
                        },
                    )
                    .await?;
                this.refresh_account_data().await?;
                for id in record.bases {
                    this.rekey_base(id).await?;
                }
                Ok(())
            })
            .await
    }

    /// Re-keys one ordinary base in integration tests.
    #[cfg(feature = "test-support")]
    pub async fn test_rekey_base(&self, id: BaseId) -> Result<(), Error> {
        let this = self.clone();
        self.inner
            .shared
            .run(async move { this.rekey_base(id).await })
            .await
    }

    fn base_row(id: BaseId, key: BaseKeyResponse) -> BaseRow {
        BaseRow {
            id,
            epoch: key.epoch,
            wrapper: key.wrapper.0,
            mode: match key.mode {
                GrantMode::ReadWrite => Mode::ReadWrite,
                GrantMode::ReadOnly => Mode::ReadOnly,
            },
            chain: key
                .previous
                .into_iter()
                .map(|p| (p.epoch, p.sealed.0))
                .collect(),
            account_epoch: key.account_epoch,
            data_floor: key.data_floor,
        }
    }

    /// Creates a base named `name`, with a new key that only this account's
    /// key opens, and sends its name before returning. Full devices only. Needs
    /// the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for an empty name, [`Error::Forbidden`] on
    /// an app device, [`Error::Revoked`] for a removed device, [`Error::Network`]
    /// for connection failure, [`Error::Conflict`] if a key conflicts, or
    /// [`Error::Storage`] for a local store failure.
    pub async fn create_base(&self, name: &str) -> Result<Base, Error> {
        self.create_base_at(BaseId::random(), name).await
    }

    /// As [`Self::create_base`], with the ID `id`. When the server already has
    /// `id`, as after a lost reply or a create that stopped midway, it adopts
    /// that base if its key opens under the account key, and writes the name
    /// only when the base has none here.
    pub(crate) async fn create_base_at(&self, id: BaseId, name: &str) -> Result<Base, Error> {
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
                let key = Secret::<32>::random();
                let ring = this.verified_keys()?;
                let data_version = this.db().account_data()?.map_or(0, |(version, _)| version);
                let wrapper = envelope::seal(
                    &bh_crypto::kdf(ring.newest().1, b"bhbasew1", 1),
                    &keys::account_wrapper_aad(&id, EPOCH),
                    key.expose(),
                );
                let request = BasesRequest {
                    base_id: id,
                    epoch: EPOCH,
                    wrapper: Bytes(wrapper.clone()),
                    account_epoch: ring.newest().0,
                    data_version,
                };
                let api = &this.inner.api;
                let created = match api.create_base(&request).await {
                    // The first request may have been stored before its reply was lost.
                    Err(Error::Network(_)) => api.create_base(&request).await,
                    other => other,
                };
                let mut row = BaseRow {
                    id,
                    epoch: EPOCH,
                    wrapper,
                    mode: Mode::ReadWrite,
                    chain: Vec::new(),
                    account_epoch: request.account_epoch,
                    data_floor: request.data_version,
                };
                match created {
                    Ok(_) => {}
                    // Already made: adopted only if it's this account's own base.
                    Err(Error::Conflict(code)) if code == "exists" => {
                        let key = api.base_key(id).await?;
                        row.epoch = key.epoch;
                        row.wrapper = key.wrapper.0;
                        row.chain = key
                            .previous
                            .into_iter()
                            .map(|p| (p.epoch, p.sealed.0))
                            .collect();
                        row.account_epoch = key.account_epoch;
                        row.data_floor = key.data_floor;
                        match this.base_key(&row) {
                            Ok(_) => {}
                            Err(Error::Crypto) => return Err(Error::Conflict(code)),
                            Err(e) => return Err(e),
                        }
                    }
                    Err(e) => return Err(e),
                }
                {
                    let db = this.db();
                    if this.inner.removal.load(Ordering::SeqCst) != 0 {
                        return Err(Error::Revoked);
                    }
                    db.put_base(&row, now_ms())?;
                }
                let base = this.base(id)?;
                if base.name().is_empty() {
                    base.write_info(&name)?;
                }
                // Send the name now: a caller may keep no handle, and a base's sync
                // stops with its last one. The base exists on the server already, so
                // a failed send isn't an error; the name stays queued for the next sync.
                // A slow one is bounded, as under repeated rate limits.
                let sent = tokio::time::timeout(Duration::from_secs(10), base.flush()).await;
                if let Ok(Err(Error::Revoked)) = sent {
                    return Err(Error::Revoked);
                }
                this.check_active()?;
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
                let ring = this.device_keys()?;
                let data_version = this.db().account_data()?.map_or(0, |(version, _)| version);
                let first_key = Secret::from_slice(ring.get(1).ok_or(Error::Crypto)?.expose())?;
                let hidden_key =
                    tokio::task::spawn_blocking(move || HiddenKey::derive(&first_key, &password))
                        .await
                        .map_err(|_| Error::Storage("hidden key derivation failed".into()))??;
                let id = BaseId::random();
                let raw_key = Zeroizing::new(bh_crypto::random::<32>());
                let key = BaseKey::new(&*raw_key)?;
                let wrapper = if ring.newest().0 == 1 {
                    hidden_key.wrap(this.id(), id, EPOCH, &key)
                } else {
                    hidden_key.wrap_v2(ring.newest().1, this.id(), id, EPOCH, &key)
                };
                let request = BasesRequest {
                    base_id: id,
                    epoch: EPOCH,
                    wrapper: Bytes(wrapper.clone()),
                    account_epoch: ring.newest().0,
                    data_version,
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
                this.db()
                    .remember_hidden(id, EPOCH, &wrapper, &[], ring.newest().0)?;
                let store_key = hidden::store_key(&key);
                let base = this.open_base_with_key(id, key, &store_key, Mode::ReadWrite)?;
                this.inner
                    .hidden_keys
                    .lock()
                    .unwrap()
                    .insert(id, hidden_key);
                base.write_info(&name)?;
                let _ = this.inner.events.send(AccountEvent::BasesChanged);
                Ok(base)
            })
            .await
    }

    /// Tests one extra password against every local hidden wrapper, opening
    /// every matching base and returning summaries including already-open ones.
    /// Works offline without waiting for the network; opened bases start background
    /// sync and re-key when connectivity is available. Runs one Argon2id even if the index
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
                let ring = this.device_keys()?;
                let first_key = Secret::from_slice(ring.get(1).ok_or(Error::Crypto)?.expose())?;
                let key =
                    tokio::task::spawn_blocking(move || HiddenKey::derive(&first_key, &password))
                        .await
                        .map_err(|_| Error::Storage("hidden key derivation failed".into()))??;
                let wrappers = this.db().hidden_wrappers()?;
                let mut found = Vec::new();
                let mut added = false;
                for row in wrappers {
                    let id = row.id;
                    let ring = this.device_keys()?;
                    let account_keys: Vec<_> = ring.iter_newest_first().map(|(_, k)| k).collect();
                    if let Some((base_key, _)) =
                        key.open_any(&account_keys, this.id(), id, row.epoch, &row.wrapper)
                    {
                        let base = if let Some(base) = this.inner.hidden.lock().unwrap().get(&id) {
                            base.clone()
                        } else {
                            let (store_base_key, _) = key
                                .open_any(
                                    &account_keys,
                                    this.id(),
                                    id,
                                    row.store_epoch,
                                    &row.store_wrapper,
                                )
                                .ok_or(Error::Crypto)?;
                            let store_key = hidden::store_key(&store_base_key);
                            let keys = BaseKeys::from_chain(
                                row.epoch,
                                BaseKey::new(base_key.secret().expose())?,
                                &row.chain,
                                &id,
                            )?;
                            match this.open_base_with_key(id, base_key, &store_key, Mode::ReadWrite)
                            {
                                Ok(base) => {
                                    base.install_keys(keys);
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
                        // Keep the derivation available to the key source until lock.
                        this.inner
                            .hidden_keys
                            .lock()
                            .unwrap()
                            .insert(id, key.duplicate());
                        found.push(BaseSummary {
                            id,
                            name: base.name(),
                            mode: base.mode(),
                            hidden: true,
                            mount: None,
                        });
                    }
                }
                if found.is_empty() {
                    return Err(Error::NothingUnlocked);
                }
                if added {
                    let _ = this.inner.events.send(AccountEvent::BasesChanged);
                }
                // Online work cannot hold the password/lock gate: offline unlock
                // must return with its local store, and lock must remain local.
                let unlocked: Vec<_> = found.iter().map(|summary| summary.id).collect();
                drop(_gate);
                for id in unlocked {
                    let account = this.clone();
                    this.inner.shared.handle.spawn(async move {
                        let _ = account.rekey_hidden(id).await;
                    });
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
        {
            let mut keys = self.inner.hidden_keys.lock().unwrap();
            let mut active = self.inner.hidden_rekeys.lock().unwrap();
            for base in &bases {
                keys.remove(&base.id());
                if let Some(task) = active.remove(&base.id()) {
                    task.cancel.send_replace(true);
                }
            }
        }
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
        if !self.begin_removal() {
            return self.wait_for_removal().await;
        }
        self.finish_removal().await
    }

    /// Starts erasing: blocks writes and takes the account off the list. False if
    /// an erasure already started.
    fn begin_removal(&self) -> bool {
        // Serialize the transition with base(): a base must not start sync
        // after we've collected the tasks to stop.
        let _bases = self.inner.bases.lock().unwrap();
        if self
            .inner
            .removal
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        if let Some(accounts) = self.inner.shared.accounts.lock().unwrap().upgrade() {
            accounts.lock().unwrap().remove(&self.inner.id);
        }
        self.inner.backup_signal.notify_one();
        true
    }

    async fn wait_for_removal(&self) -> Result<(), Error> {
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

    async fn finish_removal(&self) -> Result<(), Error> {
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
        // Stop the detached finisher before deleting any store it might access.
        let rekey_task = self.inner.rekey_task.lock().unwrap().take();
        if let Some(task) = rekey_task {
            task.abort();
            let _ = task.await;
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
                    checked_public: None,
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
                    .connect_app_with(
                        req,
                        device,
                        choice.cap_micro_usd,
                        request.checked_public.take(),
                    )
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
                    let _ = this.remove_device(device, Removal::Plain).await;
                    let _ = api.approval_end(id, EndReason::BadMessage).await;
                    return Err(e);
                }
                let removed = if let Some(old) = choice.replaces {
                    // The app already has its new credentials: a failed removal
                    // must not revoke its new device.
                    this.remove_device(old, Removal::Plain).await.is_ok()
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
                let transfer = match side.confirm_at(
                    &typed,
                    &key,
                    this.verified_keys()?.newest().0,
                    request.clock.now_ms(),
                ) {
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
    /// catch up. On full devices it also finishes app grant changes, and moves
    /// between bases this device started, that stopped midway; on app devices
    /// it erases bases no longer granted.
    /// Needs the network to fetch grants; sync then continues in the background.
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
                if this.kind() == DeviceKind::App {
                    this.ensure_kem_seed()?;
                }
                let me = this
                    .inner
                    .api
                    .me_after(this.verified_keys()?.newest().0)
                    .await?;
                this.adopt_keys(me.epoch, &me.device_keys)?;
                let listed = me.bases;
                let mounts = this.mounts();
                let data_error = if this.kind() == DeviceKind::Full {
                    match this.refresh_account_data().await {
                        Err(Error::Revoked) => return Err(Error::Revoked),
                        other => other.err(),
                    }
                } else {
                    None
                };
                if this.kind() == DeviceKind::Full && data_error.is_none() {
                    let _ = this.finish_rekeys().await;
                }
                let mut known: HashSet<BaseId> = this.db().bases()?.iter().map(|r| r.id).collect();
                known.extend(this.db().hidden_wrappers()?.into_iter().map(|row| row.id));
                let granted: HashSet<BaseId> = listed.iter().copied().collect();
                // A base mounted or moved elsewhere changes how bases are listed.
                let mut changed = this.mounts() != mounts;
                let mut needs_update = false;
                for id in listed.into_iter().filter(|id| !known.contains(id)) {
                    let key = match this.inner.api.base_key(id).await {
                        Ok(key) => key,
                        // A refused grant may leave an app listing before base access exists.
                        Err(Error::Forbidden) if this.kind() == DeviceKind::App => continue,
                        Err(error) => return Err(error),
                    };
                    let row = Self::base_row(id, key);
                    // An unopened wrapper is indexed without a name, mode or key.
                    match this.base_key(&row) {
                        Ok(_) => {}
                        Err(Error::Crypto) => {
                            this.db().remember_hidden(
                                id,
                                row.epoch,
                                &row.wrapper,
                                &row.chain,
                                row.account_epoch,
                            )?;
                            continue;
                        }
                        Err(Error::NeedsUpdate) => {
                            needs_update = true;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                    this.db().put_base(&row, now_ms())?;
                    changed = true;
                }
                // An app device keeps only the bases it's still granted. One
                // failed erase must not hold up the others or their catch-up.
                let mut erase_error = None;
                if this.kind() == DeviceKind::App {
                    let rows = this.db().bases()?;
                    for row in rows.iter().filter(|row| !granted.contains(&row.id)) {
                        if let Err(error) = this.erase_base(row.id).await {
                            erase_error.get_or_insert(error);
                        } else {
                            changed = true;
                        }
                    }
                }
                // Collected first: `base` locks the account store too.
                let all: Vec<BaseId> = this
                    .db()
                    .bases()?
                    .iter()
                    .map(|r| r.id)
                    .filter(|id| this.kind() != DeviceKind::App || granted.contains(id))
                    .collect();
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
                    let _ = this.rekey_hidden(base.id()).await;
                    base.catch_up();
                }
                if changed {
                    let _ = this.inner.events.send(AccountEvent::BasesChanged);
                }
                // Only fresh account data says which grant changes and moves are
                // still pending.
                let (settle_error, move_error) =
                    if this.kind() == DeviceKind::Full && data_error.is_none() {
                        (
                            this.settle_grants().await.err(),
                            this.resume_moves().await.err(),
                        )
                    } else {
                        (None, None)
                    };
                if needs_update {
                    Err(Error::NeedsUpdate)
                } else if let Some(error) =
                    data_error.or(erase_error).or(settle_error).or(move_error)
                {
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

    fn pin_publics(&self, data: &Data) -> Result<BTreeMap<DeviceId, Vec<u8>>, Error> {
        let mut pins = BTreeMap::new();
        // Our local seed is the authority for our own public key. Pin it before
        // considering any untrusted account-data entry, on every read and write.
        if self.kind() == DeviceKind::Full {
            let name = format!("acct.{}.kem", self.id());
            if let Some(seed) = self.inner.shared.secrets.get(&name)? {
                let public = KemKey::from_seed(&Secret::<32>::from_slice(&seed)?).public();
                if self.db().pin_public(self.device_id(), &public)? != public {
                    return Err(Error::Crypto);
                }
            }
        }
        for group in ["devices", "apps"] {
            if let Some(entries) = data.get(group).and_then(Value::as_object) {
                for (id, entry) in entries {
                    if let (Ok(device), Some(encoded)) = (
                        id.parse::<DeviceId>(),
                        entry.get("public").and_then(Value::as_str),
                    ) && let Ok(public) = URL_SAFE_NO_PAD.decode(encoded)
                        && public.len() == XWING_PUBLIC_BYTES
                    {
                        pins.insert(device, self.db().pin_public(device, &public)?);
                    }
                }
            }
        }
        Ok(pins)
    }

    fn ensure_kem_seed(&self) -> Result<Secret<32>, Error> {
        let name = format!("acct.{}.kem", self.id());
        match self.inner.shared.secrets.get(&name)? {
            Some(seed) => Ok(Secret::<32>::from_slice(&seed)?),
            None => {
                let seed = Secret::<32>::random();
                self.inner.shared.secrets.put(&name, seed.expose())?;
                Ok(seed)
            }
        }
    }

    fn own_public(&self, data: &Data) -> Result<String, Error> {
        let stored_value = data
            .get("devices")
            .and_then(|devices| devices.get(self.device_id().to_string()))
            .and_then(|device| device.get("public"));
        let stored = stored_value.and_then(Value::as_str);
        let pin = self.db().public_pin(self.device_id())?;
        let name = format!("acct.{}.kem", self.id());
        let seed = match self.inner.shared.secrets.get(&name)? {
            Some(seed) => Secret::<32>::from_slice(&seed)?,
            None if stored_value.is_some() || pin.is_some() => return Err(Error::Crypto),
            None => self.ensure_kem_seed()?,
        };
        let public = KemKey::from_seed(&seed).public();
        let encoded = URL_SAFE_NO_PAD.encode(public);
        if stored_value.is_some() && stored != Some(encoded.as_str())
            || pin.as_deref().is_some_and(|pinned| pinned != public)
        {
            return Err(Error::Crypto);
        }
        // An upgrade creates its seed only here, after checking that neither
        // account data nor the local pin records an earlier public key.
        self.pin_publics(data)?;
        Ok(encoded)
    }

    /// Refreshes encrypted account data before a Hero turn makes access decisions.
    pub(crate) async fn refresh_account_data(&self) -> Result<(), Error> {
        self.refresh_account_data_inner(
            #[cfg(feature = "test-support")]
            None,
        )
        .await
    }

    /// Suspend only this caller's reader refresh after its account GET returns.
    #[cfg(feature = "test-support")]
    pub(crate) async fn refresh_account_data_held(
        &self,
        hold: Option<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>)>,
    ) -> Result<(), Error> {
        self.refresh_account_data_inner(hold).await
    }

    async fn refresh_account_data_inner(
        &self,
        #[cfg(feature = "test-support")] hold: Option<(
            Arc<tokio::sync::Semaphore>,
            Arc<tokio::sync::Semaphore>,
        )>,
    ) -> Result<(), Error> {
        let this = self.clone();
        self.inner
            .shared
            .run(async move {
                if this.kind() != DeviceKind::Full {
                    return Ok(());
                }
                let record = this
                    .inner
                    .api
                    .account_after(this.verified_keys()?.newest().0)
                    .await?;
                #[cfg(feature = "test-support")]
                if let Some((release, entered)) = hold {
                    entered.add_permits(1);
                    release
                        .acquire()
                        .await
                        .expect("reader hold is open")
                        .forget();
                }
                this.adopt_keys(record.epoch, &record.device_keys)?;
                this.cache_envelope(&record.account_key_envelope.0)?;
                let (version, data, versioned) = this.accept_data(record.data.as_ref())?;
                this.note_envelope(&record.account_key_envelope.0, &data)
                    .await?;
                let own_public = this.own_public(&data)?;
                if data
                    .get("devices")
                    .and_then(|devices| devices.get(this.device_id().to_string()))
                    .and_then(|device| device.get("public"))
                    .and_then(Value::as_str)
                    != Some(own_public.as_str())
                {
                    let device = this.device_id();
                    this.update_data_with_envelope(move |data, _| {
                        let item = entry(data, "devices")
                            .entry(device.to_string())
                            .or_insert_with(|| json!({}));
                        if item.get("public").and_then(Value::as_str) == Some(own_public.as_str()) {
                            return false;
                        }
                        item["public"] = json!(own_public);
                        true
                    })
                    .await?;
                }
                let hash = envelope_hash(&record.account_key_envelope.0);
                if data.get("kit").is_some_and(|kit| {
                    kit.get("envelope").and_then(Value::as_str) == Some(hash.as_str())
                        && kit.get("salt").is_none()
                }) {
                    let salt = login_salt(&this.inner.api.login_params(&this.inner.email).await?)?;
                    this.update_data_with_envelope(move |data, current_hash| {
                        if current_hash != hash
                            || data.get("kit").is_none_or(|kit| {
                                kit.get("envelope").and_then(Value::as_str) != Some(hash.as_str())
                                    || kit.get("salt").is_some()
                            })
                        {
                            return false;
                        }
                        data["kit"]["salt"] = Value::String(salt_hex(&salt));
                        true
                    })
                    .await?;
                }
                // Older-format data is rewritten with its version sealed in. If
                // that fails, the next read tries again.
                if record.data.is_some() && !versioned {
                    let _ = this.write_data(version, &data).await;
                }
                Ok(())
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
                let response = this
                    .inner
                    .api
                    .account_after(this.verified_keys()?.newest().0)
                    .await?;
                this.adopt_keys(response.epoch, &response.device_keys)?;
                let (_, data, _) = this.accept_data(response.data.as_ref())?;
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
                        pending_removal: data
                            .get("pendingRemovals")
                            .and_then(|entries| entries.get(d.device_id.to_string()))
                            .is_some(),
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
                this.refresh_account_data().await?;
                let api = &this.inner.api;
                let params = api.login_params(&this.inner.email).await?;
                let salt = login_salt(&params)?;
                let secret = derive(password, salt, params.kdf.clone()).await?;
                let ring = this.verified_keys()?;
                let kit = RecoveryKit::generate();
                let envelope = envelope::seal(
                    &secret.wrap_key(&kit),
                    &keys::account_key_aad(&this.inner.id, ring.newest().0),
                    ring.newest().1.expose(),
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
                // The server has rotated the kit; a local backup-cache failure
                // must not prevent the person from receiving the new kit.
                let _ =
                    this.remember_backup_credentials(request.account_key_envelope.0.clone(), salt);
                this.inner.db.lock().unwrap().set_envelope_hash(&hash)?;
                let copy = kit.clone();
                let _ = this
                    .update_data(move |data| set_kit(data, &copy, false, &hash, &salt))
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
                this.refresh_account_data().await?;
                let api = &this.inner.api;
                let account_key = this.account_key()?;
                let sealed = api.account().await?.account_key_envelope;
                let params = api.login_params(&this.inner.email).await?;
                let current = derive(current, login_salt(&params)?, params.kdf).await?;
                let opened = envelope::open(
                    &current.wrap_key(&kit),
                    &keys::account_key_aad(
                        &this.inner.id,
                        envelope::epoch(&sealed.0).ok_or(Error::Crypto)?,
                    ),
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
                    &keys::account_key_aad(
                        &this.inner.id,
                        envelope::epoch(&sealed.0).ok_or(Error::Crypto)?,
                    ),
                    account_key.expose(),
                );
                let hash = envelope_hash(&envelope);
                api.put_credentials(&CredentialsRequest {
                    current_login_key: Bytes(current.login_key().to_vec()),
                    login_key: Bytes(next.login_key().to_vec()),
                    salt: Bytes(salt.to_vec()),
                    kdf: DEFAULT_KDF,
                    account_key_envelope: Bytes(envelope.clone()),
                })
                .await?;
                let _ = this.remember_backup_credentials(envelope, salt);
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
                    stored["salt"] = Value::String(salt_hex(&salt));
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
        self.update_data_at(move |data, _| edit(data)).await
    }

    /// Edit account data using the version of the attempt that actually wins CAS.
    pub(crate) async fn update_data_at(
        &self,
        edit: impl Fn(&mut Data, u64) + Send + 'static,
    ) -> Result<(), Error> {
        self.update_data_with_envelope_at(move |data, _, version| {
            edit(data, version);
            true
        })
        .await
        .map(|_| ())
    }

    /// The envelope hash belongs to the same server snapshot as the data being edited.
    pub(crate) async fn update_data_with_envelope(
        &self,
        edit: impl Fn(&mut Data, &str) -> bool + Send + 'static,
    ) -> Result<(), Error> {
        self.update_data_with_envelope_at(move |data, hash, _| edit(data, hash))
            .await
            .map(|_| ())
    }

    /// Returns the epoch of the key that sealed the successful data write,
    /// not a later epoch adopted while subsequent work was in flight.
    async fn update_data_with_envelope_at(
        &self,
        edit: impl Fn(&mut Data, &str, u64) -> bool + Send + 'static,
    ) -> Result<Option<u32>, Error> {
        let api = &self.inner.api;
        for _ in 0..5 {
            let record = api.account_after(self.verified_keys()?.newest().0).await?;
            self.adopt_keys(record.epoch, &record.device_keys)?;
            let hash = envelope_hash(&record.account_key_envelope.0);
            self.db().set_envelope_hash(&hash)?;
            let (version, mut data, _) = self.accept_data(record.data.as_ref())?;
            self.note_envelope(&record.account_key_envelope.0, &data)
                .await?;
            let next_version = version.checked_add(1).ok_or(Error::Crypto)?;
            if !edit(&mut data, &hash, next_version) {
                return Ok(None);
            }
            match self.write_data(version, &data).await {
                Err(Error::Conflict(code)) if code == "version_conflict" => continue,
                Err(error) => return Err(error),
                Ok(written_epoch) => {
                    self.note_envelope(&record.account_key_envelope.0, &data)
                        .await?;
                    return Ok(Some(written_epoch));
                }
            }
        }
        Err(Error::Conflict("version_conflict".into()))
    }

    /// Keeps only a pair bound to the opened kit record; never downgrades a checked pair.
    async fn note_envelope(&self, envelope: &[u8], data: &Data) -> Result<(), Error> {
        let previous = self.backup_credentials()?;
        let hash = envelope_hash(envelope);
        let checked_salt = kit_salt(data, &hash);
        // Sealed account data can't be forged, so an envelope its kit record
        // doesn't name isn't the account's. Keep only a pair the record names,
        // or one this device checked: never the server's other envelope, and
        // not an unchecked one kept before the record arrived.
        let named = data
            .get("kit")
            .and_then(|kit| kit.get("envelope"))
            .and_then(Value::as_str);
        let next = if let Some(salt) = checked_salt {
            Credentials {
                envelope: envelope.to_vec(),
                salt,
                checked: true,
            }
        } else if let Some(named) = named.filter(|named| *named != hash) {
            if previous
                .as_ref()
                .is_some_and(|c| !c.checked && envelope_hash(&c.envelope) != named)
            {
                self.db().clear_unchecked_backup_credentials()?;
                self.backup_changed();
            }
            return Ok(());
        } else if previous.as_ref().is_some_and(|c| c.checked) {
            return Ok(());
        } else {
            let salt = login_salt(&self.inner.api.login_params(&self.inner.email).await?)?;
            Credentials {
                envelope: envelope.to_vec(),
                salt,
                checked: false,
            }
        };
        if previous.as_ref() != Some(&next) {
            self.db().set_backup_credentials(&next)?;
            self.backup_changed();
        }
        Ok(())
    }

    pub(crate) fn remember_backup_credentials(
        &self,
        envelope: Vec<u8>,
        salt: [u8; 16],
    ) -> Result<(), Error> {
        self.db().set_backup_credentials(&Credentials {
            envelope,
            salt,
            checked: true,
        })?;
        self.backup_changed();
        Ok(())
    }

    pub(crate) fn backup_credentials(&self) -> Result<Option<Credentials>, Error> {
        if self.kind() != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        self.db().backup_credentials()
    }

    fn backup_changed(&self) {
        self.inner.backup_signal.notify_one();
    }

    pub(crate) fn backup_weak(&self) -> AccountWeak {
        AccountWeak(Arc::downgrade(&self.inner))
    }

    pub(crate) fn backup_signal(&self) -> Arc<Notify> {
        self.inner.backup_signal.clone()
    }

    pub(crate) fn backup_stopped(&self, generation: u64) -> bool {
        self.inner.backup_stop_generation.load(Ordering::SeqCst) != generation
    }

    /// The saved destination and progress for this device.
    ///
    /// # Errors
    /// Returns [`Error::Storage`] when local state cannot be read.
    pub fn backup_status(&self) -> Result<crate::backup::BackupStatus, Error> {
        self.check_active()?;
        let row = self.db().backup_row()?;
        let last_run_at = row
            .last_run
            .as_deref()
            .and_then(crate::backup::format::parse_run);
        let stale = row.enabled
            && last_run_at
                .is_none_or(|at| self.clock().edit_time_ms().saturating_sub(at) >= 7 * 86_400_000);
        let credentials = if row.enabled {
            self.db().backup_credentials()?
        } else {
            None
        };
        let credentials_problem = if row.enabled {
            match credentials {
                Some(c) if c.checked => self.db().envelope_hash()?.and_then(|hash| {
                    (hash != envelope_hash(&c.envelope))
                        .then_some(crate::backup::BackupProblem::UsingLastChecked)
                }),
                _ => Some(crate::backup::BackupProblem::NoKitRecord),
            }
        } else {
            None
        };
        Ok(crate::backup::BackupStatus {
            location: row.location,
            enabled: row.enabled,
            acknowledged: row.acknowledged,
            last_run_at,
            bytes: row.bytes,
            problem: row
                .problem
                .as_deref()
                .and_then(crate::backup::BackupProblem::parse)
                .or(credentials_problem),
            stale,
        })
    }

    /// Turns on backup to a destination, or turns it off without deleting files.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device.
    pub fn set_backup(&self, location: Option<crate::BackupLocation>) -> Result<(), Error> {
        self.backup_credentials()?;
        self.check_active()?;
        let mut row = self.db().backup_row()?;
        let mut stop = location.is_none() && row.enabled;
        if let Some(location) = location {
            let same = row
                .location
                .as_ref()
                .is_some_and(|saved| saved.same_destination(&location));
            if !same {
                stop = true;
                row.generation += 1;
                row.last_run = None;
                row.keys_hash = None;
                row.keys_name = None;
                row.bytes = 0;
            }
            row.location = Some(location);
            row.enabled = true;
        } else {
            row.enabled = false;
        }
        self.db().set_backup_row(&row)?;
        if stop {
            self.stop_backup();
        }
        if row.enabled {
            self.backup_changed();
        }
        Ok(())
    }

    /// Marks the backup explanation as acknowledged on this device.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device.
    pub fn acknowledge_backup(&self) -> Result<(), Error> {
        self.backup_credentials()?;
        self.check_active()?;
        let mut row = self.db().backup_row()?;
        row.acknowledged = true;
        self.db().set_backup_row(&row)
    }

    /// Writes this device's sealed local data to its saved folder without contacting the server.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device, [`Error::Revoked`] during erasure,
    /// or a local storage error if the store cannot be read.
    pub async fn backup_now(&self) -> Result<crate::backup::BackupRun, Error> {
        self.backup_credentials()?;
        let generation = self.inner.backup_stop_generation.load(Ordering::SeqCst);
        let account = self.clone();
        self.run(async move {
            let _lock = account.inner.backup_lock.lock().await;
            account.check_active()?;
            if account.backup_stopped(generation) {
                return Ok(crate::backup::BackupRun::default());
            }
            crate::backup::writer::run(&account, generation).await
        })
        .await
    }

    /// Requests that the current run stop before its next folder write, without waiting.
    pub fn stop_backup(&self) {
        self.inner
            .backup_stop_generation
            .fetch_add(1, Ordering::SeqCst);
    }

    /// Starts a single background schedule, replacing any earlier schedule for this account.
    pub fn start_backups(&self, schedule: crate::BackupSchedule) {
        let weak = self.backup_weak();
        let signal = self.backup_signal();
        let clock = self.clock();
        let task = self.runtime().spawn(async move {
            crate::backup::schedule::run(weak, signal, clock, schedule).await;
        });
        if let Some(previous) = self.inner.backup_schedule.lock().unwrap().replace(task) {
            previous.abort();
        }
        if self
            .backup_row()
            .is_ok_and(|row| row.enabled && row.last_run.is_none())
        {
            self.backup_changed();
        }
    }

    /// Approximate bytes to write from object states and locally available sealed file parts.
    ///
    /// # Errors
    /// Returns [`Error::Forbidden`] on an app device or an error reading local stores.
    pub fn backup_estimate(&self) -> Result<u64, Error> {
        self.backup_credentials()?;
        self.check_active()?;
        let (ordinary, _) = self.backup_wrappers()?;
        let mut bases = Vec::new();
        for entry in ordinary {
            if let Ok(base) = self.base(entry.id) {
                bases.push(base);
            }
        }
        bases.extend(self.unlocked_backup_bases());
        bases.into_iter().try_fold(0u64, |total, base| {
            let (states, parts) = base.db()?.backup_estimate()?;
            let mut bytes = states;
            for (id, count) in parts {
                for n in 0..count {
                    if let Ok(metadata) = std::fs::metadata(base.part_file(id, n)) {
                        bytes = bytes.saturating_add(metadata.len());
                    }
                }
            }
            Ok(total.saturating_add(bytes))
        })
    }

    pub(crate) fn backup_row(&self) -> Result<crate::store::BackupRow, Error> {
        self.db().backup_row()
    }
    pub(crate) fn update_backup_progress(
        &self,
        row: &crate::store::BackupRow,
        expected_generation: i64,
        expected_location: &crate::BackupLocation,
    ) -> Result<bool, Error> {
        self.db()
            .update_backup_progress(row, expected_generation, expected_location)
    }
    pub(crate) fn backup_account_epoch(&self) -> Result<u32, Error> {
        Ok(self.verified_keys()?.newest().0)
    }

    pub(crate) fn backup_account_keys(&self) -> Result<KeyRing, Error> {
        self.device_keys()
    }

    pub(crate) fn backup_hidden_key(&self, id: BaseId) -> Option<HiddenKey> {
        self.inner
            .hidden_keys
            .lock()
            .unwrap()
            .get(&id)
            .map(HiddenKey::duplicate)
    }

    pub(crate) fn backup_wrappers(&self) -> Result<crate::store::BackupWrappers, Error> {
        let db = self.db();
        Ok((db.bases()?, db.hidden_wrappers()?))
    }
    pub(crate) fn unlocked_backup_bases(&self) -> Vec<Base> {
        self.inner
            .hidden
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }
    pub(crate) fn backup_sealed_data(
        &self,
    ) -> Result<Option<crate::backup::format::SealedData>, Error> {
        let Some((version, json)) = self.db().account_data()? else {
            return Ok(None);
        };
        if version == 0 {
            return Ok(None);
        }
        let epoch = u32::try_from(version).map_err(|_| Error::Crypto)?;
        let sealed = envelope::seal(
            &keys::account_data_key(&self.account_key()?),
            &keys::account_data_aad(&self.inner.id, epoch),
            json.as_bytes(),
        );
        Ok(Some(crate::backup::format::SealedData { version, sealed }))
    }
    pub(crate) fn backup_shared(&self) -> &Arc<Shared> {
        &self.inner.shared
    }
    pub(crate) fn backup_server(&self) -> String {
        self.inner.server.to_string()
    }

    /// Seals `data` as the version after `expected` and stores it if the
    /// server is still at `expected`.
    async fn write_data(&self, expected: u64, data: &Data) -> Result<u32, Error> {
        let version = expected.checked_add(1).ok_or(Error::Crypto)?;
        let ring = self.verified_keys()?;
        let (account_epoch, account_key) = ring.newest();
        let json = Zeroizing::new(serde_json::to_vec(data).expect("JSON map"));
        let ciphertext = envelope::seal(
            &keys::account_data_key(account_key),
            &keys::account_data_aad(&self.inner.id, data_epoch(version)?),
            &json,
        );
        self.inner
            .api
            .put_account_data(&AccountDataRequest {
                ciphertext: Bytes(ciphertext),
                expected_version: expected,
                account_epoch,
            })
            .await?;
        // This device has seen the version it sealed, whatever the reply says.
        self.pin_publics(data)?;
        self.cache(version, data, version > 1)?;
        Ok(account_epoch)
    }

    fn cache_envelope(&self, envelope: &[u8]) -> Result<(), Error> {
        self.db().set_envelope_hash(&envelope_hash(envelope))
    }

    /// Opens the server's account data and caches it, returning its version,
    /// contents and whether that version was sealed in. Data older than this
    /// device has seen is never accepted: this device's newer data is returned
    /// instead, as when the server withholds a write. Another task may have
    /// cached a write after this read left. Older-format data once a version
    /// was sealed, or data sealed as another version, is [`Error::Crypto`].
    fn accept_data(&self, sealed: Option<&AccountData>) -> Result<(u64, Data, bool), Error> {
        let Some(sealed) = sealed else {
            let data = new_data();
            self.pin_publics(&data)?;
            return self.accept_or_newer(0, data, false);
        };
        let epoch = data_epoch(sealed.version)?;
        let (seen, latched) = self.db().account_data_seen()?.unwrap_or((0, false));
        if sealed.version < seen {
            return self.newer_data(sealed.version);
        }
        // Data from before versions were sealed has epoch 1, as has version 1.
        // It's accepted only until this device has seen a later version sealed.
        let older_format = envelope::epoch(&sealed.ciphertext.0) == Some(1);
        if older_format && latched {
            return Err(Error::Crypto);
        }
        let json = Zeroizing::new(envelope::open(
            &keys::account_data_key(&self.account_key()?),
            &keys::account_data_aad(&self.inner.id, if older_format { 1 } else { epoch }),
            &sealed.ciphertext.0,
        )?);
        let data = parse_data(&json)?;
        self.pin_publics(&data)?;
        self.accept_or_newer(sealed.version, data, !older_format)
    }

    fn accept_or_newer(
        &self,
        version: u64,
        data: Data,
        versioned: bool,
    ) -> Result<(u64, Data, bool), Error> {
        if self.cache_if_newest(version, &data, versioned)? {
            Ok((version, data, versioned))
        } else {
            self.newer_data(version)
        }
    }

    /// The cached data if it's newer than `version`; anything else that the
    /// cache refused is [`Error::Crypto`].
    fn newer_data(&self, version: u64) -> Result<(u64, Data, bool), Error> {
        match self.db().account_data_versioned()? {
            Some((seen, json, versioned)) if seen > version => {
                Ok((seen, parse_data(json.as_bytes())?, versioned))
            }
            _ => Err(Error::Crypto),
        }
    }

    /// Caches opened account data; the store refuses it if it's older than
    /// what this device has already seen.
    fn cache(&self, version: u64, data: &Data, versioned: bool) -> Result<(), Error> {
        match self.cache_if_newest(version, data, versioned)? {
            true => Ok(()),
            false => Err(Error::Crypto),
        }
    }

    fn cache_if_newest(&self, version: u64, data: &Data, versioned: bool) -> Result<bool, Error> {
        let json = Zeroizing::new(serde_json::to_string(data).expect("JSON map"));
        let accepted = self.db().accept_account_data(version, &json, versioned)?;
        if accepted {
            self.backup_changed();
        }
        Ok(accepted)
    }

    fn account_key(&self) -> Result<Secret<32>, Error> {
        if self.inner.kind != DeviceKind::Full {
            return Err(Error::Forbidden);
        }
        Ok(Secret::from_slice(
            self.verified_keys()?.newest().1.expose(),
        )?)
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
        Ok(bh_crypto::kdf(self.verified_keys()?.newest().1, context, 1))
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

    pub(crate) fn move_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.inner.moves
    }

    /// Test kit only: registers an in-memory folder for this account's core.
    #[cfg(feature = "test-support")]
    pub fn test_set_document_folders(&self, folders: Arc<dyn crate::DocumentFolders>) {
        *self.inner.shared.document_folders.lock().unwrap() = Some(folders);
    }

    /// Test kit only: read the locally retained sign-in pair.
    #[cfg(feature = "test-support")]
    pub fn test_backup_credentials(&self) -> Result<Option<Credentials>, Error> {
        self.backup_credentials()
    }

    /// Test kit only: read the account key to verify an opened envelope.
    #[cfg(feature = "test-support")]
    pub fn test_account_key(&self) -> [u8; 32] {
        *self.account_key().expect("full device").expose()
    }

    /// Test kit only: change an older kit record through the normal account-data path.
    #[cfg(feature = "test-support")]
    pub async fn test_remove_kit_record(&self, salt_only: bool) -> Result<(), Error> {
        self.update_data(move |data| {
            if salt_only {
                if let Some(kit) = data.get_mut("kit").and_then(Value::as_object_mut) {
                    kit.remove("salt");
                }
            } else {
                data.remove("kit");
            }
        })
        .await
    }

    /// Test kit only: write a kit record naming `envelope` and `salt`.
    #[cfg(feature = "test-support")]
    pub async fn test_put_kit_record(
        &self,
        kit: &RecoveryKit,
        envelope: &[u8],
        salt: [u8; 16],
    ) -> Result<(), Error> {
        let (kit, hash) = (kit.clone(), envelope_hash(envelope));
        self.update_data(move |data| set_kit(data, &kit, true, &hash, &salt))
            .await
    }

    /// Test-only simulation of an old full client that never published its public key.
    #[cfg(feature = "test-support")]
    pub async fn test_forget_device_public(&self, id: DeviceId) -> Result<(), Error> {
        self.update_data(move |data| {
            if let Some(device) = data
                .get_mut("devices")
                .and_then(|v| v.get_mut(id.to_string()))
            {
                device.as_object_mut().unwrap().remove("public");
            }
        })
        .await
    }

    /// Test kit only: inspect the salt stored in the sealed kit record.
    #[cfg(feature = "test-support")]
    pub fn test_kit_record_salt(&self) -> Option<[u8; 16]> {
        let data = self.kit_data().ok()?;
        let hash = data.get("kit")?.get("envelope")?.as_str()?;
        kit_salt(&data, hash)
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

    // A released client calls HiddenKey::open, not open_any. Creating a v2
    // wrapper at account epoch one breaks that reader even without a removal.
    #[tokio::test]
    async fn a_new_epoch_one_hidden_base_opens_with_the_legacy_reader() {
        let server = LocalServer::from_env();
        let tmp = tempfile::tempdir().unwrap();
        let (account, _) = core(tmp.path())
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        let extra = "ferry lantern quartz";
        let base = account
            .create_hidden_base("Diary", Zeroizing::new(extra.into()))
            .await
            .unwrap();
        let row = account.inner.api.base_key(base.id()).await.unwrap();
        assert_eq!(row.epoch, 1);
        assert_eq!(row.account_epoch, 1);
        let ak1 = account.device_keys().unwrap();
        let legacy = HiddenKey::derive(ak1.get(1).unwrap(), extra).unwrap();
        assert!(
            legacy
                .open(account.id(), base.id(), row.epoch, &row.wrapper.0)
                .is_some(),
            "a released client must open the server's epoch-one wrapper"
        );
    }

    // Build an on-server wrapper made by a released client, including its
    // local hidden index and encrypted store, then leave the base locked.
    async fn legacy_hidden_base(account: &Account, extra: &str) -> BaseId {
        let id = BaseId::random();
        let first = account.device_keys().unwrap();
        let hidden_key = HiddenKey::derive(first.get(1).unwrap(), extra).unwrap();
        let key = BaseKey::new(Secret::<32>::random().expose()).unwrap();
        let wrapper = hidden_key.wrap(account.id(), id, 1, &key);
        account
            .inner
            .api
            .create_base(&BasesRequest {
                base_id: id,
                epoch: 1,
                wrapper: Bytes(wrapper.clone()),
                account_epoch: 1,
                data_version: account.db().account_data().unwrap().unwrap().0,
            })
            .await
            .unwrap();
        account
            .db()
            .remember_hidden(id, 1, &wrapper, &[], 1)
            .unwrap();
        let store_key = hidden::store_key(&key);
        let base = account
            .open_base_with_key(id, key, &store_key, Mode::ReadWrite)
            .unwrap();
        account
            .inner
            .hidden_keys
            .lock()
            .unwrap()
            .insert(id, hidden_key);
        base.write_info("Diary").unwrap();
        account.lock_hidden(id).await.unwrap();
        id
    }

    #[tokio::test]
    async fn an_epoch_one_legacy_hidden_base_stays_at_epoch_one_after_unlock_and_refresh() {
        let server = LocalServer::from_env();
        let tmp = tempfile::tempdir().unwrap();
        let (account, _) = core(tmp.path())
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        let extra = "ferry lantern quartz";
        let id = legacy_hidden_base(&account, extra).await;
        let before = account.inner.api.base_key(id).await.unwrap();
        account
            .unlock_hidden(Zeroizing::new(extra.into()))
            .await
            .unwrap();
        account.refresh().await.unwrap();
        // Await the work itself rather than relying on the timing of the
        // background task started by unlock or the sync reconnect event.
        account
            .rekey_hidden_once(id, watch::channel(false).1)
            .await
            .unwrap();
        account.lock_hidden(id).await.unwrap();
        let after = account.inner.api.base_key(id).await.unwrap();
        assert_eq!(after.epoch, 1, "unlock must not post a re-key");
        assert_eq!(after.account_epoch, 1);
        assert_eq!(after.wrapper.0, before.wrapper.0);
    }

    #[tokio::test]
    async fn a_legacy_hidden_base_gets_a_v2_wrapper_after_full_device_removal() {
        let server = LocalServer::from_env();
        let tmp = tempfile::tempdir().unwrap();
        let (account, kit) = core(tmp.path())
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        let extra = "ferry lantern quartz";
        let id = legacy_hidden_base(&account, extra).await;
        let ak1 = Secret::<32>::from_slice(account.device_keys().unwrap().get(1).unwrap().expose())
            .unwrap();
        let legacy = HiddenKey::derive(&ak1, extra).unwrap();
        let before = account.inner.api.base_key(id).await.unwrap();
        let old_key = legacy
            .open(account.id(), id, before.epoch, &before.wrapper.0)
            .unwrap();
        let other = tempfile::tempdir().unwrap();
        let removed = core(other.path())
            .sign_in(SignIn {
                server: server.url(),
                email: account.email(),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "fold".into(),
            })
            .await
            .unwrap()
            .with_kit(&kit.display())
            .await
            .unwrap();
        account
            .remove_device(
                removed.device_id(),
                Removal::Full {
                    password: Zeroizing::new(PASSWORD.into()),
                    lost: false,
                },
            )
            .await
            .unwrap();
        account
            .unlock_hidden(Zeroizing::new(extra.into()))
            .await
            .unwrap();
        account
            .rekey_hidden_once(id, watch::channel(false).1)
            .await
            .unwrap();
        let row = account.inner.api.base_key(id).await.unwrap();
        assert_eq!(row.epoch, 2);
        assert_eq!(row.account_epoch, 2);
        assert!(
            legacy
                .open(account.id(), id, row.epoch, &row.wrapper.0)
                .is_none()
        );
        assert!(
            legacy
                .open_any(&[&ak1], account.id(), id, row.epoch, &row.wrapper.0)
                .is_none(),
            "the old account key cannot open the post-removal wrapper"
        );
        let current = account.device_keys().unwrap();
        let (opened, used) = legacy
            .open_any(
                &[current.newest().1],
                account.id(),
                id,
                row.epoch,
                &row.wrapper.0,
            )
            .unwrap();
        assert_eq!(used, Some(0));
        assert_ne!(opened.secret().expose(), old_key.secret().expose());
    }

    #[tokio::test]
    async fn an_app_without_a_public_key_gets_a_key_error() {
        let server = LocalServer::from_env();
        let temp = tempfile::tempdir().unwrap();
        let (a, kit) = core(temp.path())
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "mac".into(),
            })
            .await
            .unwrap();
        let other = tempfile::tempdir().unwrap();
        let b = core(other.path())
            .sign_in(SignIn {
                server: server.url(),
                email: a.email(),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "fold".into(),
            })
            .await
            .unwrap()
            .with_kit(&kit.display())
            .await
            .unwrap();
        let base = a.create_base("Shared").await.unwrap();
        let app = a
            .connect_app(AppRequest {
                app_name: "reader".into(),
                app_id: None,
                bases: vec![BaseGrantRequest::Existing {
                    base: base.id(),
                    mode: Mode::ReadOnly,
                }],
                replaces: None,
            })
            .await
            .unwrap();
        let device = app.device_id;
        let app_home = tempfile::tempdir().unwrap();
        let app_core = core(app_home.path());
        let app_account = app_core.install_app(app).await.unwrap();
        app_account.refresh().await.unwrap();
        let app_base = app_account.base(base.id()).unwrap();
        a.update_data(move |data| {
            data.get_mut("apps")
                .and_then(|v| v.get_mut(device.to_string()))
                .and_then(Value::as_object_mut)
                .unwrap()
                .remove("public");
        })
        .await
        .unwrap();
        let outcome = a
            .remove_device(
                b.device_id(),
                Removal::Full {
                    password: Zeroizing::new(PASSWORD.into()),
                    lost: false,
                },
            )
            .await
            .unwrap();
        assert!(outcome.pending);
        a.wait_for_removals().await.unwrap();
        let later = base
            .create(crate::NewObject {
                ty: crate::TypeRef::new("core.note", 1),
                parent: None,
                after: None,
                fields: Map::new(),
            })
            .unwrap();
        base.flush().await.unwrap();
        assert!(matches!(
            app_account.refresh().await,
            Err(Error::Crypto | Error::NotFound)
        ));
        let _ = app_base.sync_now().await;
        assert!(
            app_base.note(later).is_err(),
            "old app key must not open later content"
        );
    }

    #[tokio::test]
    async fn forged_delivery_never_replaces_the_persisted_key_ring() {
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
        let name = format!("acct.{}.key", account.id());
        let before = account.inner.shared.secret(&name).unwrap();
        let seed = account
            .inner
            .shared
            .secret(&format!("acct.{}.kem", account.id()))
            .unwrap();
        let kem = KemKey::from_seed(&Secret::<32>::from_slice(&seed).unwrap());
        let context = DeliveryContext {
            account: account.id(),
            device: account.device_id(),
            kind: bh_proto::DeviceKind::Full,
            from_epoch: 1,
        };
        let mut forged = crate::rotation::seal_for_device(
            &kem.public(),
            &context,
            &account.account_key().unwrap(),
            &Secret::<32>::random(),
        )
        .unwrap();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            account.adopt_keys(
                2,
                &[bh_proto::DeviceKeyDelivery {
                    epoch: 2,
                    sealed: Bytes(forged),
                }]
            ),
            Err(Error::Crypto)
        );
        assert_eq!(&*account.inner.shared.secret(&name).unwrap(), &*before);
        assert_eq!(account.verified_keys().unwrap().newest().0, 1);
    }

    // Simulates an install from before public-key pins existed.
    fn clear_own_pin(account: &Account, dir: &std::path::Path) {
        let db_key = account
            .inner
            .shared
            .secrets
            .get(&format!("acct.{}.dbkey", account.id()))
            .unwrap()
            .unwrap();
        let path = dir
            .join("data/accounts")
            .join(account.id().to_string())
            .join("account.sqlite");
        let db = crate::store::open_encrypted(&path, &db_key).unwrap();
        db.execute(
            "DELETE FROM public_pins WHERE device_id = ?",
            [account.device_id().to_string()],
        )
        .unwrap();
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
    async fn every_full_device_publishes_its_public_key() {
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
        let mut pending = core(&tmp.path().join("b"))
            .sign_in(SignIn {
                server: server.url(),
                email: email.clone(),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "second".into(),
            })
            .await
            .unwrap()
            .request_approval()
            .await
            .unwrap();
        let (open, digits) =
            tokio::try_join!(a.open_request(pending.id()), pending.digits()).unwrap();
        a.approve(open, &digits).await.unwrap();
        let b = pending.wait().await.unwrap();
        let c = core(&tmp.path().join("c"))
            .sign_in(SignIn {
                server: server.url(),
                email,
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "third".into(),
            })
            .await
            .unwrap()
            .with_kit(&kit.display())
            .await
            .unwrap();
        for account in [&a, &b, &c] {
            account.refresh().await.unwrap();
        }
        a.refresh().await.unwrap();
        let data = a.cached_data().unwrap();
        let mut publics = BTreeSet::new();
        for account in [&a, &b, &c] {
            let seed = account
                .inner
                .shared
                .secrets
                .get(&format!("acct.{}.kem", account.id()))
                .unwrap()
                .unwrap();
            let expected = URL_SAFE_NO_PAD.encode(
                bh_crypto::KemKey::from_seed(&Secret::<32>::from_slice(&seed).unwrap()).public(),
            );
            assert_eq!(
                data["devices"][account.device_id().to_string()]["public"],
                expected
            );
            publics.insert(expected);
        }
        assert_eq!(publics.len(), 3);
    }

    #[tokio::test]
    async fn an_upgrade_with_no_published_key_publishes_on_its_next_refresh() {
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
        let id = account.device_id();
        assert!(
            account.cached_data().unwrap()["devices"][id.to_string()]
                .get("public")
                .is_none()
        );
        clear_own_pin(&account, tmp.path());
        account
            .inner
            .shared
            .secrets
            .delete(&format!("acct.{}.kem", account.id()))
            .unwrap();
        account.refresh().await.unwrap();
        let seed = account
            .inner
            .shared
            .secrets
            .get(&format!("acct.{}.kem", account.id()))
            .unwrap()
            .unwrap();
        let expected = URL_SAFE_NO_PAD.encode(
            bh_crypto::KemKey::from_seed(&Secret::<32>::from_slice(&seed).unwrap()).public(),
        );
        assert_eq!(
            account.cached_data().unwrap()["devices"][id.to_string()]["public"],
            expected
        );
    }

    #[tokio::test]
    async fn losing_a_published_seed_does_not_replace_its_pinned_public() {
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
        account.refresh().await.unwrap();
        let device = account.device_id();
        let original = account.cached_data().unwrap()["devices"][device.to_string()]["public"]
            .as_str()
            .unwrap()
            .to_string();
        let before = account.db().public_pin(device).unwrap().unwrap();
        account
            .inner
            .shared
            .secrets
            .delete(&format!("acct.{}.kem", account.id()))
            .unwrap();
        assert_eq!(account.refresh().await, Err(Error::Crypto));
        assert_eq!(
            account.cached_data().unwrap()["devices"][device.to_string()]["public"],
            original
        );
        // Even if someone removes the server entry, the locally pinned key cannot change.
        account
            .update_data(move |data| {
                data["devices"][device.to_string()]
                    .as_object_mut()
                    .unwrap()
                    .remove("public");
            })
            .await
            .unwrap();
        assert_eq!(account.refresh().await, Err(Error::Crypto));
        assert!(
            account
                .inner
                .shared
                .secrets
                .get(&format!("acct.{}.kem", account.id()))
                .unwrap()
                .is_none()
        );
        assert!(
            account.cached_data().unwrap()["devices"][device.to_string()]
                .get("public")
                .is_none()
        );
        assert_eq!(account.db().public_pin(device).unwrap().unwrap(), before);
        assert_eq!(URL_SAFE_NO_PAD.decode(original).unwrap(), before);
    }

    #[tokio::test]
    async fn a_mismatched_local_seed_cannot_replace_a_published_key() {
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
        account.refresh().await.unwrap();
        let device = account.device_id();
        let original =
            account.cached_data().unwrap()["devices"][device.to_string()]["public"].clone();
        account
            .inner
            .shared
            .secrets
            .put(
                &format!("acct.{}.kem", account.id()),
                Secret::<32>::random().expose(),
            )
            .unwrap();
        assert_eq!(account.refresh().await, Err(Error::Crypto));
        assert_eq!(
            account.cached_data().unwrap()["devices"][device.to_string()]["public"],
            original
        );
        assert_eq!(
            account.db().public_pin(device).unwrap().unwrap(),
            URL_SAFE_NO_PAD.decode(original.as_str().unwrap()).unwrap()
        );
    }

    #[tokio::test]
    async fn an_unpinned_device_pins_its_local_key_before_a_conflicting_remote_entry() {
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
        let id = a.device_id();
        clear_own_pin(&a, &tmp.path().join("a"));
        assert!(a.db().public_pin(id).unwrap().is_none());
        let seed = a
            .inner
            .shared
            .secrets
            .get(&format!("acct.{}.kem", a.id()))
            .unwrap()
            .unwrap();
        let actual = KemKey::from_seed(&Secret::<32>::from_slice(&seed).unwrap()).public();
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
        let false_public = URL_SAFE_NO_PAD.encode(KemKey::generate().public());
        b.update_data(move |data| {
            data["devices"][id.to_string()]["public"] = json!(false_public);
        })
        .await
        .unwrap();
        assert_eq!(a.refresh().await, Err(Error::Crypto));
        assert_eq!(a.db().public_pin(id).unwrap().unwrap(), actual);
        assert_ne!(
            a.cached_data().unwrap()["devices"][id.to_string()]["public"],
            URL_SAFE_NO_PAD.encode(actual)
        );
        b.update_data(move |data| {
            data["devices"][id.to_string()]["public"] = json!(URL_SAFE_NO_PAD.encode(actual));
        })
        .await
        .unwrap();
        a.refresh().await.unwrap();
        assert_eq!(a.db().public_pin(id).unwrap().unwrap(), actual);
        assert_eq!(
            a.cached_data().unwrap()["devices"][id.to_string()]["public"],
            URL_SAFE_NO_PAD.encode(actual)
        );
    }

    #[tokio::test]
    async fn a_device_keeps_the_first_public_key_it_saw() {
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
        b.refresh().await.unwrap();
        a.refresh().await.unwrap();
        let id = b.device_id();
        let original = a.pin_publics(&a.cached_data().unwrap()).unwrap()[&id].clone();
        let impostor = URL_SAFE_NO_PAD.encode(bh_crypto::KemKey::generate().public());
        b.update_data(move |data| {
            data["devices"][id.to_string()]["public"] = json!(impostor);
        })
        .await
        .unwrap();
        a.refresh().await.unwrap();
        assert_eq!(
            a.pin_publics(&a.cached_data().unwrap()).unwrap()[&id],
            original
        );
        let account_id = a.id();
        drop(a);
        let restarted = core(&tmp.path().join("a")).account(account_id).unwrap();
        restarted.refresh().await.unwrap();
        assert_eq!(
            restarted
                .pin_publics(&restarted.cached_data().unwrap())
                .unwrap()[&id],
            original
        );
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
        assert_eq!(
            full.cache(version - 1, &new_data(), true).unwrap_err(),
            Error::Crypto
        );
        assert_eq!(full.app_readers(granted), [device].into());
    }

    async fn signed_up(dir: &std::path::Path) -> (Account, RecoveryKit) {
        let server = LocalServer::from_env();
        core(dir)
            .sign_up(SignUp {
                server: server.url(),
                invite: invite(server),
                email: format!("{}@example.test", AccountId::random()),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "first".into(),
            })
            .await
            .unwrap()
    }

    fn set(key: &'static str) -> impl Fn(&mut Data) + Send + 'static {
        move |data| {
            data.insert(key.into(), json!(true));
        }
    }

    /// Older data is never accepted: the device keeps and returns what it has seen.
    fn assert_keeps_newer(full: &Account, sealed: Option<&AccountData>) {
        let (seen, json, _) = full.db().account_data_versioned().unwrap().unwrap();
        let (version, data, _) = full.accept_data(sealed).unwrap();
        assert_eq!(
            (version, data),
            (seen, parse_data(json.as_bytes()).unwrap())
        );
        assert_eq!(full.db().account_data_seen().unwrap().unwrap().0, seen);
    }

    #[tokio::test]
    async fn account_data_older_than_this_device_has_seen_is_not_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = signed_up(tmp.path()).await;
        full.update_data(set("first")).await.unwrap();
        let older = full.inner.api.account().await.unwrap().data.unwrap();
        full.update_data(set("second")).await.unwrap();
        assert_keeps_newer(&full, Some(&older));
        assert_keeps_newer(&full, None);
        // The same blob under a higher number doesn't open either.
        let relabelled = AccountData {
            version: older.version + 2,
            ..older
        };
        assert_eq!(
            full.accept_data(Some(&relabelled)).unwrap_err(),
            Error::Crypto
        );
    }

    #[tokio::test]
    async fn a_read_that_returns_before_a_concurrent_write_keeps_the_newer_data() {
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = signed_up(tmp.path()).await;
        full.update_data(set("baseline")).await.unwrap();
        // One task's read has its reply; another task then writes and caches.
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let reader = {
            let full = full.clone();
            let hold = Some((release.clone(), entered.clone()));
            tokio::spawn(async move { full.refresh_account_data_held(hold).await })
        };
        tokio::time::timeout(Duration::from_secs(30), entered.acquire())
            .await
            .expect("account data read never reached its hold within 30 s")
            .unwrap()
            .forget();
        full.update_data(set("newer")).await.unwrap();
        release.add_permits(1);
        reader.await.unwrap().unwrap();
        assert_eq!(full.cached_data().unwrap()["newer"], json!(true));
        // The write can also land between a read's floor check and its caching.
        let (seen, _) = full.db().account_data_seen().unwrap().unwrap();
        let (version, data, _) = full.accept_or_newer(seen - 1, new_data(), true).unwrap();
        assert_eq!((version, &data["newer"]), (seen, &json!(true)));
    }

    /// Seals `data` at `version` and stores it as the server's next version.
    async fn put_versioned(full: &Account, data: &Data, version: u64) {
        let ciphertext = envelope::seal(
            &keys::account_data_key(&full.account_key().unwrap()),
            &keys::account_data_aad(&full.inner.id, version as u32),
            &serde_json::to_vec(data).unwrap(),
        );
        full.inner
            .api
            .put_account_data(&AccountDataRequest {
                ciphertext: Bytes(ciphertext),
                expected_version: version - 1,
                account_epoch: 1,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_read_before_an_edit_raises_the_floor_even_without_a_write() {
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = signed_up(tmp.path()).await;
        full.update_data(set("baseline")).await.unwrap();
        let old = full.inner.api.account().await.unwrap().data.unwrap();
        put_versioned(&full, &full.cached_data().unwrap(), old.version + 1).await;
        full.update_data_with_envelope(|_, _| false).await.unwrap();
        assert_keeps_newer(&full, Some(&old));
    }

    #[tokio::test]
    async fn a_failed_or_lost_write_keeps_the_floor_of_the_read_before_it() {
        for lost_reply in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let (full, _) = signed_up(tmp.path()).await;
            full.update_data(set("baseline")).await.unwrap();
            let old = full.inner.api.account().await.unwrap().data.unwrap();
            put_versioned(&full, &full.cached_data().unwrap(), old.version + 1).await;
            full.test_inject_fault(crate::client::Fault {
                method: "PUT",
                path: "v1/account/data",
                lost_reply,
                times: 1,
            });
            assert!(matches!(
                full.update_data(set("edit")).await,
                Err(Error::Network(_))
            ));
            assert_keeps_newer(&full, Some(&old));
            // The floor is what the device read, never above the server.
            full.refresh_account_data().await.unwrap();
            assert_eq!(full.cached_data().unwrap().contains_key("edit"), lost_reply);
        }
    }

    #[tokio::test]
    async fn versioned_data_at_the_cached_version_closes_the_older_format_window() {
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = signed_up(tmp.path()).await;
        let legacy = full.inner.api.account().await.unwrap().data.unwrap();
        let mut data = full.cached_data().unwrap();
        let version = legacy.version + 1;
        // An older-format reply labelled `version` was cached; its rewrite failed.
        full.cache(version, &data, false).unwrap();
        data.insert("current".into(), json!(true));
        let authenticated = AccountData {
            version,
            ciphertext: Bytes(envelope::seal(
                &keys::account_data_key(&full.account_key().unwrap()),
                &keys::account_data_aad(&full.inner.id, version as u32),
                &serde_json::to_vec(&data).unwrap(),
            )),
        };
        let (_, _, versioned) = full.accept_data(Some(&authenticated)).unwrap();
        assert!(versioned);
        assert_eq!(full.cached_data().unwrap()["current"], json!(true));
        let replay = AccountData {
            version: version + 1,
            ..legacy
        };
        assert_eq!(full.accept_data(Some(&replay)).unwrap_err(), Error::Crypto);
    }

    #[tokio::test]
    async fn an_out_of_range_version_is_refused_without_touching_the_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = signed_up(tmp.path()).await;
        let legacy = full.inner.api.account().await.unwrap().data.unwrap();
        let before = full.db().account_data_seen().unwrap();
        let oversized = AccountData {
            version: u64::from(u32::MAX) + 1,
            ..legacy
        };
        assert_eq!(
            full.accept_data(Some(&oversized)).unwrap_err(),
            Error::Crypto
        );
        assert_eq!(full.db().account_data_seen().unwrap(), before);
        assert_eq!(
            full.write_data(u64::MAX, &new_data()).await.unwrap_err(),
            Error::Crypto
        );
    }

    #[tokio::test]
    async fn concurrent_edits_from_two_full_devices_both_land() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, kit) = signed_up(&tmp.path().join("a")).await;
        let b = core(&tmp.path().join("b"))
            .sign_in(SignIn {
                server: LocalServer::from_env().url(),
                email: a.email(),
                password: Zeroizing::new(PASSWORD.into()),
                device_name: "second".into(),
            })
            .await
            .unwrap()
            .with_kit(&kit.display())
            .await
            .unwrap();
        let path = "v1/account/data";
        let puts = || a.test_request_count(path) + b.test_request_count(path);
        let before = puts();
        for (x, y) in [("a1", "b1"), ("a2", "b2"), ("a3", "b3")] {
            let (ra, rb) = tokio::join!(a.update_data(set(x)), b.update_data(set(y)));
            ra.unwrap();
            rb.unwrap();
        }
        // Each round's second write lost the race and was sealed again.
        assert!(puts() - before > 6, "no version_conflict was retried");
        b.refresh_account_data().await.unwrap();
        a.refresh_account_data().await.unwrap();
        for device in [&a, &b] {
            let data = device.cached_data().unwrap();
            for key in ["a1", "b1", "a2", "b2", "a3", "b3"] {
                assert_eq!(data[key], json!(true), "{key}");
            }
        }
    }

    #[tokio::test]
    async fn older_format_account_data_is_read_once_then_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let (full, _) = signed_up(tmp.path()).await;
        let record = full.inner.api.account().await.unwrap();
        let current = record.data.map_or(0, |d| d.version);
        // An app from before this change seals every version as epoch 1.
        let mut data = full.cached_data().unwrap();
        data.insert("old".into(), json!(true));
        let legacy = envelope::seal(
            &keys::account_data_key(&full.account_key().unwrap()),
            &keys::account_data_aad(&full.inner.id, 1),
            &serde_json::to_vec(&data).unwrap(),
        );
        let put = |expected| AccountDataRequest {
            ciphertext: Bytes(legacy.clone()),
            expected_version: expected,
            account_epoch: 1,
        };
        full.inner
            .api
            .put_account_data(&put(current))
            .await
            .unwrap();

        full.refresh_account_data().await.unwrap();
        assert_eq!(full.cached_data().unwrap()["old"], json!(true));
        let rewritten = full.inner.api.account().await.unwrap().data.unwrap();
        assert_eq!(rewritten.version, current + 2);
        assert!(
            envelope::open(
                &keys::account_data_key(&full.account_key().unwrap()),
                &keys::account_data_aad(&full.inner.id, rewritten.version as u32),
                &rewritten.ciphertext.0,
            )
            .is_ok()
        );
        // Once a device has read the new format, an older-format blob is a replay.
        full.inner
            .api
            .put_account_data(&put(rewritten.version))
            .await
            .unwrap();
        assert_eq!(full.refresh_account_data().await, Err(Error::Crypto));
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
