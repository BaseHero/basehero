use crate::{AccountId, ApprovalId, BaseId, ChangeId, DeviceId, ObjectId};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;

pub const PROTOCOL: u32 = 2;

fn default_epoch() -> u32 {
    1
}

/// Opaque wire bytes, represented in JSON and TypeScript as unpadded base64url.
#[derive(Clone, Debug, Default, Eq, PartialEq, TS)]
#[ts(export, export_to = "server/src/proto/gen/", type = "string")]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

macro_rules! empty {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, TS)]
            #[serde(rename_all = "camelCase")]
            #[ts(export, export_to = "server/src/proto/gen/")]
            pub struct $name {}
        )+
    };
}

// Empty JSON bodies ({}), and typed placeholders for endpoints without a body.
empty!(
    HealthRequest,
    AdminInvitesRequest,
    ActivateResponse,
    MeRequest,
    AccountRequest,
    CredentialsResponse,
    DeleteDeviceResponse,
    BasesResponse,
    BaseKeyRequest,
    RekeyResponse,
    GrantResponse,
    DeleteGrantRequest,
    DeleteGrantResponse,
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct HealthResponse {
    pub ok: bool,
    pub protocol: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct AdminInvitesResponse {
    pub code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct KdfParams {
    pub ops_limit: u32,
    pub mem_limit_kib: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct SignupRequest {
    pub invite: String,
    pub email: String,
    pub account_id: AccountId,
    pub salt: Bytes,
    pub kdf: KdfParams,
    pub login_key: Bytes,
    pub account_key_envelope: Bytes,
    pub activation_hash: Bytes,
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct SignupResponse {
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct LoginParamsRequest {
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct LoginParamsResponse {
    pub salt: Bytes,
    pub kdf: KdfParams,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct LoginRequest {
    pub email: String,
    pub login_key: Bytes,
    pub device_id: DeviceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct LoginResponse {
    pub account_id: AccountId,
    pub token: String,
    pub account_key_envelope: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ActivateRequest {
    pub activation: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum DeviceKind {
    Full,
    App,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct DeviceKeyDelivery {
    pub epoch: u32,
    pub sealed: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct MeResponse {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub kind: DeviceKind,
    pub bases: Vec<BaseId>,
    #[serde(default = "default_epoch")]
    pub epoch: u32,
    #[serde(default)]
    pub device_keys: Vec<DeviceKeyDelivery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct AccountDevice {
    pub device_id: DeviceId,
    pub kind: DeviceKind,
    pub status: String,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub last_seen_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub cap_micro_usd: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct AccountData {
    pub ciphertext: Bytes,
    #[ts(type = "number")]
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct AccountResponse {
    pub devices: Vec<AccountDevice>,
    pub bases: Vec<BaseId>,
    pub data: Option<AccountData>,
    pub account_key_envelope: Bytes,
    #[serde(default = "default_epoch")]
    pub epoch: u32,
    #[serde(default)]
    pub device_keys: Vec<DeviceKeyDelivery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct AccountDataRequest {
    pub ciphertext: Bytes,
    #[ts(type = "number")]
    pub expected_version: u64,
    #[serde(default = "default_epoch")]
    pub account_epoch: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct AccountDataResponse {
    #[ts(type = "number")]
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct CredentialsRequest {
    pub current_login_key: Bytes,
    pub login_key: Bytes,
    pub salt: Bytes,
    pub kdf: KdfParams,
    pub account_key_envelope: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum AppDeviceKind {
    App,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct DevicesRequest {
    pub device_id: DeviceId,
    pub kind: AppDeviceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub cap_micro_usd: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct DeviceCapRequest {
    #[ts(type = "number")]
    pub cap_micro_usd: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct DevicesResponse {
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct BasesRequest {
    pub base_id: BaseId,
    pub epoch: u32,
    pub wrapper: Bytes,
    #[serde(default = "default_epoch")]
    pub account_epoch: u32,
    #[serde(default)]
    #[ts(type = "number")]
    pub data_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum GrantMode {
    #[serde(rename = "rw")]
    #[ts(rename = "rw")]
    ReadWrite,
    #[serde(rename = "ro")]
    #[ts(rename = "ro")]
    ReadOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct BaseKeyResponse {
    pub epoch: u32,
    pub wrapper: Bytes,
    pub mode: GrantMode,
    #[serde(default)]
    pub previous: Vec<PreviousKey>,
    #[serde(default = "default_epoch")]
    pub account_epoch: u32,
    #[serde(default)]
    #[ts(type = "number")]
    pub data_floor: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct PreviousKey {
    pub epoch: u32,
    pub sealed: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct RekeyRequest {
    pub from: u32,
    pub wrapper: Bytes,
    pub previous: Bytes,
    pub apps: Vec<AppWrapper>,
    #[serde(default = "default_epoch")]
    pub account_epoch: u32,
    #[serde(default)]
    #[ts(type = "number")]
    pub data_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct AppWrapper {
    pub device_id: DeviceId,
    pub wrapper: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct GrantRequest {
    pub mode: GrantMode,
    pub epoch: u32,
    pub wrapper: Bytes,
    #[serde(default = "default_epoch")]
    pub account_epoch: u32,
    #[serde(default)]
    #[ts(type = "number")]
    pub data_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum ChangeKind {
    Update,
    State,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct Change {
    pub change_id: ChangeId,
    pub object_id: ObjectId,
    pub kind: ChangeKind,
    pub body: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub covers: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub keep: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ChangesRequest {
    pub changes: Vec<Change>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ChangeResult {
    pub change_id: ChangeId,
    #[ts(type = "number | null")]
    pub seq: Option<u64>, // stale state changes have seq: null, not an omitted field
    #[ts(type = "number")]
    pub prev_head: u64,
    #[ts(type = "number")]
    pub tail: u64,
    pub stale: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ChangesResponse {
    pub results: Vec<ChangeResult>,
    #[ts(type = "number")]
    pub head: u64,
}

/// Query parameters of GET /since; the default and maximum limit are set by the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct SinceRequest {
    #[ts(type = "number")]
    pub after: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ObjectHead {
    pub object_id: ObjectId,
    #[ts(type = "number")]
    pub head: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct SinceResponse {
    #[ts(type = "number")]
    pub head: u64,
    pub objects: Vec<ObjectHead>,
    pub more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct FetchRequest {
    pub object_ids: Vec<ObjectId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct FetchState {
    #[ts(type = "number")]
    pub seq: u64,
    #[ts(type = "number")]
    pub covers: u64,
    pub device_id: DeviceId,
    pub body: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct FetchUpdate {
    #[ts(type = "number")]
    pub seq: u64,
    pub device_id: DeviceId,
    pub body: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct FetchObject {
    pub object_id: ObjectId,
    #[ts(type = "number")]
    pub head: u64,
    pub state: Option<FetchState>,
    pub updates: Vec<FetchUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct FetchResponse {
    pub objects: Vec<FetchObject>,
    pub more: Vec<ObjectId>,
}

/// Metadata for one retained state of an object; `at` is server Unix milliseconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct VersionInfo {
    #[ts(type = "number")]
    pub seq: u64,
    #[ts(type = "number")]
    pub covers: u64,
    pub device_id: DeviceId,
    #[ts(type = "number")]
    pub at: i64,
    #[ts(type = "number")]
    pub size: u64,
}

/// A newest-first page of retained object states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct VersionsResponse {
    pub versions: Vec<VersionInfo>,
    pub more: bool,
}

/// One retained object's opaque state body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct VersionResponse {
    #[ts(type = "number")]
    pub seq: u64,
    #[ts(type = "number")]
    pub covers: u64,
    pub device_id: DeviceId,
    #[ts(type = "number")]
    pub at: i64,
    pub body: Bytes,
}

/// WebSocket server messages; clients only send pings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "t", rename_all = "camelCase", rename_all_fields = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum LiveMessage {
    Epoch {
        epoch: u32,
    },
    Change {
        #[ts(type = "number")]
        seq: u64,
        object_id: ObjectId,
        #[ts(type = "number")]
        prev_head: u64,
        kind: ChangeKind,
        change_id: ChangeId,
        device_id: DeviceId,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        body: Option<Bytes>,
    },
    /// This device was removed. `notice` is the removing device's, as in
    /// [`ErrorBody::notice`]; text, so a malformed one can't break the message.
    Revoked {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        notice: Option<String>,
    },
}

/// A pending device's request for approval; `request` is the exchange's opaque message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalCreateRequest {
    pub approval_id: ApprovalId,
    pub request: Bytes,
}

/// A new app's anonymous request, routed by the account email.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ConnectCreateRequest {
    pub email: String,
    pub approval_id: ApprovalId,
    pub device_id: DeviceId,
    pub secret_hash: Bytes,
    pub request: Bytes,
}

/// Server times, for display only: each device times the exchange itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalCreateResponse {
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalListItem {
    pub approval_id: ApprovalId,
    pub kind: ApprovalKind,
    pub device_id: DeviceId,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub expires_at: i64,
    pub request: Bytes,
}

/// The account's unanswered, unexpired requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalListResponse {
    pub approvals: Vec<ApprovalListItem>,
}

/// The exchange type; app requests never become pending-device approvals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum ApprovalKind {
    Device,
    App,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum ApprovalState {
    Requested,
    Responded,
    Revealed,
    Transferred,
    Ended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum ApprovalEndReason {
    Declined,
    Cancelled,
    WrongDigits,
    Failed,
    Expired,
}

/// An approval's state and the messages sent so far.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalStateResponse {
    pub state: ApprovalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub response: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub reveal: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub transfer: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub end_reason: Option<ApprovalEndReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalRespondRequest {
    pub response: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalRevealRequest {
    pub reveal: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalTransferRequest {
    pub transfer: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ApprovalEndRequest {
    pub reason: ApprovalEndReason,
}

/// The app's opaque reveal message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ConnectRevealRequest {
    pub reveal: Bytes,
}

/// The app's reason for ending the exchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ConnectEndRequest {
    pub reason: ApprovalEndReason,
}

/// Messages on `/v1/approvals/live`; clients only send pings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "t", rename_all = "camelCase", rename_all_fields = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub enum ApprovalLiveMessage {
    Approval {
        approval_id: ApprovalId,
        kind: ApprovalKind,
        state: ApprovalState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        end_reason: Option<ApprovalEndReason>,
    },
}

/// One day or month of attributed usage; absent IDs are unassigned or legacy calls.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct UsageRow {
    pub period: String,
    pub service: String,
    pub base: Option<BaseId>,
    pub device: Option<DeviceId>,
    #[ts(type = "number")]
    pub requests: u64,
    #[ts(type = "number")]
    pub unreported: u64,
    #[ts(type = "number")]
    pub prompt_tokens: u64,
    #[ts(type = "number")]
    pub completion_tokens: u64,
    #[ts(type = "number")]
    pub stored_bytes: u64,
    #[ts(type = "number")]
    pub cost_micro_usd: u64,
    #[ts(type = "number")]
    pub price_micro_usd: u64,
}

/// Account usage by month and the selected month's UTC days.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct UsageResponse {
    pub months: Vec<UsageRow>,
    pub days: Vec<UsageRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
    /// With `revoked`: the removal notice the removing device sent, if any. Kept as
    /// text so a malformed notice can't change how the error is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub notice: Option<String>,
}

/// `DELETE /v1/devices/{id}`. `notice` is
/// `generichash(key = kdf(K, "bhremov1", 1), accountId ‖ deviceId)`, where K is the
/// removed device's own key: the account key for a full device, its app key for an
/// app. Older clients send no body.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct DeleteDeviceRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub notice: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub data: Option<AccountDataRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rotation: Option<RotationRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct RotationRequest {
    pub epoch: u32,
    pub login_key: Bytes,
    pub account_key_envelope: Bytes,
    pub activation_hash: Bytes,
    pub device_keys: Vec<DeviceKeyEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "server/src/proto/gen/")]
pub struct DeviceKeyEntry {
    pub device_id: DeviceId,
    pub sealed: Bytes,
}
