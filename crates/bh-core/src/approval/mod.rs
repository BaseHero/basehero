//! Device approval: a signed-in device gives a new device the account key.

pub mod protocol;

use bh_proto::{ApprovalId, DeviceId};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A request's public metadata. Reading it does not answer the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct ApprovalRequest {
    #[ts(type = "string")]
    pub id: ApprovalId,
    #[ts(type = "string")]
    pub device_id: DeviceId,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub expires_at: i64,
}
