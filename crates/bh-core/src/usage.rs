//! Display-ready account usage without server-readable names.
use crate::{BaseId, DeviceId};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Attributed usage for a UTC month or day, in whole micro-dollars.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct UsageRow {
    /// UTC month or day.
    pub period: String,
    /// Service, such as model or storage.
    pub service: String,
    /// Base, or none for a call without a base or an older unbroken-down day.
    #[ts(type = "string | null")]
    pub base: Option<BaseId>,
    /// Calling device, or none for an older unbroken-down day.
    #[ts(type = "string | null")]
    pub device: Option<DeviceId>,
    /// Number of calls.
    #[ts(type = "number")]
    pub requests: u64,
    /// Calls with no reported cost.
    #[ts(type = "number")]
    pub unreported: u64,
    /// Prompt tokens.
    #[ts(type = "number")]
    pub prompt_tokens: u64,
    /// Completion tokens.
    #[ts(type = "number")]
    pub completion_tokens: u64,
    /// Current stored bytes (SQLite database plus R2 objects) for storage rows; zero for model rows.
    #[ts(type = "number")]
    pub stored_bytes: u64,
    /// Provider cost in micro-dollars.
    #[ts(type = "number")]
    pub cost_micro_usd: u64,
    /// Account price in micro-dollars.
    #[ts(type = "number")]
    pub price_micro_usd: u64,
}
impl From<bh_proto::UsageRow> for UsageRow {
    fn from(row: bh_proto::UsageRow) -> Self {
        Self {
            period: row.period,
            service: row.service,
            base: row.base,
            device: row.device,
            requests: row.requests,
            unreported: row.unreported,
            prompt_tokens: row.prompt_tokens,
            completion_tokens: row.completion_tokens,
            stored_bytes: row.stored_bytes,
            cost_micro_usd: row.cost_micro_usd,
            price_micro_usd: row.price_micro_usd,
        }
    }
}
