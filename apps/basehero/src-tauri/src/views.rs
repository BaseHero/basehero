use bh_core::{AccountEvent, AccountId};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum Platform {
    Macos,
    Android,
    Linux,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct AppInfo {
    pub version: String,
    pub server: String,
    pub platform: Platform,
}

/// Sent to every window as `bh:event`. Bases and Hero add their variants.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum AppEvent {
    Account {
        #[ts(type = "string")]
        account: AccountId,
        event: AccountEvent,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct UpdateInfo {
    pub version: String,
    pub notes: String,
}
