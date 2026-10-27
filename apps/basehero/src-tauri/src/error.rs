use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct CommandError {
    pub kind: String,
    pub message: String,
}

impl CommandError {
    /// The device's key store is missing, locked, or holds another key.
    pub fn key_unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: "KeyUnavailable".into(),
            message: message.into(),
        }
    }
}

/// `kind` is the core error's variant name.
impl From<bh_core::Error> for CommandError {
    fn from(error: bh_core::Error) -> Self {
        let kind = serde_json::to_value(&error)
            .ok()
            .and_then(|value| value["kind"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "Storage".into());
        Self {
            kind,
            message: error.to_string(),
        }
    }
}
