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
#[cfg(test)]
mod tests {
    use super::CommandError;

    #[test]
    fn known_conflicts_keep_their_codes_without_server_free_text() {
        for (code, expected) in [
            ("invite_used", "invite_used: Invite already used"),
            ("email_taken", "email_taken: Email already in use"),
            ("exists", "exists: Already exists"),
            ("version_conflict", "version_conflict: Version conflict"),
        ] {
            let mapped = CommandError::from(bh_core::Error::Conflict(code.into()));
            assert_eq!(mapped.kind, "Conflict");
            assert_eq!(mapped.message, expected);
            assert_eq!(serde_json::to_value(&mapped).unwrap()["message"], expected);
        }
    }

    #[test]
    fn server_and_network_errors_cannot_echo_arbitrary_text() {
        let marker = "SENSITIVE_SERVER_TEXT";
        for error in [
            bh_core::Error::Invalid(marker.into()),
            bh_core::Error::Conflict(marker.into()),
            bh_core::Error::Network(marker.into()),
        ] {
            let expected_kind = serde_json::to_value(&error).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned();
            let mapped = CommandError::from(error);
            assert_eq!(mapped.kind, expected_kind);
            assert!(!mapped.message.contains(marker));
            assert!(!serde_json::to_string(&mapped).unwrap().contains(marker));
        }
        assert_eq!(
            CommandError::from(bh_core::Error::Storage("disk full".into())).message,
            "storage error: disk full"
        );
    }
}

impl From<bh_core::Error> for CommandError {
    fn from(error: bh_core::Error) -> Self {
        let kind = serde_json::to_value(&error)
            .ok()
            .and_then(|value| value["kind"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "Storage".into());
        let message = match &error {
            bh_core::Error::Network(_) => "Network request failed".into(),
            bh_core::Error::Invalid(_) => "Invalid request".into(),
            bh_core::Error::ApprovalEnded(reason) => match reason {
                bh_core::EndReason::WrongDigits => "WrongDigits",
                bh_core::EndReason::Declined => "Declined",
                bh_core::EndReason::Cancelled => "Cancelled",
                bh_core::EndReason::Expired => "Expired",
                bh_core::EndReason::AlreadyAnswered => "AlreadyAnswered",
                bh_core::EndReason::BadMessage => "BadMessage",
            }
            .into(),
            bh_core::Error::Conflict(code) => match code.as_str() {
                "email_taken" => "email_taken: Email already in use",
                "invite_used" => "invite_used: Invite already used",
                "exists" => "exists: Already exists",
                "version_conflict" => "version_conflict: Version conflict",
                _ => "Conflict",
            }
            .into(),
            _ => error.to_string(),
        };
        Self { kind, message }
    }
}
