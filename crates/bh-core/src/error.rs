use serde::{Deserialize, Serialize};
use std::fmt;
use ts_rs::TS;

/// Errors from the core. Messages never contain secrets, content or names.
/// `Conflict` holds the server's error code: `email_taken`, `invite_used`,
/// `exists` or `version_conflict`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", content = "message")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum Error {
    Network(String),
    Unauthorized,
    BadCredentials,
    BadKit,
    Revoked,
    Pending,
    Forbidden,
    ReadOnly,
    NotFound,
    Conflict(String),
    TooLarge,
    RateLimited,
    NeedsUpdate,
    Invalid(String),
    Storage(String),
    Crypto,
    ApprovalEnded(EndReason),
}

/// Why a device approval ended. A retry is a fresh exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum EndReason {
    WrongDigits,
    Declined,
    Cancelled,
    Expired,
    AlreadyAnswered,
    BadMessage,
}

impl Error {
    pub(crate) fn invalid(message: &str) -> Self {
        Self::Invalid(message.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(m) => write!(f, "network error: {m}"),
            Self::Unauthorized => f.write_str("not signed in"),
            Self::BadCredentials => f.write_str("email or password is wrong"),
            Self::BadKit => f.write_str("the recovery kit doesn't match this account"),
            Self::Revoked => f.write_str("this device was removed"),
            Self::Pending => f.write_str("this device is not activated yet"),
            Self::Forbidden => f.write_str("not allowed"),
            Self::ReadOnly => f.write_str("read only"),
            Self::NotFound => f.write_str("not found"),
            Self::Conflict(code) => write!(f, "conflict: {code}"),
            Self::TooLarge => f.write_str("too large"),
            Self::RateLimited => f.write_str("too many attempts"),
            Self::NeedsUpdate => f.write_str("a newer version of BaseHero is needed"),
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::Storage(m) => write!(f, "storage error: {m}"),
            Self::Crypto => f.write_str("decryption failed"),
            Self::ApprovalEnded(reason) => f.write_str(match reason {
                EndReason::WrongDigits => "approval ended: the digits didn't match",
                EndReason::Declined => "approval ended: declined",
                EndReason::Cancelled => "approval ended: cancelled",
                EndReason::Expired => "approval ended: expired",
                EndReason::AlreadyAnswered => "approval ended: another device is answering",
                EndReason::BadMessage => "approval ended: the exchange failed",
            }),
        }
    }
}

impl std::error::Error for Error {}

impl From<bh_crypto::Error> for Error {
    fn from(_: bh_crypto::Error) -> Self {
        Self::Crypto
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Storage(e.to_string())
    }
}
