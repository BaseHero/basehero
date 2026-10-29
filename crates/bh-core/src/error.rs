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
    /// A request or connection failed.
    Network(String),
    /// No valid sign-in is available.
    Unauthorized,
    /// The account credentials were rejected.
    BadCredentials,
    /// The kit did not open this account.
    BadKit,
    /// This device has been removed.
    Revoked,
    /// This device has not finished activation.
    Pending,
    /// This device lacks permission for the operation.
    Forbidden,
    /// A write was attempted on a read-only base.
    ReadOnly,
    /// The requested resource was not found.
    NotFound,
    /// No hidden bases were unlocked for this operation.
    NothingUnlocked,
    /// A server-side conflict, with its stable code.
    Conflict(String),
    /// The request or local change exceeds its size limit.
    TooLarge,
    /// Account storage has reached its server-side limit.
    StorageFull,
    /// A request limit has been reached.
    RateLimited,
    /// A newer core is needed to read this data.
    NeedsUpdate,
    /// Input was invalid, with a human-readable reason.
    Invalid(String),
    /// Local storage failed, with a human-readable reason.
    Storage(String),
    /// An encrypted value could not be opened.
    Crypto,
    /// An approval exchange ended for the given reason.
    ApprovalEnded(EndReason),
}

/// Why a device approval ended. A retry is a fresh exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum EndReason {
    /// The displayed digits did not match.
    WrongDigits,
    /// The approving device declined.
    Declined,
    /// The exchange was cancelled.
    Cancelled,
    /// The exchange expired.
    Expired,
    /// The exchange was already answered elsewhere.
    AlreadyAnswered,
    /// The exchanged message could not be accepted.
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
            Self::NothingUnlocked => f.write_str("no hidden bases unlocked"),
            Self::Conflict(code) => write!(f, "conflict: {code}"),
            Self::TooLarge => f.write_str("too large"),
            Self::StorageFull => f.write_str("account storage is full"),
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
