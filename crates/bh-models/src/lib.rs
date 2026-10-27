//! Whole, attested Tinfoil completions through a credential-holding gateway.
//! Gateway/provider diagnostics never become public error text.

#![warn(missing_docs)]
mod probe;
mod request;
mod response;
#[cfg(feature = "testing")]
/// Synthetic model and enclave helpers for tests.
pub mod testing;
mod tinfoil;

use futures_util::future::BoxFuture;
pub use probe::{ProbeFailure, ProbeResult, probe};
pub use request::*;
pub use response::*;
pub use tinfoil::{Gateway, Tinfoil};

/// Model name sent through the configured gateway.
pub const TINFOIL_MODEL: &str = "deepseek-v4-1-flash";

/// An asynchronous chat-completion provider. Each call returns one complete
/// response or a typed model error.
pub trait ChatModel: Send + Sync + 'static {
    /// Completes a request; a live implementation needs the network, while
    /// synthetic implementations can answer locally.
    fn complete(&self, req: ChatRequest) -> BoxFuture<'_, Result<Completion, ModelError>>;
}

/// A model configuration, request, transport or response failure; diagnostics
/// from the provider are not included in the public error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    /// Gateway URL is not accepted.
    InvalidGateway,
    /// Request cannot be encoded or exceeds its format limits.
    InvalidRequest,
    /// Hardware verification did not succeed.
    Verification,
    /// Encryption or decryption failed.
    Encryption,
    /// Network request failed.
    Transport,
    /// Credentials were rejected.
    Unauthorized,
    /// This device is not allowed to use the model.
    Forbidden,
    /// Account request limit reached.
    RateLimited,
    /// Request exceeds the service size limit.
    TooLarge,
    /// A newer client is needed.
    NeedsUpdate,
    /// Unrecognized HTTP status returned by the gateway.
    HttpStatus(u16),
    /// Model response could not be decoded.
    Response,
}
impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ModelError {}
