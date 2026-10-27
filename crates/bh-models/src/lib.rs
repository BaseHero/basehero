//! Whole, attested Tinfoil completions through a credential-holding gateway.
//! Gateway/provider diagnostics never become public error text.
mod probe;
mod request;
mod response;
#[cfg(feature = "testing")]
pub mod testing;
mod tinfoil;

use futures_util::future::BoxFuture;
pub use probe::{ProbeFailure, ProbeResult, probe};
pub use request::*;
pub use response::*;
pub use tinfoil::{Gateway, Tinfoil};

pub const TINFOIL_MODEL: &str = "deepseek-v4-1-flash";

pub trait ChatModel: Send + Sync + 'static {
    fn complete(&self, req: ChatRequest) -> BoxFuture<'_, Result<Completion, ModelError>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    InvalidGateway,
    InvalidRequest,
    Verification,
    Encryption,
    Transport,
    Unauthorized,
    Forbidden,
    RateLimited,
    TooLarge,
    NeedsUpdate,
    HttpStatus(u16),
    Response,
}
impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ModelError {}
