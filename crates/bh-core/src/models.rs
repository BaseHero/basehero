//! Model construction at the core boundary.
use crate::{Account, BaseId, Error};
pub use bh_models::{
    ChatModel, ChatRequest, Completion, Finish, Message, ModelError, Role, TINFOIL_MODEL, ToolCall,
    ToolChoice, ToolSpec, Usage,
};
use bh_models::{Gateway, Tinfoil};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Constructs the attested Tinfoil model through BaseHero's gateway. A self-hosted,
/// Configuration is local; completions made through this handle need the network.
///
/// # Errors
/// Returns [`Error::Invalid`] for a malformed gateway URL,
/// [`Error::Storage`] for missing local credentials, or [`Error::Crypto`] for
/// a local key failure.
pub fn for_account(account: &Account, base: Option<BaseId>) -> Result<Arc<dyn ChatModel>, Error> {
    let url = account
        .server()
        .join("v1/models/tinfoil/")
        .map_err(|_| Error::invalid("invalid gateway URL"))?;
    let gateway = Gateway::new(url.as_str()).map_err(|_| Error::invalid("invalid gateway URL"))?;
    let secret = account.derive_secret(b"bhmcache")?;
    let mut hex = String::with_capacity(64);
    for byte in secret.expose() {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").expect("write to string");
    }
    let model = Tinfoil::new(
        gateway,
        account.token()?,
        Zeroizing::new(hex),
        crate::client::tls_config(),
    );
    Ok(Arc::new(match base {
        Some(id) => model.with_base(id.to_string()),
        None => model,
    }))
}
