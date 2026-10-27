//! Model construction at the core boundary.
use crate::{Account, Error};
use bh_models::{ChatModel, Gateway, Tinfoil};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Constructs the attested Tinfoil model through BaseHero's gateway. A self-hosted,
/// person-accepted OpenAI-compatible endpoint would be selected here later.
pub fn for_account(account: &Account) -> Result<Arc<dyn ChatModel>, Error> {
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
    Ok(Arc::new(Tinfoil::new(
        gateway,
        account.token()?,
        Zeroizing::new(hex),
        crate::client::tls_config(),
    )))
}
