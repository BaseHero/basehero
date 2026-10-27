//! Two tiny synthetic completions against the dev gateway; never a provider key.
use bh_models::*;
use serde_json::json;
use std::sync::Arc;
use zeroize::Zeroizing;

fn configured() -> Result<Tinfoil, ModelError> {
    let gateway =
        Gateway::new(&std::env::var("BH_LIVE_GATEWAY").map_err(|_| ModelError::InvalidGateway)?)?;
    let path = std::env::var("BH_LIVE_TOKEN_FILE").map_err(|_| ModelError::InvalidRequest)?;
    let raw =
        Zeroizing::new(std::fs::read_to_string(path).map_err(|_| ModelError::InvalidRequest)?);
    let credential = Zeroizing::new(raw.trim().to_owned());
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| ModelError::Encryption)?;
    let cache_secret = Zeroizing::new(random.iter().map(|b| format!("{b:02x}")).collect());
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ModelError::Transport)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Tinfoil::new(
        gateway,
        credential,
        cache_secret,
        Arc::new(tls),
    ))
}
fn fail(step: u8, error: ModelError) -> ! {
    println!(
        "{}",
        json!({"ok":false,"step":step,"error":format!("{error:?}")})
    );
    std::process::exit(1)
}
#[tokio::main]
async fn main() {
    let model = configured().unwrap_or_else(|e| fail(1, e));
    match probe(&model).await {
        // Only this synthetic probe reports content, locally; the library and
        // Worker never log request/response bodies or credentials.
        Ok(result) => println!("{}", json!(result)),
        Err(ProbeFailure { step, error }) => fail(step, error),
    }
}
