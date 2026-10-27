//! Debug builds only: proves the app verifies Tinfoil's router and completes a
//! live call. Delete it once the chat panel gives the same proof on the emulator.
use crate::error::CommandError;
use bh_models::{Gateway, ModelError, ProbeResult, Tinfoil};
use std::sync::Arc;
use zeroize::Zeroizing;

#[tauri::command]
pub async fn dev_model_probe(gateway: String, token: String) -> Result<ProbeResult, CommandError> {
    let token = Zeroizing::new(token);
    let model = model(&gateway, token).map_err(|error| failed(1, error))?;
    bh_models::probe(&model)
        .await
        .map_err(|f| failed(f.step, f.error))
}

fn model(gateway: &str, credential: Zeroizing<String>) -> Result<Tinfoil, ModelError> {
    let gateway = Gateway::new(gateway)?;
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

fn failed(step: u8, error: ModelError) -> CommandError {
    CommandError {
        kind: "Model".into(),
        message: format!("step {step}: {error:?}"),
    }
}
