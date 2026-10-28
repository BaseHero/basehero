//! Two tiny synthetic completions against the dev gateway; never a provider key.
//! With `--stream`, one short streamed reply, timed to its first text.
use bh_models::*;
use serde_json::json;
use std::{sync::Arc, time::Instant};
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
async fn stream(model: &Tinfoil) {
    let req = ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: Some("Count from one to twenty in words.".into()),
            tool_calls: vec![],
            tool_call_id: None,
        }],
        tools: vec![],
        tool_choice: None,
        max_tokens: 64,
    };
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let start = Instant::now();
    let first = tokio::spawn(async move {
        let first = receive
            .recv()
            .await
            .map(|_| start.elapsed().as_millis() as u64);
        let mut pieces = u64::from(first.is_some());
        while receive.recv().await.is_some() {
            pieces += 1;
        }
        (first, pieces)
    });
    let completion = model
        .complete_streaming(req, send)
        .await
        .unwrap_or_else(|e| fail(1, e));
    let total_ms = start.elapsed().as_millis() as u64;
    let (first_text_ms, pieces) = first.await.unwrap_or((None, 0));
    let usage = completion
        .usage
        .map(|u| json!({"prompt":u.prompt,"completion":u.completion}));
    let ok = completion.text.is_some();
    println!(
        "{}",
        json!({"ok":ok,"verified":true,"text":completion.text,
            "finish":format!("{:?}", completion.finish),"usage":usage,"pieces":pieces,
            "first_text_ms":first_text_ms,"total_ms":total_ms})
    );
    if !ok {
        std::process::exit(1)
    }
}
#[tokio::main]
async fn main() {
    let model = configured().unwrap_or_else(|e| fail(1, e));
    if std::env::args().skip(1).any(|a| a == "--stream") {
        return stream(&model).await;
    }
    match probe(&model).await {
        // Only this synthetic probe reports content, locally; the library and
        // Worker never log request/response bodies or credentials.
        Ok(result) => println!("{}", json!(result)),
        Err(ProbeFailure { step, error }) => fail(step, error),
    }
}
