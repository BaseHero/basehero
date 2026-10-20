//! Native Unix host transport ONLY. Quote acquisition is not attestation:
//! caller supplies its own fresh verifier nonce and public keys, then obtains
//! collateral, trusted time, authenticated channel and offline verification.
//! Nothing in this module grants authority or signals service readiness.
#![forbid(unsafe_code)]
#![cfg(unix)]

mod time;
pub use time::{TimeError, TimeSampler};

use bh_confidential_attestation::{MAX_INPUT_BYTES, report_data};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};

/// Maximum *aggregate HTTP response body*, before JSON parsing. A verifier-sized
/// quote (1 MiB) becomes at most 2 MiB of hex; a verifier-sized UTF-8 log
/// (1 MiB) can become 6 MiB of JSON `\u00xx` escapes. 4 KiB covers JSON keys
/// and the current dstack optional public metadata. A larger real-host response
/// needs measured sizing and an explicit revision, never an unbounded read.
const MAX_RESPONSE_BYTES: usize = 8 * MAX_INPUT_BYTES + 4096;

/// No upstream status, response, socket path or evidence is exposed via errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("quote acquisition unavailable")
    }
}
impl std::error::Error for Error {}

/// Raw, unverified evidence. No measured/verified constructor or readiness bit.
#[derive(Debug)]
pub struct UnverifiedQuote {
    quote: Vec<u8>,
    event_log: Vec<u8>,
}
impl UnverifiedQuote {
    pub fn quote(&self) -> &[u8] {
        &self.quote
    }
    pub fn event_log(&self) -> &[u8] {
        &self.event_log
    }
}

/// This path comes only from trusted local host configuration, never a peer or
/// HTTP request. No default discovery, TCP fallback, proxy or redirect.
pub struct QuoteSocket {
    path: PathBuf,
}
impl QuoteSocket {
    pub fn new(trusted_path: PathBuf) -> Self {
        Self { path: trusted_path }
    }

    /// The finite caller-trusted deadline covers headers AND all body reads.
    /// `report_data` is exactly the 64 raw bytes expected by the offline verifier;
    /// dstack's raw GetQuote endpoint pads but does not SDK-hash this input.
    pub async fn get_quote(
        &self,
        signing: &[u8; 32],
        receiving: &[u8; 1216],
        verifier_nonce: &[u8; 32],
        deadline: Duration,
    ) -> Result<UnverifiedQuote, Error> {
        self.get_quote_for_report(&report_data(signing, receiving, verifier_nonce), deadline)
            .await
    }

    /// The same request for report data the caller already holds, such as a
    /// channel handshake's, which binds keys the caller cannot see.
    pub async fn get_quote_for_report(
        &self,
        report_data: &[u8; 64],
        deadline: Duration,
    ) -> Result<UnverifiedQuote, Error> {
        if deadline.is_zero() {
            return Err(Error);
        }
        // Reqwest's workspace rustls-no-provider feature otherwise panics at
        // client construction even for plain HTTP over UDS. Use a per-client
        // empty-root TLS configuration rather than a process-global provider;
        // HTTPS is never used by the fixed endpoint or redirects.
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error)?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .unix_socket(self.path.as_path())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(deadline)
            .build()
            .map_err(|_| Error)?;
        tokio::time::timeout(deadline, async {
            let request =
                serde_json::to_vec(&serde_json::json!({"report_data": hex::encode(report_data)}))
                    .map_err(|_| Error)?;
            let mut response = client
                .post("http://localhost/GetQuote")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(request)
                .send()
                .await
                .map_err(|_| Error)?;
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
            {
                return Err(Error);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| Error)? {
                if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
                    return Err(Error);
                }
                body.extend_from_slice(&chunk);
            }
            #[derive(Deserialize)]
            struct Reply {
                quote: String,
                event_log: String,
                // dstack v0 also returns optional report_data and vm_config;
                // serde ignores them, never treating them as authenticated.
            }
            let reply: Reply = serde_json::from_slice(&body).map_err(|_| Error)?;
            if reply.quote.len() > 2 * MAX_INPUT_BYTES || reply.event_log.len() > MAX_INPUT_BYTES {
                return Err(Error);
            }
            let quote = hex::decode(reply.quote).map_err(|_| Error)?;
            if quote.len() > MAX_INPUT_BYTES {
                return Err(Error);
            }
            Ok(UnverifiedQuote {
                quote,
                event_log: reply.event_log.into_bytes(),
            })
        })
        .await
        .map_err(|_| Error)?
    }
}
