//! The edge's pairing relay: `POST|GET /v1/pair/<name>?side=&index=`, one
//! opaque message of at most 8 KiB per request, up to four per side, kept
//! five minutes from the first. The relay never reads them; the devices
//! authenticate them with the QR secret.
use crate::transport::TransportError;
use futures_util::future::BoxFuture;
use std::{sync::Arc, time::Duration};

/// Which device a message is from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The device showing the code.
    Show,
    /// The device that scanned it.
    Join,
}
impl Side {
    fn query(self) -> &'static str {
        match self {
            Self::Show => "show",
            Self::Join => "join",
        }
    }
}

/// The relay's answer to storing a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    /// Stored, or exactly these bytes were already there.
    Stored,
    /// Other bytes hold this index, or an earlier index is free.
    Taken,
    /// The side already holds four messages.
    Full,
    /// The pairing's five minutes are over.
    Expired,
    /// The message or request was not acceptable.
    Refused,
}

/// The relay's answer to reading one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Got {
    Message(Vec<u8>),
    Empty,
    Expired,
}

pub trait Relay: Send + Sync {
    fn put(
        &self,
        name: [u8; 32],
        side: Side,
        index: u8,
        message: Vec<u8>,
    ) -> BoxFuture<'_, Result<Put, TransportError>>;
    fn get(
        &self,
        name: [u8; 32],
        side: Side,
        index: u8,
    ) -> BoxFuture<'_, Result<Got, TransportError>>;
}

/// One relay request's longest wait.
const REQUEST_WAIT: Duration = Duration::from_secs(15);
/// A message is at most this long; a larger answer is not the relay's.
const MAX_MESSAGE: usize = 8192;

/// The relay over HTTPS, with the bundled public roots (HTTP for a local
/// `http://` edge).
pub struct HttpRelay {
    base: String,
    client: Option<reqwest::Client>,
}
impl HttpRelay {
    pub fn new(edge_url: &str) -> Arc<Self> {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .ok()
        .map(|builder| {
            builder
                .with_root_certificates(bh_tls_roots::browser_roots())
                .with_no_client_auth()
        });
        let client = tls.and_then(|tls| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .timeout(REQUEST_WAIT)
                .use_preconfigured_tls(tls)
                .build()
                .ok()
        });
        Arc::new(Self {
            base: edge_url.trim_end_matches('/').to_string(),
            client,
        })
    }
    fn url(&self, name: [u8; 32], side: Side, index: u8) -> String {
        let name: String = name.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "{}/v1/pair/{name}?side={}&index={index}",
            self.base,
            side.query()
        )
    }
}
impl Relay for HttpRelay {
    fn put(
        &self,
        name: [u8; 32],
        side: Side,
        index: u8,
        message: Vec<u8>,
    ) -> BoxFuture<'_, Result<Put, TransportError>> {
        Box::pin(async move {
            let client = self.client.as_ref().ok_or(TransportError)?;
            let response = client
                .post(self.url(name, side, index))
                .body(message)
                .send()
                .await
                .map_err(|_| TransportError)?;
            Ok(match response.status().as_u16() {
                204 => Put::Stored,
                409 => Put::Taken,
                429 => Put::Full,
                410 => Put::Expired,
                400 | 413 => Put::Refused,
                _ => return Err(TransportError),
            })
        })
    }
    fn get(
        &self,
        name: [u8; 32],
        side: Side,
        index: u8,
    ) -> BoxFuture<'_, Result<Got, TransportError>> {
        Box::pin(async move {
            let client = self.client.as_ref().ok_or(TransportError)?;
            let mut response = client
                .get(self.url(name, side, index))
                .send()
                .await
                .map_err(|_| TransportError)?;
            match response.status().as_u16() {
                200 => {}
                204 => return Ok(Got::Empty),
                410 => return Ok(Got::Expired),
                _ => return Err(TransportError),
            }
            if response
                .content_length()
                .is_some_and(|len| len > MAX_MESSAGE as u64)
            {
                return Err(TransportError);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| TransportError)? {
                if bytes.len() + chunk.len() > MAX_MESSAGE {
                    return Err(TransportError);
                }
                bytes.extend_from_slice(&chunk);
            }
            if bytes.is_empty() {
                return Err(TransportError);
            }
            Ok(Got::Message(bytes))
        })
    }
}
