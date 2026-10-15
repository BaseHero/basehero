//! Anonymous public fetch; signed bytes are still installed by the file owner.
use basehero_models::provider_policy::MAX_ENVELOPE_BYTES;
use futures_util::StreamExt;
use reqwest::{Client, StatusCode, redirect};
use rustls::{ClientConfig, RootCertStore};
use std::{sync::Arc, time::Duration};
use url::Url;

#[derive(Debug)]
pub enum FetchError {
    Configuration,
    Network(reqwest::Error),
    TooLarge,
    Status(StatusCode),
}
impl From<reqwest::Error> for FetchError {
    fn from(error: reqwest::Error) -> Self {
        Self::Network(error)
    }
}

pub struct Transport {
    client: Client,
    url: Url,
}
fn default_roots() -> RootCertStore {
    bh_tls_roots::browser_roots()
}
impl Transport {
    /// Only pass a release-shipped endpoint, never a provider response or account setting.
    /// Browser roots work without platform certificate-folder access on phones.
    pub fn new(url: Url) -> Result<Self, FetchError> {
        Self::with_roots(url, default_roots())
    }
    fn with_roots(url: Url, roots: RootCertStore) -> Result<Self, FetchError> {
        if url.scheme() != "https"
            || !url.has_host()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(FetchError::Configuration);
        }
        let tls = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| FetchError::Configuration)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .retry(reqwest::retry::never())
            .https_only(true)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(60))
            .use_preconfigured_tls(tls)
            .build()?;
        Ok(Self { client, url })
    }
    /// Network happens before entering the short installer gate.
    pub async fn fetch(&self) -> Result<Vec<u8>, FetchError> {
        let response = self.client.get(self.url.clone()).send().await?;
        if response.status() != StatusCode::OK {
            return Err(FetchError::Status(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_ENVELOPE_BYTES as u64)
        {
            return Err(FetchError::TooLarge);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if chunk.len() > MAX_ENVELOPE_BYTES - bytes.len() {
                return Err(FetchError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{signed, time, trust};
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn default_fetch_roots_match_browser_trust() {
        let roots = super::default_roots();
        assert_eq!(roots.roots, bh_tls_roots::browser_roots().roots);
    }

    #[tokio::test]
    async fn anonymous_bounded_https_fetch_rejects_streamed_oversize_and_redirect() {
        let _guard = crate::tests::IO_TEST_LOCK.lock().await;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "https://localhost:{}/policy",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let v11 = signed("near", 11);
        let response = v11.clone();
        let server = tokio::spawn(async move {
            for n in 0..3 {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let mut buf = [0; 4096];
                let count = socket.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..count]).to_lowercase();
                assert!(request.starts_with("get /policy http/1.1"));
                assert!(!request.contains("authorization:"));
                assert!(!request.contains("cookie:"));
                assert!(!request.contains("x-device"));
                assert!(!request.contains("?"));
                let oversized = vec![0u8; MAX_ENVELOPE_BYTES + 1];
                let header = match n {
                    0 => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()),
                    1 => "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_owned(),
                    _ => "HTTP/1.1 302 Found\r\nLocation: https://localhost/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                };
                socket.write_all(header.as_bytes()).await.unwrap();
                let body = if n == 0 {
                    response.as_slice()
                } else if n == 1 {
                    oversized.as_slice()
                } else {
                    &[]
                };
                let _ = socket.write_all(body).await;
            }
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let transport = Transport::with_roots(url, roots).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut owner =
            crate::Owner::open(dir.path(), &trust("near"), &signed("near", 10), time()).unwrap();
        let bytes = transport.fetch().await.unwrap();
        assert!(matches!(
            owner.install(&bytes, time()).unwrap(),
            crate::Change::Installed { .. }
        ));
        assert_eq!(owner.snapshot().unwrap().version(), 11);
        assert!(matches!(transport.fetch().await, Err(FetchError::TooLarge)));
        assert!(matches!(
            transport.fetch().await,
            Err(FetchError::Status(StatusCode::FOUND))
        ));
        server.await.unwrap();
    }
}
