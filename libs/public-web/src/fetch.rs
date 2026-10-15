//! Fixed public GET transport, without ambient credentials.

/// Resource caps for one read. These are implementation bounds, not quality claims.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_redirects: usize,
    pub total_timeout_ms: u64,
    pub connect_timeout_ms: u64,
    pub max_compressed_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_output_bytes: usize,
    pub max_elements: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            total_timeout_ms: 20_000,
            connect_timeout_ms: 5_000,
            max_compressed_bytes: 4 << 20,
            max_decoded_bytes: 8 << 20,
            max_output_bytes: 256 << 10,
            max_elements: 60_000,
        }
    }
}

#[derive(Clone)]
pub struct Hop {
    pub url: String,
    pub status: u16,
}

/// Content-bearing response: keep inside the authorised job, never diagnostics.
#[derive(Clone)]
pub struct RawResponse {
    pub requested_url: String,
    pub final_url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub compressed_bytes: usize,
    pub partial: bool,
    pub partial_reason: Option<String>,
    pub hops: Vec<Hop>,
    pub elapsed_ms: u64,
}

/// Content-free diagnostic categories; never wrap dependency error messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    InvalidUrl,
    Credentials,
    NonPublic,
    NeedsOutsideEffect,
    RedirectLimit,
    Timeout,
    Network,
    UnsupportedEncoding,
    InvalidRedirect,
    TlsConfiguration,
}

pub struct Reader {
    pub(crate) lookup: std::sync::Arc<dyn crate::resolve::Lookup>,
    pub(crate) tls: rustls::ClientConfig,
    pub(crate) limits: Limits,
}

impl Reader {
    pub fn new(limits: Limits) -> Result<Self, FetchError> {
        Ok(Self {
            lookup: std::sync::Arc::new(crate::resolve::SystemLookup),
            tls: tls_config(bh_tls_roots::browser_roots())?,
            limits,
        })
    }
    /// Dropping this future cancels local I/O; it cannot recall an already sent
    /// request. A service must still check current job authority before dispatch.
    pub async fn fetch(&self, permit: &crate::ReadPermit<'_>) -> Result<RawResponse, FetchError> {
        tokio::time::timeout(
            std::time::Duration::from_millis(self.limits.total_timeout_ms),
            self.fetch_inner(permit),
        )
        .await
        .map_err(|_| FetchError::Timeout)?
    }

    async fn fetch_inner(&self, permit: &crate::ReadPermit<'_>) -> Result<RawResponse, FetchError> {
        use reqwest::header::{ACCEPT, ACCEPT_ENCODING, LOCATION};
        let start = std::time::Instant::now();
        let requested_url = permit.original.to_owned();
        let mut url = permit.url.clone();
        let mut hops = Vec::new();
        for hop in 0..=self.limits.max_redirects {
            // Literal IPs bypass DNS in HTTP stacks, so check them here too.
            url = crate::policy::check_url(url.as_str())?;
            // A fresh client prevents connection reuse across hops and therefore
            // forces rebinding checks at every connection attempt.
            let client = reqwest::Client::builder()
                .no_proxy()
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .referer(false)
                .http1_only()
                .pool_max_idle_per_host(0)
                .user_agent("BaseHeroPageReader/0.1")
                .dns_resolver(std::sync::Arc::new(crate::resolve::GuardedResolver(
                    self.lookup.clone(),
                )))
                .tls_backend_preconfigured(self.tls.clone())
                .connect_timeout(std::time::Duration::from_millis(
                    self.limits.connect_timeout_ms,
                ))
                .build()
                .map_err(|_| FetchError::TlsConfiguration)?;
            let response = client
                .get(url.clone())
                .header(
                    ACCEPT,
                    "text/markdown, text/html;q=0.9, application/xhtml+xml;q=0.9, text/plain;q=0.8",
                )
                .header(ACCEPT_ENCODING, "gzip, br")
                .send()
                .await
                .map_err(network_error)?;
            let status = response.status().as_u16();
            hops.push(Hop {
                url: url.to_string(),
                status,
            });
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if hop == self.limits.max_redirects {
                    return Err(FetchError::RedirectLimit);
                }
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(FetchError::InvalidRedirect)?;
                url = url
                    .join(location)
                    .map_err(|_| FetchError::InvalidRedirect)?;
                continue;
            }
            return self
                .read_body(response, requested_url, url.to_string(), hops, start)
                .await;
        }
        Err(FetchError::RedirectLimit)
    }

    async fn read_body(
        &self,
        mut response: reqwest::Response,
        requested_url: String,
        final_url: String,
        hops: Vec<Hop>,
        start: std::time::Instant,
    ) -> Result<RawResponse, FetchError> {
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let encoding = response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .map(|v| {
                v.to_str()
                    .map(str::trim)
                    .map(str::to_ascii_lowercase)
                    .map_err(|_| FetchError::UnsupportedEncoding)
            })
            .transpose()?
            .unwrap_or_else(|| "identity".into());
        if !matches!(
            encoding.as_str(),
            "identity" | "" | "gzip" | "x-gzip" | "br"
        ) {
            return Err(FetchError::UnsupportedEncoding);
        }
        let mut bytes = Vec::new();
        let mut partial_reason = None;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let room = self.limits.max_compressed_bytes.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..chunk.len().min(room)]);
                    if chunk.len() > room {
                        partial_reason = Some("compressed input limit".to_owned());
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    if bytes.is_empty() {
                        return Err(network_error(error));
                    }
                    partial_reason = Some("incomplete response body".to_owned());
                    break;
                }
            }
        }
        let compressed_bytes = bytes.len();
        let cap = self.limits.max_decoded_bytes;
        let (body, decode_partial) = match encoding.as_str() {
            "gzip" | "x-gzip" => bounded_decode(flate2::read::MultiGzDecoder::new(&bytes[..]), cap),
            "br" => bounded_decode(brotli::Decompressor::new(&bytes[..], 4096), cap),
            _ => {
                let over = bytes.len() > cap;
                bytes.truncate(cap);
                (bytes, over.then(|| "decoded input limit".to_owned()))
            }
        };
        let partial_reason = partial_reason.or(decode_partial);
        Ok(RawResponse {
            requested_url,
            final_url,
            status,
            content_type,
            body,
            compressed_bytes,
            partial: partial_reason.is_some(),
            partial_reason,
            hops,
            elapsed_ms: start.elapsed().as_millis() as u64,
        })
    }
}
fn network_error(error: reqwest::Error) -> FetchError {
    if error.is_timeout() {
        FetchError::Timeout
    } else {
        FetchError::Network
    }
}

fn bounded_decode(reader: impl std::io::Read, cap: usize) -> (Vec<u8>, Option<String>) {
    use std::io::Read;
    let mut out = Vec::new();
    let result = reader
        .take((cap as u64).saturating_add(1))
        .read_to_end(&mut out);
    if out.len() > cap {
        out.truncate(cap);
        (out, Some("decoded input limit".to_owned()))
    } else if result.is_err() {
        (out, Some("incomplete compressed body".to_owned()))
    } else {
        (out, None)
    }
}

pub(crate) fn tls_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig, FetchError> {
    Ok(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| FetchError::TlsConfiguration)?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}
