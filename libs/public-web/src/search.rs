//! Cloudflare Web Search API adapter. Provider output is untrusted data, never authority.
//! This client is for the trusted relay; it does not authenticate a job or expose a service.
use crate::{JobSources, fetch::tls_config};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use url::Url;

const RESPONSE_CAP: usize = 256 * 1024;
const DEADLINE: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Ceramic,
    Linkup,
}
impl Provider {
    fn name(self) -> &'static str {
        match self {
            Self::Ceramic => "ceramic",
            Self::Linkup => "linkup",
        }
    }
}

/// Fixed categories only; neither dependency errors nor response text are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchFailure {
    HttpStatus,
    Network,
    Timeout,
    Malformed,
    Oversized,
    Empty,
    Partial,
    UnsafeUrl,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchError {
    Configuration,
    InvalidQuery,
    Timeout,
    Failed {
        ceramic: SearchFailure,
        linkup: SearchFailure,
    },
}

/// Content-bearing fields must remain in the authorised job; no Debug implementation.
pub struct SearchHit {
    pub url: String,
    pub title: Option<String>,
    pub description: Option<String>,
}
pub struct SearchResults {
    provider: Provider,
    hits: Vec<SearchHit>,
}
impl SearchResults {
    pub fn provider(&self) -> Provider {
        self.provider
    }
    pub fn hits(&self) -> &[SearchHit] {
        &self.hits
    }
}

pub struct SearchClient {
    endpoint: Url,
    client: reqwest::Client,
    token: HeaderValue,
    gateway: String,
    deadline: Duration,
    attempt_deadline: Duration,
}
impl SearchClient {
    /// Configuration is supplied by the trusted relay, never a model or search result.
    /// `endpoint_base` is the API origin (normally https://api.cloudflare.com).
    pub fn new(
        endpoint_base: &str,
        account: &str,
        gateway: &str,
        token: &str,
    ) -> Result<Self, SearchError> {
        Self::build(endpoint_base, account, gateway, token, false, None)
    }

    fn build(
        endpoint_base: &str,
        account: &str,
        gateway: &str,
        token: &str,
        allow_http: bool,
        dns: Option<Arc<dyn crate::resolve::Lookup>>,
    ) -> Result<Self, SearchError> {
        let mut url = Url::parse(endpoint_base).map_err(|_| SearchError::Configuration)?;
        if !(url.scheme() == "https" || (allow_http && url.scheme() == "http"))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || !valid_id(account)
            || !valid_id(gateway)
        {
            return Err(SearchError::Configuration);
        }
        url.set_path(&format!("/client/v4/accounts/{account}/ai/websearch/"));
        if token.is_empty() {
            return Err(SearchError::Configuration);
        }
        let mut token = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| SearchError::Configuration)?;
        token.set_sensitive(true);
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert).map_err(|_| SearchError::Configuration)?;
        }
        let mut builder = reqwest::Client::builder()
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
            .connect_timeout(Duration::from_secs(5))
            .tls_backend_preconfigured(tls_config(roots).map_err(|_| SearchError::Configuration)?);
        if let Some(dns) = dns {
            builder = builder.dns_resolver(Arc::new(crate::resolve::GuardedResolver(dns)));
        }
        let client = builder.build().map_err(|_| SearchError::Configuration)?;
        Ok(Self {
            endpoint: url,
            client,
            token,
            gateway: gateway.to_owned(),
            deadline: DEADLINE,
            attempt_deadline: Duration::from_secs(9),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_client(endpoint: &str, dns: Arc<dyn crate::resolve::Lookup>) -> Self {
        Self::build(
            endpoint,
            "account",
            "default",
            "test-token",
            true,
            Some(dns),
        )
        .unwrap()
    }

    #[cfg(test)]
    pub(crate) fn test_client_timed(
        endpoint: &str,
        dns: Arc<dyn crate::resolve::Lookup>,
        deadline: Duration,
        attempt_deadline: Duration,
    ) -> Self {
        let mut client = Self::test_client(endpoint, dns);
        client.deadline = deadline;
        client.attempt_deadline = attempt_deadline;
        client
    }

    /// Each attempt includes headers and body and expires after nine seconds,
    /// leaving time for Linkup under the 20-second overall bound. No provenance is
    /// added until a complete, nonempty response has passed validation in full.
    pub async fn search(
        &self,
        query: &str,
        sources: &mut JobSources,
    ) -> Result<SearchResults, SearchError> {
        if !valid_query(query) {
            return Err(SearchError::InvalidQuery);
        }
        tokio::time::timeout(self.deadline, async {
            let (provider, hits) = match self.timed_attempt(query, Provider::Ceramic).await {
                Ok(hits) => (Provider::Ceramic, hits),
                Err(ceramic) => match self.timed_attempt(query, Provider::Linkup).await {
                    Ok(hits) => (Provider::Linkup, hits),
                    Err(linkup) => return Err(SearchError::Failed { ceramic, linkup }),
                },
            };
            for hit in &hits {
                // All have already passed the same policy check in `attempt`.
                sources
                    .register_search_url(&hit.url)
                    .map_err(|_| SearchError::Configuration)?;
            }
            Ok(SearchResults { provider, hits })
        })
        .await
        .map_err(|_| SearchError::Timeout)?
    }

    async fn timed_attempt(
        &self,
        query: &str,
        provider: Provider,
    ) -> Result<Vec<SearchHit>, SearchFailure> {
        // Timeout drops the in-flight attempt before the next provider is dispatched.
        tokio::time::timeout(self.attempt_deadline, self.attempt(query, provider))
            .await
            .map_err(|_| SearchFailure::Timeout)?
    }

    async fn attempt(
        &self,
        query: &str,
        provider: Provider,
    ) -> Result<Vec<SearchHit>, SearchFailure> {
        let body = serde_json::json!({
            "query": query, "provider": provider.name(), "limit": 10,
            "options": {"gateway": {"id": self.gateway}}
        });
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header(AUTHORIZATION, self.token.clone())
            .header("cf-aig-collect-log", "false")
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(network_failure)?;
        if !response.status().is_success() {
            return Err(SearchFailure::HttpStatus);
        }
        if response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|v| v.as_bytes() != b"identity")
        {
            return Err(SearchFailure::Malformed);
        }
        if response
            .content_length()
            .is_some_and(|n| n > RESPONSE_CAP as u64)
        {
            return Err(SearchFailure::Oversized);
        }
        let mut bytes = Vec::new();
        loop {
            let chunk = response.chunk().await.map_err(|_| SearchFailure::Partial)?;
            let Some(chunk) = chunk else { break };
            if chunk.len() > RESPONSE_CAP.saturating_sub(bytes.len()) {
                return Err(SearchFailure::Oversized);
            }
            bytes.extend_from_slice(&chunk);
        }
        let decoded: WireResponse =
            serde_json::from_slice(&bytes).map_err(|_| SearchFailure::Malformed)?;
        if decoded.items.is_empty() {
            return Err(SearchFailure::Empty);
        }
        if decoded.items.len() > 10 {
            return Err(SearchFailure::Malformed);
        }
        let mut hits = Vec::with_capacity(decoded.items.len());
        for item in decoded.items {
            crate::policy::check_url(&item.url).map_err(|_| SearchFailure::UnsafeUrl)?;
            hits.push(SearchHit {
                url: item.url,
                title: item.title,
                description: item.description,
            });
        }
        Ok(hits)
    }
}
fn valid_query(query: &str) -> bool {
    !query.is_empty() && query.chars().take(1025).count() <= 1024
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn network_failure(error: reqwest::Error) -> SearchFailure {
    if error.is_timeout() {
        SearchFailure::Timeout
    } else {
        SearchFailure::Network
    }
}
#[derive(Deserialize)]
struct WireResponse {
    items: Vec<WireHit>,
}
#[derive(Deserialize)]
struct WireHit {
    url: String,
    title: Option<String>,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn query_length_counts_unicode_scalars_not_utf8_bytes() {
        assert!(valid_query(&"界".repeat(1024)));
        assert!(!valid_query(&"界".repeat(1025)));
        assert!(!valid_query(""));
    }

    #[test]
    fn production_configuration_never_accepts_cleartext_or_path_injection() {
        for (base, account, gateway) in [
            ("http://api.cloudflare.com", "account", "default"),
            ("https://user@api.cloudflare.com", "account", "default"),
            ("https://api.cloudflare.com/prefix", "account", "default"),
            ("https://api.cloudflare.com", "../escape", "default"),
            ("https://api.cloudflare.com", "account", "bad/gateway"),
        ] {
            assert!(matches!(
                SearchClient::new(base, account, gateway, "token"),
                Err(SearchError::Configuration)
            ));
        }
    }
}
