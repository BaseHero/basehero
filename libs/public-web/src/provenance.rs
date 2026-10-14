//! Job-local address provenance. Registration belongs to trusted request/search
//! adapters, never model tool arguments. Pasted text is not a typed request.

use crate::FetchError;
use std::collections::HashMap;
use url::Url;

/// A permit cannot be constructed or deserialised from model output.
/// It borrows its job's source ledger and cannot outlive that ledger.
pub struct ReadPermit<'job> {
    pub(crate) url: &'job Url,
    pub(crate) original: &'job str,
}

/// Evidence for why an address is a read, not a model-authored outside effect.
/// This enum is output only: no permit API accepts a caller-supplied variant.
#[derive(Clone, PartialEq, Eq)]
pub enum UrlSource {
    TypedRequest,
    SearchResult,
    FetchedPage { url: String },
}

struct Entry {
    url: Url,
    source: UrlSource,
}

#[derive(Default)]
pub struct JobSources {
    urls: HashMap<String, Entry>,
}

impl JobSources {
    pub fn new() -> Self {
        Self::default()
    }
    /// Call only for an address from authenticated composer-typed content,
    /// never pasted quotes, base pages or a model's claim about its origin.
    pub fn register_typed_url(&mut self, url: &str) -> Result<(), FetchError> {
        self.register(url, UrlSource::TypedRequest)
    }
    /// Call only from the verified search-response adapter, not a tool argument.
    pub fn register_search_url(&mut self, url: &str) -> Result<(), FetchError> {
        self.register(url, UrlSource::SearchResult)
    }
    fn register(&mut self, raw: &str, source: UrlSource) -> Result<(), FetchError> {
        let url = crate::policy::check_url(raw)?;
        self.urls
            .entry(raw.to_owned())
            .or_insert(Entry { url, source });
        Ok(())
    }
    /// Fetch and extract in this job, then admit explicit links only if the input
    /// response is complete. Partial input adds no fetched-link provenance.
    /// There is deliberately no API accepting an arbitrary model-made
    /// Page as evidence that this job fetched it. This performs no linked reads.
    /// `fetched_at` is trusted service time, not a model-provided claim.
    pub async fn read(
        &mut self,
        reader: &crate::Reader,
        url: &str,
        fetched_at: &str,
    ) -> Result<crate::extract::Page, FetchError> {
        let raw = reader.fetch(&self.permit(url)?).await?;
        let page = crate::extract::extract(&raw, &reader.limits, fetched_at);
        for link in page.links() {
            // Invalid or private destinations never become usable permits.
            let _ = self.register(
                &link,
                UrlSource::FetchedPage {
                    url: page.final_url.clone(),
                },
            );
        }
        Ok(page)
    }
    /// Provenance is content-bearing and stays in the authorised job.
    pub fn source(&self, url: &str) -> Option<&UrlSource> {
        self.urls.get(url).map(|entry| &entry.source)
    }

    pub fn permit(&self, url: &str) -> Result<ReadPermit<'_>, FetchError> {
        self.urls
            .get_key_value(url)
            .map(|(original, entry)| ReadPermit {
                url: &entry.url,
                original,
            })
            .ok_or(FetchError::NeedsOutsideEffect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_sources_only_not_model_labels_or_normalised_variants() {
        let mut sources = JobSources::new();
        sources
            .register_typed_url("https://EXAMPLE.com/typed#section")
            .unwrap();
        sources
            .register_search_url("https://example.com/search?q=one")
            .unwrap();
        assert!(sources.permit("https://EXAMPLE.com/typed#section").is_ok());
        assert!(matches!(
            sources.source("https://EXAMPLE.com/typed#section"),
            Some(UrlSource::TypedRequest)
        ));
        assert!(matches!(
            sources.source("https://example.com/search?q=one"),
            Some(UrlSource::SearchResult)
        ));
        assert!(sources.permit("https://example.com/search?q=one").is_ok());
        for invented in [
            "https://example.com/typed",
            "https://example.com/search?q=two",
            "https://example.com/pasted",
            "https://example.com/base-note",
        ] {
            assert!(matches!(
                sources.permit(invented),
                Err(FetchError::NeedsOutsideEffect)
            ));
        }
    }

    #[test]
    fn another_jobs_sources_do_not_grant_a_read() {
        let mut first = JobSources::new();
        first
            .register_search_url("https://example.com/result")
            .unwrap();
        assert!(
            JobSources::new()
                .permit("https://example.com/result")
                .is_err()
        );
    }

    #[test]
    fn bad_sources_are_not_registered() {
        let mut sources = JobSources::new();
        for url in [
            "file:///etc/passwd",
            "http://127.0.0.1",
            "https://user:pw@example.com",
        ] {
            assert!(sources.register_search_url(url).is_err());
            assert!(sources.permit(url).is_err());
        }
    }
}
