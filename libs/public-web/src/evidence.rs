//! Job-local retained evidence from completed public reads, not from search
//! snippets or model output. Content and addresses stay in authorised processing.
use crate::{FetchError, JobSources, Reader, extract::Verdict};

/// Code-assigned index in one collection, never a global identity or read permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceId(usize);
impl SourceId {
    pub fn index(self) -> usize {
        self.0
    }
}

/// Owned, immutable snapshot. Accessors cannot change earlier citations after a refetch.
/// Markdown remains untrusted data, not an instruction or proof of truth.
pub struct Source {
    id: SourceId,
    requested_url: String,
    final_url: String,
    title: Option<String>,
    fetched_at: String,
    verdict: Verdict,
    input_partial: bool,
    output_truncated: bool,
    markdown: String,
}
impl Source {
    pub fn id(&self) -> SourceId {
        self.id
    }
    pub fn requested_url(&self) -> &str {
        &self.requested_url
    }
    pub fn final_url(&self) -> &str {
        &self.final_url
    }
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
    pub fn fetched_at(&self) -> &str {
        &self.fetched_at
    }
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }
    pub fn input_partial(&self) -> bool {
        self.input_partial
    }
    pub fn output_truncated(&self) -> bool {
        self.output_truncated
    }
    pub fn markdown(&self) -> &str {
        &self.markdown
    }
}

/// Fixed, content-free failure categories; never log source text or addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureError {
    Capacity,
    Fetch(FetchError),
}

/// A proposed quote is valid only as an exact non-whitespace occurrence in
/// retained Markdown from a useful read in the specified collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteError {
    UnknownSource,
    EmptyQuote,
    UnusableSource,
    MissingQuote,
}

/// A borrowed excerpt, bound to the snapshot rather than model-supplied text.
/// Occurrence alone proves no semantic support, credibility, truth or completeness.
pub struct Citation<'a> {
    source: &'a Source,
    quote: &'a str,
}
impl<'a> Citation<'a> {
    pub fn source(&self) -> &'a Source {
        self.source
    }
    pub fn quote(&self) -> &'a str {
        self.quote
    }
}

/// A trusted caller selects a per-job source-count cap; Reader separately bounds
/// each page. This is not a memory budget or a durable checkpoint format.
pub struct Evidence {
    max_sources: usize,
    sources: Vec<Source>,
}
impl Evidence {
    pub fn new(max_sources: usize) -> Self {
        Self {
            max_sources,
            sources: Vec::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.sources.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
    pub fn source(&self, proposed_id: usize) -> Option<&Source> {
        self.sources.get(proposed_id)
    }

    /// The only insertion path: complete the authorised job's actual read before
    /// capturing its retained result. Capacity is checked before any I/O. A
    /// failed or cancelled read inserts nothing; partial *usable* results keep
    /// their flags. Caller checks current policy/authority/Stop before dispatch.
    pub async fn read(
        &mut self,
        job: &mut JobSources,
        reader: &Reader,
        url: &str,
        fetched_at: &str,
    ) -> Result<SourceId, CaptureError> {
        if self.sources.len() >= self.max_sources {
            return Err(CaptureError::Capacity);
        }
        let page = job
            .read(reader, url, fetched_at)
            .await
            .map_err(CaptureError::Fetch)?;
        let id = SourceId(self.sources.len());
        self.sources.push(Source {
            id,
            requested_url: page.requested_url,
            final_url: page.final_url,
            title: page.title,
            fetched_at: page.fetched_at,
            verdict: page.verdict,
            input_partial: page.input_partial,
            output_truncated: page.output_truncated,
            markdown: page.markdown,
        });
        Ok(id)
    }

    /// Model-proposed IDs are looked up only in this trusted job's collection;
    /// neither IDs nor citations admit URLs or authorize other effects. Quotes
    /// on partial/truncated useful pages remain excerpt-only with flags visible.
    pub fn validate_quote(
        &self,
        proposed_id: usize,
        proposed_quote: &str,
    ) -> Result<Citation<'_>, QuoteError> {
        let source = self.source(proposed_id).ok_or(QuoteError::UnknownSource)?;
        if proposed_quote.trim().is_empty() {
            return Err(QuoteError::EmptyQuote);
        }
        if source.verdict != Verdict::Useful {
            return Err(QuoteError::UnusableSource);
        }
        let start = source
            .markdown
            .find(proposed_quote)
            .ok_or(QuoteError::MissingQuote)?;
        Ok(Citation {
            source,
            quote: &source.markdown[start..start + proposed_quote.len()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_borrows_retained_bytes_and_errors_have_only_fixed_categories() {
        // Unit-only construction tests the validator; production insertion is read().
        let mut evidence = Evidence::new(1);
        evidence.sources.push(Source {
            id: SourceId(0),
            requested_url: "https://source.example/secret".into(),
            final_url: "https://source.example/secret".into(),
            title: None,
            fetched_at: "now".into(),
            verdict: Verdict::Useful,
            input_partial: true,
            output_truncated: true,
            markdown: "prefix exact quotation suffix".into(),
        });
        let citation = evidence.validate_quote(0, "exact quotation").unwrap();
        assert!(std::ptr::eq(
            citation.quote().as_ptr(),
            evidence
                .source(0)
                .unwrap()
                .markdown()
                .as_ptr()
                .wrapping_add(7)
        ));
        assert!(citation.source().input_partial() && citation.source().output_truncated());
        for error in [
            evidence.validate_quote(9, "secret").err().unwrap(),
            evidence.validate_quote(0, "\t").err().unwrap(),
            evidence.validate_quote(0, "secret").err().unwrap(),
        ] {
            assert!(!format!("{error:?}").contains("secret"));
        }
        let other = Evidence::new(1);
        assert_eq!(
            other
                .validate_quote(citation.source().id().index(), "exact quotation")
                .err(),
            Some(QuoteError::UnknownSource)
        );
    }
}
