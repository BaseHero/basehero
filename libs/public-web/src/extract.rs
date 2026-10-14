//! Bounded extraction of untrusted public-page content. Does no I/O.
//! Consumers must disable dependency logging at their service entry point.

use std::collections::HashSet;

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use url::Url;

use crate::fetch::{Hop, Limits, RawResponse};

/// The supported dialect is CommonMark plus tables, including converter output.
/// Consumers must use this parser for rendering too: enabling other extensions
/// can reinterpret code spans and expose syntax that was inert in this dialect.
/// Keep sanitization, truncation and provenance on this same grammar.
pub fn markdown_parser(markdown: &str) -> Parser<'_> {
    Parser::new_ext(markdown, Options::ENABLE_TABLES)
}

/// Content heuristics, not a guarantee that a successful response is useful.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Useful,
    Login,
    Challenge,
    JsShell,
    Unusable,
    Unsupported,
    HttpError,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    NativeMarkdown,
    PlainText,
    Readability,
    FullPage,
    None,
}

/// Content-bearing result; keep inside the authorised job, never diagnostics.
/// The Markdown is inert but remains untrusted evidence, not instructions.
#[derive(Clone)]
pub struct Page {
    pub requested_url: String,
    pub final_url: String,
    pub hops: Vec<Hop>,
    pub status: u16,
    pub content_type: Option<String>,
    pub title: Option<String>,
    pub fetched_at: String,
    pub verdict: Verdict,
    pub method: Method,
    pub input_partial: bool,
    pub output_truncated: bool,
    pub markdown: String,
}

impl Page {
    /// Explicit HTTP(S) link destinations in retained Markdown, in source order,
    /// deduplicated and resolved against the final URL. No text scanning, HTML
    /// base URL, script instruction, image loading or network access occurs here.
    /// Partial input yields no links: an interrupted/capped reference definition
    /// may look complete while omitting a security-relevant path or query suffix.
    /// This is provenance evidence, not permission to bypass connection policy.
    pub fn links(&self) -> Vec<String> {
        if self.input_partial {
            return Vec::new();
        }
        let mut seen = HashSet::new();
        markdown_parser(&self.markdown)
            .filter_map(|event| match event {
                Event::Start(Tag::Link { dest_url, .. }) => http_url(&dest_url, &self.final_url),
                _ => None,
            })
            .filter(|url| seen.insert(url.clone()))
            .collect()
    }
}

fn mime(ct: &Option<String>) -> String {
    ct.as_deref()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn charset(ct: &Option<String>, body: &[u8], html: bool) -> &'static encoding_rs::Encoding {
    let header = ct.as_deref().and_then(|ct| {
        ct.split(';').skip(1).find_map(|param| {
            let (name, value) = param.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("charset")
                .then(|| value.trim().trim_matches(['"', '\'']).to_string())
        })
    });
    let sniff = || {
        if !html {
            return None;
        }
        let head = String::from_utf8_lossy(&body[..body.len().min(2048)]).to_ascii_lowercase();
        let i = head.find("charset=")?;
        let rest = head[i + 8..].trim_start_matches(['"', '\'']);
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(rest.len());
        Some(rest[..end].to_string())
    };
    header
        .or_else(sniff)
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8)
}

fn words(s: &str) -> usize {
    s.split_whitespace()
        .filter(|w| w.chars().any(char::is_alphanumeric))
        .count()
}

fn headings(md: &str) -> usize {
    markdown_parser(md)
        .filter(|e| matches!(e, Event::Start(Tag::Heading { .. })))
        .count()
}

// Bound tokenizer buffering and source element count before constructing a DOM.
// Implied/reconstructed HTML5 elements are checked again after serialization.
const PREFLIGHT_MEMORY_BYTES: usize = 1 << 20;

fn preflight(html: &str, limits: &Limits) -> Result<(), Verdict> {
    if html.len() > limits.max_decoded_bytes {
        return Err(Verdict::ResourceLimit);
    }
    let mut elements = 0usize;
    let mut parser = lol_html::HtmlRewriter::new(
        lol_html::Settings {
            element_content_handlers: vec![lol_html::element!("*", |_| {
                if elements == limits.max_elements {
                    return Err("element limit".into());
                }
                elements += 1;
                Ok(())
            })],
            memory_settings: lol_html::MemorySettings {
                preallocated_parsing_buffer_size: 1024,
                max_allowed_memory_usage: PREFLIGHT_MEMORY_BYTES,
            },
            ..Default::default()
        },
        |_: &[u8]| {},
    );
    let result = (|| {
        for chunk in html.as_bytes().chunks(4096) {
            parser.write(chunk)?;
        }
        parser.end()
    })();
    result.map_err(|e| match e {
        lol_html::errors::RewritingError::MemoryLimitExceeded(_)
        | lol_html::errors::RewritingError::ContentHandlerError(_) => Verdict::ResourceLimit,
        _ => Verdict::Unusable,
    })
}

/// Remove entire active subtrees, not just tags whose text a converter may keep.
fn inert_html(html: &str) -> String {
    let doc = dom_query::Document::from(html);
    doc.select("script, style, noscript, template, iframe, object, embed, svg, math, canvas, form, link, meta, base, video, audio, source")
        .remove();
    doc.html().to_string()
}

fn convert(html: &str, limits: &Limits) -> Result<String, Verdict> {
    preflight(html, limits)?;
    let html = inert_html(html);
    preflight(&html, limits)?;
    let mut opts = html_to_markdown_rs::ConversionOptions {
        extract_metadata: false,
        ..Default::default()
    };
    // The fallback must actually include the whole page; a converter's second
    // navigation/sidebar filter would hide the losses we compare to Readability.
    opts.preprocessing.remove_navigation = false;
    // Never return or log dependency errors, which can contain source material.
    html_to_markdown_rs::convert(&html, opts)
        .map(|r| r.content.unwrap_or_default())
        .map_err(|_| Verdict::Unusable)
}

fn http_url(destination: &str, base: &str) -> Option<String> {
    // Reject rather than silently remove controls in a purported address.
    if destination.chars().any(char::is_control) {
        return None;
    }
    let url = Url::parse(destination)
        .or_else(|_| Url::parse(base)?.join(destination))
        .ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.to_string())
}

/// Entity-encoded punctuation cannot introduce Markdown or HTML syntax. Use for
/// labels and raw HTML blocks (whose contents were not parsed as Markdown).
fn literal(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_punctuation() {
            use std::fmt::Write;
            let _ = write!(out, "&#{};", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn destination_syntax(url: &str) -> String {
    url.replace('&', "&amp;")
        .replace('<', "%3C")
        .replace('>', "%3E")
        .replace('\\', "%5C")
        .replace('"', "%22")
}

/// CommonMark source ranges preserve code exactly. Rebuild complete links and
/// images with flat literal labels: nested inline images must not survive inside
/// a clickable label. Unsafe destinations retain only the visible label.
fn neutralise(md: &str, base: &str) -> String {
    let mut out = String::with_capacity(md.len());
    let mut cursor = 0;
    let mut events = markdown_parser(md).into_offset_iter();
    while let Some((event, range)) = events.next() {
        let image = matches!(&event, Event::Start(Tag::Image { .. }));
        let replacement = match event {
            Event::Html(_) | Event::InlineHtml(_) => literal(&md[range.clone()]),
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                let mut label = String::new();
                let mut depth = 1;
                for (child, _) in events.by_ref() {
                    match child {
                        Event::Start(Tag::Link { .. } | Tag::Image { .. }) => depth += 1,
                        Event::End(TagEnd::Link | TagEnd::Image) => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        Event::Text(s) | Event::Code(s) | Event::Html(s) | Event::InlineHtml(s) => {
                            label.push_str(&s)
                        }
                        Event::SoftBreak | Event::HardBreak => label.push(' '),
                        _ => {}
                    }
                }
                // A literal label cannot break out of the link, even if source
                // HTML conversion supplied brackets, backticks or line breaks.
                let label = literal(&label.replace(['\n', '\r'], " "));
                let label = if image {
                    format!("Image: {label}")
                } else {
                    label
                };
                match http_url(&dest_url, base) {
                    Some(url) => format!("[{label}](<{}>)", destination_syntax(&url)),
                    None => label,
                }
            }
            _ => continue,
        };
        out.push_str(&md[cursor..range.start]);
        out.push_str(&replacement);
        cursor = range.end;
    }
    out.push_str(&md[cursor..]);
    out
}

fn plain_text(text: &str) -> String {
    // A delimiter longer than any run in the source preserves every backtick.
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest.saturating_add(1).max(3));
    let newline = if text.ends_with('\n') { "" } else { "\n" };
    format!("{fence}text\n{text}{newline}{fence}\n")
}

fn truncate_output(md: String, max: usize) -> (String, bool) {
    if md.len() <= max {
        return (md, false);
    }
    let mut cut = max;
    while !md.is_char_boundary(cut) {
        cut -= 1;
    }
    // A partial code span could expose its HTML. A partial link could turn into
    // a different URL and incorrectly grant provenance. Drop either as a unit.
    // Fenced code safely ends at EOF, so its source can be truncated directly.
    let mut links = HashSet::new();
    for (event, range) in markdown_parser(&md).into_offset_iter() {
        if matches!(event, Event::Code(_) | Event::Start(Tag::Link { .. }))
            && range.start < cut
            && cut < range.end
        {
            cut = range.start;
        }
        if let Event::Start(Tag::Link { dest_url, .. }) = event {
            links.insert(dest_url.to_string());
        }
    }
    let prefix = &md[..cut];
    // EOF can reclassify otherwise hidden reference definitions (including
    // duplicates) as text/HTML. Validate the new parse, not just source ranges.
    // On that rare boundary, return literal source instead of active syntax or
    // a newly invented link. Literal punctuation stays safe at every byte cut.
    let changed = markdown_parser(prefix).any(|event| match event {
        Event::Html(_) | Event::InlineHtml(_) | Event::Start(Tag::Image { .. }) => true,
        Event::Start(Tag::Link { dest_url, .. }) => !links.contains(dest_url.as_ref()),
        _ => false,
    });
    if changed {
        let mut escaped = literal(prefix);
        let mut end = max.min(escaped.len());
        while !escaped.is_char_boundary(end) {
            end -= 1;
        }
        escaped.truncate(end);
        (escaped, true)
    } else {
        (prefix.to_string(), true)
    }
}

const CHALLENGE_MARKERS: &[&str] = &[
    "cf-chl",
    "challenge-platform",
    "just a moment...",
    "captcha",
    "verify you are human",
    "are you a robot",
    "access denied",
    "enable javascript and cookies to continue",
    "unusual traffic",
];

fn classify_html(lower: &str, password: bool, title: &str, count: usize) -> Verdict {
    let title = title.to_lowercase();
    let login_title = ["sign in", "log in", "login", "sign-in", "anmelden"]
        .iter()
        .any(|t| title.contains(t));
    if password && (count < 400 || login_title) {
        return Verdict::Login;
    }
    if count < 400 && CHALLENGE_MARKERS.iter().any(|m| lower.contains(m)) {
        return Verdict::Challenge;
    }
    let js_hint = [
        "enable javascript",
        "requires javascript",
        "javascript is disabled",
        "javascript is not available",
        "id=\"root\"",
        "id=\"app\"",
        "id=\"__next\"",
        "id='root'",
        "id='app'",
        "id='__next'",
    ]
    .iter()
    .any(|s| lower.contains(s));
    if (count < 60 && js_hint) || (count < 20 && lower.matches("<script").count() >= 2) {
        return Verdict::JsShell;
    }
    useful(count)
}

fn useful(count: usize) -> Verdict {
    if count >= 20 {
        Verdict::Useful
    } else {
        Verdict::Unusable
    }
}

/// Extract one already-fetched response. Resource failure never falls back to an
/// unbounded conversion; partial input and truncated output are independent.
pub fn extract(raw: &RawResponse, limits: &Limits, fetched_at: &str) -> Page {
    let mut title = None;
    let result = (|| -> Result<(Method, String, Verdict), Verdict> {
        // Check bytes before decoding, then UTF-8 expansion before any DOM.
        if raw.body.len() > limits.max_decoded_bytes {
            return Err(Verdict::ResourceLimit);
        }
        let kind = mime(&raw.content_type);
        let html = matches!(kind.as_str(), "text/html" | "application/xhtml+xml" | "");
        let enc = charset(&raw.content_type, &raw.body, html);
        let (text, _, _) = enc.decode(&raw.body);
        if text.len() > limits.max_decoded_bytes {
            return Err(Verdict::ResourceLimit);
        }
        if !(200..300).contains(&raw.status) {
            let lower = text.to_lowercase();
            return Err(if CHALLENGE_MARKERS.iter().any(|m| lower.contains(m)) {
                Verdict::Challenge
            } else {
                Verdict::HttpError
            });
        }
        if matches!(kind.as_str(), "text/markdown" | "text/x-markdown") {
            let verdict = useful(words(&text));
            return Ok((Method::NativeMarkdown, text.into_owned(), verdict));
        }
        if kind == "text/plain" {
            return Ok((Method::PlainText, plain_text(&text), useful(words(&text))));
        }
        if !html {
            return Err(Verdict::Unsupported);
        }
        preflight(&text, limits)?;
        let doc = dom_query::Document::from(text.as_ref());
        let title_text = doc.select("title").text().trim().to_string();
        title = (!title_text.is_empty()).then_some(title_text);
        let password = doc.select("input[type=password i]").length() > 0;
        drop(doc);
        // Neither Readability nor the fallback may consume base-href instructions
        // or text of scripts, forms and other active subtrees.
        let clean = inert_html(&text);
        preflight(&clean, limits)?;
        let cfg = dom_smoothie::Config {
            max_elements_to_parse: limits.max_elements,
            ..Default::default()
        };
        let article =
            match dom_smoothie::Readability::new(clean.as_str(), Some(&raw.final_url), Some(cfg))
                .and_then(|mut reader| reader.parse())
            {
                Ok(article) => Some(article),
                Err(dom_smoothie::ReadabilityError::TooManyElements(_, _)) => {
                    return Err(Verdict::ResourceLimit);
                }
                Err(_) => None,
            };
        let full = convert(&clean, limits)?;
        let fw = words(&full);
        let (method, md) = match article {
            Some(article) => {
                if !article.title.trim().is_empty() {
                    title = Some(article.title.trim().to_string());
                }
                let md = convert(&article.content, limits)?;
                let aw = words(&md);
                let (ah, fh) = (headings(&md), headings(&full));
                if (aw * 10 < fw * 3 && fw >= 60) || (fh >= 6 && ah * 3 < fh) {
                    (Method::FullPage, full)
                } else if md.trim_start().starts_with('#') || title.is_none() {
                    (Method::Readability, md)
                } else {
                    // Titles are text, never Markdown instructions.
                    (
                        Method::Readability,
                        format!("# {}\n\n{md}", literal(title.as_deref().unwrap_or(""))),
                    )
                }
            }
            None => (Method::FullPage, full),
        };
        let verdict = classify_html(
            &text.to_lowercase(),
            password,
            title.as_deref().unwrap_or(""),
            words(&md),
        );
        Ok((method, md, verdict))
    })();
    let (method, md, verdict) = result.unwrap_or_else(|verdict| {
        title = None;
        (Method::None, String::new(), verdict)
    });
    let (markdown, output_truncated) =
        truncate_output(neutralise(&md, &raw.final_url), limits.max_output_bytes);
    Page {
        requested_url: raw.requested_url.clone(),
        final_url: raw.final_url.clone(),
        hops: raw.hops.clone(),
        status: raw.status,
        content_type: raw.content_type.clone(),
        title,
        fetched_at: fetched_at.to_string(),
        verdict,
        method,
        input_partial: raw.partial,
        output_truncated,
        markdown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulldown_cmark::{Event, Tag, TagEnd};

    fn raw(body: &str, kind: &str) -> RawResponse {
        RawResponse {
            requested_url: "https://start.example/".into(),
            final_url: "https://page.example/dir/page".into(),
            hops: vec![Hop {
                url: "https://start.example/".into(),
                status: 302,
            }],
            status: 200,
            content_type: Some(kind.into()),
            body: body.as_bytes().to_vec(),
            compressed_bytes: body.len(),
            partial: false,
            partial_reason: None,
            elapsed_ms: 0,
        }
    }
    fn page(body: &str, kind: &str) -> Page {
        extract(&raw(body, kind), &Limits::default(), "now")
    }
    fn render(md: &str) -> String {
        let mut out = String::new();
        pulldown_cmark::html::push_html(&mut out, markdown_parser(md));
        out
    }
    fn assert_inert(md: &str) {
        let rendered = render(md);
        let doc = dom_query::Document::from(rendered.as_str());
        assert_eq!(doc.select("img, script, iframe, object, embed, style, form, svg, math, video, audio, source, link, meta").length(), 0, "{rendered}");
        // Inspect the rendered DOM too: a different block parse can expose a
        // destination that a code span concealed from the source parser.
        for anchor in doc.select("a[href]").iter() {
            let href = anchor.attr("href").unwrap();
            let url = Url::parse(&href).expect("rendered absolute link");
            assert!(
                matches!(url.scheme(), "http" | "https"),
                "unsafe rendered href: {href}"
            );
            assert!(url.username().is_empty() && url.password().is_none());
        }
        for event in markdown_parser(md) {
            if let Event::Start(Tag::Link { ref dest_url, .. }) = event {
                let u = url::Url::parse(dest_url).expect("absolute link");
                assert!(matches!(u.scheme(), "http" | "https"), "unsafe link");
                assert!(u.username().is_empty() && u.password().is_none());
            }
            assert!(!matches!(
                event,
                Event::Html(_) | Event::InlineHtml(_) | Event::Start(Tag::Image { .. })
            ));
        }
    }

    #[test]
    fn retains_metadata_and_explicit_partial_flags() {
        let mut raw = raw(&"a word ".repeat(40), "text/markdown");
        raw.partial = true;
        let p = extract(
            &raw,
            &Limits {
                max_output_bytes: 17,
                ..Limits::default()
            },
            "2026-10-14",
        );
        assert_eq!(p.requested_url, raw.requested_url);
        assert_eq!(p.final_url, raw.final_url);
        assert_eq!(p.hops[0].status, 302);
        assert_eq!(p.fetched_at, "2026-10-14");
        assert_eq!(p.verdict, Verdict::Useful);
        assert_eq!(p.method, Method::NativeMarkdown);
        assert!(p.input_partial && p.output_truncated);
        assert!(p.markdown.len() <= 17);
    }

    #[test]
    fn html_keeps_structure_and_discards_active_element_contents() {
        let prose =
            "A living culture needs regular feeding with fresh flour and water. ".repeat(20);
        let html = format!(
            "<html><head><title>Culture guide</title><base href='https://evil.example/'><script>CANARY_SCRIPT</script><style>CANARY_STYLE</style></head><body><article><h1>Culture guide</h1><p>{prose}</p><h2>Feeding schedule</h2><p>{prose}</p><a href='../notes'>hydration notes</a><pre><code>rise &gt;= 2.0 &amp;&amp; hours &lt;= 6.0</code></pre><table><tr><th>Day</th><th>Flour</th></tr><tr><td>Tuesday</td><td>60</td></tr></table><img src='/image.png' alt='culture'><form>CANARY_FORM</form><iframe>CANARY_FRAME</iframe></article></body></html>"
        );
        let p = page(&html, "text/html");
        assert_eq!(p.verdict, Verdict::Useful);
        assert_eq!(p.title.as_deref(), Some("Culture guide"));
        assert!(p.markdown.contains("## Feeding schedule"));
        assert!(p.markdown.contains("rise >= 2.0 && hours <= 6.0"));
        assert!(p.markdown.contains("Tuesday"));
        assert!(p.markdown.contains("|"));
        for c in [
            "CANARY_SCRIPT",
            "CANARY_STYLE",
            "CANARY_FORM",
            "CANARY_FRAME",
        ] {
            assert!(!p.markdown.contains(c));
        }
        assert!(p.links().contains(&"https://page.example/notes".into()));
        assert!(!p.links().iter().any(|s| s.contains("evil.example")));
        assert_inert(&p.markdown);
    }

    #[test]
    fn full_page_retains_distributed_headings() {
        let mut html = "<html><head><title>Reference</title></head><body>".to_string();
        for i in 0..15 {
            html.push_str(&format!(
                "<section><h2>Topic {i}</h2><p>{}</p></section>",
                "Several useful words describing this particular reference section in detail. "
                    .repeat(2)
            ));
        }
        html.push_str("</body></html>");
        let p = page(&html, "text/html");
        for i in 0..15 {
            assert!(
                p.markdown.contains(&format!("Topic {i}")),
                "lost heading {i}"
            );
        }
    }

    #[test]
    fn falls_back_when_readability_discards_words_or_headings() {
        let article = format!(
            "<article><h1>Article</h1><p>{}</p></article>",
            "This is a sufficiently long and useful article sentence. ".repeat(40)
        );
        let side_words = format!(
            "<aside class='sidebar'>{}</aside>",
            "<p>These reference details contain useful additional words for the reader.</p>"
                .repeat(150)
        );
        let side_headings = format!(
            "<nav>{}</nav>",
            (0..12)
                .map(|i| format!("<h2>Reference {i}</h2><p>Useful section.</p>"))
                .collect::<String>()
        );
        for (case, sidebar) in [side_words, side_headings].into_iter().enumerate() {
            let p = page(
                &format!(
                    "<html><head><title>Article</title></head><body>{article}{sidebar}</body></html>"
                ),
                "text/html",
            );
            assert_eq!(
                p.method,
                Method::FullPage,
                "case {case}; words {}",
                words(&p.markdown)
            );
            assert!(
                p.markdown.contains("reference details") || p.markdown.contains("Reference 11")
            );
        }
    }

    #[test]
    fn classifies_non_content_without_http_success_assumptions() {
        for (body, kind, want) in [
            (
                "<title>Sign in</title><form><input type=password></form>",
                "text/html",
                Verdict::Login,
            ),
            (
                "<title>Just a moment...</title><p>Verify you are human</p>",
                "text/html",
                Verdict::Challenge,
            ),
            (
                "<div id=\"root\"></div><script>boot()</script>",
                "text/html",
                Verdict::JsShell,
            ),
            ("", "text/html", Verdict::Unusable),
            ("%PDF-1.4", "application/pdf", Verdict::Unsupported),
        ] {
            assert_eq!(page(body, kind).verdict, want);
        }
        let mut r = raw("missing", "text/html");
        r.status = 404;
        assert_eq!(
            extract(&r, &Limits::default(), "now").verdict,
            Verdict::HttpError
        );
        r.status = 403;
        r.body = b"captcha".to_vec();
        assert_eq!(
            extract(&r, &Limits::default(), "now").verdict,
            Verdict::Challenge
        );
    }

    #[test]
    fn provenance_comes_only_from_retained_explicit_links() {
        let p = page(
            "https://loose.example/\n\n[relative](../next?x=1&y=2) [same](../next?x=1&y=2) <https://explicit.example/> [ref][r]\n\n[r]: /ref\n\n`[code](https://code.example/)`\n\n<script>https://script.example/</script>\n",
            "text/markdown",
        );
        assert_eq!(
            p.links(),
            vec![
                "https://page.example/next?x=1&y=2",
                "https://explicit.example/",
                "https://page.example/ref"
            ]
        );
        let p = page(
            "<base href='https://base.example/'><p><a href='next'>Next</a></p><script>location='https://script.example/'</script>",
            "text/html",
        );
        assert_eq!(p.links(), vec!["https://page.example/dir/next"]);
        let p = page(
            "<p>https://loose.example/ is only body text, not an anchor.</p>",
            "text/html",
        );
        assert!(p.links().is_empty());
    }

    #[test]
    fn malicious_links_images_and_inline_image_labels_are_inert() {
        let md = "[bad](javascript:alert%281%29) [data](data:text/html,boom) [file](file:///etc/passwd) [creds](https://user:pass@evil.example/)\n\n![bad](javascript:alert%281%29) ![logo][pic]\n\n[pic]: https://images.example/p.png\n\n[![inner](https://images.example/i.png)](https://good.example/)\n\n![a [nested](javascript:boom) ![inner](x.png)](https://images.example/o.png)\n\n<div>\n![hidden](hidden.png)\n<img src=x>\n</div>\n\nInline <b onclick='boom'>bold</b>.\n";
        let p = page(md, "text/markdown");
        assert_inert(&p.markdown);
        assert!(p.markdown.contains("Image:"));
        assert!(p.links().contains(&"https://good.example/".into()));
        assert!(!p.links().iter().any(|s| s.contains("hidden.png")));
        for s in ["javascript:", "data:", "file:"] {
            assert!(!p.links().iter().any(|u| u.starts_with(s)));
        }
    }

    #[test]
    fn encoded_and_reference_destinations_cannot_smuggle_active_schemes() {
        for destination in [
            "javascript:alert%281%29",
            "java&#x73;cript:alert%281%29",
            "JaVaScRiPt:alert%281%29",
            "data:text/html,evil",
            "vbscript:evil",
            "mailto:secret@example.test",
            "file:///etc/passwd",
            "https://user:pass@example.test/",
        ] {
            let md = format!(
                "[link]({destination}) ![image]({destination}) [reference][r]\n\n[r]: {destination}\n"
            );
            let p = page(&md, "text/markdown");
            assert_inert(&p.markdown);
            assert!(p.links().is_empty());
            assert!(render(&p.markdown).contains("reference"));
        }
        let p = page(
            "[punctuation](<https://safe.example/a?x=![img](javascript:bad)&y=`code`>)",
            "text/markdown",
        );
        assert_eq!(p.links().len(), 1);
        assert_inert(&p.markdown);
    }

    #[test]
    fn preserves_code_semantics_across_commonmark_boundaries() {
        for code in [
            "````\n```\n<img src='code'>\n````\n",
            "~~~\n```\n<img src='code'>\n~~~~~\n",
            "   ```\n<img src='code'>\n   ```\n",
            "    <img src='code'>\n    ![code](code.png)\n",
            "> ```\n> <img src='code'>\n> ~~~\n> ```\n",
            "- ```\n  <img src='code'>\n  ~~~\n  ```\n",
            "`<img src='code'> ![code](code.png)`\n",
            "```\n<img src='code'>\n",
        ] {
            let p = page(code, "text/markdown");
            assert_inert(&p.markdown);
            assert!(render(&p.markdown).contains("&lt;img"));
            assert_eq!(render(&p.markdown), render(code));
        }
    }

    #[test]
    fn table_code_boundaries_remain_inert_at_every_output_cut() {
        for payload in [
            "<img src=https://image.example/tracking>",
            "[bad](javascript:alert%281%29)",
            "![image](https://image.example/tracking)",
            "[good](https://site.example/read?mode=safe)",
        ] {
            let md = format!("| a | b |\n| --- | --- |\n| `test | {payload}` |\n");
            let full = page(&md, "text/markdown");
            assert_inert(&full.markdown);
            // Tables are part of the promised dialect, not escaped wholesale.
            assert!(render(&full.markdown).contains("<table>"));
            for cap in 0..full.markdown.len() {
                let cut = extract(
                    &raw(&md, "text/markdown"),
                    &Limits {
                        max_output_bytes: cap,
                        ..Limits::default()
                    },
                    "now",
                );
                assert_inert(&cut.markdown);
                assert!(cut.links().iter().all(|url| full.links().contains(url)));
            }
        }
    }

    #[test]
    fn partial_input_provides_no_link_provenance() {
        let mut response = raw(
            "[go][r]\n\n[r]: https://site.example/delete",
            "text/markdown",
        );
        response.partial = true;
        let page = extract(&response, &Limits::default(), "now");
        assert!(page.input_partial);
        assert!(page.markdown.contains("https://site.example/delete"));
        assert!(page.links().is_empty());
    }

    #[test]
    fn every_truncation_is_inert_and_does_not_invent_partial_links() {
        for md in [
            "Prefix `<img src=x> ![code](code.png)` suffix",
            "Prefix\n\n```html\n<img src=x> ![code](code.png)\n```\n",
            "[link](https://good.example/path?q=![x](javascript:bad))\n\n![a `code` <b>](https://image.example/p.png)",
            "<div>\n![hidden](hidden.png)\n</div>\n\n[explicit](https://good.example/very/long/path)",
            "é🙂 [![inline](https://image.example/)](https://link.example/)",
            "[ref]: javascript:bad \"<img src=x> ![bad](javascript:bad)\"\n",
            "[ref]: /safe\n[ref]: javascript:bad \"<img src=x> ![bad](javascript:bad)\"\n",
            "[ref]: /safe\n  \"<img src=x> ![bad](javascript:bad)\"\n",
        ] {
            let full = page(md, "text/markdown");
            assert!(!full.markdown.is_empty());
            for cap in 0..full.markdown.len() {
                let p = extract(
                    &raw(md, "text/markdown"),
                    &Limits {
                        max_output_bytes: cap,
                        ..Limits::default()
                    },
                    "now",
                );
                assert!(p.markdown.len() <= cap);
                assert!(p.output_truncated);
                assert_inert(&p.markdown);
                assert!(
                    p.links().iter().all(|link| full.links().contains(link)),
                    "partial link at {cap}"
                );
            }
        }
    }

    #[test]
    fn plain_text_preserves_fences_and_is_not_markdown() {
        let text = "````\n```\n~~~\n<img src=x>\n![image](https://image.example/)\n[link](https://link.example/)\nlast";
        let p = page(text, "text/plain");
        assert_eq!(p.method, Method::PlainText);
        assert_inert(&p.markdown);
        assert!(p.links().is_empty());
        let mut content = String::new();
        let mut in_code = false;
        for event in markdown_parser(&p.markdown) {
            match event {
                Event::Start(Tag::CodeBlock(_)) => in_code = true,
                Event::End(TagEnd::CodeBlock) => in_code = false,
                Event::Text(s) if in_code => content.push_str(&s),
                _ => (),
            }
        }
        assert_eq!(content, format!("{text}\n"));
        for cap in 0..p.markdown.len() {
            let truncated = extract(
                &raw(text, "text/plain"),
                &Limits {
                    max_output_bytes: cap,
                    ..Limits::default()
                },
                "now",
            );
            assert_inert(&truncated.markdown);
            assert!(truncated.links().is_empty());
            assert!(truncated.output_truncated);
            assert!(truncated.markdown.len() <= cap);
        }
    }

    #[test]
    fn decoded_bytes_and_utf8_expansion_are_bounded() {
        let limits = Limits {
            max_decoded_bytes: 32,
            ..Limits::default()
        };
        for kind in ["text/html", "text/plain", "text/markdown"] {
            let p = extract(&raw(&"x".repeat(33), kind), &limits, "now");
            assert_eq!(p.verdict, Verdict::ResourceLimit);
            assert_eq!(p.method, Method::None);
            assert!(p.markdown.is_empty());
        }
        let mut r = raw("", "text/html; charset=windows-1252");
        r.body = vec![0xe9; 32];
        assert_eq!(extract(&r, &limits, "now").verdict, Verdict::ResourceLimit);
        r.body = b"<p>Caf\xe9 cr\xe8me</p>".to_vec();
        assert!(
            extract(&r, &Limits::default(), "now")
                .markdown
                .contains("Café crème")
        );
    }

    #[test]
    fn element_memory_and_implied_dom_limits_fail_closed() {
        for max_elements in [0, 1, 10, 60_000] {
            let body = format!("<article>{}</article>", "<p>x</p>".repeat(max_elements + 1));
            let p = extract(
                &raw(&body, "text/html"),
                &Limits {
                    max_elements,
                    ..Limits::default()
                },
                "now",
            );
            assert_eq!(p.verdict, Verdict::ResourceLimit);
            assert_eq!(p.method, Method::None);
            assert!(p.markdown.is_empty());
        }
        let p = page(
            &format!("<p data-x='{}'>text</p>", "x".repeat((1 << 20) + 4096)),
            "text/html",
        );
        assert_eq!(p.verdict, Verdict::ResourceLimit);
        assert!(p.markdown.is_empty());
        let p = extract(
            &raw("<p>some useful content</p>", "text/html"),
            &Limits {
                max_elements: 1,
                ..Limits::default()
            },
            "now",
        );
        assert_eq!(p.verdict, Verdict::ResourceLimit);
    }
}
