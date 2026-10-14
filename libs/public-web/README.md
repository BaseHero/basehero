# Public web library

A public-only HTTP(S) page reader, Cloudflare Web Search API client and job-local
URL provenance boundary. It has no service entry point, embedded provider credentials,
browser, private-site mode or model.

## API boundary

Trusted request handling creates one `JobSources` per authorised job. It registers
URLs from authenticated **typed** request content (not pasted quotes), and the
verified search adapter registers exact returned URLs. Model tool arguments supply
only a proposed address; they never supply provenance or a permit.

`permit(address)` succeeds only for an exact registered string. URL parsing and
network normalisation happen after that exact match. A changed query, pasted URL,
base-page address or invented URL returns `NeedsOutsideEffect`. This library does
not bypass review, approval or a durable outside-effect claim: such reads are
unavailable until the calling service implements that path.

The relay can construct `search::SearchClient::new(endpoint_base, account, gateway, token)`
with its own configuration and credential. `search(query, &mut job_sources)` sends the
query unchanged to Cloudflare's `/client/v4/accounts/{account}/ai/websearch/` REST
endpoint: Ceramic first, Linkup once only if Ceramic fails. Both attempts send
`cf-aig-collect-log: false`. Empty results are failures, not successful research.
Results expose provider, exact returned URL, optional title and description; all
are untrusted data. Only a fully received, valid, nonempty result list admits its
exact URLs as search provenance. An invalid URL anywhere rejects that attempt
atomically; titles and descriptions never grant permits. The caller owns policy,
authority checks and gateway logging configuration. The library does not establish
that any provider retains no data, or implement the relay itself.

`JobSources::read(reader, address, fetched_at)` fetches and extracts, then registers
explicit links from a complete input response in that job alone. It does not follow
them. Partial input (transport interruption, compressed/decoded byte cap or decoder
failure) grants no fetched-link provenance: even a syntactically complete link may
have lost a query/path suffix. `Page::links()` therefore returns no links for partial
input. Relative links resolve against the final response URL, never an HTML base tag.
A model cannot import a manufactured page as fetched evidence. `source(address)`
exposes the recorded origin; requested/final URLs and redirect hops stay with the
returned page. The caller supplies trusted fetch time.

Registration methods are trusted integration APIs, **not model tools**. The caller
must check current signed job authority, source-policy intersection, allowance and
relay verification before each dispatch. A permit is provenance evidence, not a
delegation, attestation or approval. It borrows the ledger and is not serialisable.
Persistent job/checkpoint adapters must restore authenticated provenance in the
same job, not recreate it from model messages.

`evidence::Evidence::new(trusted_max_sources)` is a job-local retained-source
collection. Its sole insertion API, `read(&mut job_sources, reader, address,
trusted_fetch_time)`, performs an actual `JobSources::read` and owns a frozen
snapshot of the retained Markdown, title, requested/final address, verdict, checked
time and partial/truncated flags. Search titles/descriptions and model-made pages
cannot insert evidence. The caller-chosen source-count cap refuses before I/O; the
Reader's existing per-page limits compose with it, not a general memory manager.
Repeated reads of the same URL receive different local IDs and cannot retarget
older references. `source(id)` exposes immutable references only.

`validate_quote(proposed_id, proposed_quote)` resolves an ID only in the collection
supplied by trusted job code. For a useful page, it binds a nonempty exact quote
present in *retained* Markdown to that snapshot, borrowing its actual bytes;
missing IDs, empty/fabricated quotes and unusable pages fail with fixed categories.
Partial input or truncated output can still yield a useful exact excerpt, with
both flags visible through the citation's source: this **never** proves the whole
page was retained. Quote presence proves neither semantic support nor truth,
credibility or research completeness. There is no `Complete`/successful-research
status, checkpoint persistence, authenticated request contract or note delivery in
this library. IDs and citations grant no URL permit or outside-effect authority.
Keep these content-bearing objects inside authorised job processing; the caller
still checks current source policy, authority and Stop before dispatch. Future
persistence must use the job's encrypted, audience-scoped checkpoint contract.

## Network and content

- Page reads use fixed GET, Accept and User-Agent; no request body, cookies, credentials, Referer,
  proxy inheritance, automatic retries or automatic redirects.
- Fresh client and checked DNS per hop; only public addresses reach connections.
  Literal, numeric and IPv4-mapped addresses are checked too. Local/special-use
  ranges and IPv6 transition mechanisms are refused. No private-device fallback.
- TLS verifies the original URL host against system roots with an explicitly
  selected aws-lc rustls provider, preferring X25519MLKEM768. No global-provider
  fallback or insecure certificate mode.
- Defaults: 5 redirects, 20-second network deadline, 5-second connect timeout,
  4 MiB compressed input, 8 MiB decoded input, 256 KiB Markdown output and
  60,000 source elements. Trusted callers can choose stricter/different bounds;
  none are model arguments.
- gzip/brotli decoding is bounded; concatenated gzip members are all decoded.
  An incomplete later member marks the input partial. Partial input and truncated
  output are explicit.
  Login, challenge, script shell, unsupported and HTTP-error verdicts are distinct
  from useful content. Heuristics are not an assessment of citation support.
- HTML preflight bounds source elements and tracked tokenizer memory before DOM
  conversion. Readability falls back when it loses much of the page's words or
  headings. These are not a hard process-memory or synchronous parsing deadline.
- The supported Markdown dialect is **CommonMark plus tables**. Sanitization,
  truncation and link extraction use `extract::markdown_parser`; consumers must
  use it for rendering too, without additional parser extensions that could
  reinterpret code/content boundaries. Within this dialect, Markdown has no active
  HTML or remote images; images become plain links, and only credential-free
  HTTP(S) destinations remain clickable. Returned content
  is still untrusted evidence, never an instruction or authority. The app must
  use its bundled renderer/CSP, never navigate the WebView or load linked assets.

Search caps each full attempt (headers and body) at 9 seconds, leaving time for
Linkup when Ceramic stalls, within a 20-second overall deadline. It has a 256 KiB
response cap. It disables automatic redirects, retries, proxies and HTTP decompression; its
TLS uses the same explicitly configured rustls provider and system roots as page
reads. Search errors are fixed categories: HTTP failure, timeout/network, malformed,
oversized, partial, empty or unsafe results. Both providers' failure categories are
reported when neither succeeds, with no response contents or dependency strings.
The trusted caller supplies the HTTPS API endpoint base; HTTP is accepted only by
isolated socket fixtures. No dependency logging subscriber is installed.

Dropping a fetch future cancels local I/O, not a request already received by a
remote server. Synchronous extraction must be scheduled separately from responsive
job/UI cancellation. This library neither promises inference cancellation nor
implements durable research completion or note writing.

## Diagnostics

Errors contain fixed categories, never dependency error strings. Content structs
do not implement Debug. URLs, text, titles, source provenance and results remain
inside authorised processing. **The composing service must disable dependency
logging/tracing and platform crash capture**: HTTP and parser libraries can emit
content if a subscriber is installed. This library installs no subscriber.
Full service canaries and attested encrypted transport are integration checks,
not properties established by the local library fixtures.

## Checks

From the product root (`basehero/`), with `nix develop`:

```sh
# Full default check, including the socket-observed fixtures:
nix develop --command bash scripts/check.sh
# Fast affected tests:
nix develop --command cargo test --locked -p bh-public-web
```

From this library directory, `bash check.sh` runs its format, Clippy, portable
and isolated-network checks. The ignored network tests are mandatory in that
script and in the product's default full check on Linux; macOS skips them in the
product check. The namespace requires Linux unprivileged user/network namespaces
and uses test-owned public-looking,
private and metadata addresses. Fixtures check accepted sockets, request headers,
TLS SNI, roots/name refusal, redirects, rebinding, compression and timeouts.
Search fixtures also cover provider fallback including a stalled Ceramic, no-log/auth
headers, all-or-nothing provenance, malformed/oversized/partial/empty responses,
Unicode query boundaries, redirect refusal and cancellation.
They do not contact real websites or search/model services. The product workspace
owns the single committed lockfile and pins dependency versions centrally.
