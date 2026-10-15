# Model response, accounting and Tinfoil transport

This library provides bounded chat-completion decoding, per-attempt accounting
state, an opt-in Tinfoil encrypted transport (`tinfoil-route`) and the opt-in NEAR
gateway-trust/quote-verification/OHTTP framing, offline model verification and
Ed25519-v2 field encryption/response-signature preparation (`near-route`). Network
dispatch, signature fetching, gateway receipt authentication, durable reservations
and the activity UI are not implemented here.

## Response boundary

`response::ResponseDecoder` consumes **already authenticated and decrypted** SSE
bytes. Its limits bound the entire wire body, individual lines/events, retained
content and number of tools. UTF-8 and SSE delimiters may span arbitrary chunks.
It supports one choice and the `stop` / `tool_calls` finish reasons. A successful
`finish()` requires the finish reason and `[DONE]`; EOF alone is not success.
Truncation, refusal, malformed messages and exceeded bounds fail closed.

`push()` emits provisional text only. A caller may display it while explicitly
showing the run is incomplete, but must not persist it as a successful answer.
Tool proposals are available only from the validated final completion; the caller
must still check tool name, argument schema and current authority before execution.
`Completion::json()` parses JSON, **not** the requested JSON schema. The caller
validates that schema before using the value. Arbitrary JSON repair is not done.
Provider-body usage is an observation, not a trusted billing receipt.

## Accounting boundary

Use one `accounting::Attempt` for each dispatch, including retries:

1. The owning service durably reserves costs and records an attempt under current
   authority before dispatch. This library does not provide that storage or policy.
2. Mark dispatched **before** the transport can send its first byte. A connection
   loss after this point is potentially billable, not proof of zero cost.
3. Serialize Stop with publication. Check `may_deliver()` under that same lock
   immediately before emitting any text or tool. Stop changes local delivery
   eligibility immediately; it does not promise remote inference or billing stopped.
4. Keep usage from the response body as a protected observation. Only a trusted
   provider-facing accounting path may call `reconcile`, after authenticating a
   receipt and associating it with the exact dispatch. This method is not an
   endpoint accepting arbitrary client settlements. It does not verify receipts.
5. A failed uncertain attempt cannot be retried until reconciliation. `may_retry`
   is only one prerequisite: a new attempt still needs authority and reservation.
   Stopped or completed attempts do not request retries. Never redispatch the
   same attempt. Late receipts cannot restart stopped delivery.

Receipt replay on the same attempt is idempotent; conflicting settlements are
errors, not overwrites. The caller owns stable dispatch identity, crash recovery,
receipt binding and preventing duplicate insertion into its durable ledger.
There is deliberately no automatic fallback, retry loop or allowance enforcement.

`Rates` computes checked integer nano-USD estimates. Input tokens include cached
tokens; the cached subset gets its own rate. Rounding happens once, upwards to a
nano-dollar. Keep rate versions with the authoritative ledger; an estimate is not
an invoice. `Settlement::Pending` is never silently converted to zero cost.

`billing()` exposes only route and settlement; its owning gateway separately adds
permitted funding-account/base scope and the actual pinned provider model. It
must not add actor, conversation, work kind, prompt or task identifiers.
`summarize` groups distinct attempts by work kind for **authorized encrypted
activity data**, not ordinary operational records. Its known totals and pending
count must both be displayed. The caller selects the time window (for example,
a week) and seals private attribution for authorized readers. This library
neither authenticates that attribution nor implements report-reader permissions.

## Offline provider admission (`near-route`)

`provider_policy` verifies an app-root-signed, provider-scoped canonical envelope
and gives `install` one pure version/digest transition. A newer authentic
structurally valid policy advances the floor even if expired, overlong or
withdrawn; use requires the device clock at or after the app build date and
strictly before expiry. Only policy-derived `expected_gateway` and
`expected_model` can construct production verifier expectations. At handoff,
`check_current` tests verified evidence against the current immutable NEAR snapshot, the device-clock policy window, and the authenticated exclusive evidence validity end. The gateway verifier retains QVL's earliest collateral expiration; the model verifier retains the minimum of that QVL expiration and authenticated NRAS `exp`. A policy may name a model outside the app's release ceiling without preventing a retirement or version-floor advance: all entries remain signed, canonical and stored verbatim, but unsupported models cannot authorize. `Install::Installed` and `Same` report `usable_now` only when in-window with at least one supported entry, not as a specific-route permission.
The archived gateway tuple and arbitrary hash constructors are test-only.
The native owner in `bh-provider-policy-store` persists per-device policy bytes.
At each NEAR dispatch handoff, use a cloneable `Owner::reader()` and call
`Reader::check_current` with verified evidence and the device-clock time: it
loads `Reader::snapshot()` afresh and refuses a quarantined `None`. Never check
an `Arc<Snapshot>` retained from an earlier admission. The app must supply
trusted release values, its device-clock `Time`, and fresh nonces. This crate
has no storage, fetch, release root or production approval.
The later transport/reuse driver, not the policy-file persistence/fetch owner, must anchor both the local reuse cap and authenticated remaining evidence validity to monotonic elapsed time at admission. The elapsed clock must include suspend or cached admissions must be discarded on resume; never persist/reload verified keys as fresh proofs. Continue to check device-clock policy expiry and current membership at every handoff. This library supplies the authenticated bounds but not a reuse timer or driver.
See `fixtures/provider-policy-synthetic.md` for the deterministic **synthetic**
interoperability vector; it is not an approval.

For NEAR model reports, call `near_model::preflight_reports` on bounded raw
metadata/report bytes before obtaining ancillary collateral or NRAS/JWKS;
`verify` rechecks the same bounds and appraises each of the at most 32 returned
candidates sequentially, returning no partial keys. Neither the 32-report
ceiling nor one returned report describes the provider's replica inventory.

Remaining gates: authenticated release trust ceiling and shipped signed bytes,
real signed provider approvals and signing ceremony, effective downstream/key-holder
policy qualification, live route qualification and trusted billing/credentials.
The native bootstrap is deliberately inert until those release values exist. No
real-data dispatch is authorized by these offline tests.

## NEAR route (gateway trust, quote verification and OHTTP framing)

The `near-route` feature adds `near_route` and `near_gateway`. `near_gateway::verify`
appraises the NEAR Cloud Gateway's Intel TDX quote with a separate NEAR policy
(strict, with `allow_status(OutOfDate)` and unbounded platform/QE grace accepted
for this gateway by product policy, recording the actual status and advisories),
binds the verifier's fresh nonce and a signed-policy-admitted service signer in NEAR's
`signer || nonce` report-data layout, binds that signer's exact paired measured app-compose
SHA-256 to both the quoted `mr_config_id` and the `compose-hash` replayed from
the dstack RTMR3 log through the shared `bh-confidential-attestation` helper,
and is the only constructor of `GatewaySigner`.
`verify_key_config` then checks the gateway's
Ed25519 signature over the raw OHTTP key-configuration bytes against that
quote-verified signer, then parses the configuration with strict `X25519` +
`HKDF-SHA256` + `AES128-GCM` checks. The OHTTP attestation's advertised
`signing_key` must equal the same signer. Every failure is a fixed,
content-free kind.

`near_gateway` performs no network I/O, fetches no Intel PCS collateral and reads
no wall clock: the caller supplies bounded raw quote/collateral/event-log/
app-compose bytes, a fresh verifier-owned nonce and a trusted conservative time
interval. The built-in signer, measured-app-compose and source-commit values
are archived test fixtures, not production pins. Production gateway signer/compose pairs come
only from signed provider policy via `provider_policy::expected_gateway`. The
release authority checks source provenance before signing a policy; this crate
does not verify it offline. Any NEAR redeploy, including a configuration-only
change, needs a new signed policy, not an app release; an unlisted deployment
refuses this route until one is signed. NEAR model verification is described
below; network dispatch, transport and accounting are later increments.
All tests are offline and the gateway quote/assembly tests are synthetic:
the QVL appraisal runs on an archived, expired Intel quote and every successful
assembly mutates that verdict (or uses a synthetic event log) in memory, so they
prove ordering, binding and policy, not a fresh hardware attestation or a live
gateway.

`encapsulate` encodes one inner request as BHTTP and seals it as the draft
`chunked-ohttp` exchange the pinned NEAR Python SDK and Cloud Gateway use: HPKE
Base mode, varint chunk lengths, and a final chunk with `final` AAD. The scheme
and authority are fixed; only an origin-form path is accepted. The only caller
value on the outer request is the ordinary relay credential, and inner
field-encryption headers never move outside the ciphertext. `decapsulate` opens
the chunked response with the exported-secret HKDF scheme and parses the BHTTP
response.

This increment performs no network I/O. The caller still owns authority,
allowed-provider and model selection, the single durable dispatch and trusted
accounting. Tests use synthetic, explicitly unattested keys with real HPKE and
Ed25519, and run the pinned gateway's own `ohttp`/`bhttp` 0.7.2 server code
offline (a dev-dependency); they prove protocol and ordering, not hardware
validity or live gateway behaviour. Response decryption is buffered per bounded
reply in this increment; streaming stays a later increment.

## NEAR fixed-model offline verification

`near_model::verify` accepts only already-authenticated, decrypted OHTTP response
bytes for the fixed `z-ai/glm-5.3-flash` metadata and report endpoints. The caller
must issue the fresh report nonce, request `provider=near` with no aliasing and
Ed25519, provide offline Intel collateral for every candidate, a trusted bounded
time interval, independently approved SHA-256 hashes of the measured app-compose,
and a separately fetched NVIDIA NRAS overall JWT plus trusted NVIDIA JWKS for
each candidate. It accepts no empty candidate set and rejects the *whole* set if
any candidate fails. Only this verifier builds a `VerifiedModelKey`; it cannot
be substituted by a raw byte key. The approved hashes are a deployment-admission
input, **not** hashes learned from the untrusted report, and are not configured
by this library. No actual model deployment has been approved here.

Each CPU quote receives strict UpToDate QVL policy at both ends of the trusted
time interval, including Intel signature/collateral checks; there is no model
OutOfDate exception. It must be non-debug, bind `signing_address || fresh_nonce`
and any advertised report data, match the required Ed25519 model key, and replay
the dstack RTMR3 `compose-hash` to the quoted `mr_config_id` and an independently
approved compose hash. NVIDIA evidence is required: its payload nonce must match
the CPU's client nonce. The already-obtained NRAS JWT must have a valid ES384
signature against a **caller-supplied trusted NVIDIA-origin JWKS**, pinned issuer,
matching `eat_nonce`, true overall result, required `iat`/`nbf` no later than the
trusted interval's upper bound and `exp` after that bound. NVIDIA's public NRAS
overall-claims samples omit `aud`; this verifier does not require it. JWT headers
never nominate a key URL. The future online transport must POST each exact
payload to NRAS and fetch the JWKS from NVIDIA's pinned endpoint; this crate
does not do so.
The release authority checks measured-deployment source provenance before
signing provider policy; this crate does not verify it offline. Production model
compose hashes come only from that signed policy via
`provider_policy::expected_model`, not from built-in fixtures or untrusted reports.
The caller still owns transport, authorization and fetching the later response
signature. A compose-hash allowlist is not itself Sigstore source-provenance
verification. Any unlisted candidate or configuration closes the whole route;
a hash from an untrusted report never approves itself. A NEAR model redeploy
needs a new signed policy, not an app release; until signed, it cannot be used.

Tests follow NEAR's published report shape and dstack event names, with an
archived Intel quote/collateral. Successful model assemblies alter QVL claims
in memory, with synthetic report/event-log, model keys and self-signed ES384
NRAS token/JWKS shaped after NVIDIA's public overall-claims samples. They prove
bindings and ordering, not fresh hardware, NVIDIA's real signature, online
provenance or a usable model route.

## NEAR Ed25519-v2 field protocol (offline)

`near_e2ee::prepare` accepts only `near_model::VerifiedModelKey` and the fixed
GLM-5.3 Flash model with `stream=true`. It refuses unsupported request fields
rather than allowing the SDK's selective transform to leave private content
unencrypted. It encrypts messages (string and JSON-array content, reasoning,
name, refusal, audio data and historical function/tool calls), tools' names,
descriptions and parameters (including schemas), and named tool choice, using
the pinned SDK's Ed25519-to-Curve25519, ephemeral X25519, HKDF-SHA256 and
XChaCha20-Poly1305 v2 wire format. Each request gets a fresh Ed25519 response
key, kept inside its owned request/reply context. An empty **request** field is
encrypted; the SDK's empty **response** field is represented by `""`.

The request is serialized once and enclosed by `near_route::encapsulate` with
fixed inner `POST /v1/chat/completions`, mandatory v2/all-fields/no-aliasing
headers **inside OHTTP** and no caller-supplied inner authorization, cache or
body metadata. Ordinary relay headers remain credential-only. The current
OHTTP decoder still buffers and authenticates up to 16 MiB before returning a
BHTTP response. `BufferedReply::next_provisional()` incrementally decrypts its
SSE body in 1 KiB steps, with a 16 MiB encrypted-wire cap, 1 MiB encrypted
record cap, 1 MiB field cap and the existing plaintext response bounds. This
is **not yet network-level outer streaming**. Text emitted before signature
verification is provisional. `finish` consumes the reply and releases text and
tools only after the stream has been fully consumed, a finish reason and `[DONE]`
were seen, and a `provider_tee` Ed25519 signature from the *previously verified
model key* matches the exact encrypted request and response bytes. It never
promotes response-body token counts into a trusted billing receipt. Stopping or
dropping the local handle does not mean a remote call or charge stopped.

The SDK doesn't encrypt top-level `stop` strings or `response_format.json_schema`
(including its schema descriptions), so this narrow all-fields route **refuses**
those request forms rather than leak them while claiming model-only encryption.
It accepts `response_format: {"type":"json_object"}` for JSON text but that
is not schema validation; caller-side schema validation remains required.
Encrypted response `content` arrays are also refused until the response decoder
can represent them. No ECDSA legacy fallback is available. The field envelope
is provider compatibility only, not a BaseHero X-Wing seal. The separately
quoted model key, bounded signature fetch through the pinned transport, request
lifecycle, model deployment admission, online NRAS/PCS/provenance and trusted
accounting are later work. All fixture keys are synthetic, never hardware proof.

## NEAR data-only structured results (offline)

`near_structured::prepare_structured(verified_model, request_json, schema_json)`
prepares one reserved, inert result tool. Its encrypted name, description and
parameter schema are sent through `near_e2ee::prepare` and OHTTP, with an
encrypted forced named `tool_choice` and `parallel_tool_calls=false`. Requests
containing `tools`, `tool_choice`, `function_call`, `response_format` or
`parallel_tool_calls` are rejected, even when null. Ordinary `near_e2ee::prepare`
and ordinary chat/tool responses are unchanged. There is no plaintext
`response_format.json_schema` fallback.

The schema is trusted local context but stays inside the owned Prepared →
Exchange → BufferedReply chain. `BufferedReply` exposes no provisional text,
tools or value: `finish(signature)` consumes the entire stream, verifies
terminal markers and the exact encrypted-wire model signature, then requires
exactly one named tool, no text, bounded JSON object arguments and local
schema validation. The returned `StructuredResult.value` is data, never a
runner action or an executable tool. `reported_usage` is only an observation;
validation success/failure does not settle billing or authorize retry.

Uses MIT `jsonschema` 0.33.0 pinned with **no default features** (HTTP, file and
async resolvers disabled), explicit Draft 2020-12. Accepted schema keywords:
`type`, `properties`, `required`, `items`, `enum`, `const`,
`additionalProperties`, `description`, `title`, `minItems`, `maxItems`,
`minLength`, `maxLength`, `minimum`, `maximum`. Schema root, nested `items` and
property schemas must be objects; external and local references, `$id`,
retrievers, regex/pattern, formats, combinators and other keywords are rejected
before compilation. A schema is at most 64 KiB, the returned JSON object at
most 256 KiB; schema and value trees have at most 2,048 nodes and depth 32.
The structured reply also lowers the ordinary response decoder's retained
content cap to 256 KiB *before* parsing tool-argument JSON; its existing SSE
wire/record limits still apply. Errors are fixed, content-free kinds and
validator diagnostics are discarded.
No network lookup is made for schemas. If a wider vocabulary is needed, extend
this allowlist with bounded tests rather than passing unknown keywords through.

The validator is compiled once per request, owned by that request and dropped
on completion; no global cache or cross-base/account invalidation exists. For
example, a team base with 100 members dispatching 100 concurrent 4 KiB schemas
incurs 100 independent bounded compiles (roughly 400 KiB of schema input), not
one serialized global lane. Memory/time per request grow with its bounded
schema and reply, not with member count or years of history. This is a local
cost argument, not a load benchmark or admission/dispatch implementation.

## Tinfoil route

The caller creates `tinfoil_route::Gateway::new(https_url)` and invokes
`start(ChatRequest, proxy_credential, WorkKind, Limits)` for a **new** authorized,
reserved attempt. `StreamHandle::next()` yields provisional text and only after
real `[DONE]` yields final tools or structured text. `stop().await` suppresses
subsequent delivery promptly, even while headers/chunks stall. `billing()` remains
Pending once dispatch is possible. Dropping the handle/transport does not prove
remote inference or charges stopped. A caller must not retry an uncertain charge
until its trusted accounting path reconciles the original attempt.

This route fixes the provider host, repository and model internally. SDK
`SecureClient::new_with_proxy(...).verify()` performs full standard verification
before dispatch; only its active verification document supplies the attested HPKE
key. The official EHBP client seals the complete JSON and decrypts the raw
stream. The SDK's relaxed SSE parser drops `[DONE]`, and its high-level transport
can silently replay key mismatches, so neither is used here. Reqwest 0.13 has
redirects disabled and `retry::never()`; one `execute()` is made per explicit
attempt. The owned gateway TLS config explicitly selects rustls aws-lc-rs with
hybrid-first X25519MLKEM768, safe protocols and native certificate roots, even
when the SDK has selected ring globally for its own verification. The gateway
holds its provider credential, while the credential passed
here authenticates to the ordinary proxy. There is no public arbitrary-key,
GroundTruth or HTTP fixture constructor. Errors use fixed redacted kinds; neither
provider-body usage nor a client-visible header is an accounting receipt.

The HTTP fixture and independently encrypted local server in feature tests use a
**synthetic key, not hardware verification**. Fixtures enter through the same
private verification/dispatch/error runner as production; only their verifier
future is synthetic. A controlled pending-verification Stop remains NotDispatched.
Real provider streaming behavior, model format compliance, gateway meter/receipt
timing and deployed delivery remain
unverified. `Completion::json()` is only JSON parsing, not schema validation.

## Checks

This is a member of the root Cargo workspace. From the product root:

```sh
cargo fmt --all --check
cargo clippy --locked --offline -p basehero-models --all-targets -- -D warnings
cargo test --locked --offline -p basehero-models
cargo test --locked --offline -p basehero-models --features tinfoil-route
cargo clippy --locked --offline -p basehero-models --all-targets --features tinfoil-route -- -D warnings
cargo test --locked --offline -p basehero-models --features near-route
cargo clippy --locked --offline -p basehero-models --all-targets --features near-route -- -D warnings
bash scripts/check.sh
```

All tests are offline. The feature tests additionally exercise real EHBP
crypto/streaming and real HPKE/Ed25519 gateway framing against local synthetic
fixtures, not live provider verification, remote cancellation, actual bills or
deployment. The NEAR tests exercise real QVL on archived Intel material and
synthetic model assembly/ES384 JWT verification, not a fresh model quote or
response signature.
