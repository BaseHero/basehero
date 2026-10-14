# Model response, accounting and Tinfoil transport

This library provides bounded chat-completion decoding, per-attempt accounting
state, an opt-in Tinfoil encrypted transport (`tinfoil-route`) and the opt-in NEAR
gateway-trust/quote-verification/OHTTP framing and offline model-verification
increments (`near-route`). E2EE request dispatch, gateway receipt authentication,
durable reservations and the activity UI are not implemented here.

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

## NEAR route (gateway trust, quote verification and OHTTP framing)

The `near-route` feature adds `near_route` and `near_gateway`. `near_gateway::verify`
appraises the NEAR Cloud Gateway's Intel TDX quote with a separate NEAR policy
(strict, with `allow_status(OutOfDate)` and unbounded platform/QE grace accepted
for this gateway by product policy, recording the actual status and advisories),
binds the verifier's fresh nonce and the pinned service signer in NEAR's
`signer || nonce` report-data layout, binds the pinned measured app-compose
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
interval. The signer and measured-app-compose pins were observed in NEAR's
attestation report for the reviewed deployment; they are research configuration,
not policy decisions. Any NEAR redeploy, including a configuration-only change,
refuses this route until the pins are rechecked and revised, exactly as an
identity rotation does. The source-commit pin is recorded for the separate
online provenance step and is not itself verified offline. NEAR model verification
is described below; E2EE dispatch, transport and accounting are later increments.
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
The caller still owns provenance checking/admission for the measured deployment,
transport, authorization, and later response-signature checks. A compose-hash
allowlist is not itself Sigstore source-provenance verification. Any unlisted
candidate or configuration closes the whole route; a hash from an untrusted
report never approves itself. Changes in NEAR's model deployment therefore
need independent admission before they can be used.

Tests follow NEAR's published report shape and dstack event names, with an
archived Intel quote/collateral. Successful model assemblies alter QVL claims
in memory, with synthetic report/event-log, model keys and self-signed ES384
NRAS token/JWKS shaped after NVIDIA's public overall-claims samples. They prove
bindings and ordering, not fresh hardware, NVIDIA's real signature, online
provenance or a usable model route.

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
