# Content-blind sync kernel

This library implements ordinary-record framing, common commitments and exact
operation-approval consumption. It is **not a hosted sync service**, an account
verifier or a complete encrypted-event protocol. It exposes no network endpoint.
A passing hash-chain check is not permission to apply content. Account admission,
original-author verification, attested channels, protected current-authority
storage and storage adapters must be integrated before serving real data.

## Components and trust

- Devices produce an encrypted, padded envelope containing the original author
  signature and its audience/epoch/version/seen-head/control bindings (and base
  binding after genesis; genesis derives its own base id). The
  detailed inner envelope codec is outside this kernel. Devices verify those
  originals and current authority before applying content; a checker signature
  cannot substitute for them.
- The confidential checker authenticates the requesting device and verifies
  current account and audience authority. It has no content keys. Identity-bearing
  inputs stay inside its attested encrypted channel and protected storage.
- The ordinary sequencer assigns positions, stores opaque bytes and consumes a
  checker approval for an exact operation. It sees the containing base, sizes,
  ordering, timing, per-operation commitments and individual immutable objects,
  but no member/device/private-audience handle.
- The storage adapter owns the atomic transaction, replay index and durable-commit
  acknowledgement. This library returns plans; producing a plan writes nothing.

Commitments use the shared cryptographic library's libsodium BLAKE2b-256.
Approvals use its Ed25519 verification. Opaque-event framing remains version 1,
canonical ordering uses format 2, and data transport uses version 3; these
versions are independent. Changing transport framing never negotiates away an
inner signed version or a device's remembered version floor.

## Values and framing

All integers are unsigned, big-endian. Decoders reject unsupported versions,
truncation and trailing bytes. Identifiers and digests are 32 bytes.

The opaque event's 32-byte field is a freshly random **nonce**, persisted with
its exact ciphertext before first submission and reused unchanged on retries.
It is not a publication identity, device sequence, account key, audience id or
session token. The signed binding also retains that nonce. The publication
`EventId` is instead `H("bh/event-id/control/v1\0" || event_digest)` or
`H("bh/event-id/content/v1\0" || event_digest)` for its ordered route. The
same nonce under different bytes or routes cannot reserve the first Ack.

An `OpaqueEvent` is:

```
u16 version = 1
32  event_nonce
u32 envelope_length
N   encrypted_padded_envelope
```

The entire envelope length, including its internal cryptographic overhead, is
one of 1024, 4096, 16384 or 65536 bytes. No content kind, author, audience, epoch
or identity-bearing signature appears outside it. Construction checks size only;
it does not certify that arbitrary bytes really are encrypted.

The event digest is `H("bh/event/v1\0" || encoded_event)`. A containing base's id
is its genesis event digest. The empty head is position 0 and a zero digest.
Ordering the first event checks that its digest equals the base id and that it is
on the control route: a genesis is always a control.

The canonical order opening (`OrderState`) is exactly 82 bytes:

```
u16 format = 2
u64 raw_control_position
32  raw_control_node_hash
u64 trailing_content_count
32  trailing_content_suffix_hash
```

The empty opening has zero position, count and hashes. A new raw control
commits the base, assigned position, prior **global** Head and event digest
under `"bh/control-node/v2\0"`, then clears the content suffix. Content
extends the suffix under `"bh/content-suffix/v2\0"` with the control node,
count, prior suffix and event digest. A nonempty global Head is `(position,
H("bh/order-state/v2\0" || base_id || opening))`; never return a raw node
hash as a global Head or reconstruct an opening from a Head.

A body-free canonical `Commitment` is exactly 149 bytes:

```
u16 format = 2
32  base_id
u8  route (0 content, 1 control)
82  before_opening
32  event_digest
```

Its after opening, global Head and route-derived publication ID are derived by
ordering these fields; they are not independent tail bytes. The first event
must be a control whose digest equals the base id. Decoding validates format,
route, opening and transition without fetching the body. A follower also
checks that each before opening equals its previously verified after opening
and that the descriptor's exact digest matches. The sealed binding's class
must match the route. A compromised sequencer can build an internally
consistent history: author, accepted-control and remembered-head checks remain
indispensable. Device and hosted order stores persist format 2 and the opening
atomically with ordered progress; populated markerless stores refuse, not
relabel, reset or synthesize an opening.

## Exact operation approvals

The implemented operations are append of one opaque event, read of 1–64 **exact
immutable ciphertext commitments**, staging one detached padded body, and reading
1–64 exact stored bodies. A read selection cannot contain repeated objects. Its
order is part of the request. No reusable download URL or connection-wide
authority follows from a read approval. Common-header range transport, presence
and attachment publication are not implemented here.

```
append_digest = H("bh/append/v1\0" || event_digest)
read_digest   = H("bh/read/v1\0" || u16 count || object_digests_in_order)
```

The checker must authorize every selected body, not just its containing base.
A signed approval has a 226-byte body and 64-byte signature:

```
u16 version = 1
32  base_id
u64 expected_position
32  expected_chain_hash
32  checker_incarnation
u64 access_sequence
32  one_operation_nonce
32  operation_digest
32  response_binding
u64 not_before
u64 expires
64  signature
```

The `expected_chain_hash` is the global canonical Head hash, not a raw
control-node hash. The signature covers `"bh/access-approval/v1\0" || body`. The response binding
commits to a fresh one-operation encrypted response channel or receiver key; the
adapter must derive it from that actual channel/key, not accept a caller's hash
without binding delivery to it. Consumption compares it with the signed field.
A copied approval cannot redirect the response to another channel. A response
channel binding is never reused as a persistent device/member handle.

Time values are milliseconds in the host's agreed absolute time domain. Storage
supplies a conservative trusted time interval; the planner accepts an approval
only if that interval is at or after `not_before` and strictly before `expires`.
Client time and arbitrary HTTP headers are never that trusted source. Expiry is
capped by the earliest possible pending authority change; it is not a revocation
strategy by itself. The native adapter samples time *before* its SQLite commit
and imposes no maximum remaining transaction duration. A stalled commit can
finish after expiry: exact hosted removal deadlines require separately validated
host timing/serialization guarantees, not an arbitrary margin.

The incarnation is fresh for a recovered checker/storage session and scoped to
the base, not a member or audience. The sequence counts **all access operations**,
including reads, separately from common-log positions. Storage accepts only its
next sequence, expected head, incarnation and pinned checker key. This avoids an
unbounded spent-nonce table. It deliberately serializes operations within the
single-base execution lane; throughput/batching is not claimed here.

## Account ordering evidence and recovery authorization

The account's access checker signs evidence with its existing permit key, whose
certificate is verified under the device's pinned hosting root. A permit alone
is not proof of publication: a removal's wait begins only once the checker has
confirmed that the exact signed original control is durably present in the
account-home log. Evidence authenticates the checker's statement; devices still
verify original account signatures, predecessors and ordered log history.

All three new evidence encodings use version 1, big-endian unsigned integers,
fixed-width fields and exact lengths; decoders refuse trailing bytes, inverted
time bounds and non-account log kinds where a log is present. `LogId` is a kind
byte (2 for account) and 32-byte id; `Head` is a u64 position and 32-byte
hash. `TimeBounds` contains inclusive earliest and latest milliseconds.

- `OrderingConfirmation` (430 bytes) signs
  `"bh/ordering-confirmation/v1\0" || version:u16 || log:33 ||
  original_digest:32 || original_previous:40 || original_head:40 ||
  body_present:u8 || body_digest:32 || ordered:40 || earliest:u64 ||
  latest:u64`, followed by the 130-byte permit-key certificate and 64-byte
  signature. An absent body uses flag 0 and a zero digest; a present one uses
  flag 1. `original_digest = H("bh/account-original/v1\0" || exact_original)`.
  `ordered` is the enclosing log head. Its evidence commitment is the hash
  of all 430 encoded bytes; verify the original bytes and optional body against
  the claim before trusting it.
- `AcceptedHead` (349 bytes) signs
  `"bh/accepted-head/v1\0" || version:u16 || log:33 || challenge:32 ||
  original_head:40 || evidence:32 || earliest:u64 || latest:u64`, followed by
  the permit-key certificate and signature. Verify the requester's exact
  challenge and expected log. `evidence` is the confirmation commitment at
  that original head, or zero for a legacy head. It is not a substitute for
  checking account history.
- `RecoveryKeyCertificate` (1314 bytes) signs
  `"bh/recovery-key/v1\0" || version:u16 || hosting_root:32 ||
  recovery_public:1216` directly under the pinned hosting root, followed by
  its 64-byte signature. It does not introduce another root or permit-key
  custody.

Three additional signed permit scopes apply **only** to account logs:
`ReadDirectory` (tag 9: log), `StoreDirectoryEntry` (tag 10: log, entry:32,
version:u64, body:32, len:u32) and `RetireHomeObjects` (tag 11: log,
prefix_digest:32). Their ordinary permit certificate, validity window and
signature rules are unchanged. A base log in any of these scopes is refused.
The authorization protocol also frames recovery requests, notices, exact-control
confirmation and bounded account-evidence reads (up to 64 positions). These
wire formats do not themselves activate the service operations.

The data socket's directory requests and responses use version 3 frames (the
usual `version:u16 || tag:u8 || request_id:u32` header): tag 37 reads with
`permit:blob || after_present:u8 || optional_entry:32`; tag 38 stores with
`permit:blob || sealed_body:blob`; tag 39 retires home objects with
`permit:blob`. A directory response (tag 37) is `count:u16 || more:u8 ||
sealed_body:blob` repeated `count` times, at most 64, sorted by opaque entry id.
The caller pages by supplying the last entry id it received, as recovered from
its authenticated sealed body; the cursor is exclusive. Store and retire answer
with empty tag 38 and 39 frames. Each blob is `length:u32 || bytes`; all flags
are exactly 0 or 1. Directory bodies are 1–65536 bytes; the store permit's
`body` is their exact BLAKE2b-256 hash and `len` their exact byte count.
The object keeps an opaque `entry -> (version, digest, len)` row and accepts
only increasing versions, except identical equal-version retries. The sealed
body is stored under `d/<log>/<entry>/<digest>` so a newer revision cannot
overwrite the bytes the prior durable row still names during an interrupted
write. Once a higher-version row is durable, the Worker best-effort deletes its
superseded body; a read that captured the old row before that deletion retries
the directory after a missing-object refusal. An interrupted put before its row
update may leave an orphan R2 object, with no sweep. These frames reveal no
subject or content to the Worker; devices verify signatures, authorship and
rollback themselves.

## Detached bodies and descriptor closure

An encrypted event's first 32 envelope bytes commit its detached padded body `B`:
`body_commitment = H("bh/payload-object/v1\0" || P:u32 || B)`, where `P` is one of
1024, 4096, 16384, 65536, 262144, 1048576 or 4194304 bytes (`BODY_SIZES`; envelopes
use the smaller `ENVELOPE_SIZES`). The kernel computes that commitment from the
exact bytes handed to it and never accepts a caller-supplied commitment. It reads
only those first 32 envelope bytes, no other descriptor field, so this path
exposes no audience, author, epoch or content kind.

Two further operations use the same approval, one access sequence, response
binding and trusted time window, under their own domains:

```
stage_digest     = H("bh/body-stage/v1\0" || body_commitment)
body_read_digest = H("bh/body-read/v1\0" || u16 count || body_commitments_in_order)
```

Staging persists one immutable body; staging the exact bytes again is idempotent
and does not fork. A body read selects 1–64 exact commitments and returns the
stored bytes; its selection is bounded and repeat-free, and corrupt stored bytes
refuse. Event append/read approvals are never reused for body operations, and the
reverse; each requires its own approval.

A descriptor append fails closed unless the adapter found the exact body its first
32 envelope bytes name already durably staged, and it acknowledges only after the
descriptor's durable commit. An unreferenced staged body left by a failed append
is an acceptable orphan; an acknowledged descriptor with no durable body is not.
Bodies stay in the ordinary store until archival is designed; this interface does
not choose where they are archived or when they are deleted.

## Ordering, removal and uncertain outcomes

The complete hosted path must share one protected execution lane between an
account's own-base access and account authority changes. Merely protecting
approval issuance with a mutex is insufficient: an account removal could commit
while an old approval remained usable at an unchanged base head.

The required sequence is:

1. Authenticate the request privately. Establish current verified account and base
   authority, including timed changes. Catch up required account-change controls
   into the base before further content writes; affected old epochs are closed.
2. Select exact request bytes and validity bounds. Persist the outstanding
   approval in protected storage **before releasing it**. Hold the lane through
   consumption and outcome reconciliation.
3. At the sequencer, verify the checker signature and operation binding, expected
   head, incarnation, next access sequence and conservative consumption time.
4. In one transaction, compare the complete prior gate state, consume the sequence,
   append or find the original committed event, and persist the resulting head
   and receipt. Release an Ack or selected read bytes only after durable commit.
5. Authenticate the exact receipt in the protected lane before advancing it or
   allowing the next authority change/access operation.

Account mutation submission must use this same lane. A verified account snapshot
is necessary but does not implement serialization. A lane cannot postpone a
removal deadline: consumption-time checks must reject a pre-deadline approval
held until after its authority ceases. Remaining devices may need to supply fresh
epoch keys; the checker cannot create them.

A lost Ack does not mean an append failed. Reconcile its exact operation first.
A subsequent authorized append retry uses the original event id/bytes but a new
operation approval and access sequence. The replay index returns its original
commitment, never another position. Different bytes for the same event id are
rejected. Looking up an old Ack also needs fresh authority; removal does not leave
an authorization-free replay path.

An archival lookup outage is not proof that an event id is absent. The adapter
must fail closed rather than create a second append. Archival and bounding that
index are outside this kernel.

`ExecutionLane` models unavailable, ready and pending states. It has no method
that clears pending work on timeout. An unresolved operation must be reconciled
or durably fenced at storage before the lane can resume. An abandoned grant may
also be resolved when authenticated storage shows its sequence unconsumed **after**
any in-flight consumption transaction has finished or been excluded, and trusted
time under a validated host timing contract proves the approval can never be
consumed later. Expiry alone cannot clear uncertainty; this resolution has no
current `ExecutionLane` API. Every cold construction starts unavailable. Its
`establish`, `committed` and `fence` methods are **trusted host integration
boundaries**, not parsers accepting untrusted claims; adapters must authenticate
receipts and establish current state before calling them. The native SQLite
adapter supplies a last-outcome reconciliation record but no incarnation-fence
operation. This local state machine is not itself a distributed lock, persistent
storage, account-authority verifier or freshness proof.

## Recovery and client integrity

Durable storage handles ordinary process restarts, not coordinated malicious
rollback. Attestation, encrypted disk and correctly signed historical heads alone
do not prove that a snapshot is the latest. Recovery needs live protected
continuity or another qualified freshness source and reconciliation of outstanding
operations. Without it, the checker stays unavailable. A random new incarnation
by itself cannot rehabilitate an old permission snapshot.

Invalid remote history must stop client application and preserve the last
verified local state and outbox; never clear remembered heads to continue. Apply
verified incoming content and advance its local cursor in one local transaction.
A checker outage pauses new hosted access, not local reading or editing. A verified
device removal has its own account-data removal behavior; a service failure or
unverified removal claim cannot trigger that action.

No diagnostics should include request bytes, identity-bearing inputs, IPs or a
stable substitute actor/audience handle. Fixed refusal classes are available;
logging arbitrary error context is not part of this interface.

## Permissions

The hosted permit codec (`permit.rs`) is separate from the older exact-operation
approval lane. All integers are big-endian; every version is `u16 = 1`. An
independently pinned root certifies a permit-signing public key in a 130-byte
certificate: `version:2 || root:32 || permit_key:32 || Ed25519_root_signature:64`.
The root signs `"bh/permit-key/v1\0" || first_66_bytes`. Receipt certificates
have a different signing domain and cannot authorize permits.

A signed permit is `certificate:130 || permit_body || Ed25519_signature:64`.
The permit key signs `"bh/permit/v1\0" || permit_body`. The body is:

```
version:u16 = 1 || scope_tag:u8 || log_kind:u8 || log_id:32
|| scope_fields || issued_ms:u64 || deadline_ms:u64 || batch:16
```

Log kind 1 is a base and 2 an account-home log. Scope tags and fields are:

| Tag | Scope | Fields |
| --- | --- | --- |
| 1 | ReadEvents | first:u64, last:u64 (inclusive, 1–64 positions, first ≥ 1) |
| 2 | ReadBodies | count:u16 (1–64), count × commitment:32 |
| 3 | Stage | body_commitment:32, exact_length:u32 |
| 4 | Append | event_digest:32, body_present:u8 (0 or 1), optional body_commitment:32, epoch:32, after_present:u8 (0 or 1), optional predecessor (`position:u64 || hash:32`), attached_present:u8 (0 or 1), optional attached_commitment:32 |
| 5 | Subscribe | none |
| 6 | ReadControls | after:u64 |
| 7 | StoreHomeObjects | prefix_digest:32, bundle_digest:32 (account-home logs only) |
| 14 | ReadControlRange | after:u64, through:u64 (bounded inclusive endpoint) |

An Append with a predecessor is a control, ordered on the control route; its
predecessor is the log's **control head**, the last control-route event (the
empty head before genesis), not the log head. Its `epoch` is the epoch in effect
once it is ordered, and all zero means the epoch is closed. An Append without a
predecessor is content, on the content route; its `epoch` is the epoch the log
must be in. Only a control with a body may name an attached body, distinct from
its own: a second staged body (a rekey's seal set) that its own body commits to.
The log orders the attached body with the event, under the same staging checks,
so it is kept like the event's own body. ReadControls selects up to 64 control-route events after position
`after`; `after = 0` is the empty head, so that read starts at the genesis.
ReadControlRange additionally freezes the exact inclusive `through` endpoint;
returning fewer controls does not silently lower it.
The caller must bind the signed scope to the actual operation and enforce the
predecessor at use. Verification requires the caller's pinned root and trusted
`now_ms`; permits are valid only from issuance until strictly before deadline,
with `0 < deadline_ms - issued_ms ≤ 30_000`. The authorization service chooses
`batch`; it is not a reusable read grant. All framing is exact and rejects extra
bytes. An append acknowledgement is `version:1 || log_kind:1 || log_id:32 ||
routed_event_id:32 || position:u64 || global_head_hash:32 || receipt_present:u8 ||
optional_receipt:300`. The optional receipt must be verified separately against
the pinned hosting root and head; Ack framing is not an authenticity proof.

### Private initial home objects

StoreHomeObjects permits exactly one immutable signup bundle at the authenticated
account's home, not a history append or permission to retrieve recovery material.
The prefix digest is the verified original signup account-chain head hash, **not**
the outer account-log head. The service requires the three-event prefix already
ordered, refreshes current device authority, and checks all three ciphertexts
against that historical prefix's signed commitments.

The bundle is big-endian `version:u16 = 1`, then three `length:u32 || bytes`
fields: recovery record (242 bytes), device seal (1299), recovery seal (1299).
Exactly 2854 bytes, no padding or trailing bytes. Its transport digest is
`H("bh/home-objects/v1\0" || bundle)`, independent of the existing signed
record and seal commitments. The account home inserts only if absent, refuses
any changed digest or bytes under that prefix as Conflict, and awaits storage
sync before acknowledgement, including on exact retries. It takes no append
position, has no public read path, and does not use body staging or its cleanup.

## Data wire

This coordinated format switch requires matching producers and consumers. It
refuses version-2 data frames; there is no length-based fallback. Canonical
commitments and signed binding-3 originals change with it, while account
original signatures remain unchanged.

Each WebSocket message is exactly one binary frame (`wire.rs`) no larger than
4 MiB + 64 KiB, with `version:u16 = 3 || tag:u8 || request_id:u32 || fields`.
All variable byte strings are `length:u32 || bytes`; count fields are `u16`.
Request tags: 1 Read (`permit`); 2 Stage (`permit, body`); 3 Append (`permit,
event`); 4 Subscribe (`permit, after:u64`); 5 Credit (`bytes:u32`, at least 1);
6 StoreHomeObjects (`permit, bundle`); 32 Publish (`stage_permit:blob,
append_permit:blob, event:blob, body:blob`).
Credit answers no request, so its request id is always 0. Read's actual
selection is in its signed permit. Response tags: 1 Events (`count:u16,
last_item_receipt_present:u8, optional_receipt:300, coverage_tag:u8,
optional_endpoint, count × (commitment:blob, event:blob)`); 2 Body (`index:u8,
last:u8, bytes:blob`); 3 Staged (no fields); 4 Acked (`ack:blob`);
5 Head (`position:u64, hash:32, receipt_present:u8,
optional receipt`); 6 Refused (`reason:u8`); 7 HomeObjectsStored
(`prefix_digest:32, bundle_digest:32`, exactly 71 bytes including framing);
32 Published (`ack:blob || commitment:149`, exactly one canonical commitment).
Event response count cannot exceed
64. Body index is 0–63 and `last` is exactly 0 or 1. For a body read the edge
sends one Body frame for each selected commitment, in the permit's order, with
index equal to its zero-based position and `last = 1` only on the final frame.
A missing body instead produces `Refused { id, reason: Missing }`, ending the
stream for that request id; no more Body frames follow. Each body gets its own
frame so a maximum-size 4 MiB body fits with its framing overhead. Events remain
in one frame because at most 64 fixed-size envelopes fit. Refusal reasons 1–10 are
Expired, Scope, Epoch, Predecessor, Conflict, NotStaged, Reclaiming, Missing,
Malformed and Unavailable, in that order. Encoders preflight total size with
checked arithmetic before copying payloads. Decoders refuse truncation, unknown
tags, unsupported versions, oversize frames, trailing bytes, and a Credit with a
nonzero request id or zero bytes. Transport framing does not verify permission,
event authors, receipts or durable outcomes; those checks belong to the consumers.

The last-item receipt flag is 0 or 1; a present receipt is exactly 300 bytes,
without a length prefix. Nonempty ordinary base ReadEvents responses use it
for the exact **last returned** commitment; empty and account-log full reads
omit it. Full/account responses have coverage tag 0. Sparse control responses
instead have **no** last-item receipt and carry an endpoint independent of the
returned controls: tag 1 is the 82-byte EMPTY opening without a receipt; tag 2
is a nonempty 82-byte opening followed by its exact 300-byte hosting receipt.
Other tags and opening/receipt combinations are refused. This transport of an
endpoint does not by itself establish raw-control coverage or authority; those
checks are a separate consumer gate.

The log object captures sparse rows **and the exact endpoint at the permitted
through-position** in one synchronous read section before awaiting storage
sync; an unbounded read freezes its then-current endpoint. A missing nonempty
endpoint refuses. A failed durability barrier returns Unavailable, never rows
or an endpoint for the edge to sign. The edge signs the captured endpoint even
for an empty sparse page. Full-read receipts prove ordering only: clients must
still verify the extension, originals and bodies before atomic application.
At 64 maximum envelopes, a full Events frame with its receipt is
`7 + 2 + 1 + 300 + 1 + 64 × (4 + 149 + 4 + 65574) = 4,207,095` bytes;
a sparse frame with nonempty endpoint is
`7 + 2 + 1 + 1 + 82 + 300 + 64 × (4 + 149 + 4 + 65574) = 4,207,177` bytes.
Both fit the unchanged 4,259,840-byte limit. Credit covers every received byte.

The edge checks a request's permit deadline before sending **each** of its data
frames (Events, Body, Staged, Acked, Head and HomeObjectsStored). Past the deadline it withholds the
frame and sends `Refused { id, reason: Expired }` for that request id only; other
requests and the socket continue, and nothing more is sent for that id. A
withheld Staged, Acked or HomeObjectsStored does not undo the stage, commit or
immutable write; an exact retry under a fresh permit learns its outcome.
A subscription ends the same way at its permit's deadline, unless a newer
Subscribe for the same log on that socket has replaced it first.

Data frames are flow-controlled per socket. Each socket starts with a send window
of 8 MiB + 64 KiB: one largest frame plus 4 MiB. Every data frame takes its
encoded length from the window; Refused frames take none. A frame the window does
not cover waits, in arrival order, and the edge reads no stored body for it until
the window covers it. A waiting frame still ends `Expired` at its deadline. A
Credit frame adds `bytes` to the window, and a device keeps data flowing by
granting back each data frame's length once it has processed that frame. A grant
that takes the unused window above 64 MiB is a protocol violation; the edge
closes the socket with 1008.

## Checks and integration limits

In the product workspace run `cargo test --locked -p bh-sync`,
`cargo clippy --locked -p bh-sync --all-targets -- -D warnings`, and
`cargo fmt --all --check`. The native SQLite consumption adapter lives in
`services/sync/` and has separate tests; it is not a hosted endpoint. A standalone
product checkout includes the shared cryptographic library and its documented
libsodium build requirements.

The tests cover strict framing, mutations, common history, exact operation
binding, replay, conservative expiry, lost-Ack planning and unavailable/pending
lane transitions. They do not establish real account removal, attested transport,
rollback-resistant recovery, SQLite/R2 atomicity, workerd behavior, native-client
convergence or hosted deployment. Those require the corresponding real adapters
and cross-component tests; this library deliberately provides no fake account or
hardware verifier for a hosted entry point to select.
