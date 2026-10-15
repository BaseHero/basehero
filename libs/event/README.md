# bh-event (native candidate)

Experimental, in-memory shared-audience event codec and historical verifier. This
is not a deployed event format, provisioning protocol, access checker, durable
outbox or source of current authority. Callers supply independently anchored base
and account introductions, locally provisioned independent metadata and content
roots, exact detached bodies, and ordered commitments. No code in this library
makes a hosted access approval or establishes private-audience membership.

The descriptor uses `bh-sync::OpaqueEvent`: 32-byte ciphertext commitment followed
by a 992-byte encrypted binding, yielding a 1024-byte envelope and 1062-byte
framed event. The separately transported body is padded to 1024, 4096, 16384 or
65536 bytes. Both encryptions use native libsodium XChaCha20-Poly1305 with random
24-byte nonces. The body commitment hashes its exact ciphertext, nonce, tag and
size under `bh/payload-object/v1\0`; its signature binds that commitment,
author/device/account head, both author-seen heads, event/base/audience/epoch,
class, size, protocol version and capability. Its signed fields are encrypted
under an independent metadata root, not exposed in the ordinary event framing.
The content root never opens metadata/control bindings; the metadata root never
opens note bodies. After genesis, **every** binding requires the supplied metadata
root to match the genesis-signed metadata ID, including content whose signed epoch
names the independent content key. The content epoch ID and metadata root ID are
each the hash of the X-Wing public half derived with `bhKeyId1` from its root.
The per-use KDF contexts are `bhNote01`, `bhBind01`, `bhCtrl01` (id 0).

Genesis is the only zero-base event; its eventual descriptor digest becomes the
base ID. Later events bind that final ID. Only signed account genesis, device
addition and self-removal are recognised in this slice; an outer control signature
cannot mutate account history. Self-removal closes this fixed content epoch.
No replacement-epoch, metadata-key distribution/rotation, private audience,
seals, delayed removals, snapshots or body upload/read protocol is implemented.
The version-1 encoder writes `(1,1)`; the verifier also recognises signed `(1,2)`
as capability only and refuses an independently remembered higher event-version
floor. A signed v2 binding is paused for unsupported semantics, not interpreted as
version 1.

`History::inspect` verifies a descriptor, original signature and historical heads
without fetching a note body. `History::prepare(&mut self, ordered, descriptor,
Option<body>, metadata, Option<content>) -> Result<PreparedEvent, Outcome>` checks
the exact body, original and supported control/account semantics but does not
advance history, account or content. The owned, non-serializable prepared event
exposes only `note_id() -> Option<[u8; 32]>`: a supported note's authenticated
ID, or `None` for a control; the decrypted delta remains guarded inside it.
`History::consume(&mut self, prepared, Option<NoteTarget>) ->
Result<AppliedEvent, ConsumeError>` requires the Note selected by that ID or
**no Note** for controls. It compares the exact relevant in-memory predecessor
(base, common head/control, account head, metadata/content epoch IDs, version
floor, counts and stopped status) before applying a delta on a disposable Note
or publishing a validated account candidate. Its non-forgeable owned result
binds the exact ordered `Commitment` and its encoded bytes, original encoded
descriptor, body bytes and body commitment, plus the resulting head and floor.
`kind()` distinguishes `NoteAccepted { note_id, delta }` (a wiped-on-drop
`SecretBytes` with `expose()`), `NoteRejected { note_id }` (no delta), and
`Control` (no Note). `outcome()` preserves the accepted/rejected classification.
Debug formatting never prints decrypted content. A stale or wrong local selection
consumes the value but changes neither history nor Note and is not a remote
integrity stop. An identical independently trusted clone of the predecessor may
consume it; a changed state cannot. Preparation latches a stop on
`IntegrityStop` without advancing the verified checkpoint. Persist a stop marker
with the **unchanged prior verified head**, never the failing raw input. On open,
`History::replay(account_id, account_genesis, base, remembered_floor, metadata,
content, records)` reconstructs the verified history from independently anchored
introductions and roots, re-verifying each `(Commitment, descriptor bytes, body
bytes)` in order with prepare's checks, then advancing the chain and controls
without applying Note updates. Supply only **persisted applied originals** to
replay, never downloaded but unapplied ciphertext; after replay the adapter must
compare `replay.head()` with its persisted verified cursor so a truncated store
cannot silently become the new checkpoint. A gap, reorder, duplicate ID, bad
original/body or wrong anchor refuses replay; a remembered version floor is never
lowered. After replay, a stored stop marker calls `mark_stopped()`, which only
restricts future consumption. Replay currently costs O(history) on each open and
requires retained bodies and roots; no snapshot checkpoint is provided.
Unsupported/missing inputs pause, not skip.
`History::apply` remains an externally known-note compatibility wrapper around
prepare/consume: a guessed wrong note ID retains its earlier integrity-stop
behavior. No ID is readable in O; the verifier supplies routing only after opening
B. Authenticated malformed Yjs rejects content while advancing the ordered event
and retaining the prior Note. This cryptographic result is **not** an unlock or
current-authority credential.
The consuming store must persist the **applied result's exact originals and
commitment**, updated Note (only for `NoteAccepted`), verified cursor, floor and
outcome in **one transaction**, with a predecessor/generation compare at commit.
For a hidden base this includes the current unlock-generation check: successful
historical verification does not authorise a late plaintext write after relock.
`consume` advances the in-memory History and Note **before** that transaction
commits. If commit fails or the generation compare loses, discard both advanced
values (replay or start from a pre-consume clone); never continue consuming from
the uncommitted state. Do not accept a second raw-byte argument with a `verified`
flag, or treat this in-memory result as an access credential. The store owns
durable atomicity; this library does not implement a transaction. Retry by
reusing the same `Encoded` bytes; sealing again is a new random package;
serialization identity here is not a durable resend/outbox proof.
The encoder resolves key availability before copying payload bytes. Its owned
padded payload and binding scratch use `SecretBytes::from_parts`, which wipes those
owned allocations on drop, including error paths. Borrowed input, intermediate
signed-field copies, Note state and incidental compiler/OS copies are outside
those owners. This is not a hidden-lock memory-lifetime proof. For local tests:
`cargo test --locked -p bh-event`.
