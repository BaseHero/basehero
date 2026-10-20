# bh-event (native candidate)

Experimental, in-memory shared-audience event codec and historical verifier. This
is not a deployed event format, provisioning protocol, access checker, durable
outbox or source of current authority. Callers supply independently anchored base
and account introductions, locally provisioned independent metadata and content
roots, exact detached bodies, and ordered commitments. No code in this library
makes a hosted access approval or establishes private-audience membership.

The descriptor uses `bh-sync::OpaqueEvent`: 32-byte ciphertext commitment followed
by a 992-byte encrypted binding, yielding a 1024-byte envelope and 1062-byte
framed event. The separately transported body is padded to 1024, 4096, 16384,
65536, 262144, 1048576 or 4194304 bytes (`bh_sync::BODY_SIZES`); envelopes keep
`bh_sync::ENVELOPE_SIZES` (at most 65536) and this codec always writes 1024. A
body adds 46 bytes to its payload (nonce, tag, kind and length), so a 1 MiB body
holds up to 1048530 payload bytes. Both encryptions use native libsodium XChaCha20-Poly1305 with random
24-byte nonces. The body commitment hashes its exact ciphertext, nonce, tag and
size under `bh/payload-object/v1\0`; its signature binds that commitment,
author/device/account head, both author-seen heads, event/base/audience/epoch,
class, size, protocol version and capability, and from version 2 the hosting
receipt for the author's observed head. Its signed fields are encrypted
under an independent metadata root, not exposed in the ordinary event framing.
The content root never opens metadata/control bindings; the metadata root never
opens note bodies. After genesis, **every** binding requires the supplied metadata
root to match the genesis-signed metadata ID, including content whose signed epoch
names the independent content key. The content epoch ID and metadata root ID are
each the hash of the X-Wing public half derived with `bhKeyId1` from its root.
The per-use KDF contexts are `bhNote01`, `bhBind01`, `bhCtrl01` (id 0).

Genesis is the only zero-base event; its eventual descriptor digest becomes the
base ID. Its creator device signs with its ordinary signing key, and it names the
creator's independently verified account head at the moment of creation (not
necessarily account genesis). `prepare_genesis` seals the introduction and returns
bytes for external signing; `finish` checks the signature and returns the original
and base ID. `verify_genesis` checks the original against that account at the named
head and M, returning the base ID, author and M/K_e key IDs without needing K_e.
`History::with_account` and `History::replay_with_account` start from that same
anchored account snapshot, plus the independently pinned hosting root that
certifies receipt keys (`verify_genesis` needs no root: genesis has no receipt).
Later
events bind the final base ID; other control events use the device's second key.
Only signed account genesis, device
addition and self-removal are recognised in this slice; an outer control signature
cannot mutate account history. Self-removal closes this fixed content epoch.
No replacement-epoch, metadata-key distribution/rotation, private audience,
seals, delayed removals, snapshots or body upload/read protocol is implemented.
Version 1 is the base genesis only; its signed fields are 346 bytes and its bytes
are unchanged (`tests/fixtures/genesis-v1.txt` pins a complete genesis and its
base ID). Every later event is version 2: the encoder writes `(2,2)` and appends
the 300-byte `bh_sync::receipt` observed-head receipt for `seen` to the signed
fields (646 bytes). The verifier requires that receipt to verify under the pinned
hosting root for this base, with a head exactly equal to `seen`. A zeroed, wrong,
foreign-root or mismatched receipt is rejected, never awaited, because the
receipt carries its own root-signed certificate; without a pinned root a later
event pauses as unavailable (local configuration, not evidence). A receipt that
does verify but names another hash at a position this device verified is the
service contradicting itself: an integrity stop, whoever carries it. A v1 event
after genesis is rejected; an invalid genesis is an integrity stop. A higher
signed capability is accepted; a signed v3 binding is paused for unsupported
semantics, not interpreted as v2. A remembered event-version floor applies to
events after genesis only, so a device that has accepted v2 events still opens
its v1 genesis; a higher floor rejects v2.

After genesis, an invalid submission under this protocol (an original that does
not open or verify, a false claim about what its author had seen, an inactive
author, a reused event ID, a signed body size or commitment other than the
bytes the descriptor names, a malformed body or payload, an invalid account
control) is `Rejected`: `prepare` returns a rejected event
(`PreparedEvent::is_rejected`), and consuming it advances the chain with no
content, account or floor effect (`AppliedKind::Rejected`). Only evidence
against independently verified history stops: an order that does not continue
the verified head, body bytes other than the ordered descriptor names, a verified
receipt contradicting a verified head, or an invalid genesis. A metadata or
content root other than the base's is a key this device lacks: it waits. An
authentic event for an audience other than the base's ordinary one pauses as
unsupported.
Measured v2 sizes for a small note edit: 1024-byte envelope (1062 framed) and
1024-byte body. The receipt fits inside the existing 952-byte binding plaintext
(646 signed + 64 signature + zero padding), so no larger envelope class is used.

A note payload is `note_id[32] || writer[99] || update`: the note's ID, the
producing writer's `DeviceWriterDeclaration` and the Yjs v1 update
(`note_payload` builds it). A payload too short for both is rejected; a
declaration of an unsupported version or author tag pauses as unsupported.
History only decodes the declaration. `AppliedEvent::writer()` returns it and
`AppliedEvent::author()` the verified signer's account and device (None for a
rejected submission), so the
note owner can decide whether the declaration binds that author.

`History::inspect` verifies a descriptor, original signature and historical heads
without fetching a note body. `History::prepare(&mut self, ordered, descriptor,
Option<body>, metadata, Option<content>) -> Result<PreparedEvent, Outcome>` checks
the exact body, original and supported control/account semantics but does not
advance history, account or content. The owned, non-serializable prepared event
exposes only `note_id() -> Option<[u8; 32]>`: a supported note's authenticated
ID, or `None` for a control; the decrypted delta remains guarded inside it.
For device stores, use `History::materialize(&self, prepared,
Option<OwnedNoteTarget>) -> Result<Materialized, MaterializeError>`. Hand over
**exclusive ownership** of the working Note selected by the authenticated ID
(or no Note for controls). A wrong target or stale predecessor returns the Note
unchanged in the error. A successful update applies once, in place, without
encoding/replaying the old full Note. `WorkingNote::Accepted` is working state
until the owner commits and decides to expose it, not a type-enforced UI gate.
A malformed yrs Decode yields `Untouched` (same working Note), while a yrs
Apply error drops the possibly changed Note and returns a payload-free `Poisoned`
marker: reload from committed local state. Both rejections advance common order
as `ContentRejected` once committed.
The Note is separately owned from the bounded `Transition`: dropping a transition
or a failed commit cannot modify the live History. `transition.applied()` binds
the exact ordered `Commitment` and its encoded bytes, original encoded descriptor,
body bytes and body commitment, plus the resulting head, floor and outcome.
`History::publish_committed(transition)` consumes those bounded effects and
refuses a stale prestate or integrity stop. Only the trusted device-store owner
may call it, after the real transaction commits this transition's exact originals,
outcome and progress. The library cannot prove SQLite COMMIT; the store must
also fence its own target Note revision and, for hidden bases, unlock generation
before exposing accepted Note state.
Cold Note loading is a separate store load path (local checkpoint plus per-note
tail), not an O(delta) promise for a cache miss.

`History::consume_unapplied(&mut self, prepared) -> Result<AppliedEvent,
ConsumeError>` is the note owner's path: it advances against the exact
predecessor and touches no Note. A note event is `NoteAccepted { delta }`
unless its delta is not a Yjs v1 update (`NoteRejected`); whether it
integrates is the owner's judgement on its own accepted state.

`History::consume(&mut self, prepared, Option<NoteTarget>) ->
Result<AppliedEvent, ConsumeError>` remains the older compatibility API. It
compares the same predecessor and applies on a disposable full-state copy before
advancing History; it is not the device-store per-event path.
`kind()` distinguishes `NoteAccepted { note_id, delta }` (a wiped-on-drop
`SecretBytes` with `expose()`), `NoteRejected { note_id }` (no delta),
`Control` (no Note) and `Rejected` (an invalid submission). `outcome()` preserves the accepted/rejected classification.
Debug formatting never prints decrypted content. A stale or wrong local selection
consumes the value but changes neither history nor Note and is not a remote
integrity stop. An identical independently trusted clone of the predecessor may
consume it; a changed state cannot. Preparation latches a stop on
`IntegrityStop` without advancing the verified checkpoint. Persist a stop marker
with the **unchanged prior verified head**, never the failing raw input. On open,
`History::replay(account_id, account_genesis, base, hosting_root, floor_rises,
metadata, content, records)` reconstructs the verified history from independently anchored
introductions and roots, re-verifying each `(Commitment, descriptor bytes, body
bytes)` in order with prepare's checks, then advancing the chain and controls
without applying Note updates. Supply only **persisted applied originals** to
replay, never downloaded but unapplied ciphertext; after replay the adapter must
compare `replay.head()` with its persisted verified cursor so a truncated store
cannot silently become the new checkpoint. A gap, reorder, duplicate ID, bad
original/body or wrong anchor refuses replay. `floor_rises` are the stored
`(position, floor)` rises (`AppliedEvent::judged_floor` and `floor`): each event
is judged under the floor in force when it was ordered, never a later one.
After replay, a stored stop marker calls `mark_stopped()`, which only
restricts future consumption. Replay costs O(history) and requires retained
bodies and roots, so a routine reopen resumes instead.

`History::resume(anchor, base, hosting_root, continuation, account_changes,
lookup, remembered_floor)` continues from a durable verified continuation
without replaying anything. A store keeps, per applied event,
`AppliedEvent::seen()` by position and the first digest per event ID, plus the
exact verified account events (`AppliedEvent::account_change()`) and the
latest `AppliedEvent::continuation()`. `HistoryLookup` answers point queries
for positions and IDs below the continuation, so memory holds only what was
judged since. Resumed local state that does not reproduce the continuation,
or a lookup that fails, is `UnavailablePause`; nothing is judged.
`hosting_root` must be the root pinned when the base was registered, taken
from its authenticated hosting association, never invented; the device store
refuses any other (`AppliedEvent::hosting_root()`).
Unsupported/missing inputs pause, not skip.
`History::apply` remains an externally known-note compatibility wrapper around
prepare/consume: a guessed wrong note ID retains its earlier integrity-stop
behavior. No ID is readable in O; the verifier supplies routing only after opening
B. Authenticated malformed Yjs rejects content while advancing the ordered event
and retaining the prior Note. This cryptographic result is **not** an unlock or
current-authority credential.
The store persists the **transition's exact originals and commitment**,
accepted delta or rejection, verified cursor and floor in **one transaction**,
with a predecessor/generation compare at commit. Publish the transition and
cache its usable Note only after COMMIT; on failed commit, drop both and reload
from committed local state, preserving unsent work. The failed Apply Note is
discarded, even when the rejection itself commits. A hidden base additionally
fences its current unlock generation: historical verification does not authorise
a late plaintext write after relock. The store owns durable atomicity; this
library does not implement a transaction or a second device store. Do not accept
a second raw-byte argument with a `verified` flag, or treat this result as an
access credential. Retry using the same `Encoded` bytes; resealing is a new
random package, not durable resend/outbox proof.
The encoder resolves key availability before copying payload bytes. Its owned
padded payload and binding scratch use `SecretBytes::from_parts`, which wipes those
owned allocations on drop, including error paths. Borrowed input, intermediate
signed-field copies, Note state and incidental compiler/OS copies are outside
those owners. This is not a hidden-lock memory-lifetime proof. For local tests:
`cargo test --locked -p bh-event`.
