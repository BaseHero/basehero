# Bundled note engine

The core's yrs implementation is compiled for `wasm32-unknown-unknown`, then
precompiled to Pulley by `artifact/build.rs`. Applications embed only that
build's serialized module and load it with the pinned Wasmtime release and
shared configuration. Upgrading Wasmtime rebuilds the artifact. The guest has
no imports, and no network-supplied artifact is accepted.

Each open note has its own instance, capped at 256 MiB of linear memory.
Each public operation gets 12,880,000,000 fuel, covering guest allocation,
calls and output extraction. An ordered open applies all segments in one
guest invocation. Compaction shares its one budget across state/digest reads
and a scratch verification instance. Output ranges are checked against linear
memory before host allocation and copying.

Every guest-dependent host operation is fallible, including constructors,
reads, compaction and fixture authoring. A trap, exhausted resource or invalid
ABI response returns local `NoteError::Unavailable`. Incoming errors separate
`IncomingError::Unavailable` from `Refused { reason, changed }`: only the latter
is a content judgement. There is no native fallback and no fabricated state,
digest, title or writer-prefix answer. Native comparison code on the host is
behind the explicit `native-oracle` test feature, enabled only by dev dependencies.

The host drops unavailable instances. Storage evicts a poisoned cache entry
and retries from its durable ordered state. Failed reads cannot publish a
checkpoint or title. Local saves fail without an acknowledgement or new rows;
existing pending bytes remain intact. Incoming application retains an unavailable
note's verified candidates in a durable local queue while committing unrelated
notes and advancing verified log progress. Its accepted state and pending work
stay unchanged. Exact own echoes awaiting judgment stop resending without
retiring pending work. The sync client retries each held note with backoff;
held content prevents a fully synced status. Decode checks reuse the live note
instance rather than allocating another guest.

The device's 512 MiB budget covers retained encoded prepared compaction/rebuild
buffers, not RSS or peak allocation. During retry, the previous successful prefix
and the next preparation coexist. A retry considers at most 64 candidates, but
optional compaction may repeat for each; the per-operation fuel limit is not a
whole-retry CPU limit. No peak-RSS or retry call-count qualification is implied.

## Measurement status

An intermediate Linux release build measured median/max 8.681/8.715 ms for a
64 KiB open, 0.136/0.154 ms for a 4 KiB apply and 158.007/163.135 ms for a
1M-position open. A hostile K2-fragmented million-item history took
2,995.418/3,230.118 ms and consumed 3,213,596,881 fuel in its largest call.
The configured fuel limit is four times that call rounded up to 3.22 billion.
The hostile history's open time is a known limit, not an optimization target.

These are **intermediate measurements**, before the fallible API and aggregate
open-budget correction; they are not final platform qualification. The replay
measurement is available as the ignored `measure_budgets` test in
`libs/core/tests/contained.rs`. Android/emulator and macOS product measurements,
APK/app size growth and real-phone behavior remain unmeasured by this build.
