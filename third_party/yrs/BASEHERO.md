# yrs 0.28.0

This directory is the crates.io `yrs` 0.28.0 archive, SHA-256
`52c70dc8beca8666c77612a96889106ca3cd65318609721f464624ff79685da9`,
from y-crdt/y-crdt commit `23b7f5693bbf9e7d26340c521ee8647f79bdfba2`.
The upstream MIT licence at that commit is included in `LICENSE`.

Local source changes are restricted to `src/encoding/varint.rs`, `src/id_set.rs`,
`src/update.rs`, and `src/updates/decoder.rs`: reject out-of-range v1 integer
widths, clocks and client IDs, checked signed integer magnitudes, and duplicate
client sections before applying updates. The upstream test expecting a truncated
buffer error now expects the earlier checked-width error. The standalone
`[workspace]` declaration in Cargo.toml prevents this vendored package becoming
an implicit workspace member. Its `[lints.rust] warnings = "allow"` matches the
registry dependency's lint treatment when used as a path patch. Encodings emitted for valid input are unchanged.
No general resource-exhaustion bound is implied.

To compare with upstream, unpack the above crate archive and diff its `src/`
against this directory's `src/`. The workspace root patches crates.io resolution
to this path; this directory is excluded from workspace members. The upstream
lib suite needs test assets absent from the crate archive; download the VCS
archive from
https://codeload.github.com/y-crdt/y-crdt/tar.gz/23b7f5693bbf9e7d26340c521ee8647f79bdfba2
(SHA-256 `81d19865eca3c6fc2509b76c3d10207b9b78faf466ac16b88c46995d53b6ef25`),
unpack it, copy this directory beside the archive's `assets/` (for example,
`yrs-checked/` at its root), and run `cargo test --lib` in that copy.
