# Local public authorization issuer (v1)

The separate `release-sign` binary checks an already signed public release
artifact without reading a seed:

```
release-sign verify VERSION PLATFORM CHANNEL SOURCE_COMMIT PUBLIC_KEY METADATA_FILE ARTIFACT
```

`VERSION` must be positive and exactly match the signed metadata. The caller
supplies the expected source commit, release public key, platform and channel
independently; the artifact basename must match the signed filename. The
metadata JSON is bounded to 1 MiB. Verification uses the existing release
signature and hashes the exact supplied artifact bytes. Success prints only
`release verified`; failure exits nonzero with empty stdout. This is an
exact-request check, not proof of a globally newest release, installation, or
source provenance. Keep the staged artifact immutable after checking it.
Earlier locally prepared sync deployment snapshots may need re-preparation
under the corrected deployment identity. Newly prepared snapshots tolerate
relocation of identical registry manifest bytes; the raw bytes and immutable
reference are still checked at final configuration.

Build `bh-release` with its **non-default** `authorization-tools` feature. This supplies the public-request `authorization` library and `authorization-sign` binary. This local primitive does not choose, store, generate or retrieve an authority seed; only `sign` reads a 64-character lowercase hex seed from hidden stdin (one line, maximum 66 bytes including line ending). Do not pass it through arguments, a file flag or an environment variable. Inspect and verify require no seed. All failures produce empty stdout and a fixed, content-free stderr message. The tool creates no output files; redirect public stdout only after a successful exit.

Example public JSON request (no secrets):

```json
{"format":1,"public_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","product_tree":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","root":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","artifacts":[{"path":"evidence/record.json","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}],"operation":{"kind":"policy","payload_hex":"...","generation":1,"limits":{"max_lifetime_secs":3600,"max_uncertainty_secs":5},"mode":"initial","predecessor":null}}
```

The policy payload is exact lowercase hex of the already-defined policy JSON wire bytes (at most 65,536 bytes). An `advance` or `retry` operation supplies `predecessor: {"payload_hex":"...","signature_hex":"..."}`. Advance strictly increases generation; retry keeps exactly the same payload. Initial issuance requires generation 1 and null predecessor. Offline structural validation and a real policy gate authenticate the predecessor; no wall clock is invented to declare a scheduled or expired policy currently usable. A withdrawal can have empty allowlists. The workflow, not the issuer, must choose the approved predecessor; this has no global generation registry.

Alternatively, `operation` is `{"kind":"receipt","leaf_public_key":"..."}` or `{"kind":"permit","leaf_public_key":"..."}` with exactly 64 lowercase hex digits. These operations certify a leaf in their separate existing wire domains. They do **not** issue a receipt, permit or policy. The workflow must independently pin the authority root and its intended role; arbitrary Ed25519 public bytes are not evidence of that role.

All expected values must be provided independently by a trusted caller, never read back from the request. The CLI shape for each of `inspect`, `sign` and `verify` is:

```
authorization-sign COMMAND REQUEST --request-sha256 HEX --expected-root HEX --public-commit SHA --product-tree SHA --kind policy|receipt|permit --artifacts DIR
```

For `verify`, also pass `--signed FILE` containing the versioned JSON stdout of `sign`. The request file is bounded to 1 MiB, the result file to 1 MiB, and the exact raw request SHA-256 (including its formatting) is checked. The artifact paths must be unique, relative regular files with no traversing or symlink component, and their hashes are streamed. Hold this directory as a private immutable approval snapshot for the entire inspect/sign/verify sequence: this tool checks content at inspection time and does not itself protect against subsequent replacement or prove what those files mean. The public `inspect` summary includes source/tree/root, artifact paths and hashes, plus policy fields or certificate leaf intent.

The public signed result has `{"format":1,"request_sha256":"...","value":{"kind":"policy","payload_hex":"...","signature_hex":"..."}}` or a `receipt`/`permit` `value` with `certificate_hex`. The provenance/request-hash wrapper is **not** covered by the existing policy or certificate wire signature: `verify` compares it to the caller-pinned checked request and invokes the existing cryptographic verifiers on exact wire bytes. Certificate issuance alone is not publication. A protected workflow must still authenticate Git ancestry/source and product tree against trusted inputs, qualify actual release artifacts and prepared deployment, compare approved measurement/machine evidence to the exact policy semantically (hashing a file is not verifying its contents or hardware), approve predecessor and root-role custody, and sign the exact public policy-result file using existing release metadata before publication. No credential should be requested until those checks are complete.
