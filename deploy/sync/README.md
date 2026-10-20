# Local sync release preparation

These tools build and configure local artifacts. They never deploy, upload an
image, provision infrastructure, obtain a quote, or contact a hosting API.

From a checkout, with an exact reviewed commit and a new output directory:

```sh
CARGO_TARGET_DIR=/absolute/private/cargo-target \
  python3 scripts/prepare-sync-release.py build --source COMMIT --output /absolute/new-bundle
```

The builder archives only the committed product subtree (also works at a public
repository root). Dirty/untracked files and development Wasm are not inputs.
It uses the committed Cargo/flake locks, the project's pinned Rust toolchain
including wasm32, and the real note-engine Wasm → Pulley build. The Nix default
feature authz package and Docker/OCI-compatible archive contain the runtime
loader/libraries and CA roots, not compilers, fixture keys or synthetic mode.
The release Worker includes its Wasm, four runtime JS modules and crypto host
module with their relative import layout intact. Full command output and exit
codes remain under `logs/`; failures preserve the output directory for diagnosis.
Use a new output directory on retry; no arbitrary directories are removed.

`manifest.json` identifies the source commit/product tree, lock hashes, every
artifact hash and the local image tag/config digest/archive hash. The image tag
is derived from the Nix package identity. The image config digest is its local
image ID, **not** a registry manifest digest or hardware measurement. No registry
reference is invented. Loading that exact archive and publishing it are separate
authorized operations. The local image tag is useful for image smoke only, **not** as a measured
content identity. After a separately authorized push, supply
`registry/repository@sha256:DIGEST` and an absolute path to the raw public
OCI/Docker **image manifest** (not an image index). Preparation checks that
file's SHA-256 against the reference and its config digest against the bundle's
image ID. Docker Compose uses `pull_policy: missing` with that immutable digest.
No mutable tag fallback or registry query is performed. Registry availability
is an operational check.

## Operator input

Copy `operator-inputs.example.json` outside the bundle and fill the required
fields. The example deliberately fails validation. First, with explicit empty
`endpoint.policy` and `endpoint.policy_signature` and even if runtime key, policy,
certificate and collateral files do not exist yet, prepare the candidate:

```sh
python3 scripts/prepare-sync-release.py prepare-deployment \
  --bundle /absolute/new-bundle --inputs /absolute/operator-inputs.json \
  --output /absolute/new-deployment
```

The public endpoint fields are checked by the existing Rust app parser in
preparation mode, but preparation does **not** check signatures, open runtime
files, or output a deployable endpoint/Worker config. Its manifest pins the
bundle, public deployment inputs, immutable registry identity, file set, and
`compose_sha256_candidate`. `deployment/compose.json` is Docker Compose;
`deployment/app-compose.json` is the complete dstack **0.5.9 AppComposeV2**
with sorted compact UTF-8 JSON SHA-256 candidate. It specifies KMS-encrypted
storage, disabled public logs/sysinfo/TCBinfo, a fixed measured prelaunch,
explicit allowed environment names, and no automatic SSH/user_config. No
unmeasured bootstrap, arbitrary script hook, model/worker capability, or
onchain KMS is introduced. Signing a policy does not change these bytes.

The five runtime files are provided later as **encrypted environment inputs**
for the fixed measured prelaunch, not embedded in app-compose, CLI arguments or
public config. The local `authz.files` paths are for final *local* validation,
never remote bind paths:

| Local input reference | Encrypted input name | Fixed VM file (mode 0600) | Container target (read-only) |
| --- | --- | --- | --- |
| `authz.files.permit_key` | `BH_AUTHZ_PERMIT_KEY` | `/dstack/bh-authz-runtime/permit_key` | `/run/config/permit_key` |
| `authz.files.permit_cert` | `BH_AUTHZ_PERMIT_CERT` | `/dstack/bh-authz-runtime/permit_cert` | `/run/config/permit_cert` |
| `authz.files.policy` | `BH_AUTHZ_POLICY` | `/dstack/bh-authz-runtime/policy` | `/run/config/policy` |
| `authz.files.policy_signature` | `BH_AUTHZ_POLICY_SIGNATURE` | `/dstack/bh-authz-runtime/policy_signature` | `/run/config/policy_signature` |
| `authz.files.collateral` | `BH_AUTHZ_COLLATERAL` | `/dstack/bh-authz-runtime/collateral` | `/run/config/collateral` |

Registry pull uses `DSTACK_DOCKER_REGISTRY` (must equal the image registry),
`DSTACK_DOCKER_USERNAME`, and `DSTACK_DOCKER_PASSWORD`; the prelaunch writes
a mode-0600 standard Docker auth config at `/dstack/bh-registry/config.json`
in a mode-0700 directory for exactly that registry, then exports `DOCKER_CONFIG`
for the following Docker Compose pull in the sourced shell. Neither credential
enters a subprocess argv. The actual dstack image pull's use of that Docker
client config is an explicit provider compatibility check before creating a VM;
a mismatch must fail closed. The runtime directory is
private (0700) and owned by explicit UID/GID. Shell environment values cannot
contain NUL; each other byte, including trailing newlines, is materialized
without normalization. Authorized provisioning must supply these values via
its encrypted-environment mechanism; this tool never reads them or emits a
plaintext secret bundle. It creates the explicitly selected protected data
directory if missing (0700, owned by UID/GID), and leaves any existing directory
and its contents alone, refusing wrong ownership. Protection of that host path
is still a hardware/operator qualification, not a renderer guarantee.

An operator may compare a saved provision response **offline** after an
authorized, separate provider operation:

```sh
python3 scripts/prepare-sync-release.py compare-provision \
  --deployment /absolute/new-deployment --response /absolute/saved-response.json
```

The hash must equal the local candidate, and a returned `compose_file` object,
if present, must equal the exact prepared object. Supplied JSON is not
authenticated provider evidence; mismatches are refusals, never new expected
hashes. Compare and qualify actual provider canonicalization, measurement,
machine/boot evidence and registry behavior before obtaining an approved signed
policy. **No provider operation is performed by these commands.**

With an approved signed policy whose `checker` build pins exactly this prepared
candidate, fill `endpoint.policy` and `endpoint.policy_signature`, provide the
matching local runtime files and then finalize:

```sh
python3 scripts/prepare-sync-release.py configure \
  --bundle /absolute/new-bundle --deployment /absolute/new-deployment \
  --inputs /absolute/operator-inputs.json --output /absolute/new-config
python3 scripts/prepare-sync-release.py verify-config --config /absolute/new-config
```

The verification command checks the entire generated file set and hashes plus
the endpoint's actual bytes against `public_config_sha256`, and prints the exact
endpoint path to hand to app packaging. Changing deployment inputs, prepared
files or bundle identity refuses configuration. Valid *other* builds may remain
in the signed policy for future updates/pools; this tool does not invent boot
registers or approved machines.

Inputs name the Cloudflare account, Worker and private bucket, an HTTPS custom
domain matching the endpoint, an explicit list of ready HTTPS authorization
backends (one is sufficient), and the exact image identity from the bundle.
The current renderer supports custom-domain routing, not a workers.dev fallback.
It does not create the bucket, migration or Worker. `LOG`, `RELAY` and `BODIES`
are emitted in `wrangler.json`; `RECEIPT_KEY` must be separately provisioned as a
Worker secret. `HOSTING_ROOT` and `RECEIPT_CERT` are public bindings. No seed is
accepted as a config value.

Authz inputs name the explicitly selected protected persistent host directory,
a quote socket, explicit non-root UID/GID, permit key/certificate, signed
policy/signature and collateral files. File references are absolute **local
source paths** for final validation, not secret values or remote mount paths.
The configure machine must be able to read the public files and the permit key
for a local key/certificate consistency check. The Rust validator uses the app's
actual endpoint parser, existing policy/receipt verifiers and authz key matching.
It verifies the permit certificate's existing signature without issuing a permit
or signing anything. No real keys are used by the test suite. Only public output
is copied.
dstack 0.5.12's guest image creates `/var/run/dstack.sock` through systemd
socket activation with mode 0777 and its guest agent does not authorize callers
by UID, so the non-root service can open a read-only bind of that socket
without added groups. Socket access on the running host, mount ownership and
encrypted-disk protection must still be qualified there; a Compose bind mount
does not establish them.
Missing bind sources are errors, never automatically created directories.

Supply two independent literal IP:port Roughtime addresses and public pins and
all five qualified-time bounds. HZ is exactly 1000000000; drift, smear, age and
width have no assumed production values. The schema only validates the supplied
configuration; it cannot establish oscillator/time qualification. The signed
hardware policy must contain actual approved builds and machines. Source hashes
are not those measurements. Runtime quote/collateral appraisal and time/current
policy checks remain authoritative. The protected current SQLite disk is mounted
at `/data`; state survives ordinary restart. Restoring a hostile old disk is not
solved by this packaging layer.

The service listens on container port 7801, published on every CVM interface:
the dstack gateway reaches an app over the CVM's WireGuard address, never its
loopback, so a loopback-only port is unreachable. The gateway's TLS-terminating
name `<app_id>-7801.<gateway domain>` forwards plain TCP to that port. The
operator supplies the actual HTTPS ingress to `/v1/channel` represented by each
backend URL; the renderer neither configures ingress nor guesses its certificates.
Devices trust the attested channel, not the ingress path.
The service's outgoing data path is the endpoint's `/v1/data` WebSocket.

The final output contains `config/worker/`, `config/wrangler.json`,
`config/compose.json` and `config/endpoint.json` with exactly nine public fields
and `appraisal=hardware`, plus `manifest.json`. Its manifest binds the bundle,
prepared deployment manifest/candidate, operator-input hash, rendered file set
and endpoint hash. Run `verify-config` before handing its printed endpoint path
to app packaging. It grants no deployment or signing authorization. Actual
ingress reachability, quote-socket ownership/access, protected disk, hardware
appraisal, qualified time and provider canonicalization are still unverified.

## App handoff

Mac packaging requires one explicit mode:

```sh
python3 scripts/mac_package.py VERSION /absolute/package-output \
  --signing-root PUBLIC_CERTIFICATE_SHA1 --sync-endpoint /absolute/new-config/config/endpoint.json
# Deliberate local-only development instead: --local-only
```

Android unsigned packaging similarly takes `build --sync-endpoint FILE` or
`build --local-only`. A configured build snapshots the exact supplied bytes,
sets `BH_SYNC_ENDPOINT` to that snapshot and records its SHA-256 alongside the
app archive/APK hash. The app's `build.rs` rejects malformed/partial/named-empty
files. Local-only explicitly removes any inherited endpoint environment value.
The manually dispatched Mac release workflow requires the reviewed public JSON;
source ancestry/tree checks, stable Keychain helper pin, separate Environment
approval and signing roots remain unchanged. Actual Mac builds and release
signing are not performed by these local checks.

## Checks

`bash scripts/check.sh sync-release` runs portable packaging/config tests and
Rust validation. `BH_RELEASE_TEST_BUNDLE=/absolute/bundle` enables the emitted
bundle's actual artifact/config integration checks with throwaway test identities.
The Worker production-entry tests accept `BH_RELEASE_WORKER=/absolute/bundle/worker`:

```sh
cargo build --locked -p bh-sync-worker --example edge
npm ci --prefix tests/crypto-worker --ignore-scripts --no-audit --no-fund
BH_RELEASE_WORKER=/absolute/bundle/worker node --test \
  --test-name-pattern='unknown_route_404|ack_receipt_verifies|data_rejects_bad_permit|read bodies serves' \
  tests/sync-worker/test/edge.test.mjs
```

These run locally in workerd, without Wrangler authentication or telemetry.
