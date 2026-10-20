# BaseHero

BaseHero is a place for your notes, ideas, projects and shared work, with Hero,
an agent that helps you research, prepare and move things forward. Learn more at
[basehero.com](https://basehero.com/).

This directory contains the product source and its independently built website.

## Layout

- `libs/` — reusable Rust libraries for product rules, notes and local storage,
  account history, cryptography, sync, releases, model routes, public web,
  confidential policy matching, offline TDX attestation verification and native
  device keys.
- `third_party/dstack/` — pinned Apache-2.0 event-log parsing dependencies.
- `note-schema/v1.json` — shared canonical note schema checked by Rust and the
  bundled editor.
- `apps/client/` — bundled interface, bundled note editor and Tauri
  desktop/mobile shell.
- `services/sync/` — sync storage adapter.
- `services/sync-worker/` — Worker Durable Object sync storage adapter.
- `tests/system/`, `tests/crypto-worker/` and `tests/sync-worker/` — cross-component tests.
- `website/` — standalone website; see [its README](website/README.md).

Crates are not uploaded to a package registry. Libraries do not depend on app or
service entry points; Cargo.lock is committed.

## Development

Run commands from this directory. Rust is pinned by `rust-toolchain.toml`.
Node.js 22 or later and npm are needed for shell, Tiptap/Yjs interoperability
and bundled-editor checks; the website uses Node.js 24. Python 3 is needed for
Mac packaging and its portable fixtures (supplied by the default Nix shell). On Linux, native client
builds need WebKitGTK 4.1, GTK 3, libsoup 3, a C compiler, pkg-config and
libsodium with X-Wing support. On macOS, install Xcode command-line tools and
compatible libsodium. The Nix environment supplies the Linux prerequisites and
Tauri CLI:

```sh
nix develop                       # or nix develop path:. in a source-only copy
node scripts/affected.mjs --base <commit> --head HEAD --check  # affected checks
bash scripts/check.sh             # format, portable clippy/tests, shell, UI and editor checks
bash scripts/check.sh ui          # client UI in Chromium and WebKit only
bash scripts/check.sh editor      # bundled editor fixtures, bundle build and unit tests
bash scripts/check.sh desktop     # native Tauri clippy + build
bash scripts/check.sh wasm        # portable core check
bash scripts/check.sh wasm-crypto # Worker-Wasm crypto check (Nix)
cargo run --locked -p bh-client   # run the desktop shell
```

The UI check runs the real `apps/client/ui` in Chromium and WebKit with the
shell's content security policy, and then the real EditorView cases from
`apps/client/editor/test/` in the same two engines. Chromium approximates an
Android WebView and WebKit the macOS WKWebView; neither is real-device
acceptance. The engines come from the product flake's pinned nixpkgs (a one-time
substitution, not Playwright's own downloader); `scripts/check-client-ui.sh`
resolves them unless `PLAYWRIGHT_BROWSERS_PATH` is already set.

On Linux, the default check also runs isolated public-web socket tests and needs
unprivileged user and network namespaces; macOS skips those tests. Default Cargo
checks omit the native shell; use the explicit platform checks instead of
`--workspace --all-features`.

### Android

On x86_64 Linux, `nix develop .#android` supplies the Android SDK/NDK, Java and
arm64 compiler. This shell accepts the Android SDK licence; review its terms
before using it. It is separate from the default desktop environment.

```sh
nix develop .#android --command bash scripts/check.sh android
nix develop .#android --command bash scripts/check.sh android-crypto
nix develop .#android --command bash scripts/android-unsigned.sh build
```

The crypto check links arm64 test executables against static target libsodium
built from the same pinned source as native, then inspects their ELF metadata
and X-Wing symbol. It does not run them on Android. The APK command produces an
unsigned release APK; signing is required before installation or device/emulator
testing. With an existing Android toolchain, the library checks need
`CC_aarch64_linux_android`, `AR_aarch64_linux_android` and
`CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER` set to the NDK tools; crypto also
needs target libsodium/pkg-config, supplied by this pinned Nix shell.
The client identifier is `app.basehero.client` and must remain stable across updates.

### Mac application package

On an arm64 Mac with Xcode tools and the pinned Nix development shell, start from
**committed, source-only exported product files**, not a checkout or a development
binary. For a repository whose root is this directory:

```sh
mkdir -p /tmp/basehero-source /tmp/basehero-package
# Export a committed product tree; do not copy a working directory or target/.
git archive <product-commit> | tar -xf - -C /tmp/basehero-source
cd /tmp/basehero-source
nix develop path:. --command python3 scripts/mac_package.py 42 /tmp/basehero-package
```

Replace `42` with the release's positive integer version (canonical decimal
signed-release u64). The script builds Tauri's arm64 app bundle with the committed
`app.basehero.client` identity and current semver display version, sets
`CFBundleVersion` to that integer, checks every bundled Mach-O dependency and
rpath, resolves only in-bundle links, ad-hoc signs and verifies the app, and
writes `BaseHero-macos-aarch64.app.tar.gz`. It pins Cargo's lock and the
`aarch64-apple-darwin` target, overrides inherited `CARGO_TARGET_DIR` and
`CARGO_BUILD_TARGET`/Cargo `build.target`, and keeps compilation cache under
`target/mac-package/` while clearing only its expected app before each build.
Output is outside the source export; it fails if output exists. The archive has one `BaseHero.app` top-level directory
and only real files/directories, as required by the Mac installer. The native
pinned libsodium is copied into the app when linked, with its ISC notice under
`Contents/Resources/Licenses`; the system libiconv is used instead of bundling
Nix's LGPL libiconv. No other external runtime libraries are permitted. Build
and archive validation do not authorize a release: the separately signed release
metadata must name the exact archive hash/version/platform/source commit before
an installed app can use it. Ad-hoc signing is not that release signature.

For a separately identified test app, `--identifier app.example.notes` builds
that identity into Tauri, the bundle, app data directory and Keychain service
names. Use the same identifier for both versions of an update test; an update
for another identifier is refused.

### Release signature and updates

`cargo run --locked -p bh-release --bin release-sign -- generate` creates a
release key. Run it only in a private terminal: it prints the public key and
seed once. Store the seed only in the signing secret store; never in source,
logs, build configuration or an application. Apps carry only the public key.

The signer accepts `sign VERSION PLATFORM CHANNEL SOURCE_COMMIT ARCHIVE NOTES_FILE`.
It reads the 64-character lowercase hex seed from stdin (hidden when interactive),
prints the public key to stderr and signed metadata JSON to stdout. Metadata
binds the exact archive hash, integer version, platform, channel, public source
commit and plain-text release notes. Build jobs need no seed; a separately
approved signing step receives it through stdin and releases only metadata.

Mac updates are disabled without all three build-time settings:
`BH_UPDATE_METADATA_URL`, `BH_UPDATE_ARTIFACT_BASE` (HTTPS, the latter ending in
`/`) and `BH_UPDATE_PUBLIC_KEY` (64 lowercase hex characters). The app checks
shortly after launch, then at jittered roughly six-hour intervals. Only Install
update downloads the artifact. After signature, hash and bundle checks, the
native save barrier commits every window and records its place before exchange
and restart. A failed save leaves writing open and offers Try again, never
discard. The relaunch waits for the old process to exit and release its account
locks. An installed update that cannot restart asks the person to quit and reopen.

### Sync endpoint

An app syncs only with the one endpoint fixed at build time. Without
`BH_SYNC_ENDPOINT` the build is local-only: notes are saved on the device and
its status line says cloud sync is not connected. `BH_SYNC_ENDPOINT` names a
JSON file with exactly these fields; none has a default, and a file that is
empty, missing a field or does not parse fails the build:

```json
{
  "edge_url": "https://edge.example",
  "hosting_root": "<64 hex characters: the hosting association's root>",
  "app_root": "<64 hex characters: the root that signs the service policy>",
  "policy": "<hex of the signed policy, or empty>",
  "policy_signature": "<hex of its signature, or empty with no policy>",
  "max_lifetime_secs": 86400,
  "max_uncertainty_secs": 0,
  "build_floor": 1760000000,
  "appraisal": "hardware"
}
```

Neither root may be all zeros. `appraisal: "synthetic"` (and a plain `http://`
edge) is accepted only by a local build with the `synthetic-attestation`
feature, for a local stack; release builds and their checks never enable it.
No page, setting or runtime value can change the endpoint.

## Developer boundaries

The native signup/open path verifies the local account, creates or opens its own
base, and supplies account-bound note authority to its windows. The host mounts
the bundled editor after binding the note; the shell is no longer setup-only.
With a configured sync endpoint, a ready account also starts sync: the host
publishes pending local work and applies verified incoming events, and another
device joins by QR pairing. A local-only build does neither.
`libs/storage` keeps transactional note updates and pending local work
(those are not signed network event IDs), each sealed pending outbound package
and its exact ordered acknowledgement. Native note commands open and commit
bound notes before acknowledging the editor. The editor classifies canonical
Yjs state against `note-schema/v1.json`, displays unsupported notes read-only
with inert placeholders, and uses a real EditorView for supported ones. Rust
checks the same inventory.
The green `tests/interop/known.mjs` fixture checks Tiptap/Yjs conversion against
Rust yrs tests. `tests/interop/unknown-preservation.red.mjs` is an intentionally
failing test of unknown-node preservation, excluded from passing checks.
The reusable libraries' READMEs describe their own interfaces and limits.

## Licence and feedback

Except for `sdk/`, BaseHero's original code is licensed under
[AGPL-3.0-only](LICENSE). If added, code under `sdk/` will be licensed under
[Apache-2.0](LICENSES/Apache-2.0.txt). Third-party files retain their own
licences, including the OFL font licences beside the bundled fonts and the
notices listed with the bundled editor and the pinned libsodium ISC notice in
`LICENSES/libsodium.txt` when included in a Mac package. MotiveSite Inc.
also offers a commercial licence; contact licensing@basehero.com.

Copyright © 2026 MotiveSite Inc. BaseHero is a trademark of MotiveSite Inc.;
these licences grant no right to use the BaseHero name or logo.
For issues and discussions, see [CONTRIBUTING.md](CONTRIBUTING.md).
