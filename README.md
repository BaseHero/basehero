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
and bundled-editor checks; the website uses Node.js 24. On Linux, native client
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

## Developer boundaries

The shell currently shows a setup screen; the libraries are not a complete app
account or hosted sync flow. `libs/storage` keeps transactional note
updates and pending local work; those are not signed network event IDs.
The bundled note editor is not mounted by the shell; it classifies canonical
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
notices listed with the bundled editor. MotiveSite Inc.
also offers a commercial licence; contact licensing@basehero.com.

Copyright © 2026 MotiveSite Inc. BaseHero is a trademark of MotiveSite Inc.;
these licences grant no right to use the BaseHero name or logo.
For issues and discussions, see [CONTRIBUTING.md](CONTRIBUTING.md).
