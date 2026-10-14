# Product workspace

Keep this tree self-contained. Libraries live in `libs/`; the shared client UI
and Tauri shell live in `apps/client/`; runnable hosting adapters belong in
`services/`. Libraries must not import app/service entry points. Keep platform
permissions out of portable interfaces.

Dependency versions, lints and profiles belong in the root Cargo manifest.
Commit Cargo.lock. Do not change the stable client identifier during updates.
Document invariants at the code that enforces them. Prefer focused modules over
speculative crates.

## Checks

From this directory, in `nix develop` or with README prerequisites installed:

- Affected checks: `node scripts/affected.mjs --base <commit> --head HEAD --check` (Cargo metadata discovers changed crates and reverse dependents; client JS, client UI browser, interop, bundled editor, sync-worker Wasm and website checks follow relevant changes). `node scripts/affected.mjs --layers` checks one-way workspace dependencies.
- Cross-library tests: `cargo test --locked -p bh-system-tests`.
- Default full check: `bash scripts/check.sh` (Rust format, portable clippy/tests,
  bundled-shell asset/security checks, Tiptap/Yjs/yrs interop fixture, bundled
  editor build, shared-schema/cross-language tests, and the Chromium/WebKit client
  UI checks including the real EditorView cases; requires npm. On Linux it also
  needs unprivileged user and network namespaces for isolated public-web socket
  tests; macOS skips those tests.
- Unknown-content compatibility gate: `cd tests/interop && npm ci && npm run proof:unknown`
  is a recorded expected failure, not part of the green default. Never ship a
  lossy schema/binding to make that gate appear green.
- Bundled editor (schema fixtures, Rust-to-Yjs bridge, bundle build and unit
  tests): `bash scripts/check.sh editor`.
- Native client: `bash scripts/check.sh desktop`.
- Client UI in browsers: `bash scripts/check.sh ui` serves the real `apps/client/ui`
  and drives it in Chromium and WebKit with the shell's own CSP and a pre-app IPC
  stub, then runs the real EditorView cases from `apps/client/editor/test/` in the
  same two engines. Chromium approximates an Android WebView and WebKit the macOS
  WKWebView; neither is real-device acceptance. Browsers come from the product
  flake's pinned nixpkgs. The shell suite is in `apps/client/tests/browser/`.
- Android libraries: `nix develop .#android --command bash scripts/check.sh android`.
- Android crypto/release link proof (separate from fast default checks):
  `nix develop .#android --command bash scripts/check.sh android-crypto`.
- Wasm portable core: `bash scripts/check.sh wasm`.
- Worker Wasm hash/Ed25519 verifier (pinned libsodium and local workerd): `bash scripts/check.sh wasm-crypto`.
- Internal Worker SQLite DO adapter (native-signed local fixtures, pinned Wasm and workerd): `bash scripts/check.sh wasm-sync`.
- Real-app WebDriver tests (opt-in; not in the default or affected checks). The
  driver lives behind the client's non-default `webdriver` feature and never in a
  release artifact: `bash scripts/check.sh webdriver` is the portable half (the
  default feature graph contains no `tauri-plugin-webdriver` for any target, and
  the Android emulator gate is unit-tested both ways); `webdriver-linux` runs the
  setup shell under Xvfb, `webdriver-macos` runs it on macOS, and
  `webdriver-android` runs it on an x86_64 emulator from
  `nix develop .#androidEmulator`, which carries the emulator and system image
  the ordinary `android` shell deliberately does not.
- Website: its independent README defines its own build and checks.

Run affected checks while editing, then the full check once before handoff.
Nix shells use Cargo's native `target/` default per worktree, with separate
Android and crypto-worker targets, and share compiled results through a per-user
sccache. An explicit `CARGO_TARGET_DIR` or `RUSTC_WRAPPER` overrides the shell
defaults. Verify cross-worktree Rust cache reuse with
`node --test scripts/cache-shell.test.mjs` (requires Nix); a custom target path
may change sccache's key.
Record warm-check and cold-build durations separately. Aim for affected tests
under 30 seconds and the default full check under five minutes. Platform builds
and actual device checks are separate; a cross-compile is not runtime evidence.
