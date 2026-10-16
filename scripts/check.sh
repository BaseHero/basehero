#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-portable}" in
  portable)
    cargo metadata --no-deps --format-version 1 --locked | node -e '
      const { packages, workspace_members } = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
      const members = new Set(workspace_members);
      const missing = packages.filter(pkg => members.has(pkg.id) && !pkg.license);
      if (missing.length) {
        console.error(`Workspace packages without a licence: ${missing.map(pkg => pkg.name).join(", ")}`);
        process.exitCode = 1;
      }
    '
    cargo fmt --all --check
    node scripts/affected.mjs --layers
    node --test scripts/affected.test.mjs scripts/webdriver-exclusion.test.mjs scripts/check-webdriver-markers.test.mjs
    node scripts/webdriver-exclusion.mjs
    python3 -m unittest discover -s scripts -p test_mac_package.py
    python3 -m unittest discover -s scripts -p test_mac_sign.py
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked
    # Security socket fixtures need test-owned addresses inside a Linux network namespace.
    if [ "$(uname -s)" = Linux ]; then
      bash libs/public-web/netns.sh cargo test --locked --offline -p bh-public-web --lib -- --ignored --test-threads=1
    else
      echo 'Skipped isolated-network security tests (require Linux).' >&2
    fi
    node --test apps/client/tests/*.test.mjs
    bash scripts/check.sh ui
    npm ci --prefix tests/interop --ignore-scripts --no-audit --no-fund
    npm test --prefix tests/interop
    bash scripts/check.sh editor
    ;;
  editor)
    npm ci --prefix apps/client/editor --ignore-scripts --no-audit --no-fund
    node apps/client/editor/scripts/patch-yjs.mjs
    node apps/client/editor/test/rich.mjs
    node apps/client/editor/test/unsupported.mjs
    node apps/client/editor/test/notices.mjs
    npm run build --prefix apps/client/editor
    npm run test:unit --prefix apps/client/editor
    ;;
  ui)
    # Real ui/ in Chromium and WebKit: the bundled shell screen and the real
    # EditorView cases; the browser tests are not a fixture.
    bash scripts/check-client-ui.sh
    ;;
  desktop)
    cargo clippy --locked -p bh-client --all-targets -- -D warnings
    cargo test --locked -p bh-client --lib
    cargo build --locked -p bh-client
    ;;
  android)
    cargo build --locked --target aarch64-linux-android -p bh-core -p bh-storage -p bh-client --lib
    ;;
  android-device-keys)
    cargo clippy --locked --target aarch64-linux-android -p bh-device-keys --all-targets -- -D warnings
    cargo check --locked --target aarch64-linux-android -p bh-device-keys
    # The Android shell has target libsodium only; host tests need the default shell.
    nix develop --command cargo test --locked -p bh-device-keys
    apps/client/src-tauri/gen/android/gradlew -p apps/client/plugins/device-keys/android testDebugUnitTest assembleRelease --no-daemon
    ;;
  android-device-keys-emulator)
    # Opt-in Keystore/BiometricPrompt instrumentation, from nix develop .#androidEmulator.
    python3 apps/client/plugins/device-keys/android/test-runner-safety.py
    bash apps/client/plugins/device-keys/android/run-emulator.sh
    ;;
  android-crypto)
    artifacts=$(mktemp)
    trap 'rm -f "$artifacts"' EXIT
    cargo test --locked --target aarch64-linux-android -p bh-crypto -p bh-release --no-run --message-format=json > "$artifacts"
    node scripts/check-android-crypto.mjs "$artifacts"
    ;;
  wasm)
    # Only platform-independent rules belong on this target; SQLite and the
    # native shell are not Wasm libraries.
    cargo check --locked --target wasm32-unknown-unknown -p bh-core
    ;;
  wasm-crypto)
    nix develop .#cryptoWorker --command bash scripts/check-crypto-worker.sh
    ;;
  wasm-sync)
    cargo run --locked --offline -p bh-sync-worker --example fixtures > tests/sync-worker/fixtures.json
    nix develop .#cryptoWorker --command bash scripts/check-sync-worker.sh
    ;;
  webdriver)
    # Portable half of the WebDriver checks: the default feature graph never
    # contains the plugin, and its Android gate is unit-tested both ways.
    node scripts/webdriver-exclusion.mjs
    node --test scripts/webdriver-exclusion.test.mjs scripts/check-webdriver-markers.test.mjs
    cargo test --locked -p bh-client --features webdriver
    cargo clippy --locked -p bh-client --features webdriver --all-targets -- -D warnings
    ;;
  webdriver-linux)
    bash apps/client/tests/webdriver/run-linux.sh
    ;;
  webdriver-macos)
    bash apps/client/tests/webdriver/run-macos.sh
    ;;
  webdriver-android)
    # Run from `nix develop .#androidEmulator`.
    bash apps/client/tests/webdriver/run-android.sh
    ;;
  *)
    echo "usage: bash scripts/check.sh [portable|ui|editor|desktop|android|android-device-keys|android-device-keys-emulator|android-crypto|wasm|wasm-crypto|wasm-sync|webdriver|webdriver-linux|webdriver-macos|webdriver-android]" >&2
    exit 2
    ;;
esac
