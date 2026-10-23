#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-portable}" in
  data-scale)
    # Large data-query fixtures are opt-in and run with release SQLite/Rust costs.
    cargo test --release --locked -p bh-data --tests -- --ignored
    ;;
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
    bash scripts/check.sh flags
    node scripts/affected.mjs --layers
    node --test scripts/affected.test.mjs scripts/webdriver-exclusion.test.mjs scripts/check-webdriver-markers.test.mjs
    node scripts/webdriver-exclusion.mjs
    python3 -m unittest discover -s scripts -p test_mac_package.py
    python3 -m unittest discover -s scripts -p test_mac_sign.py
    python3 -m unittest discover -s scripts -p 'test_sync_*.py'
    cargo test --locked -p bh-authz --example sync-release-validator
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked
    cargo test --locked -p bh-release --features authorization-tools
    # No release dependency graph enables synthetic attestation or the sync
    # client's synthetic appraisal; service and cross-layer tests opt in explicitly.
    if cargo tree --locked --workspace -e normal,build,features --target all -i bh-confidential-attestation | grep -q synthetic-attestation; then
      echo 'A release dependency graph enables synthetic-attestation.' >&2
      exit 1
    fi
    # Nor does any app graph enable the host's labelled test key store.
    if cargo tree --locked --workspace -e normal,build,features --target all -i bh-host | grep -q test-support; then
      echo 'A release dependency graph enables bh-host test-support.' >&2
      exit 1
    fi
    # Nor the sync client's test-only pacing knobs.
    if cargo tree --locked --workspace -e normal,build,features --target all -i bh-sync-client | grep -q test-support; then
      echo 'A release dependency graph enables bh-sync-client test-support.' >&2
      exit 1
    fi
    # Nor does any app graph enable the desktop WebDriver's software key store.
    if cargo tree --locked --workspace -e normal,build,features --target all -i bh-client | grep -q desktop-fixture; then
      echo 'A release dependency graph enables bh-client desktop-fixture.' >&2
      exit 1
    fi
    cargo clippy --locked -p bh-authz -p bh-sync-client -p bh-sync-client-tests -p bh-host -p bh-host-tests -p bh-local-sync-tests --all-targets --features synthetic-attestation -- -D warnings
    cargo test --locked -p bh-authz -p bh-confidential-channel -p bh-sync-client -p bh-sync-client-tests -p bh-host -p bh-host-tests -p bh-local-sync-tests --features synthetic-attestation
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
  flags)
    cargo test --locked -p bh-flags
    BH_FLAG_REMOVAL_WAIT=5m cargo test --locked -p bh-flags
    error=$(mktemp)
    trap 'rm -f "$error"' EXIT
    if BH_RELEASE=1 BH_FLAG_REMOVAL_WAIT=5m cargo build --locked -p bh-flags 2>"$error"; then
      echo 'release accepted off-default flags' >&2; exit 1
    fi
    grep -F 'release builds refuse off-default flags' "$error"
    if BH_FLAG_REMOVAL_WAIT=invalid cargo build --locked -p bh-flags 2>"$error"; then
      echo 'unknown flag value accepted' >&2; exit 1
    fi
    grep -F 'BH_FLAG_REMOVAL_WAIT must be 5m or unset' "$error"
    BH_RELEASE=1 cargo build --locked -p bh-flags
    ;;
  sync-release)
    python3 -m unittest discover -s scripts -p 'test_sync_*.py'
    cargo test --locked -p bh-authz --example sync-release-validator
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
    node --test apps/client/tests/android/*.test.mjs scripts/android-emulator-update.test.mjs
    python3 -m unittest discover -s scripts -p test_android_no_models.py
    # No Tauri config, Gradle file, Cargo default or release script enables the fixture.
    node scripts/android-fixture-exclusion.mjs
    # The client library cargo just built, from cargo's own artifact report.
    android_client_lib() {
      cargo build --locked --target aarch64-linux-android -p bh-core -p bh-storage -p bh-client --lib "$@" \
        --message-format=json-render-diagnostics | node -e '
          const lines = require("node:fs").readFileSync(0, "utf8").split("\n").filter(Boolean);
          const libs = lines.map(JSON.parse)
            .filter(m => m.reason === "compiler-artifact" && m.target.name === "bh_client_lib")
            .flatMap(m => m.filenames.filter(f => f.endsWith(".so")));
          if (libs.length !== 1) { console.error(`expected one client library, got ${libs}`); process.exit(1); }
          console.log(libs[0]);
        '
    }
    # The test-only fixture adds no dependency, so only the built binary shows
    # it. The fixture build is the positive control; the default build, built
    # last and left in place, must carry no fixture, WebDriver or synthetic marker.
    bash scripts/android-release-check.sh "$(android_client_lib --features bh-client/emulator-fixture)" --expect-fixture
    bash scripts/android-release-check.sh "$(android_client_lib)"
    ;;
  android-sync-emulator)
    # Prepared private local stack and matching feature APKs; see run-sync.sh.
    bash apps/client/tests/android/run-sync.sh run
    ;;
  android-update-emulator)
    # A disposable signed v1 -> v2 upgrade, separate from the fast Android check.
    bash scripts/android-emulator-update.sh
    ;;
  android-editor-emulator)
    # Disposable API 36 Pixel Fold; editor/local store across a real force-stop.
    ANDROID_EMULATOR_TEST=editor bash scripts/android-emulator-update.sh
    ;;
  android-continuity-emulator)
    # Disposable API 36 Pixel Fold; real device posture, orientation and lifecycle.
    ANDROID_EMULATOR_TEST=continuity bash scripts/android-emulator-update.sh
    ;;
  android-fixture-emulator)
    # Run from `nix develop .#androidEmulator`: emulator fixture account and reopen.
    bash apps/client/tests/android/run-fixture.sh
    ;;
  android-device-keys)
    cargo clippy --locked --target aarch64-linux-android -p bh-device-keys --all-targets -- -D warnings
    cargo check --locked --target aarch64-linux-android -p bh-device-keys
    # The Android shell has target libsodium only; host tests need the default shell.
    nix develop --command cargo test --locked -p bh-device-keys
    apps/client/src-tauri/gen/android/gradlew -p apps/client/plugins/device-keys/android testDebugUnitTest assembleRelease --no-daemon
    ;;
  android-qr-scan)
    # The camera QR adapter's JVM decoder/lifecycle tests and release library
    # build, against the Tauri Android library cargo resolved for the client.
    tauri_android=$(cargo metadata --locked --format-version 1 | node -e '
      const tauri = JSON.parse(require("node:fs").readFileSync(0, "utf8")).packages.filter(p => p.name === "tauri");
      if (tauri.length !== 1) { console.error(`expected one tauri package, got ${tauri.length}`); process.exit(1); }
      console.log(require("node:path").join(require("node:path").dirname(tauri[0].manifest_path), "mobile/android"));
    ')
    apps/client/src-tauri/gen/android/gradlew -p apps/client/plugins/qr-scan/android "-PtauriAndroidDir=$tauri_android" \
      testDebugUnitTest assembleRelease --no-daemon
    ;;
  android-device-keys-emulator)
    # Opt-in Keystore/BiometricPrompt instrumentation, from nix develop .#androidEmulator.
    python3 apps/client/plugins/device-keys/android/test-runner-safety.py
    bash apps/client/plugins/device-keys/android/run-emulator.sh
    ;;
  data-android-emulator)
    # Opt-in bh-data integration tests; run from nix develop .#androidEmulator.
    bash scripts/check-data-android.sh
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
  local-stack)
    # Opt-in: uses only disposable loopback Miniflare and synthetic attestation.
    bash scripts/local-stack.test.sh
    ;;
  local-sync)
    # Opt-in: two devices of one account through private local stacks
    # (loopback Miniflare, synthetic attestation), one stack per test.
    bash tests/local-sync/run.sh
    ;;
  qualification-stress)
    # Opt-in: the stress, slow-cost and pacing-sweep qualification rows at
    # 300 ms and 1.5 s round trips. The gated 100 ms rows, their pause phases
    # and the cost bounds run in `portable`.
    cargo test --locked -p bh-sync-client-tests --features synthetic-attestation,qualification-stress --test qualification
    ;;
  wasm-sync)
    cargo run --locked --offline -p bh-sync-worker --example fixtures > tests/sync-worker/fixtures.json
    cargo run --locked --offline -p bh-sync-worker --example permit_fixtures > tests/sync-worker/permit-fixtures.json
    # The edge tests run this native example to issue permits at test time.
    cargo build --locked --offline -p bh-sync-worker --example edge
    edge_example="${CARGO_TARGET_DIR:-$PWD/target}/debug/examples/edge"
    nix develop .#cryptoWorker --command env BH_EDGE_EXAMPLE="$edge_example" bash scripts/check-sync-worker.sh
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
    echo "usage: bash scripts/check.sh [portable|sync-release|ui|editor|desktop|android|android-sync-emulator|android-update-emulator|android-editor-emulator|android-continuity-emulator|android-fixture-emulator|android-device-keys|android-qr-scan|android-device-keys-emulator|android-crypto|wasm|wasm-crypto|wasm-sync|local-stack|local-sync|qualification-stress|webdriver|webdriver-linux|webdriver-macos|webdriver-android|data-android-emulator|data-scale]" >&2
    echo 'additional check: flags' >&2
    exit 2
    ;;
esac
