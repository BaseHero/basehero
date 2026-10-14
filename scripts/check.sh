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
    node --test scripts/affected.test.mjs
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
    cargo build --locked -p bh-client
    ;;
  android)
    cargo build --locked --target aarch64-linux-android -p bh-core -p bh-storage -p bh-client --lib
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
  *)
    echo "usage: bash scripts/check.sh [portable|ui|editor|desktop|android|android-crypto|wasm|wasm-crypto|wasm-sync]" >&2
    exit 2
    ;;
esac
