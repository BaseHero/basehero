#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if (( $# == 0 )); then
  set -- rust server scale
fi

for stage in "$@"; do
  case "$stage" in
    rust)
      # The test kit runs the Worker locally, so its npm packages must be installed.
      [ server/node_modules/.package-lock.json -nt server/package-lock.json ] ||
        (cd server && npm ci --no-audit --no-fund)
      cargo fmt --all -- --check
      cargo clippy --workspace --exclude basehero-app --exclude bh-mac-keychain-helper --all-targets -- -D warnings
      cargo test --workspace --exclude basehero-app --exclude bh-mac-keychain-helper
      git diff --exit-code -- server/src/proto/gen
      git diff --exit-code -- apps/basehero/src/lib/generated
      if git ls-files -z -- . ':!website' ':!**/gen/schemas/**' ':!scripts/check.sh' |
        xargs -0 grep -nE '\b[Tt]ask [0-9]+[a-z]?\b|superpowers|/hom[e]/dan|/User[s]/dan|bh-wt|bh-archive'; then
        printf 'Published files contain private references.\n' >&2
        exit 1
      fi
      ;;
    app|app-webkit)
      # Parallel worktrees run UI tests at once, so the web server takes a free port.
      export BH_TEST_PORT="${BH_TEST_PORT:-$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}"
      python3 -m unittest scripts/test_release_scripts.py
      if [ "$(uname -s)" = Darwin ]; then
        cargo fmt -p bh-mac-keychain-helper -- --check
        cargo clippy -p bh-mac-keychain-helper -- -D warnings
        cargo test -p bh-mac-keychain-helper
        (cd apps/basehero/src-tauri/keychain-helper && sha256sum -c SHA256SUMS)
      fi
      cargo fmt -p basehero-app -- --check
      cargo clippy -p basehero-app -- -D warnings
      cargo test -p basehero-app
      (
        cd apps/basehero
        npm ci
        npm run check
        npm test
        npm run test:editor
        npx playwright test --project="$([ "$stage" = app ] && printf chromium || printf webkit)"
      )
      git diff --exit-code -- apps/basehero/src/lib/generated
      ! grep -rn '{@html' apps/basehero/src
      ;;
    android)
      scripts/android-emulator.sh
      scripts/android-dev.sh install
      # One emulator and one app: test files take turns.
      node --test --test-concurrency=1 apps/basehero/tests/android/*.test.mjs
      ;;
    server)
      (cd server && npm ci && npx tsc --noEmit)
      node --test scripts/deploy.test.mjs
      ;;
    scale)
      # The scale stage gains checks when its components are added.
      ;;
    *)
      printf 'Unknown check stage: %s\n' "$stage" >&2
      exit 2
      ;;
  esac
done
