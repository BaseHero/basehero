#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if (( $# == 0 )); then
  set -- rust server scale
fi

# The local Worker runs every Durable Object on one thread, which also waits for
# each storage fsync. On a shared Linux host another job's disk write-back can
# hold one fsync for 30 s, so tests that start it keep their files in memory.
memory_tmp() {
  if [ -z "${memory_dir:-}" ] && [ -d /dev/shm ]; then
    memory_dir=$(mktemp -d /dev/shm/bh-check.XXXXXX)
    trap 'rm -rf "$memory_dir"' EXIT
    export TMPDIR=$memory_dir
  fi
}

if [ "${1:-}" = run ]; then
  shift
  if (( $# == 0 )); then
    printf 'Usage: check.sh run <command...>\n' >&2
    exit 2
  fi
  memory_tmp
  [ server/node_modules/.package-lock.json -nt server/package-lock.json ] ||
    (cd server && npm ci --no-audit --no-fund)
  "$@"
  exit
fi

for stage in "$@"; do
  case "$stage" in
    rust)
      memory_tmp
      # The test kit runs the Worker locally, so its npm packages must be installed.
      [ server/node_modules/.package-lock.json -nt server/package-lock.json ] ||
        (cd server && npm ci --no-audit --no-fund)
      cargo fmt --all -- --check
      cargo clippy --workspace --exclude basehero-app --exclude basehero-sample --exclude bh-mac-keychain-helper --all-targets --features bh-cli/test-support -- -D warnings
      # Exercise the real bh binary with its debug-only scripted model hook.
      cargo test --workspace --exclude basehero-app --exclude basehero-sample --exclude bh-mac-keychain-helper --features bh-cli/test-support
      node scripts/check-docs.mjs
      node --test scripts/check-docs.test.mjs
      RUSTDOCFLAGS="-D warnings" cargo doc -p bh-core -p bh-docs --no-deps
      git diff --exit-code -- server/src/proto/gen
      git diff --exit-code -- apps/basehero/src/lib/generated
      if git ls-files -z -- . ':!website' ':!**/gen/schemas/**' ':!scripts/check.sh' |
        xargs -0 grep -nE '\b[Tt]ask [0-9]+[a-z]?\b|superpowers|/hom[e]/dan|/User[s]/dan|bh-wt|bh-archive'; then
        printf 'Published files contain private references.\n' >&2
        exit 1
      fi
      ;;
    app|app-webkit)
      memory_tmp
      # Core integration tests start the local Worker before the UI stage.
      [ server/node_modules/.package-lock.json -nt server/package-lock.json ] ||
        (cd server && npm ci --no-audit --no-fund)
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
      cargo clippy -p basehero-sample -- -D warnings
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
    android-sample)
      scripts/android-emulator.sh
      nix develop --command cargo build -p bh-cli
      (cd apps/basehero && npm ci --no-audit --no-fund)
      scripts/android-dev.sh install
      scripts/sample-android.sh install
      node --input-type=module -e "import { adb } from './apps/basehero/tests/android/lib.mjs'; adb('shell', 'pm', 'clear', 'app.basehero'); adb('shell', 'pm', 'clear', 'app.basehero.sample')"
      node --test apps/sample/tests/android/sample.test.mjs
      ;;
    android)
      scripts/android-emulator.sh
      # The Android cross shell has only Android libsodium; the host CLI
      # needs the native library from the default development shell.
      nix develop --command cargo build -p bh-cli
      nix develop --command cargo build -p bh-cli --features test-support --example keep_emulator_version
      (cd apps/basehero && npm ci --no-audit --no-fund)
      scripts/android-dev.sh install
      # The disposable emulator starts each suite with a new local account.
      adb -s emulator-5580 shell pm clear app.basehero
      # One emulator and one app: test files take turns. The approval runner
      # creates a disposable dev approver and isolates its CLI credentials.
      for file in lib keys shell model notes fold ime hero update approval kit hidden files backup; do
        if [ "$file" = approval ]; then
          node apps/basehero/tests/android/run-approval.mjs
        else
          node --test "apps/basehero/tests/android/$file.test.mjs"
        fi
      done
      ;;
    remote)
      token_file="$HOME/.config/basehero/dev-operator-token"
      if [ ! -s "$token_file" ]; then
        printf 'Missing dev operator token: %s\n' "$token_file" >&2
        exit 1
      fi
      remote_home=$(mktemp -d)
      (
        trap 'rm -rf "$remote_home"' EXIT
        env -u GH_TOKEN -u GITHUB_TOKEN \
          HOME="$remote_home" GH_CONFIG_DIR="$remote_home/gh" \
          XDG_CONFIG_HOME="$remote_home/config" \
          CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
          BH_TEST_SERVER=https://dev-api.basehero.com \
          BH_TEST_OPERATOR_TOKEN="$(<"$token_file")" \
          cargo test -p bh-core --features test-support --no-fail-fast -- --nocapture
      )
      ;;
    server)
      (cd server && npm ci && npx tsc --noEmit)
      node --test scripts/deploy.test.mjs
      ;;
    scale)
      memory_tmp
      [ server/node_modules/.package-lock.json -nt server/package-lock.json ] ||
        (cd server && npm ci --no-audit --no-fund)
      cargo test --release -p bh-core --test scale --test scale_files --test scale_backup -- --nocapture --test-threads=1
      du -sh "$TMPDIR" # Fixture footprint before the check's in-memory directory is removed.
      ;;
    *)
      printf 'Unknown check stage: %s\n' "$stage" >&2
      exit 2
      ;;
  esac
done
