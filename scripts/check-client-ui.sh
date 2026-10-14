#!/usr/bin/env bash
# Browser UI checks for the bundled client: the real apps/client/ui in Chromium
# and WebKit. Chromium approximates an Android WebView and WebKit the macOS
# WKWebView; neither is a real-device check.
set -euo pipefail
cd "$(dirname "$0")/.."

# Browsers come from the product flake's pinned nixpkgs rather than a per-machine
# download, so the engine versions match everywhere the flake builds.
if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
  if ! command -v nix >/dev/null 2>&1; then
    echo "check-client-ui.sh: PLAYWRIGHT_BROWSERS_PATH is unset and nix is unavailable to supply browsers." >&2
    exit 1
  fi
  # `--inputs-from .` uses the flake's own lock; an absolute-path getFlake would
  # copy this working directory (including target/ and untracked files) to the store.
  PLAYWRIGHT_BROWSERS_PATH="$(nix build --no-link --print-out-paths --inputs-from . nixpkgs#playwright-driver.browsers)"
fi
export PLAYWRIGHT_BROWSERS_PATH

cd apps/client/tests/browser
npm ci --ignore-scripts --no-audit --no-fund
node --test

# The real EditorView cases run in the same browsers from the same pinned
# install. The editor owns its sources and test host; this entry runs them
# rather than keeping a second copy.
cd ../../editor
npm ci --ignore-scripts --no-audit --no-fund
npm run test:browser
