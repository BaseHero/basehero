#!/usr/bin/env bash
# Build the unsigned production arm64 APK; signing is a separate job.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?run inside nix develop .#android}"
: "${BH_SERVER:?production endpoint must be set by the caller}"
(cd apps/basehero && npm ci --no-audit --no-fund && cargo tauri android build --apk --split-per-abi --target aarch64 --ci)
