#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
for crate in crypto account; do
  manifest="libs/$crate/Cargo.toml"
  cargo fmt --manifest-path "$manifest" -- --check
  cargo test --locked --manifest-path "$manifest"
  cargo clippy --locked --manifest-path "$manifest" --all-targets -- -D warnings
done
