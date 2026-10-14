#!/usr/bin/env bash
# Run from any directory with Cargo, rustfmt, clippy, iproute2 and util-linux.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cargo fmt --manifest-path "$here/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "$here/Cargo.toml" -p bh-public-web --all-targets -- -D warnings
cargo test --locked --manifest-path "$here/Cargo.toml" -p bh-public-web
bash "$here/netns.sh" cargo test --locked --offline --manifest-path "$here/Cargo.toml" -p bh-public-web --lib -- --ignored --test-threads=1
