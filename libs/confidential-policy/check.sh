#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/../.."
cargo fmt --all --check
cargo clippy --locked -p bh-confidential-policy --all-targets -- -D warnings
cargo test --locked -p bh-confidential-policy
