#!/usr/bin/env bash
set -euo pipefail

# Run once on arm64 macOS; commit the unsigned result and reuse those bytes on updates.
root="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$root"
triple=aarch64-apple-darwin
target="${CARGO_TARGET_DIR:-$root/target/keychain-helper}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
caller_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["macCertSha1"])' "$root/apps/basehero/release-identity.json")"
# Do not inherit app build flags or profile overrides into the immutable helper.
unset CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
while IFS='=' read -r name _; do
  if [[ $name == CARGO_PROFILE_* ]]; then unset "$name"; fi
done < <(env)
export CARGO_TARGET_DIR="$target" CARGO_BUILD_TARGET="$triple"
export BH_APP_IDENTIFIER=app.basehero BH_KEYCHAIN_CALLER_ROOT="$caller_root"
export RUSTFLAGS="--remap-path-prefix=$root=/basehero --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$target=/target -Clink-arg=-Wl,-dead_strip_dylibs -Clink-arg=-Wl,-S"
cargo build --locked --profile keychain-helper -p bh-mac-keychain-helper --bin bh-keychain-helper --target "$triple"
output="$root/apps/basehero/src-tauri/keychain-helper"
install -m 755 "$target/$triple/keychain-helper/bh-keychain-helper" "$output/bh-keychain-helper"
(cd "$output" && sha256sum bh-keychain-helper > SHA256SUMS)
