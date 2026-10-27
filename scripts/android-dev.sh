#!/usr/bin/env bash
# Debug x86_64 APK for BaseHero's disposable emulator only.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?run inside nix develop .#androidEmulator}"
case "${1:-}" in
  build)
    export BH_SERVER="${BH_SERVER:-https://dev-api.basehero.com}"
    (cd apps/basehero && VITE_BH_DEBUG=1 cargo tauri android build --debug --apk --target x86_64 --ci)
    ;;
  install)
    "$0" build
    apk=apps/basehero/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
    [ -f "$apk" ] || { echo "missing debug APK: $apk" >&2; exit 1; }
    [ "$(adb -s emulator-5580 emu avd name | tr -d '\r' | head -n 1)" = bh-fold-36 ] || {
      echo 'port 5580 is not the BaseHero emulator' >&2; exit 1;
    }
    if ! out=$(adb -s emulator-5580 install -r "$apk" 2>&1); then
      case $out in
        *INSTALL_FAILED_UPDATE_INCOMPATIBLE*)
          # Another worktree's build used a different debug key. The disposable
          # emulator's app holds nothing to keep: each suite clears it anyway.
          adb -s emulator-5580 uninstall app.basehero
          adb -s emulator-5580 install "$apk"
          ;;
        *) printf '%s\n' "$out" >&2; exit 1 ;;
      esac
    fi
    ;;
  release-check)
    # R8 must keep the verifier's Kotlin half, KeysPlugin and OpenPlugin, which Rust reaches
    # only through JNI, and release builds must not contain the debug-only model probe.
    export BH_SERVER="${BH_SERVER:-https://dev-api.basehero.com}"
    (cd apps/basehero && cargo tauri android build --apk --target x86_64 --ci)
    "$0" release-check-apk apps/basehero/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk x86_64
    ;;
  release-check-apk)
    # Check an already-built release APK (arm64-v8a in CI, x86_64 locally).
    apk=${2:?usage: android-dev.sh release-check-apk APK ABI}
    abi=${3:?usage: android-dev.sh release-check-apk APK ABI}
    [ -f "$apk" ] || { echo "missing release APK: $apk" >&2; exit 1; }
    out=$(mktemp -d)
    trap 'rm -rf "$out"' EXIT
    unzip -q "$apk" 'classes*.dex' "lib/$abi/libbasehero_app_lib.so" -d "$out"
    for dex in "$out"/classes*.dex; do "$ANDROID_HOME/build-tools/35.0.0/dexdump" "$dex"; done >"$out/classes.txt"
    grep -q "Class descriptor  : 'Lorg/rustls/platformverifier/CertificateVerifier;'" "$out/classes.txt" || {
      echo 'R8 removed org.rustls.platformverifier.CertificateVerifier' >&2; exit 1;
    }
    grep -q "Class descriptor  : 'Lapp/basehero/keys/KeysPlugin;'" "$out/classes.txt" || {
      echo 'R8 removed app.basehero.keys.KeysPlugin' >&2; exit 1;
    }
    grep -q "Class descriptor  : 'Lapp/basehero/open/OpenPlugin;'" "$out/classes.txt" || {
      echo 'R8 removed app.basehero.open.OpenPlugin' >&2; exit 1;
    }
    ! grep -q dev_model_probe "$out/lib/$abi/libbasehero_app_lib.so" || {
      echo 'the release library contains dev_model_probe' >&2; exit 1;
    }
    echo 'release APK keeps CertificateVerifier, KeysPlugin and OpenPlugin and omits dev_model_probe'
    ;;
  *) echo 'Usage: android-dev.sh build|install|release-check|release-check-apk APK ABI' >&2; exit 2 ;;
esac
