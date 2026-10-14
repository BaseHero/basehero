# Real-app WebDriver tests

These drive the real Tauri client (the setup shell) through `tauri-plugin-webdriver`
over its loopback W3C endpoint, with one shared `spec.mjs` on every platform. They
are opt-in and never part of the default or affected checks.

The driver is behind the client's non-default `webdriver` feature. A release build
must not contain it: `scripts/webdriver-exclusion.mjs` proves the default feature
graph has no `tauri-plugin-webdriver` for any target (with the feature-enabled graph
as its own positive control), `scripts/check-webdriver-markers.mjs` checks a built
binary or APK, and `scripts/android-unsigned.sh` refuses a release APK that carries
the plugin.

```sh
# Portable half: exclusion check plus the Android gate's unit tests.
bash scripts/check.sh webdriver

# Each runner builds the client with the feature, starts only its own PIDs, and
# refuses to start with an occupied port or connect outside loopback.
bash scripts/check.sh webdriver-linux    # Xvfb on Linux
bash scripts/check.sh webdriver-macos    # the host itself, including over SSH
nix develop .#androidEmulator --command bash scripts/check.sh webdriver-android
```

They are integration tests: a browser stub is not acceptance. Each writes
`session-screenshot.png` (git-ignored) and fails on missing setup-screen text, a
changed URL after a click, an inline script that ran despite the CSP, or a
screenshot that is not a valid non-empty PNG.

The plugin's unauthenticated endpoint has no Host or Origin check. Even on desktop
loopback, a web page on the same machine can reach a running test build through
DNS rebinding; only run feature builds for tests. The plugin also enables Tauri's
default features in test builds (including `dynamic-acl`), unlike release, so ACL
behaviour may differ. These tests do not exercise a privileged capability; the
setup shell grants none.

Android tests are emulator only; the driver never runs on physical devices. The
runner intentionally refuses non-emulator devices before installing, deletes its
disposable AVD afterwards, and waits for a visible, laid-out WebView
(`wait-for-layout.mjs`), retrying one app start if it stays hidden. Android's
WebView.draw can return a valid blank PNG when the page is hidden even with a
non-zero viewport; a zero-sized viewport fails the screenshot outright. Emulator build, run and memory measurements do not
establish physical-device runtime acceptance.
