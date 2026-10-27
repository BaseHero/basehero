# BaseHero Sample

A debug-only Tauri app exercising the [Build an app guide](../../docs/build-an-app.md). Its native Rust core installs `bh app connect` credentials from private app storage, writes one typed `sample.reading` record per day and calls the model as the app device. The page never receives credentials.

From the repository's `basehero/` directory, run `nix develop .#androidEmulator --command bash scripts/sample-android.sh build` for an x86_64 debug APK, or `install` to build and install on the disposable `bh-fold-36` emulator at `emulator-5580`. The install command refuses other devices. The full check is `nix develop .#androidEmulator --command bash scripts/check.sh android-sample` (uses a disposable account on `dev`, not production). It builds the CLI and sample, installs it, copies a fresh credentials file from a temporary host home into the sample's private directory and removes it after Connect. The headless tests run with `nix develop --command cargo test -p basehero-sample-core`.

This sample uses `FileSecretStore` and disables Android backup. A real app must instead seal secrets under a platform-protected key as the guide's [Open the core](../../docs/build-an-app.md#open-the-core) section explains. The sample has no release signing or production configuration.
