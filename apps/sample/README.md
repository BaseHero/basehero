# BaseHero Sample

A debug-only Tauri app exercising the [Build an app guide](../../docs/build-an-app.md). Enter your BaseHero email, open the request in BaseHero on one of your devices, type the six digits shown here, and approve the app. The native Rust core connects as its own app device, writes one typed `sample.reading` record per day and calls the model. The page receives the digits, never credentials.

From the repository's `basehero/` directory, run `nix develop .#androidEmulator --command bash scripts/sample-android.sh build` for an x86_64 debug APK, or `install` to build and install on the disposable `bh-fold-36` emulator at `emulator-5580`. The headless tests run with `nix develop --command cargo test -p basehero-sample-core`. The emulator check (`check.sh android-sample`) is updated alongside the BaseHero approval screen in the next integration task; it runs against `dev`, not production.

This sample uses `FileSecretStore` and disables Android backup. A real app must instead seal secrets under a platform-protected key as the guide's [Open the core](../../docs/build-an-app.md#open-the-core) section explains. The sample has no release signing or production configuration.
