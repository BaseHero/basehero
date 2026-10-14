# Private Android device-key plugin (inactive)

This crate is an explicit workspace member but **not** a client dependency or
`default-member`. The Android library module builds standalone with the app's
existing Gradle wrapper. From `basehero/`:

```sh
nix develop .#android --command bash scripts/check.sh android-device-keys
```

For later shell integration: package `android/` as an Android library dependency,
link this crate into the app's Rust library and register `bh_device_keys::init()`.
The shell must also call `DeviceKeysBridge.attachActivity(this)` from its
`FragmentActivity.onResume()` and `detachActivity(this)` from `onPause()`; this
is an **unwired hook**, not app registration in this increment. Tao's
`ndk_context` holds the Application, not an Activity. Every JNI request gets
the current weakly-bound Activity, promotes it to a GlobalRef just for dispatch,
and returns `Unavailable` if none is bound. The plugin has no commands or
WebView interface. Native account code constructs `AndroidKeyStore` and
`AndroidPendingSetupProtector` only when an account needs them, dispatching
**every call to a dedicated blocking worker** (for example `spawn_blocking`),
never the UI thread or an ordinary async executor worker. The adapter blocks
up to 120 seconds despite the async trait signature; `await` does not offload
it. It must compare the returned `StoredDevice` with verified account history
and recheck the account/window generation after each JNI/prompt operation.
Never hold an account or SQLite lock across it.

Rust generates independent libsodium Ed25519 and X-Wing seeds and passes records
as JNI byte arrays. Kotlin wipes its input/output `ByteArray`s; Rust wraps
returned plaintext in zeroizing owners. JVM and JNI internals may make additional
copies, which this adapter cannot wipe. No seed goes through Tauri Invoke JSON,
immutable JVM strings, or a JS command. Android Keystore AES-256-GCM wraps records
under independent ordinary and per-use strong-biometric control aliases; blobs
live in `noBackupFilesDir`. Both the control seed's initial ENCRYPT and later
DECRYPT use a strong-only CryptoObject prompt on the actual Cipher; create
returns only after the authenticated control ciphertext is persisted. The
control record is copied into a callback-owned byte array before create
returns; ordinary/receiver inputs are consumed and wiped synchronously.
Success, cancel, error and timeout wipe the callback-owned copy. Pending setup uses a
separate no-auth Keystore AES
key and a versioned `1-byte version + 12-byte IV + GCM ciphertext/tag` framing,
with purpose as GCM associated data. This differs from the portable XChaCha
framing because the Keystore key never crosses into Rust; `open` never creates
a replacement key. Control is unavailable before API 30 or without qualifying
strong biometrics, with no passcode or software fallback.

A library build, cross-compile and JVM tests do **not** establish Keystore,
biometric, power-loss, backup/transfer or full JNI behavior. Before activating,
package the module in the app, verify backup/device-transfer exclusions for all
app state, exercise create/load/sign/decapsulate/pending seal on an emulator,
check prompt cancellation and enrollment invalidation, and verify app identity
and availability on target Android versions. Do not assume that a restored blob
without its Keystore alias represents the admitted device.
