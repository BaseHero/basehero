# Private Android device-key plugin (inactive)

This crate is an explicit workspace member and Android-only client dependency,
but not a `default-member`. The app packages its Android library, registers the
empty native plugin and binds only its resumed Activity. No account operation
constructs or calls the adapter yet. The library also builds standalone with
the app's existing Gradle wrapper. From `basehero/`:

```sh
nix develop .#android --command bash scripts/check.sh android-device-keys
```

An opt-in, disposable API 36 x86_64 emulator check exercises the library's
Keystore and BiometricPrompt with an enrolled emulator fingerprint (never a
physical device):

```sh
nix develop .#androidEmulator --command bash scripts/check.sh android-device-keys-emulator
```

Its probe Activity, callback JNI shim and tests live only in the standalone
module's `androidTest` APK. The test loader is not the app's Rust JNI loader.

The shell calls `DeviceKeysBridge.attachActivity(this)` after
`FragmentActivity.onResume()` and `detachActivity(this)` before `onPause()`'s
super call. This is packaging and lifecycle wiring, not key activation. Tao's
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

The library's emulator instrumentation exercises its Kotlin Keystore and prompt
paths, but does not establish power-loss, backup/transfer, full app Rust JNI or
real-phone behavior. Before activating, verify backup/device-transfer exclusions
for all app state, exercise create/load/sign/decapsulate through Rust JNI, and
verify app identity and availability on target Android versions. Do not assume
that a restored blob
without its Keystore alias represents the admitted device.
