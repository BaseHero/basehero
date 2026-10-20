package app.basehero.devicekeys

import android.app.Activity
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Internal JNI byte-array transport; no Invoke JSON, Strings, logs or WebView commands carry seeds. */
object DeviceKeysBridge {
    const val OK = 0
    const val UNAVAILABLE = 1
    const val CANCELLED = 2
    const val INVALIDATED = 3
    const val FAILURE = 4
    private const val PREFIX = "app.basehero.device-keys.v1."
    private const val PENDING = PREFIX + "pending."
    private const val STRONG = BiometricManager.Authenticators.BIOMETRIC_STRONG
    private val store get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val activityBinding = CurrentActivity<FragmentActivity>()
    private val creating = ConcurrentHashMap<Long, () -> Unit>()

    // App integration calls these from MainActivity.onResume/onPause. Until then JNI
    // fails Unavailable rather than mistaking Tao's Application for an Activity.
    @JvmStatic fun attachActivity(activity: FragmentActivity) { activityBinding.attach(activity) }
    @JvmStatic fun detachActivity(activity: FragmentActivity) { activityBinding.detach(activity) }
    @JvmStatic fun currentActivity(): Activity? = activityBinding.current()?.takeUnless { it.isFinishing || it.isDestroyed }

    // Implemented in Rust. The native callback copies then wipes the JVM array on return.
    @JvmStatic external fun nativeComplete(ticket: Long, code: Int, bytes: ByteArray?)

    private fun alias(handle: String, role: String) = PREFIX + handle + "." + role
    private fun directory(activity: Activity) = File(activity.noBackupFilesDir, "device-keys-v1").also { check(it.isDirectory || it.mkdirs()) }
    private fun name(handle: String, role: String) = "$handle.$role"
    private fun key(alias: String): SecretKey? = store.getKey(alias, null) as? SecretKey

    private fun generate(alias: String, gated: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        if (gated) {
            if (Build.VERSION.SDK_INT < 30) throw UnsupportedOperationException()
            spec.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
        }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(spec.build()) }.generateKey()
    }

    private fun encrypt(key: SecretKey, ad: ByteArray, bytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(ad)
        check(cipher.iv.size == 12) // framing is fixed; never persist a different IV length
        return byteArrayOf(1) + cipher.iv + cipher.doFinal(bytes)
    }

    private fun decrypt(key: SecretKey, ad: ByteArray, blob: ByteArray): ByteArray {
        val (iv, ciphertext) = BlobFraming.parse(blob)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }

    private fun ad(handle: String, role: String) = BlobFraming.ad(handle, role)
    private fun read(activity: Activity, handle: String, role: String): ByteArray {
        val associatedData = ad(handle, role) // validate before using handle in a path
        val file = File(directory(activity), name(handle, role))
        if (!file.isFile) throw Missing()
        val wrapper = key(alias(handle, if (role == "control") "control" else "ordinary")) ?: throw Missing()
        return decrypt(wrapper, associatedData, file.readBytes())
    }
    private class Missing : Exception()

    private fun reply(ticket: Long, block: () -> ByteArray) {
        var output: ByteArray? = null
        var code = OK
        try { output = block() }
        catch (_: KeyPermanentlyInvalidatedException) { code = INVALIDATED }
        catch (_: Missing) { code = INVALIDATED }
        catch (_: UnsupportedOperationException) { code = UNAVAILABLE }
        catch (_: UserNotAuthenticatedException) { code = UNAVAILABLE }
        catch (_: Exception) { code = FAILURE }
        try { nativeComplete(ticket, code, output) } finally { output?.fill(0) }
    }

    private fun status(error: Exception): Int = when (error) {
        is KeyPermanentlyInvalidatedException, is Missing -> INVALIDATED
        is UnsupportedOperationException, is UserNotAuthenticatedException -> UNAVAILABLE
        else -> FAILURE
    }

    private fun cleanup(dir: File, handle: String, normalAlias: String, controlAlias: String) {
        var failed = false
        for (role in listOf("ordinary", "receiver", "control", "control-public")) {
            for (suffix in listOf("", ".tmp")) {
                val file = File(dir, name(handle, role) + suffix)
                if (file.exists() && !file.delete()) failed = true
            }
        }
        if (runCatching { store.deleteEntry(normalAlias) }.isFailure) failed = true
        if (runCatching { store.deleteEntry(controlAlias) }.isFailure) failed = true
        if (failed) throw IllegalStateException("device-key creation cleanup failed")
    }

    private fun persist(dir: File, handle: String, role: String, encrypted: ByteArray) {
        val file = File(dir, name(handle, role))
        val temp = File(dir, name(handle, role) + ".tmp")
        FileOutputStream(temp).use { it.write(encrypted); it.fd.sync() }
        if (!temp.renameTo(file)) throw IllegalStateException()
    }

    /** The control input is copied into an owned attempt before this method returns.
     *  Ordinary records are written now, but control is sealed only after
     *  a prompt authorizes the exact ENCRYPT Cipher used to seal it. */
    @JvmStatic fun create(activity: Activity, handle: String, ordinary: ByteArray, receiver: ByteArray, control: ByteArray, ticket: Long) {
        var attempt: CreationAttempt? = null
        var worker: java.util.concurrent.ExecutorService? = null
        var dir: File? = null
        val normalAlias = alias(handle, "ordinary")
        val controlAlias = alias(handle, "control")
        try {
            ad(handle, "ordinary") // validate before constructing a path or Keystore alias
            val directory = directory(activity)
            dir = directory
            if (activity !is FragmentActivity || !BlobFraming.acceptsStrongControl(
                Build.VERSION.SDK_INT,
                BiometricManager.from(activity).canAuthenticate(STRONG) == BiometricManager.BIOMETRIC_SUCCESS
            )) throw UnsupportedOperationException()
            val roles = listOf("ordinary", "receiver", "control", "control-public")
            if (key(normalAlias) != null || key(controlAlias) != null || roles.any {
                File(directory, name(handle, it)).exists() || File(directory, name(handle, it) + ".tmp").exists()
            }) throw IllegalStateException()
            val main = Handler(Looper.getMainLooper())
            val executor = Executors.newSingleThreadExecutor()
            worker = executor
            var deadline: Runnable? = null
            val owned = CreationAttempt(listOf(control)) { code ->
                creating.remove(ticket)
                deadline?.let(main::removeCallbacks)
                executor.shutdown()
                nativeComplete(ticket, code, if (code == OK) byteArrayOf() else null)
            }
            attempt = owned
            val rollback = { cleanup(directory, handle, normalAlias, controlAlias) }
            var prompt: BiometricPrompt? = null
            val finishing = AtomicBoolean(false)
            val abort: (Int) -> Unit = { code ->
                if (finishing.compareAndSet(false, true)) {
                    runCatching { executor.execute { owned.abort(code, rollback) } }
                        .onFailure { owned.abort(FAILURE, rollback) }
                    activity.runOnUiThread { prompt?.cancelAuthentication() }
                }
            }
            // Synchronous preparation finishes before any timeout/cancel can
            // race file writes; Rust's wait begins only once this call returns.
            generate(normalAlias, false)
            generate(controlAlias, true)
            val normal = key(normalAlias) ?: throw Missing()
            persist(directory, handle, "ordinary", encrypt(normal, ad(handle, "ordinary"), ordinary))
            persist(directory, handle, "receiver", encrypt(normal, ad(handle, "receiver"), receiver))
            // Metadata must be sealed before the control prompt can complete creation.
            // Invalid inputs fail and roll back, never return a metadata-less handle.
            require(control.size == 66 && control[0] == 1.toByte() && control[1] == 1.toByte())
            val publicRecord = control.copyOfRange(0, 34)
            try {
                persist(directory, handle, "control-public",
                    encrypt(normal, ad(handle, "control-public"), publicRecord))
            } finally { publicRecord.fill(0) }
            val controlAd = ad(handle, "control") // validate without using the auth-bound operation
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key(controlAlias) ?: throw Missing())
            check(cipher.iv.size == 12)
            // Register before starting the prompt so its error/timeout paths can
            // always finish the attempt. An expired prompt never retains seeds.
            creating[ticket] = { abort(UNAVAILABLE) }
            deadline = Runnable { abort(UNAVAILABLE) }
            main.postDelayed(deadline, 115_000L) // precedes Rust's 120 s blocking wait
            activity.runOnUiThread {
                if (!creating.containsKey(ticket)) return@runOnUiThread
                try {
                    prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val bound = result.cryptoObject?.cipher
                            if (bound !== cipher) { abort(FAILURE); return }
                            if (!finishing.compareAndSet(false, true)) return
                            runCatching { executor.execute {
                                owned.succeed({ records ->
                                    val encrypted = finishWithAuthenticatedAad(controlAd,
                                        { bytes -> cipher.updateAAD(bytes) },
                                        { byteArrayOf(1) + cipher.iv + cipher.doFinal(records[0]) })
                                    persist(directory, handle, "control", encrypted)
                                }, rollback)
                            } }.onFailure { owned.abort(FAILURE, rollback) }
                        }
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            abort(if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                                errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                                errorCode == BiometricPrompt.ERROR_CANCELED) CANCELLED else UNAVAILABLE)
                        }
                    })
                    prompt?.authenticate(
                        BiometricPrompt.PromptInfo.Builder().setTitle("Confirm new device")
                            .setNegativeButtonText("Cancel").setAllowedAuthenticators(STRONG).build(),
                        BiometricPrompt.CryptoObject(cipher)
                    )
                } catch (_: Exception) { abort(FAILURE) }
            }
        } catch (error: Exception) {
            // No collision cleanup: only an attempt created after a vacant-namespace
            // preflight is allowed to delete these exact fresh aliases/files.
            val owned = attempt
            val directory = dir
            if (owned != null && directory != null) {
                owned.abort(status(error)) { cleanup(directory, handle, normalAlias, controlAlias) }
                worker?.shutdown()
            } else nativeComplete(ticket, status(error), null)
        } finally {
            // These JNI argument arrays are *not* the callback's owned copies.
            ordinary.fill(0); receiver.fill(0); control.fill(0)
        }
    }

    /** Rust's 120-second wait timed out or the owner cancelled the operation. */
    @JvmStatic fun abortCreate(ticket: Long) { creating[ticket]?.invoke() }

    @JvmStatic fun readOrdinary(activity: Activity, handle: String, role: String, ticket: Long) {
        reply(ticket) {
            if (role != "ordinary" && role != "receiver") throw IllegalArgumentException()
            read(activity, handle, role)
        }
    }

    /** Read authenticated public metadata without initializing the gated control Cipher. */
    @JvmStatic fun readControlPublic(activity: Activity, handle: String, ticket: Long) {
        reply(ticket) {
            if (!File(directory(activity), name(handle, "control")).isFile) throw Missing()
            read(activity, handle, "control-public")
        }
    }

    /** Prompt decrypts with the same Cipher supplied as CryptoObject, never a prior UI-only gate. */
    @JvmStatic fun readControl(activity: Activity, handle: String, ticket: Long) {
        if (activity !is FragmentActivity || !BlobFraming.acceptsStrongControl(
            Build.VERSION.SDK_INT,
            BiometricManager.from(activity).canAuthenticate(STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        )) {
            nativeComplete(ticket, UNAVAILABLE, null)
            return
        }
        val blob: ByteArray
        val cipher: Cipher
        val associatedData: ByteArray
        try {
            associatedData = ad(handle, "control") // validate before using handle in a path
            val file = File(directory(activity), name(handle, "control"))
            if (!file.isFile) throw Missing()
            blob = file.readBytes()
            val (iv, _) = BlobFraming.parse(blob)
            val wrapper = key(alias(handle, "control")) ?: throw Missing()
            cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapper, GCMParameterSpec(128, iv))
        } catch (_: KeyPermanentlyInvalidatedException) { nativeComplete(ticket, INVALIDATED, null); return }
          catch (_: Missing) { nativeComplete(ticket, INVALIDATED, null); return }
          catch (_: Exception) { nativeComplete(ticket, FAILURE, null); return }
        activity.runOnUiThread {
            val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    reply(ticket) {
                        val bound = result.cryptoObject?.cipher ?: throw IllegalStateException()
                        if (bound !== cipher) throw IllegalStateException()
                        finishWithAuthenticatedAad(associatedData,
                            { bytes -> bound.updateAAD(bytes) },
                            { bound.doFinal(blob, 13, blob.size - 13) })
                    }
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    nativeComplete(ticket, if (cancelled) CANCELLED else UNAVAILABLE, null)
                }
            })
            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder().setTitle("Confirm account change")
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(STRONG).build(),
                BiometricPrompt.CryptoObject(cipher)
            )
        }
    }

    // Direct Keystore GCM, not portable XChaCha framing: no exportable wrapping
    // key crosses JNI; version, purpose and key handle are authenticated as AAD.
    // Every seal gets its own fresh key, so retiring one setup's code-bearing
    // key never touches its no-code replacement or another setup.
    @Suppress("UNUSED_PARAMETER")
    @JvmStatic fun sealPending(activity: Activity, handle: String, plaintext: ByteArray, ticket: Long) {
        try {
            reply(ticket) {
                val associatedData = BlobFraming.pendingAd(handle) // validate before naming an alias
                if (store.containsAlias(PENDING + handle)) throw IllegalStateException()
                generate(PENDING + handle, false)
                encrypt(key(PENDING + handle) ?: throw Missing(), associatedData, plaintext)
            }
        } finally { plaintext.fill(0) }
    }
    /** Opening never creates a replacement key: a missing key is Unavailable. */
    @Suppress("UNUSED_PARAMETER")
    @JvmStatic fun openPending(activity: Activity, handle: String, blob: ByteArray, ticket: Long) {
        reply(ticket) {
            val associatedData = BlobFraming.pendingAd(handle)
            val wrapper = key(PENDING + handle) ?: throw UnsupportedOperationException()
            decrypt(wrapper, associatedData, blob)
        }
    }
    /** Idempotent: an absent key was already retired. */
    @Suppress("UNUSED_PARAMETER")
    @JvmStatic fun retirePending(activity: Activity, handle: String, ticket: Long) {
        reply(ticket) {
            BlobFraming.pendingAd(handle)
            if (store.containsAlias(PENDING + handle)) store.deleteEntry(PENDING + handle)
            byteArrayOf()
        }
    }
}
