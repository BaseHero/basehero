package app.basehero.devicekeys

import java.util.concurrent.atomic.AtomicBoolean

/** Invoke only from the verified CryptoObject success path. Keystore2 sends
 *  updateAAD to the provider immediately, so even AAD needs its auth token. */
internal fun <T> finishWithAuthenticatedAad(
    associatedData: ByteArray,
    updateAAD: (ByteArray) -> Unit,
    finish: () -> T
): T {
    updateAAD(associatedData)
    return finish()
}

/** Owns copies of JNI inputs across an asynchronous biometric prompt. */
internal class CreationAttempt(inputs: List<ByteArray>, private val complete: (Int) -> Unit) {
    internal val owned = inputs.map { it.clone() }
    private val finished = AtomicBoolean(false)

    // Called only after BiometricPrompt returns the *same* authorized encrypt Cipher.
    fun succeed(persist: (List<ByteArray>) -> Unit, cleanup: () -> Unit) {
        if (!finished.compareAndSet(false, true)) return
        var code = DeviceKeysBridge.OK
        try {
            persist(owned)
        } catch (_: Throwable) {
            code = DeviceKeysBridge.FAILURE
            runCatching(cleanup)
        } finally {
            owned.forEach { it.fill(0) }
            complete(code)
        }
    }

    fun abort(code: Int, cleanup: () -> Unit) {
        if (!finished.compareAndSet(false, true)) return
        var outcome = code
        try { cleanup() } catch (_: Throwable) { outcome = DeviceKeysBridge.FAILURE }
        finally {
            owned.forEach { it.fill(0) }
            complete(outcome)
        }
    }
}
