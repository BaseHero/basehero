package app.basehero.keys

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The install's master key, which seals every other secret the app keeps.
 * It is stored wrapped by an Android Keystore AES-256-GCM key, in a file
 * outside backups. Rust calls this through JNI and wipes the returned array;
 * the key never reaches the WebView.
 */
class KeysPlugin(private val context: Context) {
    private val file get() = File(context.noBackupFilesDir, FILE)
    private val keyStore get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** 32 bytes. Throws, leaving the file in place, if the stored key can't be unwrapped. */
    @Synchronized fun loadOrCreateMasterKey(): ByteArray {
        val file = file
        if (file.exists()) {
            val wrap = keyStore.getKey(ALIAS, null) as? SecretKey
                ?: throw IllegalStateException("the master key's wrapping key is missing")
            return unwrap(wrap, file.readBytes())
        }
        val master = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            val sealed = wrap(newWrappingKey(), master)
            val temporary = File(file.path + ".tmp")
            FileOutputStream(temporary).use { it.write(sealed); it.fd.sync() }
            if (!temporary.renameTo(file)) throw IllegalStateException("couldn't store the master key")
            return master.copyOf()
        } finally {
            master.fill(0)
        }
    }

    /** Remove the wrapped master key and its Keystore wrapping entry, never touching account data. */
    @Synchronized fun deleteMasterKey() {
        if (file.exists() && !file.delete()) throw IllegalStateException("couldn't delete the master key file")
        val temporary = File(file.path + ".tmp")
        if (temporary.exists() && !temporary.delete()) throw IllegalStateException("couldn't delete the temporary master key")
        keyStore.deleteEntry(ALIAS)
    }

    // Replaces any key left by an earlier first run that stopped before its file was stored.
    private fun newWrappingKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(spec) }.generateKey()
    }

    /** `[format 1][IV 12][ciphertext and tag]`, with a fixed label as associated data. */
    private fun wrap(key: SecretKey, master: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        check(cipher.iv.size == IV)
        cipher.updateAAD(AD)
        return byteArrayOf(FORMAT) + cipher.iv + cipher.doFinal(master)
    }

    private fun unwrap(key: SecretKey, sealed: ByteArray): ByteArray {
        if (sealed.size != 1 + IV + 32 + 16 || sealed[0] != FORMAT) {
            throw IllegalStateException("unknown master key format")
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed, 1, IV))
        cipher.updateAAD(AD)
        return cipher.doFinal(sealed, 1 + IV, sealed.size - 1 - IV)
    }

    private companion object {
        const val ALIAS = "bh-master-wrap"
        const val FILE = "master.key.v1"
        const val FORMAT: Byte = 1
        const val IV = 12
        val AD = "app.basehero.master.key.v1".toByteArray()
    }
}
