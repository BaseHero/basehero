package app.basehero.devicekeys

/** Authenticated envelope: one version byte, 12-byte GCM IV, ciphertext+16-byte tag. */
internal object BlobFraming {
    fun acceptsStrongControl(api: Int, hasStrongBiometrics: Boolean) = api >= 30 && hasStrongBiometrics
    fun parse(blob: ByteArray): Pair<ByteArray, ByteArray> {
        require(blob.size >= 29 && blob[0] == 1.toByte())
        return blob.copyOfRange(1, 13) to blob.copyOfRange(13, blob.size)
    }
    fun ad(handle: String, role: String): ByteArray {
        require(handle.length == 64 && handle.all { it in '0'..'9' || it in 'a'..'f' })
        require(role == "ordinary" || role == "receiver" || role == "control" || role == "control-public")
        return "BaseHero device keys v1:$handle:$role".toByteArray(Charsets.US_ASCII)
    }
}
