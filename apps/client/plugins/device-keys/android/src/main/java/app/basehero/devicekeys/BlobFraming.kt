package app.basehero.devicekeys

/** Authenticated envelope: one version byte, 12-byte GCM IV, ciphertext+16-byte tag. */
internal object BlobFraming {
    fun acceptsStrongControl(api: Int, hasStrongBiometrics: Boolean) = api >= 30 && hasStrongBiometrics
    fun parse(blob: ByteArray): Pair<ByteArray, ByteArray> {
        require(blob.size >= 29 && blob[0] == 1.toByte())
        return blob.copyOfRange(1, 13) to blob.copyOfRange(13, blob.size)
    }
    private fun requireHandle(handle: String) =
        require(handle.length == 64 && handle.all { it in '0'..'9' || it in 'a'..'f' })
    fun pendingAd(handle: String): ByteArray {
        requireHandle(handle)
        return "BaseHero pending setup v2:$handle".toByteArray(Charsets.US_ASCII)
    }
    fun ad(handle: String, role: String): ByteArray {
        requireHandle(handle)
        require(role == "ordinary" || role == "receiver" || role == "control" || role == "control-public")
        return "BaseHero device keys v1:$handle:$role".toByteArray(Charsets.US_ASCII)
    }
}
