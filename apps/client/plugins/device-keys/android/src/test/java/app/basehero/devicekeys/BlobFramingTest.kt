package app.basehero.devicekeys

import org.junit.Assert.*
import org.junit.Test

class BlobFramingTest {
    @Test fun rejectsTruncatedAndFutureVersionBeforeDecrypt() {
        val valid = byteArrayOf(1) + ByteArray(12) { it.toByte() } + ByteArray(16)
        assertArrayEquals(ByteArray(12) { it.toByte() }, BlobFraming.parse(valid).first)
        assertArrayEquals(ByteArray(16), BlobFraming.parse(valid).second)
        for (malformed in listOf(valid.copyOf(28), valid.clone().apply { this[0] = 2 })) {
            try { BlobFraming.parse(malformed); fail("accepted corrupt blob") }
            catch (_: IllegalArgumentException) { }
        }
    }
    @Test fun unsupportedApiNeverDowngradesStrongControl() {
        assertFalse(BlobFraming.acceptsStrongControl(29, true))
        assertFalse(BlobFraming.acceptsStrongControl(36, false))
        assertTrue(BlobFraming.acceptsStrongControl(30, true))
    }
    @Test fun purposeAndRoleBindAssociatedData() {
        val first = "a".repeat(64)
        val second = "b".repeat(64)
        assertFalse(BlobFraming.ad(first, "control").contentEquals(BlobFraming.ad(first, "ordinary")))
        assertFalse(BlobFraming.ad(first, "control").contentEquals(BlobFraming.ad(second, "control")))
        try { BlobFraming.ad("../", "control"); fail("accepted path traversal") }
        catch (_: IllegalArgumentException) { }
    }
}
