package app.basehero.devicekeys

import android.app.Activity
import android.content.Intent
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicLong

/** Real framework/Keystore/Prompt probe. Run only on a disposable enrolled emulator. */
@RunWith(AndroidJUnit4::class)
class DeviceKeysEmulatorTest {
    private lateinit var activity: Activity
    private val next = AtomicLong(System.nanoTime())
    private fun ticket() = next.incrementAndGet()
    private fun handle() = List(2) { java.util.UUID.randomUUID().toString().replace("-", "") }.joinToString("")
    private fun dir() = File(activity.noBackupFilesDir, "device-keys-v1")
    private fun aliases(handle: String) = listOf("ordinary", "control").map { "app.basehero.device-keys.v1.$handle.$it" }
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun result(t: Long) = ProbeResults.await(t)
    private fun controlRecord() = byteArrayOf(1, 1) + ByteArray(32) { it.toByte() } + ByteArray(32) { (it + 40).toByte() }
    private fun fingerprint(t: Long): ProbeResults.Result {
        android.util.Log.i("DeviceKeysFingerprint", "touch-$t")
        return result(t)
    }
    private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean =
        haystack.asList().windowed(needle.size).any { it == needle.asList() }
    private fun roles() = listOf("ordinary", "receiver", "control", "control-public")
    private fun recordFiles(handle: String) = roles().map { File(dir(), "$handle.$it") }
    private fun filesFor(handle: String) = roles().flatMap { role ->
        listOf(File(dir(), "$handle.$role"), File(dir(), "$handle.$role.tmp"))
    }
    private fun createDevice(handle: String, ordinary: ByteArray = byteArrayOf(1, 2, 3), receiver: ByteArray = byteArrayOf(4, 5, 6)) {
        val t = ticket()
        DeviceKeysBridge.create(activity, handle, ordinary, receiver, controlRecord(), t)
        assertTrue(ProbeResults.noResponseFor(2))
        assertEquals(DeviceKeysBridge.OK, fingerprint(t).code)
    }

    @Before fun launch() {
        // Load the debug-only native callback from the target APK class loader.
        ProbeResults.noResponseFor(0)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, ProbeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        instrumentation.waitForIdleSync()
    }
    @After fun close() {
        if (this::activity.isInitialized) {
            activity.finish()
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        }
    }

    @Test fun ordinaryReceiverAndPendingRoundTrip() {
        val h = handle()
        // Match the Rust record lengths: 2-byte header, public key, 32-byte seed.
        val ordinaryExpected = ByteArray(66) { it.toByte() }
        val receiverExpected = ByteArray(1250) { (it % 251).toByte() }
        val ordinary = ordinaryExpected.clone()
        val receiver = receiverExpected.clone()
        val t = ticket()
        val control = byteArrayOf(1, 1) + ByteArray(64) { (it + 11).toByte() }
        DeviceKeysBridge.create(activity, h, ordinary, receiver, control, t)
        // Creation must not return a device before the control ENCRYPT prompt succeeds.
        assertTrue("control created without authentication", ProbeResults.noResponseFor(2))
        assertEquals(DeviceKeysBridge.OK, fingerprint(t).code)
        assertArrayEquals(ByteArray(66), ordinary)
        assertArrayEquals(ByteArray(1250), receiver)
        assertArrayEquals(ByteArray(66), control)
        val publicRead = ticket()
        DeviceKeysBridge.readControlPublic(activity, h, publicRead)
        // Unlike readControl, ordinary identity load returns without a biometric touch.
        assertArrayEquals(byteArrayOf(1, 1) + ByteArray(32) { (it + 11).toByte() }, result(publicRead).bytes)
        val publicFile = File(dir(), "$h.control-public")
        val publicBlob = publicFile.readBytes()
        val altered = publicBlob.clone().apply { this[lastIndex] = (last().toInt() xor 1).toByte() }
        publicFile.writeBytes(altered)
        val tamperedPublic = ticket()
        DeviceKeysBridge.readControlPublic(activity, h, tamperedPublic)
        assertEquals(DeviceKeysBridge.FAILURE, result(tamperedPublic).code)
        assertArrayEquals(altered, publicFile.readBytes()) // reads never repair corruption
        val ordinaryBlobForSubstitution = File(dir(), "$h.ordinary").readBytes()
        publicFile.writeBytes(ordinaryBlobForSubstitution)
        val swappedRole = ticket()
        DeviceKeysBridge.readControlPublic(activity, h, swappedRole)
        assertEquals(DeviceKeysBridge.FAILURE, result(swappedRole).code)
        assertArrayEquals(ordinaryBlobForSubstitution, publicFile.readBytes())
        publicFile.writeBytes(publicBlob)
        val records = listOf("ordinary" to ordinaryExpected, "receiver" to receiverExpected)
        for ((role, expected) in records) {
            val read = ticket()
            DeviceKeysBridge.readOrdinary(activity, h, role, read)
            assertArrayEquals(expected, result(read).bytes)
            val file = File(dir(), "$h.$role")
            assertTrue(file.isFile)
            val stored = file.readBytes()
            assertFalse("$role persisted in plaintext", containsBytes(stored, expected))
            file.writeBytes(stored.clone().apply { this[lastIndex] = (last().toInt() xor 1).toByte() })
            val tamper = ticket()
            DeviceKeysBridge.readOrdinary(activity, h, role, tamper)
            assertEquals("$role accepted altered ciphertext", DeviceKeysBridge.FAILURE, result(tamper).code)
            file.writeBytes(stored)
        }
        val ordinaryFile = File(dir(), "$h.ordinary")
        val receiverFile = File(dir(), "$h.receiver")
        val ordinaryBlob = ordinaryFile.readBytes()
        val receiverBlob = receiverFile.readBytes()
        try {
            ordinaryFile.writeBytes(receiverBlob)
            receiverFile.writeBytes(ordinaryBlob)
            for ((role, _) in records) {
                val swap = ticket()
                DeviceKeysBridge.readOrdinary(activity, h, role, swap)
                assertEquals("$role accepted the other role's blob", DeviceKeysBridge.FAILURE, result(swap).code)
            }
        } finally {
            ordinaryFile.writeBytes(ordinaryBlob)
            receiverFile.writeBytes(receiverBlob)
        }
        assertTrue(File(dir(), "$h.control").isFile)
        assertTrue(File(dir(), "$h.control-public").isFile)
        assertFalse(File(activity.filesDir, "device-keys-v1").exists())
        assertFalse(File(activity.cacheDir, "device-keys-v1").exists())
        val input = byteArrayOf(1, 2, 3, 4)
        val kit = handle()
        val seal = ticket()
        DeviceKeysBridge.sealPending(activity, kit, input, seal)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0), input)
        val blob = result(seal).bytes!!
        val reuse = ticket()
        DeviceKeysBridge.sealPending(activity, kit, byteArrayOf(5), reuse)
        assertEquals("sealing replaced an existing pending key", DeviceKeysBridge.FAILURE, result(reuse).code)
        val open = ticket()
        DeviceKeysBridge.openPending(activity, kit, blob, open)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), result(open).bytes)
        val home = handle()
        val reseal = ticket()
        DeviceKeysBridge.sealPending(activity, home, byteArrayOf(6, 7), reseal)
        val homeBlob = result(reseal).bytes!!
        val crossed = ticket()
        DeviceKeysBridge.openPending(activity, home, blob, crossed)
        assertEquals("one setup key opened another's blob", DeviceKeysBridge.FAILURE, result(crossed).code)
        val tampered = blob.clone().apply { this[lastIndex] = (last().toInt() xor 1).toByte() }
        val tamper = ticket()
        DeviceKeysBridge.openPending(activity, kit, tampered, tamper)
        assertEquals(DeviceKeysBridge.FAILURE, result(tamper).code)
        repeat(2) { // retirement is idempotent
            val retire = ticket()
            DeviceKeysBridge.retirePending(activity, kit, retire)
            assertEquals(DeviceKeysBridge.OK, result(retire).code)
        }
        assertFalse(store().containsAlias("app.basehero.device-keys.v1.pending.$kit"))
        val retired = ticket()
        DeviceKeysBridge.openPending(activity, kit, blob, retired)
        assertEquals("a retired key reopened its blob", DeviceKeysBridge.UNAVAILABLE, result(retired).code)
        val kept = ticket()
        DeviceKeysBridge.openPending(activity, home, homeBlob, kept)
        assertArrayEquals(byteArrayOf(6, 7), result(kept).bytes)
        val cleanup = ticket()
        DeviceKeysBridge.retirePending(activity, home, cleanup)
        assertEquals(DeviceKeysBridge.OK, result(cleanup).code)
    }

    @Test fun deleteKeysErasesCreatedKeys() {
        val h = handle()
        createDevice(h)
        assertTrue(aliases(h).all { store().containsAlias(it) })
        assertTrue(recordFiles(h).all { it.isFile })
        // A crash between write and rename leaves a .tmp; erase must remove those too.
        val strays = listOf("ordinary", "control-public").map { File(dir(), "$h.$it.tmp") }
        for (stray in strays) {
            stray.writeBytes(byteArrayOf(9))
            assertTrue(stray.isFile)
        }
        val erase = ticket()
        DeviceKeysBridge.deleteKeys(activity, h, erase)
        assertEquals(DeviceKeysBridge.OK, result(erase).code)
        assertTrue("erasure left records: ${filesFor(h).filter { it.exists() }}", filesFor(h).none { it.exists() })
        assertTrue("erasure left aliases: ${aliases(h).filter { store().containsAlias(it) }}", aliases(h).none { store().containsAlias(it) })
        for (role in listOf("ordinary", "receiver")) {
            val load = ticket()
            DeviceKeysBridge.readOrdinary(activity, h, role, load)
            assertEquals("erased $role still loaded", DeviceKeysBridge.INVALIDATED, result(load).code)
        }
        val control = ticket()
        DeviceKeysBridge.readControlPublic(activity, h, control)
        assertEquals("erased control still loaded", DeviceKeysBridge.INVALIDATED, result(control).code)
    }

    @Test fun deleteKeysIsIdempotent() {
        val h = handle()
        createDevice(h)
        repeat(2) { attempt ->
            val erase = ticket()
            DeviceKeysBridge.deleteKeys(activity, h, erase)
            assertEquals("erase attempt $attempt", DeviceKeysBridge.OK, result(erase).code)
        }
        assertTrue(filesFor(h).none { it.exists() })
        assertTrue(aliases(h).none { store().containsAlias(it) })
        // A handle whose creation never completed was already erased.
        val never = handle()
        val absent = ticket()
        DeviceKeysBridge.deleteKeys(activity, never, absent)
        assertEquals(DeviceKeysBridge.OK, result(absent).code)
        assertTrue(filesFor(never).none { it.exists() })
        assertTrue(aliases(never).none { store().containsAlias(it) })
    }

    @Test fun deleteKeysLeavesAnotherHandle() {
        val h = handle()
        val other = handle()
        createDevice(h)
        createDevice(other)
        val erase = ticket()
        DeviceKeysBridge.deleteKeys(activity, h, erase)
        assertEquals(DeviceKeysBridge.OK, result(erase).code)
        assertTrue(filesFor(h).none { it.exists() })
        assertTrue(aliases(h).none { store().containsAlias(it) })
        assertTrue("another handle's records were erased", recordFiles(other).all { it.isFile })
        assertTrue("another handle's aliases were erased", aliases(other).all { store().containsAlias(it) })
        for ((role, expected) in listOf("ordinary" to byteArrayOf(1, 2, 3), "receiver" to byteArrayOf(4, 5, 6))) {
            val load = ticket()
            DeviceKeysBridge.readOrdinary(activity, other, role, load)
            assertArrayEquals("another handle's $role was disturbed", expected, result(load).bytes)
        }
        val control = ticket()
        DeviceKeysBridge.readControlPublic(activity, other, control)
        assertArrayEquals(byteArrayOf(1, 1) + ByteArray(32) { it.toByte() }, result(control).bytes)
    }

    @Test fun deleteKeysRejectsInvalidHandle() {
        val dir = dir()
        val existed = dir.exists()
        fun snapshot() = dir.listFiles()?.map { it.name }?.sorted() ?: emptyList()
        val before = snapshot()
        val invalid = handle().uppercase() // right length, not lowercase hex
        val erase = ticket()
        DeviceKeysBridge.deleteKeys(activity, invalid, erase)
        assertEquals(DeviceKeysBridge.FAILURE, result(erase).code)
        assertEquals("invalid handle created the key directory", existed, dir.exists())
        assertEquals("invalid handle touched device-key storage", before, snapshot())
        assertFalse(store().containsAlias("app.basehero.device-keys.v1.$invalid.ordinary"))
        assertFalse(store().containsAlias("app.basehero.device-keys.v1.$invalid.control"))
    }

    @Test fun deleteKeysReportsFailureWhenARecordCannotBeDeleted() {
        val h = handle()
        createDevice(h)
        // A non-empty directory in a record's place cannot be deleted by File.delete.
        val blocked = File(dir(), "$h.receiver")
        assertTrue(blocked.delete())
        assertTrue(blocked.mkdir())
        val blocker = File(blocked, "still-here")
        blocker.writeText("blocker")
        val erase = ticket()
        DeviceKeysBridge.deleteKeys(activity, h, erase)
        assertEquals("an undeletable record was reported as erased", DeviceKeysBridge.FAILURE, result(erase).code)
        assertTrue(blocked.isDirectory)
        assertTrue(blocker.isFile)
        // Clearing the obstacle lets a later erase finish; partial erasure never claims success.
        assertTrue(blocker.delete())
        assertTrue(blocked.delete())
        val retry = ticket()
        DeviceKeysBridge.deleteKeys(activity, h, retry)
        assertEquals(DeviceKeysBridge.OK, result(retry).code)
        assertTrue(filesFor(h).none { it.exists() })
        assertTrue(aliases(h).none { store().containsAlias(it) })
    }

    @Test fun cancelledCreationLeavesNothing() {
        val h = handle()
        val t = ticket()
        DeviceKeysBridge.create(activity, h, byteArrayOf(1), byteArrayOf(2), controlRecord(), t)
        try { ProbeResults.noResponseFor(2) } catch (error: IllegalStateException) {
            val availability = BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            val present = aliases(h).map { store().containsAlias(it) }
            val files = listOf("ordinary", "receiver", "control").map { File(dir(), "$h.$it").exists() }
            throw AssertionError("premature result; biometric=$availability aliases=$present files=$files", error)
        }
        val ui = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        val cancel = ui.wait(Until.findObject(By.text("Cancel")), 10_000)
        assertNotNull("prompt Cancel button not shown", cancel)
        cancel.click()
        assertEquals(DeviceKeysBridge.CANCELLED, result(t).code)
        assertTrue(aliases(h).none { store().containsAlias(it) })
        assertTrue(listOf("ordinary", "receiver", "control", "control-public").none { File(dir(), "$h.$it").exists() })
    }

    @Test fun abortedCreationLeavesNothing() {
        val h = handle()
        val t = ticket()
        DeviceKeysBridge.create(activity, h, byteArrayOf(1), byteArrayOf(2), controlRecord(), t)
        assertTrue(ProbeResults.noResponseFor(2))
        DeviceKeysBridge.abortCreate(t) // deadline/owner timeout path, without a 115-second sleep
        assertEquals(DeviceKeysBridge.UNAVAILABLE, result(t).code)
        assertTrue(aliases(h).none { store().containsAlias(it) })
        assertTrue(listOf("ordinary", "receiver", "control", "control-public").none { File(dir(), "$h.$it").exists() })
    }

    @Test fun protectedReadRequiresAuthentication() {
        val h = handle()
        val create = ticket()
        DeviceKeysBridge.create(activity, h, byteArrayOf(1), byteArrayOf(2), controlRecord(), create)
        assertTrue(ProbeResults.noResponseFor(2))
        assertEquals(DeviceKeysBridge.OK, fingerprint(create).code)
        val read = ticket()
        DeviceKeysBridge.readControl(activity, h, read)
        assertTrue("protected read completed without prompt", ProbeResults.noResponseFor(2))
        assertArrayEquals(controlRecord(), fingerprint(read).bytes)
        val file = File(dir(), "$h.control")
        val stored = file.readBytes()
        file.writeBytes(stored.clone().apply { this[lastIndex] = (last().toInt() xor 1).toByte() })
        val tamper = ticket()
        DeviceKeysBridge.readControl(activity, h, tamper)
        assertTrue("altered control completed without prompt", ProbeResults.noResponseFor(2))
        assertEquals("control accepted altered ciphertext", DeviceKeysBridge.FAILURE, fingerprint(tamper).code)
    }

    @Test fun invalidMetadataAtCreationRollsBack() {
        val h = handle()
        val create = ticket()
        DeviceKeysBridge.create(activity, h, byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), create)
        assertEquals(DeviceKeysBridge.FAILURE, result(create).code)
        assertTrue(aliases(h).none { store().containsAlias(it) })
        assertTrue(listOf("ordinary", "receiver", "control", "control-public").flatMap { role ->
            listOf(File(dir(), "$h.$role"), File(dir(), "$h.$role.tmp"))
        }.none { it.exists() })
        val load = ticket()
        DeviceKeysBridge.readControlPublic(activity, h, load)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(load).code)
    }

    @Test fun missingMetadataDoesNotRepairIt() {
        val h = handle()
        val create = ticket()
        DeviceKeysBridge.create(activity, h, byteArrayOf(1), byteArrayOf(2), controlRecord(), create)
        assertTrue(ProbeResults.noResponseFor(2))
        assertEquals(DeviceKeysBridge.OK, fingerprint(create).code)
        assertTrue(File(dir(), "$h.control-public").delete())
        val missing = ticket()
        DeviceKeysBridge.readControlPublic(activity, h, missing)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(missing).code)
        assertFalse(File(dir(), "$h.control-public").exists())
    }

    @Test fun missingAliasAndFileAreInvalidated() {
        val missing = ticket()
        DeviceKeysBridge.readOrdinary(activity, handle(), "ordinary", missing)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(missing).code)
        val h = handle()
        val create = ticket()
        DeviceKeysBridge.create(activity, h, byteArrayOf(1), byteArrayOf(2), controlRecord(), create)
        assertTrue(ProbeResults.noResponseFor(2))
        assertEquals(DeviceKeysBridge.OK, fingerprint(create).code)
        File(dir(), "$h.ordinary").delete()
        val file = ticket()
        DeviceKeysBridge.readOrdinary(activity, h, "ordinary", file)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(file).code)
        store().deleteEntry(aliases(h)[0])
        val alias = ticket()
        DeviceKeysBridge.readOrdinary(activity, h, "receiver", alias)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(alias).code)
        val controlFile = File(dir(), "$h.control")
        val ciphertext = controlFile.readBytes()
        assertTrue(controlFile.delete())
        val controlMissingFile = ticket()
        DeviceKeysBridge.readControl(activity, h, controlMissingFile)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(controlMissingFile).code)
        controlFile.writeBytes(ciphertext)
        store().deleteEntry(aliases(h)[1])
        val controlMissingAlias = ticket()
        DeviceKeysBridge.readControl(activity, h, controlMissingAlias)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(controlMissingAlias).code)
    }

    @Test fun prepareEnrollmentChange() {
        val h = handle()
        val create = ticket()
        DeviceKeysBridge.create(activity, h, byteArrayOf(1), byteArrayOf(2), controlRecord(), create)
        assertTrue(ProbeResults.noResponseFor(2))
        assertEquals(DeviceKeysBridge.OK, fingerprint(create).code)
        File(dir(), "enrollment-probe-handle").writeText(h)
    }

    @Test fun enrollmentChangeInvalidatesControl() {
        val h = File(dir(), "enrollment-probe-handle").readText()
        val read = ticket()
        DeviceKeysBridge.readControl(activity, h, read)
        assertEquals(DeviceKeysBridge.INVALIDATED, result(read).code)
    }
}
