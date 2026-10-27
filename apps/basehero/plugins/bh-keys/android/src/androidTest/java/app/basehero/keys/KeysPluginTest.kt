package app.basehero.keys

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KeysPluginTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val plugin = KeysPlugin(context)
    private val file = File(context.noBackupFilesDir, "master.key.v1")
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Before fun fresh() {
        file.delete()
        if (keyStore.containsAlias("bh-master-wrap")) keyStore.deleteEntry("bh-master-wrap")
    }

    @Test fun masterKeyIsStableAndLivesOutsideBackup() {
        val a = plugin.loadOrCreateMasterKey(); val b = KeysPlugin(context).loadOrCreateMasterKey()
        assertEquals(32, a.size)
        assertArrayEquals(a, b)
        assertTrue(file.exists()); assertNotEquals(32L, file.length())
        assertFalse("the file holds the key unwrapped", file.readBytes().toList().windowed(32).any { it == a.toList() })
    }

    @Test fun aBlobWrappedByAnotherKeyIsRefused() {
        plugin.loadOrCreateMasterKey()
        val other = file.readBytes()
        fresh()
        plugin.loadOrCreateMasterKey()
        file.writeBytes(other)
        assertThrows(Exception::class.java) { plugin.loadOrCreateMasterKey() }
        assertArrayEquals(other, file.readBytes())
    }

    @Test fun aMissingWrappingKeyIsRefusedNotReplaced() {
        plugin.loadOrCreateMasterKey()
        val wrapped = file.readBytes()
        keyStore.deleteEntry("bh-master-wrap")
        assertThrows(Exception::class.java) { plugin.loadOrCreateMasterKey() }
        assertArrayEquals(wrapped, file.readBytes())
        assertFalse(keyStore.containsAlias("bh-master-wrap"))
    }
}
