package app.basehero.keys

import android.content.Context
import com.google.android.gms.auth.blockstore.Blockstore
import com.google.android.gms.auth.blockstore.DeleteBytesRequest
import com.google.android.gms.auth.blockstore.RetrieveBytesRequest
import com.google.android.gms.auth.blockstore.StoreBytesData
import com.google.android.gms.tasks.Tasks

/** Only Rust calls this, from a blocking worker thread; the kit never enters the WebView.
 * Known limits: with Google backup off, the entry stays on this phone. Without a screen lock,
 * Google's copy isn't end-to-end encrypted. Removing a device does not change the kit.
 */
class KitStore(context: Context) {
    private val client = Blockstore.getClient(context)
    private fun key(account: String) = "bh.kit.$account"

    fun save(account: String, kit: ByteArray) {
        Tasks.await(client.storeBytes(StoreBytesData.Builder()
            .setKey(key(account)).setBytes(kit).setShouldBackupToCloud(true).build()))
    }

    fun load(account: String): ByteArray? = Tasks.await(client.retrieveBytes(
        RetrieveBytesRequest.Builder().setKeys(listOf(key(account))).build()
    )).blockstoreDataMap[key(account)]?.bytes

    fun delete(account: String) {
        Tasks.await(client.deleteBytes(DeleteBytesRequest.Builder().setKeys(listOf(key(account))).build()))
    }
}
