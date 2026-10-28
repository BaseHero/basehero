package app.basehero.keys

import android.content.Context
import com.google.android.gms.auth.blockstore.Blockstore
import com.google.android.gms.auth.blockstore.DeleteBytesRequest
import com.google.android.gms.tasks.Tasks

/** Removes entries left by older releases; never stores or loads recovery kits. */
class KitStore(private val context: Context) {
    fun deleteAll() {
        Tasks.await(Blockstore.getClient(context).deleteBytes(
            DeleteBytesRequest.Builder().setDeleteAll(true).build()
        ))
    }
}
