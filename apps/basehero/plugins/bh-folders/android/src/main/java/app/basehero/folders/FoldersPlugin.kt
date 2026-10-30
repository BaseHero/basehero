package app.basehero.folders

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.os.storage.StorageManager
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@TauriPlugin
class FoldersPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun pick(invoke: Invoke) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        }
        startActivityForResult(invoke, intent, "picked")
    }

    @ActivityCallback
    private fun picked(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK || result.data?.data == null) {
            invoke.resolveObject(JSObject().apply { put("cancelled", true) })
            return
        }
        try {
            val uri = result.data!!.data!!
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            activity.contentResolver.takePersistableUriPermission(uri, flags)
            val resolver = activity.contentResolver
            val name = resolver.query(DocumentsContract.buildDocumentUriUsingTree(uri,
                DocumentsContract.getTreeDocumentId(uri)), arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
                null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            } ?: throw IllegalStateException("Unreachable")
            val rootId = DocumentsContract.getTreeDocumentId(uri).substringBefore(':')
            // Some providers restrict their roots query even after granting a tree.
            val root = try {
                resolver.query(DocumentsContract.buildRootsUri(uri.authority!!),
                    arrayOf(DocumentsContract.Root.COLUMN_ROOT_ID, DocumentsContract.Root.COLUMN_TITLE),
                    null, null, null)?.use { cursor ->
                    var title: String? = null
                    while (cursor.moveToNext()) if (cursor.getString(0) == rootId) title = cursor.getString(1)
                    title
                }
            } catch (_: SecurityException) { null } ?: when (rootId) {
                "primary" -> (activity.getSystemService(StorageManager::class.java)
                    .storageVolumes.firstOrNull { it.isPrimary }?.getDescription(activity) ?: "Internal storage")
                "downloads" -> "Downloads"
                else -> activity.packageManager.resolveContentProvider(uri.authority!!, 0)?.loadLabel(activity.packageManager)?.toString() ?: rootId
            }
            invoke.resolveObject(JSObject().apply {
                put("uri", uri.toString()); put("label", if (root == name) name else "$root › $name")
            })
        } catch (error: Exception) {
            invoke.reject(error.message ?: "Could not open folder")
        }
    }
}
