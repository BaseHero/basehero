package app.basehero.open

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/** Only hands files from the app's open cache to a system viewer on request. */
class OpenPlugin(private val context: Context) {
    fun open(path: String, mime: String) {
        // Tauri's Android app_cache_dir() calls PathPlugin.getCacheDir(), which
        // returns activity.cacheDir. This check also rejects symlinks and siblings.
        val root = File(context.cacheDir, "open").canonicalFile
        val file = File(path).canonicalFile
        require(file.isFile && file.parentFile?.toPath()?.startsWith(root.toPath()) == true) {
            "file is outside the open cache"
        }
        val uri = FileProvider.getUriForFile(context, "app.basehero.files", file)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime.ifBlank { "application/octet-stream" })
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            context.startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            throw IllegalStateException("No viewer for this file type", e)
        }
    }
}
