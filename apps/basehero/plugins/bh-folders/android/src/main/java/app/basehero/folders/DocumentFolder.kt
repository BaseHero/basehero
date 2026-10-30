package app.basehero.folders

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.system.ErrnoException
import android.system.OsConstants
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException

/** Byte-only access to a persisted document tree; the core owns the backup format. */
class DocumentFolder(private val context: Context) {
    private val resolver get() = context.contentResolver

    fun release(uri: String) {
        val tree = Uri.parse(uri)
        resolver.releasePersistableUriPermission(tree,
            android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    }

    fun persisted(uri: String): Boolean {
        val tree = Uri.parse(uri)
        return resolver.persistedUriPermissions.any { it.uri == tree && it.isReadPermission && it.isWritePermission }
    }

    private fun root(uri: String): Uri {
        if (!persisted(uri)) throw IllegalStateException("PermissionLost")
        val tree = Uri.parse(uri)
        val root = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        try {
            resolver.query(root, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID), null, null, null)?.use {
                if (it.moveToFirst()) return root
            }
        } catch (error: SecurityException) { throw IllegalStateException("PermissionLost", error) }
        catch (error: FileNotFoundException) { throw IllegalStateException("Unreachable", error) }
        catch (error: IllegalArgumentException) { throw IllegalStateException("Unreachable", error) }
        throw IllegalStateException("Unreachable")
    }

    private fun segments(path: String): List<String> {
        if (path.isEmpty()) return emptyList()
        val segments = path.split('/')
        require(segments.all { it.isNotEmpty() && it != "." && it != ".." && '\\' !in it }) { "invalid backup path" }
        return segments
    }

    private fun child(tree: Uri, parent: Uri, name: String): Pair<Uri, Boolean>? {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getDocumentId(parent))
        resolver.query(children, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME, DocumentsContract.Document.COLUMN_MIME_TYPE), null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                if (cursor.getString(1) == name) return Pair(DocumentsContract.buildDocumentUriUsingTree(tree,
                    cursor.getString(0)), cursor.getString(2) == DocumentsContract.Document.MIME_TYPE_DIR)
            }
        } ?: throw IllegalStateException("Unreachable")
        return null
    }

    private fun resolve(uri: String, path: String, createParents: Boolean = false): Uri? {
        val tree = Uri.parse(uri)
        var at = root(uri)
        val parts = segments(path)
        for ((index, name) in parts.withIndex()) {
            val existing = child(tree, at, name)
            if (existing != null) {
                if (index < parts.lastIndex && !existing.second) throw IOException("not a folder")
                at = existing.first
            } else if (createParents && index < parts.lastIndex) {
                at = DocumentsContract.createDocument(resolver, at, DocumentsContract.Document.MIME_TYPE_DIR, name)
                    ?: throw IllegalStateException("Unreachable")
            } else return null
        }
        return at
    }

    fun list(uri: String, dir: String): String = guard {
        val tree = Uri.parse(uri)
        val at = resolve(uri, dir) ?: return@guard "[]"
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getDocumentId(at))
        val array = JSONArray()
        resolver.query(children, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_DOCUMENT_ID), null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val name = cursor.getString(0)
                val directory = cursor.getString(1) == DocumentsContract.Document.MIME_TYPE_DIR
                val size = if (directory) 0L else {
                    val entry = DocumentsContract.buildDocumentUriUsingTree(tree, cursor.getString(3))
                    resolver.openFileDescriptor(entry, "r")?.use { descriptor ->
                        descriptor.statSize.takeIf { it >= 0L } ?: cursor.getLong(2)
                    } ?: throw IllegalStateException("Unreachable")
                }
                array.put(JSONObject().put("name", name).put("dir", directory).put("size", size))
            }
        } ?: throw IllegalStateException("Unreachable")
        array.toString()
    }

    fun read(uri: String, path: String): ByteArray = guard {
        val at = resolve(uri, path) ?: throw IllegalStateException("NotFound")
        resolver.openInputStream(at)?.use { it.readBytes() } ?: throw IllegalStateException("Unreachable")
    }

    fun write(uri: String, path: String, bytes: ByteArray) = guard {
        require(segments(path).isNotEmpty()) { "invalid backup path" }
        val current = resolve(uri, path, true)
        val at = current ?: run {
            val parent = resolve(uri, path.substringBeforeLast('/', "")) ?: throw IllegalStateException("Unreachable")
            DocumentsContract.createDocument(resolver, parent, "application/octet-stream", path.substringAfterLast('/'))
                ?: throw IllegalStateException("Unreachable")
        }
        resolver.openFileDescriptor(at, "wt")?.use { descriptor ->
            // A run commits its cursors only after this returns: force the provider's FD before that.
            FileOutputStream(descriptor.fileDescriptor).use { stream -> stream.write(bytes); stream.flush(); descriptor.fileDescriptor.sync() }
        } ?: throw IllegalStateException("Unreachable")
    }

    fun remove(uri: String, path: String) = guard {
        require(segments(path).isNotEmpty()) { "invalid backup path" }
        val at = resolve(uri, path) ?: return@guard
        if (!DocumentsContract.deleteDocument(resolver, at)) throw IllegalStateException("Unreachable")
    }

    private inline fun <T> guard(action: () -> T): T = try { action() }
    catch (error: SecurityException) { throw IllegalStateException("PermissionLost", error) }
    catch (error: Exception) {
        var cause: Throwable? = error
        while (cause != null) {
            if (cause is ErrnoException && cause.errno == OsConstants.ENOSPC) throw IllegalStateException("Full", error)
            cause = cause.cause
        }
        if (error.message?.contains("ENOSPC") == true || error.message?.contains("No space left") == true) throw IllegalStateException("Full", error)
        throw error
    }
}
