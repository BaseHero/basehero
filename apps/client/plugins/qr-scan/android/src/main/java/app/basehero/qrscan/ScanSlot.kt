package app.basehero.qrscan

import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Where one scan's outcome goes; [ScanSlot] calls exactly one of these, once. */
interface ScanReply {
    fun found(text: String)
    fun refused(reason: String)
}

/**
 * At most one scan at a time, settled exactly once. Not thread-safe: the
 * plugin calls it only on the main thread.
 */
class ScanSlot {
    companion object {
        const val BUSY = "busy"
        const val NO_CAMERA = "no camera"
        const val NO_PERMISSION = "camera permission not granted"
        const val CANCELLED = "cancelled"
        const val INTERRUPTED = "interrupted"
        const val UNAVAILABLE = "camera unavailable"
    }

    private var pending: ScanReply? = null
    val busy get() = pending != null

    /** Holds [reply] for a new scan, or refuses it at once and returns false. */
    fun begin(reply: ScanReply, hasCamera: Boolean, permitted: Boolean): Boolean {
        val refusal = when {
            busy -> BUSY
            !hasCamera -> NO_CAMERA
            !permitted -> NO_PERMISSION
            else -> null
        }
        if (refusal != null) {
            reply.refused(refusal)
            return false
        }
        pending = reply
        return true
    }

    fun found(text: String): Boolean = settle { it.found(text) }

    fun refuse(reason: String): Boolean = settle { it.refused(reason) }

    private inline fun settle(action: (ScanReply) -> Unit): Boolean {
        val reply = pending ?: return false
        pending = null
        action(reply)
        return true
    }
}

/** Owns one scan's worker. shutdown drains submitted frames through their close paths. */
class AnalysisWorker<F : AutoCloseable>(read: (F) -> String?, onText: (String) -> Unit) {
    val executor: ExecutorService = Executors.newSingleThreadExecutor()
    val scanner = FrameScanner(read, onText)

    fun stop() {
        scanner.stop()
        executor.shutdown()
    }
}

/**
 * Decodes one scan's camera frames on its single analysis thread. Every frame
 * is closed, whatever happens; after the first code, or [stop], none is read.
 */
class FrameScanner<F : AutoCloseable>(
    private val read: (F) -> String?,
    private val onText: (String) -> Unit,
) {
    @Volatile private var open = true

    fun stop() {
        open = false
    }

    fun analyze(frame: F) {
        frame.use {
            if (!open) return
            val text = read(it) ?: return
            open = false
            onText(text)
        }
    }
}
