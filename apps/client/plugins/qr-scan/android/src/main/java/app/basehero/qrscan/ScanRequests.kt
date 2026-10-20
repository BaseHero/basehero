package app.basehero.qrscan

/** Reserves a native request before posting its camera start. No old request survives pause/cancel. */
class ScanRequests(
    initiallyResumed: Boolean,
    private val eligible: () -> Boolean,
    private val post: (() -> Unit) -> Unit,
) {
    class Ticket internal constructor()

    private val slot = ScanSlot()
    private var resumed = initiallyResumed
    private var destroyed = false
    private var active: Ticket? = null
    val busy: Boolean @Synchronized get() = slot.busy

    @Synchronized fun scan(reply: ScanReply, start: (Ticket) -> Unit) {
        if (destroyed || !resumed || !eligible()) {
            reply.refused(ScanSlot.INTERRUPTED)
            return
        }
        if (!slot.begin(reply, hasCamera = true, permitted = true)) return
        val ticket = Ticket()
        active = ticket
        post { if (current(ticket)) start(ticket) }
    }

    /** Check again in the provider callback; inactive lifecycle also settles the request. */
    @Synchronized fun current(ticket: Ticket): Boolean {
        if (active !== ticket) return false
        if (destroyed || !resumed || !eligible()) {
            refuse(ticket, ScanSlot.INTERRUPTED)
            return false
        }
        return true
    }

    @Synchronized fun found(ticket: Ticket, text: String): Boolean {
        if (!current(ticket)) return false
        active = null
        return slot.found(text)
    }

    @Synchronized fun refuse(ticket: Ticket, reason: String): Boolean {
        if (active !== ticket) return false
        active = null
        return slot.refuse(reason)
    }

    /** Queue teardown while holding the same lock used to reserve the next start. */
    @Synchronized fun cancel(cleanup: () -> Unit = {}) {
        invalidate(ScanSlot.CANCELLED)
        post(cleanup)
    }
    @Synchronized fun pause() {
        resumed = false
        invalidate(ScanSlot.INTERRUPTED)
    }
    @Synchronized fun resume() { if (!destroyed) resumed = true }
    @Synchronized fun destroy() {
        destroyed = true
        resumed = false
        invalidate(ScanSlot.INTERRUPTED)
    }

    private fun invalidate(reason: String) {
        active = null
        slot.refuse(reason)
    }
}
