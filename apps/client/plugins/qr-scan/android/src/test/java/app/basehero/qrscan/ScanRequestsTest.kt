package app.basehero.qrscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanRequestsTest {
    private class Reply : ScanReply {
        val events = mutableListOf<String>()
        override fun found(text: String) { events += "found:$text" }
        override fun refused(reason: String) { events += "refused:$reason" }
    }

    private class Deferred {
        val queue = mutableListOf<() -> Unit>()
        fun post(action: () -> Unit) { queue += action }
        fun drain() { while (queue.isNotEmpty()) queue.removeAt(0)() }
    }

    @Test fun pauseBeforeQueuedStartRefusesOnceWithoutOpeningAndResumeDoesNotReviveIt() {
        val deferred = Deferred()
        var lifecycleResumed = true
        val requests = ScanRequests(true, { lifecycleResumed }, deferred::post)
        val first = Reply()
        var opened = 0
        requests.scan(first) { opened++ }
        lifecycleResumed = false
        requests.pause()
        lifecycleResumed = true
        requests.resume()
        deferred.drain()
        assertEquals(0, opened)
        assertEquals(listOf("refused:${ScanSlot.INTERRUPTED}"), first.events)
        val next = Reply()
        requests.scan(next) { opened++ }
        deferred.drain()
        assertEquals(1, opened)
        assertTrue(requests.busy)
        requests.cancel()
        assertEquals(listOf("refused:${ScanSlot.CANCELLED}"), next.events)
    }

    @Test fun cancelBeforeQueuedStartNeverOpensAndDuplicateDoesNotDisplaceFirst() {
        val deferred = Deferred()
        val requests = ScanRequests(true, { true }, deferred::post)
        val first = Reply()
        val duplicate = Reply()
        var opened = 0
        requests.scan(first) { opened++ }
        requests.scan(duplicate) { opened++ }
        assertEquals(listOf("refused:${ScanSlot.BUSY}"), duplicate.events)
        assertEquals(emptyList<String>(), first.events)
        requests.cancel()
        deferred.drain()
        assertEquals(0, opened)
        assertEquals(listOf("refused:${ScanSlot.CANCELLED}"), first.events)
        assertEquals(listOf("refused:${ScanSlot.BUSY}"), duplicate.events)
    }

    @Test fun destroyRejectsQueuedStartAndRefusesAnyLaterRequestEvenAfterResume() {
        val deferred = Deferred()
        val requests = ScanRequests(true, { true }, deferred::post)
        val first = Reply()
        var opened = 0
        requests.scan(first) { opened++ }
        requests.destroy()
        requests.resume()
        deferred.drain()
        val later = Reply()
        requests.scan(later) { opened++ }
        deferred.drain()
        assertEquals(0, opened)
        assertEquals(listOf("refused:${ScanSlot.INTERRUPTED}"), first.events)
        assertEquals(listOf("refused:${ScanSlot.INTERRUPTED}"), later.events)
    }

    @Test fun cancellationCleanupIsQueuedBeforeAnyReplacementStart() {
        val deferred = Deferred()
        val requests = ScanRequests(true, { true }, deferred::post)
        val first = Reply()
        val order = mutableListOf<String>()
        requests.scan(first) { order += "old start" }
        requests.cancel { order += "cleanup" }
        requests.scan(Reply()) { order += "new start" }
        deferred.drain()
        assertEquals(listOf("cleanup", "new start"), order)
        assertEquals(listOf("refused:${ScanSlot.CANCELLED}"), first.events)
    }

    @Test fun cancelledProvidersCannotBindAfterAReplacementStarts() {
        val deferred = Deferred()
        val requests = ScanRequests(true, { true }, deferred::post)
        val first = Reply()
        val next = Reply()
        var binds = 0
        requests.scan(first) { ticket -> deferred.post { if (requests.current(ticket)) binds++ } }
        deferred.queue.removeAt(0)() // Start ran; provider callback is still queued.
        requests.cancel()
        requests.scan(next) { ticket -> deferred.post { if (requests.current(ticket)) binds++ } }
        deferred.drain()
        assertEquals(1, binds)
        assertEquals(listOf("refused:${ScanSlot.CANCELLED}"), first.events)
        assertEquals(emptyList<String>(), next.events)
        requests.cancel()
        assertEquals(listOf("refused:${ScanSlot.CANCELLED}"), next.events)
    }

    @Test fun providerCallbackMustCheckTheSameRequestAndCurrentLifecycle() {
        val deferred = Deferred()
        var eligible = true
        val requests = ScanRequests(true, { eligible }, deferred::post)
        val first = Reply()
        var bind = 0
        requests.scan(first) { ticket -> deferred.post { if (requests.current(ticket)) bind++ } }
        deferred.queue.removeAt(0)()
        eligible = false
        // Even when the lifecycle state changes before its onPause notification.
        deferred.drain()
        assertEquals(0, bind)
        assertEquals(listOf("refused:${ScanSlot.INTERRUPTED}"), first.events)
        requests.pause()
        assertEquals(1, first.events.size)
    }
}
