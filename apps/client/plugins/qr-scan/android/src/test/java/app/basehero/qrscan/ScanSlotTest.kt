package app.basehero.qrscan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ScanSlotTest {
    private class Reply : ScanReply {
        val events = mutableListOf<String>()
        override fun found(text: String) { events += "found:$text" }
        override fun refused(reason: String) { events += "refused:$reason" }
    }

    @Test fun refusesPromptlyWithoutCameraPermissionOrWhileBusy() {
        val slot = ScanSlot()
        val noCamera = Reply()
        assertFalse(slot.begin(noCamera, hasCamera = false, permitted = true))
        assertEquals(listOf("refused:${ScanSlot.NO_CAMERA}"), noCamera.events)
        val noPermission = Reply()
        assertFalse(slot.begin(noPermission, hasCamera = true, permitted = false))
        assertEquals(listOf("refused:${ScanSlot.NO_PERMISSION}"), noPermission.events)
        assertFalse(slot.busy)

        val first = Reply()
        assertTrue(slot.begin(first, hasCamera = true, permitted = true))
        val second = Reply()
        assertFalse(slot.begin(second, hasCamera = true, permitted = true))
        assertEquals(listOf("refused:${ScanSlot.BUSY}"), second.events)
        // The refused second scan leaves the first one pending, not settled.
        assertEquals(emptyList<String>(), first.events)
        assertTrue(slot.busy)
    }

    @Test fun aResultAndACancelRaceSettleOnce() {
        val slot = ScanSlot()
        val decoded = Reply()
        slot.begin(decoded, hasCamera = true, permitted = true)
        assertTrue(slot.found("BH1:x"))
        assertFalse(slot.refuse(ScanSlot.CANCELLED))
        assertFalse(slot.found("BH1:y"))
        assertEquals(listOf("found:BH1:x"), decoded.events)

        val cancelled = Reply()
        slot.begin(cancelled, hasCamera = true, permitted = true)
        assertTrue(slot.refuse(ScanSlot.CANCELLED))
        assertFalse(slot.found("BH1:late"))
        assertEquals(listOf("refused:${ScanSlot.CANCELLED}"), cancelled.events)
        assertFalse(slot.busy)
    }

    private class Frame : AutoCloseable {
        var closed = 0
        override fun close() { closed++ }
    }

    @Test fun everyFrameIsClosedAndOnlyTheFirstCodeIsReported() {
        val texts = mutableListOf<String>()
        val reads = mutableListOf<String?>(null, "BH1:a", "BH1:b")
        val scanner = FrameScanner<Frame>({ reads.removeAt(0) }) { texts += it }
        val frames = List(4) { Frame() }
        frames.forEach(scanner::analyze)
        assertEquals(listOf("BH1:a"), texts)
        assertEquals(listOf(1, 1, 1, 1), frames.map { it.closed })
        // After its first code the scanner no longer decodes later frames.
        assertEquals(listOf("BH1:b"), reads)
    }

    @Test fun stoppingAnalysisReleasesWorkerButDrainsSubmittedFrames() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val worker = AnalysisWorker<Frame>({
            started.countDown()
            if (!release.await(5, TimeUnit.SECONDS)) error("frame wait timed out")
            null
        }) { }
        val first = Frame()
        val queued = Frame()
        worker.executor.execute { worker.scanner.analyze(first) }
        try {
            assertTrue(started.await(5, TimeUnit.SECONDS))
            worker.executor.execute { worker.scanner.analyze(queued) }
            worker.stop()
        } finally {
            release.countDown()
        }
        assertTrue(worker.executor.awaitTermination(5, TimeUnit.SECONDS))
        assertTrue(worker.executor.isShutdown)
        assertEquals(1, first.closed)
        assertEquals(1, queued.closed)
    }

    @Test fun framesAreClosedWhenStoppedOrWhenDecodingThrows() {
        var reads = 0
        val stopped = FrameScanner<Frame>({ reads++; null }) { }
        stopped.stop()
        val late = Frame()
        stopped.analyze(late)
        assertEquals(0, reads)
        assertEquals(1, late.closed)

        val failing = FrameScanner<Frame>({ throw IllegalStateException("decoder bug") }) { }
        val frame = Frame()
        try { failing.analyze(frame) } catch (_: IllegalStateException) { }
        assertEquals(1, frame.closed)
    }
}
