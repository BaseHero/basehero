package app.basehero.devicekeys

import org.junit.Assert.*
import org.junit.Test

class CreationAttemptTest {
    @Test fun onlySuccessMayPersistAndOwnsInputsAfterCallerWipesThem() {
        val input = byteArrayOf(1, 2, 3)
        val events = mutableListOf<String>()
        val attempt = CreationAttempt(listOf(input), { events.add("complete:$it") })
        input.fill(0) // Rust also clears its JNI argument arrays after create returns
        assertArrayEquals(byteArrayOf(1, 2, 3), attempt.owned[0])
        attempt.succeed({ owned -> events.add("persist"); assertArrayEquals(byteArrayOf(1, 2, 3), owned[0]) }, { events.add("cleanup") })
        attempt.abort(2) { events.add("cleanup") }
        assertEquals(listOf("persist", "complete:0"), events)
        assertArrayEquals(byteArrayOf(0, 0, 0), attempt.owned[0])
    }

    @Test fun authenticatedAadAndFinalizationOnlyRunOnSuccessInThatOrder() {
        val events = mutableListOf<String>()
        val ad = byteArrayOf(3, 4)
        val cancelled = CreationAttempt(listOf(byteArrayOf(9)), { events.add("cancel:$it") })
        cancelled.abort(2) { events.add("cleanup") }
        cancelled.succeed({ records ->
            finishWithAuthenticatedAad(ad, { actual ->
                assertArrayEquals(ad, actual)
                events.add("aad")
            }, { events.add("final:${records[0][0]}") })
        }, { events.add("wrong-cleanup") })
        assertEquals(listOf("cleanup", "cancel:2"), events)

        val accepted = CreationAttempt(listOf(byteArrayOf(5)), { events.add("complete:$it") })
        accepted.succeed({ records ->
            finishWithAuthenticatedAad(ad, { events.add("aad") }, { events.add("final:${records[0][0]}") })
            events.add("persist")
        }, { events.add("failed") })
        assertEquals(listOf("cleanup", "cancel:2", "aad", "final:5", "persist", "complete:0"), events)
    }

    @Test fun cancelErrorAndTimeoutCleanAndWipeWithoutPersisting() {
        for (error in listOf(2, 4, 1)) {
            val events = mutableListOf<String>()
            val attempt = CreationAttempt(listOf(byteArrayOf(9)), { events.add("complete:$it") })
            attempt.abort(error) { events.add("cleanup") }
            attempt.succeed({ events.add("persist") }, { events.add("cleanup-again") })
            assertEquals(listOf("cleanup", "complete:$error"), events)
            assertArrayEquals(byteArrayOf(0), attempt.owned[0])
        }
        val events = mutableListOf<String>()
        val attempted = CreationAttempt(listOf(byteArrayOf(5)), { events.add("complete:$it") })
        attempted.succeed({ throw IllegalStateException("write failed") }, { events.add("cleanup") })
        assertEquals(listOf("cleanup", "complete:4"), events)
        assertArrayEquals(byteArrayOf(0), attempted.owned[0])
        val cleanupFailure = CreationAttempt(listOf(byteArrayOf(7)), { events.add("complete:$it") })
        cleanupFailure.abort(2) { throw IllegalStateException("cleanup failed") }
        assertEquals("complete:4", events.last())
        assertArrayEquals(byteArrayOf(0), cleanupFailure.owned[0])
    }
}
