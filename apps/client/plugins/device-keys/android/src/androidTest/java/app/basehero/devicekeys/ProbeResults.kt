package app.basehero.devicekeys

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** JNI callback sink in the debug target process; bytes are copied before the bridge wipes them. */
object ProbeResults {
    init { System.loadLibrary("devicekeys_probe") }
    data class Result(val ticket: Long, val code: Int, val bytes: ByteArray?)
    private val responses = LinkedBlockingQueue<Result>()
    @JvmStatic fun complete(ticket: Long, code: Int, bytes: ByteArray?) {
        responses.add(Result(ticket, code, bytes?.clone()))
    }
    fun noResponseFor(seconds: Long): Boolean {
        val response = responses.poll(seconds, TimeUnit.SECONDS)
        check(response == null) { "premature callback code=${response.code} ticket=${response.ticket}" }
        return true
    }
    fun await(ticket: Long): Result {
        val result = responses.poll(30, TimeUnit.SECONDS) ?: error("no callback for ticket $ticket")
        check(result.ticket == ticket) { "unexpected callback ticket ${result.ticket}" }
        return result
    }
}
