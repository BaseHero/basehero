package app.basehero.devicekeys

import org.junit.Assert.*
import org.junit.Test

class CurrentActivityTest {
    @Test fun detachOnlyClearsTheSameActivityAfterReplacement() {
        val binding = CurrentActivity<Any>()
        val old = Any()
        val fresh = Any()
        assertNull(binding.current())
        binding.attach(old)
        binding.attach(fresh)
        binding.detach(old)
        assertSame(fresh, binding.current())
        binding.detach(fresh)
        assertNull(binding.current())
    }
}
