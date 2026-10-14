package app.basehero.devicekeys

import java.lang.ref.WeakReference

/** The shell explicitly binds its resumed Activity; do not keep a stale process-lifetime one. */
internal class CurrentActivity<T : Any> {
    @Volatile private var current = WeakReference<T>(null)

    fun attach(activity: T) { current = WeakReference(activity) }
    fun detach(activity: T) {
        if (current.get() === activity) current = WeakReference(null)
    }
    fun current(): T? = current.get()
}
