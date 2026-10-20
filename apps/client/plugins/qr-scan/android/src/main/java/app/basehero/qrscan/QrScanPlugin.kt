package app.basehero.qrscan

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.Drawable
import android.os.Handler
import android.os.Looper
import android.util.Size
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import app.tauri.PermissionState
import app.tauri.annotation.Command
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

private const val CAMERA = "camera"

/** The back camera's analysis stream as the scanner configures it. */
object ScanCamera {
    val selector: CameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

    fun analysis(): ImageAnalysis = ImageAnalysis.Builder()
        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
        .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
        .setResolutionSelector(ResolutionSelector.Builder().setResolutionStrategy(
            ResolutionStrategy(Size(1280, 720), ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER)
        ).build())
        .build()

    /** The frame's luminance plane exactly as the camera delivered it. */
    fun luma(image: ImageProxy): LumaPlane {
        val y = image.planes[0]
        val crop = image.cropRect
        return LumaPlane(y.buffer, image.width, image.height, y.rowStride, y.pixelStride,
            crop.left, crop.top, crop.width(), crop.height())
    }
}

/**
 * QR scanning for the join screen: back camera, QR only, an algorithmic
 * decoder. The camera preview sits behind the transparent WebView; the
 * decoded text goes back to the page as untrusted text, nothing else.
 */
@TauriPlugin(permissions = [Permission(strings = [Manifest.permission.CAMERA], alias = CAMERA)])
class QrScanPlugin(private val activity: Activity) : Plugin(activity) {
    private lateinit var webView: WebView
    private val main = Handler(Looper.getMainLooper())
    private val requests = ScanRequests(
        (activity as LifecycleOwner).lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED),
        { (activity as LifecycleOwner).lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) },
        // Convert the Kotlin callback to Runnable; a callable reference casts it instead.
        { work -> main.post { work() } },
    )
    private var session: Session? = null

    private class InvokeReply(private val invoke: Invoke) : ScanReply {
        override fun found(text: String) = invoke.resolve(JSObject().put("content", text))
        override fun refused(reason: String) = invoke.reject(reason)
    }

    /** One scan's camera, preview and frame decoder. */
    private inner class Session(val ticket: ScanRequests.Ticket) {
        val preview = PreviewView(activity)
        var worker: AnalysisWorker<ImageProxy>? = null
        var analysis: ImageAnalysis? = null
        var provider: ProcessCameraProvider? = null
        var background: Drawable? = null

        fun newWorker(): AnalysisWorker<ImageProxy> = AnalysisWorker<ImageProxy>(
            { QrFrameDecoder.decode(ScanCamera.luma(it)) },
            { text -> main.post {
                if (session === this@Session && requests.current(ticket)) {
                    finish(this@Session)
                    requests.found(ticket, text)
                }
            } },
        ).also { worker = it }
    }

    override fun load(webView: WebView) {
        super.load(webView)
        this.webView = webView
    }

    private fun state(): JSObject = JSObject().put(CAMERA, getPermissionState(CAMERA).toString())

    @Command
    override fun requestPermissions(invoke: Invoke) {
        if (getPermissionState(CAMERA) == PermissionState.GRANTED) invoke.resolve(state())
        else requestPermissionForAlias(CAMERA, invoke, "cameraPermissionResult")
    }

    @PermissionCallback
    fun cameraPermissionResult(invoke: Invoke) {
        invoke.resolve(state())
    }

    @Command
    fun scan(invoke: Invoke) {
        requests.scan(InvokeReply(invoke), ::start)
    }

    @Command
    fun cancel(invoke: Invoke) {
        requests.cancel { // Invalidate now; queue teardown ahead of any replacement start.
            finish(session)
            invoke.resolve()
        }
    }

    override fun onResume(activity: AppCompatActivity) {
        requests.resume()
    }

    override fun onPause(activity: AppCompatActivity) {
        requests.pause()
        finish(session)
    }

    override fun onDestroy(activity: AppCompatActivity) {
        requests.destroy()
        finish(session)
    }

    private fun start(ticket: ScanRequests.Ticket) {
        if (!requests.current(ticket)) return
        if (!activity.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
            requests.refuse(ticket, ScanSlot.NO_CAMERA)
            return
        }
        if (getPermissionState(CAMERA) != PermissionState.GRANTED) {
            requests.refuse(ticket, ScanSlot.NO_PERMISSION)
            return
        }
        try {
            val scan = Session(ticket)
            session = scan
            scan.preview.layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            (webView.parent as ViewGroup).addView(scan.preview)
            webView.bringToFront()
            scan.background = webView.background
            webView.setBackgroundColor(Color.TRANSPARENT)
            val future = ProcessCameraProvider.getInstance(activity)
            future.addListener({
                if (session !== scan || !requests.current(ticket)) {
                    finish(scan)
                    return@addListener
                }
                try {
                    val provider = future.get()
                    scan.provider = provider
                    val preview = Preview.Builder().build().also { it.setSurfaceProvider(scan.preview.surfaceProvider) }
                    val worker = scan.newWorker()
                    val analysis = ScanCamera.analysis().also {
                        scan.analysis = it
                        it.setAnalyzer(worker.executor, worker.scanner::analyze)
                    }
                    if (!requests.current(ticket)) {
                        finish(scan)
                        return@addListener
                    }
                    provider.bindToLifecycle(activity as LifecycleOwner, ScanCamera.selector, preview, analysis)
                } catch (_: Exception) {
                    finish(scan)
                    requests.refuse(ticket, ScanSlot.UNAVAILABLE)
                }
            }, ContextCompat.getMainExecutor(activity))
        } catch (_: Exception) {
            finish(session?.takeIf { it.ticket === ticket })
            requests.refuse(ticket, ScanSlot.UNAVAILABLE)
        }
    }

    /** Release camera analysis before shutting down its worker; queued frames still close. */
    private fun finish(scan: Session?) {
        if (scan == null || session !== scan) return
        session = null
        scan.analysis?.clearAnalyzer()
        scan.provider?.unbindAll()
        scan.worker?.stop()
        (scan.preview.parent as? ViewGroup)?.removeView(scan.preview)
        if (scan.background != null) webView.background = scan.background
        else webView.setBackgroundColor(Color.WHITE)
    }
}
