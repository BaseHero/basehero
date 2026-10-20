package app.basehero.client

import android.content.res.Configuration
import android.os.Bundle
import android.view.View
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import app.basehero.devicekeys.DeviceKeysBridge
import kotlin.math.roundToInt

class MainActivity : TauriActivity() {
  private var webView: WebView? = null
  private var densityDpi = 0

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // Edge to edge, Android no longer shrinks the window for the keyboard.
    // End the page above it, so the editor can keep the caret in view.
    ViewCompat.setOnApplyWindowInsetsListener(findViewById<View>(android.R.id.content)) { content, insets ->
      val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
      content.setPadding(0, 0, 0, keyboard)
      insets.inset(0, 0, 0, keyboard)
    }
  }

  override fun onWebViewCreate(webView: WebView) {
    this.webView = webView
    densityDpi = resources.configuration.densityDpi
    webView.settings.textZoom = (resources.configuration.fontScale * 100).roundToInt()
  }

  // The manifest keeps this Activity and its one WebView through every
  // configuration change, so apply here what a new WebView would pick up.
  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    val view = webView ?: return
    // A WebView reads the system font size only when it is created.
    view.settings.textZoom = (newConfig.fontScale * 100).roundToInt()
    // It takes a new density at once, but keeps the page's old viewport until
    // its size changes; resize it once so the page fills the window again.
    if (newConfig.densityDpi != densityDpi) {
      densityDpi = newConfig.densityDpi
      view.post {
        view.layout(view.left, view.top, view.right - 1, view.bottom)
        view.requestLayout()
      }
    }
  }

  override fun onResume() {
    super.onResume()
    DeviceKeysBridge.attachActivity(this)
  }

  override fun onPause() {
    DeviceKeysBridge.detachActivity(this)
    super.onPause()
  }
}
