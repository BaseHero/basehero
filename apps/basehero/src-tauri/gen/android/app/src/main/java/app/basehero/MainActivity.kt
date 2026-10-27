package app.basehero

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge(
      statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
      navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
    )
    super.onCreate(savedInstanceState)
    // Android 15+ forces edge-to-edge. Keep the WebView out of system bars,
    // display cutouts and the keyboard without reloading it on a fold.
    val content = findViewById<View>(android.R.id.content)
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
      val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
      view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, ime.bottom))
      WindowInsetsCompat.CONSUMED
    }
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    // Tauri installs its history callback during plugin setup. Register after
    // WebView creation so app navigation wins over WebView history.
    onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
      override fun handleOnBackPressed() {
        if (webView.url?.startsWith("http://tauri.localhost/") == false) {
          webView.loadUrl("http://tauri.localhost/")
        } else {
          webView.evaluateJavascript("window.__bhBack?.() === true") { handled ->
            if (handled != "true") moveTaskToBack(true)
          }
        }
      }
    })
  }

  override fun onResume() {
    super.onResume()
    // The first resume can precede WebView creation; initial load is the app's job.
    val webView = findWebView(findViewById(android.R.id.content))
    if (webView?.url?.startsWith("http://tauri.localhost/") == true) {
      webView.evaluateJavascript("window.dispatchEvent(new Event('bh:resume'))", null)
    }
  }

  private fun findWebView(view: View): WebView? {
    if (view is WebView) return view
    if (view is ViewGroup) for (i in 0 until view.childCount) {
      findWebView(view.getChildAt(i))?.let { return it }
    }
    return null
  }
}
