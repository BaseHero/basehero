package app.basehero.client

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import app.basehero.devicekeys.DeviceKeysBridge

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
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
