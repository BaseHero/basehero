package app.basehero.sample

import android.app.Application
import android.content.Context
import android.util.Log

class SampleApplication : Application() {
  override fun onCreate() {
    super.onCreate()
    System.loadLibrary("basehero_sample_lib")
    if (!initPlatformTls(this)) Log.e("BaseHero Sample", "platform TLS initialization failed")
  }

  private external fun initPlatformTls(context: Context): Boolean
}
