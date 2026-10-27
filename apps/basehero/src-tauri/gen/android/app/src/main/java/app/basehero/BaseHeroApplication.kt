package app.basehero

import android.app.Application
import android.content.Context
import android.util.Log

class BaseHeroApplication : Application() {
  override fun onCreate() {
    super.onCreate()
    // Every entry point, including later background ones, runs this first, so
    // Rust's TLS verifier has Android's trust store before any Rust networking.
    System.loadLibrary("basehero_app_lib")
    if (!initPlatformTls(this)) Log.e("BaseHero", "platform TLS initialization failed")
  }

  private external fun initPlatformTls(context: Context): Boolean
}
