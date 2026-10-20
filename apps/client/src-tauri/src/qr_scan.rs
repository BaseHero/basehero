//! Camera QR scanning for the join screen on Android. The app's own Kotlin
//! adapter (`plugins/qr-scan/android`) decodes frames algorithmically; Tauri
//! forwards the page's `plugin:qr-scan|…` calls to it after the capability
//! check, and the scanned text returns to the page as untrusted text. No Rust
//! command is involved: joining still goes only through `pairing_join`.

use tauri::{
    Manager, Runtime,
    plugin::{Builder, PluginHandle, TauriPlugin},
};

/// Keeps the registered native plugin for the app's lifetime.
struct QrScan<R: Runtime>(#[allow(dead_code)] PluginHandle<R>);

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("qr-scan")
        .setup(|app, api| {
            let handle = api.register_android_plugin("app.basehero.qrscan", "QrScanPlugin")?;
            app.manage(QrScan(handle));
            Ok(())
        })
        .build()
}
