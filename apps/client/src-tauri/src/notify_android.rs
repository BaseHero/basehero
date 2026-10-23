//! Rust-only call into the private Android notification adapter; no WebView
//! command can supply text or request a notification.
use tauri::{
    Manager, Runtime,
    plugin::{Builder, PluginHandle, TauriPlugin},
};
struct Notify<R: Runtime>(PluginHandle<R>);
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("notify")
        .setup(|app, api| {
            let handle = api.register_android_plugin("app.basehero.notify", "NotifyPlugin")?;
            app.manage(Notify(handle));
            Ok(())
        })
        .build()
}
pub fn send<R: Runtime>(app: &tauri::AppHandle<R>, tag: &str, body: &str) {
    if let Some(plugin) = app.try_state::<Notify<R>>() {
        let _: Result<serde_json::Value, _> = plugin
            .0
            .run_mobile_plugin("notify", serde_json::json!({"tag": tag, "body": body}));
    }
}
