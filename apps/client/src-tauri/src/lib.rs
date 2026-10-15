//! Thin desktop/mobile entry point for the bundled client.

#[cfg(target_os = "macos")]
mod native;
mod note_host;
// No release-approved policy root, signed bundle or public endpoint is configured.
// The native bootstrap is deliberately inert until those release inputs exist.
#[allow(dead_code)]
mod policy_host;

#[cfg(feature = "webdriver")]
mod webdriver;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = note_host::builder();
    #[cfg(target_os = "android")]
    let builder = builder.plugin(bh_device_keys::init());
    #[cfg(feature = "webdriver")]
    let builder = webdriver::register(builder);
    builder
        .run(tauri::generate_context!())
        .expect("client runtime failed");
}
