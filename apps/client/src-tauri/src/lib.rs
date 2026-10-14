//! Thin desktop/mobile entry point for the bundled client.

#[cfg(target_os = "macos")]
mod native;

#[cfg(feature = "webdriver")]
mod webdriver;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(feature = "webdriver")]
    let builder = webdriver::register(builder);
    builder
        .run(tauri::generate_context!())
        .expect("client runtime failed");
}
