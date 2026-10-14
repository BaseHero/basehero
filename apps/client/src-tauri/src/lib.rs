//! Thin desktop/mobile entry point for the bundled client.

#[cfg(target_os = "macos")]
mod native;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("client runtime failed");
}
