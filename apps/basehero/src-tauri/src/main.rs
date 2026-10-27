#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "macos")]
    if let Some(code) = basehero_app_lib::hidden_mode() {
        std::process::exit(code);
    }
    basehero_app_lib::run();
}
