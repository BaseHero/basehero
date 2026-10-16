fn main() {
    // The app's identity is its Tauri identifier, including a packaging
    // `--config` overlay, so data, Keychain items and updates follow the bundle.
    println!("cargo:rerun-if-env-changed=TAURI_CONFIG");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    let identifier = |text: &str| {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()?
            .get("identifier")?
            .as_str()
            .map(str::to_owned)
    };
    let identifier = std::env::var("TAURI_CONFIG")
        .ok()
        .and_then(|overlay| identifier(&overlay))
        .or_else(|| identifier(&std::fs::read_to_string("tauri.conf.json").ok()?))
        .expect("tauri.conf.json names the app identifier");
    println!("cargo:rustc-env=BH_APP_IDENTIFIER={identifier}");
    // App-defined commands otherwise bypass the per-command ACL entirely.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "note_binding",
            "note_open",
            "note_commit",
            "note_selection",
            "note_close",
            "note_list",
            "note_create",
            "note_show",
            "note_new_window",
            "note_drained",
            "note_drain_failed",
            "account_screen",
            "account_retry",
            "account_suggest_password",
            "account_create",
            "account_confirm_kit",
            "account_return",
            "account_print_kit",
            "account_email_kit",
            "account_save_kit_file",
            "account_open_note",
            "update_status",
            "update_not_now",
            "update_install",
            "window_sidebar",
        ]),
    ))
    .expect("Tauri client build failed");
}
