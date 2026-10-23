#[path = "../../../libs/host/src/endpoint.rs"]
#[allow(dead_code)]
mod endpoint_config;

/// The build's one sync endpoint, from the JSON file `BH_SYNC_ENDPOINT` names
/// (see the app README). Unset: a local-only build. A file that is missing,
/// empty or does not parse fails the build instead of producing an app that
/// silently cannot sync. The app reads the checked copy from OUT_DIR.
fn sync_endpoint() {
    println!("cargo:rerun-if-env-changed=BH_SYNC_ENDPOINT");
    let text = match std::env::var_os("BH_SYNC_ENDPOINT") {
        Some(path) if !path.is_empty() => {
            println!(
                "cargo:rerun-if-changed={}",
                std::path::Path::new(&path).display()
            );
            Some(std::fs::read_to_string(&path).expect("BH_SYNC_ENDPOINT names a readable file"))
        }
        _ => None,
    };
    let synthetic = std::env::var_os("CARGO_FEATURE_SYNTHETIC_ATTESTATION").is_some();
    assert!(
        endpoint_config::built(text.as_deref(), synthetic).is_ok(),
        "BH_SYNC_ENDPOINT is not one complete endpoint this build may use"
    );
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out.join("sync-endpoint.json"), text.unwrap_or_default())
        .expect("write the built endpoint");
}

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
    sync_endpoint();
    // App-defined commands otherwise bypass the per-command ACL entirely.
    // The Android QR adapter's commands get allow-/deny- permissions the same
    // way; capabilities grant them to the Android main window only.
    let qr_scan =
        tauri_build::InlinedPlugin::new().commands(&["request_permissions", "scan", "cancel"]);
    let notify = tauri_build::InlinedPlugin::new().commands(&["notify"]);
    let attributes = tauri_build::Attributes::new()
        .plugin("qr-scan", qr_scan)
        .plugin("notify", notify);
    tauri_build::try_build(
        attributes.app_manifest(tauri_build::AppManifest::new().commands(&[
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
            "sync_status",
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
            "pairing_show",
            "pairing_status",
            "pairing_approve",
            "pairing_cancel",
            "pairing_reconfirm",
            "pairing_join",
            "pairing_join_status",
            "update_status",
            "update_not_now",
            "update_install",
            "window_sidebar",
            "app_about",
            "devices_kit_screen",
            "devices_view",
            "devices_request_removal",
            "devices_cancel_removal",
            "devices_remove_now",
            "devices_remove_self",
            "account_change_password",
            "account_confirm_new_kit",
            "alerts_list",
            "account_recover",
            "account_check_code",
            "account_recovery_status",
        ])),
    )
    .expect("Tauri client build failed");
}
