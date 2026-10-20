//! Thin desktop/mobile entry point for the bundled client.

mod account_host;
#[cfg(not(target_os = "macos"))]
mod account_stub;
#[cfg(target_os = "android")]
mod android_account;
mod lifecycle;
mod mac_update;
#[cfg(target_os = "macos")]
mod native;
mod note_host;
mod pairing_host;
mod passwords;
mod sync_host;
// No release-approved policy root, signed bundle or public endpoint is configured.
// The native bootstrap is deliberately inert until those release inputs exist.
#[allow(dead_code)]
mod policy_host;
#[cfg(target_os = "android")]
mod qr_scan;
mod window_layout;

#[cfg(feature = "webdriver")]
mod webdriver;

/// The bundle identifier this build was configured with: its app data
/// directory, Keychain services and update identity all follow it.
pub(crate) const APP_IDENTIFIER: &str = env!("BH_APP_IDENTIFIER");

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = note_host::builder();
    #[cfg(target_os = "android")]
    let builder = builder.plugin(bh_device_keys::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(android_account::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(qr_scan::init());
    #[cfg(feature = "webdriver")]
    let builder = webdriver::register(builder);
    let context = tauri::generate_context!();
    assert_eq!(
        context.config().identifier,
        APP_IDENTIFIER,
        "build and Tauri configuration name different apps"
    );
    builder.run(context).expect("client runtime failed");
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_identifier_is_the_tauri_config_identifier() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let committed = config["identifier"].as_str().unwrap();
        let expected = option_env!("TAURI_CONFIG")
            .and_then(|overlay| serde_json::from_str::<serde_json::Value>(overlay).ok())
            .and_then(|overlay| overlay["identifier"].as_str().map(str::to_owned))
            .unwrap_or_else(|| committed.to_owned());
        assert_eq!(super::APP_IDENTIFIER, expected);
    }
}
