pub mod account;
pub mod approval;
pub mod backup;
pub mod base;
#[cfg(debug_assertions)]
pub mod dev_probe;
pub mod files;
pub mod hidden;
pub mod note;

use crate::views::{AppInfo, Platform};

// option_env! is fixed at build time. A release must explicitly set BH_SERVER.
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("BH_APP_VERSION").into(),
        server: option_env!("BH_SERVER")
            .unwrap_or("https://dev-api.basehero.com")
            .into(),
        platform: if cfg!(target_os = "macos") {
            Platform::Macos
        } else if cfg!(target_os = "android") {
            Platform::Android
        } else {
            Platform::Linux
        },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_info_reports_the_version_releases_set() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
        assert_eq!(super::app_info().version, conf["version"].as_str().unwrap());
    }
}
