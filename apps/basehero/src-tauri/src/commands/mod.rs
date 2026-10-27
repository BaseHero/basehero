pub mod account;
#[cfg(debug_assertions)]
pub mod dev_probe;

use crate::views::{AppInfo, Platform};

// option_env! is fixed at build time. A release must explicitly set BH_SERVER.
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
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
