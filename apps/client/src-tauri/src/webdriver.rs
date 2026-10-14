//! Registration of the test-only WebDriver plugin.
//!
//! Compiled only with the non-default `webdriver` feature, so release builds
//! never contain the driver. Upstream's Android listener binds every interface,
//! so an Android test build registers it only on an emulator: a real phone never
//! exposes the endpoint. Every other platform registers unconditionally.

/// True when the device reports that it is an emulator.
///
/// Kept free of platform calls so it is unit-testable on the host; the caller
/// reads the Android properties.
#[cfg(any(target_os = "android", test))]
fn reports_emulator(qemu: Option<&str>, boot_qemu: Option<&str>) -> bool {
    [qemu, boot_qemu]
        .into_iter()
        .flatten()
        .any(|value| value.trim() == "1")
}

#[cfg(target_os = "android")]
fn android_property(name: &str) -> Option<String> {
    // `getprop` rather than `__system_property_get`: the workspace forbids unsafe code.
    let output = std::process::Command::new("getprop")
        .arg(name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// Adds the WebDriver plugin, except on a real Android device.
pub fn register<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    #[cfg(target_os = "android")]
    {
        let emulator = reports_emulator(
            android_property("ro.kernel.qemu").as_deref(),
            android_property("ro.boot.qemu").as_deref(),
        );
        if emulator {
            builder.plugin(tauri_plugin_webdriver::init())
        } else {
            builder
        }
    }
    #[cfg(not(target_os = "android"))]
    builder.plugin(tauri_plugin_webdriver::init())
}

#[cfg(test)]
mod tests {
    use super::reports_emulator;

    #[test]
    fn refuses_anything_that_is_not_an_emulator() {
        assert!(!reports_emulator(None, None));
        assert!(!reports_emulator(Some(""), Some("")));
        assert!(!reports_emulator(Some("0"), Some("0")));
        assert!(!reports_emulator(Some("2"), None));
        assert!(!reports_emulator(Some("true"), Some("false")));
    }

    #[test]
    fn accepts_either_emulator_property() {
        assert!(reports_emulator(Some("1"), None));
        assert!(reports_emulator(None, Some("1")));
        assert!(reports_emulator(Some(" 1 "), Some("1")));
    }
}
