use crate::error::CommandError;
use crate::views::UpdateInfo;

#[cfg(target_os = "macos")]
fn failed() -> CommandError {
    CommandError {
        kind: "UpdateUnavailable".into(),
        message: "Could not check or install the update".into(),
    }
}

#[cfg(target_os = "macos")]
pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry, tauri_plugin_updater::Config> {
    tauri_plugin_updater::Builder::new().build()
}

#[cfg(target_os = "macos")]
pub fn configure_context(context: &mut tauri::Context<tauri::Wry>) {
    // The headless Mac update proof uses an HTTP loopback test server. Never
    // permit insecure transport for the production GitHub endpoint.
    if matches!(option_env!("BH_UPDATE_ENDPOINT"), Some(endpoint) if endpoint.starts_with("http://127.0.0.1:"))
        && let Some(config) = context.config_mut().plugins.0.get_mut("updater")
    {
        config["dangerousInsecureTransportProtocol"] = serde_json::json!(true);
    }
}

#[cfg(target_os = "macos")]
fn updater(app: &tauri::AppHandle) -> Result<tauri_plugin_updater::Updater, CommandError> {
    use tauri_plugin_updater::UpdaterExt;
    let mut builder = app.updater_builder();
    if let Some(endpoint) = option_env!("BH_UPDATE_ENDPOINT") {
        builder = builder
            .endpoints(vec![endpoint.parse().map_err(|_| failed())?])
            .map_err(|_| failed())?;
    }
    builder.build().map_err(|_| failed())
}

#[cfg(target_os = "macos")]
pub async fn check(app: &tauri::AppHandle) -> Result<Option<UpdateInfo>, CommandError> {
    let update = updater(app)?.check().await.map_err(|_| failed())?;
    Ok(update.map(|update| UpdateInfo {
        version: update.version,
        notes: update.body.unwrap_or_default(),
    }))
}

#[cfg(not(target_os = "macos"))]
pub async fn check(_app: &tauri::AppHandle) -> Result<Option<UpdateInfo>, CommandError> {
    Ok(None)
}

// An explicit user action must be the only caller of this path. The updater
// verifies the downloaded archive against the key in tauri.conf.json.
#[cfg(target_os = "macos")]
pub async fn install_available(app: &tauri::AppHandle) -> Result<Option<String>, CommandError> {
    let Some(update) = updater(app)?.check().await.map_err(|_| failed())? else {
        return Ok(None);
    };
    let version = update.version.clone();
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|_| failed())?;
    Ok(Some(version))
}

#[cfg(target_os = "macos")]
pub async fn install(app: &tauri::AppHandle) -> Result<(), CommandError> {
    if install_available(app).await?.is_some() {
        app.restart();
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub async fn install(_app: &tauri::AppHandle) -> Result<(), CommandError> {
    Err(CommandError {
        kind: "UpdateUnavailable".into(),
        message: "Updates are available only on the Mac".into(),
    })
}

#[tauri::command]
pub async fn update_check(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, CommandError> {
    check(&app).await
}

#[tauri::command]
pub async fn update_install(app: tauri::AppHandle) -> Result<(), CommandError> {
    install(&app).await
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
    };
    use tauri_plugin_updater::{Error, UpdaterExt};

    #[test]
    fn online_updater_requires_a_signed_version() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let updater: tauri_plugin_updater::Config =
            serde_json::from_value(config["plugins"]["updater"].clone()).unwrap();
        assert!(updater.require_signed_version);
    }

    // These genuine signatures use a throwaway key made with the pinned Tauri CLI
    // 2.12.0; only the public key and signed fixture bytes are kept in the repo.
    #[test]
    fn signed_update_version_matches_the_archive() {
        let bytes = include_bytes!("../tests/fixtures/updater-version/archive.tar.gz");
        let signature = include_str!("../tests/fixtures/updater-version/bound-2.0.0.sig");
        let public_key = include_str!("../tests/fixtures/updater-version/public-key.txt");

        let mut context = tauri::test::mock_context(tauri::test::noop_assets());
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        config["plugins"]["updater"]["pubkey"] = serde_json::json!(public_key.trim());
        // Only the test endpoint uses HTTP; the checked-in config still requires HTTPS.
        config["plugins"]["updater"]["dangerousInsecureTransportProtocol"] =
            serde_json::json!(true);
        context
            .config_mut()
            .plugins
            .0
            .insert("updater".into(), config["plugins"]["updater"].clone());
        let app = tauri::test::mock_builder()
            .plugin(tauri_plugin_updater::Builder::new().build())
            .build(context)
            .unwrap();
        // The online path must be checked: restore_update deliberately forces
        // signed versions even when online checks would still accept legacy ones.
        let offered = |version: &str, signature: &str| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let manifest = serde_json::json!({
                "version": version,
                "platforms": {"darwin-aarch64": {
                    "url": "https://example.invalid/archive.tar.gz",
                    "signature": signature,
                }}
            })
            .to_string();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", manifest.len(), manifest).unwrap();
            });
            let updater = app
                .updater_builder()
                .target("darwin-aarch64")
                .endpoints(vec![format!("http://{address}").parse().unwrap()])
                .unwrap()
                .build()
                .unwrap();
            let update = tauri::async_runtime::block_on(updater.check())
                .unwrap()
                .unwrap();
            server.join().unwrap();
            update
        };
        for (version, expected) in [("3.0.0", false), ("2.0.0", true)] {
            let update = offered(version, signature.trim());
            let result = update.verify(bytes);
            if expected {
                assert!(result.is_ok(), "correctly bound update failed: {result:?}");
            } else {
                assert!(
                    matches!(result, Err(Error::SignedVersionMismatch { .. })),
                    "rollback accepted: {result:?}"
                );
            }
        }
        // A genuine legacy archive cannot bypass the requirement either.
        let unsigned_version = include_str!("../tests/fixtures/updater-version/legacy-unbound.sig");
        let update = offered("2.0.0", unsigned_version.trim());
        assert!(matches!(
            update.verify(bytes),
            Err(Error::MissingSignedVersion)
        ));
    }
}
