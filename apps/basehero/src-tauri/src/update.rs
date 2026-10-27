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
    {
        if let Some(config) = context.config_mut().plugins.0.get_mut("updater") {
            config["dangerousInsecureTransportProtocol"] = serde_json::json!(true);
        }
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
