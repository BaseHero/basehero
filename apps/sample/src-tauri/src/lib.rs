#[cfg(target_os = "android")]
mod android_tls;

use basehero_sample_core::{CREDENTIALS_FILE, Sample};
use bh_core::FileSecretStore;
use std::sync::Arc;
use tauri::Manager;

#[tauri::command]
fn status(sample: tauri::State<'_, Sample>) -> String {
    match sample.connected() {
        Some(c) => format!("connected {} as {}", c.base, c.device),
        None => "not connected".into(),
    }
}

#[tauri::command]
async fn connect(
    app: tauri::AppHandle,
    sample: tauri::State<'_, Sample>,
) -> Result<String, String> {
    let path = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join(CREDENTIALS_FILE);
    let c = sample
        .install_file(&path)
        .await
        .map_err(|e| e.to_string())?;
    Ok(format!("connected {} as {}", c.base, c.device))
}

#[tauri::command]
async fn write_reading(sample: tauri::State<'_, Sample>, value: f64) -> Result<String, String> {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    sample
        .write_reading(&today, value)
        .await
        .map_err(|e| e.to_string())?;
    sample.flush().await.map_err(|e| e.to_string())?;
    Ok(format!("wrote {value} for {today}"))
}

#[tauri::command]
fn read_back(sample: tauri::State<'_, Sample>) -> Result<String, String> {
    let readings = sample.readings().map_err(|e| e.to_string())?;
    Ok(if readings.is_empty() {
        "No readings yet".into()
    } else {
        readings
            .iter()
            .map(|r| format!("{}: {}", r.day, r.value))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

#[tauri::command]
async fn ask_model(sample: tauri::State<'_, Sample>, question: String) -> Result<String, String> {
    sample.ask_model(&question).await.map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            // Development sample only. Production apps use platform-sealed secrets.
            let secrets = Arc::new(FileSecretStore::new(dir.join("secrets"))?);
            app.manage(Sample::open(dir.join("core"), secrets)?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            connect,
            write_reading,
            read_back,
            ask_model
        ])
        .run(tauri::generate_context!())
        .expect("run sample");
}
