#[cfg(target_os = "android")]
mod android_tls;
pub mod commands;
pub mod error;
pub mod secrets;
pub mod state;
pub mod update;
pub mod views;

use tauri::Manager;

#[tauri::command]
fn app_info() -> views::AppInfo {
    commands::app_info()
}

#[tauri::command]
fn accounts(
    startup: tauri::State<'_, state::Startup>,
) -> Result<Vec<bh_core::AccountSummary>, error::CommandError> {
    commands::account::accounts(startup.state()?)
}

fn context() -> tauri::Context<tauri::Wry> {
    tauri::generate_context!()
}

/// Hidden Mac proof modes, handled before opening any window.
#[cfg(target_os = "macos")]
pub fn hidden_mode() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first()?.as_str() {
        "--keychain-check" => Some(secrets::mac::keychain_check(
            &context().config().identifier,
            &args[1..],
        )),
        "--update-now" => Some(
            if args.len() == 1 {
                update_now()
            } else {
                Err(2)
            }
            .map(|_| 0)
            .unwrap_or_else(|code| {
                eprintln!("BaseHero helper operation failed");
                code
            }),
        ),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn update_now() -> Result<(), i32> {
    use std::io::Write;

    let mut context = context();
    update::configure_context(&mut context);
    context.config_mut().app.windows.clear();
    let app = tauri::Builder::default()
        .plugin(update::plugin())
        .plugin(tauri_plugin_process::init())
        .build(context)
        .map_err(|_| 5)?;
    let installed =
        tauri::async_runtime::block_on(update::install_available(app.handle())).map_err(|_| 5)?;
    println!("{}", serde_json::json!({ "installed": installed }));
    std::io::stdout().flush().map_err(|_| 5)?;
    // The headless proof exits here; only the in-app action restarts the GUI.
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let context = context();
    #[cfg(target_os = "macos")]
    let mut context = context;
    #[cfg(target_os = "macos")]
    update::configure_context(&mut context);
    let builder = tauri::Builder::default().plugin(tauri_plugin_opener::init());
    #[cfg(target_os = "macos")]
    let builder = builder
        .plugin(update::plugin())
        .plugin(tauri_plugin_process::init());
    builder
        .setup(|app| {
            app.manage(state::Startup::open(app.handle()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            accounts,
            update::update_check,
            update::update_install,
            #[cfg(debug_assertions)]
            commands::dev_probe::dev_model_probe
        ])
        .run(context)
        .expect("failed to start BaseHero");
}

#[cfg(test)]
mod tests {
    fn tauri_conf() -> serde_json::Value {
        serde_json::from_str(include_str!("../tauri.conf.json")).unwrap()
    }

    #[test]
    fn updater_key_matches_release_identity() {
        let identity: serde_json::Value =
            serde_json::from_str(include_str!("../../release-identity.json")).unwrap();
        assert_eq!(
            tauri_conf()["plugins"]["updater"]["pubkey"],
            identity["updaterPublicKey"]
        );
    }

    #[test]
    fn csp_allows_only_bundled_script() {
        let conf = tauri_conf();
        let csp = conf["app"]["security"]["csp"].as_str().unwrap();
        let script = csp
            .split(';')
            .find(|d| d.trim().starts_with("script-src"))
            .unwrap();
        assert_eq!(script.trim(), "script-src 'self'");
    }

    #[test]
    fn csp_forbids_frames_workers_and_objects() {
        let conf = tauri_conf();
        let csp = conf["app"]["security"]["csp"].as_str().unwrap();
        let directives: Vec<_> = csp.split(';').map(str::trim).collect();
        for blocked in ["frame-src 'none'", "worker-src 'none'", "object-src 'none'"] {
            assert!(directives.contains(&blocked), "missing {blocked} in {csp}");
        }
    }

    #[test]
    fn capability_only_opens_http_and_https_urls() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        assert_eq!(
            capability["permissions"],
            serde_json::json!([
                "core:default",
                {
                    "identifier": "opener:allow-open-url",
                    "allow": [{ "url": "http://*" }, { "url": "https://*" }]
                }
            ])
        );
    }

    #[test]
    fn app_info_defaults_to_the_dev_server() {
        assert_eq!(
            crate::commands::app_info().server,
            "https://dev-api.basehero.com"
        );
    }
}
