#[cfg(target_os = "android")]
mod android_tls;
pub mod commands;
pub mod error;
pub mod hero;
pub mod kit_store;
pub mod notes;
mod recents;
pub mod secrets;
pub mod state;
pub mod update;
pub mod views;
pub mod windows;

#[cfg(target_os = "macos")]
use tauri::Emitter;
use tauri::Manager;

#[tauri::command]
fn app_info() -> views::AppInfo {
    commands::app_info()
}

// Async, so a slow key store doesn't freeze the window.
#[tauri::command(async)]
fn reset_device(
    app: tauri::AppHandle,
    startup: tauri::State<'_, state::Startup>,
) -> Result<(), error::CommandError> {
    startup.reset(&app)
}

#[tauri::command]
fn accounts(
    startup: tauri::State<'_, state::Startup>,
) -> Result<Vec<bh_core::AccountSummary>, error::CommandError> {
    commands::account::accounts(startup.state()?)
}

#[tauri::command]
async fn sign_up(
    startup: tauri::State<'_, state::Startup>,
    form: views::SignUpForm,
) -> Result<views::SignedUp, error::CommandError> {
    commands::account::sign_up(startup.state()?, form).await
}

#[tauri::command]
async fn sign_in_start(
    startup: tauri::State<'_, state::Startup>,
    form: views::SignInForm,
) -> Result<String, error::CommandError> {
    commands::account::sign_in_start(startup.state()?, form).await
}

#[tauri::command]
async fn sign_in_with_kit(
    startup: tauri::State<'_, state::Startup>,
    pending: String,
    kit: String,
) -> Result<bh_core::AccountSummary, error::CommandError> {
    let kit = views::SecretString::from(kit);
    commands::account::sign_in_with_kit(startup.state()?, &pending, &kit).await
}

#[tauri::command]
fn sign_in_cancel(
    startup: tauri::State<'_, state::Startup>,
    pending: String,
) -> Result<(), error::CommandError> {
    commands::account::sign_in_cancel(startup.state()?, &pending)
}

#[tauri::command]
async fn sign_out(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
) -> Result<(), error::CommandError> {
    commands::account::sign_out(startup.state()?, account).await
}

#[tauri::command]
async fn new_kit(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
    password: String,
) -> Result<views::SecretString, error::CommandError> {
    let password = views::SecretString::from(password);
    commands::account::new_kit(startup.state()?, account, &password).await
}

#[tauri::command]
fn kit_status(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
) -> Result<bh_core::KitStatus, error::CommandError> {
    commands::account::kit_status(startup.state()?, account)
}

#[tauri::command]
fn show_kit(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
) -> Result<views::SecretString, error::CommandError> {
    commands::account::show_kit(startup.state()?, account)
}

#[tauri::command]
async fn set_kit_saved(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
    kit: String,
) -> Result<(), error::CommandError> {
    let kit = views::SecretString::from(kit);
    commands::account::set_kit_saved(startup.state()?, account, &kit).await
}

#[tauri::command]
async fn devices(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
) -> Result<Vec<bh_core::DeviceSummary>, error::CommandError> {
    commands::account::devices(startup.state()?, account).await
}

#[tauri::command]
fn apps(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
) -> Result<Vec<bh_core::AppSummary>, error::CommandError> {
    commands::account::apps(startup.state()?, account)
}

#[tauri::command]
async fn app_grant_add(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
    device: bh_core::DeviceId,
    choice: commands::approval::BaseChoiceInput,
) -> Result<bh_core::BaseId, error::CommandError> {
    commands::account::app_grant_add(startup.state()?, account, device, choice).await
}

#[tauri::command]
async fn app_grant_remove(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
    device: bh_core::DeviceId,
    base: bh_core::BaseId,
) -> Result<(), error::CommandError> {
    commands::account::app_grant_remove(startup.state()?, account, device, base).await
}

#[tauri::command]
async fn set_app_cap(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
    device: bh_core::DeviceId,
    cap_micro_usd: u64,
) -> Result<(), error::CommandError> {
    commands::account::set_app_cap(startup.state()?, account, device, cap_micro_usd).await
}

#[tauri::command]
async fn usage(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
    month: Option<String>,
) -> Result<bh_core::AccountUsage, error::CommandError> {
    commands::account::usage(startup.state()?, account, month.as_deref()).await
}

#[tauri::command]
async fn remove_device(
    startup: tauri::State<'_, state::Startup>,
    account: bh_core::AccountId,
    device: bh_core::DeviceId,
) -> Result<(), error::CommandError> {
    commands::account::remove_device(startup.state()?, account, device).await
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
        .plugin(tauri_plugin_process::init())
        .menu(windows::menu)
        .on_menu_event(windows::menu_event)
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window
                    .app_handle()
                    .emit_to(window.label(), "bh:close-requested", ());
            }
            tauri::WindowEvent::Destroyed => {
                if let Some(startup) = window.app_handle().try_state::<state::Startup>()
                    && let Ok(state) = startup.state()
                {
                    state.notes.close_window(window.label());
                }
                if windows::should_lock_hidden(window.app_handle().webview_windows().len()) {
                    windows::lock_hidden_bounded(window.app_handle());
                }
            }
            _ => {}
        });
    builder
        .setup(|app| {
            #[cfg(target_os = "macos")]
            {
                app.manage(windows::QuitState::default());
                windows::install_dock_quit(app.handle());
                windows::install_screen_lock(app.handle());
            }
            app.manage(state::Startup::open(app.handle()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            accounts,
            reset_device,
            sign_up,
            sign_in_start,
            sign_in_with_kit,
            sign_in_cancel,
            commands::approval::ipc::approval_start,
            commands::approval::ipc::approval_digits,
            commands::approval::ipc::approval_wait,
            commands::approval::ipc::approval_cancel,
            commands::approval::ipc::approval_use_kit,
            commands::approval::ipc::approval_requests,
            commands::approval::ipc::approval_open,
            commands::approval::ipc::approval_approve,
            commands::approval::ipc::approval_decline,
            commands::approval::ipc::connect_open,
            commands::approval::ipc::connect_check,
            commands::approval::ipc::connect_approve,
            sign_out,
            new_kit,
            kit_status,
            show_kit,
            set_kit_saved,
            devices,
            set_app_cap,
            apps,
            app_grant_add,
            app_grant_remove,
            usage,
            remove_device,
            commands::note::note_open,
            commands::note::note_apply,
            commands::note::note_close,
            commands::base::ipc::bases,
            commands::base::ipc::create_base,
            commands::hidden::ipc::create_hidden_base,
            commands::hidden::ipc::unlock_hidden,
            commands::hidden::ipc::lock_hidden,
            commands::hidden::ipc::lock_all_hidden,
            commands::hidden::ipc::password_strength,
            commands::hidden::ipc::refresh_account,
            commands::files::ipc::file_add,
            commands::files::ipc::files,
            commands::files::ipc::file_info,
            commands::files::ipc::file_image,
            commands::files::ipc::file_open,
            commands::files::ipc::versions,
            commands::files::ipc::version_state,
            commands::files::ipc::version_restore,
            commands::base::ipc::children,
            commands::base::ipc::tree_children,
            commands::base::ipc::get_object,
            commands::base::ipc::create_object,
            commands::base::ipc::rename_object,
            commands::base::ipc::move_object,
            commands::base::ipc::delete_object,
            commands::base::ipc::restore_object,
            commands::base::ipc::trash,
            commands::base::ipc::locate,
            commands::base::ipc::moved_from,
            commands::base::ipc::search,
            commands::base::ipc::sync_state,
            hero::ipc::hero_chats,
            hero::ipc::hero_chat_for,
            hero::ipc::hero_new_chat,
            hero::ipc::hero_messages,
            hero::ipc::hero_send,
            hero::ipc::hero_stop,
            hero::ipc::hero_answer,
            hero::ipc::hero_retry,
            update::update_check,
            update::update_install,
            windows::open_window,
            windows::close_window,
            #[cfg(target_os = "macos")]
            windows::window_drained,
            #[cfg(debug_assertions)]
            commands::dev_probe::dev_model_probe
        ])
        .build(context)
        .expect("failed to start BaseHero")
        .run(|app, event| {
            match event {
                tauri::RunEvent::ExitRequested { code, api, .. } => {
                    #[cfg(target_os = "macos")]
                    {
                        // None with no windows is the last-window-close policy. A
                        // programmatic exit must drain, including other callers of app.exit.
                        if code.is_none() && app.webview_windows().is_empty() {
                            api.prevent_exit();
                        } else if code != Some(tauri::RESTART_EXIT_CODE)
                            && !windows::quit_approved(app)
                        {
                            api.prevent_exit();
                            windows::request_quit(app);
                        }
                    }
                    #[cfg(not(target_os = "macos"))]
                    let _ = (code, api);
                }
                #[cfg(target_os = "macos")]
                tauri::RunEvent::Reopen {
                    has_visible_windows: false,
                    ..
                } => {
                    if let Err(error) = windows::open(app, "") {
                        eprintln!("Could not reopen BaseHero: {}", error.message);
                    }
                }
                // Stop the core's threads before the process exits; see `Core::shutdown`.
                tauri::RunEvent::Exit => {
                    #[cfg(target_os = "macos")]
                    windows::lock_hidden_bounded(app);
                    if let Some(startup) = app.try_state::<state::Startup>()
                        && let Ok(state) = startup.state()
                    {
                        state.core.shutdown();
                    }
                }
                _ => {}
            }
        });
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
