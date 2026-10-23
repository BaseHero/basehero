//! The note window's own presentation on this device: whether new windows
//! show the notes list, and the Mac menu items that reach the page. Nothing
//! here is note content, authority or synced state.
use std::path::Path;

use tauri::{AppHandle, Manager, Runtime};

/// Present only after someone hid the notes list; shown is the default.
const SIDEBAR_HIDDEN: &str = "sidebar-hidden";

/// Whether a new window shows the notes list.
pub(crate) fn sidebar_shown(dir: &Path) -> bool {
    !dir.join(SIDEBAR_HIDDEN).exists()
}

/// Remember the latest choice for the next window and restart.
pub(crate) fn remember_sidebar(dir: &Path, shown: bool) -> std::io::Result<()> {
    let marker = dir.join(SIDEBAR_HIDDEN);
    if shown {
        match std::fs::remove_file(marker) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    } else {
        std::fs::create_dir_all(dir)?;
        std::fs::write(marker, [])
    }
}

/// Read, or with `shown` also remember, whether new windows show the notes
/// list. Each open window keeps its own state; this is only the default.
#[tauri::command]
pub(crate) async fn window_sidebar<R: Runtime>(
    app: AppHandle<R>,
    shown: Option<bool>,
) -> Result<bool, &'static str> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "layout unavailable")?;
    if let Some(shown) = shown {
        remember_sidebar(&dir, shown).map_err(|_| "layout unavailable")?;
    }
    Ok(sidebar_shown(&dir))
}

#[cfg(target_os = "macos")]
pub(crate) use menu::{build as menu, event as menu_event};

#[cfg(target_os = "macos")]
mod menu {
    use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tauri::{AppHandle, Manager, Runtime};

    const ABOUT: &str = "bh-about";
    const DEVICES: &str = "bh-devices";
    const SIDEBAR: &str = "bh-sidebar";
    const NEW_NOTE: &str = "bh-new-note";
    const NEW_WINDOW: &str = "bh-new-window";

    /// The standard Mac menu with New Note and New Window in File and the
    /// notes list in View. The page performs each action, so a shortcut and
    /// its menu item do the same thing.
    pub(crate) fn build<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
        let menu = Menu::default(app)?;
        for item in menu.items()? {
            let Some(submenu) = item.as_submenu() else {
                continue;
            };
            match submenu.text()?.as_str() {
                name if name == app.package_info().name => {
                    // Tauri's first app item is its predefined About. Replace
                    // rather than add a second item with different content.
                    if let Some(default_about) = submenu
                        .items()?
                        .first()
                        .and_then(|item| item.as_predefined_menuitem().cloned())
                    {
                        submenu.remove(&default_about)?;
                    }
                    submenu.prepend_items(&[
                        &MenuItem::with_id(app, ABOUT, "About BaseHero", true, None::<&str>)?,
                        &MenuItem::with_id(app, DEVICES, "Devices…", true, None::<&str>)?,
                    ])?;
                }
                "File" => submenu.prepend_items(&[
                    &MenuItem::with_id(app, NEW_NOTE, "New Note", true, Some("Cmd+N"))?,
                    &MenuItem::with_id(app, NEW_WINDOW, "New Window", true, Some("Alt+Cmd+N"))?,
                    &PredefinedMenuItem::separator(app)?,
                ])?,
                "View" => submenu.prepend_items(&[
                    &MenuItem::with_id(
                        app,
                        SIDEBAR,
                        "Show or Hide Notes",
                        true,
                        Some("Ctrl+Cmd+S"),
                    )?,
                    &PredefinedMenuItem::separator(app)?,
                ])?,
                _ => {}
            }
        }
        Ok(menu)
    }

    /// Hand a menu action to the focused window's page; a fixed script, no data.
    pub(crate) fn event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
        let script = match event.id().as_ref() {
            ABOUT => "window.__bhAbout&&window.__bhAbout()",
            DEVICES => "window.__bhMenu&&window.__bhMenu('devices')",
            SIDEBAR => "window.__bhMenu&&window.__bhMenu('sidebar')",
            NEW_NOTE => "window.__bhMenu&&window.__bhMenu('new-note')",
            NEW_WINDOW => "window.__bhMenu&&window.__bhMenu('new-window')",
            _ => return,
        };
        let focused = app
            .webview_windows()
            .into_values()
            .find(|window| window.is_focused().unwrap_or(false));
        if let Some(window) = focused {
            let _ = window.eval(script);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_list_is_shown_until_hidden_and_remembers_the_latest_choice() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("app");
        assert!(sidebar_shown(&data), "shown before any choice");
        remember_sidebar(&data, false).unwrap();
        assert!(!sidebar_shown(&data));
        remember_sidebar(&data, false).unwrap();
        assert!(!sidebar_shown(&data), "hiding twice is still hidden");
        remember_sidebar(&data, true).unwrap();
        assert!(sidebar_shown(&data));
        remember_sidebar(&data, true).unwrap();
        assert!(sidebar_shown(&data), "showing without a marker is fine");
    }
}
