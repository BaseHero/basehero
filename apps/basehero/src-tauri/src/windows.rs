//! Native Mac windows use one app-wide Startup/Core and independent WebViews.
use crate::error::CommandError;
#[cfg(target_os = "macos")]
use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use tauri::AppHandle;
#[cfg(target_os = "macos")]
use tauri::{Emitter, Manager};

#[cfg(target_os = "macos")]
static NEXT_WINDOW: AtomicU64 = AtomicU64::new(0);

pub fn should_lock_hidden(remaining_windows: usize) -> bool {
    remaining_windows == 0
}

pub fn should_prevent_exit(code: Option<i32>, is_macos: bool) -> bool {
    is_macos && code.is_none()
}

/// A timed-out WebView must not trap the app; a reported failed save must.
pub fn should_quit(results: &[Option<bool>]) -> bool {
    !results.contains(&Some(false))
}

/// Cocoa accepts one deferred termination reply; duplicate requests share it.
#[cfg(any(target_os = "macos", test))]
#[derive(Default)]
enum NativeTermination {
    #[default]
    Idle,
    Waiting,
    ReplyQueued,
}

#[cfg(any(target_os = "macos", test))]
impl NativeTermination {
    fn begin(&mut self) -> bool {
        if matches!(self, Self::Idle) {
            *self = Self::Waiting;
            true
        } else {
            false
        }
    }

    fn decide(&mut self, quit: bool) -> Option<bool> {
        if matches!(self, Self::Waiting) {
            *self = Self::ReplyQueued;
            Some(quit)
        } else {
            None
        }
    }

    fn finish(&mut self) {
        if matches!(self, Self::ReplyQueued) {
            *self = Self::Idle;
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
pub struct QuitState {
    pending: Mutex<Option<PendingQuit>>,
    native: Mutex<NativeTermination>,
    approved: AtomicBool,
    next_id: AtomicU64,
}

#[cfg(target_os = "macos")]
struct PendingQuit {
    id: u64,
    labels: Vec<String>,
    sender: mpsc::Sender<(String, bool)>,
}

#[cfg(target_os = "macos")]
pub fn quit_approved(app: &AppHandle) -> bool {
    app.state::<QuitState>().approved.load(Ordering::SeqCst)
}

#[cfg(target_os = "macos")]
pub fn request_quit(app: &AppHandle) {
    let state = app.state::<QuitState>();
    let mut pending = state.pending.lock().unwrap();
    if pending.is_some() {
        return;
    }
    let windows = app.webview_windows();
    let labels: Vec<String> = windows.keys().cloned().collect();
    let id = state.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    let (sender, receiver) = mpsc::channel();
    *pending = Some(PendingQuit {
        id,
        labels: labels.clone(),
        sender,
    });
    drop(pending);
    for label in windows.keys() {
        if app
            .emit_to(
                label.as_str(),
                "bh:drain-requested",
                serde_json::json!({ "requestId": id }),
            )
            .is_err()
        {
            // An unresponsive WebView is subject to the same three-second timeout.
            eprintln!("Could not request drain from window {label}");
        }
    }
    let app = app.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut answers = HashMap::new();
        while answers.len() < labels.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match receiver.recv_timeout(remaining) {
                Ok((label, ok)) => {
                    answers.insert(label, ok);
                }
                Err(_) => break,
            }
        }
        let results: Vec<_> = labels
            .iter()
            .map(|label| answers.get(label).copied())
            .collect();
        let state = app.state::<QuitState>();
        let pending = state.pending.lock().unwrap();
        if pending.as_ref().is_some_and(|current| current.id == id) {
            let quit = should_quit(&results);
            drop(pending);
            // Drain has finished (or timed out); lock before replying to Cocoa or
            // allowing Tauri to exit. The bound applies even if sync stalls.
            if quit {
                lock_hidden_bounded(&app);
            }
            let mut pending = state.pending.lock().unwrap();
            let native_reply = state.native.lock().unwrap().decide(quit);
            if native_reply.is_none() && quit {
                state.approved.store(true, Ordering::SeqCst);
            }
            *pending = None;
            drop(pending);
            if let Some(reply) = native_reply {
                let reply_app = app.clone();
                if let Err(error) = app.run_on_main_thread(move || {
                    reply_to_native_termination(reply);
                    reply_app
                        .state::<QuitState>()
                        .native
                        .lock()
                        .unwrap()
                        .finish();
                }) {
                    // A live Cocoa termination has a live event loop. If it is
                    // already gone, there is no main thread left to deliver a reply.
                    eprintln!("Could not reply to native termination: {error}");
                }
            } else if quit {
                app.exit(0);
            }
        }
    });
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub fn window_drained(window: tauri::WebviewWindow, request_id: u64, ok: bool) {
    let state = window.app_handle().state::<QuitState>();
    let pending = state.pending.lock().unwrap();
    if let Some(current) = pending.as_ref()
        && current.id == request_id
        && current.labels.iter().any(|label| label == window.label())
    {
        let _ = current.sender.send((window.label().to_owned(), ok));
    }
}

// Dock Quit, logout and shutdown call NSApplication terminate:, not Tauri's
// ExitRequested. Tao's delegate has no applicationShouldTerminate: method, so
// install one on its existing class. Cocoa waits for our reply while the WebViews
// drain; YES continues termination, while a failed save replies NO and warns.
#[cfg(target_os = "macos")]
#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const std::ffi::c_char) -> *mut c_void;
    fn sel_registerName(name: *const std::ffi::c_char) -> *mut c_void;
    fn class_addMethod(
        class: *mut c_void,
        selector: *mut c_void,
        implementation: *const c_void,
        types: *const std::ffi::c_char,
    ) -> bool;
    fn objc_msgSend();
    fn objc_allocateClassPair(
        superclass: *mut c_void,
        name: *const std::ffi::c_char,
        extra_bytes: usize,
    ) -> *mut c_void;
    fn objc_registerClassPair(class: *mut c_void);
}

#[cfg(target_os = "macos")]
static DOCK_QUIT_APP: OnceLock<AppHandle> = OnceLock::new();
#[cfg(target_os = "macos")]
static SCREEN_LOCK_CALLBACK: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Run the core lock off the UI thread; never hold Cocoa termination longer
/// than three seconds even if an account's sync is unresponsive.
#[cfg(target_os = "macos")]
pub fn lock_hidden_bounded(app: &AppHandle) {
    let (sender, receiver) = mpsc::channel();
    let app = app.clone();
    std::thread::spawn(move || {
        if let Some(startup) = app.try_state::<crate::state::Startup>()
            && let Ok(state) = startup.state()
        {
            tauri::async_runtime::block_on(crate::commands::hidden::lock_all_hidden(state));
        }
        let _ = sender.send(());
    });
    let _ = receiver.recv_timeout(Duration::from_secs(3));
}

#[cfg(target_os = "macos")]
extern "C" fn screen_locked(_: *mut c_void, _: *mut c_void, _: *mut c_void) {
    if let Some(callback) = SCREEN_LOCK_CALLBACK.get() {
        callback();
    }
}

/// NSDistributedNotificationCenter delivers the screen lock notification even
/// when BaseHero has no window. Keep the observer alive for the process lifetime.
#[cfg(target_os = "macos")]
pub fn install_screen_lock(app: &AppHandle) {
    let app = app.clone();
    let _ = register_screen_lock(move || {
        // Do not freeze AppKit while sync drains its outbox.
        let app = app.clone();
        std::thread::spawn(move || lock_hidden_bounded(&app));
    });
}

/// Register one process-lifetime observer; the callback also permits a headless
/// test of the actual distributed notification delivery.
#[cfg(target_os = "macos")]
pub fn register_screen_lock(callback: impl Fn() + Send + Sync + 'static) -> bool {
    if SCREEN_LOCK_CALLBACK.set(Box::new(callback)).is_err() {
        return false;
    }
    // SAFETY: Objective-C class/selector registration is process-global. The
    // observer is deliberately retained for the app lifetime; signatures match
    // NSObject new and addObserver:selector:name:object: on arm64.
    unsafe {
        let superclass = objc_getClass(c"NSObject".as_ptr());
        let class = objc_allocateClassPair(superclass, c"BHScreenLockObserver".as_ptr(), 0);
        if class.is_null()
            || !class_addMethod(
                class,
                sel_registerName(c"screenLocked:".as_ptr()),
                screen_locked as *const c_void,
                c"v@:@".as_ptr(),
            )
        {
            eprintln!("Could not register screen lock observer");
            return false;
        }
        objc_registerClassPair(class);
        let new: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const c_void);
        let observer = new(class, sel_registerName(c"new".as_ptr()));
        let center = new(
            objc_getClass(c"NSDistributedNotificationCenter".as_ptr()),
            sel_registerName(c"defaultCenter".as_ptr()),
        );
        let string: extern "C" fn(
            *mut c_void,
            *mut c_void,
            *const std::ffi::c_char,
        ) -> *mut c_void = std::mem::transmute(objc_msgSend as *const c_void);
        let name = string(
            objc_getClass(c"NSString".as_ptr()),
            sel_registerName(c"stringWithUTF8String:".as_ptr()),
            c"com.apple.screenIsLocked".as_ptr(),
        );
        let add: extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
        ) = std::mem::transmute(objc_msgSend as *const c_void);
        add(
            center,
            sel_registerName(c"addObserver:selector:name:object:".as_ptr()),
            observer,
            sel_registerName(c"screenLocked:".as_ptr()),
            name,
            std::ptr::null_mut(),
        );
    }
    true
}

#[cfg(target_os = "macos")]
extern "C" fn dock_quit(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> isize {
    let Some(app) = DOCK_QUIT_APP.get() else {
        return 0; // No handle to drain with: do not defer without a reply.
    };
    let state = app.state::<QuitState>();
    if !state
        .native
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .begin()
    {
        return 2; // Another request waits on the same drain and single Cocoa reply.
    }
    request_quit(app);
    2 // NSTerminateLater: Cocoa waits for replyToApplicationShouldTerminate:.
}

#[cfg(target_os = "macos")]
fn reply_to_native_termination(quit: bool) {
    // SAFETY: This runs only via AppHandle::run_on_main_thread. AppKit is loaded
    // by the Mac app, NSApplication responds to sharedApplication, and its
    // replyToApplicationShouldTerminate: takes a one-byte Objective-C BOOL on
    // arm64. Both objc_msgSend casts match their selectors' exact ABI/signature.
    unsafe {
        let class = objc_getClass(c"NSApplication".as_ptr());
        let shared_application: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const c_void);
        let app = shared_application(class, sel_registerName(c"sharedApplication".as_ptr()));
        let reply: extern "C" fn(*mut c_void, *mut c_void, i8) =
            std::mem::transmute(objc_msgSend as *const c_void);
        reply(
            app,
            sel_registerName(c"replyToApplicationShouldTerminate:".as_ptr()),
            i8::from(quit),
        );
    }
}

/// Without the handler, as after a Tao change, Dock Quit still quits, but
/// without draining the windows first; the app never fails to launch over it.
#[cfg(target_os = "macos")]
pub fn install_dock_quit(app: &AppHandle) {
    if DOCK_QUIT_APP.set(app.clone()).is_err() {
        return;
    }
    let class = c"TaoAppDelegateParent";
    let selector = c"applicationShouldTerminate:";
    let types = c"q@:@";
    // SAFETY: Tao creates this Objective-C delegate before Tauri's setup runs;
    // NSApplicationTerminateReply is a signed pointer-width integer on arm64.
    let installed = unsafe {
        let class = objc_getClass(class.as_ptr());
        !class.is_null()
            && class_addMethod(
                class,
                sel_registerName(selector.as_ptr()),
                dock_quit as *const c_void,
                types.as_ptr(),
            )
    };
    if !installed {
        eprintln!("Dock Quit won't save open notes first: Tao's app delegate changed");
    }
}

/// Only hashes understood by App.svelte may be passed to WebviewUrl::App.
fn validate_route(route: &str) -> Result<&str, CommandError> {
    let invalid = || CommandError {
        kind: "Invalid".into(),
        message: "Invalid app route".into(),
    };
    if route.is_empty() {
        return Ok(route);
    }
    let Some(path) = route.strip_prefix("#/a/") else {
        return Err(invalid());
    };
    let (path, query) = path
        .split_once('?')
        .map_or((path, None), |(p, q)| (p, Some(q)));
    let parts: Vec<_> = path.split('/').collect();
    let segment = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let valid = match parts.as_slice() {
        [account] => segment(account) && query.is_none(),
        [account, "devices"] => segment(account) && query.is_none(),
        [account, "search"] => {
            segment(account)
                && query.is_none_or(|q| {
                    q.starts_with("q=")
                        && !q.contains('#')
                        && q.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"%-_+~=.&".contains(&b))
                })
        }
        [account, "b", base] => segment(account) && segment(base) && query.is_none(),
        [account, "b", base, "n", note] => {
            segment(account) && segment(base) && segment(note) && query.is_none()
        }
        _ => false,
    };
    if valid { Ok(route) } else { Err(invalid()) }
}

pub fn open(app: &AppHandle, route: &str) -> Result<(), CommandError> {
    let route = validate_route(route)?;
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (app, route);
        Err(CommandError {
            kind: "Invalid".into(),
            message: "Windows are only available on Mac".into(),
        })
    }
    #[cfg(target_os = "macos")]
    {
        let number = NEXT_WINDOW.fetch_add(1, Ordering::Relaxed) + 1;
        let builder = tauri::WebviewWindowBuilder::new(
            app,
            format!("w-{number}"),
            tauri::WebviewUrl::App(format!("index.html{route}").into()),
        )
        .title("BaseHero")
        .inner_size(1000.0, 760.0)
        .min_inner_size(360.0, 480.0)
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true)
        .traffic_light_position(tauri::LogicalPosition::new(14.0, 19.0));
        builder.build().map_err(|_| CommandError {
            kind: "Storage".into(),
            message: "Could not open window".into(),
        })?;
        Ok(())
    }
}

#[tauri::command]
pub fn open_window(app: AppHandle, route: String) -> Result<(), CommandError> {
    open(&app, &route)
}

/// Called only after this WebView has successfully drained its editors.
#[tauri::command]
pub fn close_window(window: tauri::WebviewWindow) -> Result<(), CommandError> {
    window.destroy().map_err(|_| CommandError {
        kind: "Storage".into(),
        message: "Could not close window".into(),
    })
}

#[cfg(target_os = "macos")]
const NEW_WINDOW: &str = "bh-new-window";
#[cfg(target_os = "macos")]
const CLOSE_WINDOW: &str = "bh-close-window";
#[cfg(target_os = "macos")]
const QUIT: &str = "bh-quit";

#[cfg(target_os = "macos")]
pub fn menu(app: &AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    let menu = Menu::default(app)?;
    for item in menu.items()? {
        let Some(submenu) = item.as_submenu() else {
            continue;
        };
        if submenu.text()? == "File" {
            for existing in submenu.items()? {
                if existing
                    .as_predefined_menuitem()
                    .is_some_and(|item| item.text().is_ok_and(|text| text == "Close Window"))
                {
                    submenu.remove(&existing)?;
                }
            }
            submenu.prepend_items(&[
                &MenuItem::with_id(app, NEW_WINDOW, "New Window", true, Some("Cmd+N"))?,
                &MenuItem::with_id(app, CLOSE_WINDOW, "Close Window", true, Some("Cmd+W"))?,
                &PredefinedMenuItem::separator(app)?,
            ])?;
        } else if submenu.text()? == app.package_info().name {
            for existing in submenu.items()? {
                if existing
                    .as_predefined_menuitem()
                    .is_some_and(|item| item.text().is_ok_and(|text| text.starts_with("Quit")))
                {
                    submenu.remove(&existing)?;
                }
            }
            submenu.append(&MenuItem::with_id(
                app,
                QUIT,
                "Quit BaseHero",
                true,
                Some("Cmd+Q"),
            )?)?;
        }
    }
    Ok(menu)
}

#[cfg(target_os = "macos")]
pub fn menu_event(app: &AppHandle, event: tauri::menu::MenuEvent) {
    match event.id().as_ref() {
        NEW_WINDOW => {
            let _ = open(app, "");
        }
        CLOSE_WINDOW => {
            if let Some(window) = app
                .webview_windows()
                .into_values()
                .find(|window| window.is_focused().unwrap_or(false))
            {
                let _ = window.close();
            }
        }
        QUIT => request_quit(app),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mac_app_outlives_its_last_window() {
        assert!(should_prevent_exit(None, true));
        assert!(!should_prevent_exit(Some(0), true));
        assert!(!should_prevent_exit(None, false));
    }

    #[test]
    fn quitting_waits_for_every_window_but_not_a_hung_window() {
        assert!(should_quit(&[]));
        assert!(should_quit(&[Some(true), Some(true)]));
        assert!(should_quit(&[Some(true), None]));
        assert!(!should_quit(&[Some(false), Some(true)]));
        assert!(!should_quit(&[None, Some(false)]));
    }

    #[test]
    fn native_termination_replies_once_after_all_windows_drain() {
        let mut native = NativeTermination::default();
        assert!(native.begin());
        assert!(!native.begin()); // Another request uses the same pending reply.
        assert_eq!(native.decide(should_quit(&[Some(true), None])), Some(true));
        assert_eq!(native.decide(false), None);
        assert!(!native.begin()); // Still waiting for the main-thread reply.
        native.finish();
        assert!(native.begin());
    }

    #[test]
    fn native_termination_replies_no_after_a_failed_save() {
        let mut native = NativeTermination::default();
        assert!(native.begin());
        assert_eq!(
            native.decide(should_quit(&[None, Some(false)])),
            Some(false)
        );
        native.finish();
        assert_eq!(native.decide(true), None);
        assert!(native.begin()); // Can try quitting again after the warning.
    }

    #[test]
    fn a_route_must_be_an_app_route() {
        assert_eq!(validate_route("https://x").unwrap_err().kind, "Invalid");
        assert_eq!(
            validate_route("#/a/account/b/base/n/note").unwrap(),
            "#/a/account/b/base/n/note"
        );
        assert!(validate_route("#/a/account/b/base/n/note?bad").is_err());
        assert!(validate_route("#/a/account/b/base/n/note#evil").is_err());
        assert_eq!(validate_route("").unwrap(), "");
    }
}
