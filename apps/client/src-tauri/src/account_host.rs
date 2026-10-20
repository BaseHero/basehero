//! The first-run window's account commands, bound to the app's account
//! registry (`bh_host::accounts`).
//!
//! The page sends only a password and receives screen state. The registry
//! owns the container directory, the account owner and the native key
//! stores; this module adds the platform's stores, the kit destinations and
//! the window checks. No WebView value names a container, path, key or
//! account.
use std::{path::PathBuf, sync::Arc};

#[cfg(not(target_os = "macos"))]
#[cfg_attr(feature = "desktop-fixture", allow(unused_imports))]
use bh_account::platform::ControlKeyPolicy;
use bh_account::recovery::RecoveryCode;
use bh_device::OwnerError;
#[cfg(not(target_os = "macos"))]
#[cfg_attr(feature = "desktop-fixture", allow(unused_imports))]
pub(crate) use bh_host::accounts::HostKeyStore;
pub(crate) use bh_host::accounts::{AccountOperation, NoteAuthority, Screen};
use serde::Serialize;

#[cfg(not(any(target_os = "macos", target_os = "android")))]
use crate::account_stub::{Destination, email_kit, save_kit_file};
#[cfg(all(
    not(any(target_os = "macos", target_os = "android")),
    not(feature = "desktop-fixture")
))]
use crate::account_stub::{KitProtector, LoginStore};
#[cfg(target_os = "macos")]
use crate::native::bridge::{Destination, KitProtector, LoginStore, email_kit, save_kit_file};
#[cfg(target_os = "android")]
use crate::{
    account_stub::{Destination, email_kit, save_kit_file},
    android_account::{AndroidPendingSetupProtector as KitProtector, AndroidStore as LoginStore},
};
#[cfg(all(
    not(any(target_os = "macos", target_os = "android")),
    feature = "desktop-fixture"
))]
use bh_host::test_support::{FakeStore as LoginStore, PlainProtector as KitProtector};

/// This platform's account registry: its key store and setup protector.
pub type AccountHost = bh_host::accounts::AccountHost<LoginStore, KitProtector>;
pub type SharedAccountHost = bh_host::accounts::SharedAccountHost<LoginStore, KitProtector>;

/// The app's accounts. Without the user's durable home no identity is
/// created in /tmp; Android attaches Tauri's app data directory once the
/// app exists (`AccountHost::attach_directory`).
pub fn account_host(owner: Arc<bh_device::Owner>) -> AccountHost {
    #[cfg(not(target_os = "android"))]
    let directory = directory_for_home(std::env::var_os("HOME"));
    #[cfg(target_os = "android")]
    let directory = None;
    AccountHost::new(owner, directory)
}

#[cfg(all(
    not(any(target_os = "macos", target_os = "android")),
    not(feature = "desktop-fixture")
))]
impl HostKeyStore for LoginStore {
    const JOIN_POLICY: ControlKeyPolicy = ControlKeyPolicy::AppEnforcedOwnerConfirmation;
}
#[cfg(target_os = "android")]
impl HostKeyStore for LoginStore {
    // The Keystore adapter's only control key: strong biometrics, per use.
    const JOIN_POLICY: ControlKeyPolicy = ControlKeyPolicy::CurrentBiometricsOnly;
}

/// The container owner appends `accounts/` beneath this app-data directory.
#[cfg_attr(
    target_os = "android",
    expect(dead_code, reason = "Android uses Tauri's app data directory")
)]
fn directory_for_home(home: Option<std::ffi::OsString>) -> Option<PathBuf> {
    home.filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .map(|base| {
            base.join("Library/Application Support")
                .join(crate::APP_IDENTIFIER)
        })
}

/// What `window` shows after activation, and the windows to reopen.
pub(crate) struct Restored {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the shown note, checked by tests")
    )]
    pub note: [u8; 32],
    pub main: Option<crate::note_host::Restore>,
    pub others: Vec<crate::note_host::Restore>,
}
/// Install this account's authority (unchanged if already current), then show
/// the first restart record's note in `window` (else its home note). Records
/// are consumed once, only after this fresh authority, and are never it: each
/// note is shown through the owner's capability, anchor and catalogue checks.
fn open_account_notes(
    owner: &bh_device::Owner,
    window: &str,
    (id, capability, own_base): NoteAuthority,
) -> Result<Restored, OwnerError> {
    owner.authorize(id, capability, own_base)?;
    let mut plan = owner
        .take_authorized_view_records(id)
        .map(crate::note_host::plan_restore)
        .unwrap_or_default()
        .into_iter();
    while let Some(main) = plan.next() {
        if owner.show_note(window, id, main.note).is_ok() {
            return Ok(Restored {
                note: main.note,
                main: Some(main),
                others: plan.collect(),
            });
        }
    }
    Ok(Restored {
        note: owner.open_home(window, id)?,
        main: None,
        others: Vec::new(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordScreen {
    screen: &'static str,
    suggested: String,
    error: Option<&'static str>,
}

/// The setup window's account operation through the shared setup workflow
/// (`PairingHost::setup_screen`), which follows or resumes a join.
async fn run_account(
    window: &tauri::WebviewWindow,
    state: &tauri::State<'_, SharedAccountHost>,
    sync: &tauri::State<'_, bh_host::sync::SyncHost>,
    pairing: &tauri::State<'_, bh_host::pairing::PairingHost>,
    operation: AccountOperation,
) -> Result<Screen, String> {
    pairing
        .setup_screen(window.label(), state, sync, operation)
        .await
        .map_err(str::to_owned)
}

fn setup_allowed(label: &str, note_bound: bool) -> bool {
    label == "main" && !note_bound
}
pub(crate) fn ensure_setup_window(
    window: &tauri::WebviewWindow,
    notes: &tauri::State<'_, crate::note_host::NoteHost>,
) -> Result<(), &'static str> {
    setup_allowed(window.label(), notes.has_binding(window.label()))
        .then_some(())
        .ok_or("setup unavailable")
}

#[tauri::command]
pub async fn account_screen(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, bh_host::sync::SyncHost>,
    pairing: tauri::State<'_, bh_host::pairing::PairingHost>,
) -> Result<Screen, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let screen = run_account(&window, &state, &sync, &pairing, AccountOperation::Startup).await?;
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    Ok(screen)
}

#[tauri::command]
pub async fn account_retry(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, bh_host::sync::SyncHost>,
    pairing: tauri::State<'_, bh_host::pairing::PairingHost>,
) -> Result<Screen, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let screen = run_account(&window, &state, &sync, &pairing, AccountOperation::Retry).await?;
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    Ok(screen)
}

#[tauri::command]
pub async fn account_suggest_password(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<PasswordScreen, &'static str> {
    ensure_setup_window(&window, &notes)?;
    let suggested = crate::passwords::suggest();
    state.set_suggested(Some(suggested.clone()));
    Ok(PasswordScreen {
        screen: "password",
        suggested,
        error: None,
    })
}

/// A weak custom password is refused with the decided explanation, never with
/// arbitrary character-class rules. The password itself is not retained here.
#[tauri::command]
pub async fn account_create(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, bh_host::sync::SyncHost>,
    pairing: tauri::State<'_, bh_host::pairing::PairingHost>,
    password: String,
) -> Result<serde_json::Value, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let refused = (state.suggested().as_deref() != Some(&password)
        && !crate::passwords::acceptable(&password))
    .then(|| {
        let suggested = state.suggested().unwrap_or_else(crate::passwords::suggest);
        state.set_suggested(Some(suggested.clone()));
        suggested
    });
    if let Some(suggested) = refused {
        return Ok(serde_json::json!(PasswordScreen {
            screen: "password",
            suggested,
            error: Some(
                "That password is too easy to guess. Try a longer phrase, or use the suggested one."
            ),
        }));
    }
    let screen = run_account(
        &window,
        &state,
        &sync,
        &pairing,
        AccountOperation::Create(password),
    )
    .await?;
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    if matches!(screen, Screen::Kit { .. } | Screen::Ready) {
        state.set_suggested(None);
    }
    Ok(serde_json::json!(screen))
}

#[tauri::command]
pub async fn account_confirm_kit(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, bh_host::sync::SyncHost>,
    pairing: tauri::State<'_, bh_host::pairing::PairingHost>,
) -> Result<Screen, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    run_account(
        &window,
        &state,
        &sync,
        &pairing,
        AccountOperation::ConfirmKit,
    )
    .await
}

#[tauri::command]
pub fn account_return(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
) -> Result<Screen, &'static str> {
    ensure_setup_window(&window, &notes)?;
    Ok(Screen::Return)
}

/// `saved` means the person really has the code. `opened` means a destination
/// appeared but nothing proves it was kept, so the screens ask afterwards.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteResult {
    result: &'static str,
    route: &'static str,
}

fn kit_route(result: Result<Destination, ()>, route: &'static str) -> RouteResult {
    RouteResult {
        result: match result {
            Ok(Destination::Saved) => "saved",
            Ok(Destination::Opened) => "opened",
            Ok(Destination::Cancelled) => "cancelled",
            Err(()) => "failed",
        },
        route,
    }
}

/// Run a destination with the code held only in native memory. No path,
/// address or kit text crosses the IPC boundary, and the page supplies only
/// which destination to use. The code exists only while setup is incomplete.
async fn kit_result(
    window: &tauri::WebviewWindow,
    notes: &tauri::State<'_, crate::note_host::NoteHost>,
    state: &tauri::State<'_, SharedAccountHost>,
    route: &'static str,
    action: fn(&RecoveryCode) -> Result<Destination, ()>,
) -> Result<RouteResult, String> {
    ensure_setup_window(window, notes).map_err(str::to_owned)?;
    let code = state.pending_code();
    let Some(code) = code else {
        return Ok(RouteResult {
            result: "cancelled",
            route,
        });
    };
    let result = tauri::async_runtime::spawn_blocking(move || action(&code))
        .await
        .map_err(|_| "kit destination unavailable".to_owned())?;
    Ok(kit_route(result, route))
}

#[tauri::command]
pub async fn account_print_kit(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<RouteResult, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let code_available = state.pending_code().is_some();
    if !code_available {
        return Ok(kit_route(Ok(Destination::Cancelled), "print"));
    }
    #[cfg(target_os = "macos")]
    {
        // The kit is already visible only on the setup page. WKWebView's own
        // dialog offers Print and Save as PDF; no other application receives it.
        window.print().map_err(|_| "print unavailable".to_owned())?;
        Ok(kit_route(Ok(Destination::Opened), "print"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(kit_route(Ok(Destination::Cancelled), "print"))
    }
}

#[tauri::command]
pub async fn account_email_kit(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
) -> Result<RouteResult, String> {
    kit_result(&window, &notes, &state, "email", email_kit).await
}

#[tauri::command]
pub async fn account_save_kit_file(
    window: tauri::WebviewWindow,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    state: tauri::State<'_, SharedAccountHost>,
    sync: tauri::State<'_, bh_host::sync::SyncHost>,
    pairing: tauri::State<'_, bh_host::pairing::PairingHost>,
) -> Result<RouteResult, String> {
    ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
    let code = state.pending_code();
    let Some(code) = code else {
        return Ok(RouteResult {
            result: "cancelled",
            route: "file",
        });
    };
    let saved = save_kit_file(&code).await;
    if matches!(saved, Ok(Destination::Saved)) {
        ensure_setup_window(&window, &notes).map_err(str::to_owned)?;
        // The OS write succeeded. Confirm natively before the IPC response so
        // a page navigation after file success cannot abandon the saved kit.
        let same_setup = state
            .pending_code()
            .is_some_and(|pending| pending.to_kit_text() == code.to_kit_text());
        if !same_setup {
            return Err("account changed during kit save".into());
        }
        let screen = run_account(
            &window,
            &state,
            &sync,
            &pairing,
            AccountOperation::ConfirmKit,
        )
        .await?;
        if !matches!(screen, Screen::Ready | Screen::Retry) {
            return Err("saved kit needs a retry".into());
        }
    }
    Ok(kit_route(saved, "file"))
}

/// Bind this window's note to the container the native account host routed.
/// The page never names a container; Tauri derives the calling window.
#[tauri::command]
pub async fn account_open_note(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, SharedAccountHost>,
    notes: tauri::State<'_, crate::note_host::NoteHost>,
    sync: tauri::State<'_, bh_host::sync::SyncHost>,
) -> Result<(), &'static str> {
    ensure_setup_window(&window, &notes)?;
    let authority = state.note_authority().ok_or("no verified account")?;
    let owner = Arc::clone(notes.owner());
    let label = window.label().to_owned();
    let id = authority.0;
    let restored =
        tauri::async_runtime::spawn_blocking(move || open_account_notes(&owner, &label, authority))
            .await
            .map_err(|_| "note unavailable")?
            .map_err(|_| "note unavailable")?;
    crate::note_host::restore_windows(&notes, &window, id, restored.main, restored.others);
    // The account is ready and its notes open: start (or keep) its sync.
    sync.ensure_started(
        &state,
        id,
        Arc::new(crate::note_host::AppWindows {
            app: tauri::Manager::app_handle(&window).clone(),
        }),
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_host::{
        accounts::ready_test_host,
        test_support::{FakeStore, PlainProtector},
    };

    type Host = bh_host::accounts::SharedAccountHost<FakeStore, PlainProtector>;

    async fn ready_on(owner: &Arc<bh_device::Owner>, dir: &std::path::Path) -> Host {
        ready_test_host(owner, dir, FakeStore::default()).await
    }

    #[tokio::test]
    async fn verified_session_binds_home_note_and_lists_creates_and_shows_own_notes() {
        use crate::note_host::{create_bound, list_bound, new_window_note, show_bound};
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let session = ready_on(&owner, dir.path()).await;
        let authority = session
            .note_authority()
            .expect("ready session has note authority");
        let (id, _) = session.ready_authority().unwrap();
        assert_eq!(authority.0, id);
        assert_eq!(
            authority.2,
            session.ready_parts(id).unwrap().own_base.id().0
        );
        assert!(
            list_bound(&owner, "main", None).is_err(),
            "setup window has no notes"
        );
        let home = open_account_notes(&owner, "main", authority.clone())
            .unwrap()
            .note;
        assert_eq!(owner.bound_note("main"), Some(home));
        // A second open, e.g. after a retry, reuses the authority and the window.
        assert_eq!(
            open_account_notes(&owner, "main", authority).unwrap().note,
            home
        );
        let rows = list_bound(&owner, "main", None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].note, home.to_vec());
        assert_eq!(rows[0].title, "");
        let created = create_bound(&owner, "main").unwrap();
        let notes: Vec<_> = list_bound(&owner, "main", None)
            .unwrap()
            .into_iter()
            .map(|row| row.note)
            .collect();
        assert_eq!(notes, vec![created.clone(), home.to_vec()]);
        let first = list_bound(&owner, "main", None).unwrap().remove(0);
        let after = crate::note_host::After {
            touched: first.touched,
            note: first.note.clone(),
        };
        assert_eq!(
            list_bound(&owner, "main", Some(after)).unwrap()[0].note,
            home.to_vec()
        );
        show_bound(&owner, "main", created.clone()).unwrap();
        assert_eq!(
            owner.bound_note("main").map(|n| n.to_vec()),
            Some(created.clone())
        );
        assert!(show_bound(&owner, "main", vec![9; 32]).is_err());
        assert!(show_bound(&owner, "main", vec![9; 31]).is_err());
        assert_eq!(
            new_window_note(&owner, "main", home.to_vec()).unwrap(),
            (id, home)
        );
        assert!(new_window_note(&owner, "main", vec![9; 32]).is_err());
        assert!(new_window_note(&owner, "note-7", home.to_vec()).is_err());
        let host = crate::note_host::NoteHost::with_owner(Arc::clone(&owner));
        host.remember_window("note-2", id, home);
        owner.invalidate("note-2"); // the new window's first page load starts
        assert_eq!(host.bind_window_intent("note-2"), Ok(true));
        assert_eq!(owner.bound_note("note-2"), Some(home));
        assert_eq!(
            host.bind_window_intent("note-2"),
            Ok(false),
            "an intent binds once"
        );
        host.remember_window("note-3", id, home);
        host.forget_window_intent("note-3"); // destroyed before loading
        assert_eq!(host.bind_window_intent("note-3"), Ok(false));
        assert_eq!(owner.bound_note("note-3"), None);
        // A window first loading while Quit or update holds every window
        // keeps its intent; a later binding revalidates and shows it.
        host.remember_window("note-4", id, home);
        let fence = owner.begin_drain().unwrap();
        assert_eq!(host.bind_window_intent("note-4"), Err(()));
        assert_eq!(host.bind_window_intent("note-4"), Err(()), "still kept");
        owner.end_drain(fence);
        assert_eq!(host.bind_window_intent("note-4"), Ok(true));
        assert_eq!(owner.bound_note("note-4"), Some(home));
        // A navigated or destroyed page keeps no route to list or create from.
        owner.invalidate("main");
        assert!(list_bound(&owner, "main", None).is_err());
        assert!(create_bound(&owner, "main").is_err());
    }

    #[tokio::test]
    async fn activation_restores_quit_windows_once_from_selection_bytes_not_account_ids() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(bh_device::Owner::default());
        let session = ready_on(&owner, dir.path()).await;
        let authority = session.note_authority().unwrap();
        let (id, base) = (authority.0, authority.2);
        let db = owner.shared_database(id).unwrap();
        let first = db.lock().unwrap().create_note(base, [0; 32]).unwrap();
        let second = db.lock().unwrap().create_note(base, [0; 32]).unwrap();
        let record = |note, selection: u8, scroll, x| bh_storage::ViewRecord {
            version: 1,
            key: bh_storage::NoteKey {
                base,
                audience: [0; 32],
                note,
            },
            // Encoded Yjs relative positions, as a page's view() returns.
            anchor: vec![1, selection, 3],
            head: vec![1, selection, 4],
            cursor_offset: scroll,
            frame: [x, 30.0, 900.0, 700.0],
        };
        db.lock()
            .unwrap()
            .replace_view_records(&[
                record(first, 7, 64.5, 10.0),
                record(second, 8, -120.0, 400.0),
            ])
            .unwrap();
        let restored = open_account_notes(&owner, "main", authority.clone()).unwrap();
        assert_eq!(restored.note, first);
        assert_eq!(owner.bound_note("main"), Some(first));
        let main = restored.main.unwrap();
        assert_eq!(
            (main.view.anchor, main.view.head, main.view.cursor_offset),
            (vec![1, 7, 3], vec![1, 7, 4], 64.5)
        );
        assert_eq!(main.frame, Some([10.0, 30.0, 900.0, 700.0]));
        assert_eq!(restored.others.len(), 1);
        assert_eq!(restored.others[0].note, second);
        assert_eq!(restored.others[0].view.anchor, vec![1, 8, 3]);
        assert_eq!(
            restored.others[0].view.cursor_offset, -120.0,
            "a cursor above the visible area"
        );
        // A second activation (a reload) restores nothing again.
        let again = open_account_notes(&owner, "main", authority).unwrap();
        assert!(again.main.is_none() && again.others.is_empty());
        assert_ne!(again.note, first, "back to the home note");
    }

    #[test]
    fn restored_frames_are_clamped_and_offscreen_positions_dropped() {
        use crate::note_host::{on_screen, restore_frame};
        assert_eq!(
            restore_frame([5.0, 6.0, 100.0, 50_000.0]),
            Some([5.0, 6.0, 320.0, 8000.0])
        );
        assert_eq!(restore_frame([0.0, 0.0, f64::NAN, 10.0]), None);
        let screens = [[0.0, 0.0, 1440.0, 900.0], [1440.0, 0.0, 1920.0, 1080.0]];
        assert!(on_screen([100.0, 40.0, 900.0, 700.0], &screens));
        assert!(on_screen([2000.0, 100.0, 900.0, 700.0], &screens));
        assert!(!on_screen([-5000.0, 40.0, 900.0, 700.0], &screens));
        assert!(!on_screen([100.0, 2000.0, 900.0, 700.0], &screens));
    }

    #[tokio::test]
    async fn stale_capability_and_other_accounts_notes_are_refused_natively() {
        use crate::note_host::{list_bound, show_bound};
        let owner = Arc::new(bh_device::Owner::default());
        let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let a = ready_on(&owner, a_dir.path()).await;
        let b = ready_on(&owner, b_dir.path()).await;
        let a_home = open_account_notes(&owner, "main", a.note_authority().unwrap())
            .unwrap()
            .note;
        let b_home = open_account_notes(&owner, "note-1", b.note_authority().unwrap())
            .unwrap()
            .note;
        assert!(show_bound(&owner, "main", b_home.to_vec()).is_err());
        assert!(show_bound(&owner, "note-1", a_home.to_vec()).is_err());
        assert_eq!(owner.bound_note("main"), Some(a_home));
        let old = a.note_authority().unwrap();
        let id = old.0;
        // A lock revokes A's authority.
        a.lock().stop_accounts();
        assert!(a.note_authority().is_none());
        assert!(list_bound(&owner, "main", None).is_err());
        assert!(open_account_notes(&owner, "main", old).is_err());
        // Account B is untouched by A's revocation.
        assert_eq!(list_bound(&owner, "note-1", None).unwrap().len(), 1);
        let _ = id;
        let sync = bh_host::sync::SyncHost::new(bh_host::sync::Configured::Missing, owner.clone());
        assert_eq!(
            bh_host::pairing::PairingHost::default()
                .setup_screen("main", &a, &sync, AccountOperation::Startup)
                .await,
            Ok(Screen::Ready)
        );
        let fresh = open_account_notes(&owner, "main", a.note_authority().unwrap())
            .unwrap()
            .note;
        assert_eq!(fresh, a_home, "a fresh capability reopens the same notes");
    }

    #[test]
    fn missing_mac_home_never_creates_an_ephemeral_account() {
        assert!(directory_for_home(None).is_none());
        assert_eq!(
            directory_for_home(Some(std::ffi::OsString::from("/opt/example-home"))),
            Some(
                std::path::Path::new("/opt/example-home/Library/Application Support")
                    .join(crate::APP_IDENTIFIER)
            )
        );
        if crate::APP_IDENTIFIER == "app.basehero.client" {
            assert_eq!(
                directory_for_home(Some(std::ffi::OsString::from("/opt/example-home"))),
                Some(std::path::PathBuf::from(
                    "/opt/example-home/Library/Application Support/app.basehero.client"
                ))
            );
        }
    }

    #[test]
    fn kit_screen_is_never_authorized_for_a_note_bound_or_other_window() {
        assert!(setup_allowed("main", false));
        assert!(!setup_allowed("main", true));
        assert!(!setup_allowed("note-2", false));
        assert!(!setup_allowed("note-2", true));
    }
}
