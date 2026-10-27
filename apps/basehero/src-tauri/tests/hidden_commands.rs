mod common;

use basehero_app_lib::commands::{base, hidden};
use basehero_app_lib::views::{AppEvent, BaseRef};
use bh_core::{AccountEvent, AccountId, SignIn, SignUp};
use bh_testkit::{LocalServer, TEST_PASSWORD, insert_text, invite, note};
use std::time::Duration;
use zeroize::Zeroizing;

const PASSWORD: &str = "ferry lantern quartz";

async fn setup() -> (
    LocalServer,
    basehero_app_lib::state::AppState,
    common::Events,
    AccountId,
    String,
) {
    let server = LocalServer::start();
    let (state, events) = common::state_at(server.url());
    let (account, kit) = state
        .core
        .sign_up(SignUp {
            server: server.url(),
            invite: invite(&server),
            email: format!("{}@example.test", AccountId::random()),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    state.listen(account.id()).unwrap();
    (server, state, events, account.id(), kit.display())
}

#[tokio::test]
async fn unlock_and_lock_through_the_shell() {
    let (_server, state, events, account, _kit) = setup().await;
    let created = hidden::create_hidden_base(
        &state,
        account,
        "Zebra Diary",
        Zeroizing::new(PASSWORD.to_owned()),
    )
    .await
    .unwrap();
    assert!(created.hidden);
    assert!(
        base::bases(&state, account)
            .unwrap()
            .iter()
            .any(|item| item.id == created.id && item.hidden)
    );
    hidden::lock_hidden(&state, account, created.id)
        .await
        .unwrap();
    events.wait_for(|event| matches!(event, AppEvent::Account { account: id, event: AccountEvent::BasesChanged } if *id == account));
    assert!(
        base::bases(&state, account)
            .unwrap()
            .iter()
            .all(|item| item.id != created.id)
    );
    let error = hidden::unlock_hidden(&state, account, Zeroizing::new("wrong secret".into()))
        .await
        .unwrap_err();
    assert_eq!(error.kind, "NothingUnlocked");
    assert!(!error.message.contains("wrong secret"));
    assert_eq!(
        hidden::unlock_hidden(&state, account, Zeroizing::new(PASSWORD.to_owned()))
            .await
            .unwrap()[0]
            .id,
        created.id
    );
}

#[tokio::test]
async fn locking_closes_every_session_on_that_base_in_every_window() {
    let (_server, state, _events, account, _kit) = setup().await;
    let personal = base::create_base(&state, account, "Personal")
        .await
        .unwrap();
    let hidden_base = hidden::create_hidden_base(
        &state,
        account,
        "Zebra Diary",
        Zeroizing::new(PASSWORD.to_owned()),
    )
    .await
    .unwrap();
    let h = state
        .base(&BaseRef {
            account,
            base: hidden_base.id,
        })
        .unwrap();
    let p = state
        .base(&BaseRef {
            account,
            base: personal.id,
        })
        .unwrap();
    let hidden_note = h.create(note()).unwrap();
    let personal_note = p.create(note()).unwrap();
    let first = state
        .notes
        .open("w-1", account, &h, hidden_note, Box::new(|_| {}))
        .unwrap();
    let second = state
        .notes
        .open("w-2", account, &h, hidden_note, Box::new(|_| {}))
        .unwrap();
    let ordinary = state
        .notes
        .open("w-2", account, &p, personal_note, Box::new(|_| {}))
        .unwrap();
    hidden::lock_hidden(&state, account, hidden_base.id)
        .await
        .unwrap();
    assert_eq!(
        state.notes.apply(first.session, &[]).unwrap_err().kind,
        "NotFound"
    );
    assert_eq!(
        state.notes.apply(second.session, &[]).unwrap_err().kind,
        "NotFound"
    );
    assert!(
        state
            .notes
            .apply(ordinary.session, &insert_text("kept"))
            .is_ok()
    );
}

#[tokio::test]
async fn no_events_come_from_a_locked_base() {
    let (server, state, _events, account, kit) = setup().await;
    let owner = state.core.account(account).unwrap();
    let (other, events) = common::state_at(server.url());
    let b = other
        .core
        .sign_in(SignIn {
            server: server.url(),
            email: owner.email(),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "fold".into(),
        })
        .await
        .unwrap()
        .with_kit(&kit)
        .await
        .unwrap();
    let personal = base::create_base(&state, account, "Personal")
        .await
        .unwrap();
    let hidden_base = hidden::create_hidden_base(
        &state,
        account,
        "Zebra Diary",
        Zeroizing::new(PASSWORD.to_owned()),
    )
    .await
    .unwrap();
    owner.base(personal.id).unwrap().flush().await.unwrap();
    owner.base(hidden_base.id).unwrap().flush().await.unwrap();
    b.refresh().await.unwrap();
    hidden::unlock_hidden(&other, account, Zeroizing::new(PASSWORD.to_owned()))
        .await
        .unwrap();
    other
        .base(&BaseRef {
            account,
            base: hidden_base.id,
        })
        .unwrap();
    other
        .base(&BaseRef {
            account,
            base: personal.id,
        })
        .unwrap();
    hidden::lock_hidden(&other, account, hidden_base.id)
        .await
        .unwrap();
    // A personal edit still crosses the shell boundary; a locked hidden edit cannot.
    let before = events
        .count(|event| matches!(event, AppEvent::Base { base, .. } if *base == hidden_base.id));
    let personal_before =
        events.count(|event| matches!(event, AppEvent::Base { base, .. } if *base == personal.id));
    owner.base(hidden_base.id).unwrap().create(note()).unwrap();
    owner.base(personal.id).unwrap().create(note()).unwrap();
    owner.base(personal.id).unwrap().flush().await.unwrap();
    events.wait_for_count(
        personal_before + 1,
        |event| matches!(event, AppEvent::Base { base, .. } if *base == personal.id),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        events
            .count(|event| matches!(event, AppEvent::Base { base, .. } if *base == hidden_base.id)),
        before
    );
}

#[tokio::test]
async fn a_resume_refresh_lets_a_new_hidden_base_unlock() {
    let (server, state, _events, account, kit) = setup().await;
    let owner = state.core.account(account).unwrap();
    let (other, _other_events) = common::state_at(server.url());
    other
        .core
        .sign_in(SignIn {
            server: server.url(),
            email: owner.email(),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "fold".into(),
        })
        .await
        .unwrap()
        .with_kit(&kit)
        .await
        .unwrap();
    let hidden_base = hidden::create_hidden_base(
        &state,
        account,
        "Zebra Diary",
        Zeroizing::new(PASSWORD.to_owned()),
    )
    .await
    .unwrap();
    hidden::refresh_account(&other, account).await.unwrap();
    assert_eq!(
        hidden::unlock_hidden(&other, account, Zeroizing::new(PASSWORD.to_owned()))
            .await
            .unwrap()[0]
            .id,
        hidden_base.id
    );
}

#[tokio::test]
async fn a_quit_with_an_unlocked_base_relaunches_locked_and_keeps_edits() {
    let (server, state, events, account, _kit) = setup().await;
    let owner = state.core.account(account).unwrap();
    let hidden_base = hidden::create_hidden_base(
        &state,
        account,
        "Zebra Diary",
        Zeroizing::new(PASSWORD.to_owned()),
    )
    .await
    .unwrap();
    let h = state
        .base(&BaseRef {
            account,
            base: hidden_base.id,
        })
        .unwrap();
    let id = h.create(note()).unwrap();
    let opened = state
        .notes
        .open("w-1", account, &h, id, Box::new(|_| {}))
        .unwrap();
    state
        .notes
        .apply(opened.session, &insert_text("kept after quit"))
        .unwrap();
    hidden::lock_all_hidden(&state).await;
    assert!(owner.bases().iter().all(|base| base.id != hidden_base.id));
    assert_eq!(
        state
            .notes
            .apply(opened.session, &insert_text("lost"))
            .unwrap_err()
            .kind,
        "NotFound"
    );
    drop((owner, h, state));
    let reopened = common::open_at(events.data_dir(), server.url(), &events);
    assert!(
        reopened
            .core
            .account(account)
            .unwrap()
            .bases()
            .iter()
            .all(|base| base.id != hidden_base.id)
    );
    hidden::unlock_hidden(&reopened, account, Zeroizing::new(PASSWORD.to_owned()))
        .await
        .unwrap();
    assert_eq!(
        reopened
            .core
            .account(account)
            .unwrap()
            .base(hidden_base.id)
            .unwrap()
            .note(id)
            .unwrap()
            .text(),
        "kept after quit"
    );
}

#[tokio::test]
async fn one_accounts_pending_flush_does_not_delay_another_accounts_lock() {
    let (server, state, _events, first, _kit) = setup().await;
    let (second, _) = state
        .core
        .sign_up(SignUp {
            server: server.url(),
            invite: invite(&server),
            email: "zzzzzz@example.test".into(),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    state.listen(second.id()).unwrap();
    let first_base =
        hidden::create_hidden_base(&state, first, "Slow", Zeroizing::new(PASSWORD.into()))
            .await
            .unwrap();
    let other_base =
        hidden::create_hidden_base(&state, second.id(), "Fast", Zeroizing::new(PASSWORD.into()))
            .await
            .unwrap();
    let slow = state
        .base(&BaseRef {
            account: first,
            base: first_base.id,
        })
        .unwrap();
    slow.test_pause_sync();
    slow.create(note()).unwrap();
    // The first account is already hidden while its two-second flush is pending.
    let locking = hidden::lock_all_hidden(&state);
    tokio::pin!(locking);
    tokio::select! {
        _ = &mut locking => panic!("the pending flush finished unexpectedly"),
        _ = async {
            loop {
                if base::bases(&state, first).unwrap().iter().all(|b| b.id != first_base.id) { break; }
                tokio::task::yield_now().await;
            }
        } => {}
    }
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if base::bases(&state, second.id())
                .unwrap()
                .iter()
                .all(|b| b.id != other_base.id)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("another account must lock while the first flush is pending");
    locking.await;
}

#[test]
fn the_mac_locks_when_its_last_window_closes() {
    assert!(basehero_app_lib::windows::should_lock_hidden(0));
    assert!(!basehero_app_lib::windows::should_lock_hidden(1));
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "distributed notifications are not delivered in the venus SSH session; check on Dan's logged-in Mac"]
fn the_mac_locks_when_the_screen_locks() {
    use std::{
        ffi::c_void,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const std::ffi::c_char) -> *mut c_void;
        fn sel_registerName(name: *const std::ffi::c_char) -> *mut c_void;
        fn objc_msgSend();
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopDefaultMode: *const c_void;
        fn CFRunLoopRunInMode(
            mode: *const c_void,
            seconds: f64,
            return_after_source_handled: u8,
        ) -> i32;
    }

    // Removing the production observer or registering it for the wrong name
    // must leave this flag false, even though the notification is posted.
    let fired = Arc::new(AtomicBool::new(false));
    let callback_flag = fired.clone();
    assert!(basehero_app_lib::windows::register_screen_lock(move || {
        callback_flag.store(true, Ordering::SeqCst);
    }));
    unsafe {
        let selector = sel_registerName(c"defaultCenter".as_ptr());
        let get_center: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const c_void);
        let center = get_center(
            objc_getClass(c"NSDistributedNotificationCenter".as_ptr()),
            selector,
        );
        assert!(!center.is_null());
        let get_string: extern "C" fn(
            *mut c_void,
            *mut c_void,
            *const std::ffi::c_char,
        ) -> *mut c_void = std::mem::transmute(objc_msgSend as *const c_void);
        let name = get_string(
            objc_getClass(c"NSString".as_ptr()),
            sel_registerName(c"stringWithUTF8String:".as_ptr()),
            c"com.apple.screenIsLocked".as_ptr(),
        );
        let post: extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            i8,
        ) = std::mem::transmute(objc_msgSend as *const c_void);
        post(
            center,
            sel_registerName(c"postNotificationName:object:userInfo:deliverImmediately:".as_ptr()),
            name,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            1,
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fired.load(Ordering::SeqCst) && Instant::now() < deadline {
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, 1);
        }
    }
    assert!(
        fired.load(Ordering::SeqCst),
        "screen-lock distributed notification was not delivered to the registering thread"
    );
}

#[tokio::test]
async fn locking_a_hidden_base_erases_its_open_file_copy() {
    use basehero_app_lib::commands::files;
    use bh_core::NewFile;
    let (_server, state, _events, account, _kit) = setup().await;
    let personal = base::create_base(&state, account, "Personal")
        .await
        .unwrap();
    let hidden_base = hidden::create_hidden_base(
        &state,
        account,
        "Zebra Diary",
        Zeroizing::new(PASSWORD.into()),
    )
    .await
    .unwrap();
    let h = BaseRef {
        account,
        base: hidden_base.id,
    };
    let p = BaseRef {
        account,
        base: personal.id,
    };
    let add = |r: &BaseRef| {
        state
            .base(r)
            .unwrap()
            .add_file(
                NewFile {
                    parent: None,
                    name: "Zebra Diary".into(),
                    mime: "text/plain".into(),
                },
                b"a secret",
            )
            .unwrap()
    };
    let hidden_id = add(&h);
    let personal_id = add(&p);
    let hidden_path = files::open_copy(&state, &h, hidden_id).await.unwrap();
    let personal_path = files::open_copy(&state, &p, personal_id).await.unwrap();
    assert!(hidden_path.exists() && personal_path.exists());
    hidden::lock_hidden(&state, account, hidden_base.id)
        .await
        .unwrap();
    assert!(
        !state
            .cache_dir
            .join("open")
            .join(hidden_base.id.to_string())
            .exists()
    );
    assert!(personal_path.exists());
    hidden::unlock_hidden(&state, account, Zeroizing::new(PASSWORD.into()))
        .await
        .unwrap();
    assert!(
        files::open_copy(&state, &h, hidden_id)
            .await
            .unwrap()
            .exists()
    );
}
