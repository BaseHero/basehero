use std::cell::{Cell, RefCell};

use block2::RcBlock;
use objc2::{
    MainThreadMarker, msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject, Imp, Sel},
    sel,
};
use objc2_app_kit::{
    NSAlert, NSAlertSecondButtonReturn, NSApplication, NSApplicationTerminateReply,
    NSModalResponse, NSView,
};
use objc2_foundation::{NSString, NSUInteger};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

/// Show a document-modal sheet on `window` for writing that could not be
/// saved. Keep open is the first button, so Return chooses it; `done(true)`
/// only for an explicit Close without saving. Main thread only; false (and
/// no sheet, `done` dropped) if this is not the main thread or no window.
pub fn ask_discard(window: &impl HasWindowHandle, done: impl FnOnce(bool) + 'static) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    let Ok(handle) = window.window_handle() else {
        return false;
    };
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        return false;
    };
    // SAFETY: an AppKit window handle's ns_view is that window's live NSView,
    // borrowed only on the main thread for the duration of this call.
    let view: &NSView = unsafe { handle.ns_view.cast::<NSView>().as_ref() };
    let Some(target) = view.window() else {
        return false;
    };
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("Your latest writing isn’t saved."));
    alert.setInformativeText(&NSString::from_str(
        "Keep this window open to try saving again.",
    ));
    alert.addButtonWithTitle(&NSString::from_str("Keep open"));
    alert.addButtonWithTitle(&NSString::from_str("Close without saving"));
    let done = Cell::new(Some(done));
    let handler = RcBlock::new(move |response: NSModalResponse| {
        if let Some(done) = done.take() {
            done(response == NSAlertSecondButtonReturn);
        }
    });
    alert.beginSheetModalForWindow_completionHandler(&target, Some(&handler));
    true
}

/// Why ordinary Quit could not be routed to the drain. Never worked around
/// by replacing or swizzling a method: the app must not run unguarded.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallError {
    NotMainThread,
    NoDelegate,
    /// The delegate's class already answers applicationShouldTerminate:.
    AlreadyAnswered,
    /// The application's own class already defines terminate:.
    AlreadyTerminates,
    Refused,
    AlreadyInstalled,
}

/// The pending answer to one applicationShouldTerminate:. Reply exactly
/// once on the main thread; until then AppKit waits (NSTerminateLater).
pub struct TerminateReply(());
impl TerminateReply {
    /// `terminate` false cancels this Quit and keeps the app running.
    pub fn reply(self, terminate: bool) -> Result<(), Self> {
        let Some(mtm) = MainThreadMarker::new() else {
            return Err(self);
        };
        PENDING.with(|pending| pending.set(false));
        NSApplication::sharedApplication(mtm).replyToApplicationShouldTerminate(terminate);
        Ok(())
    }
}

type Handler = Box<dyn Fn(TerminateReply)>;
thread_local! {
    static HANDLER: RefCell<Option<Handler>> = const { RefCell::new(None) };
    static PENDING: Cell<bool> = const { Cell::new(false) };
    static SUPERCLASS: Cell<Option<&'static AnyClass>> = const { Cell::new(None) };
}

/// Every ordinary terminate: (menu, Dock, logout, AppleScript) asks the
/// app delegate first. Add that one method to the existing delegate's class
/// (Tao's), keeping the delegate and all its other methods. Refuses if the
/// class already answers it rather than replacing that implementation.
///
/// While that answer is pending, AppKit would let a second terminate: exit
/// at once without asking the delegate, so terminate: is also added to the
/// application's own class (Tao's NSApplication subclass): it ignores the
/// call while a request is pending and otherwise calls the superclass's.
/// That is the class NSApp reports, not its runtime class: AppKit's key-value
/// observing can swap in, and later drop, a subclass of it.
pub fn intercept_terminate(on_quit: impl Fn(TerminateReply) + 'static) -> Result<(), InstallError> {
    let mtm = MainThreadMarker::new().ok_or(InstallError::NotMainThread)?;
    if HANDLER.with(|handler| handler.borrow().is_some()) {
        return Err(InstallError::AlreadyInstalled);
    }
    let app = NSApplication::sharedApplication(mtm);
    // SAFETY: -[NSApplication delegate] returns the current delegate object
    // or nil; the main-thread marker proves the AppKit thread.
    let delegate: Option<Retained<AnyObject>> = unsafe { msg_send![&app, delegate] };
    let delegate = delegate.ok_or(InstallError::NoDelegate)?;
    let class: &AnyClass = delegate.class();
    let selector = sel!(applicationShouldTerminate:);
    if class.responds_to(selector) {
        return Err(InstallError::AlreadyAnswered);
    }
    // SAFETY: -[NSObject class] returns the receiver's registered class.
    let app_class: &'static AnyClass = unsafe { msg_send![&app, class] };
    let superclass = app_class.superclass().ok_or(InstallError::Refused)?;
    SUPERCLASS.with(|slot| slot.set(Some(superclass)));
    // SAFETY: the function matches - (void)terminate:(id)sender with the C
    // ABI objc_msgSend uses, and "v@:@" encodes exactly that signature.
    let terminate_imp: Imp = unsafe {
        std::mem::transmute::<extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject), Imp>(terminate)
    };
    // SAFETY: adds (never replaces: class_addMethod refuses a method the
    // class itself defines) one instance method to a registered class, on
    // the main thread. Until a request is pending it only forwards.
    let added = unsafe {
        objc2::ffi::class_addMethod(
            (app_class as *const AnyClass).cast_mut(),
            sel!(terminate:),
            terminate_imp,
            c"v@:@".as_ptr(),
        )
    };
    if !added.as_bool() {
        return Err(InstallError::AlreadyTerminates);
    }
    // SAFETY: the function matches - (NSApplicationTerminateReply)
    // applicationShouldTerminate:(NSApplication *) with the C ABI objc_msgSend
    // uses, and the type string "Q@:@" encodes exactly that signature.
    let imp: Imp = unsafe {
        std::mem::transmute::<
            extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject) -> NSUInteger,
            Imp,
        >(should_terminate)
    };
    HANDLER.with(|handler| *handler.borrow_mut() = Some(Box::new(on_quit)));
    // SAFETY: adds (never replaces: class_addMethod refuses an existing one)
    // one instance method to a registered class, on the main thread.
    let added = unsafe {
        objc2::ffi::class_addMethod(
            (class as *const AnyClass).cast_mut(),
            selector,
            imp,
            c"Q@:@".as_ptr(),
        )
    };
    if !added.as_bool() {
        HANDLER.with(|handler| handler.borrow_mut().take());
        return Err(InstallError::Refused);
    }
    Ok(())
}

extern "C-unwind" fn terminate(this: &AnyObject, _: Sel, sender: *mut AnyObject) {
    // The pending request decides; its reply ends this Quit or cancels it.
    if PENDING.with(Cell::get) {
        return;
    }
    let Some(superclass) = SUPERCLASS.with(Cell::get) else {
        return;
    };
    // SAFETY: the superclass of the receiver's class implements terminate:
    // (NSApplication does) with this signature; main thread, as AppKit calls.
    unsafe {
        let () = msg_send![super(this, superclass), terminate: sender];
    }
}

extern "C-unwind" fn should_terminate(_: &AnyObject, _: Sel, _: *mut AnyObject) -> NSUInteger {
    // A second request while one is pending is refused, not stacked.
    if PENDING.with(|pending| pending.replace(true)) {
        return NSApplicationTerminateReply::TerminateCancel.0;
    }
    let asked = HANDLER.with(|handler| match handler.borrow().as_ref() {
        Some(on_quit) => {
            on_quit(TerminateReply(()));
            true
        }
        None => false,
    });
    if asked {
        NSApplicationTerminateReply::TerminateLater.0
    } else {
        PENDING.with(|pending| pending.set(false));
        NSApplicationTerminateReply::TerminateNow.0
    }
}
