//! System notifications for verified, locally delivered account alerts.
//! No WebView text reaches this adapter. Foreground delivery needs a delegate
//! (without one Notification Centre suppresses the banner while app is open).
use objc2::{MainThreadOnly, define_class, extern_methods, rc::Retained, runtime::ProtocolObject};
use objc2_foundation::{MainThreadMarker, NSObject, NSObjectProtocol, NSString};
use std::path::Path;

use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotification,
    UNNotificationPresentationOptions, UNNotificationRequest, UNUserNotificationCenter,
    UNUserNotificationCenterDelegate,
};

define_class!(
    // SAFETY: NSObject has no subclassing requirements and this class has no Drop.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    struct AlertDelegate;
    // SAFETY: NSObjectProtocol has no extra requirements.
    unsafe impl NSObjectProtocol for AlertDelegate {}
    // SAFETY: The method signature matches UNUserNotificationCenterDelegate.
    unsafe impl UNUserNotificationCenterDelegate for AlertDelegate {
        #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
        fn will_present(
            &self,
            _center: &UNUserNotificationCenter,
            _notification: &UNNotification,
            completion: &block2::DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
        ) {
            completion
                .call((UNNotificationPresentationOptions::Banner
                    | UNNotificationPresentationOptions::List,));
        }
    }
);

impl AlertDelegate {
    extern_methods!(
        #[unsafe(method(new))]
        fn new(main: MainThreadMarker) -> Retained<Self>;
    );
}

fn has_app_bundle(exe: &Path) -> bool {
    exe.parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .is_some_and(|app| app.file_name().is_some_and(|name| name == "BaseHero.app"))
}

fn notifications_available() -> bool {
    // UserNotifications throws an Objective-C exception from an unbundled CLI
    // binary, such as the direct-launch WebDriver build.
    std::env::current_exe().is_ok_and(|exe| has_app_bundle(&exe))
}

pub(crate) fn enable() {
    if !notifications_available() {
        return;
    }
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let main = MainThreadMarker::new().expect("notification delegate on main thread");
    let delegate = AlertDelegate::new(main);
    center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    // The centre's delegate is weak. Keep it for the app's process lifetime.
    std::mem::forget(delegate);
    let done = block2::RcBlock::new(|_, _| {});
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
        &done,
    );
}

pub(crate) fn send(key: &str, body: &str) {
    if !notifications_available() {
        return;
    }
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str("Security alert"));
    content.setBody(&NSString::from_str(body));
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
        &NSString::from_str(key),
        &content,
        None,
    );
    UNUserNotificationCenter::currentNotificationCenter()
        .addNotificationRequest_withCompletionHandler(&request, None);
}

#[cfg(test)]
mod tests {
    use super::has_app_bundle;
    use std::path::Path;

    #[test]
    fn notification_center_needs_an_app_bundle() {
        assert!(has_app_bundle(Path::new(
            "/Applications/BaseHero.app/Contents/MacOS/bh-client"
        )));
        assert!(!has_app_bundle(Path::new("/tmp/target/debug/bh-client")));
        assert!(!has_app_bundle(Path::new(
            "/Applications/BaseHero.app/Contents/bh-client"
        )));
    }
}
