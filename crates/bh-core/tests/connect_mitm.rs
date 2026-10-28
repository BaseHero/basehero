use bh_core::{AccountEvent, Clock, EndReason, Error};
use bh_testkit::{ApprovalMitm, LocalServer, app_identity, device_with_clock, new_signup};
use std::time::Duration;

#[tokio::test]
async fn a_relay_that_swaps_keys_gets_different_digits_and_no_credentials() {
    bh_testkit::local_only!();
    tokio::time::timeout(Duration::from_secs(30), async {
        let mitm = ApprovalMitm::start(LocalServer::from_env().url());
        let (clock, _manual) = Clock::manual();
        let mut signup = new_signup();
        signup.server = mitm.url();
        let (full, _) = device_with_clock("mac", &clock)
            .sign_up(signup)
            .await
            .unwrap();
        let before = full.devices().await.unwrap();
        let mut events = full.events();
        let app = device_with_clock("phone", &clock);
        let mut pending = app
            .start_connection(mitm.url(), &full.email(), app_identity())
            .await
            .unwrap();
        let id = loop {
            if let AccountEvent::ApprovalRequested(request) = events.recv().await.unwrap() {
                break request.id;
            }
        };
        assert_eq!(id, pending.id());
        let (mut open, digits) =
            tokio::try_join!(full.open_app_request(id), pending.digits()).unwrap();
        assert_eq!(mitm.digits_for_new(), Some(digits.clone()));
        assert_ne!(mitm.digits_for_approver(), Some(digits.clone()));
        assert!(
            mitm.opened_a_hello(),
            "the relay should open the app's sealed claim"
        );
        assert_eq!(
            open.check_digits(&digits).await.unwrap_err(),
            Error::ApprovalEnded(EndReason::WrongDigits)
        ); // No offer or app name was shown to the approver.
        assert_eq!(
            pending.wait().await.unwrap_err(),
            Error::ApprovalEnded(EndReason::WrongDigits)
        );
        assert_eq!(full.devices().await.unwrap().len(), before.len());
        assert!(!mitm.opened_a_transfer());
        assert_eq!(
            bh_testkit::request_count(&full, &format!("v1/approvals/{id}/transfer")),
            0
        );
    })
    .await
    .expect("app exchange exceeded 30 s");
}
