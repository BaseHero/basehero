use bh_core::{AccountEvent, EndReason, Error};
use bh_testkit::{ApprovalMitm, LocalServer, device, new_signup, signin_for};
use std::time::Duration;

#[tokio::test]
async fn a_relay_that_swaps_keys_gets_different_digits_and_no_account_key() {
    bh_testkit::local_only!();
    let mitm = ApprovalMitm::start(LocalServer::from_env().url());
    let mut signup = new_signup();
    signup.server = mitm.url();
    let (a, _) = device("mac").sign_up(signup).await.unwrap();
    // The approving device hears the request through the relay, not by its ID.
    let mut events = a.events();
    let mut signin = signin_for(&a);
    signin.server = mitm.url();
    let mut n = device("fold")
        .sign_in(signin)
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let id = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let AccountEvent::ApprovalRequested(request) = events.recv().await.unwrap() {
                break request.id;
            }
        }
    })
    .await
    .expect("the approving device never heard the request");
    assert_eq!(id, n.id());
    let (open, digits) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::try_join!(a.open_request(id), n.digits())
    })
    .await
    .expect("exchange stalled before the digits")
    .expect("opening the relayed request failed");
    assert_eq!(mitm.digits_for_new(), Some(digits.clone()));
    let approver = mitm
        .digits_for_approver()
        .expect("the relay computed the approver's digits");
    assert_ne!(approver, digits);
    assert_eq!(
        a.approve(open, &digits).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::WrongDigits)
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(30), n.wait())
            .await
            .expect("new device did not learn the end"),
        Err(Error::ApprovalEnded(EndReason::WrongDigits))
    ));
    assert!(!mitm.opened_a_transfer());
    assert_eq!(
        bh_testkit::request_count(&a, &format!("v1/approvals/{id}/transfer")),
        0,
        "the approving device must not post a transfer"
    );
}
