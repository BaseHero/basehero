use bh_core::test_support::Fault;
use bh_core::{AppRequest, BaseGrantRequest, DeviceKind, Error, Mode};
use bh_testkit::{TEST_PASSWORD, device, new_signup, signin_for};

#[tokio::test]
async fn every_full_device_reads_the_kit_and_app_devices_cannot() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    assert_eq!(pending.account_id(), a.id());
    let mut approval = pending.request_approval().await.unwrap();
    let (opened, digits) =
        tokio::try_join!(a.open_request(approval.id()), approval.digits()).unwrap();
    a.approve(opened, &digits).await.unwrap();
    let b = approval.wait().await.unwrap();
    assert_eq!(b.recovery_kit().unwrap(), Some(kit.clone()));
    let status = b.kit_status().unwrap();
    assert!(status.known && !status.saved && status.made_at.is_some());
    let base = a.create_base("Health").await.unwrap();
    let credentials = a
        .connect_app(AppRequest {
            app_name: "health".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = device("app").install_app(credentials).await.unwrap();
    assert_eq!(app.kind(), DeviceKind::App);
    assert_eq!(app.recovery_kit().unwrap_err(), Error::Forbidden);
    assert_eq!(app.kit_status().unwrap_err(), Error::Forbidden);
    assert_eq!(app.set_kit_saved(&kit).await.unwrap_err(), Error::Forbidden);
}

#[tokio::test]
async fn saved_is_account_wide() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let b = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.set_kit_saved(&kit).await.unwrap();
    a.refresh().await.unwrap();
    assert!(a.kit_status().unwrap().saved);
}

#[tokio::test]
async fn a_new_kit_replaces_it_unsaved() {
    let (a, old) = device("mac").sign_up(new_signup()).await.unwrap();
    a.set_kit_saved(&old).await.unwrap();
    let next = a.new_kit(TEST_PASSWORD).await.unwrap();
    assert_ne!(next, old);
    assert_eq!(a.recovery_kit().unwrap(), Some(next.clone()));
    assert!(!a.kit_status().unwrap().saved);
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    assert_eq!(
        pending.with_kit(&old.display()).await.unwrap_err(),
        Error::BadKit
    );
    assert_eq!(
        pending.with_kit(&next.display()).await.unwrap().id(),
        a.id()
    );
}

#[tokio::test]
async fn signing_in_with_the_kit_records_it_as_saved() {
    // A failed first data write leaves an account with the old, kit-less format.
    let core = device("mac");
    core.inject_fault(Fault {
        method: "PUT",
        path: "v1/account/data",
        lost_reply: false,
        times: 1,
    });
    let (a, kit) = core.sign_up(new_signup()).await.unwrap();
    assert_eq!(a.recovery_kit().unwrap(), None);
    let b = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    assert_eq!(b.recovery_kit().unwrap(), Some(kit));
    assert!(b.kit_status().unwrap().saved);
}

#[tokio::test]
async fn failed_kit_record_after_rotation_does_not_advertise_the_old_kit() {
    let (a, old) = device("mac").sign_up(new_signup()).await.unwrap();
    a.set_kit_saved(&old).await.unwrap();
    // Publish this device's key before faulting the specific kit-data write.
    a.refresh().await.unwrap();
    a.test_inject_fault(Fault {
        method: "PUT",
        path: "v1/account/data",
        lost_reply: false,
        times: 1,
    });
    let next = a.new_kit(TEST_PASSWORD).await.unwrap();
    assert_ne!(next, old);
    assert_eq!(a.recovery_kit().unwrap(), None);
    assert!(!a.kit_status().unwrap().known);
    assert!(!a.kit_status().unwrap().saved);
    a.refresh().await.unwrap();
    assert_eq!(a.recovery_kit().unwrap(), None);
    assert!(!a.kit_status().unwrap().known);
}

#[tokio::test]
async fn old_pending_sign_in_does_not_record_a_kit_after_rotation() {
    let (a, old) = device("mac").sign_up(new_signup()).await.unwrap();
    let pending = device("fold").sign_in(signin_for(&a)).await.unwrap();
    let next = a.new_kit(TEST_PASSWORD).await.unwrap();
    let signed_in = pending.with_kit(&old.display()).await.unwrap();
    assert_eq!(signed_in.recovery_kit().unwrap(), Some(next.clone()));
    assert_eq!(a.refresh().await, Ok(()));
    assert_eq!(a.recovery_kit().unwrap(), Some(next));
    assert!(!a.kit_status().unwrap().saved);
}

#[tokio::test]
async fn acknowledging_the_kit_shown_before_rotation_does_not_mark_the_new_one_saved() {
    let (a, old) = device("mac").sign_up(new_signup()).await.unwrap();
    let next = a.new_kit(TEST_PASSWORD).await.unwrap();
    assert_ne!(next, old);
    assert_eq!(
        a.set_kit_saved(&old).await,
        Err(Error::Conflict("kit_changed".into()))
    );
    assert!(!a.kit_status().unwrap().saved);
}

#[tokio::test]
async fn the_kit_never_shows_in_debug_or_errors() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let text = kit.display();
    assert!(!format!("{:?}", a.kit_status().unwrap()).contains(&text));
    assert!(!format!("{:?}", a.recovery_kit().unwrap()).contains(&text));
    let error = a.new_kit("incorrect password").await.unwrap_err();
    assert!(!format!("{error:?}").contains(&text));
}
