//! Isolated process for the global Argon2 counter: the hidden integration
//! tests run in parallel, so comparing that counter there is racy.
use bh_core::Error;
use bh_testkit::{device, new_signup};
use zeroize::Zeroizing;

// Both tests observe one process-wide counter; never measure them concurrently.
static COUNTER_TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn unlocking_still_costs_one_argon2_after_rotation() {
    let _gate = COUNTER_TEST_GATE.lock().await;
    let (a, b) = bh_testkit::two_devices().await;
    let base = a
        .create_hidden_base("Diary", Zeroizing::new("extra password".into()))
        .await
        .unwrap();
    a.lock_hidden(base.id()).await.unwrap();
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: Zeroizing::new(bh_testkit::TEST_PASSWORD.into()),
            lost: false,
        },
    )
    .await
    .unwrap();
    let before = bh_core::test_support::argon2_calls();
    assert_eq!(
        a.unlock_hidden(Zeroizing::new("extra password".into()))
            .await
            .unwrap()[0]
            .id,
        base.id()
    );
    assert_eq!(bh_core::test_support::argon2_calls(), before + 1);
}

#[tokio::test]
async fn one_argon2_runs_per_unlock_even_when_no_hidden_bases_exist() {
    let _gate = COUNTER_TEST_GATE.lock().await;
    let (a, _) = device("a").sign_up(new_signup()).await.unwrap();
    let password = || Zeroizing::new("ferry lantern quartx".to_string());
    let before = bh_core::test_support::argon2_calls();
    assert!(matches!(
        a.unlock_hidden(password()).await,
        Err(Error::NothingUnlocked)
    ));
    assert_eq!(bh_core::test_support::argon2_calls(), before + 1);
    let h = a
        .create_hidden_base("Zebra", Zeroizing::new("ferry lantern quartz".to_string()))
        .await
        .unwrap();
    a.lock_hidden(h.id()).await.unwrap();
    let before = bh_core::test_support::argon2_calls();
    assert!(matches!(
        a.unlock_hidden(password()).await,
        Err(Error::NothingUnlocked)
    ));
    assert_eq!(bh_core::test_support::argon2_calls(), before + 1);
}
