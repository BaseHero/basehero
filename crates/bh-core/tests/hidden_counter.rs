//! Isolated process for the global Argon2 counter: the hidden integration
//! tests run in parallel, so comparing that counter there is racy.
use bh_core::Error;
use bh_testkit::{device, new_signup};
use zeroize::Zeroizing;

#[tokio::test]
async fn one_argon2_runs_per_unlock_even_when_no_hidden_bases_exist() {
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
