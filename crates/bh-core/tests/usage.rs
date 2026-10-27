use bh_core::{BaseId, Error};
use bh_testkit::{device, new_signup};

#[tokio::test]
async fn usage_names_bases_and_devices_from_the_devices_own_lists() {
    let (account, _) = device("Named desktop").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Research").await.unwrap();
    let result = account.usage(None).await.unwrap();
    assert_eq!(
        result.base_names.get(&base.id()).map(String::as_str),
        Some("Research")
    );
    assert_eq!(
        result
            .device_names
            .get(&account.device_id())
            .map(String::as_str),
        Some("Named desktop")
    );
    assert!(result.days.is_empty());
}

#[tokio::test]
async fn model_for_refuses_a_base_this_device_cannot_open() {
    let (account, _) = device("Desktop").sign_up(new_signup()).await.unwrap();
    assert!(matches!(
        account.model_for(BaseId::random()),
        Err(Error::Forbidden)
    ));
    let base = account.create_base("Allowed").await.unwrap();
    assert!(account.model_for(base.id()).is_ok());
}

#[tokio::test]
async fn invalid_month_is_refused_before_a_network_call() {
    let (account, _) = device("Desktop").sign_up(new_signup()).await.unwrap();
    assert!(matches!(
        account.usage(Some("2026-13")).await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(account.test_request_count("v1/usage"), 0);
}
