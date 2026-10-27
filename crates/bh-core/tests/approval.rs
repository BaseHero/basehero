use bh_core::{AccountEvent, ApprovalId, Clock, DeviceId, DeviceKind, Digits, EndReason, Error};
use bh_testkit::{
    device, device_with_clock, new_signup, pending_device_for, request_count, signin_for,
};
use serde_json::json;
use std::{future::Future, time::Duration};

const WAIT: Duration = Duration::from_secs(30);

#[track_caller]
fn wait<T>(future: impl Future<Output = T>) -> impl Future<Output = T> {
    let caller = std::panic::Location::caller();
    async move {
        tokio::time::timeout(WAIT, future)
            .await
            .unwrap_or_else(|_| panic!("approval wait exceeded 30 s at {caller}"))
    }
}

async fn create_request(a: &bh_core::Account) -> (bh_testkit::RawDevice, ApprovalId, DeviceId) {
    let pending = pending_device_for(a).await;
    let id = ApprovalId::random();
    let new_id: DeviceId = pending.device_id.parse().unwrap();
    let (status, body) = pending
        .post("/v1/approvals", json!({"approvalId": id, "request": "AQ"}))
        .await;
    assert!(status.is_success(), "{body}");
    (pending, id, new_id)
}

// Catches a missing response/reveal/transfer/activation across real core devices.
async fn exchange(
    a: &bh_core::Account,
    n: &mut bh_core::Approval,
) -> (bh_core::OpenRequest, Digits) {
    let id = n.id();
    wait(async { tokio::try_join!(a.open_request(id), n.digits()) })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_new_device_is_approved_with_typed_digits() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    // Before approval only the device ID is available; the name arrives in account data after activation.
    let id = open.device_id();
    assert_eq!(a.approve(open, &digits).await.unwrap(), id);
    let b = wait(n.wait()).await.unwrap();
    assert_eq!(b.id(), a.id());
    assert_eq!(b.kind(), DeviceKind::Full);
    assert!(
        a.devices()
            .await
            .unwrap()
            .iter()
            .any(|d| d.id == id && d.name == "fold" && d.status == "active")
    );
    let base = b.create_base("From fold").await.unwrap();
    base.flush().await.unwrap();
    a.refresh().await.unwrap();
    let other = a.base(base.id()).expect("open base");
    bh_testkit::wait_for_base(&other, || other.name() == "From fold").await;
}

#[tokio::test]
async fn failed_activation_leaves_no_account_and_a_fresh_approval_works() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    let secrets =
        std::sync::Arc::new(bh_core::FileSecretStore::new(temp.path().join("secrets")).unwrap());
    let core = bh_core::Core::open(bh_core::CoreConfig {
        data_dir: data_dir.clone(),
        secrets: secrets.clone(),
    })
    .unwrap();
    let mut signin = signin_for(&a);
    signin.device_name = "fold".into();
    let mut n = core
        .sign_in(signin)
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    a.approve(open, &digits).await.unwrap();
    core.inject_fault(bh_core::test_support::Fault {
        method: "POST",
        path: "v1/devices/activate",
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(wait(n.wait()).await, Err(Error::Network(_))));
    assert!(core.accounts().is_empty());
    let id = a.id();
    for suffix in ["key", "token", "dbkey"] {
        assert!(
            bh_core::SecretStore::get(&*secrets, &format!("acct.{id}.{suffix}"))
                .unwrap()
                .is_none()
        );
    }
    assert!(!data_dir.join("accounts").join(id.to_string()).exists());
    let mut signin = signin_for(&a);
    signin.device_name = "fold".into();
    let mut fresh = core
        .sign_in(signin)
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut fresh).await;
    a.approve(open, &digits).await.unwrap();
    assert_eq!(wait(fresh.wait()).await.unwrap().id(), id);
}

#[tokio::test]
async fn failed_local_install_after_activation_cleans_up_everything() {
    use bh_core::{Core, CoreConfig, FileSecretStore, SecretStore};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use zeroize::Zeroizing;

    struct FailTokenOnce {
        inner: FileSecretStore,
        fail: AtomicBool,
    }
    impl SecretStore for FailTokenOnce {
        fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
            self.inner.get(name)
        }
        fn put(&self, name: &str, value: &[u8]) -> Result<(), Error> {
            if name.ends_with(".token") && self.fail.swap(false, Ordering::SeqCst) {
                return Err(Error::Storage("injected write failure".into()));
            }
            self.inner.put(name, value)
        }
        fn delete(&self, name: &str) -> Result<(), Error> {
            self.inner.delete(name)
        }
    }
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let secrets = Arc::new(FailTokenOnce {
        inner: FileSecretStore::new(temp.path().join("secrets")).unwrap(),
        fail: AtomicBool::new(true),
    });
    let data_dir = temp.path().join("data");
    let core = Core::open(CoreConfig {
        data_dir: data_dir.clone(),
        secrets: secrets.clone(),
    })
    .unwrap();
    let mut signin = signin_for(&a);
    signin.device_name = "fold".into();
    let mut n = core
        .sign_in(signin)
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    a.approve(open, &digits).await.unwrap();
    assert!(matches!(wait(n.wait()).await, Err(Error::Storage(_))));
    assert!(core.accounts().is_empty());
    let id = a.id();
    for suffix in ["key", "token", "dbkey"] {
        assert!(
            secrets
                .get(&format!("acct.{id}.{suffix}"))
                .unwrap()
                .is_none()
        );
    }
    assert!(!data_dir.join("accounts").join(id.to_string()).exists());
}

#[tokio::test]
async fn failed_name_write_after_activation_removes_the_account_store() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    let secrets =
        std::sync::Arc::new(bh_core::FileSecretStore::new(temp.path().join("secrets")).unwrap());
    let core = bh_core::Core::open(bh_core::CoreConfig {
        data_dir: data_dir.clone(),
        secrets: secrets.clone(),
    })
    .unwrap();
    let mut signin = signin_for(&a);
    signin.device_name = "fold".into();
    let mut n = core
        .sign_in(signin)
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    a.approve(open, &digits).await.unwrap();
    core.inject_fault(bh_core::test_support::Fault {
        method: "GET",
        path: "v1/account",
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(wait(n.wait()).await, Err(Error::Network(_))));
    assert!(core.accounts().is_empty());
    let id = a.id();
    for suffix in ["key", "token", "dbkey"] {
        assert!(
            bh_core::SecretStore::get(&*secrets, &format!("acct.{id}.{suffix}"))
                .unwrap()
                .is_none()
        );
    }
    assert!(!data_dir.join("accounts").join(id.to_string()).exists());
}

#[tokio::test]
async fn failed_second_install_preserves_the_first_device() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    let secrets =
        std::sync::Arc::new(bh_core::FileSecretStore::new(temp.path().join("secrets")).unwrap());
    let core = bh_core::Core::open(bh_core::CoreConfig {
        data_dir: data_dir.clone(),
        secrets: secrets.clone(),
    })
    .unwrap();
    let mut first_signin = signin_for(&a);
    first_signin.device_name = "first".into();
    let first = core.sign_in(first_signin).await.unwrap();
    let mut second_signin = signin_for(&a);
    second_signin.device_name = "second".into();
    let second = core.sign_in(second_signin).await.unwrap();
    let mut first = first.request_approval().await.unwrap();
    let mut second = second.request_approval().await.unwrap();
    let (open, digits) = exchange(&a, &mut first).await;
    a.approve(open, &digits).await.unwrap();
    let installed = wait(first.wait()).await.unwrap();
    let first_id = installed.device_id();
    let (open, digits) = exchange(&a, &mut second).await;
    assert_ne!(open.device_id(), first_id);
    a.approve(open, &digits).await.unwrap();
    core.inject_fault(bh_core::test_support::Fault {
        method: "GET",
        path: "v1/account",
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(wait(second.wait()).await, Err(Error::Network(_))));
    assert_eq!(core.account(a.id()).unwrap().device_id(), first_id);
    assert!(data_dir.join("accounts").join(a.id().to_string()).exists());
    for suffix in ["key", "token", "dbkey"] {
        assert!(
            bh_core::SecretStore::get(&*secrets, &format!("acct.{}.{suffix}", a.id()))
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        core.account(a.id())
            .unwrap()
            .devices()
            .await
            .unwrap()
            .iter()
            .find(|d| d.this_device)
            .unwrap()
            .id,
        first_id
    );
}

#[tokio::test]
async fn concurrent_installs_of_one_account_preserve_the_winner() {
    use bh_core::{Core, CoreConfig, FileSecretStore, SecretStore};
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use zeroize::Zeroizing;

    struct PausedFirstKeyWrite {
        inner: FileSecretStore,
        first: AtomicBool,
        entered: std::sync::mpsc::Sender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl SecretStore for PausedFirstKeyWrite {
        fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
            self.inner.get(name)
        }
        fn put(&self, name: &str, value: &[u8]) -> Result<(), Error> {
            if name.ends_with(".key") && self.first.swap(false, Ordering::SeqCst) {
                self.entered.send(()).unwrap();
                let (lock, ready) = &*self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = ready.wait(released).unwrap();
                }
            }
            self.inner.put(name, value)
        }
        fn delete(&self, name: &str) -> Result<(), Error> {
            self.inner.delete(name)
        }
    }

    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let (entered, first_write) = std::sync::mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let secrets = Arc::new(PausedFirstKeyWrite {
        inner: FileSecretStore::new(temp.path().join("secrets")).unwrap(),
        first: AtomicBool::new(true),
        entered,
        release: release.clone(),
    });
    let core = Core::open(CoreConfig {
        data_dir: temp.path().join("data"),
        secrets: secrets.clone(),
    })
    .unwrap();
    let mut signin = signin_for(&a);
    signin.device_name = "first".into();
    let mut first = core
        .sign_in(signin)
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let mut signin = signin_for(&a);
    signin.device_name = "second".into();
    let mut second = core
        .sign_in(signin)
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut first).await;
    let first_id = open.device_id();
    a.approve(open, &digits).await.unwrap();
    let (open, digits) = exchange(&a, &mut second).await;
    a.approve(open, &digits).await.unwrap();

    let first_install = tokio::spawn(async move { wait(first.wait()).await });
    tokio::task::spawn_blocking(move || first_write.recv_timeout(WAIT).unwrap())
        .await
        .unwrap();
    // The first installation has passed the account check but has not written a
    // secret. Without an install lock the other attempt also passes that check.
    let second_install = tokio::spawn(async move { wait(second.wait()).await });
    let premature = tokio::time::timeout(Duration::from_secs(2), async {
        while !second_install.is_finished() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok();
    let (lock, ready) = &*release;
    *lock.lock().unwrap() = true;
    ready.notify_all();

    let installed = wait(first_install).await.unwrap().unwrap();
    let refused = wait(second_install).await.unwrap();
    assert!(
        !premature,
        "second install passed the first install's check"
    );
    assert!(matches!(refused, Err(Error::Invalid(_))));
    assert_eq!(installed.device_id(), first_id);
    assert_eq!(core.accounts().len(), 1);
    assert_eq!(core.account(a.id()).unwrap().device_id(), first_id);
    for suffix in ["key", "token", "dbkey"] {
        assert!(
            secrets
                .get(&format!("acct.{}.{suffix}", a.id()))
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        core.account(a.id())
            .unwrap()
            .devices()
            .await
            .unwrap()
            .iter()
            .find(|d| d.this_device)
            .unwrap()
            .id,
        first_id
    );
}

#[tokio::test]
async fn failed_cancel_erases_local_exchange_and_returns_error() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let core = device("fold");
    let mut n = core
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let path: &'static str = Box::leak(format!("v1/approvals/{}", n.id()).into_boxed_str());
    core.inject_fault(bh_core::test_support::Fault {
        method: "DELETE",
        path,
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(n.cancel().await, Err(Error::Network(_))));
    assert!(matches!(
        wait(n.digits()).await,
        Err(Error::ApprovalEnded(EndReason::Cancelled))
    ));
    assert!(matches!(wait(n.wait()).await, Err(Error::Invalid(_))));
}

#[tokio::test]
async fn the_relay_never_stores_the_account_key_in_readable_form() {
    bh_testkit::local_only!();
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    a.approve(open, &digits).await.unwrap();
    wait(n.wait()).await.unwrap();
    let key = a
        .test_secrets()
        .get(&format!("acct.{}.key", a.id()))
        .unwrap()
        .unwrap();
    let mut stack = vec![
        bh_testkit::LocalServer::from_env()
            .persist_dir()
            .to_path_buf(),
    ];
    let mut files = 0;
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            stack.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
        } else if let Ok(bytes) = std::fs::read(&path) {
            files += 1;
            assert!(
                !bytes.windows(key.len()).any(|w| w == key.as_slice()),
                "{} holds the account key",
                path.display()
            );
        }
    }
    assert!(files > 0);
}

#[tokio::test]
async fn wrong_digits_end_it_on_both_devices() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    let wrong = Digits::parse(if digits.as_str() == "000000" {
        "000001"
    } else {
        "000000"
    })
    .unwrap();
    assert_eq!(
        a.approve(open, &wrong).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::WrongDigits)
    );
    assert!(matches!(
        wait(n.wait()).await,
        Err(Error::ApprovalEnded(EndReason::WrongDigits))
    ));
    assert!(matches!(
        a.open_request(n.id()).await,
        Err(Error::ApprovalEnded(EndReason::AlreadyAnswered))
    ));
    let old = n.id();
    n.retry().await.unwrap();
    assert_ne!(old, n.id());
    let (open, digits) = exchange(&a, &mut n).await;
    a.approve(open, &digits).await.unwrap();
    wait(n.wait()).await.unwrap();
}

#[tokio::test]
async fn the_exchange_times_out_after_two_minutes_on_each_device() {
    let (clock, manual) = Clock::manual();
    let (a, _) = device_with_clock("mac", &clock)
        .sign_up(new_signup())
        .await
        .unwrap();
    let mut n = device_with_clock("fold", &clock)
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    let before = request_count(&a, &format!("v1/approvals/{}/transfer", n.id()));
    manual.advance(Duration::from_secs(120));
    assert_eq!(
        a.approve(open, &digits).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Expired)
    );
    assert_eq!(
        request_count(&a, &format!("v1/approvals/{}/transfer", n.id())),
        before
    );
    assert!(matches!(
        n.wait().await,
        Err(Error::ApprovalEnded(EndReason::Expired))
    ));
    n.retry().await.unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    manual.advance(Duration::from_secs(119));
    a.approve(open, &digits).await.unwrap();
    n.wait().await.unwrap();
}

#[tokio::test]
async fn two_full_devices_cannot_both_answer() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let b = device("tablet")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let id = n.id();
    let (first, second, digits) =
        wait(async { tokio::join!(a.open_request(id), b.open_request(id), n.digits()) }).await;
    assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
    let winner = if let Ok(open) = first {
        assert!(matches!(
            second,
            Err(Error::ApprovalEnded(EndReason::AlreadyAnswered))
        ));
        (&a, open)
    } else {
        assert!(matches!(
            first,
            Err(Error::ApprovalEnded(EndReason::AlreadyAnswered))
        ));
        (&b, second.unwrap())
    };
    winner.0.approve(winner.1, &digits.unwrap()).await.unwrap();
    wait(n.wait()).await.unwrap();
}

#[tokio::test]
async fn a_failed_open_ends_the_exchange_instead_of_stranding_the_new_device() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let path: &'static str = Box::leak(format!("v1/approvals/{}/respond", n.id()).into_boxed_str());
    core.inject_fault(bh_core::test_support::Fault {
        method: "POST",
        path,
        lost_reply: false,
        times: 1,
    });
    assert!(wait(a.open_request(n.id())).await.is_err());
    assert!(matches!(
        tokio::time::timeout(WAIT, n.wait()).await.unwrap(),
        Err(Error::ApprovalEnded(EndReason::BadMessage))
    ));
}

#[tokio::test]
async fn a_failed_approval_ends_the_exchange_instead_of_stranding_the_new_device() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    let path: &'static str = Box::leak(format!("v1/approvals/{}", n.id()).into_boxed_str());
    core.inject_fault(bh_core::test_support::Fault {
        method: "GET",
        path,
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(
        a.approve(open, &digits).await,
        Err(Error::Network(_))
    ));
    assert!(matches!(
        tokio::time::timeout(WAIT, n.wait()).await.unwrap(),
        Err(Error::ApprovalEnded(EndReason::BadMessage))
    ));
}

#[tokio::test]
async fn failed_decline_invalidates_an_open_handle_without_sending_a_transfer() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    let transfer = format!("v1/approvals/{}/transfer", n.id());
    let before = request_count(&a, &transfer);
    let path: &'static str = Box::leak(format!("v1/approvals/{}", n.id()).into_boxed_str());
    core.inject_fault(bh_core::test_support::Fault {
        method: "DELETE",
        path,
        lost_reply: false,
        times: 1,
    });
    assert!(matches!(a.decline(n.id()).await, Err(Error::Network(_))));
    assert_eq!(
        a.approve(open, &digits).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Declined)
    );
    assert_eq!(request_count(&a, &transfer), before);
}

#[tokio::test]
async fn a_concurrent_open_cannot_return_a_usable_handle_after_decline() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let id = n.id();
    let open = a.open_request(id);
    let digits = n.digits();
    let (opened, shown) = wait(async { tokio::join!(open, digits) }).await;
    let open = opened.unwrap();
    let digits = shown.unwrap();
    let transfer = format!("v1/approvals/{id}/transfer");
    let before = request_count(&a, &transfer);
    a.decline(id).await.unwrap();
    assert_eq!(
        a.approve(open, &digits).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Declined)
    );
    assert_eq!(request_count(&a, &transfer), before);
    assert!(matches!(
        a.open_request(id).await,
        Err(Error::ApprovalEnded(EndReason::Declined))
    ));
}

#[tokio::test]
async fn cached_digits_expire_and_cannot_be_read_again() {
    let (clock, manual) = Clock::manual();
    let (a, _) = device_with_clock("mac", &clock)
        .sign_up(new_signup())
        .await
        .unwrap();
    let mut n = device_with_clock("fold", &clock)
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    assert_eq!(n.digits().await.unwrap(), digits);
    manual.advance(Duration::from_secs(120));
    assert_eq!(
        n.digits().await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Expired)
    );
    assert_eq!(
        n.digits().await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Expired)
    );
    drop(open);
}

#[tokio::test]
async fn a_cancel_or_decline_ends_it_on_the_other_device() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    n.cancel().await.unwrap();
    assert_eq!(
        a.approve(open, &digits).await.unwrap_err(),
        Error::ApprovalEnded(EndReason::Cancelled)
    );
    n.retry().await.unwrap();
    a.decline(n.id()).await.unwrap();
    assert!(matches!(
        wait(n.digits()).await,
        Err(Error::ApprovalEnded(EndReason::Declined))
    ));
}

#[tokio::test]
async fn dropping_an_open_request_ends_the_exchange() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, _) = exchange(&a, &mut n).await;
    drop(open);
    assert!(matches!(
        wait(n.wait()).await,
        Err(Error::ApprovalEnded(EndReason::Cancelled))
    ));
}

#[tokio::test]
async fn device_clocks_need_not_agree_with_the_server() {
    let (clock_a, _) = Clock::manual();
    let (clock_n, manual_n) = Clock::manual();
    manual_n.advance(Duration::from_millis(1_000_000_000_000));
    let (a, _) = device_with_clock("mac", &clock_a)
        .sign_up(new_signup())
        .await
        .unwrap();
    let mut n = device_with_clock("fold", &clock_n)
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    a.approve(open, &digits).await.unwrap();
    n.wait().await.unwrap();
}

#[tokio::test]
async fn a_second_encapsulation_for_the_same_commitment_is_never_sent() {
    use bh_core::approval::protocol::{Ids, NewSide};
    use bh_core::{Core, CoreConfig, FileSecretStore};
    use std::sync::Arc;
    let tmp = tempfile::tempdir().unwrap();
    let config = || CoreConfig {
        data_dir: tmp.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(tmp.path().join("secrets")).unwrap()),
    };
    let core = Core::open(config()).unwrap();
    let mut signup = new_signup();
    signup.device_name = "mac".into();
    let (a, _) = core.sign_up(signup).await.unwrap();
    let first = pending_device_for(&a).await;
    let x = ApprovalId::random();
    let (mut side, request) = NewSide::start(
        Ids {
            account: a.id(),
            approval: x,
            new: first.device_id.parse().unwrap(),
        },
        0,
    );
    assert!(
        first
            .post(
                "/v1/approvals",
                json!({"approvalId": x, "request": bh_proto::Bytes(request.clone())})
            )
            .await
            .0
            .is_success()
    );
    wait(async {
        tokio::try_join!(a.open_request(x), async {
            loop {
                let (status, state) = first.get(&format!("/v1/approvals/{x}"), json!({})).await;
                assert!(status.is_success(), "{state}");
                if let Some(response) = state["response"].as_str() {
                    let bytes: bh_proto::Bytes = serde_json::from_value(json!(response)).unwrap();
                    let (reveal, _) = side.on_response(&bytes.0, 0).unwrap();
                    let (status, body) = first
                        .post(
                            &format!("/v1/approvals/{x}/reveal"),
                            json!({"reveal": bh_proto::Bytes(reveal)}),
                        )
                        .await;
                    assert!(status.is_success(), "{body}");
                    return Ok::<(), Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    })
    .await
    .unwrap();
    drop(a);
    drop(core);
    let core = Core::open(config()).unwrap();
    let a = core.accounts()[0].id;
    let a = core.account(a).unwrap();
    let y = ApprovalId::random();
    let mut duplicate = request;
    duplicate[2..18].copy_from_slice(&y.0);
    assert!(
        first
            .post(
                "/v1/approvals",
                json!({"approvalId": y, "request": bh_proto::Bytes(duplicate)})
            )
            .await
            .0
            .is_success()
    );
    assert!(matches!(
        wait(a.open_request(y)).await,
        Err(Error::ApprovalEnded(EndReason::AlreadyAnswered))
    ));
    assert_eq!(request_count(&a, &format!("v1/approvals/{y}/respond")), 0);
}

#[tokio::test]
async fn the_exchange_survives_a_server_restart() {
    let mut server = bh_testkit::LocalServer::start();
    let (a, _) = bh_testkit::device_on_server("mac", &Clock::system(), &server)
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: bh_testkit::TEST_PASSWORD.to_string().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    let mut n = bh_testkit::device_on_server("fold", &Clock::system(), &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            email: a.email(),
            password: bh_testkit::TEST_PASSWORD.to_string().into(),
            device_name: "fold".into(),
        })
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    server.restart();
    a.approve(open, &digits).await.unwrap();
    wait(n.wait()).await.unwrap();
}

#[tokio::test]
async fn a_new_device_retries_a_lost_state_reply_without_losing_its_exchange() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let core = device("fold");
    let mut n = core
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let path: &'static str = Box::leak(format!("v1/approvals/{}", n.id()).into_boxed_str());
    core.inject_fault(bh_core::test_support::Fault {
        method: "GET",
        path,
        lost_reply: true,
        times: 1,
    });
    let (open, digits) = exchange(&a, &mut n).await;
    a.approve(open, &digits).await.unwrap();
    wait(n.wait()).await.unwrap();
}

#[tokio::test]
async fn a_waiting_new_device_reconnects_when_the_server_restarts() {
    let mut server = bh_testkit::LocalServer::start();
    let (a, _) = bh_testkit::device_on_server("mac", &Clock::system(), &server)
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: bh_testkit::TEST_PASSWORD.to_string().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    let mut n = bh_testkit::device_on_server("fold", &Clock::system(), &server)
        .sign_in(bh_core::SignIn {
            server: server.url(),
            email: a.email(),
            password: bh_testkit::TEST_PASSWORD.to_string().into(),
            device_name: "fold".into(),
        })
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let (open, digits) = exchange(&a, &mut n).await;
    let (result, ()) = tokio::time::timeout(WAIT, async {
        tokio::join!(n.wait(), async {
            tokio::task::yield_now().await;
            server.restart();
            a.approve(open, &digits).await.unwrap();
        })
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap().id(), a.id());
}

#[tokio::test]
async fn use_kit_cancels_the_request() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut events = a.events();
    let mut n = device("fold")
        .sign_in(signin_for(&a))
        .await
        .unwrap()
        .request_approval()
        .await
        .unwrap();
    let id = n.id();
    tokio::time::timeout(WAIT, async { loop { if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalRequested(request) if request.id == id) { break; } } }).await.unwrap();
    assert!(matches!(n.use_kit("wrong").await, Err(Error::BadKit)));
    let id = n.id();
    n.use_kit(&kit.display()).await.unwrap();
    tokio::time::timeout(WAIT, async { loop { if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalClosed(closed) if closed == id) { break; } } }).await.unwrap();
    assert_eq!(
        n.use_kit(&kit.display()).await.unwrap_err(),
        Error::Invalid("signed in".into())
    );
    assert_eq!(
        n.retry().await.unwrap_err(),
        Error::Invalid("signed in".into())
    );
}

#[tokio::test]
async fn a_full_device_hears_a_new_request_without_polling() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let mut events = a.events();
    wait(async {
        while request_count(&a, "v1/approvals") == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let before = request_count(&a, "v1/approvals");
    let (_, id, new_id) = create_request(&a).await;
    wait(async {
        loop {
            if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalRequested(r) if r.id == id && r.device_id == new_id) {
                break;
            }
        }
    })
    .await;
    assert!(
        request_count(&a, "v1/approvals") - before <= 1,
        "listener polled unnecessarily"
    );
}

#[tokio::test]
async fn a_request_made_while_offline_is_heard_on_reconnect() {
    let mut server = bh_testkit::LocalServer::start();
    let core = bh_testkit::device_on_server("mac", &bh_core::Clock::system(), &server);
    let signup = bh_core::SignUp {
        server: server.url(),
        invite: bh_testkit::invite(&server),
        email: format!("{}@example.test", bh_core::AccountId::random()),
        password: bh_testkit::TEST_PASSWORD.to_string().into(),
        device_name: "mac".into(),
    };
    let (a, _) = core.sign_up(signup).await.unwrap();
    let mut events = a.events();
    server.restart();
    let pending = bh_testkit::pending_device_on(&a, &server).await;
    let id = ApprovalId::random();
    let (status, body) = pending
        .post("/v1/approvals", json!({"approvalId": id, "request": "AQ"}))
        .await;
    assert!(status.is_success(), "{body}");
    // The socket reconnects with backoff; await its event, not a CPU-load-sensitive deadline.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop { if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalRequested(r) if r.id == id) { break; } }
    }).await.unwrap();
}

#[tokio::test]
async fn listing_requests_sends_nothing() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let (pending, id, _) = create_request(&a).await;
    assert!(
        a.approval_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == id)
    );
    let (status, state) = pending.get(&format!("/v1/approvals/{id}"), json!({})).await;
    assert!(status.is_success());
    assert_eq!(state["state"], "requested");
    assert_eq!(request_count(&a, &format!("v1/approvals/{id}/respond")), 0);
}

#[tokio::test]
async fn a_declined_request_closes_everywhere() {
    let (a, kit) = device("mac").sign_up(new_signup()).await.unwrap();
    let b = device("fold")
        .sign_in(bh_testkit::signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let mut events = b.events();
    wait(async {
        while request_count(&b, "v1/approvals") == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let (pending, id, _) = create_request(&a).await;
    wait(async {
        loop {
            if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalRequested(r) if r.id == id) {
                break;
            }
        }
    })
    .await;
    a.decline(id).await.unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            if matches!(events.recv().await.unwrap(), AccountEvent::ApprovalClosed(closed) if closed == id) {
                break;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("b missed approval close: live={}, list={}, requests={:?}", request_count(&b, "v1/approvals/live"), request_count(&b, "v1/approvals"), request_count(&a, "v1/approvals")));
    let (_, state) = pending.get(&format!("/v1/approvals/{id}"), json!({})).await;
    assert_eq!(state["endReason"], "declined");
    assert!(
        b.approval_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.id != id)
    );
}

#[tokio::test]
async fn an_idle_request_expires_and_closes_on_a_full_device() {
    let server = bh_testkit::LocalServer::start_with_vars(&[("APPROVAL_TTL_MS", "700")]);
    let core = bh_testkit::device_on_server("mac", &bh_core::Clock::system(), &server);
    let (a, _) = core
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: bh_testkit::TEST_PASSWORD.to_string().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    let mut events = a.events();
    tokio::time::timeout(Duration::from_secs(30), async {
        while request_count(&a, "v1/approvals") == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let first = bh_testkit::pending_device_on(&a, &server).await;
    let second = bh_testkit::pending_device_on(&a, &server).await;
    let ids = [ApprovalId::random(), ApprovalId::random()];
    let (one, two) = tokio::join!(
        first.post(
            "/v1/approvals",
            json!({"approvalId": ids[0], "request": "AQ"})
        ),
        second.post(
            "/v1/approvals",
            json!({"approvalId": ids[1], "request": "AQ"})
        ),
    );
    assert!(one.0.is_success(), "{}", one.1);
    assert!(two.0.is_success(), "{}", two.1);
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut requested = Vec::new();
        let mut closed = Vec::new();
        while requested.len() < 2 || closed.len() < 2 {
            match events.recv().await.unwrap() {
                AccountEvent::ApprovalRequested(r) if ids.contains(&r.id) => {
                    requested.push(r.id);
                }
                AccountEvent::ApprovalClosed(id) if ids.contains(&id) => {
                    closed.push(id);
                }
                _ => {}
            }
        }
        assert_ne!(requested[0], requested[1]);
        assert_ne!(closed[0], closed[1]);
    })
    .await
    .expect("both requests and idle expiries must be seen within 30 s");
    for (pending, id) in [(first, ids[0]), (second, ids[1])] {
        let (_, state) = pending.get(&format!("/v1/approvals/{id}"), json!({})).await;
        assert_eq!(state["endReason"], "expired");
    }
}

#[tokio::test]
async fn signing_out_stops_the_listener_and_drops_its_socket() {
    let core = device("mac");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let mut events = a.events();
    tokio::time::timeout(Duration::from_secs(30), async {
        while request_count(&a, "v1/approvals") == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    a.sign_out().await.unwrap(); // Awaits the listener's termination (and socket drop).
    assert!(core.accounts().is_empty());
    assert!(matches!(
        core.account(a.id()),
        Err(bh_core::Error::NotFound)
    ));
    assert!(matches!(
        events.recv().await.unwrap(),
        AccountEvent::Removed
    ));
    let before = request_count(&a, "v1/approvals/live");
    // A terminated task must not retry, even after its former socket closes.
    let result = tokio::time::timeout(Duration::from_millis(750), events.recv()).await;
    assert!(
        result.is_err(),
        "unexpected event after sign-out: {result:?}"
    );
    assert_eq!(request_count(&a, "v1/approvals/live"), before);
}

#[tokio::test]
async fn pending_devices_cannot_list_requests() {
    let (a, _) = device("mac").sign_up(new_signup()).await.unwrap();
    // Pending tokens also cannot list at the relay.
    let pending = pending_device_for(&a).await;
    let (status, _) = pending.get("/v1/approvals", json!({})).await;
    assert_eq!(status.as_u16(), 403);
    assert!(a.approval_requests().await.is_ok());
}
