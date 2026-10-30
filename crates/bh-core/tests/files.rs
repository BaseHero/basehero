//! Sealed file parts: outgoing and incoming, including on-demand reads.
use bh_core::{
    AppRequest, Base, BaseEvent, BaseGrantRequest, Core, CoreConfig, Error, FILE_MAX, FILE_PART,
    FileSecretStore, FileStatus, Mode, NewFile,
};
use bh_testkit::{
    LocalServer, found_under, local_only, new_signup, raw_device, two_devices_sharing_a_base,
    wait_for_base,
};
use reqwest::StatusCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn new_file(name: &str) -> NewFile {
    NewFile {
        parent: None,
        name: name.into(),
        mime: "application/pdf".into(),
    }
}

#[tokio::test]
async fn signing_out_stops_a_download_held_before_its_get() {
    let (a, b) = two_devices_sharing_a_base().await;
    let held = b.base.test_hold_file_gets();
    let alive = b.base.test_downloader_alive();
    let id = a.base.add_file(new_file("incoming"), b"encrypted").unwrap();
    wait_for_base(&a.base, || {
        a.base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    a.base.flush().await.unwrap();
    bh_testkit::wait_for(|| held.load(Ordering::SeqCst)).await;
    b.account.sign_out().await.unwrap();
    assert!(
        !alive.load(Ordering::SeqCst),
        "downloader outlived sign-out"
    );
    let prefix = format!("v1/bases/{}/files/{id}/", b.base.id());
    let count = b.account.test_request_count(&prefix);
    assert_eq!(b.base.file_bytes(id).await, Err(Error::NotFound));
    assert_eq!(b.account.test_request_count(&prefix), count);
}

#[tokio::test]
async fn sign_out_cancels_a_held_on_demand_get_and_erases_the_account() {
    use bh_core::SignIn;
    let (writer, kit) = bh_testkit::device("writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = writer.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let core = Core::open(CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let reader = core
        .sign_in(SignIn {
            device_name: "reader".into(),
            ..bh_testkit::signin_for(&writer)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    reader.refresh().await.unwrap();
    let remote = reader.base(base.id()).unwrap();
    let held_background = remote.test_hold_file_gets();
    let id = base.add_file(new_file("incoming"), b"private").unwrap();
    wait_for_base(&base, || {
        base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    base.flush().await.unwrap();
    bh_testkit::wait_for(|| held_background.load(Ordering::SeqCst)).await;
    wait_for_base(&remote, || remote.file(id).unwrap().is_some()).await;
    let held = remote.test_hold_on_demand_file_get();
    let reading = tokio::spawn({
        let remote = remote.clone();
        async move { remote.file_bytes(id).await }
    });
    bh_testkit::wait_for(|| held.load(Ordering::SeqCst)).await;
    let account_dir = dir
        .path()
        .join("data/accounts")
        .join(reader.id().to_string());
    tokio::time::timeout(Duration::from_secs(5), reader.sign_out())
        .await
        .expect("sign-out must cancel an in-flight foreground GET")
        .unwrap();
    assert!(!account_dir.exists());
    assert_eq!(reading.await.unwrap(), Err(Error::NotFound));
}

#[tokio::test]
async fn hidden_lock_cancels_a_held_on_demand_get_and_drops_its_key() {
    let (writer, kit) = bh_testkit::device("writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let hidden = writer
        .create_hidden_base(
            "Private",
            zeroize::Zeroizing::new("ferry lantern quartz".into()),
        )
        .await
        .unwrap();
    hidden.flush().await.unwrap();
    let reader = bh_testkit::device("reader")
        .sign_in(bh_testkit::signin_for(&writer))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    reader.refresh().await.unwrap();
    reader
        .unlock_hidden(zeroize::Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let remote = reader.base(hidden.id()).unwrap();
    let held_background = remote.test_hold_file_gets();
    let id = hidden.add_file(new_file("incoming"), b"private").unwrap();
    wait_for_base(&hidden, || {
        hidden.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    hidden.flush().await.unwrap();
    bh_testkit::wait_for(|| held_background.load(Ordering::SeqCst)).await;
    wait_for_base(&remote, || remote.file(id).unwrap().is_some()).await;
    let held = remote.test_hold_on_demand_file_get();
    let reading = tokio::spawn({
        let remote = remote.clone();
        async move { remote.file_bytes(id).await }
    });
    bh_testkit::wait_for(|| held.load(Ordering::SeqCst)).await;
    tokio::time::timeout(Duration::from_secs(5), reader.lock_hidden(hidden.id()))
        .await
        .expect("hidden lock must cancel an in-flight foreground GET")
        .unwrap();
    assert!(!remote.test_has_key());
    assert_eq!(reading.await.unwrap(), Err(Error::NotFound));
}

#[tokio::test]
async fn dropping_the_last_base_handle_ends_its_downloader() {
    let (a, _) = bh_testkit::device("download-drop")
        .sign_up(new_signup())
        .await
        .unwrap();
    let alive = {
        let base = a.create_base("Shared").await.unwrap();
        base.flush().await.unwrap();
        base.test_downloader_alive()
    };
    bh_testkit::wait_for(|| !alive.load(Ordering::SeqCst)).await;
    drop(a);
}

#[tokio::test]
async fn a_full_device_downloads_every_file() {
    let (a, b) = two_devices_sharing_a_base().await;
    let first = a.base.add_file(new_file("one"), b"one").unwrap();
    let second = a.base.add_file(new_file("two"), b"two").unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        [first, second].iter().all(|id| {
            b.base
                .file(*id)
                .unwrap()
                .is_some_and(|f| f.status == FileStatus::Here)
        })
    })
    .await;
    assert_eq!(b.base.file_bytes(first).await.unwrap(), b"one");
    assert_eq!(b.base.file_bytes(second).await.unwrap(), b"two");
}

#[tokio::test]
async fn a_file_waits_until_its_writer_uploads_it() {
    let (a, b) = two_devices_sharing_a_base().await;
    a.base.pause_files();
    let id = a.base.add_file(new_file("wait"), b"eventually").unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || b.base.file(id).unwrap().is_some()).await;
    assert_eq!(
        b.base.file(id).unwrap().unwrap().status,
        FileStatus::Waiting
    );
    assert_eq!(b.base.file_bytes(id).await, Err(Error::NotFound));
    let prefix = format!("v1/bases/{}/files/{id}/", b.base.id());
    assert_eq!(b.account.test_request_count(&prefix), 0);
    a.base.resume_files();
    wait_for_base(&b.base, || {
        b.base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    assert_eq!(b.base.file_bytes(id).await.unwrap(), b"eventually");
}

#[tokio::test]
async fn an_app_device_fetches_only_what_it_opens() {
    let full = bh_testkit::device("writer")
        .sign_up(new_signup())
        .await
        .unwrap()
        .0;
    let base = full.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "Reader".into(),
            app_id: Some("dev:file-on-demand".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("reader")
        .install_app(credentials)
        .await
        .unwrap();
    let remote = app.base(base.id()).unwrap();
    let id = base.add_file(new_file("read"), b"opened").unwrap();
    wait_for_base(&base, || {
        base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    base.flush().await.unwrap();
    remote.test_resume_sync();
    wait_for_base(&remote, || {
        remote
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Remote)
    })
    .await;
    let prefix = format!("v1/bases/{}/files/{id}/", base.id());
    assert_eq!(app.test_request_count(&prefix), 0);
    assert_eq!(remote.file_bytes(id).await.unwrap(), b"opened");
    assert_eq!(remote.file(id).unwrap().unwrap().status, FileStatus::Here);
}

#[tokio::test]
async fn a_part_that_does_not_open_is_set_aside() {
    let (a, b) = two_devices_sharing_a_base().await;
    b.base.test_pause_sync();
    let good = a.base.add_file(new_file("good"), b"intact").unwrap();
    wait_for_base(&a.base, || {
        a.base.file(good).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    // Pause is checked between uploads; hold this particular PUT before it starts.
    let held = a.base.test_hold_file_puts();
    let bad = a
        .base
        .add_file(new_file("bad"), b"not the garbage")
        .unwrap();
    bh_testkit::wait_for(|| held.load(std::sync::atomic::Ordering::SeqCst)).await;
    a.base.flush().await.unwrap();
    let path = format!("/v1/bases/{}/files/{bad}/0", a.base.id());
    let (status, reply) = raw_device(&a.account).put_bytes(&path, b"garbage").await;
    assert_eq!(status, StatusCode::OK, "{reply:?}");
    // Test a server returning an inauthentic part after the authenticated
    // metadata claims upload completed. A 409 for different bytes is NOT sent.
    a.base
        .set_fields(
            bad,
            serde_json::Map::from_iter([("uploaded".into(), true.into())]),
        )
        .unwrap();
    a.base.flush().await.unwrap();
    b.base.test_resume_sync();
    wait_for_base(&b.base, || {
        b.base
            .file(bad)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Broken)
    })
    .await;
    assert_eq!(b.base.file_bytes(bad).await, Err(Error::Crypto));
    wait_for_base(&b.base, || {
        b.base
            .file(good)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    assert_eq!(b.base.file_bytes(good).await.unwrap(), b"intact");
}

#[tokio::test]
async fn corrupted_sealed_disk_part_is_never_returned() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [13; 32]).unwrap();
    let id = base.add_file(new_file("local"), b"private").unwrap();
    let part = dir.path().join(format!("{}.files/{id}/0", base.id()));
    let mut sealed = std::fs::read(&part).unwrap();
    sealed[30] ^= 1;
    std::fs::write(part, sealed).unwrap();
    assert_eq!(base.file_bytes(id).await, Err(Error::Crypto));
    assert_ne!(base.file(id).unwrap().unwrap().status, FileStatus::Here);
}

#[tokio::test]
async fn missing_last_part_never_produces_a_usable_file() {
    let (a, b) = two_devices_sharing_a_base().await;
    a.base.pause_files();
    let id = a
        .base
        .add_file(new_file("two parts"), &vec![7; FILE_PART + 1])
        .unwrap();
    let key = a.base.get(id).unwrap().unwrap().fields["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let key =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key).unwrap();
    let fk = bh_crypto::Secret::<32>::from_slice(&key).unwrap();
    let part_key = bh_crypto::kdf(&fk, b"bhfblob1", 1);
    let mut aad = b"bh.v1".to_vec();
    aad.push(3);
    aad.extend_from_slice(&a.base.id().0);
    aad.extend_from_slice(&id.0);
    aad.extend_from_slice(&1u32.to_be_bytes());
    let (nonce, cipher) = bh_crypto::aead_seal(&part_key, &aad, &vec![7; FILE_PART]);
    let mut sealed = vec![1];
    sealed.extend_from_slice(&1u32.to_be_bytes());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&cipher);
    let path = format!("/v1/bases/{}/files/{id}/0", a.base.id());
    assert_eq!(
        raw_device(&a.account).put_bytes(&path, &sealed).await.0,
        StatusCode::OK
    );
    // Simulate an uploaded object whose final immutable part has not reached R2.
    a.base
        .set_fields(
            id,
            serde_json::Map::from_iter([("uploaded".into(), true.into())]),
        )
        .unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        b.base
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Fetching { done: 1, parts: 2 })
    })
    .await;
    assert_eq!(b.base.file_bytes(id).await, Err(Error::NotFound));
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("incomplete");
    assert_eq!(b.base.save_file(id, &dest).await, Err(Error::NotFound));
    assert!(!dest.exists());
    let part_key = bh_crypto::kdf(&fk, b"bhfblob1", 2);
    let (nonce, cipher) = bh_crypto::aead_seal(&part_key, &aad, &[7]);
    let mut last = vec![1];
    last.extend_from_slice(&1u32.to_be_bytes());
    last.extend_from_slice(&nonce);
    last.extend_from_slice(&cipher);
    let last_path = format!("/v1/bases/{}/files/{id}/1", a.base.id());
    assert_eq!(
        raw_device(&a.account).put_bytes(&last_path, &last).await.0,
        StatusCode::OK
    );
    b.base.test_resume_sync();
    wait_for_base(&b.base, || {
        b.base
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    assert_eq!(b.base.file_bytes(id).await.unwrap(), vec![7; FILE_PART + 1]);
}

#[tokio::test]
async fn an_authenticated_short_part_is_not_a_complete_file() {
    let (a, b) = two_devices_sharing_a_base().await;
    a.base.pause_files();
    let id = a
        .base
        .add_file(new_file("truncated"), b"eleven bytes")
        .unwrap();
    a.base.flush().await.unwrap();
    let key = a.base.get(id).unwrap().unwrap().fields["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let key =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key).unwrap();
    let fk = bh_crypto::Secret::<32>::from_slice(&key).unwrap();
    let part_key = bh_crypto::kdf(&fk, b"bhfblob1", 1);
    let mut aad = b"bh.v1".to_vec();
    aad.push(3);
    aad.extend_from_slice(&a.base.id().0);
    aad.extend_from_slice(&id.0);
    aad.extend_from_slice(&1u32.to_be_bytes());
    let (nonce, cipher) = bh_crypto::aead_seal(&part_key, &aad, b"short");
    let mut sealed = vec![1];
    sealed.extend_from_slice(&1u32.to_be_bytes());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&cipher);
    let path = format!("/v1/bases/{}/files/{id}/0", a.base.id());
    assert_eq!(
        raw_device(&a.account).put_bytes(&path, &sealed).await.0,
        StatusCode::OK
    );
    a.base
        .set_fields(
            id,
            serde_json::Map::from_iter([("uploaded".into(), true.into())]),
        )
        .unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || {
        b.base
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Broken)
    })
    .await;
    assert_eq!(b.base.file_bytes(id).await, Err(Error::Crypto));
}

#[tokio::test]
async fn locking_stops_a_download_held_before_its_get() {
    let (a, kit) = bh_testkit::device("writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let hidden = a
        .create_hidden_base(
            "Private",
            zeroize::Zeroizing::new("ferry lantern quartz".into()),
        )
        .await
        .unwrap();
    hidden.flush().await.unwrap();
    let b = bh_testkit::device("reader")
        .sign_in(bh_testkit::signin_for(&a))
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    b.unlock_hidden(zeroize::Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let reader = b.base(hidden.id()).unwrap();
    let held = reader.test_hold_file_gets();
    let alive = reader.test_downloader_alive();
    let id = hidden.add_file(new_file("locked"), b"private").unwrap();
    wait_for_base(&hidden, || {
        hidden.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    hidden.flush().await.unwrap();
    bh_testkit::wait_for(|| held.load(Ordering::SeqCst)).await;
    b.lock_hidden(hidden.id()).await.unwrap();
    assert!(
        !alive.load(Ordering::SeqCst),
        "downloader outlived hidden lock"
    );
    assert_eq!(reader.file(id), Err(Error::NotFound));
    b.unlock_hidden(zeroize::Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let reader = b.base(hidden.id()).unwrap();
    wait_for_base(&reader, || {
        reader
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    assert_eq!(reader.file_bytes(id).await.unwrap(), b"private");
}

#[tokio::test]
async fn closing_a_base_stops_its_downloader() {
    use bh_core::{SignIn, test_support::Fault};
    let (a, kit) = bh_testkit::device("writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let hidden = a
        .create_hidden_base(
            "Private",
            zeroize::Zeroizing::new("ferry lantern quartz".into()),
        )
        .await
        .unwrap();
    hidden.flush().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let core = Core::open(CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let b = core
        .sign_in(SignIn {
            device_name: "reader".into(),
            ..bh_testkit::signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    b.unlock_hidden(zeroize::Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let reader = b.base(hidden.id()).unwrap();
    hidden.pause_files();
    let id = hidden
        .add_file(new_file("multiple"), &vec![7; 3 * FILE_PART])
        .unwrap();
    hidden.flush().await.unwrap();
    let second = format!("v1/bases/{}/files/{id}/1", hidden.id());
    // Leak a test path only: Fault's path is a static string.
    let path: &'static str = Box::leak(second.clone().into_boxed_str());
    b.test_inject_fault(Fault {
        method: "GET",
        path,
        lost_reply: false,
        times: 1,
    });
    hidden.resume_files();
    wait_for_base(&hidden, || {
        hidden.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    hidden.flush().await.unwrap();
    wait_for_base(&reader, || {
        reader
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Fetching { done: 1, parts: 3 })
    })
    .await;
    b.lock_hidden(hidden.id()).await.unwrap();
    let count = b.test_request_count(&second);
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(b.test_request_count(&second), count);
    b.unlock_hidden(zeroize::Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let reader = b.base(hidden.id()).unwrap();
    wait_for_base(&reader, || {
        reader
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Here)
    })
    .await;
    assert_eq!(reader.file_bytes(id).await.unwrap().len(), 3 * FILE_PART);
}

#[tokio::test]
async fn a_missing_partial_disk_part_is_set_aside_on_resume() {
    use bh_core::{SignIn, test_support::Fault};
    let (a, kit) = bh_testkit::device("writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let core = Core::open(CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let b = core
        .sign_in(SignIn {
            device_name: "reader".into(),
            ..bh_testkit::signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let reader = b.base(base.id()).unwrap();
    let id = base
        .add_file(new_file("multiple"), &vec![7; FILE_PART + 1])
        .unwrap();
    let second = format!("v1/bases/{}/files/{id}/1", base.id());
    let path: &'static str = Box::leak(second.into_boxed_str());
    b.test_inject_fault(Fault {
        method: "GET",
        path,
        lost_reply: false,
        times: 1,
    });
    wait_for_base(&base, || {
        base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    base.flush().await.unwrap();
    wait_for_base(&reader, || {
        reader
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Fetching { done: 1, parts: 2 })
    })
    .await;
    let first = dir.path().join(format!(
        "data/accounts/{}/bases/{}.files/{id}/0",
        b.id(),
        base.id()
    ));
    std::fs::remove_file(first).unwrap();
    reader.test_resume_sync();
    wait_for_base(&reader, || {
        reader
            .file(id)
            .unwrap()
            .is_some_and(|f| f.status == FileStatus::Broken)
    })
    .await;
    assert_eq!(reader.file_bytes(id).await, Err(Error::Crypto));
}

#[tokio::test]
async fn only_raster_images_are_images() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [17; 32]).unwrap();
    for (name, picked, bytes, expected) in [
        (
            "x.svg",
            "image/svg+xml",
            &b"\x89PNG\r\n\x1a\ncontent"[..],
            Some("image/png"),
        ),
        (
            "x.jpg",
            "image/jpeg",
            &b"\xff\xd8\xffmore"[..],
            Some("image/jpeg"),
        ),
        ("x.gif", "image/gif", &b"GIF89a..."[..], Some("image/gif")),
        (
            "x.webp",
            "image/webp",
            &b"RIFF\0\0\0\0WEBPmore"[..],
            Some("image/webp"),
        ),
        ("x.png", "image/png", &b"<svg></svg>"[..], None),
        ("x.html", "image/png", &b"<html>"[..], None),
        ("x.pdf", "image/png", &b"%PDF-1.7"[..], None),
    ] {
        let id = base
            .add_file(
                NewFile {
                    parent: None,
                    name: name.into(),
                    mime: picked.into(),
                },
                bytes,
            )
            .unwrap();
        match expected {
            Some(mime) => {
                let image = base.image(id).await.unwrap();
                assert_eq!(image.mime, mime);
                assert_eq!(image.bytes, bytes);
            }
            None => assert!(
                matches!(base.image(id).await, Err(Error::Invalid(message)) if message == "not an image")
            ),
        }
    }
}

#[tokio::test]
async fn save_file_writes_the_plain_file() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [19; 32]).unwrap();
    let content = vec![7; FILE_PART + 11];
    let id = base.add_file(new_file("save"), &content).unwrap();
    let dest = dir.path().join("saved.pdf");
    base.save_file(id, &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), content);
    assert_eq!(
        std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|entry| entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("saved"))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_file_is_sealed_in_parts_and_uploaded() {
    let (a, _) = two_devices_sharing_a_base().await;
    let content = vec![0x69; 9 * 1024 * 1024];
    let id = a.base.add_file(new_file("Receipts"), &content).unwrap();
    wait_for_base(&a.base, || {
        a.base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    let info = a.base.file(id).unwrap().unwrap();
    assert_eq!(info.size, content.len() as u64);
    assert_eq!(a.base.get(id).unwrap().unwrap().fields["uploaded"], true);
    let path = format!("/v1/bases/{}/files/{id}/0", a.base.id());
    let (status, body) = raw_device(&a.account).get_bytes(&path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), FILE_PART + 45);
    assert_ne!(&body[..FILE_PART], &content[..FILE_PART]);
    let key = a.base.get(id).unwrap().unwrap().fields["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let key =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, key).unwrap();
    let fk = bh_crypto::Secret::<32>::from_slice(&key).unwrap();
    let part_key = bh_crypto::kdf(&fk, b"bhfblob1", 1);
    let mut aad = b"bh.v1".to_vec();
    aad.push(3); // FileBlob; 9 is reserved and 10 is HiddenBaseKey.
    aad.extend_from_slice(&a.base.id().0);
    aad.extend_from_slice(&id.0);
    aad.extend_from_slice(&1u32.to_be_bytes());
    let nonce: [u8; 24] = body[5..29].try_into().unwrap();
    assert_eq!(
        &*bh_crypto::aead_open(&part_key, &nonce, &aad, &body[29..]).unwrap(),
        &content[..FILE_PART]
    );
}

#[tokio::test]
async fn file_names_types_and_content_never_reach_the_server() {
    local_only!();
    let (a, _) = two_devices_sharing_a_base().await;
    let id = a
        .base
        .add_file(
            new_file("Kyoto receipts.pdf"),
            b"unique-private-file-marker",
        )
        .unwrap();
    wait_for_base(&a.base, || {
        a.base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    for marker in [
        "Kyoto receipts.pdf",
        "application/pdf",
        "unique-private-file-marker",
    ] {
        assert!(!found_under(
            LocalServer::from_env().persist_dir(),
            marker.as_bytes()
        ));
    }
}

#[tokio::test]
async fn oversized_file_is_rejected_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [4; 32]).unwrap();
    assert_eq!(
        base.add_file(new_file("large"), &vec![0; FILE_MAX as usize + 1]),
        Err(Error::TooLarge)
    );
    assert!(base.children(None).unwrap().is_empty());
    assert!(!dir.path().join(format!("{}.files", base.id())).exists());
    let id = base
        .add_file(new_file("limit"), &vec![1; FILE_MAX as usize])
        .unwrap();
    assert_eq!(
        base.file(id).unwrap().unwrap().status,
        FileStatus::Sending { done: 0, parts: 25 }
    );
}

#[tokio::test]
async fn empty_file_has_one_part() {
    let (a, _) = two_devices_sharing_a_base().await;
    let id = a.base.add_file(new_file("empty"), b"").unwrap();
    wait_for_base(&a.base, || {
        a.base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    let (status, body) = raw_device(&a.account)
        .get_bytes(&format!("/v1/bases/{}/files/{id}/0", a.base.id()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 45);
    assert!(a.base.file_bytes(id).await.unwrap().is_empty());
}

#[tokio::test]
async fn offline_file_uploads_later_and_emits_status() {
    let (a, _) = two_devices_sharing_a_base().await;
    a.base.test_pause_sync();
    a.base.pause_files();
    let mut events = a.base.events();
    let id = a
        .base
        .add_file(new_file("later"), b"some contents")
        .unwrap();
    assert_eq!(
        a.base.file(id).unwrap().unwrap().status,
        FileStatus::Sending { done: 0, parts: 1 }
    );
    a.base.test_resume_sync();
    a.base.resume_files();
    wait_for_base(&a.base, || {
        a.base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let BaseEvent::FilesChanged(ids) = events.recv().await.unwrap()
                    && ids.contains(&id)
                {
                    break;
                }
            }
        })
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn interrupted_upload_resumes_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let config = || CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    };
    let core = Core::open(config()).unwrap();
    let (account, _) = core
        .sign_up(bh_core::SignUp {
            device_name: "Files test".into(),
            ..new_signup()
        })
        .await
        .unwrap();
    let base = account.create_base("Files").await.unwrap();
    let base_id = base.id();
    let account_id = account.id();
    base.pause_files();
    let id = base
        .add_file(new_file("large"), &vec![44; 5 * FILE_PART])
        .unwrap();
    // Hold the third PUT before it starts: a remote GET becoming fetchable
    // after a lost reply races the uploader's local progress bookkeeping.
    // retry_after_a_lost_reply_keeps_identical_part_bytes covers that case.
    let held = base.test_hold_file_put_after(2);
    base.resume_files();
    bh_testkit::wait_for(|| held.load(Ordering::SeqCst)).await;
    assert_eq!(
        base.file(id).unwrap().unwrap().status,
        FileStatus::Sending { done: 2, parts: 5 }
    );
    core.shutdown();
    drop(base);
    drop(account);
    drop(core);
    let reopened = Core::open(config()).unwrap();
    let base = reopened.account(account_id).unwrap().base(base_id).unwrap();
    wait_for_base(&base, || {
        base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    assert_eq!(base.get(id).unwrap().unwrap().fields["uploaded"], true);
    assert_eq!(base.file_bytes(id).await.unwrap(), vec![44; 5 * FILE_PART]);
}

#[test]
fn orphaned_parts_are_removed_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let id;
    {
        let base = Base::open_local(dir.path(), [23; 32]).unwrap();
        id = base.id();
        base.add_file(new_file("kept"), b"retained").unwrap();
        let root = dir.path().join(format!("{id}.files"));
        std::fs::create_dir(root.join("orphan.tmp")).unwrap();
        std::fs::write(root.join("orphan.tmp/0"), b"unreachable").unwrap();
    }
    let base = Base::open_local(dir.path(), [23; 32]).unwrap();
    assert!(!dir.path().join(format!("{id}.files/orphan.tmp")).exists());
    assert_eq!(base.children(None).unwrap().len(), 1);
}

#[tokio::test]
async fn removed_device_erases_its_files() {
    let (a, kit) = bh_testkit::device("writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let core = Core::open(CoreConfig {
        data_dir: dir.path().join("data"),
        secrets: Arc::new(FileSecretStore::new(dir.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let b = core
        .sign_in(bh_core::SignIn {
            device_name: "Files reader".into(),
            ..bh_testkit::signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    b.refresh().await.unwrap();
    let local = b.base(base.id()).unwrap();
    local.pause_files();
    local.add_file(new_file("erase"), b"secret bytes").unwrap();
    let root = dir.path().join(format!(
        "data/accounts/{}/bases/{}.files",
        b.id(),
        base.id()
    ));
    assert!(root.exists());
    a.remove_device(
        b.device_id(),
        bh_core::Removal::Full {
            password: zeroize::Zeroizing::new(bh_testkit::TEST_PASSWORD.into()),
            lost: false,
        },
    )
    .await
    .unwrap();
    bh_testkit::wait_for(|| !root.exists()).await;
}

#[tokio::test]
async fn signing_out_stops_an_upload_in_flight() {
    let (a, _) = bh_testkit::device("upload-sign-out")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = a.create_base("Shared").await.unwrap();
    let held = base.test_hold_file_puts();
    let alive = base.test_uploader_alive();
    base.add_file(new_file("in flight"), b"sealed soon")
        .unwrap();
    bh_testkit::wait_for(|| held.load(Ordering::SeqCst)).await;
    a.sign_out().await.unwrap();
    assert!(
        !alive.load(Ordering::SeqCst),
        "the uploader outlived sign-out"
    );
}

#[tokio::test]
async fn dropping_the_last_base_handle_ends_its_uploader() {
    let (a, _) = bh_testkit::device("upload-drop")
        .sign_up(new_signup())
        .await
        .unwrap();
    let alive = {
        let base = a.create_base("Shared").await.unwrap();
        base.flush().await.unwrap();
        base.test_uploader_alive()
    };
    // The account keeps only weak handles to its bases.
    bh_testkit::wait_for(|| !alive.load(Ordering::SeqCst)).await;
    drop(a);
}

#[tokio::test]
async fn read_only_app_cannot_add_files() {
    let full = bh_testkit::device("full")
        .sign_up(new_signup())
        .await
        .unwrap()
        .0;
    let base = full.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "Readonly Files".into(),
            app_id: Some("dev:readonly-files".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("read-only")
        .install_app(credentials)
        .await
        .unwrap();
    let read_only = app.base(base.id()).unwrap();
    assert_eq!(
        read_only.add_file(new_file("denied"), b"private"),
        Err(Error::ReadOnly)
    );
    assert!(read_only.children(None).unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_uploaded_marker_is_retried() {
    let (a, _) = two_devices_sharing_a_base().await;
    a.base.pause_files();
    let id = a.base.add_file(new_file("marker"), b"persist").unwrap();
    a.base.test_fail_next_save();
    a.base.resume_files();
    wait_for_base(&a.base, || {
        a.base.get(id).unwrap().unwrap().fields.get("uploaded") == Some(&true.into())
    })
    .await;
}

#[tokio::test]
async fn app_files_are_remote_after_the_writer_uploads() {
    let full = bh_testkit::device("full")
        .sign_up(new_signup())
        .await
        .unwrap()
        .0;
    let base = full.create_base("Shared").await.unwrap();
    base.flush().await.unwrap();
    let credentials = full
        .connect_app(AppRequest {
            app_name: "Files Reader".into(),
            app_id: Some("dev:files-reader".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = bh_testkit::device("files-reader")
        .install_app(credentials)
        .await
        .unwrap();
    let remote = app.base(base.id()).unwrap();
    let id = base.add_file(new_file("remote"), b"private").unwrap();
    wait_for_base(&base, || {
        base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    base.flush().await.unwrap();
    remote.test_resume_sync();
    wait_for_base(&remote, || {
        remote
            .get(id)
            .unwrap()
            .is_some_and(|object| object.fields.get("uploaded") == Some(&true.into()))
    })
    .await;
    assert_eq!(remote.file(id).unwrap().unwrap().status, FileStatus::Remote);
}

#[tokio::test]
async fn a_file_key_is_not_searchable() {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [42; 32]).unwrap();
    let id = base.add_file(new_file("secret"), b"private").unwrap();
    let key = base.get(id).unwrap().unwrap().fields["key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(base.search(&key, 10).unwrap().is_empty());
    assert!(!key.is_empty());
}

#[tokio::test]
async fn closing_a_hidden_base_stops_its_uploader() {
    let core = bh_testkit::device("hidden-file");
    let (a, _) = core.sign_up(new_signup()).await.unwrap();
    let base = a
        .create_hidden_base(
            "Private",
            zeroize::Zeroizing::new("ferry lantern quartz".to_string()),
        )
        .await
        .unwrap();
    let held = base.test_hold_file_puts();
    let alive = base.test_uploader_alive();
    let id = base.add_file(new_file("locked"), b"private").unwrap();
    bh_testkit::wait_for(|| held.load(Ordering::SeqCst)).await;
    a.lock_hidden(base.id()).await.unwrap();
    assert!(
        !alive.load(Ordering::SeqCst),
        "the uploader outlived the lock"
    );
    assert_eq!(base.file(id).unwrap_err(), Error::NotFound);
    let opened = a
        .unlock_hidden(zeroize::Zeroizing::new("ferry lantern quartz".to_string()))
        .await
        .unwrap();
    let opened = a.base(opened[0].id).unwrap();
    wait_for_base(&opened, || {
        opened.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
}

#[tokio::test]
async fn retry_after_a_lost_reply_keeps_identical_part_bytes() {
    let (a, _) = two_devices_sharing_a_base().await;
    a.base.pause_files();
    let id = a
        .base
        .add_file(new_file("retry"), b"identical sealed bytes")
        .unwrap();
    a.base.fail_file_put_after(0);
    a.base.resume_files();
    wait_for_base(&a.base, || {
        a.base.file(id).unwrap().unwrap().status == FileStatus::Here
    })
    .await;
    let path = format!("/v1/bases/{}/files/{id}/0", a.base.id());
    let (status, body) = raw_device(&a.account).get_bytes(&path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        raw_device(&a.account).put_bytes(&path, &body).await.0,
        StatusCode::OK
    );
    let mut different = body.clone();
    different[30] ^= 1;
    assert_eq!(
        raw_device(&a.account).put_bytes(&path, &different).await.0,
        StatusCode::CONFLICT
    );
}
