//! Locked hidden bases must not leave readable traces in ordinary device surfaces.
use bh_core::{
    AppRequest, BaseGrantRequest, Core, CoreConfig, Error, FileSecretStore, Mode, Query,
    SecretStore, SignIn,
};
use bh_testkit::{
    LocalServer, device,
    inspect::{dump_store, files_containing},
    new_signup, note_with_text, signin_for, wait_for,
};
use rusqlite::{Connection, OpenFlags};
use std::{path::Path, sync::Arc};
use zeroize::Zeroizing;

const NAME: &str = "Zebra Diary";
const FIRST: &str = "Gelato with Marguerite";
const SECOND: &str = "Pistachio";
const PASSWORD: &str = "ferry lantern quartz";
const NEEDLES: [&str; 5] = [NAME, "Gelato", "Marguerite", SECOND, PASSWORD];

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

fn local_core(dir: &Path) -> (Core, Arc<FileSecretStore>) {
    let secrets = Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap());
    let core = Core::open(CoreConfig {
        data_dir: dir.join("data"),
        secrets: secrets.clone(),
    })
    .unwrap();
    (core, secrets)
}

fn grant(base: bh_core::BaseId) -> AppRequest {
    AppRequest {
        app_name: "Reader".into(),
        app_id: None,
        bases: vec![BaseGrantRequest::Existing {
            base,
            mode: Mode::ReadOnly,
        }],
        replaces: None,
    }
}

fn rejects_sqlite_key(path: &Path, key: Option<&[u8]>) -> bool {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    if let Some(key) = key {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        db.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
            .unwrap();
    }
    db.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .is_err()
}

#[tokio::test]
async fn a_locked_base_leaves_no_readable_trace_in_ordinary_stores() {
    bh_testkit::local_only!();
    let temp = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(temp.path());
    core.set_test_device_name("mac");
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let personal = account.create_base("Personal").await.unwrap();
    let second_ordinary = account.create_base("Shared").await.unwrap();
    let hidden = account
        .create_hidden_base(NAME, pw(PASSWORD))
        .await
        .unwrap();
    let first = note_with_text(&hidden, FIRST);
    note_with_text(&hidden, SECOND);
    assert!(
        hidden
            .search("Gelato", 10)
            .unwrap()
            .iter()
            .any(|hit| hit.id == first),
        "hidden search index must hold the note before locking"
    );
    hidden.flush().await.unwrap();
    account.lock_hidden(hidden.id()).await.unwrap();
    let account_dir = temp
        .path()
        .join("data/accounts")
        .join(account.id().to_string());
    let account_key = secrets
        .get(&format!("acct.{}.dbkey", account.id()))
        .unwrap()
        .unwrap();
    let ordinary_keys: Vec<_> = [personal.id(), second_ordinary.id()]
        .iter()
        .map(|id| secrets.get(&format!("base.{id}.dbkey")).unwrap().unwrap())
        .collect();
    let account_dump = dump_store(&account_dir.join("account.sqlite"), &account_key);
    assert!(
        account_dump.contains(&hidden.id().to_string()),
        "the hidden wrapper index was inspected"
    );
    let bases_dir = account_dir.join("bases");
    let hidden_path = bases_dir.join(format!("{}.sqlite", hidden.id()));
    let ordinary_dumps: Vec<_> = std::fs::read_dir(&bases_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sqlite") && path != &hidden_path)
        .map(|path| {
            let id = path.file_stem().unwrap().to_string_lossy();
            let key = if id == personal.id().to_string() {
                &ordinary_keys[0]
            } else {
                &ordinary_keys[1]
            };
            dump_store(&path, key)
        })
        .collect();
    assert_eq!(ordinary_dumps.len(), 2, "scan every ordinary base");
    for needle in NEEDLES {
        assert!(
            !account_dump.contains(needle),
            "account store contains {needle}"
        );
        for dump in &ordinary_dumps {
            assert!(
                !dump.contains(needle),
                "ordinary base store contains {needle}"
            );
        }
    }
    assert!(
        std::fs::read_dir(temp.path().join("secrets"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(&hidden.id().to_string()))
    );
    assert!(
        secrets
            .get(&format!("base.{}.dbkey", hidden.id()))
            .unwrap()
            .is_none()
    );
    assert!(hidden_path.exists());
    assert!(rejects_sqlite_key(&hidden_path, None));
    assert!(rejects_sqlite_key(&hidden_path, Some(&account_key)));
    for key in &ordinary_keys {
        assert!(
            rejects_sqlite_key(&hidden_path, Some(key)),
            "ordinary store key opened hidden base"
        );
    }
    let cache_dir = temp.path().join("cache");
    std::fs::create_dir(&cache_dir).unwrap();
    std::fs::write(cache_dir.join("control"), b"scan-control").unwrap();
    assert_eq!(
        files_containing(&cache_dir, b"scan-control").len(),
        1,
        "cache scan must inspect files"
    );
    // Scan a real cache directory as well as every account file and local server file.
    for needle in NEEDLES {
        for dir in [
            temp.path().join("data"),
            cache_dir.clone(),
            LocalServer::shared().persist_dir().to_path_buf(),
        ] {
            assert!(
                files_containing(&dir, needle.as_bytes()).is_empty(),
                "readable {needle} in {}",
                dir.display()
            );
        }
    }
}

#[tokio::test]
async fn locked_content_is_absent_from_search_and_queries() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let personal = account.create_base("Personal").await.unwrap();
    let hidden = account
        .create_hidden_base(NAME, pw(PASSWORD))
        .await
        .unwrap();
    let id = note_with_text(&hidden, FIRST);
    let query = Query {
        ty: "core.note".into(),
        filters: vec![],
        order_by: None,
        limit: None,
    };
    assert!(
        hidden
            .search("Gelato", 10)
            .unwrap()
            .iter()
            .any(|hit| hit.id == id)
    );
    assert!(
        hidden
            .query(&query)
            .unwrap()
            .iter()
            .any(|item| item.id == id)
    );
    assert!(personal.search("Gelato", 10).unwrap().is_empty());
    assert!(personal.query(&query).unwrap().is_empty());
    account.lock_hidden(hidden.id()).await.unwrap();
    assert!(personal.search("Gelato", 10).unwrap().is_empty());
    assert!(personal.query(&query).unwrap().is_empty());
    assert!(matches!(account.base(hidden.id()), Err(Error::NotFound)));
    assert!(account.bases().iter().all(|base| base.id != hidden.id()));
}

#[tokio::test]
async fn errors_never_carry_hidden_names_or_passwords() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let hidden = account
        .create_hidden_base(NAME, pw(PASSWORD))
        .await
        .unwrap();
    note_with_text(&hidden, FIRST);
    account.lock_hidden(hidden.id()).await.unwrap();
    let errors = [
        account
            .unlock_hidden(pw("incorrect Pistachio"))
            .await
            .unwrap_err(),
        hidden.children(None).unwrap_err(),
        account.connect_app(grant(hidden.id())).await.unwrap_err(),
    ];
    assert!(matches!(errors[0], Error::NothingUnlocked));
    assert!(matches!(errors[2], Error::Forbidden));
    // Stop only a test-owned local server to exercise the offline create error.
    let mut server = LocalServer::start();
    let remote = bh_testkit::device_on_server("offline", &bh_core::Clock::system(), &server);
    let (offline, _) = remote
        .sign_up(bh_core::SignUp {
            server: server.url(),
            invite: bh_testkit::invite(&server),
            ..new_signup()
        })
        .await
        .unwrap();
    server.stop();
    let offline_error = offline
        .create_hidden_base("Pistachio", pw(PASSWORD))
        .await
        .unwrap_err();
    assert!(matches!(offline_error, Error::Network(_)));
    for error in errors.iter().chain([offline_error].iter()) {
        for needle in NEEDLES {
            assert!(
                !format!("{error} {error:?}").contains(needle),
                "error exposes {needle}"
            );
        }
    }
}

#[tokio::test]
async fn hidden_bases_are_never_granted_to_apps() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let personal = account.create_base("Personal").await.unwrap();
    let credentials = account.connect_app(grant(personal.id())).await.unwrap();
    let app = device("app").install_app(credentials).await.unwrap();
    let hidden = account
        .create_hidden_base(NAME, pw(PASSWORD))
        .await
        .unwrap();
    for locked in [false, true] {
        if locked {
            account.lock_hidden(hidden.id()).await.unwrap();
        }
        let before = account.test_request_count("v1/devices");
        assert!(matches!(
            account.connect_app(grant(hidden.id())).await,
            Err(Error::Forbidden)
        ));
        assert_eq!(
            account.test_request_count("v1/devices"),
            before,
            "refusal must precede registration"
        );
        assert!(
            account
                .apps()
                .iter()
                .all(|app| app.bases.iter().all(|grant| grant.base != hidden.id()))
        );
        assert!(app.bases().iter().all(|base| base.id != hidden.id()));
        assert!(matches!(app.base(hidden.id()), Err(Error::NotFound)));
    }
}

#[tokio::test]
async fn removal_erases_hidden_stores() {
    let (a, kit) = device("a").sign_up(new_signup()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let (core, secrets) = local_core(temp.path());
    let b = core
        .sign_in(SignIn {
            device_name: "b".into(),
            ..signin_for(&a)
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let hidden = a.create_hidden_base(NAME, pw(PASSWORD)).await.unwrap();
    note_with_text(&hidden, FIRST);
    hidden.flush().await.unwrap();
    b.refresh().await.unwrap();
    b.unlock_hidden(pw(PASSWORD)).await.unwrap();
    let b_hidden = b.base(hidden.id()).unwrap();
    wait_for(|| b_hidden.name() == NAME).await;
    b.lock_hidden(hidden.id()).await.unwrap();
    let account_dir = temp.path().join("data/accounts").join(b.id().to_string());
    let hidden_path = account_dir
        .join("bases")
        .join(format!("{}.sqlite", hidden.id()));
    assert!(
        hidden_path.exists(),
        "removal test must start with a hidden store"
    );
    a.remove_device(b.device_id()).await.unwrap();
    wait_for(|| core.accounts().is_empty()).await;
    assert!(!hidden_path.exists());
    assert!(!account_dir.exists());
    assert!(
        secrets
            .get(&format!("acct.{}.dbkey", b.id()))
            .unwrap()
            .is_none()
    );
    assert!(
        secrets
            .get(&format!("base.{}.dbkey", hidden.id()))
            .unwrap()
            .is_none()
    );
}
