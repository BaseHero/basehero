use assert_cmd::Command;
use bh_core::{Core, CoreConfig, FileSecretStore};
use bh_testkit::{
    LocalServer, TEST_PASSWORD,
    backup::{everything_on_server, normalized_export},
};
use serde_json::Value;
use std::{fs, path::Path, process::Output, sync::Arc};
use tempfile::TempDir;

const PASSWORD: &str = "test CLI password";

fn output(home: &Path, args: &[&str], password: Option<&str>, token: Option<&str>) -> Output {
    output_with_hidden(home, args, password, token, None)
}

fn output_with_hidden(
    home: &Path,
    args: &[&str],
    password: Option<&str>,
    token: Option<&str>,
    hidden: Option<&str>,
) -> Output {
    let mut command = Command::new("timeout");
    command
        .args(["60s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.join("isolated-config"))
        .env("GH_CONFIG_DIR", home.join("isolated-gh"))
        .args(["--home", home.to_str().unwrap(), "--json"])
        .args(args);
    if let Some(password) = password {
        command.env("BH_PASSWORD", password);
    }
    if let Some(token) = token {
        command.env("BH_OPERATOR_TOKEN", token);
    }
    if let Some(hidden) = hidden {
        command.env("BH_HIDDEN_PASSWORD", hidden);
    }
    command.output().unwrap()
}

fn run(home: &Path, args: &[&str], password: Option<&str>, token: Option<&str>) -> Value {
    let result = output(home, args, password, token);
    assert!(
        result.status.success(),
        "{}: {}",
        args[0],
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn signup(server: &LocalServer, home: &Path, email: &str) -> Value {
    let url = server.url().to_string();
    let invite = run(
        home,
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    run(
        home,
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            email,
            "--name",
            "Owner",
        ],
        Some(PASSWORD),
        None,
    )
}

fn prepared(server: &LocalServer, home: &Path, folder: &Path) -> (Value, String) {
    let registration = signup(server, home, "backups-cli@example.com");
    let base = run(home, &["base", "create", "Travel"], None, None);
    let id = base["id"].as_str().unwrap().to_owned();
    run(
        home,
        &["note", "new", "--base", &id, "Ferry at 9"],
        None,
        None,
    );
    fs::create_dir(folder).unwrap();
    run(
        home,
        &["backup", "write", folder.to_str().unwrap()],
        None,
        None,
    );
    (registration, id)
}

#[test]
fn the_whole_account_survives_losing_the_server() {
    let mut server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let core = Core::open(CoreConfig {
        data_dir: home.path().to_path_buf(),
        secrets: Arc::new(FileSecretStore::new(home.path().join("secrets")).unwrap()),
    })
    .unwrap();
    core.set_test_device_name("backup source");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let fixture = runtime.block_on(everything_on_server(&core, &server));
    let kit = fixture.kit.display();
    let hidden_password = fixture.extra_password.clone();
    let names = fixture
        .account
        .bases()
        .into_iter()
        .map(|base| (base.id.to_string(), base.name))
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 3);
    let original_mount = fixture.account.mounts()[0];
    let note = fixture.note.to_string();
    let personal_id = names
        .iter()
        .find(|(_, name)| name == "Personal")
        .unwrap()
        .0
        .parse()
        .unwrap();
    let linked = bh_testkit::note_with_text(
        &fixture.account.base(personal_id).unwrap(),
        &format!("bh://notes/{note}"),
    );
    let image = fixture.image.to_string();
    core.shutdown();
    drop(fixture);
    drop(core);

    let backup_dir = TempDir::new().unwrap();
    let backup = backup_dir.path();
    let written = output_with_hidden(
        home.path(),
        &["--unlock", "backup", "write", backup.to_str().unwrap()],
        None,
        None,
        Some(&hidden_password),
    );
    assert!(
        written.status.success(),
        "backup write: {}",
        String::from_utf8_lossy(&written.stderr)
    );
    let written: Value = serde_json::from_slice(&written.stdout).unwrap();
    assert!(written["run"].is_string());
    let listings = run(
        home.path(),
        &["backup", "list", backup.to_str().unwrap()],
        None,
        None,
    );
    assert_eq!(listings.as_array().unwrap().len(), 1);
    let original = TempDir::new().unwrap();
    for (id, name) in &names {
        let path = original.path().join(name);
        let args = [
            "--unlock",
            "export",
            "--base",
            id,
            "--out",
            path.to_str().unwrap(),
        ];
        let result = output_with_hidden(home.path(), &args, None, None, Some(&hidden_password));
        assert!(
            result.status.success(),
            "export {name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let persist = server.persist_dir().to_path_buf();
    server.stop();
    fs::remove_dir_all(persist).unwrap();
    drop(server);

    let offline_home = TempDir::new().unwrap();
    let offline = TempDir::new().unwrap();
    let result = output_with_hidden(
        offline_home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            &kit,
            "--out",
            offline.path().to_str().unwrap(),
        ],
        Some(TEST_PASSWORD),
        None,
        Some(&hidden_password),
    );
    assert!(
        result.status.success(),
        "offline restore: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["exports"].as_array().unwrap().len(), names.len());
    assert!(!offline_home.path().join("secrets").exists());
    for (_, name) in &names {
        assert_eq!(
            normalized_export(&original.path().join(name), false),
            normalized_export(&offline.path().join(name), false),
            "offline {name}"
        );
    }
    let files = normalized_export(&original.path().join("Personal"), false);
    for name in ["photo.png", "nine-megabytes.bin"] {
        let path = files
            .keys()
            .find(|path| path.file_name().is_some_and(|file| file == name))
            .unwrap_or_else(|| panic!("missing {name} in {files:?}"));
        assert_eq!(
            fs::read(original.path().join("Personal").join(path)).unwrap(),
            fs::read(offline.path().join("Personal").join(path)).unwrap()
        );
    }

    let fresh = LocalServer::start();
    let restored_home = TempDir::new().unwrap();
    let url = fresh.url().to_string();
    let invite = run(
        restored_home.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(fresh.operator_token()),
    );
    let signup = output_with_hidden(
        restored_home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            &kit,
            "--signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "whole-restore@example.test",
            "--name",
            "New device",
        ],
        Some(TEST_PASSWORD),
        None,
        Some(&hidden_password),
    );
    assert!(
        signup.status.success(),
        "signup restore: {}",
        String::from_utf8_lossy(&signup.stderr)
    );
    let signup: Value = serde_json::from_slice(&signup.stdout).unwrap();
    assert_eq!(signup["restored"].as_array().unwrap().len(), names.len());
    let new_kit = signup["kit"]
        .as_str()
        .filter(|kit| !kit.is_empty())
        .unwrap();
    let second_home = TempDir::new().unwrap();
    run(
        second_home.path(),
        &[
            "signin",
            "--server",
            &url,
            "--email",
            "whole-restore@example.test",
            "--name",
            "Second device",
            "--kit",
            new_kit,
        ],
        Some(TEST_PASSWORD),
        None,
    );
    let restored_home = second_home;
    run(restored_home.path(), &["sync"], None, None);
    let mapped = |old: &str| -> String {
        signup["restored"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pair| pair[0] == old)
            .unwrap()[1]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let bases = run(restored_home.path(), &["bases"], None, None);
    assert!(
        !bases
            .as_array()
            .unwrap()
            .iter()
            .any(|base| base["hidden"] == true)
    );
    let unlocked = output_with_hidden(
        restored_home.path(),
        &["hidden", "unlock"],
        None,
        None,
        Some(&hidden_password),
    );
    assert!(
        unlocked.status.success(),
        "hidden unlock: stdout={} stderr={}",
        String::from_utf8_lossy(&unlocked.stdout),
        String::from_utf8_lossy(&unlocked.stderr)
    );
    let visible = output_with_hidden(
        restored_home.path(),
        &["--unlock", "bases"],
        None,
        None,
        Some(&hidden_password),
    );
    assert!(
        visible.status.success(),
        "bases after unlock: {}",
        String::from_utf8_lossy(&visible.stderr)
    );
    let bases = serde_json::from_slice::<Value>(&visible.stdout).unwrap();
    let restored_mount = bases
        .as_array()
        .unwrap()
        .iter()
        .find(|base| base["id"] == mapped(&original_mount.base.to_string()))
        .unwrap();
    assert_eq!(
        restored_mount["mount"]["parent"],
        mapped(&original_mount.parent.to_string())
    );
    assert_eq!(
        restored_mount["mount"]["folder"],
        original_mount.folder.to_string()
    );
    let mounted_items = run(
        restored_home.path(),
        &["ls", "--base", &mapped(&original_mount.base.to_string())],
        None,
        None,
    );
    assert!(
        !mounted_items.as_array().unwrap().is_empty(),
        "the mounted folder must still show its content"
    );
    let after = TempDir::new().unwrap();
    for (id, name) in &names {
        let restored_id = mapped(id);
        let dest = after.path().join(name);
        let result = output_with_hidden(
            restored_home.path(),
            &[
                "--unlock",
                "export",
                "--base",
                &restored_id,
                "--out",
                dest.to_str().unwrap(),
            ],
            None,
            None,
            Some(&hidden_password),
        );
        assert!(
            result.status.success(),
            "new account export {name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            normalized_export(&original.path().join(name), true),
            normalized_export(&dest, true),
            "new account {name}"
        );
    }
    let personal = mapped(&names.iter().find(|(_, name)| name == "Personal").unwrap().0);
    let shown = run(restored_home.path(), &["show", &note], None, None);
    assert!(shown["text"].as_str().unwrap().contains("Trip notes"));
    assert_eq!(shown["id"], note);
    assert_eq!(
        run(
            restored_home.path(),
            &["show", &linked.to_string()],
            None,
            None
        )["text"],
        format!("bh://notes/{note}")
    );
    assert!(
        fs::read_to_string(after.path().join("Personal/notes/Trip notes.md"))
            .unwrap()
            .contains("Trip notes")
    );
    assert!(
        normalized_export(&after.path().join("Personal"), true)
            .keys()
            .any(|path| path.file_name().is_some_and(|name| name == "photo.png")),
        "image {image} must remain readable"
    );
    assert!(
        bases
            .as_array()
            .unwrap()
            .iter()
            .any(|base| base["id"] == personal)
    );
}

#[test]
fn restore_out_exports_later_bases_before_reporting_all_missing_files() {
    let core = bh_testkit::device("missing exports");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let fixture = runtime.block_on(bh_testkit::backup::everything(&core));
    let folder = TempDir::new().unwrap();
    fixture
        .account
        .set_backup(Some(bh_core::BackupLocation::Path {
            path: folder.path().to_path_buf(),
            label: "Backup".into(),
        }))
        .unwrap();
    runtime.block_on(fixture.account.backup_now()).unwrap();
    let personal = fixture
        .account
        .bases()
        .into_iter()
        .find(|base| base.name == "Personal")
        .unwrap();
    for id in [fixture.image, fixture.big_file] {
        fs::remove_file(folder.path().join(format!(
            "{}/{}/files/{}/{id}/0",
            fixture.account.id(),
            fixture.account.device_id(),
            personal.id
        )))
        .unwrap();
    }
    let home = TempDir::new().unwrap();
    let out = TempDir::new().unwrap();
    let result = output_with_hidden(
        home.path(),
        &[
            "backup",
            "restore",
            folder.path().to_str().unwrap(),
            "--kit",
            &fixture.kit.display(),
            "--base",
            "Personal",
            "--base",
            "Diary",
            "--out",
            out.path().to_str().unwrap(),
        ],
        Some(TEST_PASSWORD),
        None,
        Some(&fixture.extra_password),
    );
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(error.contains(&fixture.image.to_string()), "{error}");
    assert!(error.contains(&fixture.big_file.to_string()), "{error}");
    assert!(out.path().join("Diary/manifest.json").exists());
}

#[test]
fn backup_write_then_restore_out_matches_export_with_no_server() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, base) = prepared(&server, home.path(), &backup);
    let exported = home.path().join("export");
    run(
        home.path(),
        &[
            "export",
            "--base",
            &base,
            "--out",
            exported.to_str().unwrap(),
        ],
        None,
        None,
    );
    drop(server);
    let empty_home = TempDir::new().unwrap();
    let out = home.path().join("restored");
    let result = run(
        empty_home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ],
        Some(PASSWORD),
        None,
    );
    assert!(result["exports"].as_array().is_some());
    assert_eq!(
        fs::read(out.join("Travel/notes/Ferry at 9.md")).unwrap(),
        fs::read(exported.join("notes/Ferry at 9.md")).unwrap()
    );
    let mut restored: Value =
        serde_json::from_slice(&fs::read(out.join("Travel/manifest.json")).unwrap()).unwrap();
    let mut original: Value =
        serde_json::from_slice(&fs::read(exported.join("manifest.json")).unwrap()).unwrap();
    restored.as_object_mut().unwrap().remove("exportedAt");
    original.as_object_mut().unwrap().remove("exportedAt");
    assert_eq!(restored, original);
    assert!(!empty_home.path().join("secrets").exists());
}

#[test]
fn backup_list_shows_the_email_without_a_password() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, _) = prepared(&server, home.path(), &backup);
    let empty_home = TempDir::new().unwrap();
    let rows = run(
        empty_home.path(),
        &["backup", "list", backup.to_str().unwrap()],
        None,
        None,
    );
    assert_eq!(rows[0]["email"], "backups-cli@example.com");
    assert_eq!(rows[0]["account"], registration["accountId"]);
    assert!(rows[0]["device"].as_str().is_some());
    assert!(rows[0]["writtenAt"].as_i64().is_some());
}

#[test]
fn restore_check_names_a_damaged_file_and_exits_nonzero() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, _) = prepared(&server, home.path(), &backup);
    let root = backup.join(registration["accountId"].as_str().unwrap());
    let device = fs::read_dir(root).unwrap().next().unwrap().unwrap().path();
    let log = fs::read_dir(device.join("log"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(&log, b"damaged").unwrap();
    let checked = output(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--check",
        ],
        Some(PASSWORD),
        None,
    );
    assert!(!checked.status.success());
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(
        text.contains(log.file_name().unwrap().to_str().unwrap()),
        "{text}"
    );
}

#[test]
fn restore_check_reports_a_missing_snapshot_and_exits_nonzero() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, _) = prepared(&server, home.path(), &backup);
    let root = backup.join(registration["accountId"].as_str().unwrap());
    let device = fs::read_dir(root).unwrap().next().unwrap().unwrap().path();
    let snapshot_dir = fs::read_dir(device.join("snapshots"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let snapshot = fs::read_dir(snapshot_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(snapshot).unwrap();
    let checked = output(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--check",
        ],
        Some(PASSWORD),
        None,
    );
    assert_eq!(checked.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(report["opened"], false);
    assert_eq!(report["missing"], 1);
}

#[test]
fn restore_at_an_earlier_time_gives_that_points_content() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, base) = prepared(&server, home.path(), &backup);
    let listing = run(
        home.path(),
        &["backup", "list", backup.to_str().unwrap()],
        None,
        None,
    );
    let earlier = listing[0]["writtenAt"].as_i64().unwrap();
    let run_name = chrono::DateTime::from_timestamp_millis(earlier)
        .unwrap()
        .format("%Y%m%dT%H%M%S%3fZ")
        .to_string();
    let notes = run(home.path(), &["ls", "--base", &base], None, None);
    run(
        home.path(),
        &[
            "note",
            "append",
            notes[0]["id"].as_str().unwrap(),
            "Bring tickets",
        ],
        None,
        None,
    );
    run(
        home.path(),
        &["backup", "write", backup.to_str().unwrap()],
        None,
        None,
    );
    let out = home.path().join("earlier");
    run(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--at",
            &run_name,
            "--out",
            out.to_str().unwrap(),
        ],
        Some(PASSWORD),
        None,
    );
    assert_eq!(
        fs::read_to_string(out.join("Travel/notes/Ferry at 9.md")).unwrap(),
        "Ferry at 9\n"
    );
    let before = output(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--at",
            &(earlier - 1).to_string(),
            "--check",
        ],
        Some(PASSWORD),
        None,
    );
    assert!(!before.status.success());
    assert!(String::from_utf8_lossy(&before.stderr).contains(&earlier.to_string()));
}

#[test]
fn restore_with_signup_makes_a_new_account_with_the_backups_bases() {
    let server = LocalServer::start();
    let source = TempDir::new().unwrap();
    let backup = source.path().join("backup");
    let (registration, _) = prepared(&server, source.path(), &backup);
    let target = TempDir::new().unwrap();
    let url = server.url().to_string();
    let invite = run(
        target.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    let result = run(
        target.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "new-backups-cli@example.com",
            "--name",
            "New",
        ],
        Some(PASSWORD),
        None,
    );
    assert_ne!(result["accountId"], registration["accountId"]);
    assert!(result["kit"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        run(target.path(), &["bases"], None, None)
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["name"].as_str().unwrap().starts_with("Travel (restored "))
    );
    let second = TempDir::new().unwrap();
    run(
        second.path(),
        &[
            "signin",
            "--server",
            &url,
            "--email",
            "new-backups-cli@example.com",
            "--name",
            "Another device",
            "--kit",
            result["kit"].as_str().unwrap(),
        ],
        Some(PASSWORD),
        None,
    );
    run(second.path(), &["sync"], None, None);
    assert!(
        run(second.path(), &["bases"], None, None)
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["name"].as_str().unwrap().starts_with("Travel (restored "))
    );
}

#[test]
fn signup_refuses_a_base_filter() {
    let server = LocalServer::start();
    let source = TempDir::new().unwrap();
    let backup = source.path().join("backup");
    let (registration, _) = prepared(&server, source.path(), &backup);
    let target = TempDir::new().unwrap();
    let url = server.url().to_string();
    let invite = run(
        target.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    let result = output(
        target.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--base",
            "Travel",
            "--signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "filtered-backups-cli@example.com",
            "--name",
            "New",
        ],
        Some(PASSWORD),
        None,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--base"));
    assert!(!target.path().join("secrets").exists());
}

#[test]
fn signup_refuses_a_home_with_an_account() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, _) = prepared(&server, home.path(), &backup);
    let url = server.url().to_string();
    let invite = run(
        home.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    let result = output(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "duplicate-backups-cli@example.com",
            "--name",
            "New",
        ],
        Some(PASSWORD),
        None,
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("empty home"));
    assert_eq!(
        run(home.path(), &["bases"], None, None)
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn restore_into_this_account_adds_restored_bases() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, _) = prepared(&server, home.path(), &backup);
    let result = run(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
        ],
        Some(PASSWORD),
        None,
    );
    assert_eq!(result["restored"].as_array().unwrap().len(), 1);
    let bases = run(home.path(), &["bases"], None, None);
    assert!(
        bases
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["name"].as_str().unwrap().starts_with("Travel (restored "))
    );
}

#[test]
fn hidden_bases_open_with_one_password_per_line() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let registration = signup(&server, home.path(), "hidden-backups-cli@example.com");
    let hidden = "hidden CLI passphrase beyond sixteen characters";
    let created = output_with_hidden(
        home.path(),
        &["hidden", "create", "Private"],
        None,
        None,
        Some(hidden),
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let id = serde_json::from_slice::<Value>(&created.stdout).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let note = output_with_hidden(
        home.path(),
        &[
            "--unlock",
            "note",
            "new",
            "--base",
            &id,
            "Offline private note",
        ],
        None,
        None,
        Some(hidden),
    );
    assert!(
        note.status.success(),
        "{}",
        String::from_utf8_lossy(&note.stderr)
    );
    let backup = home.path().join("backup");
    fs::create_dir(&backup).unwrap();
    let write = output_with_hidden(
        home.path(),
        &["--unlock", "backup", "write", backup.to_str().unwrap()],
        None,
        None,
        Some(hidden),
    );
    assert!(
        write.status.success(),
        "{}",
        String::from_utf8_lossy(&write.stderr)
    );
    let out = home.path().join("hidden-out");
    let restore = output_with_hidden(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ],
        Some(PASSWORD),
        None,
        Some(&format!("wrong extra password\n{hidden}")),
    );
    assert!(
        restore.status.success(),
        "{}",
        String::from_utf8_lossy(&restore.stderr)
    );
    assert_eq!(
        fs::read_to_string(out.join("Private/notes/Offline private note.md")).unwrap(),
        "Offline private note\n"
    );
}

#[test]
fn backup_write_reports_a_missing_folder() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    signup(&server, home.path(), "folder-cli@example.com");
    let folder = home.path().join("not-mounted");
    let result = output(
        home.path(),
        &["backup", "write", folder.to_str().unwrap()],
        None,
        None,
    );
    assert!(!result.status.success());
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("Unreachable"));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report.get("run").is_some());
    assert!(report.get("objects").is_some());
    assert!(report.get("parts").is_some());
    assert!(report.get("snapshots").is_some());
    assert_eq!(report["status"]["problem"]["kind"], "unreachable");
}

#[test]
fn restore_check_prints_points_and_counts_and_accepts_rfc3339() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let backup = home.path().join("backup");
    let (registration, _) = prepared(&server, home.path(), &backup);
    let at = run(
        home.path(),
        &["backup", "list", backup.to_str().unwrap()],
        None,
        None,
    )[0]["writtenAt"]
        .as_i64()
        .unwrap();
    let rfc3339 = chrono::DateTime::from_timestamp_millis(at)
        .unwrap()
        .to_rfc3339();
    let result = run(
        home.path(),
        &[
            "backup",
            "restore",
            backup.to_str().unwrap(),
            "--kit",
            registration["kit"].as_str().unwrap(),
            "--at",
            &rfc3339,
            "--check",
        ],
        Some(PASSWORD),
        None,
    );
    assert_eq!(result["at"], at);
    assert_eq!(result["points"][0], at);
    assert_eq!(result["opened"], true);
    assert_eq!(result["bases"][0]["unreadable"], 0);
    assert_eq!(result["bases"][0]["missingFiles"], serde_json::json!([]));
}

#[test]
fn the_version_restore_command_still_works() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    signup(&server, home.path(), "versions-backups-cli@example.com");
    use bh_core::{Clock, Core, CoreConfig, FileSecretStore};
    use std::{sync::Arc, time::Duration};
    let (clock, manual) = Clock::manual();
    let core = Core::open_with_clock(
        CoreConfig {
            data_dir: home.path().to_path_buf(),
            secrets: Arc::new(FileSecretStore::new(home.path().join("secrets")).unwrap()),
        },
        clock,
    )
    .unwrap();
    let account = core.account(core.accounts()[0].id).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (id, note_id, seq) = {
        let base = runtime.block_on(account.create_base("History")).unwrap();
        let note_id = bh_testkit::note_with_text(&base, "Old");
        runtime.block_on(async {
            base.flush().await.unwrap();
            manual.advance(Duration::from_secs(6 * 60));
            base.tick_versions().await.unwrap();
        });
        let seq = runtime.block_on(base.versions(note_id, None, 1)).unwrap().0[0].seq;
        let note = base.note(note_id).unwrap();
        note.apply(10, &bh_testkit::append_text(&note.state(), "New"))
            .unwrap();
        runtime.block_on(base.flush()).unwrap();
        (base.id().to_string(), note_id.to_string(), seq)
    };
    core.shutdown();
    drop(account);
    drop(core);
    let restored = run(
        home.path(),
        &["restore", "--base", &id, &note_id, &seq.to_string()],
        None,
        None,
    );
    assert_eq!(restored["id"], note_id);
    assert_eq!(
        run(home.path(), &["show", &note_id], None, None)["text"],
        "Old"
    );
}
