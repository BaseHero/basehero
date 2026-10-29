use bh_core::{AppIdentity, Core, CoreConfig, FileSecretStore};
use bh_testkit::LocalServer;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;

fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("timeout");
    cmd.args(["30s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.join("user"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("GH_CONFIG_DIR", home.join("gh"))
        .env("BH_PASSWORD", "folder test password")
        .args(["--home", home.to_str().unwrap(), "--json"])
        .args(args);
    cmd
}

fn run(home: &Path, args: &[&str]) -> Value {
    let output = command(home, args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn setup(server: &LocalServer, home: &Path) {
    let url = server.url().to_string();
    let invite: Value = serde_json::from_slice(
        &command(home, &["admin", "invite", "--server", &url])
            .env("BH_OPERATOR_TOKEN", server.operator_token())
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    run(
        home,
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "cli-folders@example.com",
            "--name",
            "Laptop",
        ],
    );
    run(home, &["base", "create", "Personal"]);
}

fn app(home: &Path) -> Core {
    Core::open(CoreConfig {
        data_dir: home.to_path_buf(),
        secrets: Arc::new(FileSecretStore::new(home.join("secrets")).unwrap()),
    })
    .unwrap()
}

fn health(home: &Path) -> (String, String) {
    let folder = run(home, &["folder", "new", "Health"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let note = run(home, &["note", "new", "--parent", &folder, "Inside"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    (folder, note)
}

#[tokio::test(flavor = "multi_thread")]
async fn bh_approve_grants_one_folder() {
    let server = LocalServer::start();
    let full = TempDir::new().unwrap();
    let app_home = TempDir::new().unwrap();
    setup(&server, full.path());
    let (folder, note) = health(full.path());
    run(full.path(), &["sync"]);
    let core = app(app_home.path());
    let mut pending = core
        .start_connection(
            server.url().clone(),
            "cli-folders@example.com",
            AppIdentity {
                name: "Sample".into(),
                app_id: "app.example.sample".into(),
            },
        )
        .await
        .unwrap();
    let mut child = command(
        full.path(),
        &["approve", &pending.id().to_string(), "--folder", &folder],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let digits = tokio::time::timeout(Duration::from_secs(30), pending.digits())
        .await
        .unwrap()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{}", digits.as_str()).unwrap();
    writeln!(stdin, "y").unwrap();
    drop(stdin);
    let connected = tokio::time::timeout(Duration::from_secs(30), pending.wait())
        .await
        .unwrap()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Health (folder in Personal, read-write)")
    );
    connected.refresh().await.unwrap();
    assert_eq!(connected.bases().len(), 1);
    let base = connected.base(connected.bases()[0].id).unwrap();
    bh_testkit::wait_for_base(&base, || {
        base.name() == "Health" && base.get(note.parse().unwrap()).unwrap().is_some()
    })
    .await;
    assert_eq!(base.children(None).unwrap()[0].id.to_string(), note);
    core.shutdown();
}

#[test]
fn bh_app_grant_list_and_ungrant() {
    let server = LocalServer::start();
    let full = TempDir::new().unwrap();
    setup(&server, full.path());
    let (folder, _) = health(full.path());
    let creds = full.path().join("app.json");
    let connected = run(
        full.path(),
        &[
            "app",
            "connect",
            "--name",
            "Sample",
            "--new-base",
            "Sample",
            "--out",
            creds.to_str().unwrap(),
        ],
    );
    let device = connected["deviceId"].as_str().unwrap();
    let granted = run(
        full.path(),
        &["app", "grant", device, "--folder", &folder, "--read-only"],
    );
    let health_base = granted["base"].as_str().unwrap();
    assert_eq!(granted["device"], device);
    let list = run(full.path(), &["app", "list"]);
    assert_eq!(list[0]["bases"].as_array().unwrap().len(), 2);
    assert!(
        list[0]["bases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["base"] == health_base && g["mode"] == "readOnly")
    );
    assert_eq!(
        run(
            full.path(),
            &["app", "ungrant", device, "--base", health_base]
        ),
        json!({"device": device, "base": health_base})
    );
    assert_eq!(
        run(full.path(), &["app", "list"])[0]["bases"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn bh_mv_into_a_granted_folder_moves_between_bases() {
    let server = LocalServer::start();
    let full = TempDir::new().unwrap();
    setup(&server, full.path());
    let (folder, _) = health(full.path());
    let note = run(full.path(), &["note", "new", "Outside"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let creds = full.path().join("app.json");
    run(
        full.path(),
        &[
            "app",
            "connect",
            "--name",
            "Sample",
            "--folder",
            &folder,
            "--out",
            creds.to_str().unwrap(),
        ],
    );
    run(full.path(), &["mv", &note, "--into", &folder]);
    let list = run(full.path(), &["ls", "--base", "Personal", &folder]);
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == note)
        .unwrap();
    let bases = run(full.path(), &["bases"]);
    let personal = bases
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "Personal")
        .unwrap();
    assert_ne!(row["base"], personal["id"]);
    assert_eq!(
        row["base"],
        run(full.path(), &["app", "list"])[0]["bases"][0]["base"]
    );
    assert_eq!(run(full.path(), &["show", &note])["text"], "Outside");
    run(full.path(), &["mv", &note, "--base", "Personal"]);
    let listed = run(full.path(), &["ls", "--base", "Personal"]);
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == note && row["base"] == personal["id"])
    );
}

#[test]
fn bh_export_includes_granted_folders() {
    let server = LocalServer::start();
    let full = TempDir::new().unwrap();
    setup(&server, full.path());
    let (folder, _) = health(full.path());
    let creds = full.path().join("app.json");
    run(
        full.path(),
        &[
            "app",
            "connect",
            "--name",
            "Sample",
            "--folder",
            &folder,
            "--out",
            creds.to_str().unwrap(),
        ],
    );
    let out = full.path().join("export");
    run(
        full.path(),
        &[
            "export",
            "--base",
            "Personal",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(
        fs::read_dir(out.join("notes/Health"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "md"))
    );
}
