use assert_cmd::Command;
use bh_testkit::LocalServer;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Stdio},
    sync::{Arc, Mutex},
};
use tempfile::TempDir;

#[cfg(feature = "test-support")]
fn scripted(home: &Path, args: &[&str], steps: Value, readers: Option<Value>) -> Value {
    let script = home.join("script.json");
    fs::write(&script, steps.to_string()).unwrap();
    let mut cmd = Command::new("timeout");
    cmd.args(["30s", env!("CARGO_BIN_EXE_bh")]);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.join("isolated-config"))
        .env("BH_TEST_MODEL_SCRIPT", &script)
        .args(["--home", home.to_str().unwrap(), "--json", "hero"])
        .args(args);
    if let Some(readers) = readers {
        cmd.env("BH_TEST_APP_READERS", readers.to_string());
    }
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "scripted hero failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn output(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new("timeout")
        .args(["30s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.join("isolated-config"))
        .env("GH_CONFIG_DIR", home.join("isolated-gh"))
        .args(["--home", home.to_str().unwrap(), "--json"])
        .args(args)
        .output()
        .unwrap()
}

fn enrolled(server: &LocalServer, home: &Path, email: &str) -> Value {
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
        Some("test CLI password"),
        None,
    )
}

fn run(home: &Path, args: &[&str], password: Option<&str>, token: Option<&str>) -> Value {
    let mut cmd = Command::new("timeout");
    cmd.args(["30s", env!("CARGO_BIN_EXE_bh")]);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").expect("PATH"))
        .env("HOME", home.join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.join("isolated-config"))
        .env("GH_CONFIG_DIR", home.join("isolated-gh"))
        .args(["--home", home.to_str().unwrap(), "--json"])
        .args(args);
    if let Some(password) = password {
        cmd.env("BH_PASSWORD", password);
    }
    if let Some(token) = token {
        cmd.env("BH_OPERATOR_TOKEN", token);
    }
    let output = cmd.output().expect("run CLI");
    // Never print the command or its output on failure: sign-in passes a kit,
    // and signup deliberately returns one.
    assert!(output.status.success(), "CLI failed with {}", output.status);
    serde_json::from_slice(&output.stdout).expect("one JSON response")
}

#[test]
fn bh_versions_and_restore_work_headless() {
    use bh_core::{Clock, Core, CoreConfig, FileSecretStore};
    use bh_testkit::{append_text, note_with_text};
    use std::{sync::Arc, time::Duration};

    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let _ = enrolled(&server, home.path(), "history-cli@example.com");
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
    let (base_id, id, seq) = {
        let base = runtime.block_on(account.create_base("History")).unwrap();
        let id = note_with_text(&base, "Ferry at 9");
        runtime.block_on(async {
            base.flush().await.unwrap();
            manual.advance(Duration::from_secs(6 * 60));
            base.tick_versions().await.unwrap();
        });
        let seq = runtime.block_on(base.versions(id, None, 1)).unwrap().0[0].seq;
        let note = base.note(id).unwrap();
        note.apply(10, &append_text(&note.state(), "Ferry at 10"))
            .unwrap();
        runtime.block_on(base.flush()).unwrap();
        (base.id().to_string(), id.to_string(), seq)
    };
    core.shutdown();
    drop(account);
    drop(core);
    let listed = output(home.path(), &["versions", "--base", &base_id, &id]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listing["versions"][0]["seq"], seq);
    let restored = output(
        home.path(),
        &["restore", "--base", &base_id, &id, &seq.to_string()],
    );
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(
        run(home.path(), &["show", &id], None, None)["text"],
        "Ferry at 9"
    );
}

#[test]
fn json_errors_are_machine_readable_without_credentials() {
    let home = TempDir::new().unwrap();
    let output = Command::new("timeout")
        .args(["30s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.path().join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.path().join("isolated-config"))
        .args(["--home", home.path().to_str().unwrap(), "--json", "bases"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"],
        "invalid: expected exactly one signed-in account in this home"
    );
}

#[test]
fn invalid_arguments_with_json_return_json_on_stderr() {
    let home = TempDir::new().unwrap();
    let output = Command::new("timeout")
        .args(["30s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.path().join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.path().join("isolated-config"))
        .args(["admin", "invite", "--json", "--not-an-option"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("JSON argument error");
    assert!(error["error"].as_str().unwrap().contains("--not-an-option"));
}

#[test]
fn help_and_version_stay_plain_text_with_json() {
    let home = TempDir::new().unwrap();
    for (flag, expected) in [("--help", "Usage:"), ("--version", "bh ")] {
        let output = Command::new("timeout")
            .args(["30s", env!("CARGO_BIN_EXE_bh")])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("HOME", home.path().join("isolated-user"))
            .env("XDG_CONFIG_HOME", home.path().join("isolated-config"))
            .args(["--json", flag])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8_lossy(&output.stdout).contains(expected));
    }
}

#[test]
fn admin_invite_refuses_non_loopback_http_before_request() {
    let home = TempDir::new().unwrap();
    let output = Command::new("timeout")
        .args(["30s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.path().join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.path().join("isolated-config"))
        .env("BH_OPERATOR_TOKEN", "test operator token")
        .args([
            "--json",
            "admin",
            "invite",
            "--server",
            "http://192.0.2.1:1",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("JSON URL error");
    assert_eq!(
        error["error"],
        "invalid: admin invite requires HTTPS or loopback HTTP"
    );
}

#[test]
fn two_homes_share_a_note_through_the_cli() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let url = server.url().to_string();
    let invite = run(
        a.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    let signup = run(
        a.path(),
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "cli@example.com",
            "--name",
            "Laptop",
        ],
        Some("test CLI password"),
        None,
    );
    let kit = signup["kit"].as_str().expect("kit");
    assert!(!kit.is_empty());
    run(
        b.path(),
        &[
            "signin",
            "--server",
            &url,
            "--email",
            "cli@example.com",
            "--name",
            "Desktop",
            "--kit",
            kit,
        ],
        Some("test CLI password"),
        None,
    );
    let base = run(a.path(), &["base", "create", "Travel"], None, None);
    let base_id = base["id"].as_str().unwrap();
    let note = run(
        a.path(),
        &["note", "new", "--base", base_id, "Ferry at 9"],
        None,
        None,
    );
    let id = note["id"].as_str().unwrap();
    run(a.path(), &["sync"], None, None);
    run(b.path(), &["sync"], None, None);
    let bases = run(b.path(), &["bases"], None, None);
    assert!(
        bases
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["name"] == "Travel")
    );
    let list = run(b.path(), &["ls", "--base", base_id], None, None);
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == id && n["title"] == "Ferry at 9")
    );
    let shown = run(b.path(), &["show", id], None, None);
    assert_eq!(shown["text"], "Ferry at 9");
    let hits = run(b.path(), &["search", "Ferry"], None, None);
    assert_eq!(hits.as_array().unwrap().len(), 1);
    assert_eq!(hits[0]["title"], "Ferry at 9");
}

#[test]
fn bh_export_writes_a_base_another_home_made() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let url = server.url().to_string();
    let invite = run(
        a.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    let signup = run(
        a.path(),
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "export-cli@example.com",
            "--name",
            "Laptop",
        ],
        Some("test CLI password"),
        None,
    );
    run(
        b.path(),
        &[
            "signin",
            "--server",
            &url,
            "--email",
            "export-cli@example.com",
            "--name",
            "Desktop",
            "--kit",
            signup["kit"].as_str().unwrap(),
        ],
        Some("test CLI password"),
        None,
    );
    let base = run(a.path(), &["base", "create", "Travel"], None, None);
    let id = base["id"].as_str().unwrap();
    let note = run(
        a.path(),
        &["note", "new", "--base", id, "Ferry"],
        None,
        None,
    );
    let payload = a.path().join("ticket.txt");
    fs::write(&payload, b"a plain ticket").unwrap();
    let added = run(
        a.path(),
        &[
            "file",
            "add",
            "--base",
            id,
            "--parent",
            note["id"].as_str().unwrap(),
            payload.to_str().unwrap(),
        ],
        None,
        None,
    );
    assert!(added["id"].as_str().is_some());
    run(a.path(), &["sync"], None, None);
    run(b.path(), &["sync"], None, None);
    let dir = b.path().join("export");
    let result = run(
        b.path(),
        &["export", "--base", id, "--out", dir.to_str().unwrap()],
        None,
        None,
    );
    assert_eq!(result["missingFiles"], json!([]));
    assert_eq!(
        fs::read(dir.join("notes/Ferry/ticket.txt")).unwrap(),
        b"a plain ticket"
    );
    assert_eq!(
        fs::read_to_string(dir.join("notes/Ferry.md")).unwrap(),
        "Ferry\n"
    );
    assert!(serde_json::from_slice::<Value>(&fs::read(dir.join("manifest.json")).unwrap()).is_ok());
}

#[test]
fn bh_export_help_says_hidden_bases_need_unlock() {
    let home = TempDir::new().unwrap();
    let result = output(home.path(), &["export", "--help"]);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("--unlock"));
}

#[cfg(feature = "test-support")]
#[test]
fn hero_ask_prints_the_reply_and_created_notes() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let url = server.url().to_string();
    let invite = run(
        home.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    run(
        home.path(),
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "hero-cli@example.com",
            "--name",
            "Laptop",
        ],
        Some("test CLI password"),
        None,
    );
    run(home.path(), &["base", "create", "Trips"], None, None);
    run(home.path(), &["note", "new", "Ferry at 9:10"], None, None);
    let result = scripted(
        home.path(),
        &["ask", "Make a packing list"],
        json!([
            {"tool":"search", "arguments":{"text":"ferry"}},
            {"tool":"create_note", "arguments":{"title":"Packing list", "text":"Tickets\nWater\nJacket"}},
            {"text":"Made it."}
        ]),
        None,
    );
    assert_eq!(result["text"], "Made it.");
    assert_eq!(result["state"], "done");
    let created = result["created"].as_array().unwrap();
    assert_eq!(created.len(), 1);
    assert!(created[0].as_str().is_some());
    let list = run(home.path(), &["ls"], None, None);
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == created[0] && n["title"] == "Packing list")
    );
    let hits = run(home.path(), &["search", "Packing list"], None, None);
    assert!(
        hits.as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == created[0])
    );
}

#[cfg(feature = "test-support")]
#[test]
fn hero_chats_and_cross_base_answers_use_the_real_binary() {
    for (answer, expected_title) in [("allow", Some("Private content")), ("deny", None)] {
        let server = LocalServer::start();
        let home = TempDir::new().unwrap();
        let url = server.url().to_string();
        let invite = run(
            home.path(),
            &["admin", "invite", "--server", &url],
            None,
            Some(server.operator_token()),
        );
        run(
            home.path(),
            &[
                "signup",
                "--server",
                &url,
                "--invite",
                invite["code"].as_str().unwrap(),
                "--email",
                "access-cli@example.com",
                "--name",
                "Laptop",
            ],
            Some("test CLI password"),
            None,
        );
        let chat_base = run(home.path(), &["base", "create", "Health"], None, None);
        let chat_base_id = chat_base["id"].as_str().unwrap();
        let private = run(home.path(), &["base", "create", "Private"], None, None);
        let private_id = private["id"].as_str().unwrap();
        let note = run(
            home.path(),
            &["note", "new", "--base", private_id, "Private content"],
            None,
            None,
        );
        let note_id = note["id"].as_str().unwrap();
        // Test-only synthetic readers feed the normal core access rule, not a bypass.
        let readers = json!({(chat_base_id): ["01010101010101010101010101010101"]});
        let read = json!({"tool":"read", "arguments":{"base":private_id,"id":note_id}});
        let asked = scripted(
            home.path(),
            &["ask", "--base", chat_base_id, "Read Private"],
            json!([read, {"text":"Unreachable before permission"}]),
            Some(readers.clone()),
        );
        assert_eq!(asked["state"], "asking");
        assert_eq!(asked["ask"]["base"], private_id);
        let chat = asked["chat"].as_str().unwrap();
        let chats = run(
            home.path(),
            &["hero", "chats", "--base", chat_base_id],
            None,
            None,
        );
        assert!(
            chats
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["id"] == chat)
        );
        let result = scripted(
            home.path(),
            &[answer, "--chat", chat],
            json!([read, {"text":"Answered"}]),
            Some(readers.clone()),
        );
        assert_eq!(result["state"], "done");
        assert_eq!(result["steps"][0]["tool"], "read");
        assert_eq!(result["steps"][0]["title"].as_str(), expected_title);
        let next = scripted(
            home.path(),
            &["ask", "--chat", chat, "Try again"],
            json!([read, {"text":"Follow-up"}]),
            Some(readers),
        );
        assert_eq!(next["state"], "done");
        assert_eq!(next["steps"][0]["title"].as_str(), expected_title);
    }
}

#[test]
fn hero_ask_help_explains_ctrl_c_and_stop_is_not_offered() {
    let ask = Command::new("timeout")
        .args(["30s", env!("CARGO_BIN_EXE_bh"), "hero", "ask", "--help"])
        .output()
        .unwrap();
    assert!(ask.status.success());
    assert!(String::from_utf8_lossy(&ask.stdout).contains("Press Ctrl-C to stop."));
    let hero = Command::new("timeout")
        .args(["30s", env!("CARGO_BIN_EXE_bh"), "hero", "--help"])
        .output()
        .unwrap();
    assert!(hero.status.success());
    assert!(!String::from_utf8_lossy(&hero.stdout).contains("stop"));
}

#[test]
fn note_and_folder_mutations_and_devices_are_visible() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    let url = server.url().to_string();
    let invite = run(
        home.path(),
        &["admin", "invite", "--server", &url],
        None,
        Some(server.operator_token()),
    );
    run(
        home.path(),
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            "tree@example.com",
            "--name",
            "Test device",
        ],
        Some("test CLI password"),
        None,
    );
    let base = run(home.path(), &["base", "create", "Travel"], None, None);
    let base_id = base["id"].as_str().unwrap();
    let folder = run(home.path(), &["folder", "new", "Plans"], None, None);
    let folder_id = folder["id"].as_str().unwrap();
    let note = run(
        home.path(),
        &["note", "new", "--base", base_id, "Ferry at 9"],
        None,
        None,
    );
    let id = note["id"].as_str().unwrap();
    run(
        home.path(),
        &["note", "append", id, "Bring tickets"],
        None,
        None,
    );
    let shown = run(home.path(), &["show", id], None, None);
    assert_eq!(shown["text"], "Ferry at 9\nBring tickets");
    run(home.path(), &["mv", id, "--into", folder_id], None, None);
    let list = run(
        home.path(),
        &["ls", "--base", base_id, folder_id],
        None,
        None,
    );
    assert!(list.as_array().unwrap().iter().any(|n| n["id"] == id));
    run(home.path(), &["rm", id], None, None);
    let list = run(
        home.path(),
        &["ls", "--base", base_id, folder_id],
        None,
        None,
    );
    assert_eq!(list, json!([]));
    let devices = run(home.path(), &["devices"], None, None);
    assert!(
        devices
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name"] == "Test device")
    );
}

#[test]
fn an_app_home_writes_records_the_owner_reads() {
    let server = LocalServer::start();
    let owner = TempDir::new().unwrap();
    let app = TempDir::new().unwrap();
    enrolled(&server, owner.path(), "app-cli@example.com");
    let creds = owner.path().join("creds.json");
    let file = creds.to_str().unwrap();
    run(
        owner.path(),
        &[
            "app",
            "connect",
            "--name",
            "Demo",
            "--new-base",
            "Health",
            "--out",
            file,
        ],
        None,
        None,
    );
    let raw = fs::read_to_string(&creds).unwrap();
    let secret: Value = serde_json::from_str(&raw).unwrap();
    assert!(secret["token"].as_str().is_some_and(|s| !s.is_empty()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&creds).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(
        !output(
            owner.path(),
            &[
                "app",
                "connect",
                "--name",
                "Demo",
                "--new-base",
                "Other",
                "--out",
                file
            ]
        )
        .status
        .success()
    );
    assert_eq!(fs::read_to_string(&creds).unwrap(), raw);
    let def = app.path().join("sleep.json");
    fs::write(&def, json!({"name":"demo.sleep","version":1,"doc":"","title_field":null,"fields":[{"name":"date","kind":"date","required":true,"unit":null,"doc":""}]}).to_string()).unwrap();
    run(
        app.path(),
        &[
            "--app-credentials",
            file,
            "type",
            "define",
            def.to_str().unwrap(),
        ],
        None,
        None,
    );
    let record = run(
        app.path(),
        &[
            "--app-credentials",
            file,
            "record",
            "put",
            "--type",
            "demo.sleep",
            r#"{"date":"2026-11-01"}"#,
        ],
        None,
        None,
    );
    let id = record["id"].as_str().unwrap();
    run(app.path(), &["--app-credentials", file, "sync"], None, None);
    run(owner.path(), &["sync"], None, None);
    let query = run(
        owner.path(),
        &[
            "record",
            "query",
            "--type",
            "demo.sleep",
            "--where",
            "date=2026-11-01",
        ],
        None,
        None,
    );
    assert!(
        query
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == id && r["fields"]["date"] == "2026-11-01")
    );
    // The app's credentials are never copied to stdout or leaked in an error.
    let stdout = output(app.path(), &["--app-credentials", file, "bases"]);
    assert!(stdout.status.success());
    assert!(!String::from_utf8_lossy(&stdout.stdout).contains(secret["token"].as_str().unwrap()));
}

#[test]
fn device_remove_revokes_the_other_home_and_erases_its_copy() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let signup = enrolled(&server, a.path(), "remove-cli@example.com");
    let url = server.url().to_string();
    let signed = run(
        b.path(),
        &[
            "signin",
            "--server",
            &url,
            "--email",
            "remove-cli@example.com",
            "--name",
            "Other",
            "--kit",
            signup["kit"].as_str().unwrap(),
        ],
        Some("test CLI password"),
        None,
    );
    let device = signed["deviceId"].as_str().unwrap();
    run(a.path(), &["device", "remove", device], None, None);
    let rejected = output(b.path(), &["sync"]);
    assert!(!rejected.status.success());
    let err: Value = serde_json::from_slice(&rejected.stderr).unwrap();
    assert_eq!(err["error"], "this device was removed");
    assert!(
        !b.path()
            .join("accounts")
            .join(signup["accountId"].as_str().unwrap())
            .exists()
    );
}

struct WatchChild(Child);
impl Drop for WatchChild {
    fn drop(&mut self) {
        // Only the child we spawned, never a process-name kill.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn watch_prints_an_edit_from_another_home() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let signup = enrolled(&server, a.path(), "watch-cli@example.com");
    let url = server.url().to_string();
    run(
        b.path(),
        &[
            "signin",
            "--server",
            &url,
            "--email",
            "watch-cli@example.com",
            "--name",
            "Other",
            "--kit",
            signup["kit"].as_str().unwrap(),
        ],
        Some("test CLI password"),
        None,
    );
    run(a.path(), &["base", "create", "Travel"], None, None);
    run(b.path(), &["sync"], None, None);
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_bh"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", b.path().join("isolated-user"))
        .env("XDG_CONFIG_HOME", b.path().join("isolated-config"))
        .env("GH_CONFIG_DIR", b.path().join("isolated-gh"))
        .args(["--home", b.path().to_str().unwrap(), "--json", "watch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = WatchChild(child);
    let lines = Arc::new(Mutex::new(Vec::<Value>::new()));
    let observed = lines.clone();
    let stdout = child.0.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if let Ok(Ok(value)) = line.map(|s| serde_json::from_str(&s)) {
                observed.lock().unwrap().push(value);
            }
        }
    });
    let note = run(a.path(), &["note", "new", "Ferry at 9"], None, None);
    run(a.path(), &["sync"], None, None);
    let id = note["id"].as_str().unwrap().to_string();
    bh_testkit::wait_for(|| {
        lines.lock().unwrap().iter().any(|v| {
            v["event"]["objectsChanged"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|value| value == &id))
        })
    })
    .await;
    drop(child);
    reader.join().unwrap();
}
