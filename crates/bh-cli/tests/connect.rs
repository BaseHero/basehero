use bh_core::{AppIdentity, Core, CoreConfig, EndReason, Error, FileSecretStore, Mode, SignIn};
use bh_testkit::{LocalServer, RawDevice};
use serde_json::Value;
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
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
        .env("BH_PASSWORD", "connection test password")
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

fn setup(server: &LocalServer, home: &Path) -> String {
    let email = "cli-connect@example.com";
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
            email,
            "--name",
            "Laptop",
        ],
    );
    run(home, &["base", "create", "Personal"]);
    email.into()
}

fn app(home: &Path) -> Core {
    Core::open(CoreConfig {
        data_dir: home.to_path_buf(),
        secrets: Arc::new(FileSecretStore::new(home.join("secrets")).unwrap()),
    })
    .unwrap()
}

async fn exchange(
    args: &[&str],
    input: &str,
) -> (
    Output,
    Result<bh_core::Account, Error>,
    Core,
    TempDir,
    TempDir,
    Value,
    LocalServer,
) {
    let server = LocalServer::start();
    let full = TempDir::new().unwrap();
    let app_home = TempDir::new().unwrap();
    let email = setup(&server, full.path());
    let core = app(app_home.path());
    let mut pending = core
        .start_connection(
            server.url().clone(),
            &email,
            AppIdentity {
                name: "Sample".into(),
                app_id: "app.example.sample".into(),
            },
        )
        .await
        .unwrap();
    let id = pending.id().to_string();
    let listed = run(full.path(), &["approvals"]);
    assert_eq!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["approvalId"] == id)
            .unwrap()["kind"],
        "app"
    );
    let mut cli_args = vec!["approve", &id];
    cli_args.extend_from_slice(args);
    let mut child = command(full.path(), &cli_args)
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
    writeln!(stdin, "12 3").unwrap();
    writeln!(stdin, "{}", digits.as_str()).unwrap();
    writeln!(stdin, "{input}").unwrap();
    drop(stdin);
    let result = tokio::time::timeout(Duration::from_secs(30), pending.wait())
        .await
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let devices = run(full.path(), &["devices"]);
    (output, result, core, full, app_home, devices, server)
}

#[tokio::test(flavor = "multi_thread")]
async fn bh_approve_connects_an_app_with_typed_digits() {
    let (output, result, core, _, _app_home, devices, _server) = exchange(&[], "y").await;
    let connected = result.unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr
            .contains("An app wants to connect. Approve only an app you're setting up right now.")
    );
    assert!(stderr.contains("Type the six digits the app shows: "));
    assert!(stderr.contains("Type exactly six digits: "));
    assert!(stderr.contains("Sample (not verified) joins as"));
    assert!(stderr.contains("Cap: $1.00 a month"));
    assert!(stderr.contains("Connect? [y/N] "));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["connected"], connected.device_id().to_string());
    assert!(
        devices
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == value["connected"] && d["capMicroUsd"] == 1_000_000)
    );
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn uppercase_y_connects_the_app() {
    let (output, result, core, _, _, _, _) = exchange(&[], "Y").await;
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(result.is_ok());
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_base_after_digits_declines_the_app() {
    let (output, result, core, _, _, devices, _) = exchange(&["--base", "Missing"], "y").await;
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_lowercase()
            .contains("not found"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(
        result,
        Err(Error::ApprovalEnded(EndReason::Declined))
    ));
    assert_eq!(devices.as_array().unwrap().len(), 1);
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn answering_no_declines_the_app() {
    let (output, result, core, _, _app_home, devices, _server) = exchange(&[], "n").await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("The request was declined."));
    assert!(matches!(
        result,
        Err(Error::ApprovalEnded(EndReason::Declined))
    ));
    assert_eq!(devices.as_array().unwrap().len(), 1);
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn flags_choose_the_bases_and_cap() {
    let (output, result, core, _, _app_home, devices, _server) = exchange(
        &[
            "--new-base",
            "Sample readings",
            "--read-only",
            "--cap-usd",
            "2.50",
        ],
        "y",
    )
    .await;
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let connected = result.unwrap();
    connected.refresh().await.unwrap();
    assert_eq!(connected.bases().len(), 1);
    let base = connected.base(connected.bases()[0].id).unwrap();
    bh_testkit::wait_for_base(&base, || base.name() == "Sample readings").await;
    assert_eq!(connected.bases()[0].mode, Mode::ReadOnly);
    assert!(
        devices
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == connected.device_id().to_string() && d["capMicroUsd"] == 2_500_000)
    );
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn keeping_an_old_connection_names_it() {
    let (_, result, core, full, _, _, server) = exchange(&[], "y").await;
    let old = result.unwrap();
    let fresh_home = TempDir::new().unwrap();
    let fresh = app(fresh_home.path());
    let mut pending = fresh
        .start_connection(
            server.url().clone(),
            &old.email(),
            AppIdentity {
                name: "Sample".into(),
                app_id: "app.example.sample".into(),
            },
        )
        .await
        .unwrap();
    let id = pending.id().to_string();
    let mut child = command(full.path(), &["approve", &id, "--keep-old"])
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
        String::from_utf8_lossy(&output.stderr)
            .contains("Keeps the old connection Cli-connect - Sample.")
    );
    assert_ne!(connected.device_id(), old.device_id());
    fresh.shutdown();
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_old_removal_reports_connection_and_flushes_new_base() {
    let (_, result, core, full, _, _, server) = exchange(&[], "y").await;
    let old = result.unwrap();
    let approver = app(full.path());
    let full_account = approver.account(approver.accounts()[0].id).unwrap();
    let token = full_account
        .test_secrets()
        .get(&format!("acct.{}.token", full_account.id()))
        .unwrap()
        .unwrap();
    let raw = RawDevice::new(
        &server,
        full_account.id().to_string(),
        full_account.device_id().to_string(),
        String::from_utf8(token.to_vec()).unwrap(),
    );
    assert!(
        raw.post("/v1/devices/fail-next-removal", serde_json::json!({}))
            .await
            .0
            .is_success()
    );
    drop(full_account);
    approver.shutdown();
    drop(approver);
    let fresh_home = TempDir::new().unwrap();
    let fresh = app(fresh_home.path());
    let mut pending = fresh
        .start_connection(
            server.url().clone(),
            &old.email(),
            AppIdentity {
                name: "Sample".into(),
                app_id: "app.example.sample".into(),
            },
        )
        .await
        .unwrap();
    let id = pending.id().to_string();
    let mut child = command(
        full.path(),
        &["approve", &id, "--remove-old", "--new-base", "Readings"],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let digits = match tokio::time::timeout(Duration::from_secs(8), pending.digits()).await {
        Ok(result) => result.unwrap(),
        Err(_) => {
            let pid = child.id();
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "CLI {pid} did not open request: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };
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
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["connected"],
        connected.device_id().to_string()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Connected Cli-connect - Sample."),
        "{stderr}"
    );
    assert!(
        stderr.contains("The old connection couldn't be removed; disconnect it in Devices."),
        "{stderr}"
    );
    assert!(
        run(full.path(), &["devices"])
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == old.device_id().to_string() && row["status"] == "active")
    );
    connected.refresh().await.unwrap();
    let base = connected.base(connected.bases()[0].id).unwrap();
    bh_testkit::wait_for_base(&base, || base.name() == "Readings").await;
    fresh.shutdown();
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn app_flags_are_refused_for_a_device_request() {
    let server = LocalServer::start();
    let full = TempDir::new().unwrap();
    let other = TempDir::new().unwrap();
    let email = setup(&server, full.path());
    let core = app(other.path());
    let pending = core
        .sign_in(SignIn {
            server: server.url().clone(),
            email,
            password: "connection test password".to_owned().into(),
            device_name: "Other".into(),
        })
        .await
        .unwrap();
    let mut approval = pending.request_approval().await.unwrap();
    let listed = run(full.path(), &["approvals"]);
    assert_eq!(listed.as_array().unwrap()[0]["kind"], "device");
    let output = command(
        full.path(),
        &["approve", &approval.id().to_string(), "--read-only"],
    )
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("app-only flags"));
    approval.cancel().await.unwrap();
    core.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn bh_device_cap_changes_an_apps_cap() {
    let (_, result, core, full, _app_home, _, _server) = exchange(&[], "y").await;
    let connected = result.unwrap();
    let id = connected.device_id().to_string();
    let changed = run(full.path(), &["device", "cap", &id, "0"]);
    assert_eq!(changed, serde_json::json!({"device": id, "capMicroUsd": 0}));
    assert!(
        run(full.path(), &["devices"])
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == id && d["capMicroUsd"] == 0)
    );
    let full_id = run(full.path(), &["devices"])[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let output = command(full.path(), &["device", "cap", &full_id, "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    core.shutdown();
}
