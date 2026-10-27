use assert_cmd::Command;
use bh_testkit::LocalServer;
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::process::{Child, Stdio};
use std::{fs, path::Path};
use tempfile::TempDir;

const PASSWORD: &str = "ferry lantern quartz";
const EXTRA: &str = "orchard copper lantern";

fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("timeout");
    cmd.args(["30s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.join("isolated-config"))
        .env("GH_CONFIG_DIR", home.join("isolated-gh"))
        .args(["--home", home.to_str().unwrap(), "--json"])
        .args(args);
    cmd
}

fn run(home: &Path, args: &[&str], hidden: Option<&str>, trace: bool) -> Value {
    let mut cmd = command(home, args);
    if let Some(hidden) = hidden {
        cmd.env("BH_HIDDEN_PASSWORD", hidden);
    }
    if trace {
        cmd.env("RUST_LOG", "trace");
    }
    let result = cmd.output().unwrap();
    for needle in ["Zebra Diary", "Gelato", "Marguerite", EXTRA] {
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains(needle),
            "secret leaked on stderr"
        );
    }
    assert!(result.status.success(), "CLI exited with {}", result.status);
    serde_json::from_slice(&result.stdout).expect("JSON output")
}

fn signup(server: &LocalServer, home: &Path, trace: bool) -> Value {
    let url = server.url().to_string();
    let mut invite = command(home, &["admin", "invite", "--server", &url]);
    invite.env("BH_OPERATOR_TOKEN", server.operator_token());
    let output = invite.output().unwrap();
    assert!(output.status.success(), "invite failed");
    let code: Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut signup = command(
        home,
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            code["code"].as_str().unwrap(),
            "--email",
            "hidden-cli@example.com",
            "--name",
            "Laptop",
        ],
    );
    signup.env("BH_PASSWORD", PASSWORD);
    if trace {
        signup.env("RUST_LOG", "trace");
    }
    let output = signup.output().unwrap();
    assert!(output.status.success(), "signup failed");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn flow(trace: bool) -> (TempDir, TempDir) {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let signup = signup(&server, a.path(), trace);
    let created = run(
        a.path(),
        &["hidden", "create", "Zebra Diary"],
        Some(EXTRA),
        trace,
    );
    assert_eq!(created["name"], "Zebra Diary");
    let id = created["id"].as_str().unwrap();
    let new = run(
        a.path(),
        &[
            "--unlock",
            "note",
            "new",
            "--base",
            id,
            "Gelato with Marguerite",
        ],
        Some(EXTRA),
        trace,
    );
    assert_eq!(new["baseId"], id);
    run(a.path(), &["--unlock", "sync"], Some(EXTRA), trace);
    assert!(
        run(a.path(), &["bases"], None, trace)
            .as_array()
            .unwrap()
            .iter()
            .all(|b| b["id"] != id)
    );
    assert_eq!(run(a.path(), &["search", "Gelato"], None, trace), json!([]));
    let url = server.url().to_string();
    let mut signin = command(
        b.path(),
        &[
            "signin",
            "--server",
            &url,
            "--email",
            "hidden-cli@example.com",
            "--name",
            "Desktop",
            "--kit",
            signup["kit"].as_str().unwrap(),
        ],
    );
    signin.env("BH_PASSWORD", PASSWORD);
    if trace {
        signin.env("RUST_LOG", "trace");
    }
    let output = signin.output().unwrap();
    assert!(output.status.success(), "signin failed");
    run(b.path(), &["sync"], None, trace);
    let unlocked = run(b.path(), &["hidden", "unlock"], Some(EXTRA), trace);
    assert_eq!(unlocked[0]["id"], id);
    // The hidden store starts empty on this device; wait for its background catch-up.
    let mut hits = json!([]);
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(bh_testkit::wait_for(|| {
            hits = run(
                b.path(),
                &["--unlock", "search", "Gelato"],
                Some(EXTRA),
                trace,
            );
            hits.as_array().unwrap().len() == 1
        }));
    assert_eq!(hits[0]["baseId"], id);
    let wrong = command(b.path(), &["hidden", "unlock"])
        .env("BH_HIDDEN_PASSWORD", "wrong")
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<Value>(&wrong.stdout).unwrap(),
        json!({"kind":"NothingUnlocked"})
    );
    (a, b)
}

#[test]
fn hidden_bases_work_headless_across_two_homes() {
    flow(false);
}

fn files_containing(dir: &Path, needle: &[u8]) -> Vec<std::path::PathBuf> {
    let mut matches = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                matches.extend(files_containing(&path, needle));
            } else if fs::read(&path)
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
            {
                matches.push(path);
            }
        }
    }
    matches
}

#[test]
fn the_cli_never_logs_hidden_content() {
    let (a, b) = flow(true);
    for home in [a.path(), b.path()] {
        for needle in ["Zebra Diary", "Gelato", "Marguerite", EXTRA] {
            assert!(
                files_containing(home, needle.as_bytes()).is_empty(),
                "readable hidden content in home"
            );
        }
    }
}

#[test]
fn strength_and_names_are_inert_terminal_text() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    signup(&server, home.path(), false);
    let strength = run(
        home.path(),
        &["hidden", "strength"],
        Some("password123"),
        false,
    );
    assert!(strength["score"].as_u64().unwrap() <= 1);
    assert_eq!(strength["strong"], false);
    let created = run(
        home.path(),
        &["hidden", "create", "Zebra\u{1b}[31m\u{202e}"],
        Some(EXTRA),
        false,
    );
    assert_eq!(created["name"], "Zebra\\u{1b}[31m\\u{202e}");
    let opened = run(home.path(), &["hidden", "unlock"], Some(EXTRA), false);
    assert_eq!(opened[0]["name"], created["name"]);
    let bases = run(home.path(), &["--unlock", "bases"], Some(EXTRA), false);
    assert!(
        bases
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["name"] == created["name"])
    );
}

#[cfg(target_os = "linux")]
struct WatchChild(Child);
#[cfg(target_os = "linux")]
impl Drop for WatchChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let pid = self.0.id();
            // The PID comes from this exact child; never kill by name.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ctrl_c_during_watch_exits_after_locking() {
    let server = LocalServer::start();
    let home = TempDir::new().unwrap();
    signup(&server, home.path(), false);
    run(
        home.path(),
        &["hidden", "create", "Zebra Diary"],
        Some(EXTRA),
        false,
    );
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_bh"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("HOME", home.path().join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.path().join("isolated-config"))
        .env("GH_CONFIG_DIR", home.path().join("isolated-gh"))
        .env("BH_HIDDEN_PASSWORD", EXTRA)
        .args([
            "--home",
            home.path().to_str().unwrap(),
            "--json",
            "--unlock",
            "watch",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut child = WatchChild(child);
    // SIGINT is handled only after --unlock succeeds and watch's Ctrl-C
    // branch is polled. Signal that exact child, not a process name.
    bh_testkit::wait_for(|| {
        fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("SigCgt:\t"))
                .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
                .is_some_and(|mask| mask & 2 != 0)
        })
    })
    .await;
    // Signal only once watch is reading stdin, the state a person's Ctrl-C finds.
    bh_testkit::wait_for(|| {
        fs::read_dir(format!("/proc/{pid}/task")).is_ok_and(|tasks| {
            tasks.flatten().any(|task| {
                fs::read_to_string(task.path().join("syscall"))
                    .is_ok_and(|call| call.starts_with("0 0x0 "))
            })
        })
    })
    .await;
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGINT) }, 0);
    bh_testkit::wait_for(|| child.0.try_wait().unwrap().is_some()).await;
    assert!(
        child.0.wait().unwrap().success(),
        "watch did not exit cleanly on Ctrl-C"
    );
    assert_eq!(
        run(home.path(), &["bases"], None, false)
            .as_array()
            .unwrap()
            .len(),
        0
    );
}
