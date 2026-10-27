use basehero_sample_core::{CREDENTIALS_FILE, READING, Sample};
use bh_core::{
    Account, AppCredentials, AppRequest, BaseGrantRequest, Error, FileSecretStore, Mode, Query,
    SecretStore,
};
use bh_models::{
    Completion, Finish, ToolCall,
    testing::{Scripted, ScriptedModel},
};
use bh_testkit::{device, new_signup, wait_for, wait_for_base};
use serde_json::json;
use std::{path::Path, sync::Arc};
use tempfile::TempDir;

fn sample(dir: &Path) -> Sample {
    let secrets: Arc<dyn SecretStore> =
        Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap());
    Sample::open(dir.join("data"), secrets).unwrap()
}
fn credentials(dir: &Path, creds: &AppCredentials) -> std::path::PathBuf {
    let path = dir.join(CREDENTIALS_FILE);
    std::fs::write(&path, serde_json::to_vec(creds).unwrap()).unwrap();
    path
}
async fn setup(mode: Mode) -> (Account, bh_core::Base, TempDir, Sample, std::path::PathBuf) {
    let (full, _) = device("full").sign_up(new_signup()).await.unwrap();
    let base = full.create_base("Sample readings").await.unwrap();
    base.flush().await.unwrap();
    let creds = full
        .connect_app(AppRequest {
            app_name: "Tester - BaseHero Sample".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = credentials(dir.path(), &creds);
    let app = sample(dir.path());
    (full, base, dir, app, path)
}
fn records(base: &bh_core::Base) -> Vec<bh_core::ObjectSummary> {
    base.query(&Query {
        ty: READING.into(),
        filters: vec![],
        order_by: None,
        limit: None,
    })
    .unwrap()
}

#[tokio::test]
async fn the_sample_connects_writes_and_reads_back() {
    let (_full, base, _dir, app, path) = setup(Mode::ReadWrite).await;
    let connected = app.install_file(&path).await.unwrap();
    assert_eq!(connected.base, base.id());
    assert_eq!(app.connected().unwrap().device, connected.device);
    assert!(!path.exists());
    let id = app.write_reading("2026-11-01", 42.0).await.unwrap();
    assert_eq!(app.readings().unwrap()[0].value, 42.0);
    app.flush().await.unwrap();
    wait_for_base(&base, || records(&base).len() == 1).await;
    assert_eq!(records(&base)[0].fields["value"], 42);
    assert_eq!(records(&base)[0].id, id);
    assert!(
        base.types()
            .unwrap()
            .iter()
            .any(|def| def.name == READING && def.version == 1)
    );
}

#[tokio::test]
async fn one_record_per_day() {
    let (_, _, _dir, app, path) = setup(Mode::ReadWrite).await;
    app.install_file(&path).await.unwrap();
    let first = app.write_reading("2026-11-01", 42.0).await.unwrap();
    let second = app.write_reading("2026-11-01", 43.0).await.unwrap();
    assert_eq!(first, second);
    let readings = app.readings().unwrap();
    assert_eq!(readings.len(), 1);
    assert_eq!(
        (readings[0].day.as_str(), readings[0].value),
        ("2026-11-01", 43.0)
    );
}

#[tokio::test]
async fn a_new_connection_to_the_same_base_does_not_duplicate_a_day() {
    let (full, base, _dir, first, path) = setup(Mode::ReadWrite).await;
    first.install_file(&path).await.unwrap();
    first.write_reading("2026-11-01", 42.0).await.unwrap();
    first.flush().await.unwrap();
    wait_for_base(&base, || records(&base).len() == 1).await;
    let second_dir = tempfile::tempdir().unwrap();
    let creds = full
        .connect_app(AppRequest {
            app_name: "Tester - BaseHero Sample".into(),
            app_id: None,
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: Mode::ReadWrite,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let second = sample(second_dir.path());
    second
        .install_file(&credentials(second_dir.path(), &creds))
        .await
        .unwrap();
    second.write_reading("2026-11-01", 44.0).await.unwrap();
    second.flush().await.unwrap();
    wait_for_base(&base, || {
        records(&base).len() == 1 && records(&base)[0].fields["value"] == 44
    })
    .await;
}

#[tokio::test]
async fn installing_offline_keeps_the_file_for_a_retry() {
    let (_, _, dir, app, path) = setup(Mode::ReadWrite).await;
    let original = std::fs::read(&path).unwrap();
    let mut creds: AppCredentials = serde_json::from_slice(&original).unwrap();
    creds.server = "http://127.0.0.1:1/".parse().unwrap();
    std::fs::write(&path, serde_json::to_vec(&creds).unwrap()).unwrap();
    assert!(matches!(
        app.install_file(&path).await,
        Err(Error::Network(_))
    ));
    assert!(path.exists());
    assert!(app.connected().is_none());
    std::fs::write(&path, original).unwrap();
    app.install_file(&path).await.unwrap();
    assert!(!dir.path().join(CREDENTIALS_FILE).exists());
}

#[tokio::test]
async fn a_read_only_grant_refuses_writes() {
    let (_, _, _dir, app, path) = setup(Mode::ReadOnly).await;
    app.install_file(&path).await.unwrap();
    assert_eq!(
        app.write_reading("2026-11-01", 42.0).await.unwrap_err(),
        Error::ReadOnly
    );
}

#[tokio::test]
async fn a_removed_sample_forgets_its_connection() {
    let (full, _, _dir, app, path) = setup(Mode::ReadWrite).await;
    let connected = app.install_file(&path).await.unwrap();
    full.remove_device(connected.device).await.unwrap();
    wait_for(|| app.connected().is_none()).await;
}

fn call(name: &str, args: serde_json::Value) -> Scripted {
    Scripted::Reply(Completion {
        text: None,
        tool_calls: vec![ToolCall {
            id: "call1".into(),
            name: name.into(),
            arguments: args.to_string(),
        }],
        finish: Finish::ToolCalls,
        usage: None,
    })
}
#[tokio::test]
async fn hero_reads_the_samples_records() {
    let (full, base, _dir, app, path) = setup(Mode::ReadWrite).await;
    app.install_file(&path).await.unwrap();
    let id = app.write_reading("2026-11-01", 42.0).await.unwrap();
    app.flush().await.unwrap();
    wait_for_base(&base, || records(&base).len() == 1).await;
    let personal = full.create_base("Personal").await.unwrap();
    let model = ScriptedModel::new(vec![
        call("list", json!({"base":base.id(),"type":READING})),
        call("read", json!({"base":base.id(),"id":id})),
        Scripted::Reply(Completion {
            text: Some("42".into()),
            tool_calls: vec![],
            finish: Finish::Stop,
            usage: None,
        }),
    ]);
    let hero = full.hero_with_model(model.clone());
    let chat = hero.new_chat(personal.id()).unwrap();
    hero.send(personal.id(), chat, "Read the sample", None)
        .unwrap();
    hero.wait_idle(chat).await;
    let messages = hero.messages(personal.id(), chat).unwrap();
    assert_eq!(
        messages[1]
            .steps
            .iter()
            .map(|s| s.tool.as_str())
            .collect::<Vec<_>>(),
        ["list", "read"]
    );
    assert_eq!(messages[1].steps[0].base, Some(base.id()));
    assert!(format!("{:?}", model.requests()[2].messages).contains("\\\"value\\\":42"));
}
