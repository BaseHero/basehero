use basehero_sample_core::{READING, Sample};
use bh_core::{
    Account, AppChoice, AppOffer, BaseGrantRequest, Error, FileSecretStore, Mode, Query,
    SecretStore,
};
use bh_models::{
    Completion, Finish, ToolCall,
    testing::{Scripted, ScriptedModel},
};
use bh_testkit::{LocalServer, approve_next_app, device, new_signup, wait_for, wait_for_base};
use serde_json::json;
use std::{path::Path, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::sync::oneshot;

fn sample(dir: &Path) -> Sample {
    let secrets: Arc<dyn SecretStore> =
        Arc::new(FileSecretStore::new(dir.join("secrets")).unwrap());
    Sample::open_with_server(dir.join("data"), secrets, LocalServer::from_env().url()).unwrap()
}
fn defaults(offer: &AppOffer) -> AppChoice {
    AppChoice {
        bases: offer
            .bases
            .iter()
            .map(|grant| BaseGrantRequest::Existing {
                base: grant.base,
                mode: grant.mode,
            })
            .collect(),
        cap_micro_usd: offer.cap_micro_usd,
        replaces: None,
    }
}
async fn setup() -> (Account, bh_core::Base, TempDir, Sample) {
    let (full, _) = device("full").sign_up(new_signup()).await.unwrap();
    let base = full.create_base("Personal").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let app = sample(dir.path());
    (full, base, dir, app)
}
async fn connect(
    full: &Account,
    app: &Sample,
    choose: impl FnOnce(&AppOffer) -> AppChoice + Send + 'static,
) -> basehero_sample_core::Connected {
    let (tx, rx) = oneshot::channel();
    let email = full.email();
    let full = full.clone();
    let approver = tokio::spawn(async move { approve_next_app(&full, rx, choose).await });
    let digits = tokio::time::timeout(Duration::from_secs(30), app.connect_digits(&email))
        .await
        .unwrap()
        .unwrap();
    tx.send(digits).unwrap();
    let connected = tokio::time::timeout(Duration::from_secs(30), app.connect_finish())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(connected.device, approver.await.unwrap().unwrap());
    connected
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
async fn the_sample_connects_by_approval_writes_and_reads_back() {
    let (full, base, _dir, app) = setup().await;
    let connected = connect(&full, &app, defaults).await;
    assert_eq!(connected.base, base.id());
    assert_eq!(app.connected().unwrap().device, connected.device);
    let id = app.write_reading("2026-10-28", 42.0).await.unwrap();
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
async fn a_folder_grant_exposes_only_the_folders_name_and_records() {
    let (full, personal, _dir, app) = setup().await;
    let folder = personal
        .create(bh_core::NewObject {
            ty: bh_core::TypeRef::new("core.folder", 1),
            parent: None,
            after: None,
            fields: serde_json::Map::from_iter([("name".into(), json!("Health"))]),
        })
        .unwrap();
    let personal_id = personal.id();
    let connected = connect(&full, &app, move |_| AppChoice {
        bases: vec![BaseGrantRequest::Folder {
            base: personal_id,
            folder,
            mode: Mode::ReadWrite,
        }],
        cap_micro_usd: 1_000_000,
        replaces: None,
    })
    .await;
    assert_eq!(connected.bases, vec!["Health"]);
    assert_eq!(app.connected().unwrap().bases, vec!["Health"]);
    assert_ne!(connected.base, personal.id());
    let id = app.write_reading("2026-10-28", 42.0).await.unwrap();
    app.flush().await.unwrap();
    assert_eq!(app.readings().unwrap()[0].value, 42.0);
    wait_for_base(&full.base(connected.base).unwrap(), || {
        full.base(connected.base)
            .unwrap()
            .get(id)
            .unwrap()
            .is_some()
    })
    .await;
    assert!(personal.get(id).unwrap().is_none());
}

#[tokio::test]
async fn one_record_per_day() {
    let (full, _, _dir, app) = setup().await;
    connect(&full, &app, defaults).await;
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
async fn a_reconnected_sample_finds_its_reading() {
    let (full, base, dir, first) = setup().await;
    connect(&full, &first, defaults).await;
    first.write_reading("2026-10-28", 42.0).await.unwrap();
    first.flush().await.unwrap();
    wait_for_base(&base, || records(&base).len() == 1).await;
    drop(first);
    std::fs::remove_dir_all(dir.path().join("data")).unwrap();
    std::fs::remove_dir_all(dir.path().join("secrets")).unwrap();
    let second = sample(dir.path());
    assert_eq!(connect(&full, &second, defaults).await.base, base.id());
    assert_eq!(second.readings().unwrap()[0].value, 42.0);
    second.write_reading("2026-10-28", 44.0).await.unwrap();
    second.flush().await.unwrap();
    wait_for_base(&base, || {
        records(&base).len() == 1 && records(&base)[0].fields["value"] == 44
    })
    .await;
}

#[tokio::test]
async fn a_read_only_grant_refuses_writes() {
    let (full, _, _dir, app) = setup().await;
    connect(&full, &app, |offer| {
        let mut choice = defaults(offer);
        if let BaseGrantRequest::Existing { mode, .. } = &mut choice.bases[0] {
            *mode = Mode::ReadOnly;
        }
        choice
    })
    .await;
    assert_eq!(
        app.write_reading("2026-10-28", 42.0).await.unwrap_err(),
        Error::ReadOnly
    );
}

#[tokio::test]
async fn cancelling_the_digits_ends_the_request_and_allows_a_fresh_one() {
    let (full, _, _dir, app) = setup().await;
    let email = full.email();
    let first = app.connect_digits(&email);
    tokio::pin!(first);
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = &mut first => panic!("digits before approval: {result:?}"),
            _ = async {
                loop {
                    if !full.approval_requests().await.unwrap().is_empty() { break; }
                    tokio::task::yield_now().await;
                }
                app.connect_cancel().await.unwrap();
            } => {}
        }
    })
    .await
    .unwrap();
    assert!(matches!(first.await, Err(Error::ApprovalEnded(_))));
    assert!(app.connected().is_none());
    connect(&full, &app, defaults).await;
    assert!(app.connected().is_some());
}

#[tokio::test]
async fn a_restarted_sample_checks_revocation_before_reporting_connected() {
    let (full, _, dir, app) = setup().await;
    let connected = connect(&full, &app, defaults).await;
    drop(app);
    full.remove_device(connected.device, bh_core::Removal::Plain)
        .await
        .unwrap();
    let restarted = sample(dir.path());
    assert!(restarted.check_connection().await.unwrap().is_none());
    assert!(restarted.connected().is_none());
    assert!(
        !dir.path()
            .join("data")
            .join("accounts")
            .join(connected.account.to_string())
            .exists()
    );
}

#[tokio::test]
async fn a_disconnected_sample_is_not_connected() {
    let (full, _, _dir, app) = setup().await;
    let connected = connect(&full, &app, defaults).await;
    full.remove_device(connected.device, bh_core::Removal::Plain)
        .await
        .unwrap();
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
    let (full, base, _dir, app) = setup().await;
    connect(&full, &app, defaults).await;
    let id = app.write_reading("2026-11-01", 42.0).await.unwrap();
    app.flush().await.unwrap();
    wait_for_base(&base, || records(&base).len() == 1).await;
    let personal = full.create_base("Hero chat").await.unwrap();
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
