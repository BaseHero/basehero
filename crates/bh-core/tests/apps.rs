//! App devices and whole-base grants through the real local Worker.

use bh_core::{
    AppCredentials, AppRequest, BaseGrantRequest, DeviceKind, Error, FieldDef, FieldKind, Mode,
    NewObject, Query, TypeDef, TypeRef,
};
use bh_testkit::{LocalServer, device, found_under, new_signup, raw_device, wait_for_base};
use reqwest::StatusCode;
use serde_json::{Map, json};

fn request(base: bh_core::BaseId, mode: Mode) -> AppRequest {
    AppRequest {
        app_name: "Demo Health App".into(),
        app_id: Some("dev:health".into()),
        bases: vec![BaseGrantRequest::Existing { base, mode }],
        replaces: None,
    }
}

async fn setup() -> bh_core::Account {
    device("laptop").sign_up(new_signup()).await.unwrap().0
}

async fn install(creds: AppCredentials) -> bh_core::Account {
    device("app").install_app(creds).await.unwrap()
}

#[tokio::test]
async fn failed_install_refresh_can_be_retried() {
    let full = setup().await;
    let health = full.create_base("Health").await.unwrap();
    let credentials = full
        .connect_app(request(health.id(), Mode::ReadOnly))
        .await
        .unwrap();
    let core = device("app-retry");
    core.inject_fault(bh_core::test_support::Fault {
        method: "GET",
        path: Box::leak(format!("v1/bases/{}/key", health.id()).into_boxed_str()),
        lost_reply: false,
        times: 1,
    });
    let retry = zeroize::Zeroizing::new(serde_json::to_vec(&credentials).unwrap());
    let result = core.install_app(credentials).await;
    assert!(matches!(result, Err(Error::Network(_))));
    assert!(core.accounts().is_empty());
    let account = core
        .install_app(serde_json::from_slice(&retry).unwrap())
        .await
        .unwrap();
    assert_eq!(account.bases()[0].id, health.id());
}

#[tokio::test]
async fn an_app_sees_only_its_granted_bases() {
    let full = setup().await;
    let personal = full.create_base("Personal").await.unwrap();
    let health = full.create_base("Health").await.unwrap();
    health.flush().await.unwrap();
    let app = install(
        full.connect_app(request(health.id(), Mode::ReadWrite))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(app.kind(), DeviceKind::App);
    assert_eq!(
        app.bases().iter().map(|b| b.id).collect::<Vec<_>>(),
        vec![health.id()]
    );
    assert_eq!(app.base(personal.id()).unwrap_err(), Error::NotFound);
    let (status, body) = raw_device(&app)
        .get(&format!("/v1/bases/{}/key", personal.id()), json!({}))
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
    assert_eq!(
        app.create_base("other").await.unwrap_err(),
        Error::Forbidden
    );
    assert_eq!(app.devices().await.unwrap_err(), Error::Forbidden);
    assert!(matches!(
        app.connect_app(request(health.id(), Mode::ReadWrite)).await,
        Err(Error::Forbidden)
    ));
    assert_eq!(full.apps()[0].app_id.as_deref(), Some("dev:health"));
}

#[tokio::test]
async fn a_read_only_app_cannot_write() {
    let full = setup().await;
    let health = full.create_base("Health").await.unwrap();
    health.flush().await.unwrap();
    let app = install(
        full.connect_app(request(health.id(), Mode::ReadOnly))
            .await
            .unwrap(),
    )
    .await;
    let base = app.base(health.id()).unwrap();
    assert_eq!(base.mode(), Mode::ReadOnly);
    assert_eq!(
        base.create(bh_testkit::note()).unwrap_err(),
        Error::ReadOnly
    );
    let (status, body) = raw_device(&app)
        .post(
            &format!("/v1/bases/{}/changes", health.id()),
            json!({"changes": []}),
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("read_only"))
    );
}

#[tokio::test]
async fn app_records_reach_the_full_device_with_their_type() {
    let full = setup().await;
    let health = full.create_base("Health").await.unwrap();
    health.flush().await.unwrap();
    let app = install(
        full.connect_app(request(health.id(), Mode::ReadWrite))
            .await
            .unwrap(),
    )
    .await;
    let base = app.base(health.id()).unwrap();
    let def = TypeDef {
        name: "demo.sleep".into(),
        version: 1,
        doc: "Sleep".into(),
        title_field: None,
        fields: vec![FieldDef {
            name: "score".into(),
            kind: FieldKind::Integer,
            required: true,
            unit: None,
            doc: "Score".into(),
        }],
    };
    base.define_type(def.clone()).unwrap();
    for score in [70, 80, 90] {
        base.create(NewObject {
            ty: TypeRef::new("demo.sleep", 1),
            parent: None,
            after: None,
            fields: Map::from_iter([("score".into(), json!(score))]),
        })
        .unwrap();
    }
    base.flush().await.unwrap();
    wait_for_base(&health, || {
        health.types().unwrap().contains(&def)
            && health
                .query(&Query {
                    ty: "demo.sleep".into(),
                    filters: vec![],
                    order_by: None,
                    limit: None,
                })
                .unwrap()
                .len()
                == 3
    })
    .await;
}

#[tokio::test]
async fn a_reconnected_app_gets_its_old_base_and_the_old_device_goes() {
    let full = setup().await;
    let health = full.create_base("Health").await.unwrap();
    let personal = full.create_base("Personal").await.unwrap();
    let mut order = vec![health.id(), personal.id()];
    order.sort();
    order.reverse(); // Opposite JSON map's key order: reconnection must preserve the request order.
    let mut req = request(order[0], Mode::ReadWrite);
    req.bases.push(BaseGrantRequest::Existing {
        base: order[1],
        mode: Mode::ReadOnly,
    });
    let first = full.connect_app(req.clone()).await.unwrap();
    assert_eq!(first.bases, order);
    let previous = first.device_id;
    let old = install(first).await;
    let next = full
        .connect_app(AppRequest {
            bases: vec![],
            replaces: Some(previous),
            ..req
        })
        .await
        .unwrap();
    assert_eq!(next.bases, order);
    assert_eq!(
        full.apps()[0]
            .bases
            .iter()
            .map(|grant| grant.mode)
            .collect::<Vec<_>>(),
        vec![Mode::ReadWrite, Mode::ReadOnly]
    );
    assert_ne!(next.device_id, previous);
    let (status, body) = raw_device(&old).get("/v1/me", json!({})).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("revoked"))
    );
    assert_eq!(
        full.apps()
            .iter()
            .filter(|a| a.app_id.as_deref() == Some("dev:health"))
            .count(),
        1
    );
    assert_eq!(install(next).await.bases().len(), 2);
}

#[tokio::test]
async fn an_empty_initial_app_grant_is_invalid() {
    let full = setup().await;
    let before = full.devices().await.unwrap().len();
    let result = full
        .connect_app(AppRequest {
            app_name: "Demo".into(),
            app_id: Some("dev:demo".into()),
            bases: vec![],
            replaces: None,
        })
        .await;
    assert!(matches!(result, Err(Error::Invalid(_))));
    assert_eq!(full.devices().await.unwrap().len(), before);
    assert!(full.apps().is_empty());
}

#[tokio::test]
async fn a_failed_grant_removes_the_registered_app_device() {
    let full = setup().await;
    let health = full.create_base("Health").await.unwrap();
    full.test_inject_fault(bh_core::test_support::Fault {
        method: "PUT",
        path: Box::leak(format!("v1/bases/{}/grants/", health.id()).into_boxed_str()),
        lost_reply: true,
        times: 1,
    });
    assert!(matches!(
        full.connect_app(request(health.id(), Mode::ReadWrite))
            .await,
        Err(Error::Network(_))
    ));
    assert!(
        full.devices()
            .await
            .unwrap()
            .into_iter()
            .all(|d| d.kind != DeviceKind::App || d.status == "revoked")
    );
    assert!(full.apps().is_empty());
    let creds = full
        .connect_app(request(health.id(), Mode::ReadWrite))
        .await
        .unwrap();
    assert_eq!(
        full.devices()
            .await
            .unwrap()
            .into_iter()
            .filter(|d| d.kind == DeviceKind::App && d.status == "active")
            .count(),
        1
    );
    assert_eq!(full.apps()[0].device_id, creds.device_id);
}

#[tokio::test]
async fn a_lost_registration_reply_leaves_no_active_app_device() {
    let full = setup().await;
    let health = full.create_base("Health").await.unwrap();
    full.test_inject_fault(bh_core::test_support::Fault {
        method: "POST",
        path: "v1/devices",
        lost_reply: true,
        times: 1,
    });
    assert!(matches!(
        full.connect_app(request(health.id(), Mode::ReadWrite))
            .await,
        Err(Error::Network(_))
    ));
    assert!(
        full.devices()
            .await
            .unwrap()
            .iter()
            .all(|d| d.kind != DeviceKind::App || d.status == "revoked")
    );
    assert!(full.apps().is_empty());
    let creds = full
        .connect_app(request(health.id(), Mode::ReadWrite))
        .await
        .unwrap();
    assert_eq!(
        full.devices()
            .await
            .unwrap()
            .iter()
            .filter(|d| d.kind == DeviceKind::App && d.status == "active")
            .count(),
        1
    );
    assert_eq!(full.apps()[0].device_id, creds.device_id);
}

#[tokio::test]
async fn app_names_never_reach_the_server_in_readable_form() {
    bh_testkit::local_only!();
    let full = setup().await;
    let health = full.create_base("Health").await.unwrap();
    full.connect_app(request(health.id(), Mode::ReadWrite))
        .await
        .unwrap();
    assert!(!found_under(
        LocalServer::shared().persist_dir(),
        b"Demo Health App"
    ));
}

#[tokio::test]
async fn grants_keep_request_order_and_reject_duplicate_base_and_bad_name() {
    let full = setup().await;
    let first = full.create_base("First").await.unwrap();
    let second = full.create_base("Second").await.unwrap();
    let mut req = request(second.id(), Mode::ReadOnly);
    req.bases.push(BaseGrantRequest::Existing {
        base: first.id(),
        mode: Mode::ReadWrite,
    });
    let creds = full.connect_app(req.clone()).await.unwrap();
    assert_eq!(creds.bases, vec![second.id(), first.id()]);
    req.bases.push(BaseGrantRequest::Existing {
        base: second.id(),
        mode: Mode::ReadWrite,
    });
    assert!(matches!(
        full.connect_app(req.clone()).await,
        Err(Error::Invalid(_))
    ));
    req.app_name = "x".repeat(61);
    assert!(matches!(
        full.connect_app(req).await,
        Err(Error::Invalid(_))
    ));
}
