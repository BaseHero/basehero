use bh_testkit::{LocalServer, RawAccount, b64, random_id};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn base() -> (String, RawAccount) {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let id = random_id();
    assert_eq!(
        owner
            .full
            .post(
                "/v1/bases",
                json!({"baseId": id, "epoch": 1, "wrapper": b64(&[1; 77])})
            )
            .await
            .0,
        StatusCode::OK
    );
    (id, owner)
}
fn change(object: &str, kind: &str, covers: Option<u64>, keep: bool, body: &[u8]) -> Value {
    let mut c =
        json!({"changeId": random_id(), "objectId": object, "kind": kind, "body": b64(body)});
    if let Some(n) = covers {
        c["covers"] = json!(n);
        c["keep"] = json!(keep);
    }
    c
}
async fn post(owner: &RawAccount, base: &str, changes: Vec<Value>) -> Value {
    let (status, reply) = owner
        .full
        .post(
            &format!("/v1/bases/{base}/changes"),
            json!({"changes": changes}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    reply
}
fn list(base: &str, object: &str, params: &str) -> String {
    format!("/v1/bases/{base}/objects/{object}/versions{params}")
}
#[tokio::test]
async fn kept_states_are_listed_newest_first_in_pages() {
    let (base, owner) = base().await;
    let x = random_id();
    post(&owner, &base, vec![change(&x, "update", None, false, b"1")]).await;
    let a = post(
        &owner,
        &base,
        vec![change(&x, "state", Some(1), true, b"A")],
    )
    .await["results"][0]["seq"]
        .as_u64()
        .unwrap();
    post(&owner, &base, vec![change(&x, "update", None, false, b"3")]).await;
    post(
        &owner,
        &base,
        vec![change(&x, "state", Some(3), false, b"unkept")],
    )
    .await;
    post(&owner, &base, vec![change(&x, "update", None, false, b"5")]).await;
    let b = post(
        &owner,
        &base,
        vec![change(&x, "state", Some(5), true, b"BB")],
    )
    .await["results"][0]["seq"]
        .as_u64()
        .unwrap();
    post(&owner, &base, vec![change(&x, "update", None, false, b"7")]).await;
    let c = post(
        &owner,
        &base,
        vec![change(&x, "state", Some(7), true, b"CCC")],
    )
    .await["results"][0]["seq"]
        .as_u64()
        .unwrap();
    let (status, all) = owner.full.get(&list(&base, &x, ""), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(
        all["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![c, b, a]
    );
    assert_eq!(all["versions"][0]["size"], 3);
    assert_eq!(all["versions"][0]["covers"], 7);
    assert_eq!(all["versions"][0]["deviceId"], owner.full.device_id);
    assert!(all["versions"][0]["at"].as_i64().unwrap() > 0);
    assert_eq!(all["more"], false);
    let (_, page) = owner
        .full
        .get(&list(&base, &x, "?limit=2"), json!({}))
        .await;
    assert_eq!(
        (
            page["versions"][0]["seq"].as_u64(),
            page["versions"][1]["seq"].as_u64(),
            page["more"].as_bool()
        ),
        (Some(c), Some(b), Some(true))
    );
    let (_, page) = owner
        .full
        .get(&list(&base, &x, &format!("?before={b}&limit=2")), json!({}))
        .await;
    assert_eq!(page["versions"][0]["seq"], a);
    assert_eq!(page["more"], false);
    for bad in ["?limit=0", "?before=x", "?limit=1.5"] {
        assert_eq!(
            owner.full.get(&list(&base, &x, bad), json!({})).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, capped) = owner
        .full
        .get(&list(&base, &x, "?limit=201"), json!({}))
        .await;
    assert_eq!(capped["versions"].as_array().unwrap().len(), 3);
}
#[tokio::test]
async fn a_version_is_fetched_by_its_seq() {
    let (base, owner) = base().await;
    let x = random_id();
    post(&owner, &base, vec![change(&x, "update", None, false, b"1")]).await;
    let a = post(
        &owner,
        &base,
        vec![change(&x, "state", Some(1), true, b"kept")],
    )
    .await["results"][0]["seq"]
        .as_u64()
        .unwrap();
    post(&owner, &base, vec![change(&x, "update", None, false, b"3")]).await;
    let unkept = post(
        &owner,
        &base,
        vec![change(&x, "state", Some(3), false, b"other")],
    )
    .await["results"][0]["seq"]
        .as_u64()
        .unwrap();
    let (status, reply) = owner
        .full
        .get(&format!("{}/{a}", list(&base, &x, "")), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["body"], b64(b"kept"));
    assert_eq!(reply["covers"], 1);
    assert_eq!(
        owner
            .full
            .get(&format!("{}/{unkept}", list(&base, &x, "")), json!({}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        owner
            .full
            .get(&format!("{}/{a}", list(&base, &random_id(), "")), json!({}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}
#[tokio::test]
async fn a_kept_state_may_cover_what_the_current_state_covers() {
    let (base, owner) = base().await;
    let x = random_id();
    for _ in 0..5 {
        post(&owner, &base, vec![change(&x, "update", None, false, b"x")]).await;
    }
    assert_eq!(
        post(
            &owner,
            &base,
            vec![change(&x, "state", Some(5), false, b"current")]
        )
        .await["results"][0]["stale"],
        false
    );
    assert_eq!(
        post(
            &owner,
            &base,
            vec![change(&x, "state", Some(5), true, b"kept")]
        )
        .await["results"][0]["stale"],
        false
    );
    assert_eq!(
        post(
            &owner,
            &base,
            vec![change(&x, "state", Some(5), false, b"same")]
        )
        .await["results"][0]["stale"],
        true
    );
    assert_eq!(
        post(
            &owner,
            &base,
            vec![change(&x, "state", Some(4), true, b"old")]
        )
        .await["results"][0]["stale"],
        true
    );
}
#[tokio::test]
async fn kept_state_bodies_always_go_to_r2() {
    let server = LocalServer::start();
    let owner = RawAccount::signup(&server).await;
    let base = random_id();
    let x = random_id();
    assert_eq!(
        owner
            .full
            .post(
                "/v1/bases",
                json!({"baseId":base,"epoch":1,"wrapper":b64(&[1;77])})
            )
            .await
            .0,
        StatusCode::OK
    );
    post(&owner, &base, vec![change(&x, "update", None, false, b"x")]).await;
    post(
        &owner,
        &base,
        vec![change(&x, "state", Some(1), true, &vec![7; 10240])],
    )
    .await;
    post(&owner, &base, vec![change(&x, "update", None, false, b"y")]).await;
    post(
        &owner,
        &base,
        vec![change(&x, "state", Some(3), false, &vec![8; 10240])],
    )
    .await;
    let (_, stored) = owner
        .full
        .get(&format!("/v1/bases/{base}/stored?object={x}"), json!({}))
        .await;
    assert_eq!(
        stored["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["keep"].as_bool(), c["inR2"].as_bool()))
            .collect::<Vec<_>>(),
        vec![(Some(true), Some(true)), (Some(false), Some(false))]
    );
    let (_, kept) = owner
        .full
        .get(&format!("{}/2", list(&base, &x, "")), json!({}))
        .await;
    assert_eq!(kept["body"], b64(&vec![7; 10240]));
    let (_, fetched) = owner
        .full
        .post(&format!("/v1/bases/{base}/fetch"), json!({"objectIds":[x]}))
        .await;
    assert_eq!(fetched["objects"][0]["state"]["body"], b64(&vec![8; 10240]));
}
#[tokio::test]
async fn only_members_list_versions() {
    let (base, owner) = base().await;
    let x = random_id();
    let stranger = RawAccount::signup(LocalServer::from_env()).await;
    let (status, reply) = stranger.full.get(&list(&base, &x, ""), json!({})).await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );
    let (status, reply) = owner.full.get(&list(&base, &x, ""), json!({})).await;
    assert_eq!(
        (status, reply),
        (StatusCode::OK, json!({"versions":[],"more":false}))
    );
    let pending = owner.pending(LocalServer::from_env()).await;
    for route in [list(&base, &x, ""), format!("{}/1", list(&base, &x, ""))] {
        let (status, reply) = pending.get(&route, json!({})).await;
        assert_eq!(
            (status, reply["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("pending"))
        );
    }
    let app = owner.app(LocalServer::from_env()).await;
    let (status, reply) = owner
        .full
        .put(
            &format!("/v1/bases/{base}/grants/{}", app.device_id),
            json!({"mode":"ro","epoch":1,"wrapper":b64(&[1;77])}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        app.get(&list(&base, &x, ""), json!({})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        owner
            .full
            .delete(&format!("/v1/devices/{}", app.device_id), json!({}))
            .await
            .0,
        StatusCode::OK
    );
    let (status, reply) = app.get(&list(&base, &x, ""), json!({})).await;
    assert_eq!(
        (status, reply["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("revoked"))
    );
}
