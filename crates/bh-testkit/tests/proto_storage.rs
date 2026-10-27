use bh_testkit::{LocalServer, RawAccount, b64, random_id};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn base(server: &LocalServer) -> (String, RawAccount) {
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
async fn change(
    owner: &RawAccount,
    base: &str,
    object: &str,
    kind: &str,
    body: &[u8],
    covers: Option<u64>,
    keep: bool,
) -> Value {
    let mut c =
        json!({"changeId": random_id(), "objectId": object, "kind": kind, "body": b64(body)});
    if let Some(covers) = covers {
        c["covers"] = json!(covers);
        c["keep"] = json!(keep);
    }
    let (status, result) = owner
        .full
        .post(
            &format!("/v1/bases/{base}/changes"),
            json!({"changes": [c]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    result
}
async fn storage(owner: &RawAccount, base: &str) -> Value {
    let (status, result) = owner.full.get("/v1/usage", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let rows: Vec<_> = result["months"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["service"] == "storage" && r["base"] == base)
        .collect();
    assert_eq!(rows.len(), 1, "{result}");
    assert!(
        result["days"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["service"] != "storage")
    );
    rows[0].clone()
}
fn bytes(row: &Value) -> u64 {
    row["storedBytes"].as_u64().unwrap()
}

#[tokio::test]
async fn sqlite_database_size_exists_and_grows_after_writes() {
    let server = LocalServer::from_env();
    let (base, owner) = base(server).await;
    let before = bytes(&storage(&owner, &base).await);
    assert!(before > 0, "an empty base still has a SQLite database");
    let object = random_id();
    change(
        &owner,
        &base,
        &object,
        "update",
        &vec![7; 256 * 1024],
        None,
        false,
    )
    .await;
    let after = bytes(&storage(&owner, &base).await);
    assert!(
        after >= before + 256 * 1024,
        "databaseSize must grow with inline writes: {before} -> {after}"
    );
    change(
        &owner,
        &base,
        &object,
        "state",
        b"compacted",
        Some(1),
        false,
    )
    .await;
    let compacted = bytes(&storage(&owner, &base).await);
    println!(
        "SQLite databaseSize before write: {before}; after write: {after}; after compaction: {compacted}"
    );
}

#[tokio::test]
async fn r2_bodies_and_file_parts_raise_stored_bytes_on_read() {
    let server = LocalServer::from_env();
    let (base, owner) = base(server).await;
    let object = random_id();
    let before = bytes(&storage(&owner, &base).await);
    let body = vec![1; 1024 * 1024 + 1]; // R2 change body
    change(&owner, &base, &object, "update", &body, None, false).await;
    let with_body = bytes(&storage(&owner, &base).await);
    assert!(
        with_body >= before + body.len() as u64,
        "R2 body not included"
    );
    let part = format!("/v1/bases/{base}/files/{object}/0");
    assert_eq!(owner.full.put_bytes(&part, b"part").await.0, StatusCode::OK);
    assert_eq!(bytes(&storage(&owner, &base).await), with_body + 4);
    assert_eq!(owner.full.put_bytes(&part, b"part").await.0, StatusCode::OK);
    assert_eq!(bytes(&storage(&owner, &base).await), with_body + 4);
    let next = format!("/v1/bases/{base}/files/{object}/1");
    assert_eq!(owner.full.put_bytes(&next, b"new").await.0, StatusCode::OK);
    assert_eq!(bytes(&storage(&owner, &base).await), with_body + 7);
}

#[tokio::test]
async fn identical_change_retry_does_not_increase_stored_bytes() {
    let server = LocalServer::from_env();
    let (base, owner) = base(server).await;
    let c = json!({"changeId": random_id(), "objectId": random_id(), "kind": "update", "body": b64(b"retry")});
    let path = format!("/v1/bases/{base}/changes");
    assert_eq!(
        owner
            .full
            .post(&path, json!({"changes": [c.clone()]}))
            .await
            .0,
        StatusCode::OK
    );
    let first = bytes(&storage(&owner, &base).await);
    assert_eq!(
        owner.full.post(&path, json!({"changes": [c]})).await.0,
        StatusCode::OK
    );
    assert_eq!(bytes(&storage(&owner, &base).await), first);
}

#[tokio::test]
async fn storage_cost_uses_sqlite_and_r2_rates_with_fifty_percent_markup() {
    let server = LocalServer::from_env();
    let (base, owner) = base(server).await;
    let object = random_id();
    let inline = vec![1; 1024 * 1024];
    change(&owner, &base, &object, "update", &inline, None, false).await;
    let part = format!("/v1/bases/{base}/files/{object}/0");
    assert_eq!(
        owner.full.put_bytes(&part, &vec![2; 4_194_304]).await.0,
        StatusCode::OK
    );
    let row = storage(&owner, &base).await;
    let sqlite = bytes(&row) - 4_194_304;
    assert!(
        sqlite > inline.len() as u64,
        "SQLite includes rows and indexes"
    );
    // Decimal GB; $0.20/GB-month of SQLite plus $0.015/GB-month of R2.
    let cost = (sqlite as f64 * 0.20 / 1000.0 + 4_194_304.0 * 0.015 / 1000.0).round() as u64;
    assert_eq!(row["costMicroUsd"], cost);
    assert_eq!(row["priceMicroUsd"], (cost as f64 * 1.5).round() as u64);
    assert_eq!(row["requests"], 0);
    assert!(row["device"].is_null());
}

#[tokio::test]
async fn storage_is_visible_only_to_its_owners_full_devices() {
    let server = LocalServer::from_env();
    let (base, owner) = base(server).await;
    let app = owner.app(server).await;
    let pending = owner.pending(server).await;
    assert_eq!(
        app.get("/v1/usage", json!({})).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        pending.get("/v1/usage", json!({})).await.0,
        StatusCode::FORBIDDEN
    );
    let stranger = RawAccount::signup(server).await;
    let (status, report) = stranger.full.get("/v1/usage", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !report["months"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["base"] == base)
    );
    assert!(bytes(&storage(&owner, &base).await) > 0);
}
