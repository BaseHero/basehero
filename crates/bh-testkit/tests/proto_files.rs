use bh_testkit::{LocalServer, RawAccount, b64, random_id};
use reqwest::StatusCode;
use serde_json::{Value, json};

async fn base() -> (String, RawAccount) {
    let server = LocalServer::from_env();
    let owner = RawAccount::signup(server).await;
    let id = random_id();
    let (status, reply) = owner
        .full
        .post(
            "/v1/bases",
            json!({"baseId": id, "epoch": 1, "wrapper": b64(&[1; 77])}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    (id, owner)
}
fn path(base: &str, object: &str, part: &str) -> String {
    format!("/v1/bases/{base}/files/{object}/{part}")
}
fn refused(reply: (StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(
        (reply.0, reply.1["error"].as_str()),
        (status, Some(code)),
        "{}",
        reply.1
    );
}

#[tokio::test]
async fn a_part_is_written_once_and_read_back_unchanged() {
    let (base, owner) = base().await;
    let p = path(&base, &random_id(), "0");
    assert_eq!(
        owner.full.put_bytes(&p, b"sealed opaque bytes").await,
        (StatusCode::OK, json!({}))
    );
    assert_eq!(
        owner.full.get_bytes(&p).await,
        (StatusCode::OK, b"sealed opaque bytes".to_vec())
    );
    // A retry whose reply was lost sends the same bytes again.
    assert_eq!(
        owner.full.put_bytes(&p, b"sealed opaque bytes").await,
        (StatusCode::OK, json!({}))
    );
    refused(
        owner.full.put_bytes(&p, b"different").await,
        StatusCode::CONFLICT,
        "exists",
    );
    assert_eq!(owner.full.get_bytes(&p).await.1, b"sealed opaque bytes");
}

#[tokio::test]
async fn parts_are_at_most_4_mib_plus_45_bytes_and_25_per_file() {
    let (base, owner) = base().await;
    let object = random_id();
    assert_eq!(
        owner
            .full
            .put_bytes(&path(&base, &object, "0"), &vec![7; 4_194_349])
            .await
            .0,
        StatusCode::OK
    );
    refused(
        owner
            .full
            .put_bytes(&path(&base, &object, "1"), &vec![7; 4_194_350])
            .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    );
    assert_eq!(
        owner
            .full
            .put_bytes(&path(&base, &object, "24"), b"x")
            .await
            .0,
        StatusCode::OK
    );
    refused(
        owner
            .full
            .put_bytes(&path(&base, &object, "25"), b"x")
            .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    );
    refused(
        owner.full.put_bytes(&path(&base, &object, "x"), b"x").await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
}

#[tokio::test]
async fn members_read_parts_and_only_writers_add_them() {
    let (base, owner) = base().await;
    let server = LocalServer::from_env();
    let object = random_id();
    let p = path(&base, &object, "0");
    let stranger = RawAccount::signup(server).await;
    refused(
        stranger.full.put_bytes(&p, b"x").await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_eq!(stranger.full.get_bytes(&p).await.0, StatusCode::FORBIDDEN);
    let app = owner.app(server).await;
    let (status, reply) = owner
        .full
        .put(
            &format!("/v1/bases/{base}/grants/{}", app.device_id),
            json!({"mode":"ro", "epoch":1, "wrapper": b64(&[1; 77])}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    refused(
        app.put_bytes(&p, b"x").await,
        StatusCode::FORBIDDEN,
        "read_only",
    );
    assert_eq!(owner.full.put_bytes(&p, b"x").await.0, StatusCode::OK);
    assert_eq!(app.get_bytes(&p).await, (StatusCode::OK, b"x".to_vec()));
    let pending = owner.pending(server).await;
    refused(
        pending.put_bytes(&p, b"x").await,
        StatusCode::FORBIDDEN,
        "pending",
    );
    assert_eq!(pending.get_bytes(&p).await.0, StatusCode::FORBIDDEN);
    let (status, reply) = owner
        .full
        .delete(&format!("/v1/devices/{}", app.device_id), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    refused(
        app.put_bytes(&p, b"x").await,
        StatusCode::UNAUTHORIZED,
        "revoked",
    );
    assert_eq!(app.get_bytes(&p).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_missing_part_is_not_found() {
    let (base, owner) = base().await;
    assert_eq!(
        owner
            .full
            .get_bytes(&path(&base, &random_id(), "3"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}
