use bh_testkit::{LocalServer, RawAccount, RawDevice, b64, local_only, random, random_id, unb64};
use reqwest::StatusCode;
use serde_json::{Value, json};

const MIB: usize = 1024 * 1024;

struct Base {
    id: String,
    owner: RawAccount,
}
impl Base {
    async fn new(s: &LocalServer) -> Self {
        let owner = RawAccount::signup(s).await;
        let id = random_id();
        let (status, body) = owner
            .full
            .post(
                "/v1/bases",
                json!({"baseId": id, "epoch": 1, "wrapper": b64(&random(77))}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        Self { id, owner }
    }
    fn device(&self) -> &RawDevice {
        &self.owner.full
    }
    async fn try_post(&self, device: &RawDevice, changes: Vec<Value>) -> (StatusCode, Value) {
        device
            .post(
                &format!("/v1/bases/{}/changes", self.id),
                json!({ "changes": changes }),
            )
            .await
    }
    async fn post(&self, changes: Vec<Value>) -> Value {
        let (status, body) = self.try_post(self.device(), changes).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
    async fn since(&self, after: u64, limit: Option<u64>) -> Value {
        let limit = limit.map(|l| format!("&limit={l}")).unwrap_or_default();
        let (status, body) = self
            .device()
            .get(
                &format!("/v1/bases/{}/since?after={after}{limit}", self.id),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
    async fn try_fetch(&self, ids: &[String]) -> (StatusCode, Value) {
        self.device()
            .post(
                &format!("/v1/bases/{}/fetch", self.id),
                json!({ "objectIds": ids }),
            )
            .await
    }
    async fn fetch(&self, ids: &[String]) -> Value {
        let (status, body) = self.try_fetch(ids).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
    /// What the server still stores for an object (a test-only view).
    async fn stored(&self, object: &str) -> Value {
        let (status, body) = self
            .device()
            .get(
                &format!("/v1/bases/{}/stored?object={object}", self.id),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}
fn update(object: &str, body: &[u8]) -> Value {
    json!({"changeId": random_id(), "objectId": object, "kind": "update", "body": b64(body)})
}
fn state(object: &str, covers: u64, keep: bool, body: &[u8]) -> Value {
    json!({"changeId": random_id(), "objectId": object, "kind": "state", "body": b64(body),
        "covers": covers, "keep": keep})
}
fn seqs(values: &Value) -> Vec<u64> {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["seq"].as_u64().unwrap())
        .collect()
}
fn refused(response: (StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(
        (response.0, response.1["error"].as_str()),
        (status, Some(code)),
        "{}",
        response.1
    );
}

#[tokio::test]
async fn changes_get_sequence_numbers_prev_heads_and_tails() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let (x, y) = (random_id(), random_id());
    let changes = vec![update(&x, b"a"), update(&x, b"b"), update(&y, b"c")];
    let reply = base.post(changes.clone()).await;
    let expected: Vec<Value> = changes
        .iter()
        .zip([(1, 0, 1), (2, 1, 2), (3, 0, 1)])
        .map(|(c, (seq, prev, tail))| {
            json!({"changeId": c["changeId"], "seq": seq, "prevHead": prev, "tail": tail, "stale": false})
        })
        .collect();
    assert_eq!(reply, json!({"results": expected, "head": 3}));
}

#[tokio::test]
async fn a_repeated_change_id_returns_its_original_result() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    let first = update(&x, b"a");
    let reply = base.post(vec![first.clone()]).await;
    assert_eq!(reply["results"][0]["seq"], 1);
    base.post(vec![update(&x, b"b")]).await;
    let again = base.post(vec![first]).await;
    assert_eq!(again["results"][0]["seq"], 1);
    assert_eq!(again["results"][0]["prevHead"], 0);
    assert_eq!(again["results"][0]["stale"], false);
    assert_eq!(again["head"], 2);
}

#[tokio::test]
async fn a_repeated_large_change_id_returns_its_original_result() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    let big = random(MIB + 1);
    let first = update(&x, &big);
    let original = base.post(vec![first.clone()]).await["results"][0].clone();
    base.post(vec![update(&x, b"later")]).await;
    let again = base.post(vec![first]).await;
    assert_eq!(again["results"][0]["seq"], original["seq"]);
    assert_eq!(again["results"][0]["prevHead"], original["prevHead"]);
    assert_eq!(again["head"], 2);
    let fetched = base.fetch(&[x]).await;
    assert_eq!(unb64(&fetched["objects"][0]["updates"][0]["body"]), big);
    assert_eq!(seqs(&fetched["objects"][0]["updates"]), vec![1, 2]);
}

#[tokio::test]
async fn since_lists_changed_objects_in_head_order_with_more() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let objects: Vec<String> = (0..5).map(|_| random_id()).collect();
    base.post(objects.iter().map(|o| update(o, b"x")).collect())
        .await;
    let page = base.since(0, Some(2)).await;
    assert_eq!(
        page,
        json!({"head": 5, "more": true, "objects": [
            {"objectId": objects[0], "head": 1}, {"objectId": objects[1], "head": 2}]})
    );
    // Editing the first object moves it to the end of head order.
    base.post(vec![update(&objects[0], b"y")]).await;
    let rest = base.since(2, None).await;
    let listed: Vec<&str> = rest["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["objectId"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        vec![&objects[2], &objects[3], &objects[4], &objects[0]]
    );
    assert_eq!(
        (rest["head"].clone(), rest["more"].clone()),
        (json!(6), json!(false))
    );
    assert_eq!(base.since(6, None).await["objects"], json!([]));
}

#[tokio::test]
async fn fetch_returns_state_and_later_updates() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    base.post(vec![update(&x, b"1"), update(&x, b"2"), update(&x, b"3")])
        .await;
    let reply = base.post(vec![state(&x, 2, false, b"s")]).await;
    assert_eq!(
        reply["results"][0],
        json!({"changeId": reply["results"][0]["changeId"], "seq": 4, "prevHead": 3, "tail": 1, "stale": false})
    );
    base.post(vec![update(&x, b"5")]).await;
    let fetched = base.fetch(std::slice::from_ref(&x)).await;
    let device = &base.device().device_id;
    assert_eq!(
        fetched,
        json!({"more": [], "objects": [{
            "objectId": x, "head": 5,
            "state": {"seq": 4, "covers": 2, "deviceId": device, "body": b64(b"s")},
            "updates": [{"seq": 3, "deviceId": device, "body": b64(b"3")},
                        {"seq": 5, "deviceId": device, "body": b64(b"5")}]
        }]})
    );
    // An object with no changes is empty, not an error.
    let unknown = random_id();
    let fetched = base.fetch(std::slice::from_ref(&unknown)).await;
    assert_eq!(
        fetched["objects"][0],
        json!({"objectId": unknown, "head": 0, "state": null, "updates": []})
    );
}

#[tokio::test]
async fn a_state_covering_less_than_the_current_one_is_stale() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    base.post(vec![update(&x, b"1"), update(&x, b"2"), update(&x, b"3")])
        .await;
    assert_eq!(
        base.post(vec![state(&x, 2, false, b"s")]).await["results"][0]["seq"],
        4
    );
    for covers in [1, 2] {
        let reply = base.post(vec![state(&x, covers, false, b"old")]).await;
        assert_eq!(reply["results"][0]["stale"], true);
        assert_eq!(reply["results"][0]["seq"], Value::Null);
        assert_eq!(reply["head"], 4);
    }
    assert_eq!(seqs(&base.stored(&x).await["changes"]), vec![3, 4]);
}

#[tokio::test]
async fn a_state_cannot_cover_past_the_head() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let (x, y) = (random_id(), random_id());
    base.post(vec![update(&x, b"1"), update(&y, b"2")]).await;
    // X's head is 1, though the base's head is 2.
    let reply = base.post(vec![state(&x, 2, false, b"s")]).await;
    assert_eq!(reply["results"][0]["stale"], true);
    assert_eq!(reply["results"][0]["seq"], Value::Null);
    // A new object can't start with a state.
    let reply = base.post(vec![state(&random_id(), 0, false, b"s")]).await;
    assert_eq!(reply["results"][0]["stale"], true);
}

#[tokio::test]
async fn compaction_deletes_covered_updates_and_unkept_states() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    base.post(vec![update(&x, b"1"), update(&x, b"2"), update(&x, b"3")])
        .await;
    // The first state is large, so its body lives in R2 until it is replaced.
    let big = random(MIB + 1);
    base.post(vec![state(&x, 3, false, &big)]).await;
    let r2_key = format!("b/{}/{x}/4", base.id);
    assert_eq!(base.stored(&x).await["r2"], json!([r2_key]));
    base.post(vec![update(&x, b"5"), update(&x, b"6")]).await;
    let reply = base.post(vec![state(&x, 5, false, b"s")]).await;
    assert_eq!(reply["results"][0]["seq"], 7);
    assert_eq!(reply["results"][0]["tail"], 1);
    let stored = base.stored(&x).await;
    assert_eq!(seqs(&stored["changes"]), vec![6, 7]);
    assert_eq!(stored["r2"], json!([]));
    let fetched = base.fetch(std::slice::from_ref(&x)).await;
    assert_eq!(fetched["objects"][0]["state"]["covers"], 5);
    assert_eq!(seqs(&fetched["objects"][0]["updates"]), vec![6]);
}

#[tokio::test]
async fn a_kept_state_survives_later_compaction() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    base.post(vec![update(&x, b"1"), update(&x, b"2")]).await;
    base.post(vec![state(&x, 2, true, b"kept")]).await;
    base.post(vec![update(&x, b"4")]).await;
    base.post(vec![state(&x, 4, false, b"s")]).await;
    assert_eq!(seqs(&base.stored(&x).await["changes"]), vec![3, 5]);
    let fetched = base.fetch(std::slice::from_ref(&x)).await;
    assert_eq!(fetched["objects"][0]["state"]["seq"], 5);
    assert_eq!(fetched["objects"][0]["updates"], json!([]));
}

#[tokio::test]
async fn large_bodies_round_trip_through_r2() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    let (first, second) = (random(2 * MIB), random(8 * MIB));
    // A request's bodies total at most 8 MiB, so these go one at a time.
    base.post(vec![update(&x, &first)]).await;
    base.post(vec![update(&x, &second)]).await;
    assert_eq!(
        base.stored(&x).await["r2"],
        json!([
            format!("b/{}/{x}/1", base.id),
            format!("b/{}/{x}/2", base.id)
        ])
    );
    let fetched = base.fetch(std::slice::from_ref(&x)).await;
    let updates = fetched["objects"][0]["updates"].as_array().unwrap();
    assert_eq!(unb64(&updates[0]["body"]), first);
    assert_eq!(unb64(&updates[1]["body"]), second);
}

#[tokio::test]
async fn oversized_bodies_and_fetches_are_refused() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let x = random_id();
    refused(
        base.try_post(base.device(), vec![update(&x, &random(8 * MIB + 1))])
            .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    );
    refused(
        base.try_post(
            base.device(),
            // Exceed the decoded 8 MiB limit without tripping the separate
            // Content-Length guard, which rejects before reading the upload.
            vec![
                update(&x, &random(4 * MIB)),
                update(&x, &random(4 * MIB + 1)),
            ],
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    );
    assert_eq!(base.since(0, None).await["head"], 0);
    let ids: Vec<String> = (0..201).map(|_| random_id()).collect();
    refused(
        base.try_fetch(&ids).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    assert_eq!(
        base.fetch(&ids[..200]).await["objects"]
            .as_array()
            .unwrap()
            .len(),
        200
    );
    refused(
        base.try_fetch(&[x.to_uppercase()]).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
}

#[tokio::test]
async fn a_read_only_device_cannot_post_changes() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let app = base.owner.app(s).await;
    let (status, _) = base
        .device()
        .put(
            &format!("/v1/bases/{}/grants/{}", base.id, app.device_id),
            json!({"mode": "ro", "epoch": 1, "wrapper": b64(&random(77))}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let x = random_id();
    base.post(vec![update(&x, b"1")]).await;
    refused(
        base.try_post(&app, vec![update(&x, b"2")]).await,
        StatusCode::FORBIDDEN,
        "read_only",
    );
    let (status, fetched) = app
        .post(
            &format!("/v1/bases/{}/fetch", base.id),
            json!({"objectIds": [x]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_eq!(seqs(&fetched["objects"][0]["updates"]), vec![1]);
    let stranger = RawAccount::signup(s).await;
    refused(
        base.try_post(&stranger.full, vec![update(&x, b"3")]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
}

#[tokio::test]
async fn fetch_replies_are_capped_with_more() {
    let s = LocalServer::from_env();
    let base = Base::new(s).await;
    let objects: Vec<String> = (0..20).map(|_| random_id()).collect();
    // States are over the inline limit and must be read through R2. Each batch stays under 8 MiB.
    base.post(objects.iter().map(|o| update(o, b"u")).collect())
        .await;
    let bodies: Vec<Vec<u8>> = (0..objects.len()).map(|_| random(MIB + 1)).collect();
    for (offset, chunk) in objects.chunks(5).enumerate() {
        base.post(
            chunk
                .iter()
                .enumerate()
                .map(|(i, o)| {
                    let index = offset * 5 + i;
                    state(o, (index + 1) as u64, false, &bodies[index])
                })
                .collect(),
        )
        .await;
    }
    let first = base.fetch(&objects).await;
    let returned = first["objects"].as_array().unwrap();
    let bytes: usize = returned
        .iter()
        .map(|o| unb64(&o["state"]["body"]).len())
        .sum();
    assert!(bytes <= 16 * MIB, "{bytes} bytes");
    let more: Vec<String> = first["more"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_str().unwrap().to_string())
        .collect();
    assert!(!more.is_empty());
    assert_eq!(returned.len() + more.len(), 20);
    for (i, object) in returned.iter().enumerate() {
        assert_eq!(object["objectId"], objects[i]);
        assert_eq!(unb64(&object["state"]["body"]), bodies[i]);
    }
    let second = base.fetch(&more).await;
    assert_eq!(second["more"], json!([]));
    for (i, object) in second["objects"].as_array().unwrap().iter().enumerate() {
        assert_eq!(object["objectId"], more[i]);
        assert_eq!(unb64(&object["state"]["body"]), bodies[returned.len() + i]);
    }
    let mut all: Vec<&str> = returned
        .iter()
        .chain(second["objects"].as_array().unwrap())
        .map(|o| o["objectId"].as_str().unwrap())
        .collect();
    all.sort();
    let mut expected: Vec<&str> = objects.iter().map(String::as_str).collect();
    expected.sort();
    assert_eq!(all, expected);
}
#[tokio::test]
async fn more_than_fifty_change_requests_a_second_are_limited() {
    local_only!();
    // A minute-long window makes the count independent of how fast this machine is.
    let s = LocalServer::start_with_vars(&[("CHANGE_RATE_WINDOW_MS", "60000")]);
    let base = Base::new(&s).await;
    for _ in 0..50 {
        base.post(vec![update(&random_id(), b"x")]).await;
    }
    refused(
        base.try_post(base.device(), vec![update(&random_id(), b"x")])
            .await,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
    );
    // Other requests from the device are not counted.
    assert_eq!(base.since(0, None).await["head"], 50);
}
