//! The fake hosted environment, a real signed-up device and a device about
//! to join by pairing.
pub mod device;
pub mod fake;
pub mod pair;

use bh_authz::proto::{FromService, ToService, Want, rotation_body};
use bh_sync::{
    Digest,
    permit::LogId,
    wire::{Request, Response},
};
use bh_sync_client::{Client, data::DataSocket};
use std::sync::Arc;

/// Stage a rotation's padded body on `log` under a permit `client` asks
/// for, as the trust lane does before it names the body: its commitment.
#[allow(dead_code)]
pub async fn stage_rotation(
    hosted: &Arc<fake::Hosted>,
    client: &Client,
    log: LogId,
    raw: &[u8],
) -> Digest {
    let body = rotation_body(raw).unwrap();
    let answer = client
        .authz()
        .await
        .unwrap()
        .ask(ToService::Permits {
            items: vec![Want::Stage {
                log,
                body: body.commitment(),
                len: body.bytes().len() as u32,
            }],
        })
        .await
        .unwrap();
    let FromService::Permits { mut items } = answer else {
        panic!("{answer:?}")
    };
    let permit = items.remove(0).unwrap();
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let bytes = body.bytes().to_vec();
    let staged = data
        .ask(|id| Request::Stage {
            id,
            permit,
            body: bytes,
        })
        .await
        .unwrap();
    assert!(matches!(staged, Response::Staged { .. }), "{staged:?}");
    body.commitment()
}
