use bh_authz::{EdgeClient, EdgeError, EdgeReader, HomeObjectsAck};
use bh_sync::{
    Digest, home_objects,
    wire::{Request, Response},
};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[tokio::test]
async fn immutable_write_reconnects_with_exact_bytes_after_lost_ack_and_returns_credit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = EdgeClient::new(
        format!("ws://{}/v1/data", listener.local_addr().unwrap()),
        Duration::from_secs(3),
    )
    .unwrap();
    let bundle = home_objects::encode(&[1; 242], &[2; 1299], &[3; 1299]).unwrap();
    let expected = bundle.clone();
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(tcp).await.unwrap();
            let Message::Binary(bytes) = ws.next().await.unwrap().unwrap() else {
                panic!()
            };
            let Request::StoreHomeObjects { id, permit, bundle } = Request::decode(&bytes).unwrap()
            else {
                panic!()
            };
            assert_eq!(permit, vec![8; 300]);
            assert_eq!(bundle, expected);
            if attempt == 0 {
                ws.close(None).await.unwrap();
                continue;
            }
            let answer = Response::HomeObjectsStored {
                id,
                prefix_digest: Digest([7; 32]),
                bundle_digest: home_objects::digest(&bundle).unwrap(),
            };
            let bytes = answer.encode().unwrap();
            let len = bytes.len() as u32;
            ws.send(Message::Binary(bytes.into())).await.unwrap();
            let Message::Binary(credit) = ws.next().await.unwrap().unwrap() else {
                panic!()
            };
            assert_eq!(
                Request::decode(&credit).unwrap(),
                Request::Credit { bytes: len }
            );
        }
    });
    assert_eq!(
        client
            .store_home_objects(vec![8; 300], bundle.clone())
            .await
            .unwrap(),
        HomeObjectsAck {
            prefix_digest: Digest([7; 32]),
            bundle_digest: home_objects::digest(&bundle).unwrap()
        }
    );
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn private_writes_and_reads_multiplex_by_id_with_out_of_order_answers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = EdgeClient::new(
        format!("ws://{}/v1/data", listener.local_addr().unwrap()),
        Duration::from_secs(3),
    )
    .unwrap();
    let bundle = home_objects::encode(&[1; 242], &[2; 1299], &[3; 1299]).unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(tcp).await.unwrap();
        // Warm the socket so both following operations share it.
        let Message::Binary(bytes) = ws.next().await.unwrap().unwrap() else {
            panic!()
        };
        let Request::Read { id, .. } = Request::decode(&bytes).unwrap() else {
            panic!()
        };
        ws.send(Message::Binary(
            Response::Events {
                id,
                items: vec![],
                receipt: None,
            }
            .encode()
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
        let mut requests = vec![];
        while requests.len() < 2 {
            let Message::Binary(bytes) = ws.next().await.unwrap().unwrap() else {
                panic!()
            };
            let request = Request::decode(&bytes).unwrap();
            if !matches!(request, Request::Credit { .. }) {
                requests.push(request);
            }
        }
        for r in requests.into_iter().rev() {
            let answer = match r {
                Request::Read { id, .. } => Response::Events {
                    id,
                    items: vec![(vec![1], vec![2])],
                    receipt: None,
                },
                Request::StoreHomeObjects { id, bundle, .. } => Response::HomeObjectsStored {
                    id,
                    prefix_digest: Digest([7; 32]),
                    bundle_digest: home_objects::digest(&bundle).unwrap(),
                },
                _ => panic!(),
            };
            ws.send(Message::Binary(answer.encode().unwrap().into()))
                .await
                .unwrap();
        }
        for _ in 0..2 {
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
        }
    });
    assert_eq!(client.read_log(vec![1]).await.unwrap(), vec![]);
    let (read, stored) = tokio::join!(
        client.read_log(vec![1]),
        client.store_home_objects(vec![2], bundle.clone())
    );
    assert_eq!(read.unwrap(), vec![(vec![1], vec![2])]);
    assert_eq!(
        stored.unwrap().bundle_digest,
        home_objects::digest(&bundle).unwrap()
    );
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn unrelated_response_is_not_a_storage_acknowledgement() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = EdgeClient::new(
        format!("ws://{}/v1/data", listener.local_addr().unwrap()),
        Duration::from_secs(2),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(tcp).await.unwrap();
        let Message::Binary(bytes) = ws.next().await.unwrap().unwrap() else {
            panic!()
        };
        let Request::StoreHomeObjects { id, .. } = Request::decode(&bytes).unwrap() else {
            panic!()
        };
        ws.send(Message::Binary(
            Response::Events {
                id,
                items: vec![],
                receipt: None,
            }
            .encode()
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
        let _ = ws.next().await;
    });
    assert_eq!(
        client
            .store_home_objects(
                vec![1],
                home_objects::encode(&[1; 242], &[2; 1299], &[3; 1299]).unwrap()
            )
            .await,
        Err(EdgeError::Malformed)
    );
    server.await.unwrap();
}
