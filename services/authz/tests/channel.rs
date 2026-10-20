//! The service behind a real WebSocket and attested channel, with the labelled
//! synthetic attestation a local device appraises.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::{
    SyntheticAttestation,
    proto::{FromService, Refusal, ToService},
};
use bh_crypto::{SecretBytes, SigningKey};
use std::time::Duration;
use support::{device::*, *};
use tokio::net::TcpListener;
use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};

#[tokio::test]
async fn a_device_authenticates_over_the_attested_channel() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create(&device);
    harness.publish(&account);
    let service = harness.service();
    let policy_root = SigningKey::generate();
    let config = channel_config(&policy_root);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/channel", listener.local_addr().unwrap());
    let server = service.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let service = server.clone();
            let config = config.clone();
            tokio::spawn(async move {
                let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let _ = service
                    .serve_connection(ws, &config, &SyntheticAttestation)
                    .await;
            });
        }
    });

    let (mut ws, mut session) = open(&url, &policy_root).await;
    let FromService::Challenge { challenge } = receive(&mut ws, &mut session).await else {
        panic!("challenge first")
    };
    let binding = session.binding().unwrap();
    let answer = ask(
        &mut ws,
        &mut session,
        authenticate_message(&account, &device, binding, challenge),
    )
    .await;
    assert!(
        matches!(answer, FromService::Authenticated { account_head } if account_head == account.verified.head()),
        "{answer:?}"
    );
    let answer = ask(
        &mut ws,
        &mut session,
        ToService::Permits {
            items: vec![read_events(account.log)],
        },
    )
    .await;
    single_permit(answer);
    // A record that is not a message is answered Malformed; the session stays.
    let sealed = session.seal(SecretBytes::from_vec(vec![9; 3])).unwrap();
    send(&mut ws, sealed).await;
    assert!(matches!(
        receive(&mut ws, &mut session).await,
        FromService::Refused {
            reason: Refusal::Malformed
        }
    ));

    // A proof made for another channel's binding does not authenticate here.
    let (mut ws, mut session) = open(&url, &policy_root).await;
    let FromService::Challenge { challenge } = receive(&mut ws, &mut session).await else {
        panic!("challenge first")
    };
    let answer = ask(
        &mut ws,
        &mut session,
        authenticate_message(&account, &device, binding, challenge),
    )
    .await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Unauthenticated
            }
        ),
        "{answer:?}"
    );
}

/// The service over an in-memory socket, so the test can move tokio's clock.
async fn in_memory(
    service: &bh_authz::Service,
    policy_root: &SigningKey,
) -> (
    WebSocketStream<tokio::io::DuplexStream>,
    bh_confidential_channel::record::Session<Memory>,
    tokio::task::JoinHandle<()>,
) {
    let (device, server) = tokio::io::duplex(1 << 22);
    let config = channel_config(policy_root);
    let service = service.clone();
    let serving = tokio::spawn(async move {
        let ws = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let _ = service
            .serve_connection(ws, &config, &SyntheticAttestation)
            .await;
    });
    let ws = WebSocketStream::from_raw_socket(device, Role::Client, None).await;
    let (ws, session) = handshake(ws, policy_root).await;
    (ws, session, serving)
}

#[tokio::test(start_paused = true)]
async fn a_device_that_does_not_authenticate_in_time_is_closed() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create(&device);
    harness.publish(&account);
    let service = harness.service();
    let policy_root = SigningKey::generate();
    // Silent after the channel: closed 30 s after the connection began.
    let (mut ws, mut session, serving) = in_memory(&service, &policy_root).await;
    let FromService::Challenge { .. } = receive(&mut ws, &mut session).await else {
        panic!("challenge first")
    };
    tokio::time::sleep(Duration::from_secs(29)).await;
    assert!(!serving.is_finished());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(serving.is_finished(), "closed at the deadline");
    // Busy but never authenticated: refused requests do not extend it.
    let (mut ws, mut session, serving) = in_memory(&service, &policy_root).await;
    receive(&mut ws, &mut session).await;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(9)).await;
        let answer = ask(
            &mut ws,
            &mut session,
            ToService::Permits {
                items: vec![read_events(account.log)],
            },
        )
        .await;
        assert!(matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Unauthenticated
            }
        ));
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(serving.is_finished(), "closed at the deadline");
    // Authenticated in time: the session outlives the deadline.
    let (mut ws, mut session, serving) = in_memory(&service, &policy_root).await;
    let FromService::Challenge { challenge } = receive(&mut ws, &mut session).await else {
        panic!("challenge first")
    };
    let binding = session.binding().unwrap();
    let answer = ask(
        &mut ws,
        &mut session,
        authenticate_message(&account, &device, binding, challenge),
    )
    .await;
    assert!(matches!(answer, FromService::Authenticated { .. }));
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(!serving.is_finished());
    single_permit(
        ask(
            &mut ws,
            &mut session,
            ToService::Permits {
                items: vec![read_events(account.log)],
            },
        )
        .await,
    );
}
