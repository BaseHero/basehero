//! The edge data-socket client against a loopback socket speaking the data
//! wire: it reads under the given permit, multiplexes reads by request id on a
//! few sockets, grants back each Events frame's length as credit, and fails or
//! retries reads when a socket drops.
use bh_authz::{EdgeClient, EdgeError, EdgeReader};
use bh_sync::wire::{Refusal, Request, Response};
use futures_util::{
    SinkExt, StreamExt,
    future::{BoxFuture, join_all},
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_tungstenite::tungstenite::Message;

/// How the fake edge answers.
#[derive(Clone, Copy)]
struct Behaviour {
    /// How long it takes to answer a read, by its permit.
    delay: fn(&[u8]) -> Duration,
    /// The first this many connections close on their first read, unanswered.
    drop_sockets: usize,
    /// A connection closes after answering this many reads and their credit.
    per_socket: usize,
    /// The first this many TCP connections are accepted and held open, but
    /// their WebSocket upgrade is never answered.
    stall_upgrades: usize,
}
const PROMPT: Behaviour = Behaviour {
    delay: |_| Duration::ZERO,
    drop_sockets: 0,
    per_socket: usize::MAX,
    stall_upgrades: 0,
};

/// What the fake edge saw: per connection, each request it decoded, and the
/// most reads it ever had unanswered at once.
#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<Vec<Request>>>,
    most_in_flight: Mutex<Vec<usize>>,
    connections: AtomicUsize,
}

/// A permit starting with this byte is answered as a body read.
const BODIES: u8 = 0xb0;

/// A body read's answer: one Body frame per permit byte after the first,
/// each that byte repeated, the last marked.
fn body_frames(id: u32, permit: &[u8]) -> Vec<Response> {
    let count = permit.len() - 1;
    permit[1..]
        .iter()
        .enumerate()
        .map(|(index, byte)| Response::Body {
            id,
            index: index as u8,
            last: index + 1 == count,
            bytes: vec![*byte; 100 + index],
        })
        .collect()
}

/// Answers each Read with one Events frame carrying its permit back, Body
/// frames for a body read, or Refused for a permit of `[0]`, after the
/// behaviour's delay.
async fn fake_edge(behaviour: Behaviour) -> (String, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/data", listener.local_addr().unwrap());
    let seen = Arc::new(Seen::default());
    let record = seen.clone();
    tokio::spawn(async move {
        let mut stalled = vec![];
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            if stalled.len() < behaviour.stall_upgrades {
                stalled.push(stream);
                continue;
            }
            let seen = record.clone();
            tokio::spawn(async move {
                let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let index = seen.connections.fetch_add(1, Ordering::SeqCst);
                seen.requests.lock().unwrap().push(vec![]);
                seen.most_in_flight.lock().unwrap().push(0);
                let (mut sink, mut stream) = ws.split();
                let (out, mut outgoing) = mpsc::unbounded_channel::<Message>();
                tokio::spawn(async move {
                    while let Some(message) = outgoing.recv().await {
                        if sink.send(message).await.is_err() {
                            break;
                        }
                    }
                    let _ = sink.close().await;
                });
                let in_flight = Arc::new(AtomicUsize::new(0));
                let answered = Arc::new(AtomicUsize::new(0));
                while let Some(Ok(Message::Binary(bytes))) = stream.next().await {
                    let request = Request::decode(&bytes).unwrap();
                    seen.requests.lock().unwrap()[index].push(request.clone());
                    let Request::Read { id, permit } = request else {
                        if answered.load(Ordering::SeqCst) >= behaviour.per_socket {
                            break;
                        }
                        continue;
                    };
                    if index < behaviour.drop_sockets {
                        break;
                    }
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    let most = &mut seen.most_in_flight.lock().unwrap()[index];
                    *most = (*most).max(now);
                    let (out, in_flight, answered) =
                        (out.clone(), in_flight.clone(), answered.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep((behaviour.delay)(&permit)).await;
                        let responses = if permit == [0] {
                            vec![Response::Refused {
                                id,
                                reason: Refusal::Expired,
                            }]
                        } else if permit.first() == Some(&BODIES) {
                            body_frames(id, &permit)
                        } else {
                            vec![Response::Events {
                                id,
                                items: vec![(vec![1; 178], permit.clone())],
                                receipt: Some([0x5a; 300]),
                            }]
                        };
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        answered.fetch_add(1, Ordering::SeqCst);
                        for response in responses {
                            let _ = out.send(Message::Binary(response.encode().unwrap().into()));
                        }
                    });
                }
                // Dropping the last sender closes the socket.
            });
        }
    });
    (url, seen)
}

fn frame_len(id: u32, permit: Vec<u8>) -> u32 {
    Response::Events {
        id,
        items: vec![(vec![1; 178], permit)],
        receipt: Some([0x5a; 300]),
    }
    .encode()
    .unwrap()
    .len() as u32
}

#[tokio::test]
async fn an_adapter_with_only_legacy_rows_never_invents_a_receipt() {
    struct Legacy;
    impl EdgeReader for Legacy {
        fn read_log(&self, _: Vec<u8>) -> BoxFuture<'_, Result<bh_authz::LogItems, EdgeError>> {
            Box::pin(async { Ok(vec![(vec![1], vec![2])]) })
        }
        fn read_bodies(&self, _: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
            Box::pin(async { Ok(vec![]) })
        }
    }
    assert_eq!(Legacy.read_log(vec![]).await.unwrap().len(), 1);
    assert!(matches!(
        Legacy.read_log_with_receipt(vec![]).await,
        Err(EdgeError::Unavailable)
    ));
}

#[tokio::test]
async fn receipt_is_preserved_while_legacy_read_intentionally_strips_it() {
    let (url, seen) = fake_edge(PROMPT).await;
    let client = EdgeClient::new(url, Duration::from_secs(5)).unwrap();
    let result = client.read_log_with_receipt(vec![7; 300]).await.unwrap();
    assert_eq!(result.items, vec![(vec![1; 178], vec![7; 300])]);
    assert_eq!(result.receipt, Some([0x5a; 300]));
    assert_eq!(
        client.read_log(vec![8; 300]).await.unwrap(),
        vec![(vec![1; 178], vec![8; 300])]
    );
    tokio::task::yield_now().await;
    let requests = seen.requests.lock().unwrap();
    assert!(requests[0].contains(&Request::Credit {
        bytes: frame_len(1, vec![7; 300])
    }));
}

#[tokio::test]
async fn reads_grant_credit_and_reuse_sockets() {
    let (url, seen) = fake_edge(PROMPT).await;
    let client = EdgeClient::new(url, Duration::from_secs(5)).unwrap();
    let items = client.read_log(vec![7; 300]).await.unwrap();
    assert_eq!(items, vec![(vec![1; 178], vec![7; 300])]);
    assert_eq!(
        client.read_log(vec![0]).await.err(),
        Some(EdgeError::Refused)
    );
    client.read_log(vec![8; 10]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let requests = seen.requests.lock().unwrap();
    assert_eq!(requests.len(), 1, "one socket, reused");
    assert!(
        requests[0]
            == vec![
                Request::Read {
                    id: 1,
                    permit: vec![7; 300]
                },
                Request::Credit {
                    bytes: frame_len(1, vec![7; 300])
                },
                Request::Read {
                    id: 2,
                    permit: vec![0]
                },
                Request::Read {
                    id: 3,
                    permit: vec![8; 10]
                },
                Request::Credit {
                    bytes: frame_len(3, vec![8; 10])
                },
            ]
    );
}

#[tokio::test]
async fn body_reads_collect_their_frames_in_order_and_grant_each_back() {
    let (url, seen) = fake_edge(PROMPT).await;
    let client = EdgeClient::new(url, Duration::from_secs(5)).unwrap();
    let permit = vec![BODIES, 4, 5, 6];
    let bodies = client.read_bodies(permit.clone()).await.unwrap();
    assert_eq!(bodies, vec![vec![4; 100], vec![5; 101], vec![6; 102]]);
    // A body read is not a log read, and the reverse.
    assert_eq!(
        client.read_log(permit.clone()).await.err(),
        Some(EdgeError::Malformed)
    );
    assert_eq!(
        client.read_bodies(vec![9; 3]).await.err(),
        Some(EdgeError::Malformed)
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let requests = seen.requests.lock().unwrap();
    let credits: Vec<_> = requests[0]
        .iter()
        .filter_map(|r| match r {
            Request::Credit { bytes } => Some(*bytes),
            _ => None,
        })
        .collect();
    let frames: Vec<u32> = body_frames(1, &permit)
        .iter()
        .map(|f| f.encode().unwrap().len() as u32)
        .collect();
    assert_eq!(credits[..3], frames[..]);
    assert_eq!(credits.len(), 3 + 3 + 1);
}

#[tokio::test]
async fn concurrent_reads_share_a_few_sockets_and_match_reordered_answers() {
    // Later permits are answered first.
    let (url, seen) = fake_edge(Behaviour {
        delay: |permit| Duration::from_millis(10 * (20 - u64::from(permit[0]))),
        ..PROMPT
    })
    .await;
    let client = EdgeClient::new(url, Duration::from_secs(5)).unwrap();
    let reads = (1..=16u8).map(|n| {
        let client = &client;
        async move { (n, client.read_log(vec![n; 20]).await) }
    });
    for (n, result) in join_all(reads).await {
        assert_eq!(
            result.unwrap(),
            vec![(vec![1; 178], vec![n; 20])],
            "read {n}"
        );
    }
    let connections = seen.connections.load(Ordering::SeqCst);
    assert!(connections <= 4, "{connections} sockets");
    assert!(
        seen.most_in_flight
            .lock()
            .unwrap()
            .iter()
            .all(|most| *most <= 8),
        "at most 8 reads in flight per socket"
    );
    // Every Events frame was granted back on its own socket.
    tokio::time::sleep(Duration::from_millis(100)).await;
    for requests in seen.requests.lock().unwrap().iter() {
        let reads = requests
            .iter()
            .filter(|r| matches!(r, Request::Read { .. }))
            .count();
        let credits = requests
            .iter()
            .filter(|r| matches!(r, Request::Credit { .. }))
            .count();
        assert_eq!(reads, credits);
    }
}

#[tokio::test]
async fn a_delayed_read_does_not_stall_the_others_on_its_socket() {
    let (url, seen) = fake_edge(Behaviour {
        delay: |permit| {
            if permit[0] == 99 {
                Duration::from_secs(3)
            } else {
                Duration::ZERO
            }
        },
        ..PROMPT
    })
    .await;
    let client = Arc::new(EdgeClient::new(url, Duration::from_secs(10)).unwrap());
    let slow = {
        let client = client.clone();
        tokio::spawn(async move { client.read_log(vec![99; 5]).await })
    };
    // Wait until the slow read is on the socket.
    while seen
        .requests
        .lock()
        .unwrap()
        .first()
        .is_none_or(Vec::is_empty)
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let start = Instant::now();
    let reads = (1..=7u8).map(|n| {
        let client = &client;
        async move { client.read_log(vec![n; 5]).await }
    });
    for result in join_all(reads).await {
        result.unwrap();
    }
    assert!(start.elapsed() < Duration::from_secs(1), "others waited");
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1, "same socket");
    assert!(!slow.is_finished());
    slow.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_dropped_socket_fails_its_reads_or_retries_once() {
    // One drop: the read is retried on a new socket and succeeds.
    let (url, seen) = fake_edge(Behaviour {
        drop_sockets: 1,
        ..PROMPT
    })
    .await;
    let client = EdgeClient::new(url, Duration::from_secs(5)).unwrap();
    client.read_log(vec![7; 3]).await.unwrap();
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
    // Every socket drops: the read fails after a bounded number of attempts.
    let (url, seen) = fake_edge(Behaviour {
        drop_sockets: usize::MAX,
        ..PROMPT
    })
    .await;
    let client = EdgeClient::new(url, Duration::from_secs(5)).unwrap();
    let reads = (1..=8u8).map(|n| {
        let client = &client;
        async move { client.read_log(vec![n; 3]).await }
    });
    for result in join_all(reads).await {
        assert_eq!(result.err(), Some(EdgeError::Unavailable));
    }
    let connections = seen.connections.load(Ordering::SeqCst);
    assert!(connections <= 8 * 2, "{connections} connections");
}

#[tokio::test]
async fn a_closed_reused_socket_is_replaced() {
    let (url, seen) = fake_edge(Behaviour {
        per_socket: 1,
        ..PROMPT
    })
    .await;
    let client = EdgeClient::new(url, Duration::from_secs(5)).unwrap();
    client.read_log(vec![7; 3]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.read_log(vec![7; 4]).await.unwrap();
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_unreachable_edge_is_unavailable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/data", listener.local_addr().unwrap());
    drop(listener);
    let client = EdgeClient::new(url, Duration::from_secs(2)).unwrap();
    assert_eq!(
        client.read_log(vec![1]).await.err(),
        Some(EdgeError::Unavailable)
    );
}

#[tokio::test]
async fn reads_that_time_out_while_connecting_leave_the_pool_usable() {
    // More stalled connects than the client keeps sockets.
    let (url, seen) = fake_edge(Behaviour {
        stall_upgrades: 4,
        ..PROMPT
    })
    .await;
    let client = EdgeClient::new(url, Duration::from_secs(1)).unwrap();
    for n in 1..=4u8 {
        assert_eq!(
            client.read_log(vec![n; 3]).await.err(),
            Some(EdgeError::Unavailable)
        );
    }
    // The edge now upgrades: a fifth read opens a socket and is answered.
    assert_eq!(
        client.read_log(vec![5; 3]).await.unwrap(),
        vec![(vec![1; 178], vec![5; 3])]
    );
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_stalled_connect_gives_up_and_the_read_retries_on_a_new_socket() {
    let (url, seen) = fake_edge(Behaviour {
        stall_upgrades: 1,
        ..PROMPT
    })
    .await;
    let client = EdgeClient::new(url, Duration::from_secs(30)).unwrap();
    let start = Instant::now();
    client.read_log(vec![7; 3]).await.unwrap();
    let waited = start.elapsed();
    assert!(waited < Duration::from_secs(10), "{waited:?}");
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
}
