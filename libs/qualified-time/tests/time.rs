use bh_qualified_time::{
    Bounds, Config, Counter, QualifiedClock, Sample, ServerRoot, Unavailable, verify,
};

const ROOTS: [ServerRoot; 2] = [ServerRoot { key: [0; 32] }, ServerRoot { key: [1; 32] }];
struct Tick(u64);
impl Counter for Tick {
    fn ticks(&self) -> u64 {
        self.0
    }
}
fn config() -> Config {
    Config {
        hz: 1_000_000,
        drift_ppm: 500,
        smear_us: 1_000_000,
        max_age_ticks: 20_000_000,
        max_width_ms: 15_000,
    }
}
fn samples<'a>(
    nonce: &'a [[u8; 64]; 2],
    reply: &'a [Vec<u8>; 2],
    roots: &'a [ServerRoot; 2],
) -> [Sample<'a>; 2] {
    [
        Sample {
            server: roots[0],
            nonce: &nonce[0],
            reply: &reply[0],
            sent: 0,
            received: 100_000,
        },
        Sample {
            server: roots[1],
            nonce: &nonce[1],
            reply: &reply[1],
            sent: 100_001,
            received: 150_000,
        },
    ]
}
fn recorded() -> ([ServerRoot; 2], [[u8; 64]; 2], [Vec<u8>; 2]) {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/roughtime.json")).unwrap();
    let roots = [
        ServerRoot {
            key: hex::decode("d060fb737c8ff3111ce19976cdeb8dd9294bbc3555a1c8ec3d22fcfd197fef38")
                .unwrap()
                .try_into()
                .unwrap(),
        },
        ServerRoot {
            key: hex::decode("016e6e0284d24c37c6e4d7d8d5b4e1d3c1949ceaa545bf875616c9dce0c9bec1")
                .unwrap()
                .try_into()
                .unwrap(),
        },
    ];
    let names = ["cloudflare", "int08h"];
    let nonce = names.map(|n| {
        hex::decode(fixture[n]["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    });
    let reply = names.map(|n| hex::decode(fixture[n]["reply"].as_str().unwrap()).unwrap());
    (roots, nonce, reply)
}
#[test]
fn archived_signed_replies_and_refusal() {
    let (roots, nonce, reply) = recorded();
    for i in 0..2 {
        assert!(verify(&roots[i], &nonce[i], &reply[i]).is_ok());
        assert!(verify(&roots[1 - i], &nonce[i], &reply[i]).is_err());
        let mut wrong = nonce[i];
        wrong[0] ^= 1;
        assert!(verify(&roots[i], &wrong, &reply[i]).is_err());
        for at in [0, reply[i].len() / 2, reply[i].len() - 1] {
            let mut corrupt = reply[i].clone();
            corrupt[at] ^= 1;
            assert!(verify(&roots[i], &nonce[i], &corrupt).is_err());
        }
    }
    let mut clock = QualifiedClock::new(roots, config()).unwrap();
    assert_eq!(clock.now(&Tick(0)), Err(Unavailable::Cold));
    clock
        .update(&samples(&nonce, &reply, &roots), &Tick(150_000))
        .unwrap();
    let b = clock.now(&Tick(150_000)).unwrap();
    assert!(b.earliest_ms < b.latest_ms);
    assert!(b.latest_ms - b.earliest_ms <= 15_000);
    assert!(b.earliest_ms <= 1_791_852_834_000 && b.latest_ms >= 1_791_852_835_000);
    assert_eq!(clock.now(&Tick(149_999)), Err(Unavailable::Counter));
    assert_eq!(clock.now(&Tick(150_001)), Err(Unavailable::Counter));
}
#[test]
fn outages_replays_stale_and_width_refuse() {
    let (roots, nonce, reply) = recorded();
    let mut clock = QualifiedClock::new(roots, config()).unwrap();
    assert!(
        clock
            .update(&samples(&nonce, &reply, &roots)[..1], &Tick(150_000))
            .is_err()
    );
    assert!(clock.now(&Tick(150_000)).is_err());
    let mut clock = QualifiedClock::new(roots, config()).unwrap();
    clock
        .update(&samples(&nonce, &reply, &roots), &Tick(150_000))
        .unwrap();
    let mut reused = samples(&nonce, &reply, &roots);
    reused[0].sent = 150_001;
    reused[0].received = 150_002;
    reused[1].sent = 150_003;
    reused[1].received = 150_004;
    assert_eq!(
        clock.update(&reused, &Tick(150_004)),
        Err(Unavailable::Replay)
    );
    assert!(clock.now(&Tick(150_004)).is_err());
    let mut clock = QualifiedClock::new(roots, config()).unwrap();
    clock
        .update(&samples(&nonce, &reply, &roots), &Tick(150_000))
        .unwrap();
    assert_eq!(clock.now(&Tick(20_150_001)), Err(Unavailable::Stale));
    let mut cfg = config();
    cfg.max_age_ticks = u64::MAX;
    cfg.max_width_ms = 15_000;
    let mut clock = QualifiedClock::new(roots, cfg).unwrap();
    clock
        .update(&samples(&nonce, &reply, &roots), &Tick(150_000))
        .unwrap();
    assert_eq!(clock.now(&Tick(20_000_000_000)), Err(Unavailable::Width));
}
// No archived reply exercises deliberate Merkle branches or adversarial times;
// these fixtures are signed with deterministic synthetic Ed25519 test keys.
fn message(mut fields: Vec<(&[u8; 4], Vec<u8>)>) -> Vec<u8> {
    fields.sort_by_key(|(tag, _)| u32::from_le_bytes(**tag));
    let n = fields.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(n as u32).to_le_bytes());
    let mut offset = 0u32;
    for (_, bytes) in fields.iter().take(n - 1) {
        offset += bytes.len() as u32;
        out.extend_from_slice(&offset.to_le_bytes());
    }
    for (tag, _) in &fields {
        out.extend_from_slice(*tag);
    }
    for (_, bytes) in &fields {
        out.extend_from_slice(bytes);
    }
    out
}
fn flip_field(packet: &mut [u8], path: &[[u8; 4]]) {
    let n = u32::from_le_bytes(packet[..4].try_into().unwrap()) as usize;
    for i in 0..n {
        if packet[4 * n + 4 * i..4 * n + 4 * i + 4] == path[0] {
            let start = if i == 0 {
                0
            } else {
                u32::from_le_bytes(packet[4 * i..4 * i + 4].try_into().unwrap()) as usize
            };
            let end = if i + 1 == n {
                packet.len() - 8 * n
            } else {
                u32::from_le_bytes(packet[4 + 4 * i..8 + 4 * i].try_into().unwrap()) as usize
            };
            let bytes = &mut packet[8 * n + start..8 * n + end];
            if path.len() == 1 {
                bytes[0] ^= 1;
            } else {
                flip_field(bytes, &path[1..]);
            }
            return;
        }
    }
    panic!("missing test tag");
}
fn signed_reply(
    seed: u8,
    nonce: &[u8; 64],
    midpoint_us: u64,
    radius_us: u32,
    path_bad: bool,
) -> (ServerRoot, Vec<u8>) {
    signed_reply_with_window(seed, nonce, midpoint_us, radius_us, path_bad, 0, u64::MAX)
}
fn signed_reply_with_window(
    seed: u8,
    nonce: &[u8; 64],
    midpoint_us: u64,
    radius_us: u32,
    path_bad: bool,
    mint: u64,
    maxt: u64,
) -> (ServerRoot, Vec<u8>) {
    use bh_crypto::{Secret, SigningKey, sha512};
    let root = SigningKey::from_seed(&Secret::from_slice(&[seed; 32]).unwrap());
    let online = SigningKey::from_seed(&Secret::from_slice(&[seed + 10; 32]).unwrap());
    let dele = message(vec![
        (b"PUBK", online.public().to_vec()),
        (b"MINT", mint.to_le_bytes().to_vec()),
        (b"MAXT", maxt.to_le_bytes().to_vec()),
    ]);
    let mut ds = b"RoughTime v1 delegation signature--\0".to_vec();
    ds.extend_from_slice(&dele);
    let cert = message(vec![(b"DELE", dele), (b"SIG\0", root.sign(&ds).to_vec())]);
    let mut leaf = [0; 65];
    leaf[1..].copy_from_slice(nonce);
    let leaf_hash = sha512(&leaf);
    let sibling = [9; 64];
    let mut branch = [0; 129];
    branch[0] = 1;
    branch[1..65].copy_from_slice(&leaf_hash);
    branch[65..].copy_from_slice(&sibling);
    let merkle_root = sha512(&branch);
    let srep = message(vec![
        (b"MIDP", midpoint_us.to_le_bytes().to_vec()),
        (b"RADI", radius_us.to_le_bytes().to_vec()),
        (b"ROOT", merkle_root.to_vec()),
    ]);
    let mut rs = b"RoughTime v1 response signature\0".to_vec();
    rs.extend_from_slice(&srep);
    let mut path = sibling;
    if path_bad {
        path[0] ^= 1;
    }
    let reply = message(vec![
        (b"CERT", cert),
        (b"SREP", srep),
        (b"SIG\0", online.sign(&rs).to_vec()),
        (b"PATH", path.to_vec()),
        (b"INDX", 0u32.to_le_bytes().to_vec()),
    ]);
    (ServerRoot { key: root.public() }, reply)
}
#[test]
fn synthetic_signatures_delegations_paths_hull_and_disagreement() {
    let n = [[2; 64], [3; 64]];
    let (r0, a) = signed_reply(1, &n[0], 1_000_000_000, 2_000_000, false);
    let (r1, b) = signed_reply(2, &n[1], 1_003_000_000, 10_000_000, false);
    let roots = [r0, r1];
    let replies = [a.clone(), b.clone()];
    let mut cfg = config();
    cfg.max_width_ms = 30_000;
    let mut clock = QualifiedClock::new(roots, cfg).unwrap();
    let bounds = clock
        .update(&samples(&n, &replies, &roots), &Tick(150_000))
        .unwrap();
    assert!(bounds.earliest_ms <= 992_000 && bounds.latest_ms >= 1_014_000); // hull, not intersection
    cfg.max_width_ms = 15_000;
    assert_eq!(
        QualifiedClock::new(roots, cfg)
            .unwrap()
            .update(&samples(&n, &replies, &roots), &Tick(150_000)),
        Err(Unavailable::Width)
    );
    let (_, far) = signed_reply(2, &n[1], 2_000_000_000, 0, false);
    assert_eq!(
        QualifiedClock::new(roots, config())
            .unwrap()
            .update(&samples(&n, &[a.clone(), far], &roots), &Tick(150_000)),
        Err(Unavailable::Server)
    );
    let (_, bad_path) = signed_reply(2, &n[1], 1_000_000_000, 0, true);
    assert_eq!(verify(&r1, &n[1], &bad_path), Err(Unavailable::Inclusion));
    for (path, expected) in [
        (vec![*b"SIG\0"], Unavailable::Signature),
        (vec![*b"CERT", *b"SIG\0"], Unavailable::Signature),
        (vec![*b"CERT", *b"DELE"], Unavailable::Signature),
        (vec![*b"SREP"], Unavailable::Signature),
        (vec![*b"PATH"], Unavailable::Inclusion),
    ] {
        let mut tampered = b.clone();
        flip_field(&mut tampered, &path);
        assert_eq!(verify(&r1, &n[1], &tampered), Err(expected));
    }
    assert_eq!(verify(&r0, &n[1], &b), Err(Unavailable::Signature));
    assert!(verify(&r1, &n[1], &b[..b.len() - 1]).is_err());
    assert!(verify(&r1, &n[1], &vec![0; 4097]).is_err());
    assert!(QualifiedClock::new([r0, r0], config()).is_err());
    let mut malformed_index = b.clone();
    flip_field(&mut malformed_index, &[*b"INDX"]);
    assert_eq!(
        verify(&r1, &n[1], &malformed_index),
        Err(Unavailable::Inclusion)
    );
    let mut malformed = b.clone();
    malformed[0] = 65;
    assert_eq!(verify(&r1, &n[1], &malformed), Err(Unavailable::Packet));
}
#[test]
fn packet_delay_parallel_samples_and_range_are_bounded() {
    let (roots, nonce, reply) = recorded();
    let mut cfg = config();
    cfg.max_width_ms = 15_000;
    let mut slow = samples(&nonce, &reply, &roots);
    slow[0].received = 14_000_000;
    slow[1].sent = 14_000_001;
    slow[1].received = 14_050_000;
    // The server can have measured time at either end of the packet flight.
    assert_eq!(
        QualifiedClock::new(roots, cfg)
            .unwrap()
            .update(&slow, &Tick(14_050_000)),
        Err(Unavailable::Width)
    );
    let mut parallel = samples(&nonce, &reply, &roots);
    parallel[1].sent = 1;
    parallel[1].received = 90_000;
    assert!(
        QualifiedClock::new(roots, cfg)
            .unwrap()
            .update(&parallel, &Tick(150_000))
            .is_ok()
    );
    let mut huge = config();
    huge.smear_us = u64::MAX;
    assert_eq!(
        QualifiedClock::new(roots, huge)
            .unwrap()
            .update(&samples(&nonce, &reply, &roots), &Tick(150_000)),
        Err(Unavailable::Range)
    );
}
#[test]
fn a_reader_during_refresh_does_not_latch_counter_rollback() {
    let n0 = [[2; 64], [3; 64]];
    let (r0, a0) = signed_reply(1, &n0[0], 1_000_000_000, 0, false);
    let (r1, b0) = signed_reply(2, &n0[1], 1_000_000_000, 0, false);
    let roots = [r0, r1];
    let mut clock = QualifiedClock::new(roots, config()).unwrap();
    clock
        .update(&samples(&n0, &[a0, b0], &roots), &Tick(150_000))
        .unwrap();
    // Refresh send precedes an unrelated deadline reader; receipt follows it.
    let n1 = [[4; 64], [5; 64]];
    let (_, a1) = signed_reply(1, &n1[0], 1_000_100_000, 0, false);
    let (_, b1) = signed_reply(2, &n1[1], 1_000_100_000, 0, false);
    assert!(clock.now(&Tick(210_000)).is_ok());
    let replies = [a1, b1];
    let mut refresh = samples(&n1, &replies, &roots);
    refresh[0].sent = 200_000;
    refresh[0].received = 250_000;
    refresh[1].sent = 250_001;
    refresh[1].received = 300_000;
    assert!(clock.update(&refresh, &Tick(300_000)).is_ok());
    assert!(clock.now(&Tick(400_000)).is_ok());
}
#[test]
fn delegation_window_checks_both_inclusive_endpoints() {
    let nonce = [8; 64];
    for (mid, expected) in [
        (999_999, Err(Unavailable::Packet)),
        (1_000_000, Ok(())),
        (2_000_000, Ok(())),
        (2_000_001, Err(Unavailable::Packet)),
    ] {
        let (root, reply) =
            signed_reply_with_window(1, &nonce, mid, 0, false, 1_000_000, 2_000_000);
        assert_eq!(
            verify(&root, &nonce, &reply).map(|_| ()),
            expected,
            "midpoint {mid}"
        );
    }
}
#[test]
fn same_nonce_and_exhausted_history_are_replay_errors() {
    let n = [[6; 64], [6; 64]];
    let (r0, a) = signed_reply(1, &n[0], 1_000_000_000, 0, false);
    let (r1, b) = signed_reply(2, &n[1], 1_000_000_000, 0, false);
    let roots = [r0, r1];
    assert_eq!(
        QualifiedClock::new(roots, config())
            .unwrap()
            .update(&samples(&n, &[a, b], &roots), &Tick(150_000)),
        Err(Unavailable::Replay)
    );
    let mut clock = QualifiedClock::new(roots, config()).unwrap();
    for i in 0..2048u64 {
        let mut left = [0; 64];
        left[..8].copy_from_slice(&(2 * i).to_le_bytes());
        let mut right = [0; 64];
        right[..8].copy_from_slice(&(2 * i + 1).to_le_bytes());
        let n = [left, right];
        let (_, a) = signed_reply(1, &n[0], 1_000_000_000, 0, false);
        let (_, b) = signed_reply(2, &n[1], 1_000_000_000, 0, false);
        let stamps = [
            Sample {
                server: roots[0],
                nonce: &n[0],
                reply: &a,
                sent: i,
                received: i,
            },
            Sample {
                server: roots[1],
                nonce: &n[1],
                reply: &b,
                sent: i,
                received: i,
            },
        ];
        clock.update(&stamps, &Tick(i)).unwrap();
    }
    let n = [[0x80; 64], [0x81; 64]];
    let stamps = [
        Sample {
            server: roots[0],
            nonce: &n[0],
            reply: &[],
            sent: 2048,
            received: 2048,
        },
        Sample {
            server: roots[1],
            nonce: &n[1],
            reply: &[],
            sent: 2048,
            received: 2048,
        },
    ];
    assert_eq!(clock.update(&stamps, &Tick(2048)), Err(Unavailable::Replay));
}
#[test]
fn outward_rounding_and_deadline() {
    let bounds = Bounds {
        earliest_ms: 1001,
        latest_ms: 1999,
    };
    let policy = bounds.to_policy_time();
    assert_eq!((policy.earliest, policy.latest), (1, 2));
    let attestation = bounds.to_attestation_time(3);
    assert_eq!(
        (
            attestation.earliest,
            attestation.latest,
            attestation.max_uncertainty_secs
        ),
        (1, 2, 3)
    );
    assert!(!bounds.deadline_passed_ms(1002));
    assert!(bounds.deadline_passed_ms(1001));
    assert!(bounds.before_ms(2000));
    assert!(!bounds.before_ms(1999));
    assert!(QualifiedClock::new(ROOTS, Config { hz: 0, ..config() }).is_err());
}
