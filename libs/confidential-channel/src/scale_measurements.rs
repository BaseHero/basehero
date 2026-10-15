//! Bounded explicit release probe, never part of the default check.
use super::*;
use crate::lock_measurements::{self, Stats};
use std::{mem::size_of, time::Instant};
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}
fn percentile_upper(buckets: &[u64; 32], count: u64, percent: u64) -> u64 {
    let target = (count * percent).div_ceil(100);
    let mut seen = 0;
    for (i, n) in buckets.iter().enumerate() {
        seen += n;
        if seen >= target {
            return 1u64 << (i + 1);
        }
    }
    0
}
fn add(a: &mut Stats, b: Stats) {
    a.count += b.count;
    a.wait_ns += b.wait_ns;
    a.hold_ns += b.hold_ns;
    a.max_wait = a.max_wait.max(b.max_wait);
    a.max_hold = a.max_hold.max(b.max_hold);
    for i in 0..32 {
        a.wait_buckets[i] += b.wait_buckets[i];
        a.hold_buckets[i] += b.hold_buckets[i];
    }
}
#[test]
#[ignore = "explicit release-only synthetic record matrix and genuine archived QVL baseline; not live hardware"]
#[allow(clippy::assertions_on_constants)] // Explicit probe must refuse a debug run, not fail normal test compilation.
fn release_scale_matrix() {
    assert!(!cfg!(debug_assertions), "run with --release");
    let ticks = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .unwrap();
    assert!(ticks.status.success());
    let hz = String::from_utf8(ticks.stdout)
        .unwrap()
        .trim()
        .parse::<f64>()
        .unwrap();
    let quote = include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote");
    let collateral =
        include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote_collateral.json");
    let mut baseline = Vec::with_capacity(100);
    let cpu = cpu_ticks();
    for _ in 0..100 {
        let start = Instant::now();
        attestation::quote_claims_with_policy(
            quote,
            collateral,
            Time {
                earliest: T,
                latest: T,
                max_uncertainty_secs: 0,
            },
            |now| {
                dcap_qvl::QuotePolicy::strict(now)
                    .allow_smt(true)
                    .allow_dynamic_platform(true)
                    .allow_cached_keys(true)
            },
        )
        .unwrap();
        baseline.push(start.elapsed().as_nanos());
    }
    baseline.sort_unstable();
    let median = baseline[50];
    println!(
        "ARCHIVED_QVL count=100 bytes={} min_ns={} median_ns={} max_ns={} cpu_s={:.6}",
        quote.len() + collateral.len(),
        baseline[0],
        median,
        baseline[99],
        (cpu_ticks() - cpu) as f64 / hz
    );
    let evidence = fixture_evidence();
    let owned = size_of::<VerifiedEvidence>()
        + evidence
            .measured()
            .build()
            .boot
            .iter()
            .map(Vec::capacity)
            .sum::<usize>();
    println!(
        "RETAINED evidence_owned_bytes={owned} buffers=5 (one box + four boot vectors); raw_evidence_bytes=0; excludes allocator metadata, sessions, shared context"
    );
    for len in [1, 65_536] {
        let rounds = if len == 1 { 65_536 } else { 1024 };
        for count in [1, 8, 32] {
            for repeat in 1..=3 {
                let (ctx, _, _) = context();
                let ready = Arc::new(Barrier::new(count + 1));
                let go = Arc::new(Barrier::new(count + 1));
                let mut threads = Vec::new();
                for _ in 0..count {
                    let ctx = ctx.clone();
                    let ready = ready.clone();
                    let go = go.clone();
                    threads.push(std::thread::spawn(move || {
                        let (mut client, mut server) = sessions(ctx);
                        let proof_calls = attestation::QVL_CALLS.with(|n| {
                            let count = n.get();
                            n.set(0);
                            count
                        });
                        ready.wait();
                        go.wait();
                        lock_measurements::start();
                        for _ in 0..rounds {
                            let frame = client.seal(SecretBytes::from_vec(vec![7; len])).unwrap();
                            match server.open(&frame).unwrap() {
                                Opened::Data(p) => assert_eq!(p.expose().len(), len),
                                Opened::Closed => panic!(),
                            }
                            let frame = server.seal(SecretBytes::from_vec(vec![8; len])).unwrap();
                            match client.open(&frame).unwrap() {
                                Opened::Data(p) => assert_eq!(p.expose().len(), len),
                                Opened::Closed => panic!(),
                            }
                        }
                        let stats = lock_measurements::finish();
                        let record_calls = attestation::QVL_CALLS.with(|n| n.get());
                        assert_eq!(record_calls, 0);
                        (proof_calls, record_calls, stats)
                    }));
                }
                ready.wait();
                let cpu = cpu_ticks();
                let start = Instant::now();
                go.wait();
                let mut stats = Stats::default();
                let mut proofs = 0;
                let mut records = 0;
                for t in threads {
                    let (p, r, s) = t.join().unwrap();
                    proofs += p;
                    records += r;
                    add(&mut stats, s);
                }
                let wall = start.elapsed().as_secs_f64();
                let cpu = (cpu_ticks() - cpu) as f64 / hz;
                assert_eq!(stats.count, (2 * rounds * count) as u64);
                assert_eq!(proofs, count);
                println!(
                    "MATRIX len={len} sessions={count} repeat={repeat} directional_records={} seal_open_ops={} proof_qvl={proofs} record_qvl={records} wall_s={wall:.6} cpu_s={cpu:.6} lock_calls={} hold_ns={} wait_ns={} max_hold_ns={} max_wait_ns={} hold_p50_upper_ns={} hold_p95_upper_ns={} wait_p50_upper_ns={} wait_p95_upper_ns={} old_qvl_extrapolated_s={:.6}",
                    2 * rounds * count,
                    4 * rounds * count,
                    stats.count,
                    stats.hold_ns,
                    stats.wait_ns,
                    stats.max_hold,
                    stats.max_wait,
                    percentile_upper(&stats.hold_buckets, stats.count, 50),
                    percentile_upper(&stats.hold_buckets, stats.count, 95),
                    percentile_upper(&stats.wait_buckets, stats.count, 50),
                    percentile_upper(&stats.wait_buckets, stats.count, 95),
                    (2 * rounds * count) as f64 * median as f64 / 1e9
                );
            }
        }
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status
        .lines()
        .filter(|l| l.starts_with("VmHWM:") || l.starts_with("VmRSS:"))
    {
        println!("PROCESS {line} (whole test process, not per-session allocation)");
    }
}
