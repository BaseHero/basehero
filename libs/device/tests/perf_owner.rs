//! Opt-in native owner perf: ten busy base scopes in ONE account, each with a
//! ~1-MiB working Note. Reports foreground wall and actual SQLite write-section
//! hold p50/p95/p99 independently. This measures Owner directly, not native
//! note_host admission, blocking-thread scheduling, UI or network.
use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    crypto::{KemKey, SigningKey},
};
use bh_core::note::Note;
use bh_device::{
    Owner,
    coordinator::{AuthoritySource, Scope},
};
use bh_storage::{DeviceDatabase, NoteKey};
use std::{
    collections::HashMap,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
struct Issuer(HashMap<String, Scope>);
impl AuthoritySource for Issuer {
    fn bound_scope(&self, window: &str) -> Option<Scope> {
        self.0.get(window).copied()
    }
}
fn rss() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    Some(
        status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))?
            .split_whitespace()
            .nth(1)?
            .parse::<usize>()
            .ok()?
            * 1024,
    )
}
fn percentile(samples: &mut [Duration], fraction: usize) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() - 1) * fraction / 100]
}
#[test]
#[ignore = "opt-in disk and CPU foreground performance measurement"]
fn ten_busy_mib_bases_in_one_container() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.db");
    let signing = SigningKey::generate();
    let control = SigningKey::generate();
    let device = DevicePublicKeys::new(
        signing.public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let recovery =
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
    let draft = AccountEvent::genesis(device, recovery);
    let event = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let verified =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&event).unwrap(), event.as_bytes())
            .unwrap();
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.commit_account_verified(
        verified.id().0,
        &[event.as_bytes()],
        verified.head().position,
        verified.head().hash,
        false,
    )
    .unwrap();
    let owner = Arc::new(Owner::default());
    let scopes = (1..=10u8)
        .map(|base| {
            (
                format!("base-{base}"),
                Scope {
                    account: verified.id().0,
                    key: NoteKey {
                        base: [base; 32],
                        audience: [3; 32],
                        note: [4; 32],
                    },
                },
            )
        })
        .collect();
    let id = owner
        .register(db, Some(&verified), Box::new(Issuer(scopes)))
        .unwrap();
    let big = "x".repeat(1024 * 1024);
    let mut bindings = Vec::new();
    for base in 1..=10u8 {
        let window = format!("base-{base}");
        owner.bind(&window, id).unwrap();
        let open = owner.open(&window, [4; 32]).unwrap();
        owner
            .commit_queued(
                &window,
                open.generation,
                [0; 16],
                &Note::new().append_paragraph(&big),
            )
            .unwrap();
        bindings.push((window, open.generation));
    }
    let baseline_rss = rss();
    let barrier = Arc::new(Barrier::new(10));
    let started = Instant::now();
    let handles: Vec<_> = bindings
        .into_iter()
        .enumerate()
        .map(|(index, (window, generation))| {
            let owner = Arc::clone(&owner);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut source = Note::new();
                let mut saves = Vec::new();
                let mut sql = Vec::new();
                barrier.wait();
                for n in 0..100u16 {
                    let delta = source.append_paragraph("small change");
                    let mut request = [0u8; 16];
                    request[0] = (index + 1) as u8;
                    request[1..3].copy_from_slice(&n.to_be_bytes());
                    let started = Instant::now();
                    let (_, _, held) = owner
                        .commit_queued_timed(&window, generation, request, &delta)
                        .unwrap();
                    saves.push(started.elapsed());
                    sql.push(held);
                }
                (saves, sql)
            })
        })
        .collect();
    let (mut saves, mut sql) = (Vec::new(), Vec::new());
    for handle in handles {
        let (a, b) = handle.join().unwrap();
        saves.extend(a);
        sql.extend(b);
    }
    let wall = started.elapsed();
    let after_rss = rss();
    assert_eq!(saves.len(), 1000);
    assert!(sql.iter().all(|held| *held > Duration::ZERO));
    let (p50, p95, p99) = (
        percentile(&mut saves, 50),
        percentile(&mut saves, 95),
        percentile(&mut saves, 99),
    );
    let (s50, s95, s99) = (
        percentile(&mut sql, 50),
        percentile(&mut sql, 95),
        percentile(&mut sql, 99),
    );
    eprintln!(
        "ten-bases each=1MiB 100 saves total=1000 wall={wall:?} save p50={p50:?} p95={p95:?} p99={p99:?} sqlite-CAS-hold p50={s50:?} p95={s95:?} p99={s99:?} RSS-before-saves={baseline_rss:?} RSS-after-saves={after_rss:?}"
    );
}
