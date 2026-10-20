//! Reproducible local typed-data workload. Bulk initial state is loaded in
//! bounded SQL transactions; measured reads and edits use DataSession.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use bh_data::{
    Actor, AppId, CompiledType, CoreCatalogue, FieldPath, KeyRef, MutationId, Position, RecordId,
    RecordRef, RevisionId, Scope, TypeId, index,
    mutation::{
        apply,
        ops::{FieldChange, Operation},
    },
    payload,
    query::{self, Budget, CmpOp, Expr, Follow, Query, QueryError, SortKey, TextMatch, TypeSelect},
    session::{Authority, DataSession},
    store::{self, coverage, records, registry},
    testkit::Replica,
    text,
};
use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use serde_json::json;

const SCOPE: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const SAMPLES: usize = 60;
fn tid(n: u8) -> TypeId {
    TypeId::for_app(AppId([n.min(3); 32]), [n; 16])
}
fn rid(kind: u8, n: usize) -> RecordId {
    let mut b = [0; 32];
    b[0] = kind;
    b[1..9].copy_from_slice(&(n as u64).to_be_bytes());
    RecordId(b)
}
fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).expect("fixture path")
}
fn key(s: &str) -> KeyRef {
    KeyRef::Field(path(s))
}
fn definition_bytes(n: u8) -> Vec<u8> {
    let mut doc = json!({"format":"bh-type/1","local":format!("{n:02x}").repeat(16),"app":AppId([n.min(3);32]),"kind":"record",
        "name":(["","Article","SourceSelection","Contact","LargeText"][n as usize]),
        "description":"Constrained deterministic synthetic scale data","extends":null,"uses":[],
        "schema":{"type":"object","properties":{"title":{"type":"string","maxLength":200},"status":{"type":"string","enum":["featured","normal"]},"rank":{"type":"integer","minimum":0}},"required":["title","status","rank"]},
        "fields":{"/title":{"kind":"string","write":"direct","meaning":"Display title"},"/status":{"kind":"enum","write":"direct","meaning":"Selection state"},"/rank":{"kind":"integer","write":"direct","meaning":"Stable fixture rank"}},
        "indexes":[{"name":"by_status_rank","keys":["/status","/rank"]}],
        "unique":[],"search":{"title":"/title","text":[]},"actions":[],"queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],"examples":{"valid":[],"invalid":[]}},"rationale":[]});
    if n != 3 {
        doc["indexes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"by_title","keys":["/title"]}));
    }
    if n == 2 || n == 3 {
        doc["schema"]["properties"]["contact"] = json!({"type":"object","additionalProperties":false,"required":["record"],"properties":{"record":{"type":"string","minLength":64,"maxLength":64},"audience":{"type":"string","minLength":64,"maxLength":64}}});
        doc["fields"]["/contact"] = json!({"kind":"reference","write":"direct","meaning":"Referenced contact","ref":{"targets":[tid(3)],"family":false}});
    }
    if n == 1 || n == 4 {
        doc["schema"]["properties"]["body"] = json!({"type":"string","maxLength":16384});
        doc["fields"]["/body"] = json!({"kind":"string","write":"direct","meaning":"Bounded inline summary, not a Note body"});
        doc["search"]["text"] = json!(["/body"]);
    }
    if n == 3 {
        doc["schema"]["properties"]["email"] = json!({"type":"string","maxLength":200});
        doc["schema"]["required"]
            .as_array_mut()
            .unwrap()
            .push(json!("email"));
        doc["fields"]["/email"] =
            json!({"kind":"string","write":"direct","meaning":"Synthetic unique contact key"});
        doc["unique"] = json!([{"name":"unique_email","keys":["/email"]}]);
    }
    serde_json::to_vec(&doc).unwrap()
}
fn fixture(n: u8) -> CompiledType {
    static TYPES: std::sync::LazyLock<Vec<CompiledType>> = std::sync::LazyLock::new(|| {
        (1..=4)
            .map(|n| {
                let d = bh_data::definition::parse(&definition_bytes(n)).unwrap();
                bh_data::compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).unwrap()
            })
            .collect()
    });
    TYPES[n as usize - 1].clone()
}
#[derive(Clone, Copy)]
struct Reader;
impl Authority for Reader {
    fn actor(&self) -> Actor {
        Actor::Device {
            account: [9; 32],
            device: [8; 32],
        }
    }
    fn reads(&self) -> Vec<Scope> {
        vec![SCOPE]
    }
    fn write(&self) -> Option<Scope> {
        Some(SCOPE)
    }
}
struct NoCore;
impl CoreCatalogue for NoCore {
    fn core_type(&self, _: TypeId) -> Option<CompiledType> {
        None
    }
}
fn seed(db: &PathBuf, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut c = Connection::open(db)?;
    c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL")?;
    let tx = c.transaction()?;
    store::migrate(&tx)?;
    let sid = records::scope_id(&tx, SCOPE, &NoCore)?;
    coverage::set(&tx, sid, Position(0), true)?;
    let mut position = 0;
    let accept = |tx: &Transaction<'_>,
                  position: u64,
                  op: &Operation|
     -> Result<(), Box<dyn std::error::Error>> {
        let result = apply::apply_ordered(
            tx,
            &NoCore,
            &apply::Ordered {
                scope: SCOPE,
                position: Position(position),
                actor: &Reader.actor(),
                mutation: MutationId::random(),
                op,
            },
        )?;
        if !matches!(result, apply::Outcome::Accepted { .. }) {
            return Err(format!("invalid scale setup: {result:?}").into());
        }
        Ok(())
    };
    for app in 1..=3 {
        position += 1;
        accept(
            &tx,
            position,
            &Operation::DefineApp {
                app: AppId([app; 32]),
                name: "Scale fixture".into(),
            },
        )?;
    }
    for n in 1..=4 {
        position += 1;
        accept(
            &tx,
            position,
            &Operation::DefineType {
                bytes: definition_bytes(n),
            },
        )?;
    }
    tx.commit()?;
    // Round-robin validated records; sparse 16 KiB inline summaries. Large
    // Note bodies belong to the separate queued body-extraction workload.
    // Each transaction is bounded; all derived projections use production hooks.
    for start in (0..count).step_by(250) {
        let tx = c.transaction()?;
        for i in start..count.min(start + 250) {
            let n = if i % 1000 < 2 { 4 } else { 1 + (i % 3) as u8 };
            let t = fixture(n);
            let contact = RecordRef {
                audience: None,
                record: rid(3, (i / 3) * 3 + 2),
            };
            let body = if n == 4 {
                "largeword ".repeat(1_600)
            } else {
                format!(
                    "article text {} {} {}",
                    i,
                    if i % 100 == 0 {
                        "scaletoken"
                    } else {
                        "ordinary"
                    },
                    "detail ".repeat(140)
                )
            };
            let mut doc = json!({"title":format!("item-{i:08}"), "status": if i % 200 < 3 { "featured" } else { "normal" }, "rank":i});
            if n == 1 || n == 4 {
                doc["body"] = json!(body);
            }
            if n == 2 || n == 3 {
                doc["contact"] = json!(contact);
            }
            if n == 3 {
                doc["email"] = json!(format!("person-{i}@example.invalid"));
            }
            position += 1;
            accept(
                &tx,
                position,
                &Operation::Create {
                    record: rid(n, i),
                    type_id: t.type_id,
                    revision: t.revision,
                    doc,
                },
            )?;
        }
        tx.commit()?;
        if start % 10_000 == 0 {
            eprintln!("seeded {start}/{count}");
        }
    }
    Ok(())
}
fn page(n: u8) -> Query {
    Query {
        select: TypeSelect::Exact(tid(n)),
        filter: None,
        sort: vec![],
        fields: vec![path("/title")],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    }
}
fn percentile(samples: &mut [u128], pct: usize) -> u128 {
    samples.sort_unstable();
    samples[(samples.len() - 1) * pct / 100]
}
fn sample(
    mut action: impl FnMut() -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(u128, u128), Box<dyn std::error::Error>> {
    let mut times = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        action()?;
        times.push(t.elapsed().as_micros());
    }
    let p50 = percentile(&mut times, 50);
    let p95 = percentile(&mut times, 95);
    Ok((p50, p95))
}
/// Optional edit-path diagnostic: elapsed time and SQLite VM work.
fn profile_group(
    conn: &Connection,
    mut edit: impl FnMut(usize) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(u128, u64), Box<dyn std::error::Error>> {
    let steps = Arc::new(AtomicU64::new(0));
    let meter = steps.clone();
    conn.progress_handler(
        100,
        Some(move || {
            meter.fetch_add(100, Ordering::Relaxed);
            false
        }),
    )?;
    let mut durations = vec![];
    let mut work = vec![];
    for j in 0..SAMPLES {
        steps.store(0, Ordering::Relaxed);
        let t = Instant::now();
        edit(j)?;
        durations.push(t.elapsed().as_micros());
        work.push(steps.load(Ordering::Relaxed) as u128);
    }
    conn.progress_handler(0, None::<fn() -> bool>)?;
    Ok((
        percentile(&mut durations, 95),
        percentile(&mut work, 95) as u64,
    ))
}
fn metric(out: &mut String, name: &str, p: (u128, u128)) {
    out.push_str(&format!("| {name} | {} | {} |\n", p.0, p.1));
}
fn db_size(db: &PathBuf) -> Result<u64, Box<dyn std::error::Error>> {
    let c = Connection::open(db)?;
    let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok((pages * size) as u64)
}
const LIMITS: [(&str, Option<u128>); 8] = [
    ("indexed", Some(1000)),
    ("Follow", Some(5000)),
    ("Via", Some(5000)),
    ("text", Some(5000)),
    ("edit", None), // Requires a matched Note-writer baseline, absent here.
    ("reopen", Some(738)),
    ("backfill step hold p95", Some(50_000)),
    ("backfill foreground wait p95", Some(50_000)),
];
struct RunSummary {
    load: String,
    detail: String,
    p95: [u128; 8],
    floor_p95: u128,
    hold_max: u128,
    wait_max: u128,
}
fn median(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    let n = samples.len();
    if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2
    }
}
fn median_edit_ratio(pairs: &[(u128, u128)]) -> f64 {
    let mut ratios = pairs
        .iter()
        .map(|(edit, floor)| *edit as f64 / *floor as f64)
        .collect::<Vec<_>>();
    ratios.sort_by(f64::total_cmp);
    let n = ratios.len();
    if n % 2 == 1 {
        ratios[n / 2]
    } else {
        (ratios[n / 2 - 1] + ratios[n / 2]) / 2.0
    }
}
fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let mut records = 100_000usize;
    let mut out = None;
    let mut check = false;
    let mut runs = 1usize;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--records" => records = args.next().ok_or("missing records")?.parse()?,
            "--out" => out = Some(PathBuf::from(args.next().ok_or("missing output")?)),
            "--runs" => runs = args.next().ok_or("missing runs")?.parse()?,
            "--check" => check = true,
            _ => return Err(format!("unknown argument {arg}").into()),
        }
    }
    if records < 1000 {
        return Err("at least 1000 records required".into());
    }
    if runs == 0 {
        return Err("--runs requires a positive count".into());
    }
    if check && records != 100_000 {
        return Err("--check requires --records 100000".into());
    }
    if check && runs != 5 {
        return Err("--check requires --runs 5".into());
    }
    let out = out.ok_or("--out is required")?;
    fs::create_dir_all(&out)?;
    let mut measured = Vec::with_capacity(runs);
    for i in 0..runs {
        let dir = if runs == 1 {
            out.clone()
        } else {
            out.join(format!("run-{}", i + 1))
        };
        fs::create_dir_all(&dir)?;
        let result = run_once(records, &dir)?;
        if runs > 1 {
            fs::write(dir.join("scale.md"), &result.detail)?;
        }
        measured.push(result);
    }
    let binding = if runs == 5 && records == 100_000 {
        "Five-run native evaluation; --check enforces binding budgets."
    } else {
        "Nonbinding exploratory run: binding evaluation requires --records 100000 --runs 5 --check."
    };
    let mut report = format!(
        "# Typed-data scale: {records} records, {runs} independent runs\n\n{binding} Each run seeds its own file database and collects 60 samples per metric. Other binding absolute budgets apply to the median of per-run p95s (µs), not each run's p95 or maxima. Generic-save comparison is UNVERIFIED here: this standalone workload has no matched existing Note-writer baseline. A reference-host matched comparison is required. Edit/floor ratios are diagnostic only, not replacement acceptance criteria. Load is `uptime` captured before seeding each run.\n\n| Metric (µs except ratio) | {} | Median p95 | Budget |\n|---|{}---:|---:|\n",
        (1..=runs)
            .map(|n| format!("Run {n} p95"))
            .collect::<Vec<_>>()
            .join(" | "),
        "---:|".repeat(runs)
    );
    let mut breached = vec![];
    for (i, (name, limit)) in LIMITS.iter().enumerate() {
        let mut values = measured.iter().map(|m| m.p95[i]).collect::<Vec<_>>();
        let mid = median(&mut values);
        if let Some(limit) = limit
            && mid > *limit
        {
            breached.push(format!("{name}: median {mid} µs > {limit} µs"));
        }
        let budget = limit.map_or(
            "UNVERIFIED (matched Note-writer baseline required)".to_owned(),
            |n| n.to_string(),
        );
        report.push_str(&format!(
            "| {name} | {} | {mid} | {budget} |\n",
            measured
                .iter()
                .map(|m| m.p95[i].to_string())
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    let floors = measured.iter().map(|m| m.floor_p95).collect::<Vec<_>>();
    let mut floor_median = floors.clone();
    let floor_mid = median(&mut floor_median);
    report.push_str(&format!(
        "| durable-commit floor | {} | {floor_mid} | reference |\n",
        floors
            .iter()
            .map(u128::to_string)
            .collect::<Vec<_>>()
            .join(" | ")
    ));
    let pairs = measured
        .iter()
        .map(|m| (m.p95[4], m.floor_p95))
        .collect::<Vec<_>>();
    let ratio = median_edit_ratio(&pairs);
    report.push_str(&format!(
        "| edit / durable-commit floor | {} | {ratio:.3}× | diagnostic only (not a Note-writer comparison) |\n",
        pairs
            .iter()
            .map(|(edit, floor)| format!("{:.3}×", *edit as f64 / *floor as f64))
            .collect::<Vec<_>>()
            .join(" | ")
    ));
    report.push_str("| generic-save vs existing Note writer | UNVERIFIED | UNVERIFIED | reference-host comparison required |\n");
    report.push_str("\n| Run | Uptime before run | Hold max µs | Queue wait max µs | Detail |\n|---:|---|---:|---:|---|\n");
    for (i, item) in measured.iter().enumerate() {
        let detail = if runs == 1 {
            "below".into()
        } else {
            format!("[run-{}/scale.md](run-{}/scale.md)", i + 1, i + 1)
        };
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            i + 1,
            item.load,
            item.hold_max,
            item.wait_max,
            detail
        ));
    }
    report.push_str(&format!(
        "\nBudget check: {}\n",
        if breached.is_empty() {
            "other metrics have no median breaches; overall acceptance UNVERIFIED (generic-save comparison requires a matched Note-writer baseline)".into()
        } else {
            format!("OPEN: {}; overall acceptance UNVERIFIED (generic-save comparison requires a matched Note-writer baseline)", breached.join("; "))
        }
    ));
    if runs == 1 {
        report.push_str("\n## Individual run\n\n");
        report.push_str(&measured[0].detail);
    }
    fs::write(out.join("scale.md"), &report)?;
    println!("{report}");
    Ok(!check || breached.is_empty())
}
fn run_once(records: usize, out: &Path) -> Result<RunSummary, Box<dyn std::error::Error>> {
    let load = match Command::new("uptime").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "uptime unavailable".into(),
    };
    eprintln!("before-run load: {load}");
    let db = out.join("scale.sqlite");
    if db.exists() {
        return Err("output DB already exists; choose a fresh directory".into());
    }
    let started = Instant::now();
    seed(&db, records)?;
    let seeded = started.elapsed();
    let replica = Replica::new_file(&db)?;
    let session = DataSession::new(&replica, Reader);
    let mut indexed = page(1);
    indexed.filter = Some(Expr::Cmp {
        path: path("/status"),
        op: CmpOp::Eq,
        value: json!("normal"),
    });
    indexed.sort = vec![SortKey {
        key: key("/rank"),
        desc: false,
    }];
    let mut follow = page(2);
    follow.sort = vec![SortKey {
        key: key("/title"),
        desc: false,
    }];
    follow.follow.push(Follow {
        path: path("/contact"),
        fields: vec![path("/email")],
    });
    let mut via = page(2);
    via.filter = Some(Expr::Via {
        path: path("/contact"),
        filter: Box::new(Expr::Cmp {
            path: path("/status"),
            op: CmpOp::Eq,
            value: json!("featured"),
        }),
    });
    let mut textq = page(1);
    textq.text = Some(TextMatch {
        terms: "scaletoken".into(),
        on: None,
        require_revision: None,
    });
    let mut report = format!(
        "# Typed-data scale workload\n\nHardware: {} / {} / {}\n\nRecords: {records}; database: {} bytes ({} bytes/record); seed via 250-row transactions: {:.2} s.\n\nAll page samples are 50-row first pages through DataSession (60 iterations), microseconds; local edit is a pending overlay through DataSession. All definitions and seed records pass ordered registry/mutation validation. Setup timing includes that validation and derived hooks in 250-row transactions. The fourth type uses 16 KiB inline summaries within record limits; large Note bodies use the separate body-extraction workload.\n\n| Metric (µs) | p50 | p95 |\n|---|---:|---:|\n",
        env::consts::OS,
        env::consts::ARCH,
        fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with("model name") || l.starts_with("Hardware"))
            .unwrap_or("CPU not exposed"),
        db_size(&db)?,
        db_size(&db)? / records as u64,
        seeded.as_secs_f64()
    );
    let measure = |q: &Query| {
        sample(|| {
            let p = session.query(SCOPE, q).map_err(|e| e.to_string())?;
            if p.rows.len() != 50 && records >= 100_000 {
                return Err(format!("expected 50 rows, got {}", p.rows.len()).into());
            }
            Ok(())
        })
    };
    let indexed_time = measure(&indexed)?;
    metric(&mut report, "indexed", indexed_time);
    let indexed_steps = (0..=100)
        .map(|k| k * 1000)
        .find(|steps| {
            query::run(
                replica.conn(),
                SCOPE,
                &[SCOPE],
                &bh_data::catalogue::Shipped,
                &indexed,
                Budget { vm_steps: *steps },
            )
            .is_ok()
        })
        .ok_or("indexed page exceeded 100k VM steps")?;
    let follow_time = measure(&follow)?;
    metric(&mut report, "Follow", follow_time);
    let via_time = measure(&via)?;
    metric(&mut report, "Via", via_time);
    let via_steps = (0..=1000)
        .map(|k| k * 1000)
        .find(|steps| {
            query::run(
                replica.conn(),
                SCOPE,
                &[SCOPE],
                &bh_data::catalogue::Shipped,
                &via,
                Budget { vm_steps: *steps },
            )
            .is_ok()
        })
        .ok_or("Via exceeded 1m VM steps")?;
    let text_time = measure(&textq)?;
    metric(&mut report, "text", text_time);
    // Use the edit connection itself: the initial seeding connection's PRAGMA
    // synchronous does not carry over to Replica's new connection.
    let sync: i64 = replica
        .conn()
        .query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    let journal: String = replica
        .conn()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    replica
        .conn()
        .execute_batch("CREATE TABLE scale_commit_floor (sample INTEGER PRIMARY KEY)")?;
    let mut edits = Vec::new();
    let mut floors = Vec::new();
    let mut freshness = Vec::new();
    let mut validation = Vec::new();
    for j in 0..SAMPLES {
        let i = 3 + (j * 3); // article, excluding large-body slots
        let op = Operation::Edit {
            record: rid(1, i),
            revision: fixture(1).revision,
            changes: vec![
                FieldChange {
                    path: path("/title"),
                    value: Some(json!(format!("changed-{j}"))),
                },
                FieldChange {
                    path: path("/status"),
                    value: Some(json!("normal")),
                },
            ],
        };
        // Alternating AB/BA arms avoid always giving the edit the second turn.
        let mut floor = || -> Result<(), Box<dyn std::error::Error>> {
            let start = Instant::now();
            let tx = Transaction::new_unchecked(replica.conn(), TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO scale_commit_floor(sample) VALUES(?1)",
                params![j as i64],
            )?;
            tx.commit()?;
            floors.push(start.elapsed().as_micros());
            Ok(())
        };
        let mut validate = || -> Result<(), Box<dyn std::error::Error>> {
            let t = Instant::now();
            session.validate(&op)?;
            validation.push(t.elapsed().as_micros());
            Ok(())
        };
        if j % 2 == 0 {
            validate()?;
            floor()?;
        }
        let t = Instant::now();
        let saved = session.submit(op.clone())?;
        edits.push(t.elapsed().as_micros());
        if j % 2 == 1 {
            floor()?;
            validate()?;
        }
        let mark = replica
            .conn()
            .query_row("SELECT max(next)-1 FROM data_seq", [], |r| {
                r.get::<_, i64>(0)
            })? as u64;
        let wm = text::watermark(replica.conn(), SCOPE)?;
        freshness.push((mark.saturating_sub(wm.complete_through), saved.content_rev));
    }
    let edits_time = (percentile(&mut edits, 50), percentile(&mut edits, 95));
    let floor_time = (percentile(&mut floors, 50), percentile(&mut floors, 95));
    if floor_time.1 == 0 {
        return Err("durable-commit floor p95 had zero microseconds".into());
    }
    metric(
        &mut report,
        "generic edit (2 index entries, 2 fields)",
        edits_time,
    );
    metric(
        &mut report,
        "durable-commit floor (IMMEDIATE single-row INSERT)",
        floor_time,
    );
    metric(
        &mut report,
        "validation + overlay/hooks (savepoint rolled back)",
        (
            percentile(&mut validation, 50),
            percentile(&mut validation, 95),
        ),
    );
    report.push_str(&format!("Edit/floor p95 ratio: {:.3}× (connection journal_mode={journal}, synchronous={sync}; same file and connection, alternating 60 commits with 60 edits).\n", edits_time.1 as f64 / floor_time.1 as f64));
    report.push_str(&format!("\nIndexed page budget probe: ≤{indexed_steps} SQLite VM steps; Via: ≤{via_steps} steps (1,000-step resolution).\n"));
    if env::var_os("BH_DATA_PROFILE_EDITS").is_some() && records >= 100_000 {
        let edit_for = |i: usize, changes: Vec<FieldChange>| Operation::Edit {
            record: rid(1, i),
            revision: fixture(1).revision,
            changes,
        };
        let title = profile_group(replica.conn(), |j| {
            session.submit(edit_for(
                303 + 3 * j,
                vec![FieldChange {
                    path: path("/title"),
                    value: Some(json!(format!("profile-{j}"))),
                }],
            ))?;
            Ok(())
        })?;
        let nontext = profile_group(replica.conn(), |j| {
            session.submit(edit_for(
                603 + 3 * j,
                vec![FieldChange {
                    path: path("/rank"),
                    value: Some(json!(j + 100_000)),
                }],
            ))?;
            Ok(())
        })?;
        let raw = Replica::new_file(&db)?;
        let direct = profile_group(raw.conn(), |j| {
            let tx = raw.conn().unchecked_transaction()?;
            bh_data::mutation::pending::submit(
                &tx,
                &bh_data::catalogue::Shipped,
                SCOPE,
                &Reader.actor(),
                edit_for(
                    903 + 3 * j,
                    vec![FieldChange {
                        path: path("/title"),
                        value: Some(json!(format!("direct-{j}"))),
                    }],
                ),
            )?;
            tx.commit()?;
            Ok(())
        })?;
        report.push_str(&format!("\nEdit diagnostic p95 over 60 distinct records: session title edit {} µs/{} VM steps; session non-text rank edit {} µs/{} steps; direct pending::submit+commit title edit without testkit host maintenance {} µs/{} steps. Callbacks include validation, overlay, index/text hooks and, for session, host maintenance (100-step resolution).\n",
            title.0,title.1,nontext.0,nontext.1,direct.0,direct.1));
    }
    let max_lag = freshness.iter().map(|x| x.0).max().unwrap_or(0);
    report.push_str(&format!("\nText freshness lag: max {} sequence revisions, sampled after edit; {} edits returned nonzero content_rev. Generic inline text is synchronously projected.\n",
        max_lag,freshness.iter().filter(|x|x.1!=0).count()));
    // An additional, local index is built after all records exist.
    let build = Instant::now();
    // Create a building index without the testkit Store's eager maintenance;
    // the measured scheduler will service foreground requests between steps.
    let setup_tx = replica.conn().unchecked_transaction()?;
    let sid = records::lookup_scope(&setup_tx, SCOPE)?.ok_or("scope missing")?;
    let ix = index::ensure_local(&setup_tx, sid, tid(1), vec![key("/rank")])?;
    setup_tx.commit()?;
    // A single foreground producer waits for each edit to be serviced before
    // queuing the next. The writer alternates its FIFO with maintenance,
    // avoiding both lock spinning and artificial request overload.
    let (request_tx, request_rx) = mpsc::channel::<(Instant, usize)>();
    request_tx.send((Instant::now(), 0))?;
    let (ack_tx, ack_rx) = mpsc::channel::<()>();
    let producer = thread::spawn(move || {
        for n in 1..200 {
            if ack_rx.recv().is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(2));
            if request_tx.send((Instant::now(), n)).is_err() {
                break;
            }
        }
    });
    let mut backfill_conn = Connection::open(&db)?;
    let mut batches = 0;
    let mut holds = vec![];
    let mut waits = vec![];
    loop {
        if let Ok((queued, n)) = request_rx.try_recv() {
            waits.push(queued.elapsed().as_micros());
            let tx = backfill_conn.transaction()?;
            let mut row = records::get(&tx, sid, rid(1, 3))?.ok_or("foreground record missing")?;
            row.accepted.as_mut().ok_or("foreground document missing")?["rank"] = json!(n);
            records::put(&tx, &mut row)?;
            index::on_record_changed(&tx, &row, &fixture(1))?;
            tx.commit()?;
            let _ = ack_tx.send(());
        }
        let start = Instant::now();
        let tx = backfill_conn.transaction()?;
        let progress = index::backfill_step_bounded(&tx, ix, index::BACKFILL_BATCH, 3_000)?;
        tx.commit()?;
        holds.push(start.elapsed().as_micros());
        batches += 1;
        if progress.ready {
            break;
        }
    }
    drop(ack_tx);
    producer.join().map_err(|_| "producer panicked")?;
    if waits.is_empty() {
        return Err("no foreground requests were serviced during build".into());
    }
    let hold_max = *holds.iter().max().unwrap();
    let wait_max = *waits.iter().max().unwrap();
    let hold_time = (percentile(&mut holds, 50), percentile(&mut holds, 95));
    let wait_p95 = percentile(&mut waits, 95);
    report.push_str(&format!("Index build: {:.3} s, {batches} bounded steps (≤500 rows, ≤3000 VM steps at record boundary); {} FIFO foreground edits serviced. Per-step writer hold p50/p95/max: {}/{}/{hold_max} µs; foreground queue wait p95/max: {wait_p95}/{wait_max} µs.\n",
        build.elapsed().as_secs_f64(),waits.len(),hold_time.0,hold_time.1));
    drop(replica);
    drop(backfill_conn);
    let reopen = sample(|| {
        let r = Replica::new_file(&db)?;
        let s = DataSession::new(&r, Reader);
        let p = s.query(SCOPE, &indexed).map_err(|e| e.to_string())?;
        if p.rows.len() != 50 && records >= 100_000 {
            return Err("short reopened page".into());
        }
        Ok(())
    })?;
    report.push_str("\n| Reopen metric (µs) | p50 | p95 |\n|---|---:|---:|\n");
    metric(&mut report, "reopen → first indexed page", reopen);
    let rebuild = Instant::now();
    index::rebuild_all(|| {
        Connection::open(&db).map_err(|e| bh_data::DataError::Corrupt(e.to_string()))
    })?;
    let mut c = Connection::open(&db)?;
    let mut rebuilt_batches = 0;
    for id in index::pending_work(&c)? {
        if id == index::TEXT_REBUILD_WORK {
            continue;
        }
        loop {
            let tx = c.transaction()?;
            let p = index::backfill_step(&tx, id, index::BACKFILL_BATCH)?;
            tx.commit()?;
            rebuilt_batches += 1;
            if p.ready {
                break;
            }
        }
    }
    report.push_str(&format!("Rebuild derived state from scratch: {:.3} s, {rebuilt_batches} index batches plus bounded text rebuild steps.\n",rebuild.elapsed().as_secs_f64()));
    let r = Replica::new_file(&db)?;
    let s = DataSession::new(&r, Reader);
    let mut unsupported = page(1);
    unsupported.sort = vec![SortKey {
        key: key("/body"),
        desc: false,
    }];
    let unsupported_result = s.query(SCOPE, &unsupported);
    report.push_str(&format!(
        "Unsupported unindexed large sort: {} (expected TooCostly).\n",
        match &unsupported_result {
            Err(e) => format!("{e:?}"),
            Ok(_) => "Ok (small fixture)".into(),
        }
    ));
    if records >= 10_000 && !matches!(unsupported_result, Err(QueryError::TooCostly { .. })) {
        return Err("unsupported query did not report TooCostly".into());
    }
    drop(r);
    let mut parked_conn = Connection::open(&db)?;
    let parked_sid = records::lookup_scope(&parked_conn, SCOPE)?.ok_or("scope missing")?;
    let actor = serde_json::to_vec(&Reader.actor())?;
    for (prior, target) in [(0, 1000), (1000, 10_000)] {
        for start in (prior..target).step_by(250) {
            let tx = parked_conn.transaction()?;
            for n in start..(start + 250).min(target) {
                let record = rid(1, records + n);
                let op = Operation::Delete { record };
                let mut bytes = payload::encode(MutationId([7; 16]), &op)?;
                bytes[0] = 255; // a well-framed but unsupported future payload
                let affects = serde_json::to_string(&payload::Affects {
                    type_id: None,
                    record: Some(record),
                })?;
                tx.execute("INSERT INTO data_parked(scope,position,affects,payload,actor,reason,record,holds) VALUES(?1,?2,?3,?4,?5,'unsupported',?6,1)",
                    rusqlite::params![parked_sid, n as i64+1,affects,bytes,actor,record.0.as_slice()])?;
            }
            tx.commit()?;
        }
        let mut times = vec![];
        for _ in 0..3 {
            let tx = parked_conn.transaction()?;
            let start = Instant::now();
            let applied = apply::retry_parked(&tx, &bh_data::catalogue::Shipped, SCOPE)?;
            let applied = applied.len();
            times.push(start.elapsed().as_micros());
            if applied != 0 {
                return Err("unsupported parked work unexpectedly applied".into());
            }
            tx.rollback()?; // same parked population for each timed pass
        }
        report.push_str(&format!("retry_parked with {target} unsupported record-scoped rows: {} µs median of 3 passes (transaction rolled back between passes).\n",percentile(&mut times,50)));
    }
    let revisions = sample(|| {
        let revisions = registry::revisions(&parked_conn, parked_sid, tid(1))?;
        if revisions.len() != 1 {
            return Err("expected one article revision".into());
        }
        Ok(())
    })?;
    let index_bytes: Result<i64, _> = parked_conn.query_row(
        "SELECT sum(pgsize) FROM dbstat WHERE name='data_record_revision'",
        [],
        |r| r.get(0),
    );
    report.push_str(&format!("registry::revisions (one revision, 60 reads): p50 {} µs, p95 {} µs; data_record_revision B-tree: {} bytes (dbstat, 100k records).\n",
        revisions.0,revisions.1,index_bytes.map(|n|n.to_string()).unwrap_or_else(|_|"dbstat unavailable".into())));
    Ok(RunSummary {
        load,
        detail: report,
        p95: [
            indexed_time.1,
            follow_time.1,
            via_time.1,
            text_time.1,
            edits_time.1,
            reopen.1,
            hold_time.1,
            wait_p95,
        ],
        floor_p95: floor_time.1,
        hold_max,
        wait_max,
    })
}
#[cfg(test)]
mod tests {
    use super::median_edit_ratio;
    #[test]
    fn scale_definitions_reject_invalid_field_values() {
        let t = super::fixture(1);
        let validator =
            bh_data::validate::Compiled::new(&t.effective_schema, &t.resources).unwrap();
        assert!(
            validator
                .validate(&serde_json::json!({"title":5,"status":"normal","rank":1}))
                .is_err()
        );
    }

    #[test]
    fn diagnostic_edit_ratio_is_median_of_run_ratios() {
        // The median of individual ratios differs from the ratio of median p95s.
        assert_eq!(median_edit_ratio(&[(10, 2), (20, 20), (40, 10)]), 4.0);
    }
}
fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("scale: {e}");
            std::process::exit(2)
        }
    }
}
