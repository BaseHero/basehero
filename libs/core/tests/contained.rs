//! The contained note engine against the native one, and its local limits.

use bh_core::contained::{self, MEMORY_LIMIT};
use bh_core::note::{
    IncomingError, IncomingRefusal, Note, NoteError, OrderedState, WriterError, abi, is_update,
    native,
};
use bh_core::note_schema;
use std::time::Instant;
use yrs::updates::decoder::Decode;

mod support;
use support::honest_history;

#[test]
fn decoding_reuses_the_note_guest_and_failed_decode_invalidates_it() {
    let mut note = Note::new().unwrap();
    let bytes = note.append_paragraph("kept").unwrap();
    let before = note.digest().unwrap();
    assert!(note.is_update(&bytes).unwrap());
    assert!(!note.is_update(&[255, 255, 255]).unwrap());
    assert_eq!(note.digest().unwrap(), before);
    let failed = contained::with_fuel(0, || note.is_update(&bytes));
    assert!(matches!(failed, Err(NoteError::Unavailable)));
    // A separate scratch decoder would leave this guest usable instead.
    assert!(matches!(note.digest(), Err(NoteError::Unavailable)));
    let reopened = Note::from_ordered(&OrderedState::single(bytes)).unwrap();
    assert_eq!(reopened.digest().unwrap(), before);
}

fn updates(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect()
}

fn k2() -> Vec<Vec<u8>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/k2.json")).unwrap();
    fixture["updates"]
        .as_array()
        .unwrap()
        .iter()
        .map(updates)
        .collect()
}

/// The real editor's Undo/redo history: `(origin's writer, update)` in
/// canonical order after the seed, for each captured browser.
type WriterLog = Vec<(u64, Vec<u8>)>;
fn supported_editor() -> Vec<(String, WriterLog)> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/supported-editor.json")).unwrap();
    let writers = &fixture["writers"];
    let writer = |origin: &str| writers[origin].as_u64().unwrap();
    fixture["captures"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(browser, capture)| {
            let mut log = vec![(writer("seed"), updates(&capture["seed"]))];
            for name in capture["canonical"].as_array().unwrap() {
                let original = &capture["originals"][name.as_str().unwrap()];
                log.push((
                    writer(original["origin"].as_str().unwrap()),
                    updates(&original["bytes"]),
                ));
            }
            (browser.clone(), log)
        })
        .collect()
}

/// The writer an update inserts under, if it inserts at all.
fn inserter(update: &[u8]) -> Option<u64> {
    let inserts = yrs::Update::decode_v1(update).ok()?.insertions(true);
    inserts.iter().next().map(|(id, _)| id.get())
}

fn note_error(error: &NoteError) -> Vec<u8> {
    let mut out = Vec::new();
    abi::note_error(error, &mut out);
    out
}

fn writer_error(error: &WriterError) -> Vec<u8> {
    let mut out = Vec::new();
    abi::writer_error(error, &mut out);
    out
}

thread_local! {
    /// Every incoming outcome the comparison reached.
    static OUTCOMES: std::cell::RefCell<std::collections::BTreeSet<String>> =
        Default::default();
}

/// A contained note and its native twin, compared after every step.
struct Twin {
    contained: Note,
    native: native::Note,
    writers: Vec<u64>,
}

impl Twin {
    fn reader(writers: &[u64]) -> Self {
        Self {
            contained: Note::new().unwrap(),
            native: native::Note::new(),
            writers: writers.to_vec(),
        }
    }

    fn writer(client: u64, writers: &[u64]) -> Self {
        Self {
            contained: Note::with_writer(client).unwrap(),
            native: native::Note::with_writer(client).unwrap(),
            writers: writers.to_vec(),
        }
    }

    fn from_ordered(state: &OrderedState, writers: &[u64]) -> Self {
        let twin = Self {
            contained: Note::from_ordered(state).unwrap(),
            native: native::Note::from_ordered(state).unwrap(),
            writers: writers.to_vec(),
        };
        twin.check("reopened");
        twin
    }

    fn check(&self, what: &str) {
        let (c, n) = (&self.contained, &self.native);
        assert_eq!(c.digest().unwrap(), n.digest(), "{what}: digest");
        assert_eq!(c.state().unwrap(), n.state(), "{what}: state");
        assert_eq!(
            c.title_preview().unwrap(),
            n.title_preview(),
            "{what}: title"
        );
        assert_eq!(c.has_pending().unwrap(), n.has_pending(), "{what}: pending");
        assert_eq!(
            c.document_positions().unwrap(),
            n.document_positions(),
            "{what}: positions"
        );
        for &w in &self.writers {
            assert_eq!(c.has_writer(w).unwrap(), n.has_writer(w), "{what}: has {w}");
            assert_eq!(
                c.writer_prefix(w).unwrap(),
                n.writer_prefix(w),
                "{what}: prefix {w}"
            );
        }
    }

    fn apply(&mut self, update: &[u8], what: &str) -> bool {
        let c = self.contained.apply_update(update);
        let n = self.native.apply_update(update);
        assert_eq!(
            c.as_ref().err().map(note_error),
            n.as_ref().err().map(note_error),
            "{what}: apply"
        );
        self.check(what);
        n.is_ok()
    }

    fn apply_writer(&mut self, update: &[u8], client: u64, what: &str) {
        let c = self.contained.apply_writer_update(update, client);
        let n = self.native.apply_writer_update(update, client);
        assert_eq!(
            c.as_ref().err().map(writer_error),
            n.as_ref().err().map(writer_error),
            "{what}: apply as writer"
        );
        self.check(what);
    }

    fn incoming(
        &mut self,
        update: &[u8],
        client: u64,
        what: &str,
    ) -> Result<(), (IncomingRefusal, bool)> {
        let c = self.contained.apply_incoming(update, client);
        let n = self.native.apply_incoming(update, client);
        assert_eq!(
            c,
            n.map_err(|(reason, changed)| IncomingError::Refused { reason, changed }),
            "{what}: incoming as {client}"
        );
        OUTCOMES.with(|o| o.borrow_mut().insert(format!("{n:?}")));
        self.check(what);
        n
    }

    fn author(&mut self, text: &str, what: &str) {
        let c = self.contained.try_append_paragraph(text);
        let n = self.native.try_append_paragraph(text);
        match (c, n) {
            (Ok(c), Ok(n)) => assert_eq!(c, n, "{what}: authored update"),
            (c, n) => assert_eq!(
                c.err().map(|e| writer_error(&e)),
                n.err().map(|e| writer_error(&e)),
                "{what}: authoring"
            ),
        }
        self.check(what);
    }

    fn compaction(&self, previous: &OrderedState, tail: &[Vec<u8>], what: &str) {
        let before = bh_core::note::verification_rebuilds();
        let c = self.contained.ordered(previous, tail).unwrap();
        let spent = bh_core::note::verification_rebuilds() - before;
        let n = self.native.ordered(previous, tail);
        assert_eq!(
            bh_core::note::verification_rebuilds() - before - spent,
            spent,
            "{what}: rebuilds"
        );
        assert_eq!(c, n, "{what}: ordered");
        assert_eq!(
            self.contained.merged().unwrap(),
            self.native.merged(),
            "{what}: merged"
        );
    }
}

/// The incoming writer rule on accepted state, in log order, with a foreign
/// declaration, an early later run and a duplicate probed around each one.
fn incoming_rule(log: &[(u64, Vec<u8>)], writers: &[u64], what: &str) {
    let mut accepted: Vec<Vec<u8>> = Vec::new();
    let mut twin = Twin::reader(writers);
    let rebuild = |accepted: &[Vec<u8>]| {
        let mut state = OrderedState::default();
        for update in accepted {
            state.push(update.clone());
        }
        Twin::from_ordered(&state, writers)
    };
    for (i, (declared, update)) in log.iter().enumerate() {
        let what = format!("{what} #{i}");
        let foreign = writers
            .iter()
            .copied()
            .find(|w| w != declared)
            .unwrap_or(1 << 52);
        if inserter(update).is_some() {
            assert_eq!(
                twin.incoming(update, foreign, &what),
                Err((IncomingRefusal::ForeignWriter, false))
            );
        }
        if inserter(update) == Some(*declared)
            && let Some((_, later)) = log[i + 1..].iter().find(|(w, _)| w == declared)
            && let Err((_, true)) = twin.incoming(later, *declared, &what)
        {
            twin = rebuild(&accepted);
        }
        match twin.incoming(update, *declared, &what) {
            Ok(()) => {
                accepted.push(update.clone());
                if inserter(update).is_some() {
                    assert_eq!(
                        twin.incoming(update, *declared, &what),
                        Err((IncomingRefusal::Duplicate, false))
                    );
                }
            }
            Err((_, true)) => twin = rebuild(&accepted),
            Err((_, false)) => {}
        }
    }
}

fn ordered_of(log: &[Vec<u8>]) -> OrderedState {
    let mut state = OrderedState::default();
    for update in log {
        state.push(update.clone());
    }
    state
}

/// Replay, compaction, reopening, authoring, classification and the
/// incoming rule, each compared with the native engine.
fn compare(log: &[(u64, Vec<u8>)], writers: &[u64], what: &str) {
    let updates: Vec<Vec<u8>> = log.iter().map(|(_, u)| u.clone()).collect();
    let mut twin = Twin::reader(writers);
    for (i, update) in updates.iter().enumerate() {
        assert_eq!(
            is_update(update).unwrap(),
            native::is_update(update),
            "{what} #{i}: is_update"
        );
        twin.apply(update, &format!("{what} #{i}"));
    }
    twin.compaction(&OrderedState::default(), &updates, what);
    let half = updates.len() / 2;
    twin.compaction(&ordered_of(&updates[..half]), &updates[half..], what);
    let state = twin.native.state();
    assert_eq!(
        note_schema::classify_note(&state).map_err(|e| note_error(&e)),
        note_schema::native::classify_note(&state).map_err(|e| note_error(&e)),
        "{what}: classify"
    );
    let ordered = twin.native.ordered(&OrderedState::default(), &updates);
    if let Some(ordered) = ordered {
        let mut reopened = Twin::from_ordered(&ordered, writers);
        let late = native::Note::with_writer(1 << 52)
            .unwrap()
            .append_paragraph("late");
        reopened.apply(&late, what);
    }

    // Each writer's own updates through the authoring rule, others' as read.
    for &author in writers {
        let mut twin = Twin::writer(author, writers);
        for (i, (writer, update)) in log.iter().enumerate() {
            let what = format!("{what} as {author} #{i}");
            if *writer == author {
                twin.apply_writer(update, author, &what);
            } else {
                twin.apply(update, &what);
            }
        }
        twin.author("contained", &format!("{what} as {author}"));
    }
    incoming_rule(log, writers, what);
}

#[test]
fn contained_matches_native_digest() {
    for seed in 0..500 {
        let (log, docs) = honest_history(seed);
        let writers: Vec<u64> = docs.iter().map(|d| d.client_id().get()).collect();
        let log: Vec<(u64, Vec<u8>)> = log
            .into_iter()
            .map(|u| (inserter(&u).unwrap_or(writers[0]), u))
            .collect();
        compare(&log, &writers, &format!("seed {seed}"));
    }

    let crafted: Vec<(u64, Vec<u8>)> = k2()
        .into_iter()
        .map(|u| (inserter(&u).unwrap(), u))
        .collect();
    let mut writers: Vec<u64> = crafted.iter().map(|(w, _)| *w).collect();
    writers.sort();
    writers.dedup();
    compare(&crafted, &writers, "K2");

    for (browser, log) in supported_editor() {
        let mut writers: Vec<u64> = log.iter().map(|(w, _)| *w).collect();
        writers.sort();
        writers.dedup();
        compare(&log, &writers, &browser);
        let mut note = Note::new().unwrap();
        for (_, update) in &log {
            note.apply_update(update).unwrap();
        }
        assert_eq!(note.title_preview().unwrap(), "aXd", "{browser}");
    }

    // The corpus reaches acceptance and each writer-rule refusal.
    let outcomes = OUTCOMES.with(|o| o.borrow().clone());
    for expected in [
        "Ok(())",
        "Err((ForeignWriter, false))",
        "Err((NotContinuous, false))",
        "Err((Duplicate, false))",
    ] {
        assert!(outcomes.contains(expected), "{expected} in {outcomes:?}");
    }
    eprintln!("incoming outcomes compared: {outcomes:?}");

    for garbage in [&[][..], &[1, 2, 3], &[0, 0, 7], &k2()[2][..9]] {
        assert_eq!(is_update(garbage).unwrap(), native::is_update(garbage));
        let mut twin = Twin::reader(&[1]);
        twin.apply(garbage, "garbage");
    }
}

fn var(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// One item at root array `bomb` holding `depth` nested one-element arrays:
/// decoding it recurses once per level, past any thread's stack.
fn nesting_bomb(depth: usize) -> Vec<u8> {
    let mut update = vec![1, 1];
    var(&mut update, 3); // client
    var(&mut update, 0); // clock
    update.push(8); // an Any item without origins, so with parent info
    update.push(1); // named root
    var(&mut update, 4);
    update.extend_from_slice(b"bomb");
    update.push(1); // one value
    for _ in 0..depth {
        update.extend_from_slice(&[117, 1]); // an array of one
    }
    update.push(126); // null
    update.push(0); // empty delete set
    update
}

/// An honest note's accepted state and digest.
fn accepted() -> (OrderedState, [u8; 32]) {
    let (log, _) = honest_history(3);
    let state = ordered_of(&log);
    let digest = Note::from_ordered(&state).unwrap().digest().unwrap();
    (state, digest)
}

#[test]
fn trap_is_waiting_not_refusal() {
    let (state, digest) = accepted();
    let bomb = nesting_bomb(1_000_000);

    let mut note = Note::from_ordered(&state).unwrap();
    assert!(matches!(
        note.apply_update(&bomb),
        Err(NoteError::Unavailable)
    ));
    let mut note = Note::from_ordered(&state).unwrap();
    assert_eq!(
        note.apply_incoming(&bomb, 3),
        Err(IncomingError::Unavailable)
    );
    assert!(matches!(
        Note::with_writer(3).unwrap().apply_writer_update(&bomb, 3),
        Err(WriterError::Update(NoteError::Unavailable))
    ));
    // Classification leaves the judgement to the owner's apply, which waits.
    assert!(matches!(is_update(&bomb), Err(NoteError::Unavailable)));
    assert!(matches!(
        note_schema::classify_note(&bomb),
        Err(NoteError::Unavailable)
    ));

    // Accepted state is unchanged and reopens as before.
    assert_eq!(
        Note::from_ordered(&state).unwrap().digest().unwrap(),
        digest
    );
    // The trapped note reads conservatively, never as some other note.
    assert!(matches!(note.has_pending(), Err(NoteError::Unavailable)));
    assert!(matches!(note.writer_end(3), Err(NoteError::Unavailable)));
}

#[test]
fn memory_cap_enforced() {
    let (state, digest) = accepted();
    let mut author = native::Note::with_writer(41).unwrap();
    // Copied in, then decoded: twice this text exceeds the cap.
    let large = author.append_paragraph(&"m".repeat(MEMORY_LIMIT / 2 + (1 << 20)));
    let mut native = native::Note::from_ordered(&state).unwrap();
    native.apply_update(&large).unwrap();

    let mut note = Note::from_ordered(&state).unwrap();
    assert!(matches!(
        note.apply_update(&large),
        Err(NoteError::Unavailable)
    ));
    let mut note = Note::from_ordered(&state).unwrap();
    assert_eq!(
        note.apply_incoming(&large, 41),
        Err(IncomingError::Unavailable)
    );
    assert_eq!(
        Note::from_ordered(&state).unwrap().digest().unwrap(),
        digest
    );

    // Well under the cap, the same kind of note opens.
    let mut author = native::Note::with_writer(42).unwrap();
    let fits = author.append_paragraph(&"m".repeat(MEMORY_LIMIT / 8));
    let mut note = Note::from_ordered(&state).unwrap();
    note.apply_update(&fits).unwrap();
}

#[test]
fn fuel_exhausted_is_waiting() {
    let (state, digest) = accepted();
    let mut author = native::Note::with_writer(43).unwrap();
    let update = author.append_paragraph(&"f".repeat(4096));

    let mut note = Note::from_ordered(&state).unwrap();
    note.apply_update(&update).unwrap();
    let needed = contained::last_fuel();
    assert!(needed > 1_000, "an apply costs fuel: {needed}");

    let mut note = Note::from_ordered(&state).unwrap();
    assert!(matches!(
        contained::with_fuel(needed / 2, || note.apply_update(&update)),
        Err(NoteError::Unavailable)
    ));
    let mut note = Note::from_ordered(&state).unwrap();
    assert_eq!(
        contained::with_fuel(needed / 2, || note.apply_incoming(&update, 43)),
        Err(IncomingError::Unavailable)
    );
    assert!(contained::with_fuel(100, || Note::from_ordered(&state)).is_err());
    assert_eq!(
        Note::from_ordered(&state).unwrap().digest().unwrap(),
        digest
    );
}

/// Resource failure must be explicit; retry opens the same durable bytes.
#[test]
fn limited_read_does_not_silently_replace_state() {
    let mut author = native::Note::with_writer(47).unwrap();
    let update = author.append_paragraph("keep this accepted content");
    let mut note = Note::new().unwrap();
    note.apply_update(&update).unwrap();
    let before = note.state().unwrap();
    assert!(!before.is_empty());
    let durable = OrderedState::single(update);
    let after = contained::with_fuel(0, || note.state());
    assert!(matches!(after, Err(NoteError::Unavailable)));
    let reopened = Note::from_ordered(&durable).unwrap();
    assert_eq!(reopened.state().unwrap(), before);
}

#[test]
fn malformed_error_output_cannot_panic_the_host() {
    let mut bytes = vec![2]; // invalid-parent error
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.push(0);
    assert!(abi::read_note_error(&bytes).is_none());
}

#[test]
fn multisegment_open_and_apply_share_one_budget() {
    let update = native::Note::with_writer(49)
        .unwrap()
        .append_paragraph("one segment");
    let single = OrderedState::single(update.clone());
    Note::from_ordered(&single).unwrap();
    let cap = contained::last_fuel() * 2;
    let mut many = OrderedState::default();
    for _ in 0..1000 {
        many.push(update.clone());
    }
    // Every individual operation fits, but the complete open must not buy
    // a new budget for every segment.
    let mut healthy = Note::new().unwrap();
    for _ in 0..4 {
        contained::with_fuel(cap, || healthy.apply_update(&update)).unwrap();
    }
    assert!(matches!(
        contained::with_fuel(cap, || Note::from_ordered(&many)),
        Err(NoteError::Unavailable)
    ));
    let mut candidate = Note::new().unwrap();
    assert!(matches!(
        contained::with_fuel(cap, || candidate.apply_ordered(&many)),
        Err(NoteError::Unavailable)
    ));
    assert_eq!(
        healthy.state().unwrap(),
        Note::from_ordered(&many).unwrap().state().unwrap()
    );
}

#[test]
fn exhausted_reads_are_explicit_errors() {
    for op in ["state", "digest", "title", "prefix"] {
        let mut author = native::Note::with_writer(48).unwrap();
        let update = author.append_paragraph("unchanged");
        let mut note = Note::new().unwrap();
        note.apply_update(&update).unwrap();
        let result = contained::with_fuel(0, || match op {
            "state" => format!("{:?}", note.state()),
            "digest" => format!("{:?}", note.digest()),
            "title" => format!("{:?}", note.title_preview()),
            _ => format!("{:?}", note.writer_prefix(48)),
        });
        assert_eq!(result, "Err(Unavailable)", "{op}");
    }
}

#[test]
fn module_has_no_unexpected_imports() {
    assert_eq!(
        contained::module_imports().unwrap(),
        Vec::<(String, String)>::new()
    );
}

#[test]
fn instance_per_note_isolated() {
    let (state, digest) = accepted();
    let mut one = Note::from_ordered(&state).unwrap();
    let mut two = Note::from_ordered(&state).unwrap();
    let mut author = native::Note::with_writer(44).unwrap();
    let update = author.append_paragraph("only one");
    one.apply_update(&update).unwrap();
    assert_ne!(one.digest().unwrap(), digest);
    assert_eq!(two.digest().unwrap(), digest);

    // A trap in one note's instance leaves the other working.
    assert!(matches!(
        one.apply_update(&nesting_bomb(1_000_000)),
        Err(NoteError::Unavailable)
    ));
    assert!(matches!(
        one.apply_update(&update),
        Err(NoteError::Unavailable)
    ));
    two.apply_update(&update).unwrap();
    let mut native = native::Note::from_ordered(&state).unwrap();
    native.apply_update(&update).unwrap();
    assert_eq!(two.digest().unwrap(), native.digest());
    assert_eq!(two.state().unwrap(), native.state());

    // Writers keep their own replicas.
    let a = Note::with_writer(45).unwrap();
    let b = Note::with_writer(46).unwrap();
    assert_eq!((a.replica_id(), b.replica_id()), (45, 46));
}

/// Release measurement of the product path for the engine's README:
/// `cargo test --release -p bh-core --test contained -- --ignored --nocapture`.
#[test]
#[ignore]
fn measure_budgets() {
    fn ms(start: Instant) -> f64 {
        start.elapsed().as_secs_f64() * 1000.0
    }
    fn row(label: &str, budget: f64, contained: &mut [f64], native: &mut [f64]) {
        contained.sort_by(f64::total_cmp);
        native.sort_by(f64::total_cmp);
        let (cm, cx) = (
            contained[contained.len() / 2],
            contained[contained.len() - 1],
        );
        let (nm, nx) = (native[native.len() / 2], native[native.len() - 1]);
        println!(
            "{label}: contained median {cm:.3} max {cx:.3} ms; native median {nm:.3} max {nx:.3} ms; budget {budget:.0} ms {}",
            if cx <= budget { "PASS" } else { "FAIL" }
        );
    }

    let start = Instant::now();
    drop(Note::new().unwrap());
    println!("module load and first instance {:.3} ms", ms(start));
    let start = Instant::now();
    drop(Note::new().unwrap());
    println!("instance {:.3} ms", ms(start));

    let line = "x".repeat(98);
    let mut author = native::Note::with_writer(9).unwrap();
    let mut log = Vec::new();
    while yrs::merge_updates_v1(&log).unwrap_or_default().len() < 65_536 {
        for _ in 0..16 {
            log.push(author.append_paragraph(&line));
        }
    }
    let small = yrs::merge_updates_v1(&log).unwrap();
    let mut other = native::Note::with_writer(17).unwrap();
    other.apply_update(&small).unwrap();
    let update = other.append_paragraph(&"u".repeat(4096));
    let mut million_author = native::Note::with_writer(19).unwrap();
    let million: Vec<_> = (0..10_010)
        .map(|_| million_author.append_paragraph(&line))
        .collect();
    let million = yrs::merge_updates_v1(&million).unwrap();
    let mut hostile = ordered_of(&k2());
    hostile.push(support::reverse_typed(11, 1_000_000));
    let cases = [
        ("64 KiB note open", 150.0, OrderedState::single(small)),
        (
            "1M-position note open",
            3000.0,
            OrderedState::single(million),
        ),
        ("hostile K2 + 1M fragmented open", 3000.0, hostile),
    ];
    println!(
        "fixtures: states {:?} B, update {} B",
        cases
            .iter()
            .map(|(_, _, s)| s.segments().iter().map(Vec::len).sum::<usize>())
            .collect::<Vec<_>>(),
        update.len()
    );
    for (i, (label, budget, state)) in cases.iter().enumerate() {
        let (mut c, mut n, mut ca, mut na) = (vec![], vec![], vec![], vec![]);
        let (mut fuel, mut memory) = (0, 0);
        for _ in 0..5 {
            let start = Instant::now();
            let mut note = Note::from_ordered(state).unwrap();
            fuel = fuel.max(contained::last_fuel());
            c.push(ms(start));
            let start = Instant::now();
            let mut twin = native::Note::from_ordered(state).unwrap();
            n.push(ms(start));
            assert_eq!(note.digest().unwrap(), twin.digest());
            if i == 0 {
                let start = Instant::now();
                note.apply_update(&update).unwrap();
                ca.push(ms(start));
                let start = Instant::now();
                twin.apply_update(&update).unwrap();
                na.push(ms(start));
                assert_eq!(note.state().unwrap(), twin.state());
            }
            memory = note.memory_bytes().unwrap();
        }
        row(label, *budget, &mut c, &mut n);
        println!("  largest call {fuel} fuel; instance memory {memory} B");
        if i == 0 {
            row("4 KiB update apply", 20.0, &mut ca, &mut na);
        }
    }
}
