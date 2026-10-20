use bh_core::note::{Note, ORDERED_REBUILD_BUDGET, OrderedState, verification_rebuilds};
use yrs::types::xml::XmlOut;
use yrs::undo::UndoManager;
use yrs::updates::decoder::Decode;
use yrs::{
    GetString, ReadTxn, Text, Transact, WriteTxn, Xml, XmlElementPrelim, XmlFragment, XmlTextPrelim,
};

mod support;
use support::{honest_history, writer};

/// Updates in log order whose third names non-adjacent anchors.
fn k2() -> Vec<Vec<u8>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/k2.json")).unwrap();
    fixture["updates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|update| {
            update
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_u64().unwrap() as u8)
                .collect()
        })
        .collect()
}
fn replay(log: &[Vec<u8>]) -> Note {
    let mut note = Note::new().unwrap();
    for update in log {
        note.apply_update(update).unwrap();
    }
    note
}

#[test]
fn k2_ordered_reopen() {
    let log = k2();
    let live = replay(&log);
    assert_eq!(live.title_preview().unwrap(), "helloH worldabcdL");
    // A full state integrates by client ID, not log order: the K2 divergence.
    let merged = Note::from_ordered(&OrderedState::single(live.state().unwrap())).unwrap();
    assert_eq!(merged.title_preview().unwrap(), "helloHabcdL world");
    assert_ne!(merged.digest().unwrap(), live.digest().unwrap());

    let ordered = live
        .ordered(&OrderedState::default(), &log)
        .unwrap()
        .unwrap();
    assert!(ordered.segments().len() < log.len(), "{ordered:?}");
    let reopened = Note::from_ordered(&ordered).unwrap();
    assert_eq!(reopened.digest().unwrap(), live.digest().unwrap());
    assert_eq!(reopened.title_preview().unwrap(), "helloH worldabcdL");
    let decoded = OrderedState::decode(&ordered.encode()).unwrap();
    assert_eq!(decoded, ordered);

    // Later compaction keeps the live structure, and honest edits after the
    // crafted one still merge rather than adding a segment per compaction.
    let mut later = Note::from_ordered(&decoded).unwrap();
    let mut tail = Vec::new();
    for _ in 0..3 {
        let mut author = Note::with_writer(9).unwrap();
        author.apply_update(&later.state().unwrap()).unwrap();
        let mut delta = Vec::new();
        for word in ["one", "two"] {
            delta.push(author.append_paragraph(word).unwrap());
        }
        for update in &delta {
            later.apply_update(update).unwrap();
        }
        tail.extend(delta);
    }
    let next = later.ordered(&decoded, &tail).unwrap().unwrap();
    assert!(
        next.segments().len() <= ordered.segments().len(),
        "{next:?}"
    );
    assert_eq!(
        Note::from_ordered(&next).unwrap().digest().unwrap(),
        later.digest().unwrap()
    );
}

fn var(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}
/// One client's string after `origin`, and before `right` if given.
fn insert(client: u64, origin: (u64, u64), right: Option<(u64, u64)>, text: &str) -> Vec<u8> {
    let mut out = vec![1, 1];
    var(&mut out, client);
    out.push(0);
    out.push(if right.is_some() { 0xc4 } else { 0x84 });
    for (client, clock) in [Some(origin), right].into_iter().flatten() {
        var(&mut out, client);
        var(&mut out, clock);
    }
    var(&mut out, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
    out.push(0);
    out
}
/// The K2 shape once per paragraph, alternating an honest update with a
/// crafted one: `hello` and `HL` after it, then `abcd` anchored inside
/// `hello` and before `L`, then a higher client's ` world` after `hello`,
/// carried by the next honest update.
fn crafted_history(rounds: u64) -> Vec<Vec<u8>> {
    let mut base = Note::with_writer(2).unwrap();
    let mut log = Vec::new();
    let mut world: Option<Vec<u8>> = None;
    for round in 0..rounds {
        // A paragraph, its text, then `hello` from this clock on.
        let at = round * 7;
        let (a, b, c) = (100 + 3 * round, 101 + 3 * round, 102 + 3 * round);
        let hello = base.append_paragraph("hello").unwrap();
        let honest = [
            world.take(),
            Some(hello),
            Some(insert(a, (2, at + 6), None, "HL")),
        ];
        log.push(yrs::merge_updates_v1(honest.iter().flatten()).unwrap());
        log.push(insert(b, (2, at + 4), Some((a, 1)), "abcd"));
        world = Some(insert(c, (2, at + 6), None, " world"));
    }
    log.extend(world);
    log
}

#[test]
fn ordered_respects_rebuild_budget() {
    let log = crafted_history(32);
    let live = replay(&log);
    let merged = Note::from_ordered(&OrderedState::single(live.state().unwrap())).unwrap();
    assert_ne!(
        merged.digest().unwrap(),
        live.digest().unwrap(),
        "every round diverges"
    );
    let spent = |run: &mut dyn FnMut() -> OrderedState| {
        let before = verification_rebuilds();
        let state = run();
        (state, verification_rebuilds() - before)
    };
    let (whole, rebuilds) = spent(&mut || {
        live.ordered(&OrderedState::default(), &log)
            .unwrap()
            .unwrap()
    });
    assert!(rebuilds <= ORDERED_REBUILD_BUDGET, "{rebuilds} rebuilds");
    assert_eq!(
        Note::from_ordered(&whole).unwrap().digest().unwrap(),
        live.digest().unwrap()
    );

    // Checkpoint after checkpoint, each within budget and reopening as the
    // note, with `previous` as stored.
    let mut previous = OrderedState::default();
    let mut note = Note::new().unwrap();
    for chunk in log.chunks(16) {
        for update in chunk {
            note.apply_update(update).unwrap();
        }
        let (ordered, rebuilds) = spent(&mut || note.ordered(&previous, chunk).unwrap().unwrap());
        assert!(rebuilds <= ORDERED_REBUILD_BUDGET, "{rebuilds} rebuilds");
        previous = OrderedState::decode(&ordered.encode()).unwrap();
        assert_eq!(
            Note::from_ordered(&previous).unwrap().digest().unwrap(),
            note.digest().unwrap()
        );
    }
    assert_eq!(note.digest().unwrap(), live.digest().unwrap());
}

#[test]
fn ordered_refuses_a_result_that_reopens_differently() {
    let log = crafted_history(4);
    let live = replay(&log);
    assert!(
        live.ordered(&OrderedState::default(), &log)
            .unwrap()
            .is_some()
    );
    // Not the updates this note was built from: nothing to publish.
    assert_eq!(
        live.ordered(&OrderedState::default(), &log[..log.len() - 1])
            .unwrap(),
        None
    );
}

#[test]
fn legacy_single_checkpoint_decodes_unchanged() {
    let live = replay(&k2()[..2]);
    let legacy = live.state().unwrap();
    assert_eq!(
        OrderedState::decode(&legacy).unwrap(),
        OrderedState::single(legacy.clone())
    );
    assert_eq!(OrderedState::decode(&[]).unwrap(), OrderedState::default());
    let encoded = OrderedState::single(legacy.clone()).encode();
    assert_eq!(&encoded[..5], b"BHOS1");
    assert_eq!(&encoded[5..9], &1u32.to_be_bytes());
    assert_eq!(&encoded[9..13], &(legacy.len() as u32).to_be_bytes());
    assert_eq!(&encoded[13..], legacy.as_slice());
    for bad in [
        &encoded[..encoded.len() - 1],
        &[encoded.as_slice(), &[0]].concat(),
        b"BHOS1\xff\xff\xff\xff".as_slice(),
    ] {
        assert!(OrderedState::decode(bad).is_err());
    }
    assert!(Note::from_ordered(&OrderedState::single(vec![9, 9, 9])).is_err());
}

#[test]
fn honest_histories_compact_to_one_segment() {
    for seed in 0..500 {
        let (log, writers) = honest_history(seed);
        let live = replay(&log);
        for doc in &writers {
            // Each replica integrated in its own order, with its own blocks.
            assert_eq!(
                yrs::structure_digest(&doc.transact()),
                live.digest().unwrap(),
                "seed {seed}"
            );
        }
        let ordered = live
            .ordered(&OrderedState::default(), &log)
            .unwrap()
            .unwrap();
        assert_eq!(ordered.segments().len(), 1, "seed {seed}");
        let reopened = Note::from_ordered(&ordered).unwrap();
        assert_eq!(
            reopened.digest().unwrap(),
            live.digest().unwrap(),
            "seed {seed}"
        );
        assert_eq!(
            reopened.title_preview().unwrap(),
            live.title_preview().unwrap(),
            "seed {seed}"
        );
    }
}

#[test]
fn digest_ignores_block_segmentation() {
    // Integrating the crafted update in log order splits `hello` where it
    // names its origin; the compacted reopen keeps it as one block.
    let log = k2();
    let live = replay(&log);
    let reopened = Note::from_ordered(
        &live
            .ordered(&OrderedState::default(), &log)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_ne!(
        live.state().unwrap(),
        reopened.state().unwrap(),
        "blocks should differ"
    );
    assert_eq!(live.digest().unwrap(), reopened.digest().unwrap());

    // An undo manager keeps deleted text that a replica collects.
    let author = writer(2);
    let text = author.get_or_insert_text("t");
    let mut undo: UndoManager<()> = UndoManager::with_options(yrs::undo::Options::default());
    undo.expand_scope(&author, &text);
    let mut saves = Vec::new();
    let mut save = |edit: &dyn Fn(&mut yrs::TransactionMut)| {
        let mut txn = author.transact_mut();
        edit(&mut txn);
        saves.push(txn.encode_update_v1());
    };
    save(&|txn| text.insert(txn, 0, "abc"));
    save(&|txn| text.remove_range(txn, 1, 1));
    save(&|txn| text.remove_range(txn, 0, 2));
    let collected = replay(&saves);
    let kept = author
        .transact()
        .encode_state_as_update_v1(&yrs::StateVector::default());
    assert_ne!(kept, collected.state().unwrap(), "content should differ");
    assert_eq!(
        yrs::structure_digest(&author.transact()),
        collected.digest().unwrap()
    );

    // Typing in separate saves versus the same keystrokes merged into one.
    let typist = writer(5);
    let text = typist.get_or_insert_text("t");
    let keys: Vec<Vec<u8>> = "hello"
        .chars()
        .enumerate()
        .map(|(at, key)| {
            let mut txn = typist.transact_mut();
            text.insert(&mut txn, at as u32, &key.to_string());
            txn.encode_update_v1()
        })
        .collect();
    let keys_ref: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let merged = yrs::merge_updates_v1(&keys_ref).unwrap();
    assert_eq!(
        replay(&keys).digest().unwrap(),
        replay(&[merged]).digest().unwrap()
    );
}

#[test]
fn digest_detects_order_change() {
    let log = k2();
    let live = replay(&log);
    let merged = Note::from_ordered(&OrderedState::single(live.state().unwrap())).unwrap();
    // Same items, same deletions, different sibling order.
    assert_ne!(merged.digest().unwrap(), live.digest().unwrap());

    // Deletion, content, attributes and pending structs all count.
    let base = live.digest().unwrap();
    let doc = writer(77);
    for update in &log {
        doc.transact_mut()
            .apply_update(yrs::Update::decode_v1(update).unwrap())
            .unwrap();
    }
    let root = doc.get_or_insert_xml_fragment("default");
    let changes: Vec<Vec<u8>> = {
        let Some(XmlOut::Element(p)) = root.get(&doc.transact(), 0) else {
            panic!("paragraph")
        };
        let text = match p.get(&doc.transact(), 0) {
            Some(XmlOut::Text(text)) => text,
            _ => panic!("text"),
        };
        let delete = {
            let mut txn = doc.transact_mut();
            text.remove_range(&mut txn, 0, 1);
            txn.encode_update_v1()
        };
        let attribute = {
            let mut txn = doc.transact_mut();
            p.insert_attribute(&mut txn, "textAlign", "center");
            txn.encode_update_v1()
        };
        let insert = {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, "h");
            txn.encode_update_v1()
        };
        assert_eq!(text.get_string(&doc.transact()), "helloH worldabcdL");
        vec![delete, attribute, insert]
    };
    let mut seen = vec![base];
    let mut note = replay(&log);
    for change in &changes {
        note.apply_update(change).unwrap();
        assert!(!seen.contains(&note.digest().unwrap()));
        seen.push(note.digest().unwrap());
    }
    // An update waiting on a missing origin changes the digest too.
    note.apply_update(&[1, 1, 42, 0, 132, 99, 5, 1, 99, 0])
        .unwrap();
    assert!(!seen.contains(&note.digest().unwrap()));
}

/// Reproduce with: cargo test --release -p bh-core --test ordered_state
/// measure_digest_and_compaction -- --ignored --nocapture
#[test]
#[ignore = "explicit performance run; not an affected-check cost"]
fn measure_digest_and_compaction() {
    use std::time::Instant;
    // One writer's paragraphs as one large update, then 256 small saves.
    fn history(paragraphs: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut author = Note::with_writer(9).unwrap();
        let line = "x".repeat(98);
        let body: Vec<Vec<u8>> = (0..paragraphs)
            .map(|_| author.append_paragraph(&line).unwrap())
            .collect();
        let big = yrs::merge_updates_v1(&body).unwrap();
        let saves = (0..256)
            .map(|n| author.append_paragraph(&format!("save {n}")).unwrap())
            .collect();
        (big, saves)
    }
    // Characters typed backwards: each one a separate item that yrs cannot
    // merge, the digest's worst case for a note of this length.
    fn fragmented(chars: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let doc = writer(11);
        let text = {
            let mut txn = doc.transact_mut();
            let root = txn.get_or_insert_xml_fragment("default");
            let p = root.insert(&mut txn, 0, XmlElementPrelim::empty("paragraph"));
            let text = p.insert(&mut txn, 0, XmlTextPrelim::new(""));
            for _ in 0..chars {
                text.insert(&mut txn, 0, "y");
            }
            text
        };
        let big = doc
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());
        let saves = (0..256)
            .map(|_| {
                let mut txn = doc.transact_mut();
                text.insert(&mut txn, 0, "z");
                txn.encode_update_v1()
            })
            .collect();
        (big, saves)
    }
    for (label, size) in [
        ("64KiB", 0usize),
        ("1M", 9_990),
        ("1M-fragmented", 1_000_000),
    ] {
        let (big, saves) = match (label, size) {
            ("1M-fragmented", chars) => fragmented(chars),
            (_, 0) => {
                // The smallest paragraph count whose merged state reaches 64 KiB.
                let mut n = 8;
                while replay(&[history(n).0]).state().unwrap().len() < 64 * 1024 {
                    n += 8;
                }
                history(n)
            }
            (_, paragraphs) => history(paragraphs),
        };
        // Honest; K2 first; and 256 saves alternating with crafted updates.
        for hostile in ["no", "k2", "crafted"] {
            let mut log: Vec<Vec<u8>> = if hostile == "k2" { k2() } else { Vec::new() };
            log.push(big.clone());
            let prefix = log.len();
            if hostile == "crafted" {
                log.extend(crafted_history(128));
            } else {
                log.extend(saves.iter().cloned());
            }
            let live = replay(&log);
            let started = Instant::now();
            let digest = live.digest().unwrap();
            let digest_time = started.elapsed();
            let previous = live_ordered(&log[..prefix]);
            let (before, started) = (verification_rebuilds(), Instant::now());
            let ordered = live.ordered(&previous, &log[prefix..]).unwrap().unwrap();
            let compact = started.elapsed();
            let rebuilds = verification_rebuilds() - before;
            // What opening adds when a checkpoint is due: one full-state check.
            let started = Instant::now();
            let merged = live.merged().unwrap().is_some();
            let open_check = started.elapsed();
            let started = Instant::now();
            let reopened = Note::from_ordered(&ordered).unwrap();
            let reopen = started.elapsed();
            assert_eq!(reopened.digest().unwrap(), digest);
            eprintln!(
                "measure note={label} hostile={hostile} positions={} state_bytes={} digest={digest_time:?} compact_tail={} compact={compact:?} rebuilds={rebuilds} segments={} encoded_bytes={} open_check={open_check:?} merged={merged} reopen={reopen:?}",
                live.document_positions().unwrap(),
                live.state().unwrap().len(),
                log.len() - prefix,
                ordered.segments().len(),
                ordered.encode().len(),
            );
        }
    }
    fn live_ordered(log: &[Vec<u8>]) -> OrderedState {
        replay(log)
            .ordered(&OrderedState::default(), log)
            .unwrap()
            .unwrap()
    }
}
