//! Malformed Yjs v1 updates must fail at Note's decode boundary, before mutation.
use bh_core::note::{Note, NoteError};
use yrs::encoding::write::Write;
use yrs::updates::encoder::{Encoder, EncoderV1};

fn delete(client: u64, clock: u64, len: u64) -> Vec<u8> {
    let mut e = EncoderV1::new();
    e.write_var(0u32); // no blocks
    e.write_var(1u32); // one delete client
    e.write_var(client);
    e.write_var(1u32); // one range
    e.write_var(clock);
    e.write_var(len);
    e.to_vec()
}

fn block(kind: u8, client: u64, clock: u64, len: u64) -> Vec<u8> {
    let mut e = EncoderV1::new();
    e.write_var(1u32);
    e.write_var(1u32);
    e.write_var(client);
    e.write_var(clock);
    e.write_u8(kind); // GC 0, Skip 10, deleted Item 1, string Item 4
    if kind == 0 || kind == 10 {
        e.write_var(len);
    } else {
        e.write_var(1u32); // named parent
        e.write_string("t");
        if kind == 4 {
            e.write_string("x");
        } else {
            e.write_var(len);
        }
    }
    e.write_var(0u32); // empty delete set
    e.to_vec()
}

fn origin(client: u64, clock: u64) -> Vec<u8> {
    let mut e = EncoderV1::new();
    e.write_var(1u32);
    e.write_var(1u32);
    e.write_var(42u64);
    e.write_var(0u32);
    e.write_u8(132); // string Item with left origin
    e.write_var(client);
    e.write_var(clock);
    e.write_string("x");
    e.write_var(0u32);
    e.to_vec()
}

fn any_int(raw: &[u8]) -> Vec<u8> {
    let mut e = EncoderV1::new();
    e.write_var(1u32);
    e.write_var(1u32);
    e.write_var(42u64);
    e.write_var(0u32);
    e.write_u8(8); // ContentAny
    e.write_var(1u32); // named parent
    e.write_string("a");
    e.write_var(1u32); // one Any
    let mut out = e.to_vec();
    out.push(125); // Any integer
    out.extend_from_slice(raw);
    out.push(0); // empty delete set
    out
}

fn malformed() -> Vec<(&'static str, Vec<u8>)> {
    let max = u32::MAX as u64;
    let mut duplicate_delete = EncoderV1::new();
    duplicate_delete.write_var(0u32);
    duplicate_delete.write_var(2u32);
    for clock in [0u32, 5] {
        duplicate_delete.write_var(42u64);
        duplicate_delete.write_var(1u32);
        duplicate_delete.write_var(clock);
        duplicate_delete.write_var(1u32);
    }
    let duplicate_block = block(4, 42, 0, 1);
    let section = &duplicate_block[1..duplicate_block.len() - 1]; // one client section, no delete set
    let mut twice = vec![2]; // two clients, despite same client ID
    twice.extend_from_slice(section);
    twice.extend_from_slice(section);
    twice.push(0);

    vec![
        ("delete-end", delete(42, max, 1)),
        ("delete-wide-clock", delete(42, 1u64 << 32, 1)),
        ("delete-wide-length", delete(42, 0, 1u64 << 32)),
        ("delete-client-wide", delete(1u64 << 53, 0, 1)),
        ("gc-end", block(0, 42, max, 1)),
        ("skip-end", block(10, 42, max, 1)),
        ("item-end", block(4, 42, max, 1)),
        ("deleted-item-end", block(1, 42, max, 1)),
        ("gc-wide-clock", block(0, 42, 1u64 << 32, 1)),
        ("gc-wide-length", block(0, 42, 0, 1u64 << 32)),
        ("client-wide", block(4, 1u64 << 53, 0, 1)),
        ("origin-client-wide", origin(1u64 << 53, 0)),
        ("origin-clock-wide", origin(99, 1u64 << 32)),
        (
            "delete-overlong-zero",
            vec![0, 1, 42, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1],
        ),
        ("block-duplicate-client", twice),
        ("delete-duplicate-client", duplicate_delete.to_vec()),
        (
            "i64-overlong-shift",
            any_int(&[
                0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
            ]),
        ),
        (
            "i64-positive-overflow",
            any_int(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2]),
        ),
        (
            "i64-negative-overflow",
            any_int(&[0xc1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2]),
        ),
    ]
}

#[test]
fn rejects_invalid_widths_and_duplicate_sections_before_mutating_note() {
    for (name, bytes) in malformed() {
        let mut note = Note::new();
        note.append_paragraph("before");
        let before = note.state();
        let result = note.apply_update(&bytes);
        assert!(
            matches!(result, Err(NoteError::Decode(_))),
            "{name}: {result:?}"
        );
        assert_eq!(note.state(), before, "{name} changed note");
    }
}

#[test]
fn accepts_valid_numeric_boundaries() {
    // Upstream's *encoder* panics on i64::MIN; these are valid lib0 signed-varint bytes.
    let min_bytes = [0xc0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
    let mut i64_max = EncoderV1::new();
    i64_max.write_var(i64::MAX);
    for (name, bytes) in [
        ("delete-last-clock", delete(42, u32::MAX as u64 - 1, 1)),
        ("block-last-clock", block(0, 42, u32::MAX as u64 - 1, 1)),
        ("client-max53", block(4, (1u64 << 53) - 1, 0, 1)),
        ("delete-client-max53", delete((1u64 << 53) - 1, 0, 1)),
        ("origin-last-clock", origin(99, u32::MAX as u64)),
        ("zero-gc", block(0, 42, 0, 0)),
        ("zero-skip", block(10, 42, 0, 0)),
        ("zero-delete", delete(42, 0, 0)),
        ("i64-min", any_int(&min_bytes)),
        ("i64-max", any_int(&i64_max.to_vec())),
        ("i64-minus-300", any_int(&[0xec, 0x04])),
    ] {
        let mut note = Note::new();
        assert!(note.apply_update(&bytes).is_ok(), "valid {name} rejected");
        if let Some(want) = match name {
            "i64-min" => Some(i64::MIN),
            "i64-max" => Some(i64::MAX),
            "i64-minus-300" => Some(-300),
            _ => None,
        } {
            use yrs::updates::decoder::Decode;
            use yrs::{Any, Array, Doc, Number, Out, Transact};
            let mut restored = Note::new();
            restored
                .apply_update(&note.state())
                .expect("signed integer round-trip");
            for state in [note.state(), restored.state()] {
                let doc = Doc::new();
                doc.transact_mut()
                    .apply_update(yrs::Update::decode_v1(&state).unwrap())
                    .unwrap();
                let array = doc.get_or_insert_array("a");
                assert_eq!(
                    array.get(&doc.transact(), 0),
                    Some(Out::Any(Any::Number(Number::Int(want)))),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn yjs_rich_state_and_merged_gaps_decode_through_note() {
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/interop/checked-yrs-expected.json"
    ))
    .unwrap();
    for (name, bytes) in [
        (
            "rich",
            include_bytes!("../../../tests/interop/checked-yrs-rich.bin").as_slice(),
        ),
        (
            "gap",
            include_bytes!("../../../tests/interop/checked-yrs-gap.bin").as_slice(),
        ),
    ] {
        let mut note = Note::new();
        note.apply_update(bytes).expect("Yjs v1 fixture");
        let mut restored = Note::new();
        restored.apply_update(&note.state()).expect("yrs snapshot");
        // Hash-map key serialization order need not be byte-identical after reload.
        // The native reader must retain Yjs's client clocks and rendered content.
        let inspect = |state: &[u8]| {
            use yrs::updates::decoder::Decode;
            use yrs::{Any, Doc, GetString, Map, Number, Out, ReadTxn, Transact, Update};
            let doc = Doc::new();
            doc.transact_mut()
                .apply_update(Update::decode_v1(state).unwrap())
                .unwrap();
            let text = doc.get_or_insert_text("t");
            let map = doc.get_or_insert_map("m");
            let tx = doc.transact();
            let mut vector: Vec<_> = tx
                .state_vector()
                .iter()
                .map(|(id, clock)| (id.to_string(), *clock))
                .collect();
            vector.sort();
            let ints: Vec<_> = ["-1", "-300", "2147483647"]
                .iter()
                .map(|key| match map.get(&tx, key) {
                    Some(Out::Any(Any::Number(Number::Int(n)))) => Some(n.to_string()),
                    _ => None,
                })
                .collect();
            (vector, text.get_string(&tx), ints)
        };
        let want = &expected[name];
        for state in [note.state(), restored.state()] {
            let (vector, text, ints) = inspect(&state);
            assert_eq!(serde_json::json!(vector), want["vector"], "{name} vector");
            if name == "rich" {
                assert_eq!(text, want["text"].as_str().unwrap(), "{name} text");
                for (key, value) in ["-1", "-300", "2147483647"].iter().zip(ints) {
                    assert_eq!(
                        value.as_deref(),
                        Some(want["integers"][key].as_str().expect("Yjs integer")),
                        "{name} integer {key}"
                    );
                }
            }
        }
    }
}
