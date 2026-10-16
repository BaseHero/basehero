//! Catalogue titles are bounded literal previews of a working note, computed
//! while it is already open for a commit; never XML markup or attributes.
use bh_core::note::Note;
use yrs::types::Attrs;
use yrs::{
    Any, Doc, Options, ReadTxn, StateVector, Text, Transact, TransactionMut, WriteTxn, Xml,
    XmlElementPrelim, XmlFragment, XmlFragmentRef, XmlTextPrelim,
};

fn note_from(build: impl FnOnce(&mut TransactionMut, &XmlFragmentRef)) -> Note {
    let doc = Doc::new();
    let mut tx = doc.transact_mut();
    let frag = tx.get_or_insert_xml_fragment("default");
    build(&mut tx, &frag);
    let mut note = Note::new();
    note.apply_update(&tx.encode_update_v1()).unwrap();
    note
}

fn paragraph(tx: &mut TransactionMut, parent: &impl XmlFragment, text: &str) {
    let p = parent.push_back(tx, XmlElementPrelim::empty("paragraph"));
    if !text.is_empty() {
        p.push_back(tx, XmlTextPrelim::new(text));
    }
}

#[test]
fn first_nonempty_supported_block_is_the_trimmed_title() {
    let mut note = Note::new();
    note.append_paragraph("");
    note.append_paragraph(" 🦀  café ");
    note.append_paragraph("later");
    assert_eq!(note.title_preview(), "🦀  café");
    let nested = note_from(|tx, frag| {
        let list = frag.push_back(tx, XmlElementPrelim::empty("bulletList"));
        let item = list.push_back(tx, XmlElementPrelim::empty("listItem"));
        paragraph(tx, &item, "nested");
    });
    assert_eq!(nested.title_preview(), "nested");
    let after_unknown = note_from(|tx, frag| {
        let unknown = frag.push_back(tx, XmlElementPrelim::empty("futureWidget"));
        unknown.push_back(tx, XmlTextPrelim::new("secret"));
        paragraph(tx, frag, "visible");
    });
    assert_eq!(after_unknown.title_preview(), "visible");
    assert_eq!(Note::new().title_preview(), "");
    let empty = note_from(|tx, frag| paragraph(tx, frag, ""));
    assert_eq!(empty.title_preview(), "");
}

#[test]
fn marks_embeds_and_attributes_never_leak_into_literal_title() {
    let note = note_from(|tx, frag| {
        let heading = frag.push_back(tx, XmlElementPrelim::empty("heading"));
        heading.insert_attribute(tx, "level", "secret-attr");
        let text = heading.push_back(tx, XmlTextPrelim::new("<title> café 🦀 "));
        text.format(
            tx,
            0,
            7,
            Attrs::from([("bold".into(), Any::Map(Default::default()))]),
        );
        let end = text.len(tx);
        text.insert_embed(tx, end, Any::from("secret-embed"));
        let end = text.len(tx);
        let secret =
            Any::Map(std::collections::HashMap::from([("v".into(), "secret".into())]).into());
        text.insert_with_attributes(
            tx,
            end,
            "code italic",
            Attrs::from([
                ("code".into(), Any::Bool(true)),
                ("futureMark".into(), secret),
            ]),
        );
        heading.push_back(tx, XmlElementPrelim::empty("hardBreak"));
        heading.push_back(tx, XmlTextPrelim::new("line"));
    });
    assert_eq!(note.title_preview(), "<title> café 🦀 code italic line");
    for fixture in [
        include_bytes!("../../../apps/client/editor/test/mark.bin").as_slice(),
        include_bytes!("../../../apps/client/editor/test/attr.bin").as_slice(),
        include_bytes!("../../../apps/client/editor/test/value.bin").as_slice(),
        include_bytes!("../../../apps/client/editor/test/textAttr.bin").as_slice(),
    ] {
        let mut note = Note::new();
        note.apply_update(fixture).unwrap();
        assert_eq!(note.title_preview(), "hello");
    }
}

#[test]
fn long_first_paragraph_keeps_its_exact_first_80_scalars() {
    for (source, expected) in [
        ("x".repeat(257), "x".repeat(80)),
        ("x".repeat(50_000), "x".repeat(80)),
        ("🦀".repeat(65), "🦀".repeat(65)),
        ("é".repeat(81), "é".repeat(80)),
        (
            format!("{}🦀later", "a".repeat(79)),
            format!("{}🦀", "a".repeat(79)),
        ),
    ] {
        let mut note = Note::new();
        note.append_paragraph(&source);
        assert_eq!(note.title_preview(), expected);
    }
}

#[test]
fn truncated_whitespace_never_selects_a_later_paragraph() {
    let short = note_from(|tx, frag| {
        paragraph(tx, frag, &format!("{}hello", " ".repeat(10)));
    });
    assert_eq!(short.title_preview(), "hello");
    // 80 leading spaces cannot prove the first block is empty.
    let long = note_from(|tx, frag| {
        paragraph(tx, frag, &format!("{}hidden", " ".repeat(100)));
        paragraph(tx, frag, "later");
    });
    assert_eq!(long.title_preview(), "");
}

#[test]
fn deleted_text_is_not_a_stale_title() {
    let doc = Doc::new();
    let mut tx = doc.transact_mut();
    let frag = tx.get_or_insert_xml_fragment("default");
    paragraph(&mut tx, &frag, "deleted block");
    let p = frag.push_back(&mut tx, XmlElementPrelim::empty("paragraph"));
    let text = p.push_back(&mut tx, XmlTextPrelim::new("secret visible"));
    frag.remove(&mut tx, 0);
    text.remove_range(&mut tx, 0, 7);
    let mut note = Note::new();
    note.apply_update(&tx.encode_update_v1()).unwrap();
    assert_eq!(note.title_preview(), "visible");
}

#[test]
fn nesting_beyond_16_levels_is_untitled() {
    for (levels, expected) in [(15, "deep"), (16, "")] {
        let note = note_from(|tx, frag| {
            let mut quote = frag.push_back(tx, XmlElementPrelim::empty("blockquote"));
            for _ in 1..levels {
                quote = quote.push_back(tx, XmlElementPrelim::empty("blockquote"));
            }
            paragraph(tx, &quote, "deep");
        });
        assert_eq!(note.title_preview(), expected, "{levels} levels");
    }
}

#[test]
fn many_leading_empty_blocks_exhaust_the_source_budget() {
    let mut note = Note::new();
    for _ in 0..300 {
        note.append_paragraph("");
    }
    note.append_paragraph("beyond budget");
    assert_eq!(note.title_preview(), "");
}

#[test]
fn whitespace_blocks_share_one_utf8_byte_budget() {
    for (blocks, expected) in [(10, "title"), (20, "")] {
        let note = note_from(|tx, frag| {
            for _ in 0..blocks {
                paragraph(tx, frag, &" ".repeat(60));
            }
            paragraph(tx, frag, "title");
        });
        assert_eq!(
            note.title_preview(),
            expected,
            "{blocks} blocks of 60 spaces"
        );
    }
}

#[test]
fn tombstone_history_before_the_title_is_bounded_and_never_stale() {
    for (deleted, expected) in [(100, "visible"), (10_000, "")] {
        let doc = Doc::with_options(Options {
            skip_gc: true,
            ..Default::default()
        });
        let mut tx = doc.transact_mut();
        let frag = tx.get_or_insert_xml_fragment("default");
        for i in 0..deleted {
            paragraph(&mut tx, &frag, &format!("deleted {i}"));
        }
        paragraph(&mut tx, &frag, "visible");
        drop(tx);
        frag.remove_range(&mut doc.transact_mut(), 0, deleted);
        let bytes = doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default());
        let mut note = Note::new();
        note.apply_update(&bytes).unwrap();
        // Each deleted block stays a linked source item after apply/GC.
        assert_eq!(note.title_preview(), expected, "{deleted} deleted blocks");
    }
}

#[test]
fn early_nested_title_survives_many_later_siblings() {
    let note = note_from(|tx, frag| {
        let list = frag.push_back(tx, XmlElementPrelim::empty("bulletList"));
        for label in ["first", "second"] {
            let item = list.push_back(tx, XmlElementPrelim::empty("listItem"));
            paragraph(tx, &item, label);
        }
        for _ in 0..10_000 {
            paragraph(tx, frag, "");
        }
    });
    assert_eq!(note.title_preview(), "first");
}

#[test]
fn extraction_leaves_the_note_state_unchanged() {
    let mut note = Note::new();
    note.append_paragraph("unchanged");
    let before = note.state();
    assert_eq!(note.title_preview(), "unchanged");
    assert_eq!(note.state(), before);
}

#[test]
fn cursor_charges_tombstones_and_stops_lazily() {
    let doc = Doc::with_options(Options {
        skip_gc: true,
        ..Default::default()
    });
    let mut tx = doc.transact_mut();
    let frag = tx.get_or_insert_xml_fragment("default");
    for _ in 0..1_000 {
        paragraph(&mut tx, &frag, "");
    }
    drop(tx);
    let tx = doc.transact();
    // A lazy cursor charges only the one item it visited.
    let mut items = 256;
    let mut cursor = frag.source_children(&tx);
    assert!(cursor.next(&mut items).unwrap().is_some());
    assert_eq!(items, 255);
    drop(tx);
    let mut tx = doc.transact_mut();
    frag.remove_range(&mut tx, 0, 999);
    drop(tx);
    let tx = doc.transact();
    let mut items = 256;
    let mut cursor = frag.source_children(&tx);
    assert!(
        cursor.next(&mut items).is_err(),
        "999 tombstones precede it"
    );
    assert_eq!(items, 0);
    let mut items = 1_000;
    let mut cursor = frag.source_children(&tx);
    assert!(cursor.next(&mut items).unwrap().is_some());
    assert!(matches!(cursor.next(&mut items), Ok(None)));
    assert_eq!(items, 0);
}

#[test]
fn plain_prefix_charges_formatting_and_utf8_bytes() {
    let doc = Doc::with_options(Options {
        skip_gc: true,
        ..Default::default()
    });
    let mut tx = doc.transact_mut();
    let frag = tx.get_or_insert_xml_fragment("default");
    let p = frag.push_back(&mut tx, XmlElementPrelim::empty("paragraph"));
    let crabs = p.push_back(&mut tx, XmlTextPrelim::new("🦀".repeat(65)));
    let marked = p.push_back(&mut tx, XmlTextPrelim::new("visible"));
    for i in 0..1_000 {
        let bold = Attrs::from([("bold".into(), (i % 2 == 0).into())]);
        marked.format(&mut tx, 0, 1, bold);
    }
    drop(tx);
    let tx = doc.transact();
    let (mut items, mut bytes) = (256, 259);
    assert!(crabs.plain_prefix(&tx, &mut items, &mut bytes, 80).is_err());
    assert_eq!(bytes, 3, "64 whole scalars fit, the 65th does not");
    let (mut items, mut bytes) = (256, 260);
    let prefix = crabs.plain_prefix(&tx, &mut items, &mut bytes, 80).unwrap();
    assert_eq!(prefix, "🦀".repeat(65));
    assert_eq!((items, bytes), (255, 0));
    let (mut items, mut bytes) = (256, 1024);
    assert_eq!(
        crabs.plain_prefix(&tx, &mut items, &mut bytes, 3).unwrap(),
        "🦀🦀🦀"
    );
    assert_eq!(bytes, 1012, "only the requested prefix is copied");
    let (mut items, mut bytes) = (256, 1024);
    assert!(
        marked
            .plain_prefix(&tx, &mut items, &mut bytes, 80)
            .is_err()
    );
    assert_eq!(items, 0, "formatting history consumes the source budget");
}
