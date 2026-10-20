use bh_core::note::Note;

#[test]
fn native_safe_integer_boundaries_roundtrip_and_utf16_clocks() {
    for id in [0, 2_002_468_231_004_600, (1u64 << 53) - 1] {
        let mut author = Note::with_writer(id).unwrap();
        let delta = author.append_paragraph("🦀").unwrap();
        assert_eq!(author.replica_id(), id);
        let mut durable = Note::new().unwrap();
        durable.apply_writer_update(&delta, id).unwrap();
        assert_eq!(durable.writer_end(id).unwrap(), Some(4)); // element, text, two UTF16 units
        assert_eq!(author.writer_end(id).unwrap(), Some(4));
        let mut reopened = Note::new().unwrap();
        reopened.apply_update(&durable.state().unwrap()).unwrap();
        assert_eq!(reopened.writer_end(id).unwrap(), Some(4));
    }
    assert!(Note::with_writer(1u64 << 53).is_err());
}
#[test]
fn new_save_refuses_foreign_or_repeated_insertions_but_not_delete_only() {
    let mut author = Note::with_writer(42).unwrap();
    let delta = author.append_paragraph("hi").unwrap();
    let mut durable = Note::new().unwrap();
    assert!(durable.apply_writer_update(&delta, 43).is_err());
    assert_eq!(durable.writer_end(42).unwrap(), Some(0));
    durable.apply_writer_update(&delta, 42).unwrap();
    assert!(durable.apply_writer_update(&delta, 42).is_err());
    durable.apply_writer_update(&[0, 0], 43).unwrap();
    let next = author.append_paragraph("next").unwrap();
    durable.apply_writer_update(&next, 42).unwrap();
    assert_eq!(durable.writer_end(42).unwrap(), Some(10));
}
// Writer 42 inserts "b" after origin 1:2, which this document has not seen.
const PENDING_42: [u8; 10] = [1, 1, 42, 0, 132, 1, 2, 1, 98, 0];
fn dependency() -> Vec<u8> {
    use yrs::{ReadTxn, Text, Transact};
    let doc = yrs::Doc::with_client_id(1);
    let text = doc.get_or_insert_text("t");
    text.insert(&mut doc.transact_mut(), 0, "abc");
    doc.transact()
        .encode_state_as_update_v1(&yrs::StateVector::default())
}
#[test]
fn pending_complete_input_is_not_an_author_clock_until_its_dependency_integrates() {
    let mut note = Note::new().unwrap();
    note.apply_update(&PENDING_42).unwrap();
    // Still screened as a used ID, and kept in the materialized state.
    assert!(note.has_writer(42).unwrap());
    assert_eq!(note.writer_end(42).unwrap(), None);
    let mut reopened = Note::new().unwrap();
    reopened.apply_update(&note.state().unwrap()).unwrap();
    assert!(reopened.has_writer(42).unwrap());
    assert_eq!(reopened.writer_end(42).unwrap(), None);
    // A writer hydrated from that state allocates from its integrated clock 0.
    let mut overlapping = Note::with_writer(42).unwrap();
    overlapping
        .apply_update(&reopened.state().unwrap())
        .unwrap();
    let delta = overlapping.append_paragraph("x").unwrap();
    assert!(reopened.apply_writer_update(&delta, 42).is_err());

    reopened.apply_update(&dependency()).unwrap();
    assert_eq!(reopened.writer_end(42).unwrap(), Some(1));
    let mut author = Note::with_writer(42).unwrap();
    author.apply_update(&reopened.state().unwrap()).unwrap();
    let next = author.append_paragraph("x").unwrap();
    reopened.apply_writer_update(&next, 42).unwrap();
    assert_eq!(reopened.writer_end(42).unwrap(), Some(4));
}
#[test]
fn new_save_whose_own_insertion_stays_pending_is_refused() {
    let mut note = Note::new().unwrap();
    note.apply_update(&dependency()).unwrap();
    note.apply_update(&PENDING_42).unwrap();
    assert_eq!(note.writer_end(42).unwrap(), Some(1));
    // 42:1 also hangs off an absent origin 99:5: applied, but not integrated.
    assert!(
        note.apply_writer_update(&[1, 1, 42, 1, 132, 99, 5, 1, 99, 0], 42)
            .is_err()
    );
}
/// Writer 42's GC prefix 0..len, as a durable save could have left it.
fn gc(len: u32) -> Vec<u8> {
    let mut bytes = vec![1, 1, 42, 0, 0];
    let mut n = len;
    while n >= 128 {
        bytes.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    bytes.extend([n as u8, 0]);
    bytes
}
#[test]
fn terminal_run_ending_at_u32_max_is_valid_progress() {
    let mut durable = Note::new().unwrap();
    durable.apply_update(&gc(u32::MAX - 1)).unwrap();
    assert_eq!(durable.writer_end(42).unwrap(), Some(u32::MAX - 1));
    let mut author = Note::with_writer(42).unwrap();
    author.apply_update(&durable.state().unwrap()).unwrap();
    let last = author.append_paragraph("").unwrap(); // one clock: the element
    durable.apply_writer_update(&last, 42).unwrap();
    assert_eq!(durable.writer_end(42).unwrap(), Some(u32::MAX));
    let mut reopened = Note::new().unwrap();
    reopened.apply_update(&durable.state().unwrap()).unwrap();
    assert_eq!(reopened.writer_end(42).unwrap(), Some(u32::MAX));
    // A run that would cross u32::MAX never decodes, so it can never wrap.
    let mut crossing = Note::new().unwrap();
    crossing.apply_update(&gc(u32::MAX - 1)).unwrap();
    let mut overrun = vec![1, 1, 42, 254, 255, 255, 255, 15, 0, 5, 0]; // GC MAX-1, len 5
    assert!(crossing.apply_writer_update(&overrun, 42).is_err());
    // Exact pinned-Yjs bytes for "ab" typed by 42 at MAX-1: kept by the page,
    // refused here, and never stored as a wrapped clock.
    let yjs_ab = [1, 1, 42, 254, 255, 255, 255, 15, 4, 1, 1, 116, 2, 97, 98, 0];
    assert!(crossing.apply_writer_update(&yjs_ab, 42).is_err());
    overrun[9] = 1; // the same position with len 1 is the valid terminal run
    crossing.apply_writer_update(&overrun, 42).unwrap();
    assert_eq!(crossing.writer_end(42).unwrap(), Some(u32::MAX));
}
#[test]
fn checked_authoring_refuses_an_operation_beyond_remaining_capacity_before_mutating() {
    let mut durable = Note::new().unwrap();
    durable.apply_update(&gc(u32::MAX - 3)).unwrap();
    let mut author = Note::with_writer(42).unwrap();
    author.apply_update(&durable.state().unwrap()).unwrap();
    let before = author.state().unwrap();
    // Element, text and two UTF16 units need four clocks; three remain.
    assert!(author.try_append_paragraph("ab").is_err());
    assert!(author.try_append_paragraph("🦀").is_err());
    assert_eq!(author.state().unwrap(), before);
    let last = author.try_append_paragraph("a").unwrap();
    durable.apply_writer_update(&last, 42).unwrap();
    assert_eq!(durable.writer_end(42).unwrap(), Some(u32::MAX));
    let full = author.state().unwrap();
    assert!(author.try_append_paragraph("").is_err());
    assert_eq!(author.state().unwrap(), full);
    // Without a proven integrated prefix there is nothing to extend.
    let mut pending = Note::with_writer(42).unwrap();
    pending.apply_update(&PENDING_42).unwrap();
    assert!(pending.try_append_paragraph("").is_err());
    let mut fresh = Note::with_writer(7).unwrap();
    let delta = fresh.try_append_paragraph("🦀").unwrap();
    let mut saved = Note::new().unwrap();
    saved.apply_writer_update(&delta, 7).unwrap();
    assert_eq!(saved.writer_end(7).unwrap(), Some(4));
}
#[test]
fn gc_fills_prefix_but_skip_does_not() {
    let mut note = Note::new().unwrap();
    note.apply_update(&[1, 1, 7, 0, 0, 3, 0]).unwrap();
    assert_eq!(note.writer_end(7).unwrap(), Some(3));
    let mut gap = Note::new().unwrap();
    gap.apply_update(&[1, 3, 7, 0, 0, 2, 10, 2, 0, 2, 0])
        .unwrap();
    assert_eq!(gap.writer_end(7).unwrap(), None);
    assert!(gap.has_writer(7).unwrap());
    gap.apply_update(&[1, 1, 7, 2, 0, 2, 0]).unwrap();
    assert_eq!(gap.writer_end(7).unwrap(), Some(6));
}

/// Keystrokes as the editor saves them: one character at a time at the end
/// of a paragraph, each its own update, after a remote paragraph.
fn keystrokes(writer: u64, text: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
    use yrs::{ReadTxn, Text, Transact, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};
    let mut remote = Note::with_writer(7).unwrap();
    let before = remote.append_paragraph("remote").unwrap();
    let doc = yrs::Doc::with_client_id(writer);
    {
        let mut txn = doc.transact_mut();
        txn.apply_update(yrs::updates::decoder::Decode::decode_v1(&before).unwrap())
            .unwrap();
    }
    let paragraph = {
        let mut txn = doc.transact_mut();
        let fragment = txn.get_or_insert_xml_fragment(bh_core::note::FRAGMENT);
        let len = fragment.len(&txn);
        let element = fragment.insert(&mut txn, len, XmlElementPrelim::empty("paragraph"));
        element.insert(&mut txn, 0, XmlTextPrelim::new(""))
    };
    let mut updates = vec![
        doc.transact()
            .encode_state_as_update_v1(&yrs::StateVector::from_iter([(
                yrs::ClientID::new(7),
                remote.writer_end(7).unwrap().unwrap(),
            )])),
    ];
    for c in text.chars() {
        let mut txn = doc.transact_mut();
        let end = paragraph.len(&txn);
        paragraph.insert(&mut txn, end, &c.to_string());
        updates.push(txn.encode_update_v1());
    }
    (before, updates)
}

#[test]
fn one_writers_keystrokes_merge_into_one_update_with_the_same_structure() {
    let (remote, updates) = keystrokes(42, "Hi, this is a test");
    let merged = bh_core::note::merge_updates(&updates).unwrap();
    let parts: Vec<&[u8]> = updates.iter().map(Vec::as_slice).collect();
    assert_eq!(
        merged,
        bh_core::note::native::merge_updates(&parts).unwrap()
    );
    let mut one_by_one = Note::new().unwrap();
    one_by_one.apply_update(&remote).unwrap();
    for update in &updates {
        one_by_one.apply_update(update).unwrap();
    }
    // A receiver judges the merged update as one continuous run of the writer.
    let mut received = Note::new().unwrap();
    received.apply_update(&remote).unwrap();
    received.apply_incoming(&merged, 42).unwrap();
    assert_eq!(received.digest().unwrap(), one_by_one.digest().unwrap());
    assert_eq!(
        received.writer_end(42).unwrap(),
        one_by_one.writer_end(42).unwrap()
    );
    assert!(merged.len() < updates.iter().map(Vec::len).sum::<usize>());
    assert!(bh_core::note::merge_updates(&[vec![9, 9, 9]]).is_err());
}
