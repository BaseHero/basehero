//! The incoming writer rule on accepted note state: a remote update inserts
//! only under its declared writer, continuing exactly at that writer's end,
//! and attaches at its position or is refused with no effect.
use bh_core::note::{IncomingError, IncomingRefusal, Note};

fn var(out: &mut Vec<u8>, mut n: u64) {
    while n >= 128 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// One string item with a left origin (lib0 v1); no delete set.
fn item(client: u64, clock: u32, origin: (u64, u32), text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    var(&mut out, 1);
    var(&mut out, 1);
    var(&mut out, client);
    var(&mut out, clock as u64);
    out.push(0x84);
    var(&mut out, origin.0);
    var(&mut out, origin.1 as u64);
    var(&mut out, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
    var(&mut out, 0);
    out
}

/// Delete `len` clocks of `client` from `clock`, inserting nothing.
fn delete(client: u64, clock: u32, len: u32) -> Vec<u8> {
    let mut out = vec![0, 1];
    var(&mut out, client);
    var(&mut out, 1);
    var(&mut out, clock as u64);
    var(&mut out, len as u64);
    out
}

/// Writer 5 authored a paragraph with "hello": clocks 0..7.
fn seeded() -> (Note, Vec<u8>) {
    let mut author = Note::with_writer(5).unwrap();
    let seed = author.append_paragraph("hello").unwrap();
    let mut note = Note::new().unwrap();
    note.apply_incoming(&seed, 5).unwrap();
    assert_eq!(note.writer_end(5).unwrap(), Some(7));
    (note, seed)
}

#[test]
fn continuing_writer_and_foreign_deletes_are_accepted() {
    let (mut note, _) = seeded();
    note.apply_incoming(&item(9, 0, (5, 6), " world"), 9)
        .unwrap();
    assert_eq!(note.title_preview().unwrap(), "hello world");
    note.apply_incoming(&item(9, 6, (9, 5), "!"), 9).unwrap();
    // Writer 9 deletes writer 5's "h": references to others are fine.
    note.apply_incoming(&delete(5, 2, 1), 9).unwrap();
    assert_eq!(note.title_preview().unwrap(), "ello world!");
    assert!(!note.has_pending().unwrap());
}

#[test]
fn refusals_leave_the_note_unchanged() {
    let (mut note, _) = seeded();
    let before = note.digest().unwrap();
    for (update, writer, reason, changed) in [
        (
            item(9, 0, (5, 6), "x"),
            8,
            IncomingRefusal::ForeignWriter,
            false,
        ),
        (
            item(9, 1, (5, 6), "x"),
            9,
            IncomingRefusal::NotContinuous,
            false,
        ),
        (
            item(5, 7, (5, 6), "x"),
            9,
            IncomingRefusal::ForeignWriter,
            false,
        ),
        (
            item(5, 2, (5, 1), "he"),
            5,
            IncomingRefusal::Duplicate,
            false,
        ),
        (
            item(5, 6, (5, 5), "ox"),
            5,
            IncomingRefusal::NotContinuous,
            false,
        ),
        (
            vec![0xff, 0xff, 0xff],
            5,
            IncomingRefusal::Undecodable,
            false,
        ),
        // Its origin, writer 4's clock 0, is not in the accepted state.
        (
            item(9, 0, (4, 0), "x"),
            9,
            IncomingRefusal::MissingDependency,
            true,
        ),
        (delete(4, 0, 1), 9, IncomingRefusal::MissingDependency, true),
    ] {
        let mut candidate = Note::new().unwrap();
        candidate
            .apply_ordered(&bh_core::note::OrderedState::single(note.state().unwrap()))
            .unwrap();
        let result = candidate.apply_incoming(&update, writer);
        assert_eq!(
            result.err(),
            Some(IncomingError::Refused { reason, changed }),
            "{reason:?}"
        );
        if !changed {
            assert_eq!(candidate.digest().unwrap(), before, "{reason:?}");
        }
    }
    // The same checks on the note itself, for the refusals it can survive.
    assert!(note.apply_incoming(&item(9, 1, (5, 6), "x"), 9).is_err());
    assert_eq!(note.digest().unwrap(), before);
}

#[test]
fn an_update_yrs_cannot_integrate_is_apply_failed_not_undecodable() {
    // Client 1's root String "x", then client 2 inserts at root "y" and
    // uses client 1's primitive String as a parent: it decodes, and yrs
    // fails part-way through integrating it.
    let valid = [1, 1, 1, 0, 4, 1, 1, b'x', 1, b'a', 0];
    let partial = [1, 2, 2, 0, 4, 1, 1, b'y', 1, b'z', 4, 0, 1, 0, 1, b'b', 0];
    let mut note = Note::new().unwrap();
    note.apply_incoming(&valid, 1).unwrap();
    assert_eq!(
        note.apply_incoming(&partial, 2),
        Err(IncomingError::Refused {
            reason: IncomingRefusal::ApplyFailed,
            changed: true
        })
    );
    let mut fresh = Note::new().unwrap();
    assert_eq!(
        fresh.apply_incoming(&[0xff, 0xff, 0xff], 2),
        Err(IncomingError::Refused {
            reason: IncomingRefusal::Undecodable,
            changed: false
        })
    );
}
