//! The bundled note engine: bh-core's own yrs note operations behind a small
//! C ABI, built for `wasm32-unknown-unknown` and run contained by bh-core.
//! It imports nothing. An instance holds at most one note; the verification
//! exports need none. Results follow `bh_core::note::abi`.

#![cfg(target_family = "wasm")]

use bh_core::note::native::{self, Note};
use bh_core::note::{OrderedState, abi, verification_rebuilds};
use std::cell::RefCell;

thread_local! {
    static NOTE: RefCell<Option<Note>> = const { RefCell::new(None) };
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Not called as specified: no note, a second note, or input that is not
/// what the host sends.
const MISUSE: i32 = -1;

/// An input buffer of exactly `len` bytes, owned by the export it is passed to.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn out_ptr() -> *const u8 {
    OUT.with(|out| out.borrow().as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn out_len() -> usize {
    OUT.with(|out| out.borrow().len())
}

/// Take back a buffer from [`alloc`].
fn input(ptr: *mut u8, len: usize) -> Box<[u8]> {
    // SAFETY: the host passes each pointer and length from `alloc` exactly
    // once; Wasm has no other memory to point at.
    unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) }
}

fn finish(result: Result<Vec<u8>, impl FnOnce(&mut Vec<u8>)>) -> i32 {
    OUT.with(|out| {
        let mut out = out.borrow_mut();
        *out = Vec::new();
        match result {
            Ok(bytes) => {
                *out = bytes;
                abi::OK
            }
            Err(encode) => {
                encode(&mut out);
                abi::ERR
            }
        }
    })
}

fn ok(bytes: Vec<u8>) -> i32 {
    finish(Ok::<_, fn(&mut Vec<u8>)>(bytes))
}

fn with_note(op: impl FnOnce(&mut Note) -> i32) -> i32 {
    NOTE.with(|note| match note.borrow_mut().as_mut() {
        Some(note) => op(note),
        None => MISUSE,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn create(client: u64, kind: i32) -> i32 {
    let note = match kind {
        abi::READER => Note::with_replica(client),
        abi::WRITER => match Note::with_writer(client) {
            Ok(note) => note,
            Err(e) => return finish(Err(|out: &mut Vec<u8>| abi::writer_error(&e, out))),
        },
        _ => return MISUSE,
    };
    NOTE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return MISUSE;
        }
        *slot = Some(note);
        ok(Vec::new())
    })
}

/// Open every ordered segment under the host's single operation budget.
#[unsafe(export_name = "open")]
pub extern "C" fn open_note(ptr: *mut u8, len: usize, client: u64) -> i32 {
    let bytes = input(ptr, len);
    let result = (|| {
        let state = OrderedState::decode(&bytes)?;
        let mut note = Note::with_replica(client);
        note.apply_ordered(&state)?;
        NOTE.with(|slot| *slot.borrow_mut() = Some(note));
        Ok::<_, bh_core::note::NoteError>(Vec::new())
    })();
    finish(result.map_err(|e| move |out: &mut Vec<u8>| abi::note_error(&e, out)))
}

#[unsafe(no_mangle)]
pub extern "C" fn apply_ordered(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    with_note(|note| {
        let result = OrderedState::decode(&bytes).and_then(|s| note.apply_ordered(&s));
        finish(
            result
                .map(|()| Vec::new())
                .map_err(|e| move |out: &mut Vec<u8>| abi::note_error(&e, out)),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn apply(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    with_note(|note| {
        finish(
            note.apply_update(&bytes)
                .map(|()| Vec::new())
                .map_err(|e| move |out: &mut Vec<u8>| abi::note_error(&e, out)),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn apply_writer(ptr: *mut u8, len: usize, client: u64) -> i32 {
    let bytes = input(ptr, len);
    with_note(|note| {
        finish(
            note.apply_writer_update(&bytes, client)
                .map(|()| Vec::new())
                .map_err(|e| move |out: &mut Vec<u8>| abi::writer_error(&e, out)),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn apply_incoming(ptr: *mut u8, len: usize, client: u64) -> i32 {
    let bytes = input(ptr, len);
    with_note(|note| {
        finish(
            note.apply_incoming(&bytes, client)
                .map(|()| Vec::new())
                .map_err(|(reason, changed)| {
                    move |out: &mut Vec<u8>| abi::refusal(reason, changed, out)
                }),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn state() -> i32 {
    with_note(|note| ok(note.state()))
}

#[unsafe(no_mangle)]
pub extern "C" fn digest() -> i32 {
    with_note(|note| ok(note.digest().to_vec()))
}

#[unsafe(no_mangle)]
pub extern "C" fn title_preview() -> i32 {
    with_note(|note| ok(note.title_preview().into_bytes()))
}

#[unsafe(no_mangle)]
pub extern "C" fn body_text(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    let Ok(max_bytes) = <[u8; 8]>::try_from(bytes.as_ref()) else {
        return MISUSE;
    };
    let Ok(max_bytes) = usize::try_from(u64::from_le_bytes(max_bytes)) else {
        return MISUSE;
    };
    with_note(|note| ok(note.body_text(max_bytes).into_bytes()))
}

#[unsafe(no_mangle)]
pub extern "C" fn document_positions() -> i32 {
    with_note(|note| ok((note.document_positions() as u64).to_le_bytes().to_vec()))
}

#[unsafe(no_mangle)]
pub extern "C" fn has_writer(client: u64) -> i32 {
    with_note(|note| ok(vec![u8::from(note.has_writer(client))]))
}

#[unsafe(no_mangle)]
pub extern "C" fn writer_prefix(client: u64) -> i32 {
    with_note(|note| {
        let mut out = Vec::new();
        abi::prefix(note.writer_prefix(client), &mut out);
        ok(out)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn has_pending() -> i32 {
    with_note(|note| ok(vec![u8::from(note.has_pending())]))
}

#[unsafe(no_mangle)]
pub extern "C" fn append_paragraph(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return MISUSE;
    };
    with_note(|note| ok(note.append_paragraph(text)))
}

#[unsafe(no_mangle)]
pub extern "C" fn try_append_paragraph(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return MISUSE;
    };
    with_note(|note| {
        finish(
            note.try_append_paragraph(text)
                .map_err(|e| move |out: &mut Vec<u8>| abi::writer_error(&e, out)),
        )
    })
}

/// `framed(digest, state)`: whether that state alone reopens as the digest.
#[unsafe(no_mangle)]
pub extern "C" fn merged(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    let Some([target, state]) = abi::unframed(&bytes).and_then(|p| <[&[u8]; 2]>::try_from(p).ok())
    else {
        return MISUSE;
    };
    let Ok(target) = <[u8; 32]>::try_from(target) else {
        return MISUSE;
    };
    let before = verification_rebuilds();
    let found = native::merged(state.to_vec(), target).is_some();
    let mut out = Vec::new();
    abi::rebuilt(
        verification_rebuilds() - before,
        found.then_some(&[]),
        &mut out,
    );
    ok(out)
}

/// `framed(digest, state, previous, tail)`, the orders encoded: the
/// compaction `Note::ordered` would choose.
#[unsafe(no_mangle)]
pub extern "C" fn ordered(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    let Some([target, state, previous, tail]) =
        abi::unframed(&bytes).and_then(|p| <[&[u8]; 4]>::try_from(p).ok())
    else {
        return MISUSE;
    };
    let (Ok(target), Ok(previous), Ok(tail)) = (
        <[u8; 32]>::try_from(target),
        OrderedState::decode(previous),
        OrderedState::decode(tail),
    ) else {
        return MISUSE;
    };
    let state = state.to_vec();
    drop(bytes);
    let before = verification_rebuilds();
    let found = native::ordered(state, target, &previous, tail.segments()).map(|s| s.encode());
    let mut out = Vec::new();
    abi::rebuilt(verification_rebuilds() - before, found.as_deref(), &mut out);
    ok(out)
}

/// The encoded order of updates: them merged into one.
#[unsafe(no_mangle)]
pub extern "C" fn merge_updates(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    let Ok(updates) = OrderedState::decode(&bytes) else {
        return MISUSE;
    };
    drop(bytes);
    let parts: Vec<&[u8]> = updates.segments().iter().map(Vec::as_slice).collect();
    finish(
        native::merge_updates(&parts)
            .map_err(|e| move |out: &mut Vec<u8>| abi::note_error(&e, out)),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn classify(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    finish(
        bh_core::note_schema::native::classify_note(&bytes)
            .map(|supported| vec![u8::from(supported)])
            .map_err(|e| move |out: &mut Vec<u8>| abi::note_error(&e, out)),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn is_update(ptr: *mut u8, len: usize) -> i32 {
    let bytes = input(ptr, len);
    ok(vec![u8::from(native::is_update(&bytes))])
}
