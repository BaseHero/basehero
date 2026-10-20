use super::*;
use bh_core::{contained::with_fuel, note::NoteError};

fn key(n: u8) -> NoteKey {
    NoteKey {
        base: [1; 32],
        audience: [2; 32],
        note: [n; 32],
    }
}
fn charge(note: &Note) -> usize {
    note.memory_bytes().unwrap() + NOTE_CACHE_OVERHEAD
}
fn coherent(db: &DeviceDatabase) {
    assert_eq!(
        db.cache_bytes,
        db.notes.values().map(|e| e.weight).sum::<usize>()
    );
    assert!(db.cache_bytes <= db.cache_budget);
}

#[test]
fn tiny_guests_obey_linear_memory_budget_and_lru() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let note = Note::new().unwrap();
    let memory = note.memory_bytes().unwrap();
    let weight = charge(&note);
    assert!(memory > 1024 * 1024);
    db.set_note_cache_budget(memory - 1);
    db.return_committed_note(key(0), note, 0, 1);
    assert_eq!(db.cached_note_count(), 0, "one guest exceeds the budget");
    db.set_note_cache_budget(2 * weight);
    for n in 0..3 {
        db.return_committed_note(key(n), Note::new().unwrap(), 0, 1);
        coherent(&db);
    }
    assert_eq!(db.cached_note_count(), 2);
    assert!(!db.notes.contains_key(&key(0)));
    assert_eq!(db.cache_bytes, 2 * weight);
    assert!(db.take_cached_note(key(1), 99).is_none());
    assert_eq!(db.cache_bytes, weight, "stale take removes its charge");
    db.set_note_cache_budget(0);
    assert_eq!(db.cache_bytes, 0);
    assert_eq!(db.cached_note_count(), 0);
}

#[test]
fn borrowed_encoded_weight_is_separate_from_guest_charge() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let note = Note::new().unwrap();
    let weight = charge(&note);
    db.return_committed_note(key(1), note, 0, 1024);
    assert_eq!(db.cache_bytes, weight);
    for n in 1..10 {
        let (note, encoded) = db.take_cached_note(key(1), n - 1).unwrap();
        assert_eq!(encoded, 1024 + (n - 1) as usize);
        assert_eq!(db.cache_bytes, 0);
        db.return_committed_note(key(1), note, n, encoded + 1);
        assert_eq!(db.cache_bytes, weight);
        coherent(&db);
    }
}

#[test]
fn grown_guest_keeps_high_water_charge_with_small_encoded_state() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let mut note = Note::new().unwrap();
    let initial = charge(&note);
    let update = Note::with_writer(100)
        .unwrap()
        .append_paragraph("small")
        .unwrap();
    // Repeated identical updates require transient input/replay allocations,
    // but integrate only one tiny paragraph. Linear memory cannot shrink.
    let mut ordered = OrderedState::default();
    for _ in 0..20_000 {
        ordered.push(update.clone());
    }
    note.apply_ordered(&ordered).unwrap();
    let state = note.state().unwrap();
    assert!(state.len() < 100);
    let grown = charge(&note);
    assert!(grown > initial, "fixture must grow the actual guest memory");
    db.return_committed_note(key(1), note, 0, state.len());
    assert_eq!(db.cache_bytes, grown);
    let (note, encoded) = db.take_cached_note(key(1), 0).unwrap();
    assert_eq!(encoded, state.len());
    assert_eq!(note.state().unwrap(), state);
    db.set_note_cache_budget(initial);
    db.return_committed_note(key(1), note, 0, encoded);
    assert_eq!(db.cached_note_count(), 0, "grown guest no longer fits");
    coherent(&db);
}

#[test]
fn load_read_and_local_growth_refresh_guest_charge() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    db.note_state(key(1)).unwrap();
    let initial = charge(&db.notes[&key(1)].note);
    assert_eq!(db.cache_bytes, initial);
    let mut author = Note::with_writer(101).unwrap();
    let update = author
        .append_paragraph(&"x".repeat(2 * 1024 * 1024))
        .unwrap();
    let saved = db.apply_local_update(key(1), [1; 16], &update).unwrap();
    assert_eq!(db.notes[&key(1)].frontier, saved.update_id);
    assert!(charge(&db.notes[&key(1)].note) > initial);
    assert_eq!(db.cache_bytes, charge(&db.notes[&key(1)].note));
    db.note_state(key(1)).unwrap();
    assert_eq!(db.cache_bytes, charge(&db.notes[&key(1)].note));
    coherent(&db);
    db.set_note_cache_budget(initial);
    assert_eq!(db.cached_note_count(), 0);
    assert_eq!(db.note_state(key(1)).unwrap(), author.state().unwrap());
    assert_eq!(
        db.cached_note_count(),
        0,
        "oversized cold load is not retained"
    );
    coherent(&db);
}

#[test]
fn failed_cache_metric_skips_return_without_cancelling_committed_save() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let mut note = Note::with_writer(102).unwrap();
    let update = note.append_paragraph("already committed").unwrap();
    let expected = note.state().unwrap();
    let committed = db.apply_local_update(key(1), [1; 16], &update).unwrap();
    assert!(!committed.replayed);
    // Simulate an unusable returned candidate using a real contained trap.
    assert!(matches!(
        with_fuel(0, || note.state()),
        Err(NoteError::Unavailable)
    ));
    assert!(matches!(note.memory_bytes(), Err(NoteError::Unavailable)));
    db.return_committed_note(key(1), note, committed.update_id, update.len());
    assert_eq!(
        db.cached_note_count(),
        0,
        "never cache a failed metric as zero"
    );
    assert_eq!(db.cache_bytes, 0);
    assert_eq!(db.local_frontier(key(1)).unwrap(), committed.update_id);
    assert_eq!(db.pending_note_updates().unwrap()[0].bytes, update);
    assert_eq!(db.note_state(key(1)).unwrap(), expected);
    assert!(
        db.apply_local_update(key(1), [1; 16], &update)
            .unwrap()
            .replayed
    );
}
