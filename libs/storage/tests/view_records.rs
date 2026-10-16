use bh_storage::{DeviceDatabase, NoteKey, ViewRecord};

fn view(note: u8) -> ViewRecord {
    ViewRecord {
        version: 1,
        key: NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [note; 32],
        },
        anchor: vec![3, 4],
        head: vec![5, 6],
        cursor_offset: 24.0,
        frame: [10.0, 20.0, 640.0, 480.0],
    }
}

#[test]
fn replace_even_empty_erases_closed_windows_and_take_is_once_only() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    db.replace_view_records(&[view(3), view(4)]).unwrap();
    db.replace_view_records(&[view(5)]).unwrap();
    assert_eq!(db.take_view_records().unwrap(), vec![view(5)]);
    assert!(db.take_view_records().unwrap().is_empty());
    db.replace_view_records(&[view(7)]).unwrap();
    db.replace_view_records(&[]).unwrap();
    assert!(db.take_view_records().unwrap().is_empty());
}

#[test]
fn file_reopens_and_unknown_version_is_ignored_and_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("views.sqlite");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.replace_view_records(&[view(3)]).unwrap();
    drop(db);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE view_records SET version=999", [])
        .unwrap();
    drop(conn);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert!(db.take_view_records().unwrap().is_empty());
    assert!(db.take_view_records().unwrap().is_empty());
}

#[test]
fn dropped_restart_guard_deletes_only_its_own_records() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    db.replace_view_records(&[view(3)]).unwrap();
    db.delete_view_records().unwrap();
    assert!(db.take_view_records().unwrap().is_empty());
}
