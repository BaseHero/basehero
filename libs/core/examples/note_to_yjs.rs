// Test-only cross-language fixture runner: stdout is the raw Yjs v1 update.
use bh_core::note::Note;
use std::io::Write;
fn main() {
    let mut note = Note::new().unwrap();
    note.apply_update(include_bytes!("../../../apps/client/editor/test/rich.bin"))
        .expect("rich fixture update");
    note.append_paragraph("from Rust core").unwrap();
    std::io::stdout()
        .write_all(&note.state().unwrap())
        .expect("fixture stdout");
}
