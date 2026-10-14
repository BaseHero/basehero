fn main() {
    // App-defined commands otherwise bypass the per-command ACL entirely.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "note_binding",
            "note_open",
            "note_commit",
            "note_close",
        ]),
    ))
    .expect("Tauri client build failed");
}
