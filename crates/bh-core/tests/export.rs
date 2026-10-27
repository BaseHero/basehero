//! Exporting a base to Markdown, JSON and plain files.
use bh_core::{
    AppRequest, BaseGrantRequest, FieldDef, FieldKind, NewFile, NewObject, ObjectId, TypeDef,
    TypeRef,
};
use bh_testkit::{device, new_signup, wait_for_base};
use serde_json::{Map, Value, json};
use std::path::Path;
use yrs::updates::decoder::Decode;
use yrs::{
    Doc, ReadTxn, Transact, Update, WriteTxn, Xml, XmlElementPrelim, XmlFragment, XmlTextPrelim,
};

fn object(ty: &str, parent: Option<ObjectId>, fields: Map<String, Value>) -> NewObject {
    NewObject {
        ty: TypeRef::new(ty, 1),
        parent,
        after: None,
        fields,
    }
}

/// An update adding `blocks` to a note body held in `state`.
fn body(state: &[u8], blocks: &[(&str, &str)]) -> Vec<u8> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    if !state.is_empty() {
        txn.apply_update(Update::decode_v1(state).unwrap()).unwrap();
    }
    let before = txn.state_vector();
    let root = txn.get_or_insert_xml_fragment("default");
    for (node, text) in blocks {
        if text.is_empty() {
            root.push_back(&mut txn, XmlElementPrelim::empty(*node));
        } else {
            root.push_back(
                &mut txn,
                XmlElementPrelim::new(*node, [XmlTextPrelim::new(*text).into()]),
            );
        }
    }
    txn.encode_state_as_update_v1(&before)
}

/// An `image` block referring to `file`.
fn image_update(state: &[u8], file: ObjectId) -> Vec<u8> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    if !state.is_empty() {
        txn.apply_update(Update::decode_v1(state).unwrap()).unwrap();
    }
    let before = txn.state_vector();
    let root = txn.get_or_insert_xml_fragment("default");
    let node = root.push_back(&mut txn, XmlElementPrelim::empty("image"));
    node.insert_attribute(&mut txn, "file", file.to_string());
    txn.encode_state_as_update_v1(&before)
}

/// Every path under `dir`, sorted, with `/` separators.
fn listing(dir: &Path) -> Vec<String> {
    fn walk(at: &Path, root: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                out.push(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn out(dir: &Path) -> std::path::PathBuf {
    dir.join("BaseHero export")
}

#[tokio::test]
async fn export_writes_notes_records_and_files_readably() {
    let (account, _) = device("export").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    let trips = base
        .create(object(
            "core.folder",
            None,
            Map::from_iter([("name".into(), json!("Trips"))]),
        ))
        .unwrap();
    let kyoto = base
        .create(object("core.note", Some(trips), Map::new()))
        .unwrap();
    let photo = base
        .add_file(
            NewFile {
                parent: Some(kyoto),
                name: "photo.png".into(),
                mime: "image/png".into(),
            },
            b"\x89PNG photo bytes",
        )
        .unwrap();
    let pdf = base
        .add_file(
            NewFile {
                parent: Some(kyoto),
                name: "plan.pdf".into(),
                mime: "application/pdf".into(),
            },
            b"%PDF plan bytes",
        )
        .unwrap();
    let note = base.note(kyoto).unwrap();
    note.apply(5, &body(&[], &[("heading", "Kyoto")])).unwrap();
    note.apply(5, &image_update(&note.state(), photo)).unwrap();
    note.apply(
        5,
        &body(&note.state(), &[("paragraph", "Temples and tea.")]),
    )
    .unwrap();
    let japan = base
        .create(object(
            "core.project",
            None,
            Map::from_iter([("name".into(), json!("Japan"))]),
        ))
        .unwrap();
    base.note(japan)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "A month in Japan.")]))
        .unwrap();
    base.define_type(TypeDef {
        name: "demo.sleep".into(),
        version: 1,
        doc: "A night's sleep".into(),
        title_field: None,
        fields: vec![FieldDef {
            name: "hours".into(),
            kind: FieldKind::Number,
            required: true,
            unit: Some("h".into()),
            doc: String::new(),
        }],
    })
    .unwrap();
    let first = base
        .create(object(
            "demo.sleep",
            None,
            Map::from_iter([("hours".into(), json!(7.5))]),
        ))
        .unwrap();
    let second = base
        .create(object(
            "demo.sleep",
            None,
            Map::from_iter([("hours".into(), json!(6))]),
        ))
        .unwrap();
    base.flush().await.unwrap();
    wait_for_base(&base, || {
        base.file(photo)
            .unwrap()
            .is_some_and(|f| matches!(f.status, bh_core::FileStatus::Here))
    })
    .await;

    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    let summary = base.export(&out).await.unwrap();

    let mut expected = vec![
        "README.txt".to_string(),
        "manifest.json".into(),
        "notes/Japan.md".into(),
        "notes/Trips/Kyoto.md".into(),
        "notes/Trips/Kyoto/photo.png".into(),
        "notes/Trips/Kyoto/plan.pdf".into(),
        format!("records/demo.sleep/{first}.json"),
        format!("records/demo.sleep/{second}.json"),
        "types/demo.sleep.v1.json".into(),
    ];
    expected.sort();
    assert_eq!(listing(&out), expected);
    assert_eq!((summary.notes, summary.records, summary.files), (2, 2, 2));
    assert!(summary.missing_files.is_empty() && !summary.offline);
    assert_eq!(
        std::fs::read(out.join("notes/Trips/Kyoto/photo.png")).unwrap(),
        b"\x89PNG photo bytes"
    );
    assert_eq!(
        std::fs::read(out.join("notes/Trips/Kyoto/plan.pdf")).unwrap(),
        b"%PDF plan bytes"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("notes/Trips/Kyoto.md")).unwrap(),
        "# Kyoto\n\n![photo.png](Kyoto/photo.png)\n\nTemples and tea.\n"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("notes/Japan.md")).unwrap(),
        "A month in Japan.\n"
    );
    let record: Value = serde_json::from_slice(
        &std::fs::read(out.join(format!("records/demo.sleep/{first}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(record["id"], first.to_string());
    assert_eq!(record["type"], json!({"name": "demo.sleep", "version": 1}));
    assert_eq!(record["fields"]["hours"], json!(7.5));
    assert_eq!(record["deleted"], json!(false));
    let ty: Value =
        serde_json::from_slice(&std::fs::read(out.join("types/demo.sleep.v1.json")).unwrap())
            .unwrap();
    assert_eq!(ty["name"], "demo.sleep");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["format"], 1);
    assert_eq!(manifest["base"]["name"], "Travel");
    assert_eq!(manifest["missingFiles"], json!([]));
    let ids: Vec<&str> = manifest["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&pdf.to_string().as_str()) && ids.contains(&trips.to_string().as_str()));
    assert!(
        ids.contains(&base.id().to_string().as_str()),
        "the base's own object is included"
    );
    let type_object = base.get(first).unwrap().unwrap();
    assert_eq!(type_object.ty.name, "demo.sleep");
    assert!(
        manifest["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["type"] == "core.type" && o["path"] == "types/demo.sleep.v1.json")
    );
    assert!(
        std::fs::read_to_string(out.join("README.txt"))
            .unwrap()
            .contains("notes/")
    );
}

#[tokio::test]
async fn names_are_safe_unique_and_inside_dir() {
    let (account, _) = device("names").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    for title in ["a/b", "..", "CON", "Kyoto", "kyoto", ""] {
        let id = base.create(object("core.note", None, Map::new())).unwrap();
        base.note(id)
            .unwrap()
            .apply(5, &body(&[], &[("paragraph", title)]))
            .unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    base.export(&out).await.unwrap();
    assert_eq!(
        listing(&out),
        [
            "README.txt",
            "manifest.json",
            "notes/CON_.md",
            "notes/Kyoto.md",
            "notes/Untitled (2).md",
            "notes/Untitled.md",
            "notes/a-b.md",
            "notes/kyoto (2).md",
        ]
    );
    let root = std::fs::canonicalize(&out).unwrap();
    for name in listing(&out) {
        assert!(
            std::fs::canonicalize(out.join(&name))
                .unwrap()
                .starts_with(&root),
            "{name}"
        );
    }
}

#[tokio::test]
async fn dots_in_note_names_keep_the_whole_title() {
    let (account, _) = device("dots").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    let id = base.create(object("core.note", None, Map::new())).unwrap();
    base.note(id)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "Plan.v2")]))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    base.export(&out).await.unwrap();
    assert!(out.join("notes/Plan.v2.md").is_file());
    assert!(!out.join("notes/Plan.md").exists());
}

#[tokio::test]
async fn a_note_and_a_file_cannot_overwrite_each_other() {
    let (account, _) = device("collision").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    let id = base.create(object("core.note", None, Map::new())).unwrap();
    base.note(id)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "Plan")]))
        .unwrap();
    let file = base
        .add_file(
            NewFile {
                parent: None,
                name: "Plan.md".into(),
                mime: "text/plain".into(),
            },
            b"file contents",
        )
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    let summary = base.export(&out).await.unwrap();
    assert_eq!(summary.files, 1);
    assert_eq!(
        std::fs::read_to_string(out.join("notes/Plan.md")).unwrap(),
        "Plan\n"
    );
    assert_eq!(
        std::fs::read(out.join("notes/Plan.md (2)")).unwrap(),
        b"file contents"
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let row = manifest["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == file.to_string())
        .unwrap();
    assert_eq!(row["path"], "notes/Plan.md (2)");
}

#[tokio::test]
async fn deleted_items_go_to_trash() {
    let (account, _) = device("trash").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    let folder = base
        .create(object(
            "core.folder",
            None,
            Map::from_iter([("name".into(), json!("Old"))]),
        ))
        .unwrap();
    let note = base
        .create(object("core.note", Some(folder), Map::new()))
        .unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "Forget this")]))
        .unwrap();
    let kept = base.create(object("core.note", None, Map::new())).unwrap();
    base.note(kept)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "Keep this")]))
        .unwrap();
    base.delete(folder).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    base.export(&out).await.unwrap();
    assert_eq!(
        listing(&out),
        [
            "README.txt",
            "manifest.json",
            "notes/Keep this.md",
            "trash/Old/Forget this.md"
        ]
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let row = manifest["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == note.to_string())
        .unwrap();
    assert_eq!(row["deleted"], json!(true));
    assert_eq!(row["path"], "trash/Old/Forget this.md");
}

#[tokio::test]
async fn a_record_under_a_deleted_folder_is_in_trash() {
    let (account, _) = device("record-trash").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    base.define_type(TypeDef {
        name: "demo.sleep".into(),
        version: 1,
        doc: String::new(),
        title_field: None,
        fields: vec![FieldDef {
            name: "hours".into(),
            kind: FieldKind::Number,
            required: true,
            unit: None,
            doc: String::new(),
        }],
    })
    .unwrap();
    let folder = base
        .create(object(
            "core.folder",
            None,
            Map::from_iter([("name".into(), json!("Old"))]),
        ))
        .unwrap();
    let record = base
        .create(object(
            "demo.sleep",
            Some(folder),
            Map::from_iter([("hours".into(), json!(7.5))]),
        ))
        .unwrap();
    base.delete(folder).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    base.export(&out).await.unwrap();
    let path = format!("trash/records/demo.sleep/{record}.json");
    assert!(out.join(&path).is_file());
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let row = manifest["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["id"] == record.to_string())
        .unwrap();
    assert_eq!(row["path"], path);
    assert_eq!(row["deleted"], true);
}

#[tokio::test]
async fn export_refuses_a_non_empty_directory() {
    let (account, _) = device("nonempty").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    for kept in ["keep", ".hidden"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(kept), b"safe").unwrap();
        assert!(matches!(
            base.export(dir.path()).await,
            Err(bh_core::Error::Invalid(_))
        ));
        assert_eq!(std::fs::read(dir.path().join(kept)).unwrap(), b"safe");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn an_app_device_exports_files_it_had_not_fetched() {
    let full = device("writer").sign_up(new_signup()).await.unwrap().0;
    let base = full.create_base("Shared").await.unwrap();
    let note = base.create(object("core.note", None, Map::new())).unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "With a file")]))
        .unwrap();
    let file = base
        .add_file(
            NewFile {
                parent: Some(note),
                name: "notes.txt".into(),
                mime: "text/plain".into(),
            },
            b"plain text",
        )
        .unwrap();
    base.flush().await.unwrap();
    wait_for_base(&base, || {
        base.file(file)
            .unwrap()
            .is_some_and(|f| matches!(f.status, bh_core::FileStatus::Here))
    })
    .await;
    let credentials = full
        .connect_app(AppRequest {
            app_name: "Reader".into(),
            app_id: Some("dev:export".into()),
            bases: vec![BaseGrantRequest::Existing {
                base: base.id(),
                mode: bh_core::Mode::ReadOnly,
            }],
            replaces: None,
        })
        .await
        .unwrap();
    let app = device("reader").install_app(credentials).await.unwrap();
    app.refresh().await.unwrap();
    let remote = app.base(base.id()).unwrap();
    wait_for_base(&remote, || {
        remote
            .file(file)
            .unwrap()
            .is_some_and(|f| matches!(f.status, bh_core::FileStatus::Remote))
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    let summary = remote.export(&out).await.unwrap();
    assert_eq!(summary.files, 1);
    assert_eq!(
        std::fs::read(out.join("notes/With a file/notes.txt")).unwrap(),
        b"plain text"
    );
    assert_eq!(
        remote.file(file).unwrap().unwrap().status,
        bh_core::FileStatus::Here
    );
}

#[tokio::test]
async fn a_missing_file_is_reported_and_the_rest_written() {
    let (a, b) = bh_testkit::two_devices_sharing_a_base().await;
    a.base.pause_files();
    let note = a
        .base
        .create(object("core.note", None, Map::new()))
        .unwrap();
    a.base
        .note(note)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "Waiting")]))
        .unwrap();
    let waiting = a
        .base
        .add_file(
            NewFile {
                parent: Some(note),
                name: "later.txt".into(),
                mime: "text/plain".into(),
            },
            b"not yet",
        )
        .unwrap();
    a.base.flush().await.unwrap();
    wait_for_base(&b.base, || b.base.file(waiting).unwrap().is_some()).await;
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    let summary = b.base.export(&out).await.unwrap();
    assert_eq!(summary.missing_files, vec![waiting]);
    assert_eq!(summary.notes, 1);
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["missingFiles"], json!([waiting.to_string()]));
    assert_eq!(
        std::fs::read_to_string(out.join("notes/Waiting.md")).unwrap(),
        "Waiting\n"
    );
    assert!(!out.join("notes/Waiting/later.txt").exists());
    a.base.resume_files();
}

#[tokio::test]
async fn an_offline_export_uses_the_local_copy() {
    let (account, _) = device("offline").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    let note = base.create(object("core.note", None, Map::new())).unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "Offline text")]))
        .unwrap();
    base.test_pause_sync();
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    let summary = base.export(&out).await.unwrap();
    assert!(summary.offline);
    assert_eq!(
        std::fs::read_to_string(out.join("notes/Offline text.md")).unwrap(),
        "Offline text\n"
    );
    base.test_resume_sync();
}

#[cfg(unix)]
#[tokio::test]
async fn an_export_path_through_a_symlink_is_resolved_and_used() {
    // The Mac's /tmp is a symlink; a path the person chose through one is fine.
    let (account, _) = device("symlink-parent")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = account.create_base("Travel").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.path().join("alias")).unwrap();
    base.export(&dir.path().join("alias/export")).await.unwrap();
    assert!(elsewhere.join("export/README.txt").exists());
}

#[tokio::test]
async fn a_failed_export_leaves_no_partial_copy() {
    let (account, _) = device("partial").sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Travel").await.unwrap();
    let note = base.create(object("core.note", None, Map::new())).unwrap();
    base.note(note)
        .unwrap()
        .apply(5, &body(&[], &[("paragraph", "Text")]))
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = out(dir.path());
    std::fs::create_dir(&out).unwrap();
    // A symlink inside the target must stop the write rather than be followed.
    #[cfg(unix)]
    {
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join("notes")).unwrap();
        let result = base.export(&out).await;
        assert!(
            matches!(result, Err(bh_core::Error::Invalid(_))),
            "{result:?}"
        );
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
        assert!(!out.join("README.txt").exists() && !out.join("manifest.json").exists());
    }
}
