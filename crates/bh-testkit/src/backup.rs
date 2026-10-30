//! Rich local backup fixture and stable comparison of readable exports.

use bh_core::{
    Account, AppRequest, Base, BaseGrantRequest, Core, FieldDef, FieldKind, Mode, NewFile,
    NewObject, ObjectId, RecoveryKit, TypeDef, TypeRef,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::LocalServer;

/// A full account with connected, hidden, attached and ordinary content.
pub struct Fixture {
    /// The full device's signed-in account.
    pub account: Account,
    /// The account's original recovery kit.
    pub kit: RecoveryKit,
    /// Password of the hidden base.
    pub extra_password: String,
    /// Hidden base containing a note.
    pub hidden: Base,
    /// Base that appears under an ordinary folder.
    pub mounted: Base,
    /// Ordinary note with an attached image.
    pub note: ObjectId,
    /// PNG file in the note.
    pub image: ObjectId,
    /// Three-part file.
    pub big_file: ObjectId,
}

fn object(ty: &str, parent: Option<ObjectId>, fields: Value) -> NewObject {
    NewObject {
        ty: TypeRef::new(ty, 1),
        parent,
        after: None,
        fields: fields.as_object().cloned().unwrap_or_else(Map::new),
    }
}

/// Builds a representative full account without making a model call.
pub async fn everything(core: &Core) -> Fixture {
    everything_on(core, None).await
}

/// Builds the same fixture against a private local server.
pub async fn everything_on_server(core: &Core, server: &LocalServer) -> Fixture {
    everything_on(core, Some(server)).await
}

async fn everything_on(core: &Core, server: Option<&LocalServer>) -> Fixture {
    let signup = if let Some(server) = server {
        bh_core::SignUp {
            server: server.url(),
            invite: crate::invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: crate::TEST_PASSWORD.to_string().into(),
            device_name: String::new(),
        }
    } else {
        crate::new_signup()
    };
    let (account, kit) = core.sign_up(signup).await.unwrap();
    let personal = account.create_base("Personal").await.unwrap();
    let folder = personal
        .create(object(
            "core.folder",
            None,
            json!({"name": "Shared folder"}),
        ))
        .unwrap();
    let note = crate::note_with_text(&personal, "Trip notes");
    let image = personal
        .add_file(
            NewFile {
                parent: Some(note),
                name: "photo.png".into(),
                mime: "image/png".into(),
            },
            b"\x89PNG\r\n\x1a\nfixture image",
        )
        .unwrap();
    let big_file = personal
        .add_file(
            NewFile {
                parent: Some(note),
                name: "nine-megabytes.bin".into(),
                mime: "application/octet-stream".into(),
            },
            &vec![42; 9 * 1024 * 1024],
        )
        .unwrap();
    personal
        .define_type(TypeDef {
            name: "demo.measurement".into(),
            version: 1,
            doc: "A measurement".into(),
            title_field: None,
            fields: vec![FieldDef {
                name: "reading".into(),
                kind: FieldKind::Number,
                required: true,
                unit: None,
                doc: String::new(),
            }],
        })
        .unwrap();
    personal
        .create(object("demo.measurement", None, json!({"reading": 6.5})))
        .unwrap();
    let trashed = crate::note_with_text(&personal, "Old note");
    personal.delete(trashed).unwrap();
    account.hero().new_chat(personal.id()).unwrap();
    let credentials = account
        .connect_app(AppRequest {
            app_name: "Folder app".into(),
            app_id: Some("dev:backup-folder".into()),
            replaces: None,
            bases: vec![BaseGrantRequest::Folder {
                base: personal.id(),
                folder,
                mode: Mode::ReadWrite,
            }],
        })
        .await
        .unwrap();
    let app = server.map_or_else(
        || crate::device("folder app"),
        |server| crate::device_on_server("folder app", &bh_core::Clock::system(), server),
    );
    let _app = app.install_app(credentials).await.unwrap();
    let mount = account
        .mounts()
        .into_iter()
        .find(|m| m.parent == personal.id() && m.folder == folder)
        .unwrap();
    let mounted = account.base(mount.base).unwrap();
    crate::note_with_text(&mounted, "Mounted note");
    let extra_password = "ferry lantern quartz".to_string();
    let hidden = account
        .create_hidden_base("Diary", Zeroizing::new(extra_password.clone()))
        .await
        .unwrap();
    crate::note_with_text(&hidden, "Hidden note");
    Fixture {
        account,
        kit,
        extra_password,
        hidden,
        mounted,
        note,
        image,
        big_file,
    }
}

/// Reads exported files, omitting export/save timestamps. With `drop_base`,
/// also omits the base identity and key-derived base/type object IDs from the
/// manifest, while comparing the exported type definitions themselves.
pub fn normalized_export(dir: &Path, drop_base: bool) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(dir: &Path, at: &Path, drop_base: bool, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(dir, &path, drop_base, files);
                continue;
            }
            let relative = path.strip_prefix(dir).unwrap().to_path_buf();
            let mut bytes = std::fs::read(&path).unwrap();
            if relative == Path::new("manifest.json") {
                let mut value: Value = serde_json::from_slice(&bytes).unwrap();
                value.as_object_mut().unwrap().remove("exportedAt");
                if drop_base {
                    value.as_object_mut().unwrap().remove("base");
                    // Base and type-definition object IDs derive from the base's
                    // key; the exported type definitions themselves are compared.
                    let objects = value["objects"].as_array_mut().unwrap();
                    objects.retain(|object| {
                        !matches!(object["type"].as_str(), Some("core.base" | "core.type"))
                    });
                    objects.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
                }
                bytes = serde_json::to_vec(&value).unwrap();
            } else if (relative.starts_with("records") || relative.starts_with("trash/records"))
                && relative.extension().is_some_and(|e| e == "json")
            {
                let mut value: Value = serde_json::from_slice(&bytes).unwrap();
                value.as_object_mut().unwrap().remove("updatedAt");
                bytes = serde_json::to_vec(&value).unwrap();
            }
            files.insert(relative, bytes);
        }
    }
    let mut files = BTreeMap::new();
    collect(dir, dir, drop_base, &mut files);
    files
}
