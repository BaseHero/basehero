//! A readable, plaintext copy of one base.

use crate::base::Base;
use crate::markdown;
use crate::objects::ObjectSummary;
use crate::types::{BASE, FILE, FOLDER, NOTE, PROJECT, TYPE};
use crate::{Error, ObjectId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use ts_rs::TS;
use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, Transact, Update};

/// Counts of the objects copied, and files that could not be read.
#[derive(Clone, Debug, Default, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct ExportSummary {
    /// Markdown documents written.
    pub notes: usize,
    /// JSON records written.
    pub records: usize,
    /// Plain files written.
    pub files: usize,
    /// File object IDs whose content was unavailable or failed authentication.
    #[ts(type = "Array<string>")]
    pub missing_files: Vec<ObjectId>,
    /// True when the server could not be reached and the local copy was used.
    pub offline: bool,
}

const README: &str = "This folder is a readable copy of your BaseHero base.\n\nnotes/ contains notes as Markdown and their attached files in folders beside them.\nrecords/ contains other records as JSON, grouped by type.\ntypes/ contains the definitions of those record types.\ntrash/ contains deleted notes, records and files in the same layout.\nmanifest.json lists every item, its original ID and path, and any files that could not be copied.\n\nThis copy is not encrypted. Keep it somewhere you trust.\n";

fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "/\\:*?\"<>|".contains(c) {
                '-'
            } else {
                c
            }
        })
        .collect();
    let mut result: String = cleaned.trim_matches([' ', '.']).chars().take(100).collect();
    if result.is_empty() {
        result = "Untitled".into();
    }
    let stem = result.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        result.push('_');
    }
    result
}

fn unique(name: &str, used: &mut HashSet<String>) -> String {
    let original = safe_name(name);
    let mut result = original.clone();
    let mut n = 2;
    while !used.insert(result.to_lowercase()) {
        let suffix = format!(" ({n})");
        result = format!(
            "{}{}",
            original
                .chars()
                .take(100 - suffix.len())
                .collect::<String>()
                .trim_end_matches([' ', '.']),
            suffix
        );
        n += 1;
    }
    result
}

struct Writer {
    root: PathBuf,
    created: Vec<PathBuf>,
}

impl Writer {
    fn checked(&self, relative: &Path) -> Result<PathBuf, Error> {
        if !relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        {
            return Err(Error::invalid("unsafe export path"));
        }
        let mut at = self.root.clone();
        for part in relative.components() {
            at.push(part.as_os_str());
            if let Ok(meta) = fs::symlink_metadata(&at)
                && meta.file_type().is_symlink()
            {
                return Err(Error::invalid("symlink in export directory"));
            }
        }
        if !at.starts_with(&self.root) {
            return Err(Error::invalid("unsafe export path"));
        }
        Ok(at)
    }

    fn directory(&mut self, relative: &Path) -> Result<(), Error> {
        let mut path = PathBuf::new();
        for part in relative.components() {
            path.push(part.as_os_str());
            let full = self.checked(&path)?;
            if !full.exists() {
                fs::create_dir(&full)?;
                self.created.push(full);
            } else if !full.is_dir() {
                return Err(Error::invalid("export path is not a directory"));
            }
        }
        Ok(())
    }

    fn write(&mut self, relative: &Path, bytes: &[u8]) -> Result<(), Error> {
        if let Some(parent) = relative.parent() {
            self.directory(parent)?;
        }
        let full = self.checked(relative)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&full)?;
        self.created.push(full);
        file.write_all(bytes)?;
        Ok(())
    }

    fn rollback(&mut self) {
        for path in self.created.drain(..).rev() {
            if path.is_dir() {
                let _ = fs::remove_dir(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

fn trashed(row: &ObjectSummary, nodes: &HashMap<ObjectId, &ObjectSummary>) -> bool {
    let mut seen = HashSet::new();
    let mut current = Some(row.id);
    while let Some(id) = current
        && seen.insert(id)
    {
        let Some(node) = nodes.get(&id) else { break };
        if node.deleted {
            return true;
        }
        current = node.parent;
    }
    false
}

fn tree_paths(objects: &[ObjectSummary]) -> HashMap<ObjectId, PathBuf> {
    let nodes: HashMap<_, _> = objects.iter().map(|s| (s.id, s)).collect();
    let mut siblings: HashMap<(Option<ObjectId>, bool), HashSet<String>> = HashMap::new();
    let mut paths = HashMap::new();
    // Parents precede children irrespective of their object ID or update time.
    let mut remaining: Vec<_> = objects
        .iter()
        .filter(|s| matches!(s.ty.name.as_str(), NOTE | FOLDER | PROJECT | FILE))
        .collect();
    while !remaining.is_empty() {
        let before = remaining.len();
        let mut later = Vec::new();
        for row in remaining {
            let parent = row.parent.filter(|p| {
                nodes
                    .get(p)
                    .is_some_and(|r| matches!(r.ty.name.as_str(), NOTE | FOLDER | PROJECT | FILE))
            });
            if parent.is_some_and(|p| !paths.contains_key(&p)) {
                later.push(row);
                continue;
            }
            let trashed = trashed(row, &nodes);
            let root = if trashed {
                PathBuf::from("trash")
            } else {
                PathBuf::from("notes")
            };
            let prefix = parent.and_then(|p| paths.get(&p).cloned()).unwrap_or(root);
            let name = if row.ty.name == NOTE {
                &row.title
            } else {
                row.fields
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(&row.title)
            };
            let used = siblings.entry((parent, trashed)).or_default();
            let original = safe_name(name);
            let mut candidate = original.clone();
            let mut n = 2;
            let document = row.ty.name != FILE;
            while used.contains(&candidate.to_lowercase())
                || (document && used.contains(&format!("{candidate}.md").to_lowercase()))
            {
                let suffix = format!(" ({n})");
                candidate = format!(
                    "{}{}",
                    original
                        .chars()
                        .take(100 - suffix.len())
                        .collect::<String>()
                        .trim_end_matches([' ', '.']),
                    suffix
                );
                n += 1;
            }
            used.insert(candidate.to_lowercase());
            if document {
                used.insert(format!("{candidate}.md").to_lowercase());
            }
            paths.insert(row.id, prefix.join(candidate));
        }
        if later.len() == before {
            // A damaged or cyclic parent relation: place the lowest ID at the root.
            let first = later.remove(0);
            let root = if trashed(first, &nodes) {
                "trash"
            } else {
                "notes"
            };
            let candidate = unique(
                &first.title,
                siblings.entry((None, first.deleted)).or_default(),
            );
            paths.insert(first.id, PathBuf::from(root).join(candidate));
        }
        remaining = later;
    }
    paths
}

fn markdown_path(stem: &Path) -> PathBuf {
    let mut path = stem.as_os_str().to_os_string();
    path.push(".md");
    PathBuf::from(path)
}

fn relative_link(from: &Path, to: &Path) -> String {
    let a: Vec<_> = from
        .parent()
        .unwrap_or(Path::new(""))
        .components()
        .collect();
    let b: Vec<_> = to.components().collect();
    let shared = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut path = PathBuf::new();
    for _ in shared..a.len() {
        path.push("..");
    }
    for part in &b[shared..] {
        path.push(part.as_os_str());
    }
    path.to_string_lossy().into_owned()
}

pub(crate) async fn run(base: &Base, dir: &Path) -> Result<ExportSummary, Error> {
    // DIR is the person's own choice, so a path through symlinks or `..` (as
    // /tmp is on the Mac) is resolved once, not refused. What's checked is that
    // the export never follows a symlink out of the resolved DIR.
    if let Ok(meta) = fs::metadata(dir)
        && (!meta.is_dir() || fs::read_dir(dir)?.next().is_some())
    {
        return Err(Error::invalid("export directory must be empty"));
    }
    let offline = match base.sync_now().await {
        Ok(()) => false,
        Err(Error::Network(_)) => true,
        Err(e) => return Err(e),
    };
    let existed = dir.exists();
    if !existed {
        fs::create_dir_all(dir)?;
    }
    let mut writer = Writer {
        root: fs::canonicalize(dir)?,
        created: Vec::new(),
    };
    let result = write_export(base, &mut writer, offline).await;
    if result.is_err() {
        writer.rollback();
        if !existed {
            let _ = fs::remove_dir(dir);
        }
    }
    result
}

async fn write_export(
    base: &Base,
    writer: &mut Writer,
    offline: bool,
) -> Result<ExportSummary, Error> {
    let mut summary = ExportSummary {
        offline,
        ..Default::default()
    };
    let objects = base.export_objects()?;
    let paths = tree_paths(&objects);
    let nodes: HashMap<_, _> = objects.iter().map(|o| (o.id, o)).collect();
    let mut listed = Vec::new();
    writer.write(Path::new("README.txt"), README.as_bytes())?;
    for row in &objects {
        if row.ty.name == BASE {
            listed.push(json!({"id": row.id, "type": row.ty.name, "version": row.ty.version, "path": "manifest.json", "deleted": row.deleted}));
            continue;
        }
        if row.ty.name == TYPE {
            if let Some(def) = row.fields.get("def")
                && let (Some(name), Some(version)) = (
                    def.get("name").and_then(Value::as_str),
                    def.get("version").and_then(Value::as_u64),
                )
            {
                listed.push(json!({"id": row.id, "type": row.ty.name, "version": row.ty.version, "path": format!("types/{}.v{version}.json", safe_name(name)), "deleted": row.deleted}));
            }
            continue;
        }
        let (mut path, deleted) = if let Some(tree) = paths.get(&row.id) {
            (tree.clone(), tree.starts_with("trash"))
        } else {
            let folder = if trashed(row, &nodes) {
                "trash/records"
            } else {
                "records"
            };
            (
                PathBuf::from(folder)
                    .join(safe_name(&row.ty.name))
                    .join(format!("{}.json", row.id)),
                trashed(row, &nodes),
            )
        };
        match row.ty.name.as_str() {
            NOTE | FOLDER | PROJECT => {
                let state = base.note(row.id)?.state();
                let doc = Doc::new();
                if !state.is_empty() {
                    let mut txn = doc.transact_mut();
                    txn.apply_update(
                        Update::decode_v1(&state)
                            .map_err(|_| Error::invalid("invalid note state"))?,
                    )
                    .map_err(|_| Error::invalid("invalid note state"))?;
                }
                let txn = doc.transact();
                let mut md = String::new();
                if let Some(body) = txn.get_xml_fragment("default") {
                    let note_path = markdown_path(&path);
                    md = markdown::to_markdown(
                        &body,
                        &txn,
                        &|id| {
                            paths
                                .get(&id)
                                .map(|p| relative_link(&note_path, &markdown_path(p)))
                        },
                        &|id| {
                            paths.get(&id).and_then(|p| {
                                objects.iter().find(|o| o.id == id).map(|o| {
                                    (
                                        o.fields
                                            .get("name")
                                            .and_then(Value::as_str)
                                            .unwrap_or(&o.title)
                                            .to_owned(),
                                        relative_link(&note_path, p),
                                    )
                                })
                            })
                        },
                    );
                }
                let children = objects
                    .iter()
                    .any(|other| other.parent == Some(row.id) && paths.contains_key(&other.id));
                if children {
                    writer.directory(&path)?;
                }
                if row.ty.name == NOTE || !md.is_empty() {
                    path = markdown_path(&path);
                    writer.write(&path, md.as_bytes())?;
                    summary.notes += 1;
                }
            }
            FILE => match base.file_bytes(row.id).await {
                Ok(bytes) => {
                    writer.write(&path, &bytes)?;
                    summary.files += 1;
                }
                Err(Error::NotFound | Error::Crypto | Error::Network(_)) => {
                    summary.missing_files.push(row.id)
                }
                Err(e) => return Err(e),
            },
            _ => {
                let record = json!({"id": row.id, "type": row.ty, "parent": row.parent, "deleted": deleted, "updatedAt": row.updated_at, "fields": row.fields});
                writer.write(
                    &path,
                    &serde_json::to_vec_pretty(&record)
                        .map_err(|_| Error::invalid("invalid record JSON"))?,
                )?;
                summary.records += 1;
            }
        }
        listed.push(json!({"id": row.id, "type": row.ty.name, "version": row.ty.version, "path": path.to_string_lossy(), "deleted": deleted}));
    }
    for def in base.types()? {
        let path =
            PathBuf::from("types").join(format!("{}.v{}.json", safe_name(&def.name), def.version));
        writer.write(
            &path,
            &serde_json::to_vec_pretty(&def).map_err(|_| Error::invalid("invalid type JSON"))?,
        )?;
    }
    let exported_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let manifest = json!({"format": 1, "exportedAt": exported_at, "base": {"id": base.id(), "name": base.name()}, "objects": listed, "missingFiles": summary.missing_files});
    writer.write(
        Path::new("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)
            .map_err(|_| Error::invalid("invalid manifest JSON"))?,
    )?;
    Ok(summary)
}
