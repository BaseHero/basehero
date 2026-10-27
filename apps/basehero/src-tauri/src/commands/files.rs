//! Files cross the shell as raw bytes; only sniffed raster content may return to the WebView.
use crate::error::CommandError;
use crate::state::AppState;
use crate::views::BaseRef;
use bh_core::{BaseId, FileInfo, Image, NewFile, ObjectId};
use std::path::{Path, PathBuf};

pub fn file_add(
    state: &AppState,
    r: &BaseRef,
    parent: Option<ObjectId>,
    name: &str,
    mime: &str,
    bytes: &[u8],
) -> Result<FileInfo, CommandError> {
    let base = state.base(r)?;
    let id = base.add_file(
        NewFile {
            parent,
            name: name.into(),
            mime: mime.into(),
        },
        bytes,
    )?;
    Ok(base.file(id)?.ok_or(bh_core::Error::NotFound)?)
}

pub fn files(
    state: &AppState,
    r: &BaseRef,
    parent: Option<ObjectId>,
) -> Result<Vec<FileInfo>, CommandError> {
    let base = state.base(r)?;
    base.children(parent)?
        .into_iter()
        .filter(|child| child.ty.name == "core.file" && !child.deleted)
        .map(|child| {
            base.file(child.id)
                .map_err(Into::into)
                .and_then(|file| file.ok_or(bh_core::Error::NotFound.into()))
        })
        .collect()
}

pub fn file_info(
    state: &AppState,
    r: &BaseRef,
    id: ObjectId,
) -> Result<Option<FileInfo>, CommandError> {
    Ok(state.base(r)?.file(id)?)
}

pub async fn file_image(
    state: &AppState,
    r: &BaseRef,
    id: ObjectId,
) -> Result<Image, CommandError> {
    Ok(state.base(r)?.image(id).await?)
}

fn storage(error: std::io::Error) -> CommandError {
    CommandError {
        kind: "Storage".into(),
        message: error.to_string(),
    }
}

/// Remove plaintext left by a previous run. Does not follow a symlink at `open`.
pub fn clear_open_copies(cache: &Path) -> Result<(), CommandError> {
    remove_tree(&cache.join("open"))
}

/// Remove only this base's temporary copies before its cached handle is dropped.
pub fn clear_open_copies_for_base(cache: &Path, base: BaseId) -> Result<(), CommandError> {
    remove_tree(&cache.join("open").join(base.to_string()))
}

fn remove_tree(path: &Path) -> Result<(), CommandError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path).map_err(storage),
        Ok(_) => std::fs::remove_file(path).map_err(storage),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(storage(e)),
    }
}

fn safe_name(name: &str) -> String {
    let name = name.rsplit(['/', '\\']).next().unwrap_or("");
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let name = name.trim_matches([' ', '.']);
    if name.is_empty() {
        "file".into()
    } else {
        name.into()
    }
}

/// Materialize one plain copy for the system viewer, never for a WebView URL.
pub async fn open_copy(
    state: &AppState,
    r: &BaseRef,
    id: ObjectId,
) -> Result<PathBuf, CommandError> {
    let base = state.base(r)?;
    let info = base.file(id)?.ok_or(bh_core::Error::NotFound)?;
    let root = state.cache_dir.join("open");
    std::fs::create_dir_all(&root).map_err(storage)?;
    let cache = state.cache_dir.canonicalize().map_err(storage)?;
    if root.canonicalize().map_err(storage)? != cache.join("open") {
        return Err(bh_core::Error::Invalid("unsafe open path".into()).into());
    }
    let directory = root.join(r.base.to_string()).join(id.to_string());
    std::fs::create_dir_all(&directory).map_err(storage)?;
    let directory = directory.canonicalize().map_err(storage)?;
    let expected_base = cache
        .join("open")
        .join(r.base.to_string())
        .join(id.to_string());
    if directory != expected_base {
        return Err(bh_core::Error::Invalid("unsafe open path".into()).into());
    }
    let path = directory.join(safe_name(&info.name));
    if path.parent() != Some(directory.as_path()) || path.file_name().is_none() {
        return Err(bh_core::Error::Invalid("unsafe file name".into()).into());
    }
    base.save_file(id, &path).await?;
    Ok(path)
}

pub mod ipc {
    use super::*;
    use crate::state::Startup;
    use tauri::ipc::{InvokeBody, Request, Response};

    fn invalid(message: &str) -> CommandError {
        CommandError {
            kind: "Invalid".into(),
            message: message.into(),
        }
    }
    fn header(request: &Request<'_>, name: &str) -> Result<String, CommandError> {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| invalid("Missing file header"))
    }

    // Async, so encrypting a large file doesn't freeze the window.
    #[tauri::command(async)]
    pub fn file_add(
        startup: tauri::State<'_, Startup>,
        request: Request<'_>,
    ) -> Result<FileInfo, CommandError> {
        let account = header(&request, "bh-account")?
            .parse()
            .map_err(|_| invalid("Invalid account"))?;
        let base = header(&request, "bh-base")?
            .parse()
            .map_err(|_| invalid("Invalid base"))?;
        let parent = header(&request, "bh-parent")?;
        let parent = if parent.is_empty() {
            None
        } else {
            Some(parent.parse().map_err(|_| invalid("Invalid parent"))?)
        };
        let name = percent_encoding::percent_decode_str(&header(&request, "bh-name")?)
            .decode_utf8()
            .map_err(|_| invalid("Invalid file name"))?
            .into_owned();
        let mime = header(&request, "bh-mime")?;
        let InvokeBody::Raw(bytes) = request.body() else {
            return Err(invalid("Expected raw file bytes"));
        };
        super::file_add(
            startup.state()?,
            &BaseRef { account, base },
            parent,
            &name,
            &mime,
            bytes,
        )
    }

    #[tauri::command]
    pub fn files(
        startup: tauri::State<'_, Startup>,
        r: BaseRef,
        parent: Option<ObjectId>,
    ) -> Result<Vec<FileInfo>, CommandError> {
        super::files(startup.state()?, &r, parent)
    }
    #[tauri::command]
    pub fn file_info(
        startup: tauri::State<'_, Startup>,
        r: BaseRef,
        id: ObjectId,
    ) -> Result<Option<FileInfo>, CommandError> {
        super::file_info(startup.state()?, &r, id)
    }
    #[tauri::command]
    pub async fn file_image(
        startup: tauri::State<'_, Startup>,
        r: BaseRef,
        id: ObjectId,
    ) -> Result<Response, CommandError> {
        let image = super::file_image(startup.state()?, &r, id).await?;
        let mut raw = Vec::with_capacity(1 + image.mime.len() + image.bytes.len());
        raw.push(u8::try_from(image.mime.len()).map_err(|_| invalid("Invalid image type"))?);
        raw.extend_from_slice(image.mime.as_bytes());
        raw.extend(image.bytes);
        Ok(Response::new(raw))
    }
    #[tauri::command]
    pub async fn file_open(
        app: tauri::AppHandle,
        startup: tauri::State<'_, Startup>,
        r: BaseRef,
        id: ObjectId,
    ) -> Result<(), CommandError> {
        #[cfg(target_os = "android")]
        {
            let _ = (app, startup, r, id);
            // Android needs a FileProvider; opener paths cannot grant an external viewer access.
            Err(invalid("not on Android yet"))
        }
        #[cfg(not(target_os = "android"))]
        {
            use tauri_plugin_opener::OpenerExt;
            let path = super::open_copy(startup.state()?, &r, id).await?;
            app.opener()
                .open_path(path.to_string_lossy().into_owned(), None::<&str>)
                .map_err(|e| CommandError {
                    kind: "Storage".into(),
                    message: e.to_string(),
                })
        }
    }
}
