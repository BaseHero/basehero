//! Raw IPC bridge from editor sessions to the core's persistent NoteDoc.
use crate::error::CommandError;
use crate::notes::NoteOpened;
use crate::state::{AppState, Startup};
use bh_core::{AccountId, BaseId, ObjectId};
use serde::Deserialize;
use tauri::ipc::{Channel, InvokeBody, InvokeResponseBody, Request, Response};

#[derive(Deserialize)]
pub struct BaseRef {
    pub account: AccountId,
    pub base: BaseId,
}

pub fn open(
    state: &AppState,
    window: &str,
    r: BaseRef,
    note: ObjectId,
    sink: Box<dyn Fn(Vec<u8>) + Send + Sync>,
) -> Result<NoteOpened, CommandError> {
    let base = state.core.account(r.account)?.base(r.base)?;
    let opened = state.notes.open(window, r.account, &base, note, sink)?;
    // Sign-out may have closed this account's sessions while this one opened. The core
    // forgets the account first, so checking again here closes any such late session.
    if state.core.account(r.account).is_err() {
        state.notes.close(opened.session);
        return Err(bh_core::Error::NotFound.into());
    }
    Ok(opened)
}

pub fn apply(state: &AppState, session: u64, update: &[u8]) -> Result<(), CommandError> {
    state.notes.apply(session, update)
}

pub fn close(state: &AppState, session: u64) {
    state.notes.close(session);
}

pub fn encode_opened(opened: NoteOpened) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9 + opened.state.len());
    bytes.extend_from_slice(&opened.session.to_be_bytes());
    bytes.push(u8::from(opened.read_only));
    bytes.extend_from_slice(&opened.state);
    bytes
}

#[tauri::command]
pub fn note_open(
    startup: tauri::State<'_, Startup>,
    window: tauri::Window,
    r: BaseRef,
    note: ObjectId,
    channel: Channel<InvokeResponseBody>,
) -> Result<Response, CommandError> {
    let sink = Box::new(move |update| {
        let _ = channel.send(InvokeResponseBody::Raw(update));
    });
    let opened = open(startup.state()?, window.label(), r, note, sink)?;
    Ok(Response::new(encode_opened(opened)))
}

fn update_bytes(body: &InvokeBody) -> Result<Vec<u8>, CommandError> {
    match body {
        InvokeBody::Raw(bytes) => Ok(bytes.clone()),
        InvokeBody::Json(serde_json::Value::Array(values)) => values
            .iter()
            .map(|value| value.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(invalid_update_body),
        _ => Err(invalid_update_body()),
    }
}

fn invalid_update_body() -> CommandError {
    CommandError {
        kind: "Invalid".into(),
        message: "Expected raw note update or an array of bytes".into(),
    }
}

#[tauri::command]
pub fn note_apply(
    startup: tauri::State<'_, Startup>,
    request: Request<'_>,
) -> Result<(), CommandError> {
    let session = request
        .headers()
        .get("bh-session")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| CommandError {
            kind: "Invalid".into(),
            message: "Missing or invalid bh-session header".into(),
        })?;
    let update = update_bytes(request.body())?;
    apply(startup.state()?, session, &update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_android_json_bytes_and_desktop_raw_bytes() {
        assert_eq!(
            update_bytes(&InvokeBody::Json(json!([0, 127, 255]))).unwrap(),
            [0, 127, 255]
        );
        assert_eq!(
            update_bytes(&InvokeBody::Raw(vec![0, 255])).unwrap(),
            [0, 255]
        );
    }

    #[test]
    fn rejects_non_byte_arrays_and_other_json() {
        for value in [
            json!({"0": 1}),
            json!("bytes"),
            json!(null),
            json!([256]),
            json!([-1]),
            json!([1.5]),
            json!([true]),
            json!([1, "2"]),
        ] {
            assert_eq!(
                update_bytes(&InvokeBody::Json(value)).unwrap_err().kind,
                "Invalid"
            );
        }
    }
}

#[tauri::command]
pub fn note_close(startup: tauri::State<'_, Startup>, session: u64) -> Result<(), CommandError> {
    close(startup.state()?, session);
    Ok(())
}
