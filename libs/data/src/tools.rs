//! JSON adapter over the production session. Tool arguments never supply an
//! actor; supplied read scopes are checked against verified host authority.
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    MutationId, RecordId, RejectCode, Rejection, Scope, TypeId,
    mutation::{history::HistoryCursor, ops::Operation, pending::LocalSaved},
    query::{Aggregate, Query, QueryError},
    session::{Authority, DataSession, SessionError, Store, TypeRef},
};

fn ok(value: impl Serialize) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => json!({"ok": value}),
        Err(error) => failure("Storage", error.to_string()),
    }
}
fn failure(code: &str, detail: impl ToString) -> Value {
    json!({"error": {"code": code, "detail": detail.to_string()}})
}
fn rejected(rejection: Rejection) -> Value {
    let code = match rejection.code {
        RejectCode::Schema => "Schema",
        RejectCode::UnknownField => "UnknownField",
        RejectCode::DerivedField => "DerivedField",
        RejectCode::ActionOnly => "ActionOnly",
        RejectCode::Overlap => "Overlap",
        RejectCode::Unique => "Unique",
        RejectCode::RevisionNotPermitted => "RevisionNotPermitted",
        RejectCode::DeviceOnly => "DeviceOnly",
        RejectCode::AppInactive => "AppInactive",
        RejectCode::ReservedType => "ReservedType",
        RejectCode::ConcreteTypeChange => "ConcreteTypeChange",
        RejectCode::TooLarge => "TooLarge",
        RejectCode::NotFound => "NotFound",
        RejectCode::Deleted => "Deleted",
        RejectCode::NothingToUndo => "NothingToUndo",
        RejectCode::Exists => "Exists",
        RejectCode::NeedsCoreTransition => "NeedsCoreTransition",
        RejectCode::Unauthorized => "Unauthorized",
    };
    json!({"error": {"code": code, "detail": rejection.detail, "path": rejection.path}})
}
fn session_error(error: SessionError) -> Value {
    match error {
        SessionError::ConfirmationRequired(proposal) => {
            json!({"proposal": proposal, "status":"confirmation_required"})
        }
        SessionError::Rejected(rejection) => rejected(rejection),
        SessionError::Data(data) => failure(&data_code(&data), data),
    }
}
fn query_error(err: QueryError) -> Value {
    let code = match &err {
        QueryError::UnknownType => "UnknownType",
        QueryError::UnknownField(_) => "UnknownField",
        QueryError::TypeMismatch(_) => "TypeMismatch",
        QueryError::NotQueryable { .. } => "NotQueryable",
        QueryError::TooCostly { .. } => "TooCostly",
        QueryError::IndexBuilding { .. } => "IndexBuilding",
        QueryError::TextBehind { .. } => "TextBehind",
        QueryError::Storage(_) => "Storage",
        QueryError::Unauthorized => "Unauthorized",
    };
    failure(code, format!("{err:?}"))
}
fn saved(saved: LocalSaved) -> Value {
    ok(
        json!({"mutation": saved.mutation, "payload": saved.payload, "content_rev": saved.content_rev, "skipped": saved.skipped}),
    )
}
fn parse<T: DeserializeOwned>(args: Value) -> Result<T, Value> {
    serde_json::from_value(args).map_err(|e| failure("InvalidArguments", e))
}
struct Hex32([u8; 32]);
impl<'de> Deserialize<'de> for Hex32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        crate::ids::deserialize_hex(deserializer).map(Self)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolScope {
    base: Hex32,
    audience: Hex32,
}

fn scope(args: &Value) -> Result<Scope, Value> {
    let input: ToolScope = parse(
        args.get("scope")
            .cloned()
            .ok_or_else(|| failure("InvalidArguments", "missing scope"))?,
    )?;
    Ok(Scope {
        base: input.base.0,
        audience: input.audience.0,
    })
}
fn reference(args: &Value) -> Result<TypeRef, Value> {
    match (args.get("type"), args.get("revision")) {
        (Some(id), None) => parse::<TypeId>(id.clone()).map(TypeRef::Current),
        (None, Some(revision)) => {
            parse::<crate::RevisionId>(revision.clone()).map(TypeRef::Revision)
        }
        _ => Err(failure(
            "InvalidArguments",
            "provide exactly one of type or revision",
        )),
    }
}

/// Invoke a named tool using only the session's verified host authority.
pub fn call<S: Store, A: Authority>(session: &DataSession<S, A>, name: &str, args: Value) -> Value {
    match name {
        "types.list" => {
            let scope = match scope(&args) {
                Ok(scope) => scope,
                Err(e) => return e,
            };
            session
                .list_types(scope)
                .map(ok)
                .unwrap_or_else(|e| failure(&data_code(&e), e))
        }
        "types.describe" => {
            let reference = match reference(&args) {
                Ok(id) => id,
                Err(e) => return e,
            };
            let scope = match scope(&args) {
                Ok(scope) => scope,
                Err(e) => return e,
            };
            session
                .describe(scope, reference)
                .map(ok)
                .unwrap_or_else(|e| failure(&data_code(&e), e))
        }
        "types.validate_example" => {
            let reference = match reference(&args) {
                Ok(id) => id,
                Err(e) => return e,
            };
            let Some(example) = args.get("example") else {
                return failure("InvalidArguments", "missing example");
            };
            let scope = match scope(&args) {
                Ok(scope) => scope,
                Err(e) => return e,
            };
            session
                .validate_example(scope, reference, example)
                .map(|_| ok(json!({"valid":true})))
                .unwrap_or_else(session_error)
        }
        "types.prepare_change" => {
            let Some(bytes) = args.get("bytes").cloned() else {
                return failure("InvalidArguments", "missing bytes");
            };
            let bytes: Vec<u8> = match parse(bytes) {
                Ok(bytes) => bytes,
                Err(e) => return e,
            };
            session
                .prepare_change(&bytes)
                .map(ok)
                .unwrap_or_else(|e| failure(&data_code(&e), e))
        }
        "records.validate" | "records.mutate" => {
            let op: Operation = match parse(args) {
                Ok(op) => op,
                Err(e) => return e,
            };
            if name == "records.validate" {
                session
                    .validate(&op)
                    .map(|_| ok(json!({"valid":true})))
                    .unwrap_or_else(session_error)
            } else {
                session.submit(op).map(saved).unwrap_or_else(session_error)
            }
        }
        "records.query" => {
            let scope = match scope(&args) {
                Ok(scope) => scope,
                Err(e) => return e,
            };
            let q: Query = match parse(args) {
                Ok(q) => q,
                Err(e) => return e,
            };
            session.query(scope, &q).map(ok).unwrap_or_else(query_error)
        }
        "records.aggregate" => {
            let scope = match scope(&args) {
                Ok(scope) => scope,
                Err(e) => return e,
            };
            let q: Aggregate = match parse(args) {
                Ok(q) => q,
                Err(e) => return e,
            };
            session
                .aggregate(scope, &q)
                .map(ok)
                .unwrap_or_else(query_error)
        }
        "records.get" | "records.history" => {
            let scope = match scope(&args) {
                Ok(scope) => scope,
                Err(e) => return e,
            };
            let Some(id) = args.get("record").cloned() else {
                return failure("InvalidArguments", "missing record");
            };
            let id: RecordId = match parse(id) {
                Ok(id) => id,
                Err(e) => return e,
            };
            if name == "records.get" {
                session.get(scope, id).map(|row| ok(row.map(|r| json!({"record":r.record, "type_id":r.type_id, "revision":r.revision, "doc":r.view(), "pending":r.pending})))).unwrap_or_else(|e| failure(&data_code(&e), e))
            } else {
                let before: Option<HistoryCursor> =
                    match args.get("before").cloned().map(parse).transpose() {
                        Ok(before) => before,
                        Err(e) => return e,
                    };
                let limit: usize = match args.get("limit").cloned().map(parse).transpose() {
                    Ok(Some(limit)) => limit,
                    Ok(None) => 50,
                    Err(e) => return e,
                };
                session.history(scope, id, before, limit).map(|entries| ok(entries.into_iter().map(|h| json!({"position":h.position, "mutation":h.mutation, "actor":h.actor, "path":h.path, "old":h.old, "new":h.new})).collect::<Vec<_>>())).unwrap_or_else(|e| failure(&data_code(&e), e))
            }
        }
        "records.undo" => {
            let Some(id) = args.get("mutation").cloned() else {
                return failure("InvalidArguments", "missing mutation");
            };
            let id: MutationId = match parse(id) {
                Ok(id) => id,
                Err(e) => return e,
            };
            session.undo(id).map(saved).unwrap_or_else(session_error)
        }
        _ => failure("UnknownTool", name),
    }
}
fn data_code(error: &crate::DataError) -> String {
    match error {
        crate::DataError::Sql(_) => "Sql",
        crate::DataError::Corrupt(_) => "Corrupt",
        crate::DataError::Limit(_) => "Limit",
        crate::DataError::Profile { .. } => "Profile",
        crate::DataError::Definition(_) => "Definition",
        crate::DataError::UniqueConflict => "UniqueConflict",
        crate::DataError::NotFound => "NotFound",
        crate::DataError::Unauthorized => "Unauthorized",
        crate::DataError::Path(_) => "Path",
        crate::DataError::Value(_) => "Value",
    }
    .into()
}
