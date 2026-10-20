//! The closed operation grammar every replica applies at ordered positions.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{AppId, FieldPath, MutationId, Position, RecordId, RevisionId, TypeId};

/// An unknown field inside a known kind is malformed, never ignored: an
/// extension uses a new kind or payload version.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    DefineApp {
        app: AppId,
        name: String,
    },
    /// The exact signed definition bytes; the revision is their content address.
    DefineType {
        bytes: Vec<u8>,
    },
    /// Copies a definition already accepted in another audience of the same
    /// base. The host supplies the exact bytes; they must hash to `revision`.
    Adopt {
        from_audience: [u8; 32],
        revision: RevisionId,
        bytes: Vec<u8>,
    },
    Create {
        record: RecordId,
        type_id: TypeId,
        revision: RevisionId,
        doc: Value,
    },
    /// `revision` is the contract the writer used; it limits which paths it may name.
    Edit {
        record: RecordId,
        revision: RevisionId,
        changes: Vec<FieldChange>,
    },
    Delete {
        record: RecordId,
    },
    /// Removes a creation/restoration only while its lifecycle and all field
    /// clocks still belong to that exact ordered change. Unlike deliberate Delete.
    UndoRemove {
        target: MutationId,
        position: Position,
        record: RecordId,
    },
    /// Reverses only fields of `record` whose latest accepted change is still `target`.
    Undo {
        target: MutationId,
        record: RecordId,
        changes: Vec<FieldChange>,
    },
    /// A declared app action's result, submitted by the job delegated to run it.
    Action {
        record: RecordId,
        app: AppId,
        action: String,
        changes: Vec<FieldChange>,
    },
    /// Makes an app's actions and new records available (`active`) or not.
    /// Its definitions, records and indexes stay either way, and so do the
    /// rules that protect them. A person's own device only.
    SetAppState {
        app: AppId,
        active: bool,
    },
    /// Binds a core contract revision this executable ships to this audience,
    /// so the audience's data may use it. A person's own device only.
    BindCore {
        type_id: TypeId,
        revision: RevisionId,
    },
    /// Makes an already defined revision of an app type the only permitted
    /// one: records on older revisions must be migrated before they change
    /// again. A person's own device only.
    Transition {
        type_id: TypeId,
        to: RevisionId,
    },
    /// Moves one record from revision `from` to `to` after a transition to
    /// `to`. When `to` declares a migration, `changes` must be exactly what it
    /// produces for the record.
    Migrate {
        record: RecordId,
        from: RevisionId,
        to: RevisionId,
        changes: Vec<FieldChange>,
    },
    /// Makes an existing plain Note a record of `type_id`, a specialisation
    /// of the Note, with the specialisation's own fields in `doc`. The Note
    /// keeps its identity, body and title, which stay with the note writer.
    BindNote {
        note: RecordId,
        type_id: TypeId,
        /// The writer's contract, as for a creation.
        revision: RevisionId,
        doc: Value,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldChange {
    pub path: FieldPath,
    /// `None` removes the field; `Some(Value::Null)` stores JSON null.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub value: Option<Value>,
}

fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

impl Operation {
    /// The `kind` tag this operation carries in a payload.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DefineApp { .. } => "define_app",
            Self::DefineType { .. } => "define_type",
            Self::Adopt { .. } => "adopt",
            Self::Create { .. } => "create",
            Self::Edit { .. } => "edit",
            Self::Delete { .. } => "delete",
            Self::UndoRemove { .. } => "undo_remove",
            Self::Undo { .. } => "undo",
            Self::Action { .. } => "action",
            Self::SetAppState { .. } => "set_app_state",
            Self::BindCore { .. } => "bind_core",
            Self::Transition { .. } => "transition",
            Self::Migrate { .. } => "migrate",
            Self::BindNote { .. } => "bind_note",
        }
    }

    pub fn record(&self) -> Option<RecordId> {
        match self {
            Self::Create { record, .. }
            | Self::Edit { record, .. }
            | Self::Delete { record }
            | Self::UndoRemove { record, .. }
            | Self::Undo { record, .. }
            | Self::Action { record, .. }
            | Self::Migrate { record, .. }
            | Self::BindNote { note: record, .. } => Some(*record),
            Self::DefineApp { .. }
            | Self::DefineType { .. }
            | Self::Adopt { .. }
            | Self::SetAppState { .. }
            | Self::BindCore { .. }
            | Self::Transition { .. } => None,
        }
    }

    pub fn changes(&self) -> &[FieldChange] {
        match self {
            Self::Edit { changes, .. }
            | Self::Undo { changes, .. }
            | Self::Action { changes, .. }
            | Self::Migrate { changes, .. } => changes,
            _ => &[],
        }
    }
}
