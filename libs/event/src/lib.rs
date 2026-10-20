//! Experimental native encrypted event framing and historical verification.
//! This library neither provisions keys nor grants current access.

mod codec;
mod control;
mod genesis;
mod history;
pub mod presence;
pub mod writer;
pub use codec::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, Error, GENESIS, NOTE,
    NOTE_PREFIX, NoteDraft, NoteSigningRequest, Payload, key_id, note_payload, prepare_note, seal,
    sealed_epoch,
};
pub use control::{
    ControlChange, ControlEffect, ControlSigningRequest, ControlSpine, ControlState,
    prepare_account_change,
};
pub use genesis::{GenesisSigningRequest, VerifiedGenesis, prepare_genesis, verify_genesis};
pub use history::{
    AppliedEvent, AppliedKind, ConsumeError, Continuation, History, HistoryLookup, LookupError,
    MaterializeError, Materialized, NoteTarget, Outcome, OwnedNoteTarget, PreparedEvent,
    PublishError, Seen, Transition, WorkingNote,
};
