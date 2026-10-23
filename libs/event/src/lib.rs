//! Experimental native encrypted event framing and historical verification.
//! This library neither provisions keys nor grants current access.

pub mod account_run;
mod codec;
mod control;
mod genesis;
mod history;
pub mod presence;
pub mod rekey;
pub mod writer;
pub use account_run::{AccountCopy, Copier, MAX_RUN};
pub use codec::{
    ACCOUNT_CHANGE, ACCOUNT_CHANGE_V2, ACCOUNT_REKEY, Binding, CLASS_CONTENT, CLASS_CONTROL,
    ContentSigningRequest, Encoded, Error, GENESIS, NOTE, NOTE_PREFIX, NoteDraft, Payload,
    TYPED_DATA, TypedDraft, key_id, note_payload, prepare_note, prepare_typed, seal, sealed_epoch,
    sealed_seen,
};
pub use control::{
    ControlChange, ControlEffect, ControlSigningRequest, ControlSpine, ControlState,
    SeenReceiptConflict, prepare_account_change,
};
pub use genesis::{GenesisSigningRequest, VerifiedGenesis, prepare_genesis, verify_genesis};
pub use history::{
    AppliedEvent, AppliedKind, ConsumeError, Continuation, History, HistoryLookup, LookupError,
    MaterializeError, Materialized, NoteTarget, Outcome, OwnedNoteTarget, PreparedEvent,
    PublishError, Seen, Transition, WorkingNote,
};
