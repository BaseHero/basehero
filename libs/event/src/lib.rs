//! Experimental native encrypted event framing and historical verification.
//! This library neither provisions keys nor grants current access.

mod codec;
mod genesis;
mod history;
pub use codec::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, Error, GENESIS, NOTE, Payload,
    key_id, seal,
};
pub use genesis::{GenesisSigningRequest, VerifiedGenesis, prepare_genesis, verify_genesis};
pub use history::{
    AppliedEvent, AppliedKind, ConsumeError, History, MaterializeError, Materialized, NoteTarget,
    Outcome, OwnedNoteTarget, PreparedEvent, PublishError, Transition, WorkingNote,
};
