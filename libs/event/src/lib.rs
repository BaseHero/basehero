//! Experimental native encrypted event framing and historical verification.
//! This library neither provisions keys nor grants current access.

mod codec;
mod history;
pub use codec::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, Error, GENESIS, NOTE, Payload,
    key_id, seal,
};
pub use history::{ConsumeError, History, NoteTarget, Outcome, PreparedEvent};
