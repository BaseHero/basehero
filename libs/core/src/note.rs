//! Note documents. [`Note`] is the yrs document behind the note API: on
//! devices and services it runs contained in the bundled note engine, so a
//! yrs parse or apply bug cannot reach the host's keys or decrypted data; on
//! Wasm, including inside that engine, it is [`native::Note`] itself. Neither
//! a Note nor its snapshots are a storage acknowledgement: the device store
//! serializes mutation with commit.

#[doc(hidden)]
pub mod abi;
#[cfg(any(target_family = "wasm", feature = "native-oracle"))]
pub mod native;

#[cfg(not(target_family = "wasm"))]
pub use crate::contained::Note;
#[cfg(target_family = "wasm")]
pub use native::Note;

pub const FRAGMENT: &str = "default";
/// Local editing policy shared with the editor (`editingPositions` in the note
/// inventory): checked authoring may grow a note to this many ProseMirror
/// positions, about a million characters. Larger notes are kept and readable;
/// this never rejects stored, received or already accepted content.
pub const EDITING_POSITIONS: usize = 1_000_000;

/// A note's persisted state: Yjs v1 updates applied in this order. yrs
/// integrates one merged update by descending client ID, which can place
/// concurrent text differently from the order its parts were integrated in,
/// so updates are merged only where a [`Note::digest`] shows the merged form
/// reproduces the same structure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderedState {
    segments: Vec<Vec<u8>>,
}

const ORDERED_MAGIC: &[u8; 5] = b"BHOS1";

impl OrderedState {
    pub fn single(state: Vec<u8>) -> Self {
        Self {
            segments: vec![state],
        }
    }
    pub fn segments(&self) -> &[Vec<u8>] {
        &self.segments
    }
    pub fn into_segments(self) -> Vec<Vec<u8>> {
        self.segments
    }
    /// Append a later update; the result applies it after every segment.
    pub fn push(&mut self, update: Vec<u8>) {
        self.segments.push(update);
    }
    /// `BHOS1 || u32 count || (u32 len || bytes)*`, big-endian.
    pub fn encode(&self) -> Vec<u8> {
        let size = self.segments.iter().map(|s| 4 + s.len()).sum::<usize>();
        let mut out = Vec::with_capacity(ORDERED_MAGIC.len() + 4 + size);
        out.extend_from_slice(ORDERED_MAGIC);
        out.extend_from_slice(&u32_len(self.segments.len()).to_be_bytes());
        for segment in &self.segments {
            out.extend_from_slice(&u32_len(segment.len()).to_be_bytes());
            out.extend_from_slice(segment);
        }
        out
    }
    /// Bytes without the magic are an older single full state, kept as is;
    /// empty bytes are no state.
    pub fn decode(bytes: &[u8]) -> Result<Self, NoteError> {
        // An older state is `Note::state()`, whose first client starts at clock 0;
        // `BHOS1` would read as 66 clients, 72 structs, client 79, clock 83.
        let Some(mut rest) = bytes.strip_prefix(ORDERED_MAGIC.as_slice()) else {
            if bytes.is_empty() {
                return Ok(Self::default());
            }
            return Ok(Self::single(bytes.to_vec()));
        };
        let count = take_word(&mut rest)?;
        let mut segments = Vec::new();
        for _ in 0..count {
            let len = take_word(&mut rest)?;
            segments.push(take(&mut rest, len)?.to_vec());
        }
        if !rest.is_empty() {
            return Err(NoteError::Decode(
                yrs::encoding::read::Error::UnexpectedValue,
            ));
        }
        Ok(Self { segments })
    }
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], NoteError> {
    if rest.len() < n {
        return Err(NoteError::Decode(yrs::encoding::read::Error::EndOfBuffer(
            n,
        )));
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn take_word(rest: &mut &[u8]) -> Result<usize, NoteError> {
    let word: [u8; 4] = take(rest, 4)?.try_into().expect("four bytes");
    Ok(u32::from_be_bytes(word) as usize)
}

fn u32_len(len: usize) -> u32 {
    u32::try_from(len).expect("note state segment beyond 4 GiB")
}

/// Rebuilds one [`Note::ordered`] call may spend, its final check included.
/// Past it the rest of the tail stays as given: crafted history can cost a
/// note more segments, but never more compaction work per call.
pub const ORDERED_REBUILD_BUDGET: usize = 8;

thread_local! {
    static REBUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test seam: verification rebuilds run on this thread so far, by either
/// engine.
#[doc(hidden)]
pub fn verification_rebuilds() -> usize {
    REBUILDS.with(std::cell::Cell::get)
}

pub(crate) fn count_rebuilds(n: usize) {
    REBUILDS.with(|r| r.set(r.get() + n));
}

#[derive(Debug)]
pub enum NoteError {
    Decode(yrs::encoding::read::Error),
    Apply(yrs::error::UpdateError),
    /// Not a judgement on the update: the contained engine trapped or hit a
    /// local fuel or memory limit. Accepted state is unchanged; the caller
    /// keeps it, discards this working Note and waits.
    Unavailable,
}

#[derive(Debug)]
pub enum WriterError {
    InvalidWriter,
    /// Too few clocks remain for this operation: reacquire, never wrap.
    Exhausted,
    /// The operation would take the note past [`EDITING_POSITIONS`].
    TooLarge,
    Update(NoteError),
}

/// Whether these bytes are a Yjs v1 update at all, without integrating them.
/// A local engine failure judges nothing about these bytes.
#[cfg(not(target_family = "wasm"))]
pub fn is_update(bytes: &[u8]) -> Result<bool, NoteError> {
    crate::contained::is_update(bytes)
}
#[cfg(target_family = "wasm")]
pub use native::is_update;

/// One update holding every change in `updates`, in order. Callers merge
/// only one writer's consecutive updates, which integrate as the same
/// structure merged or not. A local engine failure judges nothing.
#[cfg(not(target_family = "wasm"))]
pub fn merge_updates(updates: &[Vec<u8>]) -> Result<Vec<u8>, NoteError> {
    crate::contained::merge_updates(updates)
}

/// Why an incoming update was refused. Each refusal has no effect on accepted
/// state, and every device reaches the same one from the same log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingRefusal {
    /// It inserts under a writer other than the one it declared.
    ForeignWriter,
    /// Its run does not start exactly at the writer's accepted end.
    NotContinuous,
    /// Its whole run is already accepted.
    Duplicate,
    /// It references items that are not accepted, so it cannot attach at
    /// its ordered position.
    MissingDependency,
    /// It is not a Yjs v1 update.
    Undecodable,
    /// It decodes, but yrs failed while integrating it.
    ApplyFailed,
}

/// Local inability to judge is never a replicated refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingError {
    Refused {
        reason: IncomingRefusal,
        changed: bool,
    },
    Unavailable,
}

/// One writer's clocks: received Item+GC input checked against the integrated
/// store. Only Ready proves the next clock an author would allocate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterPrefix {
    /// Complete, integrated 0..end.
    Ready(u32),
    /// Complete input still waiting on another writer's missing struct.
    Pending,
    /// A Skip gap or other missing input: no prefix proof.
    Incomplete,
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "note engine unavailable"),
            _ => write!(f, "invalid note update: {self:?}"),
        }
    }
}
impl std::error::Error for NoteError {}
