//! How the publisher paces one note's new packages, and what tests may
//! change. Defaults are the shipped policy; the knobs are re-exported only
//! with the `test-support` feature.
use std::time::Duration;

/// How the publisher paces one note's new packages. The default is the
/// shipped policy; only tests choose another (`Client::start_tuned`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pacing {
    /// The least time between one note's new package starts. The first edit
    /// after that long starts one at once.
    pub spacing: Duration,
    /// With `Some`, a note's new package also waits for a quiet spell.
    pub quiet: Option<Quiet>,
}
impl Default for Pacing {
    fn default() -> Self {
        Self {
            spacing: crate::outbox::SPACING,
            quiet: Some(Quiet::default()),
        }
    }
}

/// A trailing quiet period: a note's run starts once the note had no edit
/// for `after`, but no later than `within` after its first unsent edit.
/// The shipped policy sends 300 ms after the last edit, and at most 1 s
/// after the first unsent one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quiet {
    pub after: Duration,
    pub within: Duration,
}
impl Default for Quiet {
    fn default() -> Self {
        Self {
            after: Duration::from_millis(300),
            within: Duration::from_secs(1),
        }
    }
}

/// What tests may set about a client. Every default is the shipped
/// behaviour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tuning {
    pub pacing: Pacing,
    /// How long each durable commit this client makes on the typing path
    /// takes (persisting a seal, recording an Ack, committing received
    /// history), awaited before the commit: a stand-in for storage sync
    /// time under a paused test clock. Zero, and never awaited, in use.
    pub commit_delay: Duration,
}
