use crate::codec::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Error, GENESIS, NOTE, OpenPayload,
    apply_note, key_id, open_binding, open_body,
};
use bh_account::{
    AccountEvent, AccountId, Error as AccountError, Head as AccountHead, VerifiedAccount,
};
use bh_core::note::Note;
use bh_crypto::{Secret, verify};
use bh_sync::{BaseId, Commitment, Digest, Head, OpaqueEvent};
use std::collections::BTreeMap;

/// These results establish only historical verification, never a currently
/// authorised service operation. A caller must stop after `IntegrityStop`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    ContentRejected,
    IntegrityStop,
    UnsupportedPause,
    UnavailablePause,
}
/// Selected Note, checked against the authenticated ID before writing. The
/// compatibility `apply` API still stops on an externally guessed wrong target.
pub struct NoteTarget<'a> {
    pub id: [u8; 32],
    pub note: &'a mut Note,
}

/// A local selection/state race, not evidence of malicious remote history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeError {
    StaleState,
    WrongTarget,
}

// No public constructor or deserializer: only prepare() can produce this owned
// authenticated event. Note plaintext remains guarded in OpenPayload.
pub struct PreparedEvent {
    before: Prestate,
    head: Head,
    digest: Digest,
    event_id: [u8; 32],
    version: u16,
    kind: PreparedKind,
}
impl PreparedEvent {
    /// Only supported note events have a target. Controls return None.
    pub fn note_id(&self) -> Option<[u8; 32]> {
        match &self.kind {
            PreparedKind::Note { id, .. } => Some(*id),
            PreparedKind::Control { .. } => None,
        }
    }
}
enum PreparedKind {
    Note {
        id: [u8; 32],
        payload: OpenPayload,
    },
    Control {
        account: Box<VerifiedAccount>,
        metadata_id: Option<[u8; 32]>,
        epoch_id: Option<[u8; 32]>,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Prestate {
    base: BaseId,
    head: Head,
    control: [u8; 32],
    account: AccountHead,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    floor: u16,
    entries: usize,
    ids: usize,
    stopped: bool,
}

#[derive(Clone)]
struct Seen {
    head: Head,
    control: [u8; 32],
    account: AccountHead,
}

/// In-memory candidate. The containing device store must persist its checkpoint,
/// original bytes and Note atomically; this type does not create durable authority.
#[derive(Clone)]
pub struct History {
    base: BaseId,
    account: VerifiedAccount,
    entries: Vec<Seen>,
    ids: BTreeMap<[u8; 32], Digest>,
    metadata_id: Option<[u8; 32]>,
    epoch_id: Option<[u8; 32]>,
    floor: u16,
    stopped: bool,
}
impl History {
    /// `base` and `account_id` must come from local creation or an independent
    /// introduction, never from the untrusted log being checked.
    pub fn new(
        account_id: AccountId,
        account_genesis: &[u8],
        base: BaseId,
        remembered_floor: u16,
    ) -> Result<Self, Error> {
        if remembered_floor == 0 {
            return Err(Error::Invalid);
        }
        let account = VerifiedAccount::from_genesis(account_id, account_genesis)
            .map_err(|_| Error::Invalid)?;
        Ok(Self {
            base,
            account,
            entries: vec![],
            ids: BTreeMap::new(),
            metadata_id: None,
            epoch_id: None,
            floor: remembered_floor,
            stopped: false,
        })
    }
    pub fn head(&self) -> Head {
        self.entries.last().map_or(Head::EMPTY, |s| s.head)
    }
    pub fn floor(&self) -> u16 {
        self.floor
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    pub fn account_head(&self) -> AccountHead {
        self.account.head()
    }
    fn prestate(&self) -> Prestate {
        Prestate {
            base: self.base,
            head: self.head(),
            control: self.entries.last().map_or([0; 32], |s| s.control),
            account: self.account.head(),
            metadata_id: self.metadata_id,
            epoch_id: self.epoch_id,
            floor: self.floor,
            entries: self.entries.len(),
            ids: self.ids.len(),
            stopped: self.stopped,
        }
    }

    /// Verify descriptor, original signature, author-seen heads and account
    /// authority without fetching/opening a note body. This does not advance.
    pub fn inspect(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        metadata: &Secret<32>,
    ) -> Result<Binding, Outcome> {
        if self.stopped {
            return Err(Outcome::IntegrityStop);
        }
        let genesis = self.entries.is_empty();
        if ordered.verify_next(self.base, self.head()).is_err()
            || ordered.verify_body(event).is_err()
            || self.ids.contains_key(&event.id().0)
        {
            return Err(Outcome::IntegrityStop);
        }
        let (signed, signature) = match open_binding(
            event,
            metadata,
            if genesis { [0; 32] } else { self.base.0 },
            genesis,
        ) {
            Ok(v) => v,
            Err(Error::Unsupported) => return Err(Outcome::UnsupportedPause),
            Err(Error::Unavailable) => return Err(Outcome::UnavailablePause),
            Err(Error::Invalid) => return Err(Outcome::IntegrityStop),
        };
        if signed.audience != [0; 32] || signed.account != self.account.id() {
            return Err(Outcome::IntegrityStop);
        }
        // AEAD success alone cannot authenticate a substituted metadata root.
        // Genesis introduces M; every later original, including content, must
        // use precisely that committed root. S's epoch remains class-specific.
        let metadata_key_id = key_id(metadata);
        if !genesis && self.metadata_id != Some(metadata_key_id) {
            return Err(Outcome::IntegrityStop);
        }
        if !genesis && signed.class == CLASS_CONTENT && Some(signed.epoch) != self.epoch_id {
            return Err(Outcome::IntegrityStop);
        }
        if signed.class == CLASS_CONTROL && signed.epoch != metadata_key_id {
            return Err(Outcome::IntegrityStop);
        }
        if genesis {
            if signed.class != CLASS_CONTROL
                || signed.seen != Head::EMPTY
                || signed.seen_control != [0; 32]
                || signed.account_head != self.account.head()
            {
                return Err(Outcome::IntegrityStop);
            }
        } else {
            if signed.seen.position == 0 {
                return Err(Outcome::IntegrityStop);
            }
            let Ok(index) = usize::try_from(signed.seen.position - 1) else {
                return Err(Outcome::IntegrityStop);
            };
            let Some(seen) = self.entries.get(index) else {
                return Err(Outcome::IntegrityStop);
            };
            if seen.head != signed.seen
                || seen.control != signed.seen_control
                || seen.account != signed.account_head
            {
                return Err(Outcome::IntegrityStop);
            }
            if signed.class == CLASS_CONTROL
                && signed.seen_control != self.entries.last().expect("nonempty history").control
            {
                return Err(Outcome::IntegrityStop);
            }
        }
        let device = match self.account.active_device(signed.device) {
            Ok(v) => v,
            Err(_) => return Err(Outcome::IntegrityStop),
        };
        let key = if signed.class == CLASS_CONTROL {
            device.control()
        } else {
            device.signing()
        };
        let mut signed_bytes = b"bh/original-envelope/v1\0".to_vec();
        signed_bytes.extend(signed.encode_for_verify());
        if verify(key, &signed_bytes, &signature).is_err()
            || signed.highest < signed.version
            || signed.version < self.floor
        {
            return Err(Outcome::IntegrityStop);
        }
        if signed.version != 1 {
            return Err(Outcome::UnsupportedPause);
        }
        Ok(signed)
    }

    /// Fully verify one ordered original and body without advancing the
    /// checkpoint or modifying a Note. Invalid history latches an integrity
    /// stop; missing input and unsupported semantics do not. This grants no
    /// current/unlock authority.
    pub fn prepare(
        &mut self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
    ) -> Result<PreparedEvent, Outcome> {
        let result = self.prepare_checked(ordered, event, body, metadata, content);
        if matches!(result, Err(Outcome::IntegrityStop)) {
            self.stopped = true;
        }
        result
    }

    fn prepare_checked(
        &self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
    ) -> Result<PreparedEvent, Outcome> {
        let signed = self.inspect(ordered, event, metadata)?;
        let body = body.ok_or(Outcome::UnavailablePause)?;
        if signed.class == CLASS_CONTENT && content.is_some_and(|root| key_id(root) != signed.epoch)
        {
            return Err(Outcome::IntegrityStop);
        }
        let payload = open_body(&signed, body, metadata, content).map_err(|e| match e {
            Error::Unavailable => Outcome::UnavailablePause,
            Error::Unsupported => Outcome::UnsupportedPause,
            Error::Invalid => Outcome::IntegrityStop,
        })?;
        let mut next_account = self.account.clone();
        let mut next_metadata = self.metadata_id;
        let mut next_epoch = self.epoch_id;
        match (signed.class, payload.kind) {
            (CLASS_CONTROL, GENESIS) if self.entries.is_empty() => {
                let data = payload.data();
                if data.len() != 168
                    || data[..32] != signed.account.0
                    || data[32..40] != signed.account_head.position.to_be_bytes()
                    || data[40..72] != signed.account_head.hash
                    || data[72..104] != [0; 32]
                    || data[136..168] != signed.epoch
                {
                    return Err(Outcome::IntegrityStop);
                }
                next_metadata = Some(signed.epoch);
                next_epoch = Some(data[104..136].try_into().expect("length checked"));
            }
            (CLASS_CONTROL, ACCOUNT_CHANGE) if !self.entries.is_empty() => {
                let data = payload.data();
                // Independent allowlist; expanding the account parser cannot make
                // private recovery/seal records forwardable under metadata M.
                const TAG: usize = b"BaseHero account event\0".len() + 2 + 2 + 8 + 32 + 32 + 32;
                let Some(tag) = data.get(TAG) else {
                    return Err(Outcome::IntegrityStop);
                };
                if !matches!(tag, 1 | 2) {
                    return Err(Outcome::UnsupportedPause);
                }
                let parsed = match AccountEvent::decode(data) {
                    Ok(event) => event,
                    Err(AccountError::UnsupportedVersion | AccountError::UnsupportedControl) => {
                        return Err(Outcome::UnsupportedPause);
                    }
                    Err(_) => return Err(Outcome::IntegrityStop),
                };
                if signed.account_head != self.account.head() {
                    return Err(Outcome::IntegrityStop);
                }
                match next_account.apply(parsed.as_bytes()) {
                    Ok(()) => {}
                    Err(AccountError::UnsupportedVersion | AccountError::UnsupportedControl) => {
                        return Err(Outcome::UnsupportedPause);
                    }
                    Err(_) => return Err(Outcome::IntegrityStop),
                }
                if data[TAG] == 2 {
                    next_epoch = None;
                }
            }
            (CLASS_CONTENT, NOTE) if !self.entries.is_empty() => {
                let data = payload.data();
                let id: [u8; 32] = data
                    .get(..32)
                    .ok_or(Outcome::IntegrityStop)?
                    .try_into()
                    .expect("length checked");
                return Ok(PreparedEvent {
                    before: self.prestate(),
                    head: ordered.head(),
                    digest: ordered.event_digest(),
                    event_id: event.id().0,
                    version: signed.version,
                    kind: PreparedKind::Note { id, payload },
                });
            }
            (CLASS_CONTROL, GENESIS)
            | (CLASS_CONTENT, GENESIS | ACCOUNT_CHANGE)
            | (CLASS_CONTROL, NOTE) => return Err(Outcome::IntegrityStop),
            _ => return Err(Outcome::UnsupportedPause),
        }
        Ok(PreparedEvent {
            before: self.prestate(),
            head: ordered.head(),
            digest: ordered.event_digest(),
            event_id: event.id().0,
            version: signed.version,
            kind: PreparedKind::Control {
                account: Box::new(next_account),
                metadata_id: next_metadata,
                epoch_id: next_epoch,
            },
        })
    }

    /// Consume only against the exact verified predecessor. Selection errors do
    /// not poison history or modify a Note. The caller owns the atomic store and
    /// (for hidden bases) must separately fence its current unlock generation.
    pub fn consume(
        &mut self,
        prepared: PreparedEvent,
        target: Option<NoteTarget<'_>>,
    ) -> Result<Outcome, ConsumeError> {
        if self.prestate() != prepared.before || self.stopped {
            return Err(ConsumeError::StaleState);
        }
        let is_control = matches!(&prepared.kind, PreparedKind::Control { .. });
        if is_control != target.is_none()
            || target
                .as_ref()
                .is_some_and(|t| Some(t.id) != prepared.note_id())
        {
            return Err(ConsumeError::WrongTarget);
        }
        let (account, metadata_id, epoch_id, note, result) = match prepared.kind {
            PreparedKind::Control {
                account,
                metadata_id,
                epoch_id,
            } => (*account, metadata_id, epoch_id, None, Outcome::Accepted),
            PreparedKind::Note { payload, .. } => {
                let target = target.expect("target checked");
                let next = apply_note(target.note, &payload.data()[32..]);
                let result = if next.is_ok() {
                    Outcome::Accepted
                } else {
                    Outcome::ContentRejected
                };
                (
                    self.account.clone(),
                    self.metadata_id,
                    self.epoch_id,
                    next.ok().map(|candidate| (target.note, candidate)),
                    result,
                )
            }
        };
        let previous = self.entries.last();
        self.entries.push(Seen {
            head: prepared.head,
            control: if is_control {
                prepared.digest.0
            } else {
                previous.map_or([0; 32], |p| p.control)
            },
            account: account.head(),
        });
        self.ids.insert(prepared.event_id, prepared.digest);
        self.account = account;
        self.metadata_id = metadata_id;
        self.epoch_id = epoch_id;
        self.floor = self.floor.max(prepared.version);
        if let Some((target, candidate)) = note {
            *target = candidate;
        }
        Ok(result)
    }

    /// Compatibility API for a caller with an externally known note ID. Unlike
    /// consume(), a wrong guess remains an integrity stop as before.
    pub fn apply(
        &mut self,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
        metadata: &Secret<32>,
        content: Option<&Secret<32>>,
        target: NoteTarget<'_>,
    ) -> Outcome {
        let prepared = match self.prepare(ordered, event, body, metadata, content) {
            Ok(p) => p,
            Err(other) => return other,
        };
        let target = if prepared.note_id().is_some() {
            Some(target)
        } else {
            None
        };
        match self.consume(prepared, target) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.stopped = true;
                Outcome::IntegrityStop
            }
        }
    }
}
