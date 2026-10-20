//! The signed-event checks every follower of a base shares, and the
//! service-side follower of one base's controls.
//!
//! `History` follows every event on a device. [`ControlSpine`] follows only a
//! base's control-route events, for the service that admits them: it never
//! sees content, so it judges an author's claim about what they had seen
//! against the last control alone. Both run the same checks here, so for the
//! same control they reach the same verdict and effect.
use crate::codec::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, Error, EventSigningRequest,
    GENESIS, NOTE, NOTE_PREFIX, OpenPayload, Payload, TYPED_DATA, body_committed, body_named,
    key_id, open_binding, open_body, prepare_seal,
};
use crate::genesis::{VerifiedGenesis, judge_genesis};
use crate::history::{History, Outcome, Seen};
use crate::writer::{DeviceWriterDeclaration, WriterDecodeError};
use bh_account::{
    AccountEvent, AccountId, DeviceId, Error as AccountError, Head as AccountHead, VerifiedAccount,
};
use bh_crypto::{Secret, random, verify};
use bh_sync::{
    BaseId, Commitment, Digest, EventId, Head, OpaqueEvent, Route, receipt, receipt::RECEIPT_LEN,
};
use std::sync::Arc;

/// Where an account event's control tag sits. An independent allowlist:
/// expanding the account parser cannot make private recovery or seal records
/// forwardable under metadata M.
const ACCOUNT_TAG: usize = b"BaseHero account event\0".len() + 2 + 2 + 8 + 32 + 32 + 32;
const ADD_DEVICE: u8 = 1;
const REMOVE_SELF: u8 = 2;

/// What a follower knows when it judges the next event: the state its
/// verified history reached, and what that history had at the positions an
/// author may claim to have seen.
pub(crate) trait SignedContext {
    fn base(&self) -> BaseId;
    /// Only a base genesis is judged before any position.
    fn genesis(&self) -> bool;
    fn account(&self) -> &VerifiedAccount;
    fn metadata_id(&self) -> Option<[u8; 32]>;
    fn epoch_id(&self) -> Option<[u8; 32]>;
    fn floor(&self) -> u16;
    fn hosting_root(&self) -> Option<[u8; 32]>;
    /// The digest of the newest valid control.
    fn last_control(&self) -> [u8; 32];
    fn id_used(&self, event_id: [u8; 32]) -> Result<bool, Outcome>;
    /// The head verified history has at `position`, where this follower
    /// knows it.
    fn known_head(&self, position: u64) -> Result<Option<Head>, Outcome>;
    /// Whether verified history had applied exactly `claim` at its position.
    fn saw(&self, claim: Seen) -> Result<bool, Outcome>;
}

/// Verify an ordered original's binding, author, signature, version, receipt
/// and seen claims, and that its sealed class matches the route it was
/// ordered on, without opening its body. An invalid submission is
/// `Err(Rejected)`, or an integrity stop at genesis.
pub(crate) fn verify_signed(
    ctx: &impl SignedContext,
    route: Route,
    event: &OpaqueEvent,
    metadata: &Secret<32>,
) -> Result<Binding, Outcome> {
    let genesis = ctx.genesis();
    // The independently introduced base names its genesis, so an invalid
    // genesis contradicts that introduction. After it, an invalid
    // submission holds its position with no effect.
    let invalid = if genesis {
        Outcome::IntegrityStop
    } else {
        Outcome::Rejected
    };
    if ctx.id_used(event.id().0)? {
        return Err(invalid);
    }
    // Genesis introduces M; every later original must use exactly that
    // committed root. A caller without it lacks a key: it waits.
    let metadata_key_id = key_id(metadata);
    if !genesis && ctx.metadata_id() != Some(metadata_key_id) {
        return Err(Outcome::UnavailablePause);
    }
    let (signed, signature) = match open_binding(
        event,
        metadata,
        if genesis { [0; 32] } else { ctx.base().0 },
        genesis,
    ) {
        Ok(v) => v,
        Err(Error::Unsupported) => return Err(Outcome::UnsupportedPause),
        Err(Error::Unavailable) => return Err(Outcome::UnavailablePause),
        Err(Error::Invalid) => return Err(invalid),
    };
    if !genesis {
        // A receipt the pinned hosting key signed for a head that differs
        // from the one verified at its position is the service
        // contradicting itself, whoever carries it: nothing a member signs
        // can make one. Anything else wrong with it is the author's.
        let root = ctx.hosting_root().ok_or(Outcome::UnavailablePause)?;
        if let Ok(observed) = receipt::verify(&root, ctx.base(), &signed.seen_receipt) {
            let head = observed.head();
            if ctx
                .known_head(head.position)?
                .is_some_and(|known| known != head)
            {
                return Err(Outcome::IntegrityStop);
            }
        }
    }
    let account = ctx.account();
    if signed.account != account.id() || (genesis && signed.audience != [0; 32]) {
        return Err(invalid);
    }
    if genesis {
        if signed.class != CLASS_CONTROL
            || signed.seen != Head::EMPTY
            || signed.seen_control != [0; 32]
            || signed.account_head != account.head()
        {
            return Err(invalid);
        }
    } else {
        // A false claim about what the author had seen is the author's,
        // not proof of a fork.
        let claim = Seen {
            head: signed.seen,
            control: signed.seen_control,
            account: signed.account_head,
        };
        if !ctx.saw(claim)? {
            return Err(invalid);
        }
        if signed.class == CLASS_CONTROL && signed.seen_control != ctx.last_control() {
            return Err(invalid);
        }
    }
    let device = match account.active_device(signed.device) {
        Ok(v) => v,
        Err(_) => return Err(invalid),
    };
    let key = if genesis || signed.class == CLASS_CONTENT {
        device.signing()
    } else {
        device.control()
    };
    let mut signed_bytes = b"bh/original-envelope/v1\0".to_vec();
    signed_bytes.extend(signed.encode_for_verify());
    // Genesis is version 1 forever, so a remembered floor applies only to
    // later events, which are version 2 and carry a receipt.
    if verify(key, &signed_bytes, &signature).is_err()
        || signed.highest < signed.version
        || (!genesis && signed.version < ctx.floor())
    {
        return Err(invalid);
    }
    if signed.version > 2 {
        return Err(Outcome::UnsupportedPause);
    }
    // Only the base's ordinary audience is known; another one's events
    // (and their epochs) are semantics this version cannot judge.
    if signed.audience != [0; 32] {
        return Err(Outcome::UnsupportedPause);
    }
    // The sequencer committed which permit it ordered this under. A control
    // ordered as content, or content ordered as a control, is the author's
    // invalid submission; at genesis it stops.
    if (signed.class == CLASS_CONTROL) != (route == Route::Control) {
        return Err(invalid);
    }
    if signed.version != if genesis { 1 } else { 2 } {
        return Err(invalid);
    }
    // S's epoch is class-specific.
    if !genesis && signed.class == CLASS_CONTENT && Some(signed.epoch) != ctx.epoch_id() {
        return Err(invalid);
    }
    if signed.class == CLASS_CONTROL && signed.epoch != metadata_key_id {
        return Err(invalid);
    }
    if !genesis {
        // The receipt names its own certificate, checked only against the
        // pinned root: an unknown or wrong key is refused, never awaited.
        let root = ctx.hosting_root().ok_or(Outcome::UnavailablePause)?;
        match receipt::verify(&root, ctx.base(), &signed.seen_receipt) {
            Ok(observed) if observed.head() == signed.seen => {}
            _ => return Err(invalid),
        }
    }
    Ok(signed)
}

/// A verified event's effect, before any follower applies it.
pub(crate) enum Judged {
    Note {
        id: [u8; 32],
        writer: DeviceWriterDeclaration,
        payload: OpenPayload,
    },
    /// Typed data this build carries but does not parse.
    Typed { payload: OpenPayload },
    /// A class-content kind this build does not know.
    UnknownContent { kind: u16, payload: OpenPayload },
    /// A note event whose writer declaration this build cannot read.
    NoteUnsupported { id: [u8; 32], payload: OpenPayload },
    Control {
        /// The account after an account change; None when unchanged.
        account: Option<Arc<VerifiedAccount>>,
        change: Option<Vec<u8>>,
        metadata_id: Option<[u8; 32]>,
        epoch_id: Option<[u8; 32]>,
    },
}

/// Open and judge the body of an original [`verify_signed`] accepted.
pub(crate) fn judge(
    ctx: &impl SignedContext,
    signed: &Binding,
    event: &OpaqueEvent,
    body: &[u8],
    metadata: &Secret<32>,
    content: Option<&Secret<32>>,
) -> Result<Judged, Outcome> {
    let genesis = ctx.genesis();
    let invalid = if genesis {
        Outcome::IntegrityStop
    } else {
        Outcome::Rejected
    };
    // A content root other than the epoch the base uses is this device's
    // missing key, not a fault in the event.
    if signed.class == CLASS_CONTENT && content.is_some_and(|root| key_id(root) != signed.epoch) {
        return Err(Outcome::UnavailablePause);
    }
    // Bytes other than those the ordered descriptor names were changed:
    // only the service can do that. With the named bytes, a signed size
    // or commitment that disagrees with them is the author's.
    if !body_named(event, body) {
        return Err(Outcome::IntegrityStop);
    }
    if !body_committed(signed, body) {
        return Err(invalid);
    }
    let payload = open_body(signed, body, metadata, content).map_err(|e| match e {
        Error::Unavailable => Outcome::UnavailablePause,
        Error::Unsupported => Outcome::UnsupportedPause,
        Error::Invalid => invalid,
    })?;
    match (signed.class, payload.kind) {
        (CLASS_CONTROL, GENESIS) if genesis => {
            let data = payload.data();
            if data.len() != 168
                || data[..32] != signed.account.0
                || data[32..40] != signed.account_head.position.to_be_bytes()
                || data[40..72] != signed.account_head.hash
                || data[72..104] != [0; 32]
                || data[136..168] != signed.epoch
            {
                return Err(invalid);
            }
            Ok(Judged::Control {
                account: None,
                change: None,
                metadata_id: Some(signed.epoch),
                epoch_id: Some(data[104..136].try_into().expect("length checked")),
            })
        }
        (CLASS_CONTROL, ACCOUNT_CHANGE) if !genesis => {
            let (account, change) = account_change(
                ctx.account(),
                payload.data(),
                signed.account_head == ctx.account().head(),
            )?;
            let epoch_id = if change[ACCOUNT_TAG] == REMOVE_SELF {
                None
            } else {
                ctx.epoch_id()
            };
            Ok(Judged::Control {
                account: Some(Arc::new(account)),
                change: Some(change),
                metadata_id: ctx.metadata_id(),
                epoch_id,
            })
        }
        (CLASS_CONTENT, NOTE) if !genesis => {
            // Note ID, then the producing writer's declaration, then the
            // update: a note event without both is malformed.
            let data = payload.data();
            if data.len() < NOTE_PREFIX {
                return Err(invalid);
            }
            let id: [u8; 32] = data[..32].try_into().expect("length checked");
            let writer = match DeviceWriterDeclaration::decode(&data[32..NOTE_PREFIX]) {
                Ok(writer) => writer,
                // A declaration only a newer version reads names the note it
                // is for, so that note alone waits; the exact bytes are kept.
                Err(
                    WriterDecodeError::UnsupportedVersion(_)
                    | WriterDecodeError::UnsupportedAuthor(_),
                ) => return Ok(Judged::NoteUnsupported { id, payload }),
                Err(_) => return Err(invalid),
            };
            Ok(Judged::Note {
                id,
                writer,
                payload,
            })
        }
        (CLASS_CONTENT, TYPED_DATA) if !genesis => Ok(Judged::Typed { payload }),
        // Known kinds in the wrong class stay the author's invalid submission.
        (CLASS_CONTROL, GENESIS)
        | (CLASS_CONTENT, GENESIS | ACCOUNT_CHANGE)
        | (CLASS_CONTROL, NOTE | TYPED_DATA) => Err(invalid),
        // Any other class-content kind is content this build retains without
        // applying: its exact bytes are kept, history continues past it, and
        // the scope it could affect reports incomplete until a newer build
        // replays it. It never changes control state.
        (CLASS_CONTENT, kind) if !genesis => Ok(Judged::UnknownContent { kind, payload }),
        _ => Err(Outcome::UnsupportedPause),
    }
}

/// The account after copying `data`, the next account event, into a base
/// whose copy of the account is `account`; `at_head` is whether its author
/// claimed that copy's head. Only AddDevice and RemoveSelf are judged here;
/// any later event is invalid, as is anything but the next one.
fn account_change(
    account: &VerifiedAccount,
    data: &[u8],
    at_head: bool,
) -> Result<(VerifiedAccount, Vec<u8>), Outcome> {
    let invalid = Outcome::Rejected;
    let Some(tag) = data.get(ACCOUNT_TAG) else {
        return Err(invalid);
    };
    if !matches!(*tag, ADD_DEVICE | REMOVE_SELF) {
        return Err(Outcome::UnsupportedPause);
    }
    let parsed = match AccountEvent::decode(data) {
        Ok(event) => event,
        Err(AccountError::UnsupportedVersion | AccountError::UnsupportedControl) => {
            return Err(Outcome::UnsupportedPause);
        }
        Err(_) => return Err(invalid),
    };
    if !at_head {
        return Err(invalid);
    }
    let mut next = account.clone();
    match next.apply(parsed.as_bytes()) {
        Ok(()) => Ok((next, parsed.as_bytes().to_vec())),
        Err(AccountError::Unavailable) => Err(Outcome::UnavailablePause),
        Err(AccountError::UnsupportedVersion | AccountError::UnsupportedControl) => {
            Err(Outcome::UnsupportedPause)
        }
        Err(_) => Err(invalid),
    }
}

/// What a base control did to the base's copy of the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlChange {
    AddDevice,
    RemoveSelf,
}

/// A valid control's effect, judged against the spine before it applies.
/// It holds no secret, so the service may keep it while the control is
/// pending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlEffect {
    /// The control's `OpaqueEvent::digest`.
    pub digest: Digest,
    /// The content epoch after it; None once a removal closed it.
    pub epoch_after: Option<[u8; 32]>,
    pub account_head_after: AccountHead,
    pub change: ControlChange,
    /// The exact verified account event it copied.
    pub account_event: Vec<u8>,
    pub floor_after: u16,
    /// Position attested by the author's seen receipt.
    pub seen_position: u64,
    /// State against which this effect was judged, before ordering.
    pub judged_control_digest: [u8; 32],
    pub judged_account_head: AccountHead,
}

/// Everything a service keeps to follow one base's controls. No secret: M
/// verifies a control and is never part of it.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlState {
    pub base: BaseId,
    pub creator: AccountId,
    pub hosting_root: [u8; 32],
    pub metadata_id: [u8; 32],
    /// The content epoch; None after a removal closed it.
    pub epoch: Option<[u8; 32]>,
    pub floor: u16,
    /// The last valid control's position and its `OpaqueEvent::digest`.
    pub control: Head,
    pub control_digest: [u8; 32],
    /// The last control-route event; the last valid control unless an
    /// invalid one was ordered after it.
    pub control_head: Head,
    /// The base's copy of the account: its head, and the exact verified
    /// account events copied after the head the genesis names, in order.
    pub account: AccountHead,
    pub account_changes: Vec<Vec<u8>>,
}

impl std::fmt::Debug for ControlState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlState")
            .field("base", &self.base)
            .field("creator", &self.creator.0)
            .field("hosting_root", &self.hosting_root)
            .field("metadata_id", &self.metadata_id)
            .field("epoch", &self.epoch)
            .field("floor", &self.floor)
            .field("control", &self.control)
            .field("control_digest", &self.control_digest)
            .field("control_head", &self.control_head)
            .field("account", &self.account)
            .field("account_changes", &self.account_changes.len())
            .finish()
    }
}

/// The service-side follower of one base's controls. It needs M to judge a
/// control, never K, and never sees content: an author's seen claim is
/// judged against the last valid control, which every position after it
/// shares, and the hosting receipt attests the head itself.
///
/// Known limits compared with `History`:
/// - A verified receipt contradicting a *content* head stops `History`, but
///   this follower only knows control heads.
/// - A control-route event that `History` would pause, but whose seen claim
///   predates the last control, is rejected here instead. Reaching this case
///   requires a dishonest DO to order such a submission on the control route.
/// - Event IDs are not tracked; this relies on the DO's unique IDs.
///
/// For controls it can judge, it gives `History`'s verdict and effect.
#[derive(Clone)]
pub struct ControlSpine {
    state: ControlState,
}

impl ControlSpine {
    /// Verify a base's genesis with `History`'s own checks. `view` is the
    /// creator's verified account at the head the genesis names; `root`
    /// the pinned hosting root.
    pub fn from_genesis(
        view: &VerifiedAccount,
        descriptor: &OpaqueEvent,
        body: &[u8],
        metadata: &Secret<32>,
        root: [u8; 32],
        ordered: &Commitment,
    ) -> Result<(Self, VerifiedGenesis), Outcome> {
        let base = BaseId::from_genesis(descriptor);
        let mut history =
            History::with_account(view, base, root, 1).map_err(|_| Outcome::IntegrityStop)?;
        let genesis = judge_genesis(&mut history, ordered, descriptor, body, metadata)?;
        let state = ControlState {
            base,
            creator: view.id(),
            hosting_root: root,
            metadata_id: genesis.metadata_key_id,
            epoch: Some(genesis.content_key_id),
            floor: history.floor(),
            control: ordered.head(),
            control_digest: ordered.event_digest().0,
            control_head: ordered.head(),
            account: view.head(),
            account_changes: vec![],
        };
        Ok((Self { state }, genesis))
    }

    /// Continue from state this follower produced.
    pub fn resume(state: ControlState) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &ControlState {
        &self.state
    }

    /// Judge an ordered control. `view_at_base_head` is the creator's
    /// verified account at the base's account head.
    pub fn check(
        &self,
        view_at_base_head: &VerifiedAccount,
        descriptor: &OpaqueEvent,
        body: &[u8],
        metadata: &Secret<32>,
        ordered: &Commitment,
    ) -> Result<ControlEffect, Outcome> {
        self.continues(ordered)?;
        if ordered.verify_body(descriptor).is_err() {
            return Err(Outcome::IntegrityStop);
        }
        self.judge(
            view_at_base_head,
            descriptor,
            body,
            metadata,
            ordered.route(),
            Some(ordered.head().position),
        )
    }

    /// Judge a control submitted for ordering on the control route. Its
    /// effect is the one [`ControlSpine::check`] gives once it is ordered
    /// after the current control head.
    pub fn check_submission(
        &self,
        view_at_base_head: &VerifiedAccount,
        descriptor: &OpaqueEvent,
        body: &[u8],
        metadata: &Secret<32>,
    ) -> Result<ControlEffect, Outcome> {
        self.judge(
            view_at_base_head,
            descriptor,
            body,
            metadata,
            Route::Control,
            None,
        )
    }

    /// Apply a checked control's effect at its ordered position.
    pub fn apply(&mut self, effect: ControlEffect, ordered: &Commitment) -> Result<(), Outcome> {
        self.continues(ordered)?;
        if ordered.route() != Route::Control
            || ordered.event_digest() != effect.digest
            || ordered.head().position <= effect.seen_position
            || self.state.control_digest != effect.judged_control_digest
            || self.state.account != effect.judged_account_head
        {
            return Err(Outcome::IntegrityStop);
        }
        let state = &mut self.state;
        state.epoch = effect.epoch_after;
        state.floor = effect.floor_after;
        state.control = ordered.head();
        state.control_digest = effect.digest.0;
        state.control_head = ordered.head();
        state.account = effect.account_head_after;
        state.account_changes.push(effect.account_event);
        Ok(())
    }

    /// Hold the position of a control-route event judged invalid: it moves
    /// the control head and nothing else.
    pub fn apply_rejected(&mut self, ordered: &Commitment) -> Result<(), Outcome> {
        self.continues(ordered)?;
        if ordered.route() != Route::Control {
            return Err(Outcome::IntegrityStop);
        }
        self.state.control_head = ordered.head();
        Ok(())
    }

    /// An ordered control must be a sound commitment in this base after the
    /// control head; anything else is the sequencer contradicting itself.
    fn continues(&self, ordered: &Commitment) -> Result<(), Outcome> {
        let previous = ordered.previous();
        if ordered.base() != self.state.base
            || ordered.verify_next(self.state.base, previous).is_err()
            || ordered.head().position <= self.state.control_head.position
            || (previous.position == self.state.control_head.position
                && previous != self.state.control_head)
        {
            return Err(Outcome::IntegrityStop);
        }
        Ok(())
    }

    fn judge(
        &self,
        view: &VerifiedAccount,
        descriptor: &OpaqueEvent,
        body: &[u8],
        metadata: &Secret<32>,
        route: Route,
        position: Option<u64>,
    ) -> Result<ControlEffect, Outcome> {
        let state = &self.state;
        // The caller's account view must be this base's copy: anything else
        // is local state that cannot judge, not a fault in the control.
        if view.is_stopped() || view.id() != state.creator || view.head() != state.account {
            return Err(Outcome::UnavailablePause);
        }
        let ctx = SpineContext {
            state,
            account: view,
            position,
        };
        let signed = verify_signed(&ctx, route, descriptor, metadata)?;
        match judge(&ctx, &signed, descriptor, body, metadata, None)? {
            Judged::Control {
                account: Some(account),
                change: Some(change),
                epoch_id,
                ..
            } => Ok(ControlEffect {
                digest: descriptor.digest(),
                epoch_after: epoch_id,
                account_head_after: account.head(),
                change: if change[ACCOUNT_TAG] == REMOVE_SELF {
                    ControlChange::RemoveSelf
                } else {
                    ControlChange::AddDevice
                },
                account_event: change,
                floor_after: state.floor.max(signed.version),
                seen_position: signed.seen.position,
                judged_control_digest: state.control_digest,
                judged_account_head: state.account,
            }),
            // The route check refuses content, and only genesis is a
            // control without an account change.
            _ => Err(Outcome::Rejected),
        }
    }
}

/// The spine's knowledge for one judgement: the last valid control, the
/// control head and, once ordered, the control's own position.
struct SpineContext<'a> {
    state: &'a ControlState,
    account: &'a VerifiedAccount,
    position: Option<u64>,
}
impl SignedContext for SpineContext<'_> {
    fn base(&self) -> BaseId {
        self.state.base
    }
    fn genesis(&self) -> bool {
        false
    }
    fn account(&self) -> &VerifiedAccount {
        self.account
    }
    fn metadata_id(&self) -> Option<[u8; 32]> {
        Some(self.state.metadata_id)
    }
    fn epoch_id(&self) -> Option<[u8; 32]> {
        self.state.epoch
    }
    fn floor(&self) -> u16 {
        self.state.floor
    }
    fn hosting_root(&self) -> Option<[u8; 32]> {
        Some(self.state.hosting_root)
    }
    fn last_control(&self) -> [u8; 32] {
        self.state.control_digest
    }
    fn id_used(&self, _: [u8; 32]) -> Result<bool, Outcome> {
        Ok(false)
    }
    fn known_head(&self, position: u64) -> Result<Option<Head>, Outcome> {
        Ok([self.state.control, self.state.control_head]
            .into_iter()
            .find(|head| head.position == position))
    }
    /// Every position from the last valid control up to this event's own
    /// had that control and the account head it left.
    fn saw(&self, claim: Seen) -> Result<bool, Outcome> {
        let position = claim.head.position;
        if position < self.state.control.position
            || self.position.is_some_and(|own| position >= own)
            || self
                .known_head(position)?
                .is_some_and(|known| known != claim.head)
        {
            return Ok(false);
        }
        Ok(claim.control == self.state.control_digest && claim.account == self.state.account)
    }
}

/// A base control copying one account event into the base, for its
/// author's control key to sign outside this library.
pub struct ControlSigningRequest(EventSigningRequest);
impl ControlSigningRequest {
    pub fn signing_bytes(&self) -> &[u8] {
        self.0.signing_bytes()
    }
    pub fn expected_key(&self) -> &[u8; 32] {
        self.0.expected_key()
    }
    pub fn finish(self, signature: [u8; 64]) -> Result<Encoded, Error> {
        self.0.finish(signature)
    }
}

/// Prepare the base control that copies `account_event`, which must be the
/// next account event after `base_account`, the base's copy of the account.
/// `seen` is what the author's verified history of the base had applied at
/// its head and `receipt` the hosting receipt for that head. The author must
/// be active in the base's copy; it signs with its control key.
pub fn prepare_account_change(
    base: BaseId,
    base_account: &VerifiedAccount,
    device: DeviceId,
    metadata: &Secret<32>,
    seen: Seen,
    receipt: [u8; RECEIPT_LEN],
    account_event: &[u8],
) -> Result<ControlSigningRequest, Error> {
    if seen.head.position == 0 || seen.account != base_account.head() {
        return Err(Error::Invalid);
    }
    let expected = *base_account
        .active_device(device)
        .map_err(|_| Error::Invalid)?
        .control();
    account_change(base_account, account_event, true).map_err(|_| Error::Invalid)?;
    Ok(ControlSigningRequest(prepare_seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: base.0,
            audience: [0; 32],
            epoch: key_id(metadata),
            event_id: EventId(random()),
            account: base_account.id(),
            device,
            account_head: seen.account,
            seen: seen.head,
            seen_control: seen.control,
            class: CLASS_CONTROL,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt,
        },
        Payload {
            kind: ACCOUNT_CHANGE,
            data: account_event,
        },
        expected,
        metadata,
        None,
    )?))
}
