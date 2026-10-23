//! Bounded account-home reads: authenticate the source and every outer
//! opening before an inner apply or a durable checkpoint.
use crate::{
    Shared,
    authz::Authz,
    outbox::{Fail, Link, usable_until},
    puller::ordered_events,
};
use bh_account::{AccountEvent, Head as AccountHead};
use bh_authz_proto::{FromService, ToService, account_log_id, account_log_unwrap};
use bh_sync::{
    BaseId, Digest, Head, OrderState, Route,
    evidence::{AcceptedHead, OrderingConfirmation, TimeBounds},
    permit::{self, LogId, LogKind, Scope},
    wire::{Request, Response},
};
use tokio::time::Instant;

pub(crate) enum Session<'a> {
    Public,
    Normal,
    At(&'a Authz, Option<AccountHead>),
    Exclusive,
}

pub(crate) struct VerifiedEvent {
    pub original: Vec<u8>,
    pub body: Option<Digest>,
    pub opening: OrderState,
    /// A timed account owner can consume this verified bound.
    pub time: Option<TimeBounds>,
    pub proof: Option<OrderingConfirmation>,
}

pub(crate) struct Page {
    pub events: Vec<VerifiedEvent>,
    /// Authenticated independently; it is not this page's tail unless its
    /// original head and confirmation match this page's verified last item.
    pub accepted: AcceptedHead,
}

/// The caller supplies a pinned genesis and prior canonical opening, with
/// the verified time of the entry at that opening when it has one; a
/// service-issued permit is never accepted as a substitute for either.
/// Transport/unavailability is not a forged removal and must not raise an
/// alert; an invalid response or proof from an attested source does.
pub(crate) enum EvidenceFailure {
    Unavailable(Fail),
    Invalid,
}
impl EvidenceFailure {
    fn fail(self) -> Fail {
        match self {
            Self::Unavailable(fail) => fail,
            Self::Invalid => Fail::Network,
        }
    }
}

#[allow(clippy::too_many_arguments)] // One read's independently pinned inputs.
pub(crate) async fn read(
    shared: &Shared,
    link: &mut Link,
    genesis: &[u8],
    before: OrderState,
    prior: Option<TimeBounds>,
    last: u64,
    session: Session<'_>,
) -> Result<Page, Fail> {
    read_internal(shared, link, genesis, before, prior, last, session)
        .await
        .map_err(EvidenceFailure::fail)
}

pub(crate) async fn read_public(
    shared: &Shared,
    link: &mut Link,
    genesis: &[u8],
    before: OrderState,
    prior: Option<TimeBounds>,
    last: u64,
) -> Result<Page, EvidenceFailure> {
    read_internal(shared, link, genesis, before, prior, last, Session::Public).await
}

#[allow(clippy::too_many_arguments)]
async fn read_internal(
    shared: &Shared,
    link: &mut Link,
    genesis: &[u8],
    before: OrderState,
    prior: Option<TimeBounds>,
    last: u64,
    session: Session<'_>,
) -> Result<Page, EvidenceFailure> {
    let log = LogId {
        kind: LogKind::Account,
        id: account_log_id(genesis).map_err(|_| EvidenceFailure::Invalid)?,
    };
    let first = before
        .position()
        .checked_add(1)
        .ok_or(EvidenceFailure::Invalid)?;
    if last < first || last - first >= 64 {
        return Err(EvidenceFailure::Invalid);
    }
    let challenge: [u8; 32] = bh_crypto::random();
    let request = ToService::ReadAccountEvidence {
        genesis: genesis.to_vec(),
        first,
        last,
        challenge,
    };
    let requested_at = Instant::now();
    let answer = match session {
        Session::Public => shared.authz.public_evidence(shared, request).await,
        Session::Normal => shared.authz.request(shared, request).await,
        Session::At(authz, at) => match authz.session_at(shared, at).await {
            Ok(mut session) => session.ask(request).await,
            Err(error) => Err(error),
        },
        Session::Exclusive => match shared.authz.session(shared).await {
            Ok(mut session) => session.ask(request).await,
            Err(error) => Err(error),
        },
    }
    .map_err(|error| EvidenceFailure::Unavailable(error.into()))?;
    let FromService::AccountEvidence {
        events_permit,
        confirmations,
        head,
    } = answer
    else {
        return Err(EvidenceFailure::Unavailable(Fail::from_answer(&answer)));
    };
    let root = shared.endpoint.hosting_root;
    verify_permit(root, &events_permit, requested_at, log, first, last)?;
    let accepted = AcceptedHead::verify(&head, &root, log, &challenge)
        .map_err(|_| EvidenceFailure::Invalid)?;
    let response = link
        .data(shared)
        .await
        .map_err(EvidenceFailure::Unavailable)?
        .ask(|id| Request::Read {
            id,
            permit: events_permit,
        })
        .await
        .map_err(|_| EvidenceFailure::Unavailable(Fail::Network))?;
    let Response::Events {
        items,
        receipt: None,
        coverage: None,
        ..
    } = response
    else {
        return Err(EvidenceFailure::Unavailable(Fail::from_response(&response)));
    };
    verified_page(
        Source { root, log },
        genesis,
        before,
        prior,
        last,
        items,
        confirmations,
        accepted,
    )
}

/// Judge one answer's entries after its permit, challenge and transport were
/// authenticated. Entries the edge serves past the challenged head may
/// postdate the answer, so their missing confirmations are an honest race to
/// retry with the link kept: dropping and reopening it would show a network
/// wait in the middle of a renewal that is in fact progressing. The same page
/// cut at that head must still verify: a gap at or below it contradicts the
/// head.
#[allow(clippy::too_many_arguments)] // One answer's independently verified pieces.
fn verified_page(
    source: Source,
    genesis: &[u8],
    before: OrderState,
    prior: Option<TimeBounds>,
    last: u64,
    items: Vec<(Vec<u8>, Vec<u8>)>,
    confirmations: Vec<Vec<u8>>,
    accepted: AcceptedHead,
) -> Result<Page, EvidenceFailure> {
    let first = before
        .position()
        .checked_add(1)
        .ok_or(EvidenceFailure::Invalid)?;
    if items.len() as u64 > last - first + 1 {
        return Err(EvidenceFailure::Invalid);
    }
    let within_head = accepted
        .original_head
        .position
        .saturating_sub(before.position())
        .min(items.len() as u64) as usize;
    let (head_items, head_confirmations) = (items[..within_head].to_vec(), confirmations.clone());
    verify_page(
        source,
        genesis,
        before,
        prior,
        last,
        items,
        confirmations,
        accepted,
    )
    .map_err(|fail| match fail {
        Fail::Missing
            if verify_page(
                source,
                genesis,
                before,
                prior,
                last,
                head_items,
                head_confirmations,
                accepted,
            )
            .is_ok() =>
        {
            EvidenceFailure::Unavailable(Fail::Retry)
        }
        _ => EvidenceFailure::Invalid,
    })
}

fn verify_permit(
    root: [u8; 32],
    signed: &[u8],
    requested_at: Instant,
    log: LogId,
    first: u64,
    last: u64,
) -> Result<(), EvidenceFailure> {
    let issued = permit::issued_ms(signed).map_err(|_| EvidenceFailure::Invalid)?;
    let verified = permit::verify(root, signed, issued).map_err(|_| EvidenceFailure::Invalid)?;
    if verified.scope != (Scope::ReadEvents { log, first, last }) {
        return Err(EvidenceFailure::Invalid);
    }
    usable_until(root, signed, requested_at).ok_or(EvidenceFailure::Unavailable(Fail::Network))?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Source {
    root: [u8; 32],
    log: LogId,
}

#[allow(clippy::too_many_arguments)] // One page's independently pinned inputs.
fn verify_page(
    Source { root, log }: Source,
    genesis: &[u8],
    before: OrderState,
    prior: Option<TimeBounds>,
    last: u64,
    items: Vec<(Vec<u8>, Vec<u8>)>,
    confirmations: Vec<Vec<u8>>,
    accepted: AcceptedHead,
) -> Result<Page, Fail> {
    let first = before.position().checked_add(1).ok_or(Fail::Network)?;
    if last < first || last - first >= 64 || items.len() as u64 > last - first + 1 {
        return Err(Fail::Network);
    }
    let ordered = ordered_events(BaseId(log.id), first, &items)?;
    // The service lists only the positions it holds a confirmation for:
    // pair each proof with the position it claims, so a gap is Missing.
    let mut proofs = std::collections::BTreeMap::new();
    for bytes in confirmations {
        let proof = OrderingConfirmation::decode(&bytes).map_err(|_| Fail::Network)?;
        if proofs
            .insert(proof.claim().original_head.position, proof)
            .is_some()
        {
            return Err(Fail::Network);
        }
    }
    let mut events = Vec::with_capacity(ordered.len());
    let mut outer = before;
    let mut inner_previous: Option<Head> = None;
    // Bounds stay monotone from the caller's last verified entry on.
    let mut prior_time = prior;
    for (commitment, wrapper) in ordered {
        if commitment.before() != outer
            || commitment
                .verify_next(BaseId(log.id), outer.head(BaseId(log.id)))
                .is_err()
            || commitment.route() != Route::Control
        {
            return Err(Fail::Network);
        }
        let (original, body) = account_log_unwrap(&wrapper).map_err(|_| Fail::Network)?;
        let position = commitment.head().position;
        let actual = Head {
            position,
            hash: Digest(bh_crypto::hash(original)),
        };
        let (time, proof) = if position == 1 {
            if before != OrderState::EMPTY || original != genesis || body.is_some() {
                return Err(Fail::Network);
            }
            (None, None)
        } else {
            let proof = proofs.remove(&position).ok_or(Fail::Missing)?;
            let claim = proof
                .verify_for(&root, original, body)
                .map_err(|_| Fail::Network)?;
            // The certificate authenticates the original digest but does not
            // itself bind its predecessor. Decode supported originals with the
            // account library; the owner still verifies the author and checks
            // this signed predecessor against its independently held history.
            // An unknown event version must reach that owner's Unsupported
            // pause, not be accepted as a supported header by this reader.
            let original_previous = match AccountEvent::decode(original) {
                Ok(event) => Some(event.previous_head()),
                // Invalid or unsupported originals are never persisted: the
                // owner rejects or pauses them after the outer evidence check.
                Err(_) => None,
            };
            let preceding = inner_previous.unwrap_or(claim.original_previous);
            if original_previous.is_some_and(|previous| {
                previous.position.checked_add(1) != Some(position)
                    || previous.hash != claim.original_previous.hash.0
            }) || claim.log != log
                || (position == 2
                    && claim.original_previous.hash != Digest(bh_crypto::hash(genesis)))
                || claim.original_previous != preceding
                || claim.original_previous.position.checked_add(1) != Some(position)
                || claim.original_head != actual
                || claim.ordered != commitment.after().head(BaseId(log.id))
                || prior_time.is_some_and(|prior| {
                    claim.bounds.earliest_ms < prior.earliest_ms
                        || claim.bounds.latest_ms < prior.latest_ms
                })
            {
                return Err(Fail::Network);
            }
            prior_time = Some(claim.bounds);
            (Some(claim.bounds), Some(proof))
        };
        inner_previous = Some(actual);
        outer = commitment.after();
        events.push(VerifiedEvent {
            original: original.to_vec(),
            body,
            opening: outer,
            time,
            proof,
        });
    }
    // No confirmation can be attributed to an unreturned wrapper, including
    // one on a short page; the accepted head alone cannot fill that gap.
    if !proofs.is_empty() {
        return Err(Fail::Network);
    }
    if let Some(at) = events
        .iter()
        .find(|event| event.opening.position() == accepted.original_head.position)
    {
        match_accepted_event(accepted, at)?;
    }
    Ok(Page { events, accepted })
}

/// Reconcile every still-ahead authenticated claim with its exact returned
/// original and confirmation. A newer signed response cannot replace an
/// unresolved earlier one. Only unmatched ahead claims are retained; memory
/// is proportional to outstanding observations within this bounded read.
pub(crate) fn match_page_claims(
    pending: &mut Vec<AcceptedHead>,
    events: &[VerifiedEvent],
    accepted: AcceptedHead,
) -> Result<Vec<(usize, AcceptedHead)>, Fail> {
    if !pending.contains(&accepted) {
        pending.push(accepted);
    }
    let mut reached = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let mut i = 0;
        while i < pending.len() {
            if pending[i].original_head.position == event.opening.position() {
                match_accepted_event(pending[i], event)?;
                reached.push((index, pending.remove(i)));
            } else {
                i += 1;
            }
        }
    }
    Ok(reached)
}

/// Compare the challenged head with the actual original and independent
/// confirmation at that position, including when it was returned later.
pub(crate) fn match_accepted_event(
    accepted: AcceptedHead,
    event: &VerifiedEvent,
) -> Result<(), Fail> {
    let actual = Head {
        position: event.opening.position(),
        hash: Digest(bh_crypto::hash(&event.original)),
    };
    if accepted.original_head != actual
        || accepted.evidence
            != event
                .proof
                .as_ref()
                .map_or([0; 32], OrderingConfirmation::commitment)
        || event.time.is_some_and(|time| {
            accepted.bounds.earliest_ms < time.earliest_ms
                || accepted.bounds.latest_ms < time.latest_ms
        })
    {
        return Err(Fail::Network);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{outbox::condition_of, status::Condition};
    use bh_authz_proto::account_log_wrap;
    use bh_crypto::SigningKey;
    use bh_sync::{
        Commitment,
        evidence::{ConfirmationClaim, original_digest},
        permit::Permit,
    };

    struct Fixture {
        root: [u8; 32],
        key: SigningKey,
        certificate: [u8; bh_sync::receipt::CERTIFICATE_LEN],
        log: LogId,
        originals: [Vec<u8>; 3],
        items: Vec<(Vec<u8>, Vec<u8>)>,
        proofs: Vec<Vec<u8>>,
        accepted: AcceptedHead,
    }
    fn fixture() -> Fixture {
        let authority = SigningKey::generate();
        let key = SigningKey::generate();
        let root = authority.public();
        let certificate = permit::certify(&authority, key.public());
        let originals = [
            b"genesis".to_vec(),
            b"setup device".to_vec(),
            b"setup recovery".to_vec(),
        ];
        let log = LogId {
            kind: LogKind::Account,
            id: account_log_id(&originals[0]).unwrap(),
        };
        let bounds = TimeBounds {
            earliest_ms: 9,
            latest_ms: 10,
        };
        let mut order = OrderState::EMPTY;
        let mut previous = Head::EMPTY;
        let mut proofs = Vec::new();
        let mut items = Vec::new();
        for (index, original) in originals.iter().enumerate() {
            let wrapper = account_log_wrap(original, None).unwrap();
            let commitment =
                Commitment::order(BaseId(log.id), order, &wrapper, Route::Control).unwrap();
            let inner = Head {
                position: index as u64 + 1,
                hash: Digest(bh_crypto::hash(original)),
            };
            if index > 0 {
                proofs.push(
                    OrderingConfirmation::sign(
                        &key,
                        &certificate,
                        ConfirmationClaim {
                            log,
                            original: original_digest(original),
                            original_previous: previous,
                            original_head: inner,
                            body: None,
                            ordered: commitment.after().head(BaseId(log.id)),
                            bounds,
                        },
                    )
                    .encode()
                    .to_vec(),
                );
            }
            previous = inner;
            order = commitment.after();
            items.push((commitment.encode(), wrapper.encode()));
        }
        let challenged = AcceptedHead::sign(
            &key,
            &certificate,
            log,
            [7; 32],
            previous,
            bh_crypto::hash(proofs.last().unwrap()),
            bounds,
        );
        let accepted = AcceptedHead::verify(&challenged, &root, log, &[7; 32]).unwrap();
        Fixture {
            root,
            key,
            certificate,
            log,
            originals,
            items,
            proofs,
            accepted,
        }
    }
    fn check(
        f: &Fixture,
        items: Vec<(Vec<u8>, Vec<u8>)>,
        proofs: Vec<Vec<u8>>,
    ) -> Result<Page, Fail> {
        verify_page(
            Source {
                root: f.root,
                log: f.log,
            },
            &f.originals[0],
            OrderState::EMPTY,
            None,
            64,
            items,
            proofs,
            f.accepted,
        )
    }
    #[test]
    fn each_returned_wrapper_needs_its_signed_body_and_exact_ordered_head() {
        let f = fixture();
        assert_eq!(
            check(&f, f.items.clone(), f.proofs.clone())
                .unwrap()
                .events
                .len(),
            3
        );
        assert!(matches!(
            check(&f, f.items.clone(), f.proofs[..1].to_vec()),
            Err(Fail::Missing)
        ));
        let mut duplicate = f.proofs.clone();
        duplicate.insert(0, duplicate[0].clone());
        assert!(check(&f, f.items.clone(), duplicate).is_err());
        let mut substituted = f.proofs.clone();
        substituted[0] = substituted[1].clone();
        assert!(check(&f, f.items.clone(), substituted).is_err());
        let mut extra = f.proofs.clone();
        extra.push(f.proofs[0].clone());
        assert!(check(&f, f.items.clone(), extra).is_err());
        let mut wrong_body = f.items.clone();
        let wrapper = account_log_wrap(&f.originals[1], Some(Digest([12; 32]))).unwrap();
        // Recompute from the genuine genesis, and re-chain the third item.
        let genesis = Commitment::decode(&f.items[0].0).unwrap();
        let second =
            Commitment::order(BaseId(f.log.id), genesis.after(), &wrapper, Route::Control).unwrap();
        let third_wrapper = account_log_wrap(&f.originals[2], None).unwrap();
        let third = Commitment::order(
            BaseId(f.log.id),
            second.after(),
            &third_wrapper,
            Route::Control,
        )
        .unwrap();
        wrong_body[1] = (second.encode(), wrapper.encode());
        wrong_body[2] = (third.encode(), third_wrapper.encode());
        assert!(check(&f, wrong_body, f.proofs.clone()).is_err());
        let original = &f.originals[1];
        let prior = Head {
            position: 1,
            hash: Digest(bh_crypto::hash(&f.originals[0])),
        };
        let mut wrong_head = f.proofs.clone();
        let claim = ConfirmationClaim {
            log: f.log,
            original: original_digest(original),
            original_previous: prior,
            original_head: Head {
                position: 2,
                hash: Digest(bh_crypto::hash(original)),
            },
            body: None,
            ordered: Head {
                position: 2,
                hash: Digest([99; 32]),
            },
            bounds: TimeBounds {
                earliest_ms: 9,
                latest_ms: 10,
            },
        };
        wrong_head[0] = OrderingConfirmation::sign(&f.key, &f.certificate, claim)
            .encode()
            .to_vec();
        assert!(check(&f, f.items.clone(), wrong_head).is_err());
        let third = &f.originals[2];
        let mut regressed = f.proofs.clone();
        regressed[1] = OrderingConfirmation::sign(
            &f.key,
            &f.certificate,
            ConfirmationClaim {
                log: f.log,
                original: original_digest(third),
                original_previous: Head {
                    position: 2,
                    hash: Digest(bh_crypto::hash(&f.originals[1])),
                },
                original_head: Head {
                    position: 3,
                    hash: Digest(bh_crypto::hash(third)),
                },
                body: None,
                ordered: Commitment::decode(&f.items[2].0)
                    .unwrap()
                    .after()
                    .head(BaseId(f.log.id)),
                bounds: TimeBounds {
                    earliest_ms: 8,
                    latest_ms: 9,
                },
            },
        )
        .encode()
        .to_vec();
        assert!(check(&f, f.items.clone(), regressed).is_err());
    }
    #[test]
    fn genesis_is_the_only_proofless_entry_and_ahead_head_is_not_the_page_tail() {
        let f = fixture();
        let genesis = check(&f, f.items[..1].to_vec(), Vec::new()).unwrap();
        assert_eq!(genesis.events[0].opening.position(), 1);
        assert!(genesis.events[0].proof.is_none());
        assert_eq!(genesis.accepted.original_head.position, 3);
        assert!(matches!(
            check(&f, f.items[..2].to_vec(), Vec::new()),
            Err(Fail::Missing)
        ));
        assert!(
            verify_page(
                Source {
                    root: f.root,
                    log: f.log
                },
                b"other pinned genesis",
                OrderState::EMPTY,
                None,
                64,
                f.items[..1].to_vec(),
                Vec::new(),
                f.accepted
            )
            .is_err()
        );
        let wrong_tail = AcceptedHead {
            evidence: [42; 32],
            ..f.accepted
        };
        assert!(
            verify_page(
                Source {
                    root: f.root,
                    log: f.log
                },
                &f.originals[0],
                OrderState::EMPTY,
                None,
                64,
                f.items.clone(),
                f.proofs.clone(),
                wrong_tail
            )
            .is_err()
        );
        let ahead = AcceptedHead {
            original_head: Head {
                position: 4,
                hash: Digest([43; 32]),
            },
            ..f.accepted
        };
        assert_eq!(
            verify_page(
                Source {
                    root: f.root,
                    log: f.log
                },
                &f.originals[0],
                OrderState::EMPTY,
                None,
                64,
                f.items.clone(),
                f.proofs.clone(),
                ahead
            )
            .unwrap()
            .events
            .len(),
            3
        );
    }
    #[test]
    fn accepted_head_inside_a_page_must_match_its_exact_confirmation() {
        let f = fixture();
        let second = Head {
            position: 2,
            hash: Digest(bh_crypto::hash(&f.originals[1])),
        };
        let bad = AcceptedHead {
            original_head: second,
            evidence: f.accepted.evidence,
            ..f.accepted
        };
        assert!(
            verify_page(
                Source {
                    root: f.root,
                    log: f.log
                },
                &f.originals[0],
                OrderState::EMPTY,
                None,
                64,
                f.items.clone(),
                f.proofs.clone(),
                bad,
            )
            .is_err(),
            "the third proof cannot attest the second original"
        );
    }
    #[test]
    fn missing_full_initial_proof_page_is_not_excused_by_a_valid_later_head() {
        let f = fixture();
        let mut items = f.items[..1].to_vec();
        let mut previous = Head {
            position: 1,
            hash: Digest(bh_crypto::hash(&f.originals[0])),
        };
        let mut outer = Commitment::decode(&items[0].0).unwrap().after();
        let mut last_proof = None;
        for position in 2..=65 {
            let original = format!("original at {position}").into_bytes();
            let wrapper = account_log_wrap(&original, None).unwrap();
            let commitment =
                Commitment::order(BaseId(f.log.id), outer, &wrapper, Route::Control).unwrap();
            let head = Head {
                position,
                hash: Digest(bh_crypto::hash(&original)),
            };
            let proof = OrderingConfirmation::sign(
                &f.key,
                &f.certificate,
                ConfirmationClaim {
                    log: f.log,
                    original: original_digest(&original),
                    original_previous: previous,
                    original_head: head,
                    body: None,
                    ordered: commitment.after().head(BaseId(f.log.id)),
                    bounds: TimeBounds {
                        earliest_ms: 9,
                        latest_ms: 10,
                    },
                },
            );
            previous = head;
            outer = commitment.after();
            items.push((commitment.encode(), wrapper.encode()));
            last_proof = Some(proof);
        }
        let last = last_proof.unwrap();
        let challenged = AcceptedHead::sign(
            &f.key,
            &f.certificate,
            f.log,
            [7; 32],
            previous,
            last.commitment(),
            TimeBounds {
                earliest_ms: 9,
                latest_ms: 10,
            },
        );
        let accepted = AcceptedHead::verify(&challenged, &f.root, f.log, &[7; 32]).unwrap();
        assert!(matches!(
            verify_page(
                Source {
                    root: f.root,
                    log: f.log
                },
                &f.originals[0],
                OrderState::EMPTY,
                None,
                64,
                items[..64].to_vec(),
                vec![],
                accepted
            ),
            Err(Fail::Missing)
        ));
        // A valid later signed proof does not bridge the omitted prefix.
        assert!(matches!(
            verify_page(
                Source {
                    root: f.root,
                    log: f.log
                },
                &f.originals[0],
                OrderState::EMPTY,
                None,
                64,
                items[..64].to_vec(),
                vec![last.encode().to_vec()],
                accepted
            ),
            Err(Fail::Missing) | Err(Fail::Network)
        ));
    }
    #[test]
    fn an_entry_past_the_challenged_head_retries_without_the_link() {
        let f = fixture();
        // The edge ordered one entry after the head it challenged, so no
        // confirmation for that entry exists yet; the page is not corrupt.
        let third = Commitment::decode(&f.items[2].0).unwrap();
        let wrapper = account_log_wrap(b"rotation after the answer", None).unwrap();
        let fourth =
            Commitment::order(BaseId(f.log.id), third.after(), &wrapper, Route::Control).unwrap();
        let mut items = f.items.clone();
        items.push((fourth.encode(), wrapper.encode()));
        assert!(matches!(
            verified_page(
                Source {
                    root: f.root,
                    log: f.log,
                },
                &f.originals[0],
                OrderState::EMPTY,
                None,
                64,
                items,
                f.proofs.clone(),
                f.accepted,
            ),
            Err(EvidenceFailure::Unavailable(Fail::Retry))
        ));
        // This race is the middle of a renewal that is progressing, so it keeps
        // the data link and does not read as a network wait.
        assert_eq!(condition_of(Fail::Retry), Condition::Working);
    }
    #[test]
    fn a_gap_before_a_later_proof_is_missing_not_misattributed() {
        let f = fixture();
        // The service skips a position it holds no confirmation for.
        assert!(matches!(
            check(&f, f.items.clone(), f.proofs[1..].to_vec()),
            Err(Fail::Missing)
        ));
        // A later proof listed first still pairs with its own position.
        let mut reversed = f.proofs.clone();
        reversed.reverse();
        assert_eq!(
            check(&f, f.items.clone(), reversed).unwrap().events.len(),
            3
        );
    }
    #[test]
    fn time_bounds_stay_monotone_across_pages() {
        let f = fixture();
        let genesis = Commitment::decode(&f.items[0].0).unwrap().after();
        let page = |prior| {
            verify_page(
                Source {
                    root: f.root,
                    log: f.log,
                },
                &f.originals[0],
                genesis,
                prior,
                64,
                f.items[1..].to_vec(),
                f.proofs.clone(),
                f.accepted,
            )
        };
        let at = |earliest_ms, latest_ms| {
            Some(TimeBounds {
                earliest_ms,
                latest_ms,
            })
        };
        assert_eq!(page(at(9, 10)).unwrap().events.len(), 2);
        assert!(page(at(10, 10)).is_err());
        assert!(page(at(9, 11)).is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn elapsed_permit_lifetime_is_unavailability_not_invalid_evidence() {
        let f = fixture();
        let signed = permit::sign(
            &f.key,
            &f.certificate,
            &Permit {
                scope: Scope::ReadEvents {
                    log: f.log,
                    first: 1,
                    last: 64,
                },
                issued_ms: 100,
                deadline_ms: 30100,
                batch: [3; 16],
            },
        );
        let requested = Instant::now();
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        assert!(matches!(
            verify_permit(f.root, &signed, requested, f.log, 1, 64),
            Err(EvidenceFailure::Unavailable(Fail::Network))
        ));
        assert!(matches!(
            verify_permit([0; 32], &signed, requested, f.log, 1, 64),
            Err(EvidenceFailure::Invalid)
        ));
    }

    #[test]
    fn permit_and_accepted_head_are_bound_to_independent_root_scope_and_challenge() {
        let f = fixture();
        let signed = |log, first, last| {
            permit::sign(
                &f.key,
                &f.certificate,
                &Permit {
                    scope: Scope::ReadEvents { log, first, last },
                    issued_ms: 100,
                    deadline_ms: 30100,
                    batch: [3; 16],
                },
            )
        };
        let at = Instant::now();
        assert!(verify_permit(f.root, &signed(f.log, 1, 64), at, f.log, 1, 64).is_ok());
        assert!(verify_permit([0; 32], &signed(f.log, 1, 64), at, f.log, 1, 64).is_err());
        assert!(
            verify_permit(
                f.root,
                &signed(
                    LogId {
                        id: [3; 32],
                        ..f.log
                    },
                    1,
                    64
                ),
                at,
                f.log,
                1,
                64
            )
            .is_err()
        );
        assert!(verify_permit(f.root, &signed(f.log, 2, 3), at, f.log, 1, 64).is_err());
        let signed = AcceptedHead::sign(
            &f.key,
            &f.certificate,
            f.log,
            [7; 32],
            f.accepted.original_head,
            f.accepted.evidence,
            f.accepted.bounds,
        );
        assert!(AcceptedHead::verify(&signed, &f.root, f.log, &[7; 32]).is_ok());
        assert!(AcceptedHead::verify(&signed, &f.root, f.log, &[8; 32]).is_err());
        assert!(AcceptedHead::verify(&signed, &[0; 32], f.log, &[7; 32]).is_err());
    }
}
