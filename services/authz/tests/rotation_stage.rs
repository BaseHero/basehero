//! A personal-key rotation's body is staged on the account log first and the
//! rotation names it by commitment: the service reads that body back from the
//! edge and judges its exact frame before it permits the append.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::{
    AccountEvent, ConfirmedTime, VerifiedAccount,
    personal::{self, PersonalKey, PreparedRotation},
};
use bh_authz::{
    Connection,
    proto::{
        FromService, LogId, LogKind, RecoveryAttachment, Refusal, ToService, Want,
        account_log_wrap, delivery_body, rotation_body,
    },
};
use bh_sync::{BodyObject, Digest, permit::Scope};
use std::sync::atomic::Ordering;
use support::{claims::*, native::session_as, *};

/// A home whose second device removed itself, so a rotation is due, and the
/// owner's session and verified view at that removal.
struct Due {
    h: Harness,
    service: bh_authz::Service,
    home: Home,
    owner: Connection,
    view: VerifiedAccount,
    reason: u64,
}

fn time(ms: u64) -> Option<ConfirmedTime> {
    Some(ConfirmedTime {
        earliest_ms: ms,
        latest_ms: ms,
    })
}

async fn due() -> Due {
    let h = Harness::new();
    let service = h.service();
    let home = Home::new(&h, &service).await;
    let mut owner = session(&service, &home.signup.account, &home.device).await;
    let mut view = home.signup.account.verified.clone();
    let other = Device::new();
    add(&h, &mut owner, &home, &mut view, &other).await;
    let mut leaving = session_as(
        &service,
        &view,
        &home.signup.account.genesis,
        other.id(),
        |m| other.ordinary.sign(m),
    )
    .await;
    let draft = view.remove_self(other.id()).unwrap();
    let remove = draft
        .finish(other.control.sign(draft.signing_bytes()))
        .unwrap();
    submit(&h, &mut leaving, &home.signup.account, remove.as_bytes()).await;
    confirmed(&mut owner, home.signup.account.log, remove.as_bytes()).await;
    view.apply_timed(remove.as_bytes(), time(h.clock.now()))
        .unwrap();
    Due {
        h,
        service,
        home,
        owner,
        view,
        reason: remove.head().position,
    }
}

/// `new` added by the home's device, ordered and confirmed, and `view`
/// advanced past it.
async fn add(
    h: &Harness,
    owner: &mut Connection,
    home: &Home,
    view: &mut VerifiedAccount,
    new: &Device,
) -> AccountEvent {
    let draft = view.add_device(home.device.id(), new.keys.clone()).unwrap();
    let event = draft
        .finish(home.device.control.sign(draft.signing_bytes()))
        .unwrap();
    submit(h, owner, &home.signup.account, event.as_bytes()).await;
    confirmed(owner, home.signup.account.log, event.as_bytes()).await;
    view.apply_timed(event.as_bytes(), time(h.clock.now()))
        .unwrap();
    event
}

async fn confirmed(c: &mut Connection, log: LogId, original: &[u8]) {
    let event = account_log_wrap(original, None).unwrap().digest();
    let answer = c
        .handle(ToService::ConfirmControl {
            log,
            event,
            challenge: [7; 32],
        })
        .await;
    assert!(
        matches!(answer, FromService::Confirmed { .. }),
        "{answer:?}"
    );
}

impl Due {
    fn log(&self) -> LogId {
        self.home.signup.account.log
    }
    /// The home's device's rotation, on `view`, for `prepared`.
    fn rotation(&self, view: &VerifiedAccount, prepared: &PreparedRotation) -> AccountEvent {
        let draft = view
            .rotate_personal(
                self.home.device.id(),
                self.reason,
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .unwrap();
        draft
            .finish(self.home.device.ordinary.sign(draft.signing_bytes()))
            .unwrap()
    }
    async fn submit(
        &mut self,
        event: &AccountEvent,
        seal: &[u8],
        body: Option<Digest>,
    ) -> FromService {
        self.owner
            .handle(ToService::SubmitControl {
                log: self.log(),
                event: event.as_bytes().to_vec(),
                delivery: None,
                attachment: Some(Box::new(RecoveryAttachment {
                    record: None,
                    recovery_seal: seal.to_vec(),
                    rotation_body: body,
                })),
            })
            .await
    }
    fn pending(&self) -> i64 {
        rusqlite::Connection::open(self.h.dir.path().join("authz.sqlite"))
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM pending_attachments WHERE account=?1",
                [self.home.signup.account.id.0.as_slice()],
                |r| r.get(0),
            )
            .unwrap()
    }
}

fn refused(answer: &FromService, reason: Refusal) {
    assert!(
        matches!(answer, FromService::Refused { reason: r } if *r == reason),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_rotation_names_its_staged_body_and_gets_only_its_append() {
    let mut d = due().await;
    let prepared = personal::prepare_rotation(&d.view, &PersonalKey::generate()).unwrap();
    let rotation = d.rotation(&d.view, &prepared);
    let log = d.log();
    let commitment = stage_rotation(&d.h, &mut d.owner, log, &prepared.body).await;
    assert_eq!(
        commitment,
        rotation_body(&prepared.body).unwrap().commitment()
    );
    let answer = d
        .submit(&rotation, &prepared.recovery_seal, Some(commitment))
        .await;
    let FromService::Permits { items } = &answer else {
        panic!("{answer:?}")
    };
    let wrapped = account_log_wrap(rotation.as_bytes(), Some(commitment)).unwrap();
    let [append] = <[_; 1]>::try_from(items.clone()).unwrap();
    let append = append.unwrap();
    assert!(matches!(
        d.h.permit(&append).scope,
        Scope::Append { log: l, event, body: Some(body), .. }
            if l == log && event == wrapped.digest() && body == commitment
    ));
    // The raw frame read back is what the service holds for the follow.
    let held: Vec<u8> = rusqlite::Connection::open(d.h.dir.path().join("authz.sqlite"))
        .unwrap()
        .query_row(
            "SELECT rotation_body FROM pending_attachments WHERE account=?1",
            [d.home.signup.account.id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(held, prepared.body);
    d.h.edge.append(&append, &wrapped).unwrap();
    let answer = d
        .owner
        .handle(ToService::ConfirmControl {
            log,
            event: wrapped.digest(),
            challenge: [9; 32],
        })
        .await;
    assert!(
        matches!(answer, FromService::Confirmed { .. }),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_lost_submit_answer_resubmits_the_same_commitment_for_the_same_append() {
    let mut d = due().await;
    let prepared = personal::prepare_rotation(&d.view, &PersonalKey::generate()).unwrap();
    let rotation = d.rotation(&d.view, &prepared);
    let log = d.log();
    let commitment = stage_rotation(&d.h, &mut d.owner, log, &prepared.body).await;
    let first = d
        .submit(&rotation, &prepared.recovery_seal, Some(commitment))
        .await;
    // The answer was lost: the device stages the same bytes again and
    // submits the same commitment.
    assert_eq!(
        stage_rotation(&d.h, &mut d.owner, log, &prepared.body).await,
        commitment
    );
    let second = d
        .submit(&rotation, &prepared.recovery_seal, Some(commitment))
        .await;
    let scope = |answer: &FromService| {
        let FromService::Permits { items } = answer else {
            panic!("{answer:?}")
        };
        assert_eq!(items.len(), 1);
        d.h.permit(items[0].as_ref().unwrap()).scope
    };
    assert_eq!(scope(&first), scope(&second));
    assert_eq!(d.pending(), 1);
}

#[tokio::test]
async fn a_staged_body_that_omits_an_active_device_gets_no_append() {
    let mut d = due().await;
    // Prepared before a third device joined: the body leaves it out.
    let prepared = personal::prepare_rotation(&d.view, &PersonalKey::generate()).unwrap();
    let mut grown = d.view.clone();
    let third = Device::new();
    let (h, home) = (&d.h, &d.home);
    add(h, &mut d.owner, home, &mut grown, &third).await;
    let head = d.h.edge.head(d.log());
    let rotation = d.rotation(&grown, &prepared);
    let log = d.log();
    let commitment = stage_rotation(&d.h, &mut d.owner, log, &prepared.body).await;
    let answer = d
        .submit(&rotation, &prepared.recovery_seal, Some(commitment))
        .await;
    refused(&answer, Refusal::Invalid);
    assert_eq!(d.pending(), 0);
    assert_eq!(d.h.edge.head(d.log()), head);
    // Sealed to every active device, the same rotation is permitted.
    let complete = personal::prepare_rotation(&grown, &PersonalKey::generate()).unwrap();
    let rotation = d.rotation(&grown, &complete);
    let commitment = stage_rotation(&d.h, &mut d.owner, log, &complete.body).await;
    let answer = d
        .submit(&rotation, &complete.recovery_seal, Some(commitment))
        .await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
}

#[tokio::test]
async fn a_missing_wrong_or_unserved_commitment_gets_no_append() {
    let mut d = due().await;
    let prepared = personal::prepare_rotation(&d.view, &PersonalKey::generate()).unwrap();
    let rotation = d.rotation(&d.view, &prepared);
    let log = d.log();
    let seal = prepared.recovery_seal.clone();
    // No commitment at all.
    refused(&d.submit(&rotation, &seal, None).await, Refusal::Invalid);
    // A staged body that is not a rotation transport: a plain body and a
    // delivery body holding the same frame.
    let plain = stage_body(&d.h, &mut d.owner, log, &[3; 1024]).await;
    refused(
        &d.submit(&rotation, &seal, Some(plain)).await,
        Refusal::Invalid,
    );
    let delivery = delivery_body(&prepared.body).unwrap();
    let delivery = stage_body(&d.h, &mut d.owner, log, delivery.bytes()).await;
    refused(
        &d.submit(&rotation, &seal, Some(delivery)).await,
        Refusal::Invalid,
    );
    // Another rotation's genuine body, which the event does not sign.
    let other = personal::prepare_rotation(&d.view, &PersonalKey::generate()).unwrap();
    let other = stage_rotation(&d.h, &mut d.owner, log, &other.body).await;
    refused(
        &d.submit(&rotation, &seal, Some(other)).await,
        Refusal::Invalid,
    );
    // Never staged: the edge cannot serve it, so the device stages again.
    let unstaged = rotation_body(&prepared.body).unwrap().commitment();
    assert_eq!(
        d.submit(&rotation, &seal, Some(unstaged)).await,
        FromService::Unavailable
    );
    let commitment = stage_rotation(&d.h, &mut d.owner, log, &prepared.body).await;
    // An edge that is down, or serves other bytes under the commitment.
    d.h.edge.down.store(true, Ordering::SeqCst);
    assert_eq!(
        d.submit(&rotation, &seal, Some(commitment)).await,
        FromService::Unavailable
    );
    d.h.edge.down.store(false, Ordering::SeqCst);
    d.h.edge.corrupt_body.store(true, Ordering::SeqCst);
    assert_eq!(
        d.submit(&rotation, &seal, Some(commitment)).await,
        FromService::Unavailable
    );
    d.h.edge.corrupt_body.store(false, Ordering::SeqCst);
    assert_eq!(d.pending(), 0);
    let answer = d.submit(&rotation, &seal, Some(commitment)).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
}

#[tokio::test]
async fn a_device_stages_only_on_its_own_account_log_and_never_reads_a_staged_body() {
    let mut d = due().await;
    let other = Home::new(&d.h, &d.service).await;
    let body = BodyObject::new(vec![5; 1024]).unwrap();
    let stage = |log| ToService::Permits {
        items: vec![Want::Stage {
            log,
            body: body.commitment(),
            len: 1024,
        }],
    };
    let answer = d.owner.handle(stage(other.signup.account.log)).await;
    assert_eq!(
        answer,
        FromService::Permits {
            items: vec![Err(Refusal::Unknown)]
        }
    );
    let unknown = LogId {
        kind: LogKind::Account,
        id: [9; 32],
    };
    let answer = d.owner.handle(stage(unknown)).await;
    assert_eq!(
        answer,
        FromService::Permits {
            items: vec![Err(Refusal::Unknown)]
        }
    );
    // Its own log: staged, but a device can never read it back unordered.
    let log = d.log();
    let prepared = personal::prepare_rotation(&d.view, &PersonalKey::generate()).unwrap();
    let commitment = stage_rotation(&d.h, &mut d.owner, log, &prepared.body).await;
    let read = ToService::Permits {
        items: vec![Want::ReadBodies {
            log,
            bodies: vec![commitment],
        }],
    };
    assert_eq!(
        d.owner.handle(read).await,
        FromService::Permits {
            items: vec![Err(Refusal::Unknown)]
        }
    );
}
