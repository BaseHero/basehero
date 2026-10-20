#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_account::{AccountEvent, AccountId, VerifiedAccount, personal, recovery};
use bh_authz::{
    EdgeError, EdgeReader, HomeObjectsAck, Service,
    proto::{FromService, Refusal, ToService, account_log_id},
};
use bh_sync::{
    Digest, home_objects,
    permit::{self, Scope},
};
use futures_util::future::BoxFuture;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use support::*;

fn signup(device: &Device) -> (Account, ToService) {
    let recovery = recovery::RecoveryKeys::generate();
    let draft = AccountEvent::genesis(device.keys.clone(), recovery.public());
    let genesis = draft
        .finish(device.control.sign(draft.signing_bytes()))
        .unwrap();
    let id = AccountId::of_genesis(&genesis).unwrap();
    let mut account = Account {
        genesis: genesis.as_bytes().to_vec(),
        id,
        log: bh_authz::proto::LogId {
            kind: bh_authz::proto::LogKind::Account,
            id: account_log_id(genesis.as_bytes()).unwrap(),
        },
        verified: VerifiedAccount::from_genesis(id, genesis.as_bytes()).unwrap(),
        originals: vec![genesis.as_bytes().to_vec()],
        personal: None,
    };
    let record = recovery::prepare_record(
        &account.verified,
        &recovery,
        &recovery::Password::new("synthetic passphrase").unwrap(),
        &recovery::RecoveryCode::generate(),
    )
    .unwrap();
    let draft = account
        .verified
        .prepare_recovery_record(device.id(), record.digest())
        .unwrap();
    account.apply(
        &draft
            .finish(device.control.sign(draft.signing_bytes()))
            .unwrap(),
    );
    let personal = personal::PersonalKey::generate();
    let publication = personal::prepare_publication(&account.verified, &personal).unwrap();
    let draft = account
        .verified
        .publish_personal_key(
            device.id(),
            publication.public(),
            publication.device_digest(),
            publication.recovery_digest(),
        )
        .unwrap();
    account.apply(
        &draft
            .finish(device.control.sign(draft.signing_bytes()))
            .unwrap(),
    );
    account.personal = Some(personal);
    let request = ToService::StoreHomeObjects {
        prefix: account.verified.head(),
        record: record.as_bytes().to_vec(),
        device_seal: publication.device_seal().to_vec(),
        recovery_seal: publication.recovery_seal().to_vec(),
    };
    (account, request)
}
fn bundle(request: &ToService) -> Vec<u8> {
    let ToService::StoreHomeObjects {
        record,
        device_seal,
        recovery_seal,
        ..
    } = request
    else {
        panic!()
    };
    home_objects::encode(record, device_seal, recovery_seal).unwrap()
}

// The network boundary is deliberately controllable: success may only follow
// its durable acknowledgement, never cache insertion or permit issuance.
struct StorageEdge {
    read: Arc<FakeEdge>,
    root: [u8; 32],
    expected_log: bh_authz::proto::LogId,
    expected_prefix: Digest,
    expected_bundle: Vec<u8>,
    mode: AtomicU8,
    calls: AtomicUsize,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
    permits: Mutex<Vec<Vec<u8>>>,
}
impl EdgeReader for StorageEdge {
    fn read_log(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<bh_authz::LogItems, EdgeError>> {
        self.read.read_log(permit)
    }
    fn read_bodies(&self, permit: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        self.read.read_bodies(permit)
    }
    fn store_home_objects(
        &self,
        signed: Vec<u8>,
        bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<HomeObjectsAck, EdgeError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let permit = permit::verify(self.root, &signed, TIME_START).unwrap();
            let Scope::StoreHomeObjects {
                log,
                prefix_digest,
                bundle_digest,
            } = permit.scope
            else {
                panic!("wrong scope")
            };
            assert_eq!(log, self.expected_log);
            assert_eq!(prefix_digest, self.expected_prefix);
            assert_eq!(bundle, self.expected_bundle);
            assert_eq!(bundle_digest, home_objects::digest(&bundle).unwrap());
            self.permits.lock().unwrap().push(signed);
            let mode = self.mode.load(Ordering::SeqCst);
            if mode == 1 {
                return Err(EdgeError::Unavailable);
            }
            if mode == 4 {
                self.reached.notify_one();
                self.release.notified().await;
            }
            Ok(HomeObjectsAck {
                prefix_digest: if mode == 2 {
                    Digest([0; 32])
                } else {
                    prefix_digest
                },
                bundle_digest: if mode == 3 {
                    Digest([0; 32])
                } else {
                    bundle_digest
                },
            })
        })
    }
}
fn service(h: &Harness, a: &Account, request: &ToService) -> (Service, Arc<StorageEdge>) {
    let edge = Arc::new(StorageEdge {
        read: h.edge.clone(),
        root: h.root.public(),
        expected_log: a.log,
        expected_prefix: Digest(a.verified.head().hash),
        expected_bundle: bundle(request),
        mode: AtomicU8::new(0),
        calls: AtomicUsize::new(0),
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        permits: Mutex::default(),
    });
    let service = Service::open(
        &h.dir.path().join("authz.sqlite"),
        h.keys(),
        h.clock.clone(),
        edge.clone(),
    )
    .unwrap();
    (service, edge)
}
fn invalid(answer: FromService) {
    assert_eq!(
        answer,
        FromService::Refused {
            reason: Refusal::Invalid
        }
    );
}

#[tokio::test]
async fn objects_checked_against_retained_historical_signup_not_current_or_caller_prefix() {
    let h = Harness::new();
    let d = Device::new();
    let (mut a, request) = signup(&d);
    let base = a.base_genesis(&d);
    h.publish(&a);
    let (s, edge) = service(&h, &a, &request);
    let mut c = session(&s, &a, &d).await;
    let registered = c.handle(base.register()).await;
    order_genesis(&h, &registered, &base);
    let account_before = h.edge.after(a.log, 0);
    let base_before = h.edge.after(base.log(), 0);
    for slot in 0..3 {
        for missing in [false, true] {
            let mut bad = request.clone();
            let ToService::StoreHomeObjects {
                record,
                device_seal,
                recovery_seal,
                ..
            } = &mut bad
            else {
                panic!()
            };
            let object = [record, device_seal, recovery_seal]
                .into_iter()
                .nth(slot)
                .unwrap();
            if missing {
                object.clear();
            } else {
                object[100] ^= 1;
            }
            invalid(c.handle(bad).await);
        }
    }
    let mut swapped = request.clone();
    if let ToService::StoreHomeObjects {
        device_seal,
        recovery_seal,
        ..
    } = &mut swapped
    {
        std::mem::swap(device_seal, recovery_seal);
    }
    invalid(c.handle(swapped).await);
    for position in [1, 2, 4] {
        let mut bad = request.clone();
        if let ToService::StoreHomeObjects { prefix, .. } = &mut bad {
            prefix.position = position;
        }
        invalid(c.handle(bad).await);
    }
    let (_, mut foreign) = signup(&Device::new());
    if let ToService::StoreHomeObjects { prefix, .. } = &mut foreign {
        *prefix = a.verified.head();
    }
    invalid(c.handle(foreign).await);
    let mut wrong_prefix = request.clone();
    if let ToService::StoreHomeObjects { prefix, .. } = &mut wrong_prefix {
        prefix.hash[0] ^= 1;
    }
    invalid(c.handle(wrong_prefix).await);
    assert_eq!(edge.calls.load(Ordering::SeqCst), 0);
    let prefix = a.verified.head();
    a.add_device(&d, &Device::new());
    h.publish(&a);
    let answer = c.handle(request.clone()).await;
    assert_eq!(
        answer,
        FromService::HomeObjectsStored {
            prefix,
            digest: home_objects::digest(&bundle(&request)).unwrap().0
        }
    );
    // Real stored wrappers and the registered base genesis remain untouched,
    // including their ids, commitments and body. Only the later device-add
    // control has acquired a new account-log position.
    assert_eq!(&h.edge.after(a.log, 0)[..3], account_before.as_slice());
    assert_eq!(h.edge.after(base.log(), 0), base_before);
    // It is not cached as success: a second request reaches storage again.
    edge.mode.store(1, Ordering::SeqCst);
    assert_eq!(c.handle(request).await, FromService::Unavailable);
}

#[tokio::test]
async fn durable_matching_ack_required_and_private_bundle_not_in_authz_database() {
    let h = Harness::new();
    let d = Device::new();
    let (a, request) = signup(&d);
    h.publish(&a);
    let (s, edge) = service(&h, &a, &request);
    let mut c = session(&s, &a, &d).await;
    for mode in [1, 2, 3] {
        edge.mode.store(mode, Ordering::SeqCst);
        assert_eq!(c.handle(request.clone()).await, FromService::Unavailable);
    }
    edge.mode.store(4, Ordering::SeqCst);
    let bytes = bundle(&request);
    let expected_digest = home_objects::digest(&bytes).unwrap().0;
    let pending = tokio::spawn(async move { c.handle(request).await });
    edge.reached.notified().await;
    assert!(
        !pending.is_finished(),
        "no success before storage acknowledges"
    );
    edge.release.notify_one();
    assert_eq!(
        pending.await.unwrap(),
        FromService::HomeObjectsStored {
            prefix: a.verified.head(),
            digest: expected_digest
        }
    );
    // Disk cache contains signed public history only, not the private objects.
    drop(s);
    for item in std::fs::read_dir(h.dir.path()).unwrap() {
        let contents = std::fs::read(item.unwrap().path()).unwrap();
        for object in [
            home_objects::Bundle::decode(&bytes).unwrap().record,
            home_objects::Bundle::decode(&bytes).unwrap().device_seal,
            home_objects::Bundle::decode(&bytes).unwrap().recovery_seal,
        ] {
            assert!(!contents.windows(object.len()).any(|w| w == object));
        }
    }
}

#[tokio::test]
async fn matching_answer_released_at_the_permit_deadline_is_unavailable() {
    for (late, in_time) in [(29_999, true), (30_000, false)] {
        let h = Harness::new();
        let d = Device::new();
        let (a, request) = signup(&d);
        h.publish(&a);
        let (s, edge) = service(&h, &a, &request);
        let mut c = session(&s, &a, &d).await;
        edge.mode.store(4, Ordering::SeqCst);
        let digest = home_objects::digest(&bundle(&request)).unwrap().0;
        let pending = tokio::spawn(async move { c.handle(request).await });
        edge.reached.notified().await;
        let issued = permit::issued_ms(&edge.permits.lock().unwrap()[0]).unwrap();
        h.clock.set(issued + late);
        edge.release.notify_one();
        let expected = if in_time {
            FromService::HomeObjectsStored {
                prefix: a.verified.head(),
                digest,
            }
        } else {
            FromService::Unavailable
        };
        assert_eq!(pending.await.unwrap(), expected, "released at +{late} ms");
    }
}

#[tokio::test]
async fn unauthenticated_unknown_removed_and_unreachable_never_store() {
    let h = Harness::new();
    let d = Device::new();
    let (mut a, request) = signup(&d);
    h.publish(&a);
    let (s, edge) = service(&h, &a, &request);
    let (mut unauth, _, _) = connect(&s);
    assert_eq!(
        unauth.handle(request.clone()).await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    );
    let unknown = Device::new();
    let (mut unknown_c, binding, challenge) = connect(&s);
    assert_eq!(
        unknown_c
            .handle(ToService::Authenticate {
                proof: raw_proof(&a, &unknown, binding, challenge),
                account: a.id,
                device: unknown.id(),
                genesis: a.genesis.clone()
            })
            .await,
        FromService::Refused {
            reason: Refusal::NotActive
        }
    );
    assert_eq!(
        unknown_c.handle(request.clone()).await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    );
    let mut c = session(&s, &a, &d).await;
    h.edge.down.store(true, Ordering::SeqCst);
    assert_eq!(c.handle(request.clone()).await, FromService::Unavailable);
    h.edge.down.store(false, Ordering::SeqCst);
    a.add_device(&d, &Device::new());
    a.remove_self(&d);
    h.publish(&a);
    assert_eq!(
        c.handle(request).await,
        FromService::Refused {
            reason: Refusal::NotActive
        }
    );
    assert_eq!(edge.calls.load(Ordering::SeqCst), 0);
}
