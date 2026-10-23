//! Local synthetic checkpoint using the real AccountOwner producer and service.
use super::{data, device_channel, key, socket_url};
use bh_account::{
    AccountId, VerifiedAccount,
    crypto::{KemKey, Secret},
    device_auth::{self, Context},
    journal::SetupStage,
    owner::{AccountGeneration, AccountLoad, AccountOwner},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_authz::proto::{
    FromService, LogId, LogKind, Refusal, ToService, Want, account_log_id, account_log_unwrap,
    account_log_wrap,
};
use bh_sync::{
    BaseId, Commitment, Head, OpaqueEvent, home_objects,
    permit::AppendAck,
    wire::{Request, Response},
};
use std::{fs, path::Path};

#[allow(dead_code)]
#[path = "../../../../libs/account/tests/support/protector.rs"]
mod protector;
#[path = "../../../../libs/account/tests/support/store.rs"]
mod store;

pub fn verify_readback(dir: &Path) {
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("home-probe.json")).unwrap()).unwrap();
    let originals: Vec<Vec<u8>> = expected["originals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
        .collect();
    let genesis = bh_account::AccountEvent::decode(&originals[0]).unwrap();
    let anchor = AccountId::of_genesis(&genesis).unwrap();
    let prefix = bh_account::Head {
        position: 3,
        hash: hex::decode(expected["prefix"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let view = VerifiedAccount::replay(
        anchor,
        &originals.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        prefix,
    )
    .unwrap();
    let persisted = fs::read(dir.join("home-readback.bundle")).unwrap();
    assert_eq!(
        persisted,
        hex::decode(expected["bundle"].as_str().unwrap()).unwrap()
    );
    let objects = home_objects::Bundle::decode(&persisted).unwrap();
    view.verify_initial_objects(objects.record, objects.device_seal, objects.recovery_seal)
        .unwrap();
    assert_eq!(
        hex::encode(home_objects::digest(&persisted).unwrap().0),
        expected["digest"].as_str().unwrap()
    );
    println!(
        "home-verify: restarted DO's exact 242/1299/1299-byte objects match all three signed commitments"
    );
}

pub async fn run(phase: &str, dir: &Path) {
    let first = phase == "home-first";
    assert!(first || phase == "home-again");
    let env = fs::read_to_string(dir.join("env")).unwrap();
    let edge = env
        .lines()
        .find_map(|line| line.strip_prefix("LOCAL_STACK_HOST_EDGE_URL="))
        .unwrap();
    let keys = dir.join("keys");
    let generation = AccountGeneration::new();
    let store = store::FakeStore::new(generation.clone());
    if !first {
        let mut state = store.state_mut();
        state.ordinary = Some(key(&keys.join("home-ordinary.seed")));
        state.control = Some(key(&keys.join("home-control.seed")));
        state.receiver = Some(KemKey::from_seed(
            &Secret::from_slice(
                &hex::decode(fs::read_to_string(keys.join("home-receiver.seed")).unwrap()).unwrap(),
            )
            .unwrap(),
        ));
    }
    let journal = DeviceJournal::open(dir.join("home-owner.sqlite")).unwrap();
    let mut owner = AccountOwner::new(
        journal,
        store.clone(),
        protector::PlainProtector,
        generation,
    );
    if first {
        owner
            .begin_first_device(
                ControlKeyPolicy::AppEnforcedOwnerConfirmation,
                &Password::new("synthetic local home objects").unwrap(),
            )
            .await
            .unwrap();
        owner.confirm_kit_saved().unwrap();
        let state = store.state();
        for (name, seed) in [
            ("ordinary", state.ordinary.as_ref().unwrap().export_seed()),
            ("control", state.control.as_ref().unwrap().export_seed()),
            ("receiver", state.receiver.as_ref().unwrap().export_seed()),
        ] {
            fs::write(
                keys.join(format!("home-{name}.seed")),
                hex::encode(seed.expose()),
            )
            .unwrap();
        }
    }
    let AccountLoad::Active(cap) = owner.activate().await.unwrap() else {
        panic!("active signup owner")
    };
    let (prefix, objects) = owner.initial_bootstrap(&cap).unwrap();
    let bundle = home_objects::encode(
        &objects.record,
        &objects.device_seal,
        &objects.recovery_seal,
    )
    .unwrap();
    let digest = home_objects::digest(&bundle).unwrap().0;
    let log = LogId {
        kind: LogKind::Account,
        id: account_log_id(&prefix.events[0]).unwrap(),
    };
    assert_eq!(
        owner.setup_status().unwrap().unwrap().stage,
        SetupStage::Prepared,
        "lost answer never marks home complete"
    );
    let request = ToService::StoreHomeObjects {
        prefix: prefix.head,
        record: objects.record,
        device_seal: objects.device_seal,
        recovery_seal: objects.recovery_seal,
    };
    let expected = serde_json::json!({
        "log": format!("02{}", hex::encode(log.id)), "prefix": hex::encode(prefix.head.hash),
        "digest": hex::encode(digest), "bundle": hex::encode(&bundle),
        "originals": prefix.events.iter().map(hex::encode).collect::<Vec<_>>(),
    });
    if first {
        fs::write(
            dir.join("home-probe.json"),
            serde_json::to_vec(&expected).unwrap(),
        )
        .unwrap();
    } else {
        assert_eq!(
            expected,
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(dir.join("home-probe.json")).unwrap()
            )
            .unwrap()
        );
    }

    let app = key(&keys.join("app-root.seed"));
    let (mut ws, mut channel) =
        device_channel::open_with_snapshot(&socket_url(edge, "/v1/authz"), &app, None).await;
    let FromService::Challenge { challenge } = device_channel::receive(&mut ws, &mut channel).await
    else {
        panic!("challenge")
    };
    // A genesis-head proof also works before publishing. The production
    // native client's historical proof integration is independent of this test.
    let genesis_view = VerifiedAccount::from_genesis(prefix.anchor, &prefix.events[0]).unwrap();
    let possession = device_auth::prepare(
        &genesis_view,
        cap.device_id(),
        Context {
            channel_binding: channel.binding().unwrap(),
            challenge,
        },
    )
    .unwrap();
    let signature = store
        .state()
        .ordinary
        .as_ref()
        .unwrap()
        .sign(possession.message());
    let proof = possession.finish(signature).unwrap();
    assert!(matches!(
        device_channel::ask(
            &mut ws,
            &mut channel,
            ToService::Authenticate {
                proof: Box::new(*proof.as_bytes()),
                account: prefix.anchor,
                device: cap.device_id(),
                genesis: prefix.events[0].clone(),
            }
        )
        .await,
        FromService::Authenticated { .. }
    ));
    if first {
        assert_eq!(
            device_channel::ask(&mut ws, &mut channel, request.clone()).await,
            FromService::Refused {
                reason: Refusal::Invalid
            }
        );
        for original in &prefix.events {
            let FromService::Permits { mut items } = device_channel::ask(
                &mut ws,
                &mut channel,
                ToService::SubmitControl {
                    log,
                    event: original.clone(),
                    delivery: None,
                    attachment: None,
                },
            )
            .await
            else {
                panic!("public prefix append permit")
            };
            assert_eq!(items.len(), 1);
            let response = data(
                edge,
                Request::Append {
                    id: 1,
                    permit: items.remove(0).unwrap(),
                    event: account_log_wrap(original, None).unwrap().encode(),
                },
            )
            .await;
            let Response::Acked { ack, .. } = response else {
                panic!("public prefix ordered: {response:?}")
            };
            assert_eq!(AppendAck::decode(&ack).unwrap().log, log);
        }
    }
    let FromService::Permits { mut items } = device_channel::ask(
        &mut ws,
        &mut channel,
        ToService::Permits {
            items: vec![Want::ReadEvents {
                log,
                first: 1,
                last: 4,
            }],
        },
    )
    .await
    else {
        panic!("public prefix read")
    };
    let Response::Events { items, .. } = data(
        edge,
        Request::Read {
            id: 2,
            permit: items.remove(0).unwrap(),
        },
    )
    .await
    else {
        panic!("ordered public prefix")
    };
    assert_eq!(items.len(), 3, "private storage never appends a position");
    let mut head = Head::EMPTY;
    for ((commitment, event), original) in items.iter().zip(&prefix.events) {
        let commitment = Commitment::decode(commitment).unwrap();
        let event = OpaqueEvent::decode(event).unwrap();
        head = commitment.verify_next(BaseId(log.id), head).unwrap();
        commitment.verify_body(&event).unwrap();
        assert_eq!(
            account_log_unwrap(&event).unwrap(),
            (original.as_slice(), None)
        );
        assert_eq!(
            event.encode(),
            account_log_wrap(original, None).unwrap().encode()
        );
    }
    // The only completion signal is the matching response inside this session.
    assert_eq!(
        device_channel::ask(&mut ws, &mut channel, request).await,
        FromService::HomeObjectsStored {
            prefix: prefix.head,
            digest
        }
    );
    if first {
        // Simulate losing the response before committing the local checkpoint.
        assert_eq!(
            owner.setup_status().unwrap().unwrap().stage,
            SetupStage::Prepared
        );
        println!(
            "home-first: real AccountOwner objects stored through attested authz; response lost before local confirmation"
        );
    } else {
        owner.confirm_home_ordered(prefix.head, None).unwrap();
        assert!(owner.setup_status().unwrap().is_none());
        println!(
            "home-again: cold authz replay, exact durable retry, verified public prefix, then home confirmation"
        );
    }
}
