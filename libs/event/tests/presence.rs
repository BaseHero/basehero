use bh_account::DeviceId;
use bh_crypto::Secret;
use bh_event::presence::{self, PresenceRecord};

fn record() -> PresenceRecord {
    PresenceRecord {
        kind: 1,
        handle: [9; 16],
        seq: 123,
        colour: 3,
        note: [4; 32],
        anchor: vec![0x61, 0x62],
        head: vec![0x63],
        label: "CANARY-LBL-7f3".to_string(),
    }
}
fn key() -> Secret<32> {
    Secret::from_slice(&[17; 32]).unwrap()
}

#[test]
fn record_has_exact_fixed_plaintext_layout_and_strict_canonical_decode() {
    let record = record();
    let bytes = record.encode().unwrap();
    assert_eq!(bytes.len(), 320);
    assert_eq!(
        &bytes[..27],
        &[&[1, 1][..], &[9; 16], &123_u64.to_be_bytes(), &[3]].concat()
    );
    assert_eq!(&bytes[27..59], &[4; 32]);
    assert_eq!(bytes[59], 2);
    assert_eq!(&bytes[60..62], b"ab");
    assert_eq!(bytes[156], 1);
    assert_eq!(bytes[157], b'c');
    assert_eq!(bytes[253], 14);
    assert_eq!(&bytes[254..268], b"CANARY-LBL-7f3");
    assert!(bytes[268..].iter().all(|b| *b == 0));
    assert_eq!(PresenceRecord::decode(&bytes), Ok(record.clone()));
    for offset in [60 + 2, 157 + 1, 254 + 14, 319] {
        let mut bad = bytes;
        bad[offset] = 1;
        assert!(PresenceRecord::decode(&bad).is_err());
    }
    let mut bad = bytes;
    bad[0] = 2;
    assert!(PresenceRecord::decode(&bad).is_err());
    let mut bad = bytes;
    bad[59] = 97;
    assert!(PresenceRecord::decode(&bad).is_err());
    let mut bad = bytes;
    bad[253] = 65;
    assert!(PresenceRecord::decode(&bad).is_err());
    let mut bad = bytes;
    bad[254] = 0xff;
    assert!(PresenceRecord::decode(&bad).is_err());
    let mut bad_record = record;
    bad_record.anchor = vec![1; 97];
    assert!(bad_record.encode().is_err());
    bad_record.anchor.clear();
    bad_record.label = "x".repeat(65);
    assert!(bad_record.encode().is_err());
}

#[test]
fn presence_seal_binds_base_audience_epoch_and_hides_label() {
    let record = record();
    let (base, audience, key_id) = ([1; 32], [2; 32], [3; 32]);
    let frame = presence::seal(&key(), base, audience, key_id, &record).unwrap();
    assert_eq!(frame.len(), 393);
    assert_eq!(&frame[..33], &[&[1][..], &[3; 32]].concat());
    assert!(
        !frame
            .windows(record.label.len())
            .any(|window| window == record.label.as_bytes())
    );
    assert_eq!(
        presence::open(&key(), base, audience, key_id, &frame),
        Ok(record.clone())
    );
    let another = presence::seal(&key(), base, audience, key_id, &record).unwrap();
    assert_ne!(frame, another);
    for i in 0..frame.len() {
        let mut bad = frame.clone();
        bad[i] ^= 1;
        assert!(
            presence::open(&key(), base, audience, key_id, &bad).is_err(),
            "tamper {i}"
        );
    }
    for (b, a, e) in [
        ([0; 32], audience, key_id),
        (base, [0; 32], key_id),
        (base, audience, [0; 32]),
    ] {
        assert!(presence::open(&key(), b, a, e, &frame).is_err());
    }
    assert!(presence::open(&key(), base, audience, key_id, &frame[..392]).is_err());
    let mut extra = frame;
    extra.push(0);
    assert!(presence::open(&key(), base, audience, key_id, &extra).is_err());
    for (anchor, head, label) in [
        (vec![], vec![], "".to_string()),
        (vec![1; 96], vec![2; 96], "x".repeat(64)),
    ] {
        let sample = PresenceRecord {
            anchor,
            head,
            label,
            ..record.clone()
        };
        assert_eq!(sample.encode().unwrap().len(), 320);
        let sealed = presence::seal(&key(), base, audience, key_id, &sample).unwrap();
        assert_eq!(sealed.len(), 393);
        assert_eq!(
            presence::open(&key(), base, audience, key_id, &sealed),
            Ok(sample)
        );
    }
    assert!(!format!("{record:?}").contains("CANARY-LBL"));
}

#[test]
fn device_handle_changes_with_device_and_epoch_without_exposing_device_id() {
    let d1 = DeviceId([1; 32]);
    let d2 = DeviceId([2; 32]);
    let h = presence::handle(&key(), d1);
    assert_eq!(h, presence::handle(&key(), d1));
    assert_ne!(h, presence::handle(&key(), d2));
    assert_ne!(
        h,
        presence::handle(&Secret::from_slice(&[18; 32]).unwrap(), d1)
    );
    assert_ne!(h, [1; 16]);
}
