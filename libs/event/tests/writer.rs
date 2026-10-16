use bh_event::writer::{DeviceWriterDeclaration, WriterDecodeError, WriterScope};

fn scope() -> WriterScope {
    WriterScope {
        base: [0x11; 32],
        audience: [0x22; 32],
        note: [0x33; 32],
    }
}
fn declaration() -> DeviceWriterDeclaration {
    DeviceWriterDeclaration {
        account: [0x44; 32],
        device: [0x55; 32],
        nonce: [0x66; 32],
    }
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn independent_full_wire_hash_and_safe_integer_vector() {
    let wire = unhex(concat!(
        "000101",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "5555555555555555555555555555555555555555555555555555555555555555",
        "6666666666666666666666666666666666666666666666666666666666666666"
    ));
    let d = declaration();
    assert_eq!(d.encode().as_slice(), wire);
    assert_eq!(DeviceWriterDeclaration::decode(&wire).unwrap(), d);
    assert_eq!(
        d.digest(scope()).as_slice(),
        unhex("09e71d3bf79541b8e6e9d12f091ed7d5f1499c59f24d7b42fc81c578881aff48")
    );
    assert_eq!(d.client_id(scope()), 2_002_468_231_004_600);
}

#[test]
fn every_scope_and_principal_field_changes_derivation() {
    let d = declaration();
    let s = scope();
    let id = d.client_id(s);
    for field in 0..6 {
        let mut d = d;
        let mut s = s;
        match field {
            0 => s.base[0] ^= 1,
            1 => s.audience[0] ^= 1,
            2 => s.note[0] ^= 1,
            3 => d.account[0] ^= 1,
            4 => d.device[0] ^= 1,
            _ => d.nonce[0] ^= 1,
        }
        assert_ne!(d.client_id(s), id);
    }
}

#[test]
fn unsupported_versions_and_tags_are_not_malformed_or_trailing_data() {
    let mut wire = declaration().encode();
    wire[1] = 2;
    assert_eq!(
        DeviceWriterDeclaration::decode(&wire),
        Err(WriterDecodeError::UnsupportedVersion(2))
    );
    wire[1] = 1;
    wire[2] = 2;
    assert_eq!(
        DeviceWriterDeclaration::decode(&wire),
        Err(WriterDecodeError::UnsupportedAuthor(2))
    );
    assert_eq!(
        DeviceWriterDeclaration::decode(&wire[..98]),
        Err(WriterDecodeError::Malformed)
    );
    let mut extra = declaration().encode().to_vec();
    extra.push(0);
    assert_eq!(
        DeviceWriterDeclaration::decode(&extra),
        Err(WriterDecodeError::TrailingData)
    );
}
