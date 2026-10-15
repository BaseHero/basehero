use bh_confidential_channel::{
    Error,
    wire::{MAX_PROOF, Parser, Read, frame, make_proof, parse},
};

#[test]
fn exact_vectors_and_bounded_stream() {
    let mut body = [0; 65];
    body[32] = 1;
    let hello = frame(1, &body).unwrap();
    assert_eq!(&hello[..11], b"BHCH\0\x01\x01\0\0\0A");
    assert_eq!(parse(&hello).unwrap(), (1, &hello[11..]));
    for i in 0..hello.len() {
        let mut parser = Parser::new();
        assert_eq!(parser.feed(&hello[..i]).unwrap(), Read::NeedMore);
        assert_eq!(
            parser.feed(&hello[i..]).unwrap(),
            Read::Frame(hello.clone())
        );
        assert!(parser.feed(&[1]).is_err());
    }
    let mut wrong = hello.clone();
    wrong[5] = 2;
    assert!(parse(&wrong).is_err());
    let mut malformed = Parser::new();
    assert!(malformed.feed(&wrong[..11]).is_err());
    assert_eq!(
        malformed.feed(&hello),
        Err(bh_confidential_channel::Error::Order)
    );
    assert!(parse(&[hello.as_slice(), &[0]].concat()).is_err());
    let mut too_long = hello;
    too_long[7..11].copy_from_slice(&((MAX_PROOF + 1) as u32).to_be_bytes());
    assert!(Parser::new().feed(&too_long[..11]).is_err());
    assert_eq!(
        Parser::new().eof(),
        Err(bh_confidential_channel::Error::Frame)
    );
}

#[test]
fn proof_encoder_rejects_each_zero_and_oversized_field() {
    let valid = [1u8];
    let too_much_policy = vec![1; 65_537];
    let too_much_evidence = vec![1; 1_048_577];
    let fields = [valid.as_slice(); 4];
    for at in 0..4 {
        for replacement in [
            &[][..],
            if at == 0 {
                &too_much_policy
            } else {
                &too_much_evidence
            },
        ] {
            let mut fields = fields;
            fields[at] = replacement;
            assert_eq!(
                make_proof(
                    &[1; 32], &[2; 1216], fields[0], &[3; 64], fields[1], fields[2], fields[3]
                )
                .err(),
                Some(Error::Limit)
            );
        }
    }
}

#[test]
fn largest_frame_one_byte_feed_and_length_bound_before_allocation() {
    let proof = bh_confidential_channel::wire::make_proof(
        &[1; 32],
        &[2; 1216],
        &vec![3; 65_536],
        &[4; 64],
        &vec![5; 1_048_576],
        &vec![6; 1_048_576],
        &vec![7; 1_048_576],
    )
    .unwrap();
    assert_eq!(proof.len(), 11 + MAX_PROOF);
    let mut parser = Parser::new();
    for byte in &proof[..proof.len() - 1] {
        assert_eq!(
            parser.feed(std::slice::from_ref(byte)).unwrap(),
            Read::NeedMore
        );
    }
    assert_eq!(parser.buffered(), proof.len() - 1);
    assert_eq!(
        parser.feed(&proof[proof.len() - 1..]).unwrap(),
        Read::Frame(proof)
    );
}
