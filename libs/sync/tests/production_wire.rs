use bh_sync::wire::{self, CoverageEndpoint, Request, Response};
use bh_sync::{EventId, OpaqueEvent, OrderState};

#[test]
fn v3_events_frame_names_endpoint_independently_of_last_item() {
    let genesis = OpaqueEvent::new(EventId([7; 32]), vec![0x44; 1024]).unwrap();
    let base = bh_sync::BaseId::from_genesis(&genesis);
    let opening =
        bh_sync::Commitment::order(base, OrderState::EMPTY, &genesis, bh_sync::Route::Control)
            .unwrap();
    let response = Response::Events {
        id: 0x01020304,
        items: vec![(opening.encode(), genesis.encode())],
        receipt: None,
        coverage: Some(CoverageEndpoint {
            order: opening.after(),
            receipt: Some([0x77; 300]),
        }),
    };
    let frame = response.encode().unwrap();
    assert_eq!(&frame[..11], &[0, 3, 1, 1, 2, 3, 4, 0, 1, 0, 2]);
    assert_eq!(&frame[11..93], &opening.after().encode());
    assert_eq!(&frame[93..393], &[0x77; 300]);
    assert_eq!(&frame[393..397], &[0, 0, 0, 149]);
    assert_eq!(frame.len(), 393 + 4 + 149 + 4 + genesis.encode().len());
    assert_eq!(response.encoded_len(), Ok(frame.len()));
    assert_eq!(Response::decode(&frame), Ok(response));
    let mut old = frame.clone();
    old[1] = 2;
    assert_eq!(Response::decode(&old), Err(wire::Error::Version));
    let mut short = frame;
    short.truncate(92);
    assert_eq!(Response::decode(&short), Err(wire::Error::Encoding));
}

#[test]
fn sparse_empty_endpoint_has_no_receipt_and_full_reads_have_no_coverage() {
    let empty = Response::Events {
        id: 1,
        items: vec![],
        receipt: None,
        coverage: Some(CoverageEndpoint {
            order: OrderState::EMPTY,
            receipt: None,
        }),
    };
    let frame = empty.encode().unwrap();
    assert_eq!(&frame[..11], &[0, 3, 1, 0, 0, 0, 1, 0, 0, 0, 1]);
    assert_eq!(frame.len(), 11 + 82);
    assert_eq!(Response::decode(&frame), Ok(empty));
    let full = Response::Events {
        id: 1,
        items: vec![],
        receipt: None,
        coverage: None,
    };
    assert_eq!(
        &full.encode().unwrap()[..],
        &[0, 3, 1, 0, 0, 0, 1, 0, 0, 0, 0]
    );
    assert_eq!(
        Response::Events {
            id: 1,
            items: vec![],
            receipt: Some([1; 300]),
            coverage: Some(CoverageEndpoint {
                order: OrderState::EMPTY,
                receipt: None
            })
        }
        .encode(),
        Err(wire::Error::Encoding)
    );
    assert_eq!(
        Response::Events {
            id: 1,
            items: vec![],
            receipt: None,
            coverage: Some(CoverageEndpoint {
                order: OrderState::EMPTY,
                receipt: Some([1; 300])
            })
        }
        .encode(),
        Err(wire::Error::Encoding)
    );
    for tag in [3, 255] {
        let mut wrong = frame.clone();
        wrong[10] = tag;
        assert_eq!(Response::decode(&wrong), Err(wire::Error::Encoding));
    }
    let mut old = Request::Credit { bytes: 5 }.encode().unwrap();
    old[1] = 2;
    assert_eq!(Request::decode(&old), Err(wire::Error::Version));
}
