//! Generated histories shared by the note suites.
#![allow(dead_code)]

use yrs::types::xml::XmlOut;
use yrs::updates::decoder::Decode;
use yrs::{Doc, Text, Transact, WriteTxn, Xml, XmlElementPrelim, XmlFragment, XmlTextPrelim};

pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: u32) -> u32 {
        (self.next() % u64::from(n.max(1))) as u32
    }
}
pub fn writer(id: u64) -> Doc {
    Doc::with_options(yrs::Options {
        client_id: yrs::ClientID::new(id),
        offset_kind: yrs::OffsetKind::Utf16,
        ..yrs::Options::default()
    })
}
/// One random XML edit as the editor's binding would make it: paragraphs,
/// typing, deletion, bold formatting, attributes and removed blocks.
pub fn edit(doc: &Doc, rng: &mut Rng) -> Vec<u8> {
    let mut txn = doc.transact_mut();
    let root = txn.get_or_insert_xml_fragment("default");
    let blocks = root.len(&txn);
    // BMP only: a random UTF-16 offset never splits a surrogate pair.
    let word = ["a", "bc", "def", " ", "xyz!", "é"][rng.below(6) as usize];
    let block = (blocks > 0)
        .then(|| root.get(&txn, rng.below(blocks)))
        .flatten();
    let text = match &block {
        Some(XmlOut::Element(el)) => match el.get(&txn, 0) {
            Some(XmlOut::Text(text)) => Some(text),
            _ => None,
        },
        _ => None,
    };
    match (rng.below(8), text) {
        (0 | 1, _) | (_, None) if blocks < 6 || rng.below(2) == 0 => {
            let at = rng.below(blocks + 1);
            let el = root.insert(&mut txn, at, XmlElementPrelim::empty("paragraph"));
            el.insert(&mut txn, 0, XmlTextPrelim::new(word));
        }
        (2..=4, Some(text)) => {
            let len = text.len(&txn);
            text.insert(&mut txn, rng.below(len + 1), word);
        }
        (5, Some(text)) if text.len(&txn) > 0 => {
            let len = text.len(&txn);
            let at = rng.below(len);
            let n = 1 + rng.below(len - at);
            text.remove_range(&mut txn, at, n);
        }
        (6, Some(text)) if text.len(&txn) > 0 => {
            let len = text.len(&txn);
            let at = rng.below(len);
            let n = 1 + rng.below(len - at);
            let bold = yrs::types::Attrs::from([("bold".into(), yrs::Any::Bool(true))]);
            text.format(&mut txn, at, n, bold);
        }
        (7, _) if rng.below(3) == 0 && blocks > 1 => {
            root.remove_range(&mut txn, rng.below(blocks), 1);
        }
        _ => {
            if let Some(XmlOut::Element(el)) = block {
                let align = ["left", "center"][rng.below(2) as usize];
                el.insert_attribute(&mut txn, "textAlign", align);
            }
        }
    }
    txn.encode_update_v1()
}
/// Three writers editing concurrently, each publishing to one ordered log and
/// catching up from it at random points, as honest devices do.
pub fn honest_history(seed: u64) -> (Vec<Vec<u8>>, Vec<Doc>) {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let writers: Vec<Doc> = (0..3)
        .map(|n| writer(1 + n + (rng.next() & ((1 << 50) - 1))))
        .collect();
    let mut seen = [0usize; 3];
    let mut log: Vec<Vec<u8>> = Vec::new();
    for _ in 0..(8 + rng.below(40)) {
        let w = rng.below(3) as usize;
        if rng.below(3) == 0 {
            let mut txn = writers[w].transact_mut();
            for update in &log[seen[w]..] {
                txn.apply_update(yrs::Update::decode_v1(update).unwrap())
                    .unwrap();
            }
            seen[w] = log.len();
        }
        let update = edit(&writers[w], &mut rng);
        if update != [0, 0] {
            log.push(update);
        }
    }
    for (w, doc) in writers.iter().enumerate() {
        let mut txn = doc.transact_mut();
        for update in &log[seen[w]..] {
            txn.apply_update(yrs::Update::decode_v1(update).unwrap())
                .unwrap();
        }
    }
    (log, writers)
}

/// One paragraph typed backwards a character at a time: one unmergeable
/// item per character, as a full state.
pub fn reverse_typed(client: u64, chars: usize) -> Vec<u8> {
    let doc = writer(client);
    {
        let mut txn = doc.transact_mut();
        let root = txn.get_or_insert_xml_fragment("default");
        let p = root.insert(&mut txn, 0, XmlElementPrelim::empty("paragraph"));
        let text = p.insert(&mut txn, 0, XmlTextPrelim::new(""));
        for _ in 0..chars {
            text.insert(&mut txn, 0, "y");
        }
    }
    yrs::ReadTxn::encode_state_as_update_v1(&doc.transact(), &yrs::StateVector::default())
}
