//! Closed, bounded framing. Parser buffers only one frame; no resynchronization.
use crate::Error;

pub const HEADER: usize = 11;
pub const MAX_PROOF: usize = 3_212_592;
pub const MAX_FRAME: usize = HEADER + MAX_PROOF;
pub const MAX_HANDSHAKE: usize = 4 * 1024 * 1024;
pub const DOMAIN: &[u8] = b"basehero.checker-channel.v1\0";
const MAX_EVIDENCE: usize = 1_048_576;

fn body_limit(kind: u8) -> Result<(usize, usize), Error> {
    match kind {
        1 => Ok((65, 65)),
        2 => Ok((32 + 1216 + 4 + 1 + 64 + 3 * 5, MAX_PROOF)),
        3 => Ok((1120, 1120)),
        4 => Ok((64 + 49, 64 + 49)),
        5 | 7 => Ok((49, 49)),
        6 => Ok((50, 65_585)),
        _ => Err(Error::Frame),
    }
}
fn header(bytes: &[u8]) -> Result<Option<(u8, usize)>, Error> {
    if bytes.len() < HEADER {
        return Ok(None);
    }
    if &bytes[..4] != b"BHCH" || bytes[4..6] != 1u16.to_be_bytes() {
        return Err(Error::Frame);
    }
    let kind = bytes[6];
    let size = u32::from_be_bytes(bytes[7..11].try_into().map_err(|_| Error::Frame)?) as usize;
    let (min, max) = body_limit(kind)?;
    if !(min..=max).contains(&size) {
        return Err(Error::Limit);
    }
    Ok(Some((kind, size)))
}
fn validate(kind: u8, body: &[u8]) -> Result<(), Error> {
    match kind {
        1 if body[32] != 1 => Err(Error::Frame),
        2 => {
            proof(body)?;
            Ok(())
        }
        4 => envelope(&body[64..], true),
        5 | 7 => envelope(body, true),
        6 => envelope(body, false),
        _ => Ok(()),
    }
}
fn envelope(body: &[u8], empty: bool) -> Result<(), Error> {
    if body[0] > 1
        || (empty && body.len() != 49)
        || (!empty && !(50..=65_585).contains(&body.len()))
    {
        return Err(Error::Frame);
    }
    Ok(())
}
/// Encode only the fixed grammar; canonical exact bytes are returned.
pub fn frame(kind: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    let (min, max) = body_limit(kind)?;
    if !(min..=max).contains(&body.len()) {
        return Err(Error::Limit);
    }
    validate(kind, body)?;
    let mut result = Vec::with_capacity(HEADER + body.len());
    result.extend_from_slice(b"BHCH");
    result.extend_from_slice(&1u16.to_be_bytes());
    result.push(kind);
    result.extend_from_slice(&(body.len() as u32).to_be_bytes());
    result.extend_from_slice(body);
    Ok(result)
}
/// Exactly one complete frame; no trailing or partial bytes.
pub fn parse(bytes: &[u8]) -> Result<(u8, &[u8]), Error> {
    let (kind, size) = header(bytes)?.ok_or(Error::Frame)?;
    if bytes.len() != HEADER + size {
        return Err(Error::Frame);
    }
    validate(kind, &bytes[HEADER..])?;
    Ok((kind, &bytes[HEADER..]))
}

pub struct Proof<'a> {
    pub signing: [u8; 32],
    pub receiving: [u8; 1216],
    pub policy: &'a [u8],
    pub signature: [u8; 64],
    pub quote: &'a [u8],
    pub collateral: &'a [u8],
    pub log: &'a [u8],
}
pub fn proof(body: &[u8]) -> Result<Proof<'_>, Error> {
    if body.len() < 32 + 1216 + 4 + 1 + 64 + 3 * 5 || body.len() > MAX_PROOF {
        return Err(Error::Frame);
    }
    let signing = body[..32].try_into().map_err(|_| Error::Frame)?;
    let receiving = body[32..1248].try_into().map_err(|_| Error::Frame)?;
    let mut at = 1248;
    fn field<'a>(body: &'a [u8], at: &mut usize, max: usize) -> Result<&'a [u8], Error> {
        let end = at.checked_add(4).ok_or(Error::Limit)?;
        let bytes = body.get(*at..end).ok_or(Error::Frame)?;
        let len = u32::from_be_bytes(bytes.try_into().map_err(|_| Error::Frame)?) as usize;
        if len == 0 || len > max {
            return Err(Error::Limit);
        }
        *at = end;
        let end = at.checked_add(len).ok_or(Error::Limit)?;
        let value = body.get(*at..end).ok_or(Error::Frame)?;
        *at = end;
        Ok(value)
    }
    let policy = field(body, &mut at, 65_536)?;
    let end = at.checked_add(64).ok_or(Error::Limit)?;
    let signature = body
        .get(at..end)
        .ok_or(Error::Frame)?
        .try_into()
        .map_err(|_| Error::Frame)?;
    at = end;
    let quote = field(body, &mut at, MAX_EVIDENCE)?;
    let collateral = field(body, &mut at, MAX_EVIDENCE)?;
    let log = field(body, &mut at, MAX_EVIDENCE)?;
    if at != body.len() {
        return Err(Error::Frame);
    }
    Ok(Proof {
        signing,
        receiving,
        policy,
        signature,
        quote,
        collateral,
        log,
    })
}
pub fn make_proof(
    signing: &[u8; 32],
    receiving: &[u8; 1216],
    policy: &[u8],
    signature: &[u8; 64],
    quote: &[u8],
    collateral: &[u8],
    log: &[u8],
) -> Result<Vec<u8>, Error> {
    // Validate every field before copying any caller-supplied bytes. The checked
    // capacity includes the fixed keys, signature and all four length prefixes.
    let mut size: usize = 32 + 1216 + 64 + 4 * 4;
    for (bytes, max) in [
        (policy, 65_536),
        (quote, MAX_EVIDENCE),
        (collateral, MAX_EVIDENCE),
        (log, MAX_EVIDENCE),
    ] {
        if bytes.is_empty() || bytes.len() > max {
            return Err(Error::Limit);
        }
        size = size.checked_add(bytes.len()).ok_or(Error::Limit)?;
    }
    if size > MAX_PROOF {
        return Err(Error::Limit);
    }
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(signing);
    body.extend_from_slice(receiving);
    fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    lp(&mut body, policy);
    body.extend_from_slice(signature);
    for bytes in [quote, collateral, log] {
        lp(&mut body, bytes);
    }
    frame(2, &body)
}
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    NeedMore,
    Frame(Vec<u8>),
}
pub struct Parser {
    buffer: Vec<u8>,
    expected: Option<usize>,
    finished: bool,
}
impl Parser {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            expected: None,
            finished: false,
        }
    }
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
    pub fn feed(&mut self, input: &[u8]) -> Result<Read, Error> {
        let result = self.feed_inner(input);
        if result.is_err() {
            self.finished = true;
            self.buffer.clear();
        }
        result
    }
    fn feed_inner(&mut self, mut input: &[u8]) -> Result<Read, Error> {
        if self.finished {
            return Err(Error::Order);
        }
        if self.buffer.len() < HEADER {
            let take = (HEADER - self.buffer.len()).min(input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
        }
        if self.buffer.len() == HEADER && self.expected.is_none() {
            let (_, size) = header(&self.buffer)?.ok_or(Error::Frame)?;
            self.expected = Some(HEADER + size);
        }
        if let Some(expected) = self.expected {
            let take = (expected - self.buffer.len()).min(input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if !input.is_empty() {
                return Err(Error::Frame);
            }
            if self.buffer.len() == expected {
                parse(&self.buffer)?;
                self.finished = true;
                return Ok(Read::Frame(std::mem::take(&mut self.buffer)));
            }
        }
        Ok(Read::NeedMore)
    }
    pub fn eof(&self) -> Result<(), Error> {
        Err(Error::Frame)
    }
}
impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}
