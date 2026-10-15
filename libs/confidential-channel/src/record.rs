//! Confirmed directional records. Any failed operation destroys both traffic keys.
use crate::attestation::VerifiedEvidence;
use crate::{
    Error,
    appraisal::{Clock, PolicyContext, PolicyStore, Sample},
    wire::{self, DOMAIN},
};
use bh_crypto::{Secret, SecretBytes};

pub(crate) struct Keys {
    pub(crate) c: Secret<32>,
    pub(crate) s: Secret<32>,
}
pub(crate) enum Appraisal<S: PolicyStore> {
    Server(Box<dyn Clock>),
    Client(PolicyContext<S>, Box<VerifiedEvidence>),
}
impl<S: PolicyStore> Appraisal<S> {
    pub(crate) fn use_now<R>(
        &self,
        action: impl FnOnce(Sample) -> Result<R, Error>,
    ) -> Result<R, Error> {
        match self {
            Self::Server(clock) => action(clock.sample()),
            Self::Client(ctx, evidence) => ctx.with_current(evidence, action),
        }
    }
}
const MAX_RECORDS: u64 = 65_536;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const SESSION_MS: u64 = 600_000;

/// Owned traffic keys never implement Clone or Debug.
/// ```compile_fail
/// use bh_confidential_channel::{appraisal::PolicyStore, record::Session};
/// fn duplicate<S: PolicyStore>(session: Session<S>) {
///     let _ = session.clone();
/// }
/// ```
/// ```compile_fail
/// use bh_confidential_channel::{appraisal::PolicyStore, record::Session};
/// fn log<S: PolicyStore>(session: Session<S>) {
///     let _ = format!("{session:?}");
/// }
/// ```
/// Plaintext is owned and similarly non-Clone/non-Debug.
/// ```compile_fail
/// use bh_crypto::SecretBytes;
/// let plaintext = SecretBytes::from_vec(vec![42]);
/// let _ = plaintext.clone();
/// ```
pub struct Session<S: PolicyStore> {
    keys: Option<Keys>,
    appraisal: Appraisal<S>,
    binding: [u8; 32],
    outbound: u8,
    send_next: u64,
    recv_next: u64,
    sent_bytes: u64,
    recv_bytes: u64,
    confirmed_at: u64,
    last_mono: u64,
}
pub enum Opened {
    Data(SecretBytes),
    Closed,
}
impl<S: PolicyStore> Session<S> {
    pub(crate) fn new(
        keys: Keys,
        appraisal: Appraisal<S>,
        binding: [u8; 32],
        outbound: u8,
        now: u64,
    ) -> Self {
        Self {
            keys: Some(keys),
            appraisal,
            binding,
            outbound,
            send_next: 1,
            recv_next: 1,
            sent_bytes: 0,
            recv_bytes: 0,
            confirmed_at: now,
            last_mono: now,
        }
    }
    #[cfg(test)]
    pub(crate) fn appraisal_for_test(&self) -> &Appraisal<S> {
        &self.appraisal
    }
    pub fn binding(&self) -> Result<[u8; 32], Error> {
        self.keys.as_ref().map(|_| self.binding).ok_or(Error::Order)
    }
    pub fn is_closed(&self) -> bool {
        self.keys.is_none()
    }
    pub fn abort(&mut self) {
        self.keys = None;
    }
    fn use_now<R>(&mut self, action: impl FnOnce(&Keys) -> Result<R, Error>) -> Result<R, Error> {
        if self.keys.is_none() {
            return Err(Error::Order);
        }
        let result = self.appraisal.use_now(|sample| {
            let now = sample.monotonic_ms;
            if now < self.last_mono {
                return Err(Error::Clock);
            }
            if now
                .checked_sub(self.confirmed_at)
                .is_none_or(|d| d > SESSION_MS)
            {
                return Err(Error::Deadline);
            }
            let value = action(self.keys.as_ref().ok_or(Error::Order)?)?;
            Ok((value, now))
        });
        match result {
            Ok((value, now)) => {
                self.last_mono = now;
                Ok(value)
            }
            Err(error) => {
                self.abort();
                Err(error)
            }
        }
    }
    pub fn seal(&mut self, plaintext: SecretBytes) -> Result<Vec<u8>, Error> {
        let len = plaintext.expose().len();
        if !(1..=65_536).contains(&len) {
            self.abort();
            return Err(Error::Limit);
        }
        let Some(next) = self.sent_bytes.checked_add(len as u64) else {
            self.abort();
            return Err(Error::Limit);
        };
        if self.send_next > MAX_RECORDS || next > MAX_BYTES {
            self.abort();
            return Err(Error::Limit);
        }
        let direction = self.outbound;
        let seq = self.send_next;
        let binding = self.binding;
        let frame =
            self.use_now(|keys| seal_frame(keys, &binding, 6, direction, seq, plaintext.expose()))?;
        self.send_next += 1;
        self.sent_bytes = next;
        Ok(frame)
    }
    pub fn close(&mut self) -> Result<Vec<u8>, Error> {
        if self.send_next > MAX_RECORDS {
            self.abort();
            return Err(Error::Limit);
        }
        let direction = self.outbound;
        let seq = self.send_next;
        let binding = self.binding;
        let frame = self.use_now(|keys| seal_frame(keys, &binding, 7, direction, seq, b""))?;
        self.abort();
        Ok(frame)
    }
    pub fn open(&mut self, frame: &[u8]) -> Result<Opened, Error> {
        let result = (|| {
            let (kind, body) = wire::parse(frame)?;
            if kind != 6 && kind != 7 {
                return Err(Error::Order);
            }
            if body[0] != 1 - self.outbound {
                return Err(Error::Direction);
            }
            let seq = u64::from_be_bytes(body[1..9].try_into().map_err(|_| Error::Frame)?);
            if seq != self.recv_next {
                return Err(Error::Sequence);
            }
            if seq > MAX_RECORDS {
                return Err(Error::Limit);
            }
            let len = if kind == 6 { body.len() - 49 } else { 0 };
            let next = self
                .recv_bytes
                .checked_add(len as u64)
                .ok_or(Error::Limit)?;
            if next > MAX_BYTES {
                return Err(Error::Limit);
            }
            let binding = self.binding;
            let direction = body[0];
            let plaintext = self.use_now(|keys| {
                open_envelope(keys, &binding, frame, body, direction, seq, false)
            })?;
            self.recv_next += 1;
            self.recv_bytes = next;
            if kind == 7 {
                Ok(Opened::Closed)
            } else {
                Ok(Opened::Data(plaintext))
            }
        })();
        if result.is_err() || matches!(result, Ok(Opened::Closed)) {
            self.abort();
        }
        result
    }
}
fn key(keys: &Keys, direction: u8) -> &Secret<32> {
    if direction == 0 { &keys.c } else { &keys.s }
}
fn ad(label: &[u8], binding: &[u8; 32], header: &[u8], direction: u8, seq: u64) -> Vec<u8> {
    [
        DOMAIN,
        label,
        binding,
        header,
        &[direction],
        &seq.to_be_bytes(),
    ]
    .concat()
}
pub(crate) fn seal_frame(
    keys: &Keys,
    binding: &[u8; 32],
    kind: u8,
    direction: u8,
    seq: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let body_len = 1 + 8 + 24 + plaintext.len() + 16;
    let mut header = Vec::with_capacity(11);
    header.extend_from_slice(b"BHCH");
    header.extend_from_slice(&1u16.to_be_bytes());
    header.push(kind);
    header.extend_from_slice(&(body_len as u32).to_be_bytes());
    let label = if kind == 4 || kind == 5 {
        b"confirm\0".as_slice()
    } else {
        b"record\0".as_slice()
    };
    let (nonce, ciphertext) = bh_crypto::aead_seal(
        key(keys, direction),
        &ad(label, binding, &header, direction, seq),
        plaintext,
    )
    .map_err(|_| Error::Authentication)?;
    let mut body = Vec::with_capacity(body_len);
    body.push(direction);
    body.extend_from_slice(&seq.to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);
    if kind == 4 {
        return Err(Error::Frame);
    } // signature prefix is assembled by handshake
    wire::frame(kind, &body)
}
pub(crate) fn seal_finish(
    keys: &Keys,
    t: &[u8; 32],
    kind: u8,
    direction: u8,
    signature: Option<&[u8; 64]>,
) -> Result<Vec<u8>, Error> {
    let body_len = 49 + if kind == 4 { 64 } else { 0 };
    let header = [
        b"BHCH".as_slice(),
        &1u16.to_be_bytes(),
        &[kind],
        &(body_len as u32).to_be_bytes(),
    ]
    .concat();
    let (nonce, ciphertext) = bh_crypto::aead_seal(
        key(keys, direction),
        &ad(b"confirm\0", t, &header, direction, 0),
        b"",
    )
    .map_err(|_| Error::Authentication)?;
    let mut body = Vec::with_capacity(body_len);
    if let Some(sig) = signature {
        body.extend_from_slice(sig);
    }
    body.push(direction);
    body.extend_from_slice(&0u64.to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);
    wire::frame(kind, &body)
}
pub(crate) fn open_finish(
    keys: &Keys,
    t: &[u8; 32],
    frame: &[u8],
    kind: u8,
    direction: u8,
) -> Result<(), Error> {
    let (actual, body) = wire::parse(frame)?;
    if actual != kind {
        return Err(Error::Order);
    }
    let envelope = if kind == 4 { &body[64..] } else { body };
    let plaintext = open_envelope(keys, t, frame, envelope, direction, 0, true)?;
    if !plaintext.expose().is_empty() {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn open_envelope(
    keys: &Keys,
    binding: &[u8; 32],
    frame: &[u8],
    body: &[u8],
    direction: u8,
    sequence: u64,
    confirm: bool,
) -> Result<SecretBytes, Error> {
    if body[0] != direction {
        return Err(Error::Direction);
    }
    if u64::from_be_bytes(body[1..9].try_into().map_err(|_| Error::Frame)?) != sequence {
        return Err(Error::Sequence);
    }
    let nonce: &[u8; 24] = body[9..33].try_into().map_err(|_| Error::Frame)?;
    let label = if confirm {
        b"confirm\0".as_slice()
    } else {
        b"record\0".as_slice()
    };
    bh_crypto::aead_open(
        key(keys, direction),
        nonce,
        &ad(label, binding, &frame[..11], direction, sequence),
        &body[33..],
    )
    .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appraisal::PolicyStore;
    use bh_confidential_policy::Snapshot;
    struct NoStore;
    impl PolicyStore for NoStore {
        type Error = ();
        fn load(&mut self) -> Result<crate::appraisal::StoredState, Self::Error> {
            unreachable!()
        }
        fn save(&mut self, _: &Snapshot) -> Result<(), Self::Error> {
            unreachable!()
        }
    }
    fn keys() -> Keys {
        Keys {
            c: Secret::random(),
            s: Secret::random(),
        }
    }
    fn sample(ms: u64) -> Sample {
        Sample {
            system_seconds: None,
            monotonic_ms: ms,
        }
    }
    #[test]
    fn valid_tag_wrong_sequence_reflection_and_cross_session_terminate() {
        let keys = keys();
        let binding = [9; 32];
        let reflected = seal_frame(&keys, &binding, 6, 1, 1, b"valid tag").unwrap();
        let valid = seal_frame(&keys, &binding, 6, 0, 1, b"valid tag").unwrap();
        let mut receiver = Session::<NoStore>::new(
            keys,
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            1,
            10,
        );
        assert!(matches!(
            receiver.at(sample(11)).open(&reflected),
            Err(Error::Direction)
        ));
        assert!(receiver.is_closed());
        assert_eq!(receiver.binding(), Err(Error::Order));
        let keys = self::keys();
        let wrong_sequence = seal_frame(&keys, &binding, 6, 0, 2, b"valid tag").unwrap();
        let mut receiver = Session::<NoStore>::new(
            keys,
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            1,
            10,
        );
        assert!(matches!(
            receiver.at(sample(11)).open(&wrong_sequence),
            Err(Error::Sequence)
        ));
        assert!(receiver.is_closed());
        assert_eq!(receiver.binding(), Err(Error::Order));
        let mut receiver = Session::<NoStore>::new(
            self::keys(),
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            1,
            10,
        );
        assert!(matches!(
            receiver.at(sample(11)).open(&valid),
            Err(Error::Authentication)
        ));
        assert!(receiver.is_closed());
        assert_eq!(receiver.binding(), Err(Error::Order));
    }
    #[test]
    fn directional_count_and_byte_boundaries_are_independent() {
        let binding = [4; 32];
        let mut count = Session::<NoStore>::new(
            keys(),
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            0,
            10,
        );
        count.send_next = MAX_RECORDS;
        count
            .at(sample(11))
            .seal(SecretBytes::from_vec(vec![1]))
            .unwrap();
        assert_eq!(count.sent_bytes, 1);
        assert!(matches!(
            count.at(sample(12)).seal(SecretBytes::from_vec(vec![1])),
            Err(Error::Limit)
        ));
        assert!(count.is_closed());
        assert_eq!(count.binding(), Err(Error::Order));

        let keys = keys();
        let mut sender = Session::<NoStore>::new(
            Keys {
                c: Secret::from_slice(keys.c.expose()).unwrap(),
                s: Secret::from_slice(keys.s.expose()).unwrap(),
            },
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            0,
            10,
        );
        let mut receiver = Session::<NoStore>::new(
            keys,
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            1,
            10,
        );
        sender.sent_bytes = MAX_BYTES - 1;
        receiver.recv_bytes = MAX_BYTES - 1;
        let frame = sender
            .at(sample(11))
            .seal(SecretBytes::from_vec(vec![1]))
            .unwrap();
        assert_eq!(sender.sent_bytes, MAX_BYTES);
        assert!(matches!(
            receiver.at(sample(11)).open(&frame),
            Ok(Opened::Data(_))
        ));
        assert_eq!(receiver.recv_bytes, MAX_BYTES);
        assert!(matches!(
            sender.at(sample(12)).seal(SecretBytes::from_vec(vec![1])),
            Err(Error::Limit)
        ));
        assert!(sender.is_closed());
        assert_eq!(sender.binding(), Err(Error::Order));
        // Independently valid-tag, next-sequence Data at the receiver's byte cap.
        let next = seal_frame(receiver.keys.as_ref().unwrap(), &binding, 6, 0, 2, b"x").unwrap();
        assert!(matches!(
            receiver.at(sample(12)).open(&next),
            Err(Error::Limit)
        ));
        assert!(receiver.is_closed());
        assert_eq!(receiver.binding(), Err(Error::Order));

        let close_keys = self::keys();
        let mut sender = Session::<NoStore>::new(
            Keys {
                c: Secret::from_slice(close_keys.c.expose()).unwrap(),
                s: Secret::from_slice(close_keys.s.expose()).unwrap(),
            },
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            0,
            10,
        );
        let mut receiver = Session::<NoStore>::new(
            close_keys,
            Appraisal::Server(Box::new(crate::test_clock::read)),
            binding,
            1,
            10,
        );
        let close = sender.at(sample(11)).close().unwrap();
        assert!(sender.is_closed());
        assert_eq!(sender.binding(), Err(Error::Order));
        assert!(matches!(
            receiver.at(sample(11)).open(&close),
            Ok(Opened::Closed)
        ));
        assert!(receiver.is_closed());
        assert_eq!(receiver.binding(), Err(Error::Order));
    }
    #[test]
    fn caps_deadlines_backward_and_close_terminal() {
        let mut session = Session::<NoStore>::new(
            keys(),
            Appraisal::Server(Box::new(crate::test_clock::read)),
            [0; 32],
            1,
            10,
        );
        session.send_next = MAX_RECORDS;
        session.sent_bytes = MAX_BYTES - 1;
        session
            .at(sample(10))
            .seal(SecretBytes::from_vec(vec![1]))
            .unwrap();
        assert!(matches!(
            session.at(sample(10)).seal(SecretBytes::from_vec(vec![1])),
            Err(Error::Limit)
        ));
        assert!(session.is_closed());
        assert_eq!(session.binding(), Err(Error::Order));
        let mut session = Session::<NoStore>::new(
            keys(),
            Appraisal::Server(Box::new(crate::test_clock::read)),
            [0; 32],
            1,
            10,
        );
        assert!(matches!(
            session
                .at(sample(600_011))
                .seal(SecretBytes::from_vec(vec![1])),
            Err(Error::Deadline)
        ));
        assert!(session.is_closed());
        assert_eq!(session.binding(), Err(Error::Order));
        let mut session = Session::<NoStore>::new(
            keys(),
            Appraisal::Server(Box::new(crate::test_clock::read)),
            [0; 32],
            1,
            10,
        );
        session
            .at(sample(11))
            .seal(SecretBytes::from_vec(vec![1]))
            .unwrap();
        assert!(matches!(session.at(sample(10)).close(), Err(Error::Clock)));
        assert!(session.is_closed());
        assert_eq!(session.binding(), Err(Error::Order));
    }
}
