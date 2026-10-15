//! Consuming five-frame, checker-only handshake. No network or device identity.
use crate::attestation::{self, Evidence, Expected, Time, VerifiedEvidence};
use crate::{
    Error,
    appraisal::{Clock, PolicyContext, PolicyStore},
    record::{Appraisal, Keys, Session, open_finish, seal_finish},
    wire::{self, DOMAIN},
};
use bh_crypto::{KemKey, SigningKey};
use std::marker::PhantomData;

const HANDSHAKE_MS: u64 = 60_000;
fn deadline(start: u64, last: u64, now: u64) -> Result<(), Error> {
    if now < last {
        return Err(Error::Clock);
    }
    if now
        .checked_sub(start)
        .is_none_or(|elapsed| elapsed > HANDSHAKE_MS)
    {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn transcript(hello: &[u8], proof: &[u8], encapsulation: &[u8]) -> [u8; 32] {
    bh_crypto::hash(&[DOMAIN, b"transcript\0", hello, proof, encapsulation].concat())
}
fn binding(t: &[u8; 32], server: &[u8], client: &[u8]) -> [u8; 32] {
    bh_crypto::hash(&[DOMAIN, b"binding\0", t, server, client].concat())
}
fn signature_message(t: &[u8; 32]) -> Vec<u8> {
    [DOMAIN, b"server-signature\0", t].concat()
}

pub struct ClientHello<S: PolicyStore> {
    context: PolicyContext<S>,
    nonce: [u8; 32],
    hello: Vec<u8>,
    start: u64,
}
impl<S: PolicyStore> ClientHello<S> {
    pub fn new(context: PolicyContext<S>) -> Result<Self, Error> {
        let now_ms = context.with_clock(|sample| Ok(sample.monotonic_ms))?;
        let nonce = bh_crypto::random();
        let root_hash = context.root_hash()?;
        let mut body = Vec::with_capacity(65);
        body.extend_from_slice(&nonce);
        body.push(1);
        body.extend_from_slice(&root_hash);
        let hello = wire::frame(1, &body).expect("fixed Hello");
        Ok(Self {
            context,
            nonce,
            hello,
            start: now_ms,
        })
    }
    pub fn frame(&self) -> &[u8] {
        &self.hello
    }
    /// Policy delivery is persisted even if a subsequent genuine attestation fails.
    pub fn accept_proof(self, frame: &[u8]) -> Result<ProofChecked<S>, Error> {
        self.accept_proof_with(frame, attestation::verify_evidence)
    }
    // Private injection boundary for synthetic full-assembly unit tests only.
    fn accept_proof_with(
        self,
        frame: &[u8],
        verify: impl FnOnce(
            Evidence<'_>,
            &Expected,
            Option<Time>,
        ) -> Result<VerifiedEvidence, attestation::Error>,
    ) -> Result<ProofChecked<S>, Error> {
        let (kind, body) = wire::parse(frame)?;
        if kind != 2 || self.hello.len() + frame.len() + 1142 + 124 + 60 > wire::MAX_HANDSHAKE {
            return Err(Error::Limit);
        }
        let proof = wire::proof(body)?;
        self.context
            .deliver_policy(proof.policy, &proof.signature)?;
        let admission = self.context.with_clock(|sample| {
            deadline(self.start, self.start, sample.monotonic_ms)?;
            let seconds = sample.system_seconds.ok_or(Error::Clock)?;
            Ok(Time {
                earliest: seconds,
                latest: seconds,
                max_uncertainty_secs: 0,
            })
        })?;
        let expected = Expected {
            signing: proof.signing,
            receiving: proof.receiving,
            nonce: self.nonce,
            role: bh_confidential_policy::Role::Checker,
        };
        // No app-root lock during Intel signatures/certs/TCB or full log replay.
        let evidence = verify(
            Evidence {
                quote: proof.quote,
                collateral: proof.collateral,
                event_log: proof.log,
            },
            &expected,
            Some(admission),
        )?;
        let appraisal = Appraisal::Client(self.context, Box::new(evidence));
        // A concurrent withdrawal/outage/pending save must win before publication.
        let sample = appraisal.use_now(|sample| {
            deadline(self.start, self.start, sample.monotonic_ms)?;
            Ok(sample)
        })?;
        Ok(ProofChecked {
            appraisal,
            hello: self.hello,
            proof: frame.to_vec(),
            start: self.start,
            last: sample.monotonic_ms,
        })
    }
}

pub struct ProofChecked<S: PolicyStore> {
    appraisal: Appraisal<S>,
    hello: Vec<u8>,
    proof: Vec<u8>,
    start: u64,
    last: u64,
}
impl<S: PolicyStore> ProofChecked<S> {
    pub fn encapsulate(self) -> Result<(Vec<u8>, ClientAwaitServer<S>), Error> {
        let receiving = match &self.appraisal {
            Appraisal::Client(_, evidence) => *evidence.measured().receiving(),
            Appraisal::Server(_) => return Err(Error::Order),
        };
        let ((ct, shared), sample) = self.appraisal.use_now(|sample| {
            deadline(self.start, self.last, sample.monotonic_ms)?;
            Ok((
                bh_crypto::encapsulate(&receiving).map_err(|_| Error::Authentication)?,
                sample,
            ))
        })?;
        let encapsulation = wire::frame(3, &ct)?;
        let t = transcript(&self.hello, &self.proof, &encapsulation);
        let keys = Keys {
            c: bh_crypto::derive_key(&shared, b"BHCHC001", 0),
            s: bh_crypto::derive_key(&shared, b"BHCHS001", 0),
        };
        drop(shared);
        let (_, body) = wire::parse(&self.proof)?;
        let signing = wire::proof(body)?.signing;
        Ok((
            encapsulation,
            ClientAwaitServer {
                appraisal: self.appraisal,
                keys,
                t,
                signing,
                start: self.start,
                last: sample.monotonic_ms,
            },
        ))
    }
}

/// Consuming state: an accepted Finish cannot be processed a second time.
///
/// ```compile_fail
/// use bh_confidential_channel::{appraisal::PolicyStore, handshake::ClientAwaitServer};
/// fn retry<S: PolicyStore>(state: ClientAwaitServer<S>, frame: &[u8]) {
///     let _ = state.accept_finish(frame);
///     let _ = state.accept_finish(frame); // moved state
/// }
/// ```
///
/// A pending secret-bearing handshake is neither Clone nor Debug.
/// ```compile_fail
/// use bh_confidential_channel::{appraisal::PolicyStore, handshake::ClientAwaitServer};
/// fn duplicate<S: PolicyStore>(state: ClientAwaitServer<S>) {
///     let _ = state.clone();
/// }
/// ```
/// ```compile_fail
/// use bh_confidential_channel::{appraisal::PolicyStore, handshake::ClientAwaitServer};
/// fn log<S: PolicyStore>(state: ClientAwaitServer<S>) {
///     let _ = format!("{state:?}");
/// }
/// ```
pub struct ClientAwaitServer<S: PolicyStore> {
    appraisal: Appraisal<S>,
    keys: Keys,
    t: [u8; 32],
    signing: [u8; 32],
    start: u64,
    last: u64,
}
impl<S: PolicyStore> ClientAwaitServer<S> {
    pub fn accept_finish(self, server: &[u8]) -> Result<(Vec<u8>, Session<S>), Error> {
        let (client, sample) = self.appraisal.use_now(|sample| {
            deadline(self.start, self.last, sample.monotonic_ms)?;
            let (kind, body) = wire::parse(server)?;
            if kind != 4 {
                return Err(Error::Order);
            }
            let signature: &[u8; 64] = body[..64].try_into().map_err(|_| Error::Frame)?;
            bh_crypto::verify(&self.signing, &signature_message(&self.t), signature)
                .map_err(|_| Error::Authentication)?;
            open_finish(&self.keys, &self.t, server, 4, 1)?;
            Ok((seal_finish(&self.keys, &self.t, 5, 0, None)?, sample))
        })?;
        let b = binding(&self.t, server, &client);
        Ok((
            client,
            Session::new(self.keys, self.appraisal, b, 0, sample.monotonic_ms),
        ))
    }
}

pub struct ServerPending<S: PolicyStore> {
    signing: SigningKey,
    receiving: KemKey,
    hello: Vec<u8>,
    start: u64,
    last: u64,
    _store: PhantomData<S>,
}
impl<S: PolicyStore> ServerPending<S> {
    pub fn accept_hello(hello: &[u8], app_root: [u8; 32], now_ms: u64) -> Result<Self, Error> {
        let (kind, body) = wire::parse(hello)?;
        if kind != 1 || body[32] != 1 || body[33..65] != bh_crypto::hash(&app_root) {
            return Err(Error::Authentication);
        }
        Ok(Self {
            signing: SigningKey::generate(),
            receiving: KemKey::generate(),
            hello: hello.to_vec(),
            start: now_ms,
            last: now_ms,
            _store: PhantomData,
        })
    }
    pub fn report_data(&self) -> [u8; 64] {
        let nonce: &[u8; 32] = self.hello[11..43].try_into().expect("fixed Hello");
        bh_confidential_attestation::report_data(
            &self.signing.public(),
            &self.receiving.public(),
            nonce,
        )
    }
    /// Caller acquires a fresh quote containing `report_data`; no fake proof
    /// capability is supplied here. This stage does not claim server authorization.
    pub fn attach_evidence(
        self,
        policy: &[u8],
        signature: &[u8; 64],
        quote: &[u8],
        collateral: &[u8],
        log: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, ServerAwaitEncapsulation<S>), Error> {
        deadline(self.start, self.last, now_ms)?;
        let proof = wire::make_proof(
            &self.signing.public(),
            &self.receiving.public(),
            policy,
            signature,
            quote,
            collateral,
            log,
        )?;
        if self.hello.len() + proof.len() + 1142 + 124 + 60 > wire::MAX_HANDSHAKE {
            return Err(Error::Limit);
        }
        Ok((
            proof.clone(),
            ServerAwaitEncapsulation {
                signing: self.signing,
                receiving: self.receiving,
                hello: self.hello,
                proof,
                start: self.start,
                last: now_ms,
                _store: PhantomData,
            },
        ))
    }
}
pub struct ServerAwaitEncapsulation<S: PolicyStore> {
    signing: SigningKey,
    receiving: KemKey,
    hello: Vec<u8>,
    proof: Vec<u8>,
    start: u64,
    last: u64,
    _store: PhantomData<S>,
}
impl<S: PolicyStore> ServerAwaitEncapsulation<S> {
    pub fn accept_encapsulation(
        self,
        encapsulation: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, ServerAwaitClient<S>), Error> {
        deadline(self.start, self.last, now_ms)?;
        let (kind, body) = wire::parse(encapsulation)?;
        if kind != 3 {
            return Err(Error::Order);
        }
        let ct: &[u8; 1120] = body.try_into().map_err(|_| Error::Frame)?;
        let shared =
            bh_crypto::decapsulate(&self.receiving, ct).map_err(|_| Error::Authentication)?;
        drop(self.receiving);
        let t = transcript(&self.hello, &self.proof, encapsulation);
        let keys = Keys {
            c: bh_crypto::derive_key(&shared, b"BHCHC001", 0),
            s: bh_crypto::derive_key(&shared, b"BHCHS001", 0),
        };
        drop(shared);
        let signature = self.signing.sign(&signature_message(&t));
        drop(self.signing);
        let finish = seal_finish(&keys, &t, 4, 1, Some(&signature))?;
        Ok((
            finish.clone(),
            ServerAwaitClient {
                keys,
                t,
                finish,
                start: self.start,
                last: now_ms,
                _store: PhantomData,
            },
        ))
    }
}
/// The server also consumes its confirmation gate exactly once.
/// ```compile_fail
/// use bh_confidential_channel::{appraisal::{PolicyStore, Sample}, handshake::ServerAwaitClient};
/// fn clock() -> Sample { Sample { system_seconds: None, monotonic_ms: 1 } }
/// fn retry<S: PolicyStore>(state: ServerAwaitClient<S>, frame: &[u8]) {
///     let _ = state.accept_finish(frame, clock);
///     let _ = state.accept_finish(frame, clock); // moved state
/// }
/// ```
pub struct ServerAwaitClient<S: PolicyStore> {
    keys: Keys,
    t: [u8; 32],
    finish: Vec<u8>,
    start: u64,
    last: u64,
    _store: PhantomData<S>,
}
impl<S: PolicyStore> ServerAwaitClient<S> {
    pub fn accept_finish(
        self,
        client: &[u8],
        clock: impl Clock + 'static,
    ) -> Result<Session<S>, Error> {
        let now_ms = clock.sample().monotonic_ms;
        deadline(self.start, self.last, now_ms)?;
        open_finish(&self.keys, &self.t, client, 5, 0)?;
        let b = binding(&self.t, &self.finish, client);
        Ok(Session::new(
            self.keys,
            Appraisal::Server(Box::new(clock)),
            b,
            1,
            now_ms,
        ))
    }
}

#[cfg(test)]
impl<S: PolicyStore> ClientHello<S> {
    pub(crate) fn synthetic_checked(
        self,
        frame: &[u8],
        build: bh_confidential_policy::Build,
        machine: [u8; 32],
    ) -> Result<ProofChecked<S>, Error> {
        self.accept_proof_with(frame, |_, expected, time| {
            attestation::synthetic_evidence(expected, time.unwrap(), Some((build, machine)))
        })
    }
    pub(crate) fn checked_with_test(
        self,
        frame: &[u8],
        verify: impl FnOnce(
            Evidence<'_>,
            &Expected,
            Option<Time>,
        ) -> Result<VerifiedEvidence, attestation::Error>,
    ) -> Result<ProofChecked<S>, Error> {
        self.accept_proof_with(frame, verify)
    }
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
