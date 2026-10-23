//! Canonical order openings and structural raw-control coverage.
//! Endpoint authority and control acceptance belong to the caller, not this module.
use crate::{BaseId, Digest, Error, EventId, Head, OpaqueEvent, Route};

const VERSION: u16 = 2;
const ZERO: Digest = Digest([0; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RawControlHead {
    pub position: u64,
    pub node_hash: Digest,
}
impl RawControlHead {
    pub const EMPTY: Self = Self {
        position: 0,
        node_hash: ZERO,
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OrderState {
    raw_control: RawControlHead,
    suffix_count: u64,
    suffix_hash: Digest,
}
impl OrderState {
    pub const EMPTY: Self = Self {
        raw_control: RawControlHead::EMPTY,
        suffix_count: 0,
        suffix_hash: ZERO,
    };
    pub const LEN: usize = 82;

    pub fn new(
        raw_control: RawControlHead,
        suffix_count: u64,
        suffix_hash: Digest,
    ) -> Result<Self, Error> {
        if (raw_control.position == 0
            && (raw_control != RawControlHead::EMPTY || suffix_count != 0))
            || (suffix_count == 0 && suffix_hash != ZERO)
        {
            return Err(Error::Encoding);
        }
        raw_control
            .position
            .checked_add(suffix_count)
            .ok_or(Error::Exhausted)?;
        Ok(Self {
            raw_control,
            suffix_count,
            suffix_hash,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::LEN {
            return Err(Error::Encoding);
        }
        let mut input = crate::log::Input(bytes);
        if u16::from_be_bytes(input.array()?) != VERSION {
            return Err(Error::Version);
        }
        let raw = RawControlHead {
            position: u64::from_be_bytes(input.array()?),
            node_hash: Digest(input.array()?),
        };
        let suffix_count = u64::from_be_bytes(input.array()?);
        let suffix_hash = Digest(input.array()?);
        Self::new(raw, suffix_count, suffix_hash)
    }
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[..2].copy_from_slice(&VERSION.to_be_bytes());
        bytes[2..10].copy_from_slice(&self.raw_control.position.to_be_bytes());
        bytes[10..42].copy_from_slice(&self.raw_control.node_hash.0);
        bytes[42..50].copy_from_slice(&self.suffix_count.to_be_bytes());
        bytes[50..82].copy_from_slice(&self.suffix_hash.0);
        bytes
    }
    pub fn raw_control(&self) -> RawControlHead {
        self.raw_control
    }
    pub fn suffix_count(&self) -> u64 {
        self.suffix_count
    }
    pub fn suffix_hash(&self) -> Digest {
        self.suffix_hash
    }
    pub fn position(&self) -> u64 {
        // Validated by construction; transitions use checked arithmetic.
        self.raw_control.position + self.suffix_count
    }
    pub fn head(&self, base: BaseId) -> Head {
        if *self == Self::EMPTY {
            return Head::EMPTY;
        }
        Head {
            position: self.position(),
            hash: crate::log::hash(b"bh/order-state/v2\0", &[&base.0, &self.encode()]),
        }
    }
}

pub fn publication_id(route: Route, event_digest: Digest) -> EventId {
    let domain: &[u8] = match route {
        Route::Control => b"bh/event-id/control/v1\0",
        Route::Content => b"bh/event-id/content/v1\0",
    };
    EventId(crate::log::hash(domain, &[&event_digest.0]).0)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CanonicalCommitment {
    base: BaseId,
    route: Route,
    before: OrderState,
    event_digest: Digest,
    after: OrderState,
}
impl CanonicalCommitment {
    pub const LEN: usize = 149;
    pub fn order(
        base: BaseId,
        before: OrderState,
        event_digest: Digest,
        route: Route,
    ) -> Result<Self, Error> {
        let previous = before.head(base);
        let position = previous.position.checked_add(1).ok_or(Error::Exhausted)?;
        if previous.position == 0
            && (before != OrderState::EMPTY || route != Route::Control || event_digest.0 != base.0)
        {
            return Err(Error::GenesisMismatch);
        }
        let after = match route {
            Route::Control => {
                let node_hash = crate::log::hash(
                    b"bh/control-node/v2\0",
                    &[
                        &base.0,
                        &position.to_be_bytes(),
                        &previous.position.to_be_bytes(),
                        &previous.hash.0,
                        &event_digest.0,
                    ],
                );
                OrderState::new(
                    RawControlHead {
                        position,
                        node_hash,
                    },
                    0,
                    ZERO,
                )?
            }
            Route::Content => {
                let count = before.suffix_count.checked_add(1).ok_or(Error::Exhausted)?;
                let raw = before.raw_control;
                let suffix_hash = crate::log::hash(
                    b"bh/content-suffix/v2\0",
                    &[
                        &base.0,
                        &raw.position.to_be_bytes(),
                        &raw.node_hash.0,
                        &count.to_be_bytes(),
                        &before.suffix_hash.0,
                        &event_digest.0,
                    ],
                );
                OrderState::new(raw, count, suffix_hash)?
            }
        };
        Ok(Self {
            base,
            route,
            before,
            event_digest,
            after,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::LEN {
            return Err(Error::Encoding);
        }
        if u16::from_be_bytes(bytes[..2].try_into().map_err(|_| Error::Encoding)?) != VERSION {
            return Err(Error::Version);
        }
        let base = BaseId(bytes[2..34].try_into().map_err(|_| Error::Encoding)?);
        let route = match bytes[34] {
            0 => Route::Content,
            1 => Route::Control,
            _ => return Err(Error::Encoding),
        };
        let before = OrderState::decode(&bytes[35..117])?;
        let digest = Digest(bytes[117..149].try_into().map_err(|_| Error::Encoding)?);
        Self::order(base, before, digest, route)
    }
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut bytes = [0; Self::LEN];
        bytes[..2].copy_from_slice(&VERSION.to_be_bytes());
        bytes[2..34].copy_from_slice(&self.base.0);
        bytes[34] = self.route as u8;
        bytes[35..117].copy_from_slice(&self.before.encode());
        bytes[117..149].copy_from_slice(&self.event_digest.0);
        bytes
    }
    pub fn base(&self) -> BaseId {
        self.base
    }
    pub fn route(&self) -> Route {
        self.route
    }
    pub fn event_digest(&self) -> Digest {
        self.event_digest
    }
    pub fn event_id(&self) -> EventId {
        publication_id(self.route, self.event_digest)
    }
    pub fn before(&self) -> OrderState {
        self.before
    }
    pub fn after(&self) -> OrderState {
        self.after
    }
    pub fn previous(&self) -> Head {
        self.before.head(self.base)
    }
    pub fn head(&self) -> Head {
        self.after.head(self.base)
    }
    pub fn verify_next(&self, base: BaseId, previous: Head) -> Result<Head, Error> {
        if self.base != base || self.previous() != previous {
            return Err(Error::HistoryMismatch);
        }
        Ok(self.head())
    }
    pub fn verify_body(&self, event: &OpaqueEvent) -> Result<(), Error> {
        if self.event_digest != event.digest() {
            return Err(Error::BodyMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoverageError {
    WrongBase,
    NotControl,
    MissingControl,
    EndpointMismatch,
}

pub struct RawControlChain {
    base: BaseId,
    current: RawControlHead,
}
impl RawControlChain {
    pub fn new(base: BaseId) -> Self {
        Self {
            base,
            current: RawControlHead::EMPTY,
        }
    }
    /// Continue from a raw control head the caller verified and kept
    /// durably. It is a starting point, not coverage: only `finish` against
    /// an authenticated endpoint establishes that.
    pub fn resume(base: BaseId, current: RawControlHead) -> Self {
        Self { base, current }
    }
    pub fn advance(&mut self, commitment: &CanonicalCommitment) -> Result<(), CoverageError> {
        if commitment.base != self.base {
            return Err(CoverageError::WrongBase);
        }
        if commitment.route != Route::Control {
            return Err(CoverageError::NotControl);
        }
        if commitment.before.raw_control != self.current {
            return Err(CoverageError::MissingControl);
        }
        self.current = commitment.after.raw_control;
        Ok(())
    }
    pub fn finish(
        &self,
        endpoint: OrderState,
        expected: Head,
    ) -> Result<ControlCoverage, CoverageError> {
        if endpoint.raw_control != self.current {
            return Err(CoverageError::MissingControl);
        }
        if endpoint.head(self.base) != expected {
            return Err(CoverageError::EndpointMismatch);
        }
        Ok(ControlCoverage {
            through: expected,
            raw_control: self.current,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ControlCoverage {
    through: Head,
    raw_control: RawControlHead,
}
impl ControlCoverage {
    pub fn through(&self) -> Head {
        self.through
    }
    pub fn raw_control(&self) -> RawControlHead {
        self.raw_control
    }
}
