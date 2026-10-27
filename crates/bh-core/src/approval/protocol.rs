//! The approval exchange as pure functions; the core and test kit carry its
//! messages. The new device commits to its key and a hidden random value; the
//! approving device encapsulates once; both derive the six digits and the
//! transfer key from the whole transcript.
//!
//! Each side measures two minutes on the caller's monotonic clock and ends at
//! its first failure: every later step returns the same `ApprovalEnded`.

use crate::envelope::{self, Aad, Purpose};
use crate::{EndReason, Error};
use bh_crypto::{
    KemKey, Secret, XWING_CIPHERTEXT_BYTES, XWING_PUBLIC_BYTES, constant_time_eq, decapsulate,
    encapsulate, generichash, kdf, random,
};
use bh_proto::{AccountId, ApprovalId, DeviceId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, mem};
use ts_rs::TS;
use zeroize::{Zeroize, Zeroizing};

/// How long each device keeps an exchange open, from its own first step.
pub const TTL_MS: u64 = 120_000;

const FORMAT: u8 = 1;
const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;
const REVEAL: u8 = 3;
const TRANSFER: u8 = 4;
const HEADER: usize = 2 + 16;
const REQUEST_LEN: usize = HEADER + 16 + XWING_PUBLIC_BYTES + 32;
const RESPONSE_LEN: usize = HEADER + 16 + XWING_CIPHERTEXT_BYTES + 32;
const NAME_MAX: usize = 64;
const REVEAL_MIN: usize = HEADER + 32 + envelope::OVERHEAD;
const TRANSFER_LEN: usize = HEADER + envelope::OVERHEAD + 32;

fn bad() -> Error {
    Error::ApprovalEnded(EndReason::BadMessage)
}

/// Six digits, leading zeroes kept. Wiped on drop, compared in constant time
/// and never shown by `Debug`; `Display` shows them as `482 913`.
#[derive(Clone, TS)]
#[ts(
    type = "string",
    export,
    export_to = "apps/basehero/src/lib/generated/"
)]
pub struct Digits([u8; 6]);

impl Digits {
    /// Six ASCII digits; spaces and hyphens are ignored, anything else is refused.
    pub fn parse(typed: &str) -> Result<Digits, Error> {
        let mut digits = Digits([0; 6]);
        let mut count = 0;
        for byte in typed.trim().bytes() {
            match byte {
                b'0'..=b'9' if count < 6 => {
                    digits.0[count] = byte;
                    count += 1;
                }
                b' ' | b'-' => {}
                _ => return Err(Error::invalid("type the six digits")),
            }
        }
        if count != 6 {
            return Err(Error::invalid("type the six digits"));
        }
        Ok(digits)
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("digits are ASCII")
    }
}

impl Drop for Digits {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for Digits {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for Digits {}

impl fmt::Debug for Digits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Digits(..)")
    }
}

impl fmt::Display for Digits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.as_str();
        write!(f, "{} {}", &text[..3], &text[3..])
    }
}

impl Serialize for Digits {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Digits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let typed = Zeroizing::new(String::deserialize(deserializer)?);
        Digits::parse(&typed).map_err(serde::de::Error::custom)
    }
}

/// The digits of 32 bytes of material: the first eight, big-endian, modulo a
/// million. The bias is below 2^-44.
pub fn digits_from(material: &Secret<32>) -> Digits {
    let bytes = Zeroizing::new(<[u8; 8]>::try_from(&material.expose()[..8]).expect("eight bytes"));
    let mut n = u64::from_be_bytes(*bytes) % 1_000_000;
    let mut digits = Digits([0; 6]);
    for slot in digits.0.iter_mut().rev() {
        *slot = b'0' + (n % 10) as u8;
        n /= 10;
    }
    digits
}

/// The exchange's identities, fixed by the new device's request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ids {
    pub account: AccountId,
    pub approval: ApprovalId,
    pub new: DeviceId,
}

/// The new device's commitment to its public key and hidden random value.
/// Every input has a fixed length, so concatenation is unambiguous.
pub fn commitment(ids: &Ids, pk: &[u8; XWING_PUBLIC_BYTES], r_new: &[u8; 32]) -> [u8; 32] {
    generichash(
        None,
        &[
            b"bh.v1.approval-commit",
            &ids.account.0,
            &ids.approval.0,
            &ids.new.0,
            pk,
            r_new,
        ],
    )
}

/// Everything both devices saw; the digits and transfer key depend on all of it.
pub struct Transcript<'a> {
    pub ids: &'a Ids,
    pub approver: DeviceId,
    pub pk: &'a [u8; XWING_PUBLIC_BYTES],
    pub commitment: &'a [u8; 32],
    pub ct: &'a [u8; XWING_CIPHERTEXT_BYTES],
    pub r_approver: &'a [u8; 32],
    pub r_new: &'a [u8; 32],
}

impl Transcript<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"bh.v1.approval-transcript".to_vec();
        out.extend_from_slice(&1u32.to_be_bytes());
        for part in [
            &self.ids.account.0[..],
            &self.ids.approval.0,
            b"new",
            &self.ids.new.0,
            b"approver",
            &self.approver.0,
            self.pk,
            self.commitment,
            self.ct,
            self.r_approver,
            self.r_new,
        ] {
            let len = u32::try_from(part.len()).expect("transcript part fits u32");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }
}

/// The digits and transfer key from the shared secret and the encoded transcript.
pub fn derive(shared: &Secret<32>, transcript: &[u8]) -> (Digits, Secret<32>) {
    let bound = Zeroizing::new(generichash(Some(shared.expose()), &[transcript]));
    let bound = Secret::from_slice(&*bound).expect("32 bytes");
    let material = kdf(&bound, b"bhaprdg1", 1);
    (digits_from(&material), kdf(&bound, b"bhaprtk1", 1))
}

/// The four messages, binary and opaque to the server.
pub enum Message {
    Request {
        approval: ApprovalId,
        new: DeviceId,
        pk: Box<[u8; XWING_PUBLIC_BYTES]>,
        commitment: [u8; 32],
    },
    Response {
        approval: ApprovalId,
        approver: DeviceId,
        ct: Box<[u8; XWING_CIPHERTEXT_BYTES]>,
        r_approver: [u8; 32],
    },
    /// `name` is the device name sealed under the transfer key.
    Reveal {
        approval: ApprovalId,
        r_new: [u8; 32],
        name: Vec<u8>,
    },
    /// `account_key` is the account key sealed under the transfer key.
    Transfer {
        approval: ApprovalId,
        account_key: Vec<u8>,
    },
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let (kind, approval, parts): (u8, &ApprovalId, [&[u8]; 3]) = match self {
            Self::Request {
                approval,
                new,
                pk,
                commitment,
            } => (REQUEST, approval, [&new.0, &pk[..], commitment]),
            Self::Response {
                approval,
                approver,
                ct,
                r_approver,
            } => (RESPONSE, approval, [&approver.0, &ct[..], r_approver]),
            Self::Reveal {
                approval,
                r_new,
                name,
            } => (REVEAL, approval, [r_new, name, &[]]),
            Self::Transfer {
                approval,
                account_key,
            } => (TRANSFER, approval, [account_key, &[], &[]]),
        };
        let mut out = vec![FORMAT, kind];
        out.extend_from_slice(&approval.0);
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    /// Another format is `NeedsUpdate`; a wrong kind, length or approval is
    /// `ApprovalEnded(BadMessage)`.
    pub fn parse(bytes: &[u8], approval: ApprovalId) -> Result<Message, Error> {
        match bytes.first() {
            Some(&FORMAT) => {}
            Some(_) => return Err(Error::NeedsUpdate),
            None => return Err(bad()),
        }
        if bytes.len() < HEADER || bytes[2..HEADER] != approval.0 {
            return Err(bad());
        }
        let body = &bytes[HEADER..];
        let fixed = |len: usize| bytes.len() == len;
        match bytes[1] {
            REQUEST if fixed(REQUEST_LEN) => Ok(Self::Request {
                approval,
                new: DeviceId(array(&body[..16])),
                pk: Box::new(array(&body[16..16 + XWING_PUBLIC_BYTES])),
                commitment: array(&body[16 + XWING_PUBLIC_BYTES..]),
            }),
            RESPONSE if fixed(RESPONSE_LEN) => Ok(Self::Response {
                approval,
                approver: DeviceId(array(&body[..16])),
                ct: Box::new(array(&body[16..16 + XWING_CIPHERTEXT_BYTES])),
                r_approver: array(&body[16 + XWING_CIPHERTEXT_BYTES..]),
            }),
            REVEAL if (REVEAL_MIN..=REVEAL_MIN + NAME_MAX).contains(&bytes.len()) => {
                Ok(Self::Reveal {
                    approval,
                    r_new: array(&body[..32]),
                    name: body[32..].to_vec(),
                })
            }
            TRANSFER if fixed(TRANSFER_LEN) => Ok(Self::Transfer {
                approval,
                account_key: body.to_vec(),
            }),
            _ => Err(bad()),
        }
    }
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("length checked")
}

fn aad(purpose: Purpose, ids: &Ids) -> Aad {
    Aad {
        purpose,
        base: ids.approval.0,
        object: ids.new.0,
        epoch: 1,
    }
}

/// The UTF-8 name cut to at most 64 bytes on a character boundary.
fn cut(name: &str) -> &str {
    let mut end = name.len().min(NAME_MAX);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

fn end<T>(reason: EndReason) -> Result<T, Error> {
    Err(Error::ApprovalEnded(reason))
}

/// The new device's side, from its request until it receives the account key.
pub struct NewSide {
    ids: Ids,
    deadline: u64,
    state: NewState,
}

enum NewState {
    Requested {
        kem: Box<KemKey>,
        commitment: [u8; 32],
        r_new: Zeroizing<[u8; 32]>,
    },
    Revealed {
        transfer_key: Secret<32>,
    },
    Ended(EndReason),
}

impl NewSide {
    /// Step 1: a fresh key and hidden random value; returns the request.
    pub fn start(ids: Ids, now_ms: u64) -> (NewSide, Vec<u8>) {
        let kem = Box::new(KemKey::generate());
        let pk = kem.public();
        let r_new = Zeroizing::new(random::<32>());
        let commitment = commitment(&ids, &pk, &r_new);
        let request = Message::Request {
            approval: ids.approval,
            new: ids.new,
            pk: Box::new(pk),
            commitment,
        }
        .encode();
        let side = NewSide {
            ids,
            deadline: now_ms.saturating_add(TTL_MS),
            state: NewState::Requested {
                kem,
                commitment,
                r_new,
            },
        };
        (side, request)
    }

    /// Step 3: takes the one response; returns the reveal and the digits to show.
    pub fn on_response(
        &mut self,
        response: &[u8],
        device_name: &str,
        now_ms: u64,
    ) -> Result<(Vec<u8>, Digits), Error> {
        let state = mem::replace(&mut self.state, NewState::Ended(EndReason::BadMessage));
        let (kem, commitment, r_new) = match state {
            NewState::Ended(reason) => {
                self.state = NewState::Ended(reason);
                return end(reason);
            }
            _ if now_ms >= self.deadline => {
                self.state = NewState::Ended(EndReason::Expired);
                return end(EndReason::Expired);
            }
            NewState::Revealed { .. } => return end(EndReason::BadMessage),
            NewState::Requested {
                kem,
                commitment,
                r_new,
            } => (kem, commitment, r_new),
        };
        let Message::Response {
            approver,
            ct,
            r_approver,
            ..
        } = Message::parse(response, self.ids.approval)?
        else {
            return Err(bad());
        };
        if approver == self.ids.new {
            return Err(bad());
        }
        let shared = decapsulate(&kem, &ct).map_err(|_| bad())?;
        let transcript = Transcript {
            ids: &self.ids,
            approver,
            pk: &kem.public(),
            commitment: &commitment,
            ct: &ct,
            r_approver: &r_approver,
            r_new: &r_new,
        }
        .encode();
        let (digits, transfer_key) = derive(&shared, &transcript);
        let name = envelope::seal(
            &transfer_key,
            &aad(Purpose::ApprovalDeviceName, &self.ids),
            cut(device_name).as_bytes(),
        );
        let reveal = Message::Reveal {
            approval: self.ids.approval,
            r_new: *r_new,
            name,
        }
        .encode();
        self.state = NewState::Revealed { transfer_key };
        Ok((reveal, digits))
    }

    /// Step 7: opens the account key from the transfer.
    pub fn on_transfer(self, transfer: &[u8], now_ms: u64) -> Result<Secret<32>, Error> {
        let transfer_key = match self.state {
            NewState::Ended(reason) => return end(reason),
            _ if now_ms >= self.deadline => return end(EndReason::Expired),
            NewState::Requested { .. } => return Err(bad()),
            NewState::Revealed { transfer_key } => transfer_key,
        };
        let Message::Transfer { account_key, .. } = Message::parse(transfer, self.ids.approval)?
        else {
            return Err(bad());
        };
        let opened = envelope::open(
            &transfer_key,
            &aad(Purpose::ApprovalTransfer, &self.ids),
            &account_key,
        )
        .map_err(|_| bad())?;
        Secret::from_slice(&opened).map_err(|_| bad())
    }
}

/// The approving device's side, from its one response until it sends the
/// account key or the digits don't match.
pub struct ApproverSide {
    ids: Ids,
    me: DeviceId,
    pk: Box<[u8; XWING_PUBLIC_BYTES]>,
    commitment: [u8; 32],
    ct: Box<[u8; XWING_CIPHERTEXT_BYTES]>,
    r_approver: [u8; 32],
    deadline: u64,
    state: ApproverState,
}

enum ApproverState {
    Responded {
        shared: Secret<32>,
    },
    Revealed {
        digits: Digits,
        transfer_key: Secret<32>,
    },
    Ended(EndReason),
}

impl ApproverSide {
    /// Step 2: the one encapsulation for this request's commitment. The caller
    /// records `commitment()` before sending the response.
    pub fn respond(
        account: AccountId,
        me: DeviceId,
        approval: ApprovalId,
        request: &[u8],
        now_ms: u64,
    ) -> Result<(ApproverSide, Vec<u8>), Error> {
        let Message::Request {
            new,
            pk,
            commitment,
            ..
        } = Message::parse(request, approval)?
        else {
            return Err(bad());
        };
        if new == me {
            return Err(bad());
        }
        let (ct, shared) = encapsulate(&pk).map_err(|_| bad())?;
        let ct = Box::new(ct);
        let r_approver = random::<32>();
        let response = Message::Response {
            approval,
            approver: me,
            ct: ct.clone(),
            r_approver,
        }
        .encode();
        let side = ApproverSide {
            ids: Ids {
                account,
                approval,
                new,
            },
            me,
            pk,
            commitment,
            ct,
            r_approver,
            deadline: now_ms.saturating_add(TTL_MS),
            state: ApproverState::Responded { shared },
        };
        Ok((side, response))
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn new_device(&self) -> DeviceId {
        self.ids.new
    }

    /// Checks the commitment and derives the digits; returns the new device's
    /// name, an unverified label until the digits match.
    pub fn on_reveal(&mut self, reveal: &[u8], now_ms: u64) -> Result<String, Error> {
        let state = mem::replace(&mut self.state, ApproverState::Ended(EndReason::BadMessage));
        let shared = match state {
            ApproverState::Ended(reason) => {
                self.state = ApproverState::Ended(reason);
                return end(reason);
            }
            _ if now_ms >= self.deadline => {
                self.state = ApproverState::Ended(EndReason::Expired);
                return end(EndReason::Expired);
            }
            ApproverState::Revealed { .. } => return end(EndReason::BadMessage),
            ApproverState::Responded { shared } => shared,
        };
        let Message::Reveal { r_new, name, .. } = Message::parse(reveal, self.ids.approval)? else {
            return Err(bad());
        };
        let opened = commitment(&self.ids, &self.pk, &r_new);
        if !constant_time_eq(&opened, &self.commitment) {
            return Err(bad());
        }
        let transcript = Transcript {
            ids: &self.ids,
            approver: self.me,
            pk: &self.pk,
            commitment: &self.commitment,
            ct: &self.ct,
            r_approver: &self.r_approver,
            r_new: &r_new,
        }
        .encode();
        let (digits, transfer_key) = derive(&shared, &transcript);
        let name = envelope::open(
            &transfer_key,
            &aad(Purpose::ApprovalDeviceName, &self.ids),
            &name,
        )
        .map_err(|_| bad())?;
        let name = String::from_utf8(name.to_vec()).map_err(|_| bad())?;
        self.state = ApproverState::Revealed {
            digits,
            transfer_key,
        };
        Ok(name)
    }

    /// Steps 5–7: compares the typed digits and, only if they match, seals the
    /// account key for the new device. A mismatch ends the exchange.
    pub fn confirm(
        self,
        typed: &Digits,
        account_key: &Secret<32>,
        now_ms: u64,
    ) -> Result<Vec<u8>, Error> {
        let (digits, transfer_key) = match self.state {
            ApproverState::Ended(reason) => return end(reason),
            _ if now_ms >= self.deadline => return end(EndReason::Expired),
            ApproverState::Responded { .. } => return Err(bad()),
            ApproverState::Revealed {
                digits,
                transfer_key,
            } => (digits, transfer_key),
        };
        if *typed != digits {
            return end(EndReason::WrongDigits);
        }
        Ok(Message::Transfer {
            approval: self.ids.approval,
            account_key: envelope::seal(
                &transfer_key,
                &aad(Purpose::ApprovalTransfer, &self.ids),
                account_key.expose(),
            ),
        }
        .encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "Dan - Fold";
    const START: u64 = 1_000;
    const RESPOND: u64 = 50_000;

    fn ids() -> Ids {
        Ids {
            account: AccountId::random(),
            approval: ApprovalId::random(),
            new: DeviceId::random(),
        }
    }

    fn ended(reason: EndReason) -> Error {
        Error::ApprovalEnded(reason)
    }

    /// The error of a result whose value has no `Debug`, such as a secret.
    fn err<T>(result: Result<T, Error>) -> Error {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(error) => error,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Both sides after the reveal: the new device shows `digits`.
    struct Revealed {
        ids: Ids,
        new: NewSide,
        approver: ApproverSide,
        digits: Digits,
        name: String,
        reveal: Vec<u8>,
        response: Vec<u8>,
    }

    fn to_reveal(ids: Ids, name: &str) -> Revealed {
        let account = ids.account;
        let approval = ids.approval;
        let (mut new, request) = NewSide::start(ids, START);
        let (mut approver, response) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        let (reveal, digits) = new.on_response(&response, name, START + 1).unwrap();
        let name = approver.on_reveal(&reveal, RESPOND + 1).unwrap();
        Revealed {
            ids,
            new,
            approver,
            digits,
            name,
            reveal,
            response,
        }
    }

    /// An honest exchange: the new device's digits, the name the approver
    /// read, the account key sent and the account key received.
    fn honest() -> (Digits, String, Secret<32>, Secret<32>) {
        let r = to_reveal(ids(), NAME);
        let ak = Secret::<32>::random();
        let transfer = r.approver.confirm(&r.digits, &ak, RESPOND + 2).unwrap();
        let received = r.new.on_transfer(&transfer, START + 2).unwrap();
        (r.digits, r.name, ak, received)
    }

    fn other_digits(digits: &Digits) -> Digits {
        let n: u32 = digits.as_str().parse().unwrap();
        Digits::parse(&format!("{:06}", (n + 1) % 1_000_000)).unwrap()
    }

    #[test]
    fn an_honest_exchange_gives_both_sides_the_same_digits_and_key() {
        let (digits, name, sent, received) = honest();
        assert_eq!(digits.as_str().len(), 6);
        assert_eq!(name, NAME);
        assert_eq!(sent.expose(), received.expose());
    }

    #[test]
    fn derivation_matches_its_test_vector() {
        let ids = Ids {
            account: AccountId([1; 16]),
            approval: ApprovalId([2; 16]),
            new: DeviceId([3; 16]),
        };
        let transcript = Transcript {
            ids: &ids,
            approver: DeviceId([4; 16]),
            pk: &[5; XWING_PUBLIC_BYTES],
            commitment: &[6; 32],
            ct: &[7; XWING_CIPHERTEXT_BYTES],
            r_approver: &[8; 32],
            r_new: &[9; 32],
        }
        .encode();
        let (digits, tk) = derive(&Secret::from_slice(&[10; 32]).unwrap(), &transcript);
        let actual = (
            hex(&bh_crypto::generichash(None, &[&transcript])),
            digits.as_str().to_string(),
            hex(tk.expose()),
        );
        // Recorded on first run and matched by an independent Python
        // implementation; a change to the derivation fails here.
        let pinned = (
            "26ffb80215f0985e19e187031ace62b8dd89625c7b94a5175ffcc97ba3d85c3a",
            "585540",
            "cf83f427787d71556bb22b1d7f47f8074fdfb8d7c59868eca3f2f0dadf938ae8",
        );
        assert_eq!(
            (actual.0.as_str(), actual.1.as_str(), actual.2.as_str()),
            pinned,
            "pinned (T hash, digits, TK)"
        );
    }

    #[test]
    fn digits_keep_leading_zeroes() {
        let mut material = [0xff; 32];
        material[..8].copy_from_slice(&7u64.to_be_bytes());
        let digits = digits_from(&Secret::from_slice(&material).unwrap());
        assert_eq!(digits.as_str(), "000007");
        assert_eq!(digits.to_string(), "000 007");
    }

    #[test]
    fn digits_are_uniform() {
        let mut counts = [[0u32; 10]; 6];
        for _ in 0..100_000 {
            let digits = digits_from(&Secret::<32>::random());
            for (position, c) in digits.as_str().bytes().enumerate() {
                counts[position][usize::from(c - b'0')] += 1;
            }
        }
        for (position, values) in counts.iter().enumerate() {
            for (value, &count) in values.iter().enumerate() {
                assert!(
                    (9_500..=10_500).contains(&count),
                    "position {position} value {value} occurred {count} times"
                );
            }
        }
    }

    #[test]
    fn typed_digits_parse_forgivingly_but_exactly() {
        for typed in ["482 913", "482-913", " 482913 "] {
            assert_eq!(
                Digits::parse(typed).unwrap().as_str(),
                "482913",
                "{typed:?}"
            );
        }
        for typed in ["48291", "4829134", "48291a", "４８２９１３"] {
            assert!(
                matches!(Digits::parse(typed), Err(Error::Invalid(_))),
                "{typed:?}"
            );
        }
    }

    #[test]
    fn wrong_digits_end_the_exchange() {
        let r = to_reveal(ids(), NAME);
        let wrong = other_digits(&r.digits);
        let result = r
            .approver
            .confirm(&wrong, &Secret::<32>::random(), RESPOND + 2);
        assert_eq!(result.unwrap_err(), ended(EndReason::WrongDigits));
    }

    #[test]
    fn an_expired_exchange_refuses_every_step() {
        // The new device times itself from its request.
        let ids_ = ids();
        let (account, approval) = (ids_.account, ids_.approval);
        let (mut late, request) = NewSide::start(ids_, START);
        let (_, response) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        assert_eq!(
            late.on_response(&response, NAME, START + TTL_MS)
                .unwrap_err(),
            ended(EndReason::Expired)
        );

        let ids_ = ids();
        let (account, approval) = (ids_.account, ids_.approval);
        let (mut new, request) = NewSide::start(ids_, START);
        let (mut approver, response) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        let (reveal, digits) = new
            .on_response(&response, NAME, START + TTL_MS - 1)
            .unwrap();
        approver.on_reveal(&reveal, RESPOND + 1).unwrap();
        let transfer = approver
            .confirm(&digits, &Secret::<32>::random(), RESPOND + 2)
            .unwrap();
        assert_eq!(
            err(new.on_transfer(&transfer, START + TTL_MS)),
            ended(EndReason::Expired)
        );

        let r = to_reveal(ids(), NAME);
        let transfer = r
            .approver
            .confirm(&r.digits, &Secret::<32>::random(), RESPOND + 2)
            .unwrap();
        assert!(r.new.on_transfer(&transfer, START + TTL_MS - 1).is_ok());

        // The approving device times itself from its response.
        let ids_ = ids();
        let (account, approval) = (ids_.account, ids_.approval);
        let (mut new, request) = NewSide::start(ids_, START);
        let (mut approver, response) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        let (reveal, _) = new.on_response(&response, NAME, START + 1).unwrap();
        assert_eq!(
            approver.on_reveal(&reveal, RESPOND + TTL_MS).unwrap_err(),
            ended(EndReason::Expired)
        );

        let r = to_reveal(ids(), NAME);
        assert_eq!(
            r.approver
                .confirm(&r.digits, &Secret::<32>::random(), RESPOND + TTL_MS)
                .unwrap_err(),
            ended(EndReason::Expired)
        );
    }

    #[test]
    fn the_new_device_takes_one_response() {
        let mut r = to_reveal(ids(), NAME);
        assert_eq!(
            r.new.on_response(&r.response, NAME, START + 2).unwrap_err(),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn swapping_only_the_public_key_fails_the_commitment() {
        // The server swaps in its own key, keeping the new device's commitment.
        let ids_ = ids();
        let (mut new, mut request) = NewSide::start(ids_, START);
        let swapped = KemKey::generate();
        request[34..34 + XWING_PUBLIC_BYTES].copy_from_slice(&swapped.public());
        let approver_id = DeviceId::random();
        let (mut approver, response) =
            ApproverSide::respond(ids_.account, approver_id, ids_.approval, &request, RESPOND)
                .unwrap();

        // It learns the real rN from the new device's reveal, then reveals to
        // the approving device with a name that opens under its own key, so
        // only the commitment can refuse it.
        let (reveal, _) = new.on_response(&response, NAME, START + 1).unwrap();
        let Ok(Message::Response { ct, r_approver, .. }) = Message::parse(&response, ids_.approval)
        else {
            unreachable!()
        };
        let r_new: [u8; 32] = reveal[18..50].try_into().unwrap();
        let transcript = Transcript {
            ids: &ids_,
            approver: approver_id,
            pk: &swapped.public(),
            commitment: &request[1250..].try_into().unwrap(),
            ct: &ct,
            r_approver: &r_approver,
            r_new: &r_new,
        }
        .encode();
        let (_, transfer_key) = derive(&decapsulate(&swapped, &ct).unwrap(), &transcript);
        let forged = Message::Reveal {
            approval: ids_.approval,
            r_new,
            name: envelope::seal(
                &transfer_key,
                &aad(Purpose::ApprovalDeviceName, &ids_),
                NAME.as_bytes(),
            ),
        }
        .encode();
        assert_eq!(
            approver.on_reveal(&forged, RESPOND + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn a_swapped_public_key_gives_different_digits() {
        for _ in 0..5 {
            let ids_ = ids();
            let (account, approval, new_id) = (ids_.account, ids_.approval, ids_.new);
            let approver_id = DeviceId::random();
            let (mut new, request) = NewSide::start(ids_, START);

            // The server answers the new device itself, and asks the
            // approving device with its own key and commitment.
            let (mut fake_approver, fake_response) =
                ApproverSide::respond(account, approver_id, approval, &request, RESPOND).unwrap();
            let (mut fake_new, fake_request) = NewSide::start(
                Ids {
                    account,
                    approval,
                    new: new_id,
                },
                START,
            );
            let (mut approver, response) =
                ApproverSide::respond(account, approver_id, approval, &fake_request, RESPOND)
                    .unwrap();

            let (reveal, digits) = new.on_response(&fake_response, NAME, START + 1).unwrap();
            fake_approver.on_reveal(&reveal, RESPOND + 1).unwrap();
            let (fake_reveal, approver_digits) =
                fake_new.on_response(&response, NAME, START + 1).unwrap();
            approver.on_reveal(&fake_reveal, RESPOND + 1).unwrap();

            assert_ne!(digits, approver_digits);
            assert_eq!(
                approver
                    .confirm(&digits, &Secret::<32>::random(), RESPOND + 2)
                    .unwrap_err(),
                ended(EndReason::WrongDigits)
            );
        }
    }

    #[test]
    fn messages_from_another_session_are_refused() {
        let x = to_reveal(ids(), NAME);
        let x_transfer = x
            .approver
            .confirm(&x.digits, &Secret::<32>::random(), RESPOND + 2)
            .unwrap();

        // A response from X to Y's new device.
        let ids_ = ids();
        let (mut y_new, _) = NewSide::start(ids_, START);
        assert_eq!(
            y_new.on_response(&x.response, NAME, START + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );

        // A reveal from X to Y's approving device.
        let ids_ = ids();
        let (account, approval) = (ids_.account, ids_.approval);
        let (_, request) = NewSide::start(ids_, START);
        let (mut y_approver, _) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        assert_eq!(
            y_approver.on_reveal(&x.reveal, RESPOND + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );

        // A transfer from X to Y's new device, as is and with Y's header.
        let y = to_reveal(ids(), NAME);
        assert_eq!(
            err(y.new.on_transfer(&x_transfer, START + 2)),
            ended(EndReason::BadMessage)
        );
        let y = to_reveal(ids(), NAME);
        let mut rewritten = x_transfer.clone();
        rewritten[2..18].copy_from_slice(&y.ids.approval.0);
        assert_eq!(
            err(y.new.on_transfer(&rewritten, START + 2)),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn a_request_from_another_account_gets_different_digits() {
        let ids_ = ids();
        let approval = ids_.approval;
        let (mut new, request) = NewSide::start(ids_, START);
        let (mut approver, response) = ApproverSide::respond(
            AccountId::random(),
            DeviceId::random(),
            approval,
            &request,
            RESPOND,
        )
        .unwrap();
        let (reveal, _) = new.on_response(&response, NAME, START + 1).unwrap();
        // The commitment and the name's key both bind the account, so the
        // approving device refuses the reveal...
        assert_eq!(
            approver.on_reveal(&reveal, RESPOND + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );

        // ...and the transcript binds it too.
        let shared = Secret::<32>::random();
        let digits_for = |account: AccountId| {
            let ids = Ids {
                account,
                approval,
                new: DeviceId([3; 16]),
            };
            let transcript = Transcript {
                ids: &ids,
                approver: DeviceId([4; 16]),
                pk: &[5; XWING_PUBLIC_BYTES],
                commitment: &[6; 32],
                ct: &[7; XWING_CIPHERTEXT_BYTES],
                r_approver: &[8; 32],
                r_new: &[9; 32],
            };
            derive(&shared, &transcript.encode()).0
        };
        assert_ne!(
            digits_for(AccountId([1; 16])),
            digits_for(AccountId([11; 16]))
        );
    }

    #[test]
    fn swapping_roles_changes_digits_and_key() {
        let shared = Secret::<32>::random();
        let (x, y) = (DeviceId([3; 16]), DeviceId([4; 16]));
        let derive_for = |new: DeviceId, approver: DeviceId| {
            let ids = Ids {
                account: AccountId([1; 16]),
                approval: ApprovalId([2; 16]),
                new,
            };
            let transcript = Transcript {
                ids: &ids,
                approver,
                pk: &[5; XWING_PUBLIC_BYTES],
                commitment: &[6; 32],
                ct: &[7; XWING_CIPHERTEXT_BYTES],
                r_approver: &[8; 32],
                r_new: &[9; 32],
            };
            derive(&shared, &transcript.encode())
        };
        let (digits_xy, tk_xy) = derive_for(x, y);
        let (digits_yx, tk_yx) = derive_for(y, x);
        assert_ne!(digits_xy, digits_yx);
        assert_ne!(tk_xy.expose(), tk_yx.expose());
    }

    #[test]
    fn a_device_cannot_answer_its_own_request() {
        let ids_ = ids();
        let (account, approval, new_id) = (ids_.account, ids_.approval, ids_.new);
        let (mut new, request) = NewSide::start(ids_, START);
        assert!(matches!(
            ApproverSide::respond(account, new_id, approval, &request, RESPOND),
            Err(Error::ApprovalEnded(EndReason::BadMessage))
        ));

        let (_, mut response) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        response[18..34].copy_from_slice(&new_id.0);
        assert_eq!(
            new.on_response(&response, NAME, START + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn a_message_of_one_kind_is_refused_as_another() {
        let ids_ = ids();
        let (account, approval) = (ids_.account, ids_.approval);
        let (mut new, request) = NewSide::start(ids_, START);
        assert_eq!(
            new.on_response(&request, NAME, START + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );
        assert!(matches!(
            Message::parse(&request, approval),
            Ok(Message::Request { .. })
        ));

        let mut newer = request.clone();
        newer[0] = 2;
        assert!(matches!(
            Message::parse(&newer, approval),
            Err(Error::NeedsUpdate)
        ));
        assert!(matches!(
            ApproverSide::respond(account, DeviceId::random(), approval, &newer, RESPOND),
            Err(Error::NeedsUpdate)
        ));

        for cut in [0, 1, 2, 18, request.len() - 1] {
            assert!(
                matches!(
                    Message::parse(&request[..cut], approval),
                    Err(Error::ApprovalEnded(EndReason::BadMessage))
                ),
                "cut at {cut}"
            );
        }
        let mut longer = request.clone();
        longer.push(0);
        assert!(matches!(
            ApproverSide::respond(account, DeviceId::random(), approval, &longer, RESPOND),
            Err(Error::ApprovalEnded(EndReason::BadMessage))
        ));
        let mut unknown = request.clone();
        unknown[1] = 5;
        assert!(matches!(
            Message::parse(&unknown, approval),
            Err(Error::ApprovalEnded(EndReason::BadMessage))
        ));
    }

    #[test]
    fn the_device_name_is_sealed_under_the_transfer_key() {
        let r = to_reveal(ids(), NAME);
        assert!(!r.reveal.windows(NAME.len()).any(|w| w == NAME.as_bytes()));

        let long = format!("x{}y", "é".repeat(49));
        assert_eq!(long.len(), 100);
        let r = to_reveal(ids(), &long);
        assert!(r.name.len() <= 64);
        assert_eq!(r.name, format!("x{}", "é".repeat(31)));
        assert!(long.starts_with(&r.name));
    }
}
