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
/// Maximum length of a claimed app name, in characters.
pub const HELLO_NAME_MAX: usize = 40;
/// Maximum length of an app exchange message, in bytes.
pub const MESSAGE_MAX: usize = 4096;

/// The separate domains of the device approval and app connection exchanges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exchange {
    /// Ordinary full-device approval.
    Device,
    /// Connection for an app device.
    App,
}

/// The email's case- and surrounding-space-independent exchange scope.
pub fn email_scope(email: &str) -> AccountId {
    let normalized = email.trim().to_lowercase();
    let hash = generichash(None, &[b"bh.v1.app-connect-email", normalized.as_bytes()]);
    AccountId(array(&hash[..16]))
}

/// The app's sealed claim, opened only after the digits match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppHello {
    /// Claimed display name.
    pub name: String,
    /// Claimed app identifier.
    pub app_id: String,
    /// Base64url X-Wing public key of the requesting app, when supported.
    #[serde(default)]
    pub public: Option<String>,
}

/// Whether a character can change or hide the rendering of a device name.
pub fn is_unsafe_device_name_char(ch: char) -> bool {
    ch.is_control()
        || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

impl AppHello {
    /// Refuses malformed names and app identifiers.
    ///
    /// # Errors
    /// Returns `ApprovalEnded(BadMessage)` for invalid claims.
    pub fn validate(&self) -> Result<(), Error> {
        let name = self.name.trim();
        if name.is_empty()
            || name.chars().count() > HELLO_NAME_MAX
            || name.chars().any(is_unsafe_device_name_char)
            || self.app_id.is_empty()
            || self.app_id.len() > 100
            || !self
                .app_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        {
            return Err(bad());
        }
        Ok(())
    }
}

const FORMAT: u8 = 1;
const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;
const REVEAL: u8 = 3;
const TRANSFER: u8 = 4;
const APP_REQUEST: u8 = 5;
const APP_RESPONSE: u8 = 6;
const APP_REVEAL: u8 = 7;
const APP_TRANSFER: u8 = 8;
const HEADER: usize = 2 + 16;
const REQUEST_LEN: usize = HEADER + 16 + XWING_PUBLIC_BYTES + 32;
const RESPONSE_LEN: usize = HEADER + 16 + XWING_CIPHERTEXT_BYTES + 32;
const REVEAL_LEN: usize = HEADER + 32;
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
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] unless the input contains exactly six digits.
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

    /// Returns six ASCII digits without the display separator.
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
    /// Account being signed in.
    pub account: AccountId,
    /// Exchange identifier.
    pub approval: ApprovalId,
    /// Device requesting approval.
    pub new: DeviceId,
}

/// The new device's commitment to its public key and hidden random value.
/// Every input has a fixed length, so concatenation is unambiguous.
pub fn commitment(ids: &Ids, pk: &[u8; XWING_PUBLIC_BYTES], r_new: &[u8; 32]) -> [u8; 32] {
    commitment_as(Exchange::Device, ids, pk, r_new)
}

fn commitment_as(
    exchange: Exchange,
    ids: &Ids,
    pk: &[u8; XWING_PUBLIC_BYTES],
    r_new: &[u8; 32],
) -> [u8; 32] {
    let label: &[u8] = match exchange {
        Exchange::Device => b"bh.v1.approval-commit",
        Exchange::App => b"bh.v1.app-connect-commit",
    };
    generichash(
        None,
        &[
            label,
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
    /// Fixed exchange identities.
    pub ids: &'a Ids,
    /// Device answering the request.
    pub approver: DeviceId,
    /// New device's public encapsulation key.
    pub pk: &'a [u8; XWING_PUBLIC_BYTES],
    /// New device's original commitment.
    pub commitment: &'a [u8; 32],
    /// Approver's encapsulated ciphertext.
    pub ct: &'a [u8; XWING_CIPHERTEXT_BYTES],
    /// Random value chosen by the approver.
    pub r_approver: &'a [u8; 32],
    /// Random value revealed by the new device.
    pub r_new: &'a [u8; 32],
}

impl Transcript<'_> {
    /// Encodes every length-delimited exchange input for key derivation.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_as(Exchange::Device)
    }

    /// Encodes with the selected exchange's independent label.
    pub fn encode_as(&self, exchange: Exchange) -> Vec<u8> {
        let mut out = match exchange {
            Exchange::Device => b"bh.v1.approval-transcript".to_vec(),
            Exchange::App => b"bh.v1.app-connect-transcript".to_vec(),
        };
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
    derive_as(Exchange::Device, shared, transcript)
}

fn derive_as(exchange: Exchange, shared: &Secret<32>, transcript: &[u8]) -> (Digits, Secret<32>) {
    let bound = Zeroizing::new(generichash(Some(shared.expose()), &[transcript]));
    let bound = Secret::from_slice(&*bound).expect("32 bytes");
    let (digits_label, transfer_label): (&[u8; 8], &[u8; 8]) = match exchange {
        Exchange::Device => (b"bhaprdg1", b"bhaprtk1"),
        Exchange::App => (b"bhapcdg1", b"bhapctk1"),
    };
    let material = kdf(&bound, digits_label, 1);
    (digits_from(&material), kdf(&bound, transfer_label, 1))
}

fn hello_key(shared: &Secret<32>, transcript: &[u8]) -> Secret<32> {
    let bound = Zeroizing::new(generichash(Some(shared.expose()), &[transcript]));
    let bound = Secret::from_slice(&*bound).expect("32 bytes");
    kdf(&bound, b"bhapchl1", 1)
}

/// The four messages, binary and opaque to the server.
pub enum Message {
    /// New device's first, committed request.
    Request {
        /// Exchange identifier.
        approval: ApprovalId,
        /// New device ID.
        new: DeviceId,
        /// Public encapsulation key.
        pk: Box<[u8; XWING_PUBLIC_BYTES]>,
        /// Commitment to the public key and hidden random value.
        commitment: [u8; 32],
    },
    /// Approver's one-time response.
    Response {
        /// Exchange identifier.
        approval: ApprovalId,
        /// Approving device ID.
        approver: DeviceId,
        /// Encapsulated shared secret.
        ct: Box<[u8; XWING_CIPHERTEXT_BYTES]>,
        /// Approver's random value.
        r_approver: [u8; 32],
    },
    /// New device reveals its committed random value.
    Reveal {
        /// Exchange identifier.
        approval: ApprovalId,
        /// Random value committed in the request.
        r_new: [u8; 32],
    },
    /// App's random reveal and sealed hello.
    AppReveal {
        /// Exchange identifier.
        approval: ApprovalId,
        /// Committed random value.
        r_new: [u8; 32],
        /// Sealed app claim.
        hello: Vec<u8>,
    },
    /// App credentials sealed under the transfer key.
    AppTransfer {
        /// Exchange identifier.
        approval: ApprovalId,
        /// Sealed credentials.
        payload: Vec<u8>,
    },
    /// Account key sealed under the transfer key.
    Transfer {
        /// Exchange identifier.
        approval: ApprovalId,
        /// Sealed account key.
        account_key: Vec<u8>,
    },
}

impl Message {
    /// Encodes this message in the version-one binary format.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_as(Exchange::Device)
    }

    fn encode_as(&self, exchange: Exchange) -> Vec<u8> {
        let (kind, approval, parts): (u8, &ApprovalId, [&[u8]; 3]) = match self {
            Self::Request {
                approval,
                new,
                pk,
                commitment,
            } => (
                match exchange {
                    Exchange::Device => REQUEST,
                    Exchange::App => APP_REQUEST,
                },
                approval,
                [&new.0, &pk[..], commitment],
            ),
            Self::Response {
                approval,
                approver,
                ct,
                r_approver,
            } => (
                match exchange {
                    Exchange::Device => RESPONSE,
                    Exchange::App => APP_RESPONSE,
                },
                approval,
                [&approver.0, &ct[..], r_approver],
            ),
            Self::Reveal { approval, r_new } => (REVEAL, approval, [r_new, &[], &[]]),
            Self::AppReveal {
                approval,
                r_new,
                hello,
            } => (APP_REVEAL, approval, [r_new, hello, &[]]),
            Self::AppTransfer { approval, payload } => {
                (APP_TRANSFER, approval, [payload, &[], &[]])
            }
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
    ///
    /// # Errors
    /// Returns [`Error::NeedsUpdate`] for an unsupported format or
    /// [`Error::ApprovalEnded`] for a malformed message or wrong exchange.
    pub fn parse(bytes: &[u8], approval: ApprovalId) -> Result<Message, Error> {
        Self::parse_as(Exchange::Device, bytes, approval)
    }

    fn parse_as(exchange: Exchange, bytes: &[u8], approval: ApprovalId) -> Result<Message, Error> {
        match bytes.first() {
            Some(&FORMAT) => {}
            Some(_) => return Err(Error::NeedsUpdate),
            None => return Err(bad()),
        }
        if bytes.len() < HEADER || bytes[2..HEADER] != approval.0 {
            return Err(bad());
        }
        if exchange == Exchange::App && bytes.len() > MESSAGE_MAX {
            return Err(bad());
        }
        let body = &bytes[HEADER..];
        let fixed = |len: usize| bytes.len() == len;
        let (request, response, reveal, transfer) = match exchange {
            Exchange::Device => (REQUEST, RESPONSE, REVEAL, TRANSFER),
            Exchange::App => (APP_REQUEST, APP_RESPONSE, APP_REVEAL, APP_TRANSFER),
        };
        match bytes[1] {
            kind if kind == request && fixed(REQUEST_LEN) => Ok(Self::Request {
                approval,
                new: DeviceId(array(&body[..16])),
                pk: Box::new(array(&body[16..16 + XWING_PUBLIC_BYTES])),
                commitment: array(&body[16 + XWING_PUBLIC_BYTES..]),
            }),
            kind if kind == response && fixed(RESPONSE_LEN) => Ok(Self::Response {
                approval,
                approver: DeviceId(array(&body[..16])),
                ct: Box::new(array(&body[16..16 + XWING_CIPHERTEXT_BYTES])),
                r_approver: array(&body[16 + XWING_CIPHERTEXT_BYTES..]),
            }),
            kind if kind == reveal && exchange == Exchange::Device && fixed(REVEAL_LEN) => {
                Ok(Self::Reveal {
                    approval,
                    r_new: array(body),
                })
            }
            kind if kind == reveal
                && exchange == Exchange::App
                && bytes.len() >= REVEAL_LEN + envelope::OVERHEAD =>
            {
                Ok(Self::AppReveal {
                    approval,
                    r_new: array(&body[..32]),
                    hello: body[32..].to_vec(),
                })
            }
            kind if kind == transfer
                && exchange == Exchange::App
                && bytes.len() >= HEADER + envelope::OVERHEAD =>
            {
                Ok(Self::AppTransfer {
                    approval,
                    payload: body.to_vec(),
                })
            }
            kind if kind == transfer
                && exchange == Exchange::Device
                && (fixed(TRANSFER_LEN) || fixed(TRANSFER_LEN + 4)) =>
            {
                Ok(Self::Transfer {
                    approval,
                    account_key: body.to_vec(),
                })
            }
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

fn end<T>(reason: EndReason) -> Result<T, Error> {
    Err(Error::ApprovalEnded(reason))
}

/// The new device's side, from its request until it receives the account key.
pub struct NewSide {
    exchange: Exchange,
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
        Self::start_as(Exchange::Device, ids, now_ms)
    }

    /// Starts a device approval or a separately labelled app connection.
    pub fn start_as(exchange: Exchange, ids: Ids, now_ms: u64) -> (NewSide, Vec<u8>) {
        let kem = Box::new(KemKey::generate());
        let pk = kem.public();
        let r_new = Zeroizing::new(random::<32>());
        let commitment = commitment_as(exchange, &ids, &pk, &r_new);
        let request = Message::Request {
            approval: ids.approval,
            new: ids.new,
            pk: Box::new(pk),
            commitment,
        }
        .encode_as(exchange);
        let side = NewSide {
            exchange,
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
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] for an expired, repeated or malformed
    /// exchange, or [`Error::NeedsUpdate`] for an unsupported message format.
    pub fn on_response(
        &mut self,
        response: &[u8],
        now_ms: u64,
    ) -> Result<(Vec<u8>, Digits), Error> {
        self.response_as(Exchange::Device, response, None, now_ms)
    }

    /// Opens the response and seals the app's claim into its reveal.
    ///
    /// # Errors
    /// Returns `ApprovalEnded` for an invalid claim, message or expired exchange.
    pub fn on_app_response(
        &mut self,
        response: &[u8],
        hello: &AppHello,
        now_ms: u64,
    ) -> Result<(Vec<u8>, Digits), Error> {
        self.response_as(Exchange::App, response, Some(hello), now_ms)
    }

    fn response_as(
        &mut self,
        exchange: Exchange,
        response: &[u8],
        hello: Option<&AppHello>,
        now_ms: u64,
    ) -> Result<(Vec<u8>, Digits), Error> {
        if self.exchange != exchange {
            return Err(bad());
        }
        if let Some(hello) = hello {
            hello.validate()?;
        }
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
        } = Message::parse_as(exchange, response, self.ids.approval)?
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
        .encode_as(exchange);
        let (digits, transfer_key) = derive_as(exchange, &shared, &transcript);
        let reveal = match hello {
            Some(hello) => Message::AppReveal {
                approval: self.ids.approval,
                r_new: *r_new,
                hello: envelope::seal(
                    &hello_key(&shared, &transcript),
                    &aad(Purpose::AppConnectHello, &self.ids),
                    &serde_json::to_vec(hello).map_err(|_| bad())?,
                ),
            },
            None => Message::Reveal {
                approval: self.ids.approval,
                r_new: *r_new,
            },
        }
        .encode();
        if exchange == Exchange::App && reveal.len() > MESSAGE_MAX {
            return Err(bad());
        }
        self.state = NewState::Revealed { transfer_key };
        Ok((reveal, digits))
    }

    /// Step 7: opens the account key from the transfer.
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] for an expired, malformed or ended
    /// exchange, or [`Error::NeedsUpdate`] for an unsupported message format.
    pub fn on_transfer(self, transfer: &[u8], now_ms: u64) -> Result<Secret<32>, Error> {
        self.on_transfer_at(transfer, now_ms).map(|(_, key)| key)
    }

    /// Opens the key and its account epoch together from the authenticated transfer.
    pub fn on_transfer_at(self, transfer: &[u8], now_ms: u64) -> Result<(u32, Secret<32>), Error> {
        if self.exchange != Exchange::Device {
            return Err(bad());
        }
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
        let (epoch, key) = if opened.len() == 32 {
            (1, opened.as_slice())
        } else if opened.len() == 36 {
            (
                u32::from_be_bytes(opened[..4].try_into().expect("epoch length")),
                &opened[4..],
            )
        } else {
            return Err(bad());
        };
        if epoch == 0 {
            return Err(bad());
        }
        Ok((epoch, Secret::from_slice(key).map_err(|_| bad())?))
    }

    /// Opens the app credentials only under this exchange's transfer key.
    ///
    /// # Errors
    /// Returns `ApprovalEnded` if the transfer is malformed, wrong-kind or expired.
    pub fn on_app_transfer(
        self,
        transfer: &[u8],
        now_ms: u64,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.exchange != Exchange::App {
            return Err(bad());
        }
        let transfer_key = match self.state {
            NewState::Ended(reason) => return end(reason),
            _ if now_ms >= self.deadline => return end(EndReason::Expired),
            NewState::Requested { .. } => return Err(bad()),
            NewState::Revealed { transfer_key } => transfer_key,
        };
        let Message::AppTransfer { payload, .. } =
            Message::parse_as(Exchange::App, transfer, self.ids.approval)?
        else {
            return Err(bad());
        };
        envelope::open(
            &transfer_key,
            &aad(Purpose::AppConnectTransfer, &self.ids),
            &payload,
        )
        .map_err(|_| bad())
    }
}

/// The approving device's side, from its one response until it sends the
/// account key or the digits don't match.
pub struct ApproverSide {
    exchange: Exchange,
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
        hello: Option<(Secret<32>, Vec<u8>)>,
    },
    Checked {
        transfer_key: Secret<32>,
    },
    Ended(EndReason),
}

impl ApproverSide {
    /// Step 2: the one encapsulation for this request's commitment. The caller
    /// records `commitment()` before sending the response.
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] for a malformed request or
    /// [`Error::NeedsUpdate`] for an unsupported format.
    pub fn respond(
        account: AccountId,
        me: DeviceId,
        approval: ApprovalId,
        request: &[u8],
        now_ms: u64,
    ) -> Result<(ApproverSide, Vec<u8>), Error> {
        Self::respond_as(Exchange::Device, account, me, approval, request, now_ms)
    }

    /// Answers a request using its exchange's independent message kinds.
    ///
    /// # Errors
    /// Returns `ApprovalEnded` for a malformed or wrong-kind request.
    pub fn respond_as(
        exchange: Exchange,
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
        } = Message::parse_as(exchange, request, approval)?
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
        .encode_as(exchange);
        let side = ApproverSide {
            exchange,
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

    /// Returns the commitment to claim before responding.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Returns the device requesting approval.
    pub fn new_device(&self) -> DeviceId {
        self.ids.new
    }

    /// Checks the commitment and derives the digits.
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] for an expired, repeated or malformed
    /// exchange, or [`Error::NeedsUpdate`] for an unsupported message format.
    pub fn on_reveal(&mut self, reveal: &[u8], now_ms: u64) -> Result<(), Error> {
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
            ApproverState::Revealed { .. } | ApproverState::Checked { .. } => {
                return end(EndReason::BadMessage);
            }
            ApproverState::Responded { shared } => shared,
        };
        let message = Message::parse_as(self.exchange, reveal, self.ids.approval)?;
        let (r_new, hello) = match (self.exchange, message) {
            (Exchange::Device, Message::Reveal { r_new, .. }) => (r_new, None),
            (Exchange::App, Message::AppReveal { r_new, hello, .. }) => (r_new, Some(hello)),
            _ => return Err(bad()),
        };
        let opened = commitment_as(self.exchange, &self.ids, &self.pk, &r_new);
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
        .encode_as(self.exchange);
        let (digits, transfer_key) = derive_as(self.exchange, &shared, &transcript);
        self.state = ApproverState::Revealed {
            digits,
            transfer_key,
            hello: hello.map(|sealed| (hello_key(&shared, &transcript), sealed)),
        };
        Ok(())
    }

    /// Steps 5–7: compares the typed digits and, only if they match, seals the
    /// account key for the new device. A mismatch ends the exchange.
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] for wrong digits or an expired,
    /// incomplete or ended exchange.
    pub fn confirm(
        self,
        typed: &Digits,
        account_key: &Secret<32>,
        now_ms: u64,
    ) -> Result<Vec<u8>, Error> {
        self.confirm_at(typed, account_key, 1, now_ms)
    }

    /// Seals the current epoch and key in the approval exchange.
    pub fn confirm_at(
        self,
        typed: &Digits,
        account_key: &Secret<32>,
        epoch: u32,
        now_ms: u64,
    ) -> Result<Vec<u8>, Error> {
        if epoch == 0 {
            return Err(bad());
        }
        if self.exchange != Exchange::Device {
            return Err(bad());
        }
        let (digits, transfer_key) = match self.state {
            ApproverState::Ended(reason) => return end(reason),
            _ if now_ms >= self.deadline => return end(EndReason::Expired),
            ApproverState::Responded { .. } => return Err(bad()),
            ApproverState::Revealed {
                digits,
                transfer_key,
                ..
            } => (digits, transfer_key),
            ApproverState::Checked { .. } => return Err(bad()),
        };
        if *typed != digits {
            return end(EndReason::WrongDigits);
        }
        // Preserve the original 32-byte epoch-one transfer for updated and
        // older devices that are still sharing an unrotated account.
        let payload = Zeroizing::new(if epoch == 1 {
            account_key.expose().to_vec()
        } else {
            [epoch.to_be_bytes().as_slice(), account_key.expose()].concat()
        });
        Ok(Message::Transfer {
            approval: self.ids.approval,
            account_key: envelope::seal(
                &transfer_key,
                &aad(Purpose::ApprovalTransfer, &self.ids),
                &payload,
            ),
        }
        .encode())
    }

    /// Compares the typed digits before opening the app's sealed claim.
    ///
    /// # Errors
    /// Wrong digits end this side permanently; malformed or expired exchanges are refused.
    pub fn check(&mut self, typed: &Digits, now_ms: u64) -> Result<AppHello, Error> {
        if self.exchange != Exchange::App {
            return Err(bad());
        }
        let state = mem::replace(&mut self.state, ApproverState::Ended(EndReason::BadMessage));
        let (digits, transfer_key, hello) = match state {
            ApproverState::Ended(reason) => {
                self.state = ApproverState::Ended(reason);
                return end(reason);
            }
            _ if now_ms >= self.deadline => {
                self.state = ApproverState::Ended(EndReason::Expired);
                return end(EndReason::Expired);
            }
            ApproverState::Revealed {
                digits,
                transfer_key,
                hello: Some(hello),
            } => (digits, transfer_key, hello),
            _ => return Err(bad()),
        };
        if *typed != digits {
            self.state = ApproverState::Ended(EndReason::WrongDigits);
            return end(EndReason::WrongDigits);
        }
        let opened = envelope::open(
            &hello.0,
            &aad(Purpose::AppConnectHello, &self.ids),
            &hello.1,
        )
        .map_err(|_| bad())?;
        let claim: AppHello = serde_json::from_slice(&opened).map_err(|_| bad())?;
        claim.validate()?;
        self.state = ApproverState::Checked { transfer_key };
        Ok(claim)
    }

    /// Seals credentials after a successful app-digit check.
    ///
    /// # Errors
    /// Returns `ApprovalEnded` for an unchecked, expired or ended exchange.
    pub fn seal_payload(self, payload: &[u8], now_ms: u64) -> Result<Vec<u8>, Error> {
        if self.exchange != Exchange::App {
            return Err(bad());
        }
        let transfer_key = match self.state {
            ApproverState::Ended(reason) => return end(reason),
            _ if now_ms >= self.deadline => return end(EndReason::Expired),
            ApproverState::Checked { transfer_key } => transfer_key,
            _ => return Err(bad()),
        };
        if HEADER + envelope::OVERHEAD + payload.len() > MESSAGE_MAX {
            return Err(bad());
        }
        Ok(Message::AppTransfer {
            approval: self.ids.approval,
            payload: envelope::seal(
                &transfer_key,
                &aad(Purpose::AppConnectTransfer, &self.ids),
                payload,
            ),
        }
        .encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        reveal: Vec<u8>,
        response: Vec<u8>,
    }

    fn to_reveal(ids: Ids) -> Revealed {
        let account = ids.account;
        let approval = ids.approval;
        let (mut new, request) = NewSide::start(ids, START);
        let (mut approver, response) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        let (reveal, digits) = new.on_response(&response, START + 1).unwrap();
        let _: () = approver.on_reveal(&reveal, RESPOND + 1).unwrap();
        Revealed {
            ids,
            new,
            approver,
            digits,
            reveal,
            response,
        }
    }

    #[test]
    fn epoch_one_approval_keeps_the_original_transfer_format() {
        let r = to_reveal(ids());
        let key = Secret::<32>::random();
        let transfer = r
            .approver
            .confirm_at(&r.digits, &key, 1, RESPOND + 2)
            .unwrap();
        assert_eq!(transfer.len(), TRANSFER_LEN);
        let (epoch, received) = r.new.on_transfer_at(&transfer, START + 2).unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(received.expose(), key.expose());
    }

    #[test]
    fn an_approved_device_receives_the_authenticated_account_epoch() {
        let r = to_reveal(ids());
        let key = Secret::<32>::random();
        let transfer = r
            .approver
            .confirm_at(&r.digits, &key, 3, RESPOND + 2)
            .unwrap();
        let (epoch, received) = r.new.on_transfer_at(&transfer, START + 2).unwrap();
        assert_eq!(epoch, 3);
        assert_eq!(received.expose(), key.expose());
    }

    /// An honest exchange: both devices agree on the digits and account key.
    fn honest() -> (Digits, Secret<32>, Secret<32>) {
        let r = to_reveal(ids());
        let ak = Secret::<32>::random();
        let transfer = r.approver.confirm(&r.digits, &ak, RESPOND + 2).unwrap();
        let received = r.new.on_transfer(&transfer, START + 2).unwrap();
        (r.digits, ak, received)
    }

    fn other_digits(digits: &Digits) -> Digits {
        let n: u32 = digits.as_str().parse().unwrap();
        Digits::parse(&format!("{:06}", (n + 1) % 1_000_000)).unwrap()
    }

    fn app_hello() -> AppHello {
        AppHello {
            name: "Sample".into(),
            app_id: "app.basehero.sample".into(),
            public: None,
        }
    }

    fn app_revealed() -> (NewSide, ApproverSide, Digits) {
        let ids = ids();
        let (mut new, request) = NewSide::start_as(Exchange::App, ids, START);
        let (mut approver, response) = ApproverSide::respond_as(
            Exchange::App,
            ids.account,
            DeviceId::random(),
            ids.approval,
            &request,
            RESPOND,
        )
        .unwrap();
        let (reveal, digits) = new
            .on_app_response(&response, &app_hello(), START + 1)
            .unwrap();
        approver.on_reveal(&reveal, RESPOND + 1).unwrap();
        (new, approver, digits)
    }

    #[test]
    fn an_honest_app_exchange_carries_the_hello_and_the_payload() {
        let (new, mut approver, digits) = app_revealed();
        assert_eq!(approver.check(&digits, RESPOND + 2).unwrap(), app_hello());
        let transfer = approver.seal_payload(b"{creds}", RESPOND + 3).unwrap();
        assert_eq!(
            &*new.on_app_transfer(&transfer, START + 2).unwrap(),
            b"{creds}"
        );
    }

    #[test]
    fn an_app_message_is_never_taken_for_a_device_one() {
        let ids = ids();
        let (mut app, request) = NewSide::start_as(Exchange::App, ids, START);
        assert_eq!(
            err(ApproverSide::respond(
                ids.account,
                DeviceId::random(),
                ids.approval,
                &request,
                RESPOND
            )),
            ended(EndReason::BadMessage)
        );
        let (mut approver, response) = ApproverSide::respond_as(
            Exchange::App,
            ids.account,
            DeviceId::random(),
            ids.approval,
            &request,
            RESPOND,
        )
        .unwrap();
        assert_eq!(
            app.on_response(&response, START + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );
        let (reveal, digits) = app
            .on_app_response(&response, &app_hello(), START + 1)
            .unwrap();
        approver.on_reveal(&reveal, RESPOND + 1).unwrap();
        approver.check(&digits, RESPOND + 2).unwrap();
        let app_transfer = approver.seal_payload(b"creds", RESPOND + 3).unwrap();
        assert_eq!(
            err(app.on_transfer(&app_transfer, START + 2)),
            ended(EndReason::BadMessage)
        );
        let (mut device, _) = NewSide::start(ids, START);
        assert_eq!(
            device.on_response(&response, START + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );
        let (mut device, device_request) = NewSide::start(ids, START);
        assert_eq!(
            err(ApproverSide::respond_as(
                Exchange::App,
                ids.account,
                DeviceId::random(),
                ids.approval,
                &device_request,
                RESPOND
            )),
            ended(EndReason::BadMessage)
        );
        let (mut device_approver, device_response) = ApproverSide::respond(
            ids.account,
            DeviceId::random(),
            ids.approval,
            &device_request,
            RESPOND,
        )
        .unwrap();
        let (device_reveal, device_digits) =
            device.on_response(&device_response, START + 1).unwrap();
        device_approver
            .on_reveal(&device_reveal, RESPOND + 1)
            .unwrap();
        let transfer = device_approver
            .confirm(&device_digits, &Secret::<32>::random(), RESPOND + 2)
            .unwrap();
        let (mut app, app_request) = NewSide::start_as(Exchange::App, ids, START);
        let (_, app_response) = ApproverSide::respond_as(
            Exchange::App,
            ids.account,
            DeviceId::random(),
            ids.approval,
            &app_request,
            RESPOND,
        )
        .unwrap();
        app.on_app_response(&app_response, &app_hello(), START + 1)
            .unwrap();
        assert_eq!(
            err(app.on_app_transfer(&transfer, START + 2)),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn wrong_digits_end_an_app_exchange_before_the_hello_opens() {
        let (_, mut approver, digits) = app_revealed();
        assert_eq!(
            err(approver.check(&other_digits(&digits), RESPOND + 2)),
            ended(EndReason::WrongDigits)
        );
        assert_eq!(
            err(approver.check(&digits, RESPOND + 3)),
            ended(EndReason::WrongDigits)
        );
        assert_eq!(
            err(approver.seal_payload(b"creds", RESPOND + 4)),
            ended(EndReason::WrongDigits)
        );
    }

    #[test]
    fn the_payload_is_sealed_only_after_a_matching_check() {
        let (_, approver, _) = app_revealed();
        assert_eq!(
            err(approver.seal_payload(b"creds", RESPOND + 2)),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn an_expired_app_exchange_refuses_every_step() {
        let (new, mut approver, digits) = app_revealed();
        assert_eq!(
            err(approver.check(&digits, RESPOND + TTL_MS)),
            ended(EndReason::Expired)
        );
        assert_eq!(
            err(approver.seal_payload(b"creds", RESPOND + TTL_MS)),
            ended(EndReason::Expired)
        );
        let (_, mut approver, digits) = app_revealed();
        approver.check(&digits, RESPOND + 2).unwrap();
        let transfer = approver.seal_payload(b"creds", RESPOND + 3).unwrap();
        assert_eq!(
            err(new.on_app_transfer(&transfer, START + TTL_MS)),
            ended(EndReason::Expired)
        );
    }

    #[test]
    fn a_bad_hello_is_refused() {
        for hello in [
            AppHello {
                name: "".into(),
                ..app_hello()
            },
            AppHello {
                name: "a".repeat(41),
                ..app_hello()
            },
            AppHello {
                name: "a\nb".into(),
                ..app_hello()
            },
            AppHello {
                name: "Sample\u{202e}".into(),
                ..app_hello()
            },
            AppHello {
                name: "Sam\u{200e}ple".into(),
                ..app_hello()
            },
            AppHello {
                app_id: "bad id".into(),
                ..app_hello()
            },
            AppHello {
                app_id: "a".repeat(101),
                ..app_hello()
            },
        ] {
            let ids = ids();
            let (mut new, request) = NewSide::start_as(Exchange::App, ids, START);
            let (_, response) = ApproverSide::respond_as(
                Exchange::App,
                ids.account,
                DeviceId::random(),
                ids.approval,
                &request,
                RESPOND,
            )
            .unwrap();
            assert_eq!(
                err(new.on_app_response(&response, &hello, START + 1)),
                ended(EndReason::BadMessage)
            );
        }
        let ids = ids();
        let (mut new, request) = NewSide::start_as(Exchange::App, ids, START);
        let (mut approver, response) = ApproverSide::respond_as(
            Exchange::App,
            ids.account,
            DeviceId::random(),
            ids.approval,
            &request,
            RESPOND,
        )
        .unwrap();
        let (mut reveal, _) = new
            .on_app_response(&response, &app_hello(), START + 1)
            .unwrap();
        reveal.resize(MESSAGE_MAX + 1, 0);
        assert_eq!(
            approver.on_reveal(&reveal, RESPOND + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn email_scope_ignores_case_and_spaces() {
        assert_eq!(email_scope(" Dan@HLD.ca "), email_scope("dan@hld.ca"));
        assert_ne!(email_scope("dan@hld.com"), email_scope("dan@hld.ca"));
    }

    #[test]
    fn the_same_inputs_give_different_digits_for_an_app() {
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
        };
        let secret = Secret::from_slice(&[10; 32]).unwrap();
        let (device_digits, device_key) = derive(&secret, &transcript.encode());
        let (app_digits, app_key) =
            derive_as(Exchange::App, &secret, &transcript.encode_as(Exchange::App));
        assert_ne!(device_digits, app_digits);
        assert_ne!(device_key.expose(), app_key.expose());
    }

    #[test]
    fn app_derivation_matches_its_test_vector() {
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
        .encode_as(Exchange::App);
        let secret = Secret::from_slice(&[10; 32]).unwrap();
        let (digits, tk) = derive_as(Exchange::App, &secret, &transcript);
        let bound =
            Secret::from_slice(&generichash(Some(secret.expose()), &[&transcript])).unwrap();
        let hello_key = kdf(&bound, b"bhapchl1", 1);
        assert_eq!(
            (
                hex(&generichash(None, &[&transcript])),
                digits.as_str().to_string(),
                hex(tk.expose()),
                hex(hello_key.expose())
            ),
            (
                "66262722aa9bddd4262e6cbb773e3a62103b6a23170ddd4aad6f2e68920d2d42".into(),
                "227422".into(),
                "d689641a3ffd15031acef3f69876544e9a55b4b6edaf9f7ab7dac7b5f3a879aa".into(),
                "8805ccc4c2e485215763e37f2c989e3eaea273db5f71936cff5734b1b52243ff".into()
            )
        );
    }

    #[test]
    fn an_honest_exchange_gives_both_sides_the_same_digits_and_key() {
        let (digits, sent, received) = honest();
        assert_eq!(digits.as_str().len(), 6);
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
        let r = to_reveal(ids());
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
            late.on_response(&response, START + TTL_MS).unwrap_err(),
            ended(EndReason::Expired)
        );

        let ids_ = ids();
        let (account, approval) = (ids_.account, ids_.approval);
        let (mut new, request) = NewSide::start(ids_, START);
        let (mut approver, response) =
            ApproverSide::respond(account, DeviceId::random(), approval, &request, RESPOND)
                .unwrap();
        let (reveal, digits) = new.on_response(&response, START + TTL_MS - 1).unwrap();
        approver.on_reveal(&reveal, RESPOND + 1).unwrap();
        let transfer = approver
            .confirm(&digits, &Secret::<32>::random(), RESPOND + 2)
            .unwrap();
        assert_eq!(
            err(new.on_transfer(&transfer, START + TTL_MS)),
            ended(EndReason::Expired)
        );

        let r = to_reveal(ids());
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
        let (reveal, _) = new.on_response(&response, START + 1).unwrap();
        assert_eq!(
            approver.on_reveal(&reveal, RESPOND + TTL_MS).unwrap_err(),
            ended(EndReason::Expired)
        );

        let r = to_reveal(ids());
        assert_eq!(
            r.approver
                .confirm(&r.digits, &Secret::<32>::random(), RESPOND + TTL_MS)
                .unwrap_err(),
            ended(EndReason::Expired)
        );
    }

    #[test]
    fn the_new_device_takes_one_response() {
        let mut r = to_reveal(ids());
        assert_eq!(
            r.new.on_response(&r.response, START + 2).unwrap_err(),
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

        // It learns the real rN from the new device's reveal, then sends
        // that value to the approving device; the commitment must refuse it.
        let (reveal, _) = new.on_response(&response, START + 1).unwrap();
        assert_eq!(
            approver.on_reveal(&reveal, RESPOND + 1).unwrap_err(),
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

            let (reveal, digits) = new.on_response(&fake_response, START + 1).unwrap();
            fake_approver.on_reveal(&reveal, RESPOND + 1).unwrap();
            let (fake_reveal, approver_digits) =
                fake_new.on_response(&response, START + 1).unwrap();
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
        let x = to_reveal(ids());
        let x_transfer = x
            .approver
            .confirm(&x.digits, &Secret::<32>::random(), RESPOND + 2)
            .unwrap();

        // A response from X to Y's new device.
        let ids_ = ids();
        let (mut y_new, _) = NewSide::start(ids_, START);
        assert_eq!(
            y_new.on_response(&x.response, START + 1).unwrap_err(),
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
        let y = to_reveal(ids());
        assert_eq!(
            err(y.new.on_transfer(&x_transfer, START + 2)),
            ended(EndReason::BadMessage)
        );
        let y = to_reveal(ids());
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
        let (reveal, _) = new.on_response(&response, START + 1).unwrap();
        // The commitment binds the account, so the approving device refuses the reveal...
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
            new.on_response(&response, START + 1).unwrap_err(),
            ended(EndReason::BadMessage)
        );
    }

    #[test]
    fn a_message_of_one_kind_is_refused_as_another() {
        let ids_ = ids();
        let (account, approval) = (ids_.account, ids_.approval);
        let (mut new, request) = NewSide::start(ids_, START);
        assert_eq!(
            new.on_response(&request, START + 1).unwrap_err(),
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
    fn the_reveal_has_only_the_fixed_length_random_value() {
        let r = to_reveal(ids());
        assert_eq!(r.reveal.len(), REVEAL_LEN);
        let mut trailing = r.reveal;
        trailing.push(0);
        assert!(matches!(
            Message::parse(&trailing, r.ids.approval),
            Err(Error::ApprovalEnded(EndReason::BadMessage))
        ));
    }
}
