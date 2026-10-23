//! Test accounts, an in-memory edge that checks permits like the real one, and
//! helpers to drive the service's application protocol after the channel.
#![allow(dead_code)]

pub mod claims;
pub mod device;
pub mod native;

use bh_account::{
    AccountEvent, AccountId, DeviceId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    crypto::{KemKey, Secret, SigningKey},
    device_auth::{self, Context},
    personal::{self, PersonalKey},
    platform::{
        ControlKeyPolicy, DeviceKeyStore, DeviceKeyStoreKind, KeyHandle, KeyStoreError,
        StoredDevice,
    },
};
use bh_authz::{
    Connection, EdgeError, EdgeReader, FixedClock, HomeObjectsAck, LogRead, PermitKeys,
    RecoveryHomeKey, Service,
    proto::{
        ACCOUNT_EPOCH, FromService, LogId, LogKind, MetadataKey, ToService, Want, account_log_id,
        account_log_wrap,
    },
};
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, EventId, Head, OpaqueEvent, OrderState, Route,
    evidence::{RecoveryKeyCertificate, certify_recovery_key},
    home_objects,
    permit::{self, Permit, Scope},
    receipt,
    wire::CoverageEndpoint,
};
use futures_util::future::BoxFuture;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

pub const TIME_START: u64 = 1_900_000_000_000;

pub struct Device {
    pub ordinary: SigningKey,
    pub control: SigningKey,
    pub keys: DevicePublicKeys,
}
impl Device {
    pub fn new() -> Self {
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Self {
            ordinary,
            control,
            keys,
        }
    }
    pub fn id(&self) -> DeviceId {
        self.keys.id()
    }
    fn stored(&self) -> StoredDevice {
        StoredDevice {
            handle: KeyHandle([1; 32]),
            keys: self.keys.clone(),
            policy: ControlKeyPolicy::CurrentBiometricsOnly,
            kind: DeviceKeyStoreKind::MacDataProtectionKeychainV1,
        }
    }
}

fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("test signer pending"),
    }
}

/// A device's key store that only signs content, with its ordinary key.
struct Signer<'a>(&'a Device);
impl DeviceKeyStore for Signer<'_> {
    async fn create(&mut self, _: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        unreachable!()
    }
    async fn load(&mut self, _: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        Ok(self.0.stored())
    }
    async fn sign_control(&mut self, _: KeyHandle, _: Vec<u8>) -> Result<[u8; 64], KeyStoreError> {
        unreachable!()
    }
    async fn sign_content(
        &mut self,
        _: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        Ok(self.0.ordinary.sign(&message))
    }
    async fn decapsulate(
        &mut self,
        _: KeyHandle,
        _: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        unreachable!()
    }
}

/// The account as its devices know it: originals in order and the verified view.
pub struct Account {
    pub genesis: Vec<u8>,
    pub id: AccountId,
    pub log: LogId,
    pub verified: VerifiedAccount,
    pub originals: Vec<Vec<u8>>,
    pub personal: Option<PersonalKey>,
}
/// A base genesis made by a device, with its two independent roots.
pub struct BaseGenesis {
    pub descriptor: OpaqueEvent,
    pub body: Vec<u8>,
    pub creator_head: bh_account::Head,
    /// M, which registration carries, and K, which never leaves devices.
    pub metadata: Secret<32>,
    pub content: Secret<32>,
}
impl BaseGenesis {
    pub fn log(&self) -> LogId {
        LogId {
            kind: LogKind::Base,
            id: BaseId::from_genesis(&self.descriptor).0,
        }
    }
    pub fn register(&self) -> ToService {
        self.register_with(&self.metadata)
    }
    pub fn register_with(&self, metadata: &Secret<32>) -> ToService {
        ToService::RegisterBase {
            descriptor: self.descriptor.encode(),
            body: self.body.clone(),
            creator_head: self.creator_head,
            metadata: MetadataKey::new(metadata),
        }
    }
}
impl Account {
    /// An account with its recovery record and personal key published, as
    /// signup leaves it: it can create bases and deliver its personal key.
    pub fn create_full(first: &Device) -> Self {
        let mut account = Self::create(first);
        let record = account
            .verified
            .prepare_recovery_record(first.id(), bh_crypto::random())
            .unwrap();
        account.accept(
            record
                .finish(first.control.sign(record.signing_bytes()))
                .unwrap(),
        );
        let key = PersonalKey::generate();
        let publication = personal::prepare_publication(&account.verified, &key).unwrap();
        let draft = account
            .verified
            .publish_personal_key(
                first.id(),
                publication.public(),
                publication.device_digest(),
                publication.recovery_digest(),
            )
            .unwrap();
        account.accept(
            draft
                .finish(first.control.sign(draft.signing_bytes()))
                .unwrap(),
        );
        account.personal = Some(key);
        account
    }
    /// A base genesis `device` signs at the account's current head.
    pub fn base_genesis(&self, device: &Device) -> BaseGenesis {
        let metadata = Secret::<32>::random();
        let content = Secret::<32>::random();
        let request =
            bh_event::prepare_genesis(&self.verified, device.id(), &metadata, &content).unwrap();
        let signature = device.ordinary.sign(request.signing_bytes());
        let (encoded, _) = request.finish(signature).unwrap();
        BaseGenesis {
            descriptor: encoded.descriptor,
            body: encoded.body,
            creator_head: self.verified.head(),
            metadata,
            content,
        }
    }
    /// The signed addition of `new` by `by`, not yet applied, and `by`'s
    /// signed delivery of the personal key to it.
    pub fn add_with_delivery(&self, by: &Device, new: &Device) -> (AccountEvent, Vec<u8>) {
        let draft = self.verified.add_device(by.id(), new.keys.clone()).unwrap();
        let added = draft
            .finish(by.control.sign(draft.signing_bytes()))
            .unwrap();
        let frame = ready(personal::seal_for_device(
            &self.verified,
            self.personal.as_ref().unwrap(),
            &by.stored(),
            &new.keys,
            &added,
            &mut Signer(by),
        ))
        .unwrap();
        (added, frame)
    }
    /// A delivery frame built by hand and validly signed by `by`, sealed to
    /// `recipient`'s receiving key under the personal key `personal_public`:
    /// what the signing API refuses to make, such as a delivery to a device
    /// that is already active.
    pub fn forge_delivery(
        &self,
        by: &Device,
        recipient: &DevicePublicKeys,
        personal_public: &[u8; 1216],
    ) -> Vec<u8> {
        use bh_account::crypto;
        let personal_id =
            crypto::hash(&[b"BH personal key id v1\0".as_slice(), personal_public].concat());
        let recipient_hash = crypto::hash(
            &[
                b"BH personal recipient v1\0".as_slice(),
                recipient.receiving(),
            ]
            .concat(),
        );
        let (ct, shared) = crypto::encapsulate(recipient.receiving()).unwrap();
        let key = crypto::derive_key(&shared, b"BHPSEA01", 1);
        let header = [
            1u16.to_be_bytes().as_slice(),
            &[3],
            &self.id.0,
            &personal_id,
            &recipient_hash,
        ]
        .concat();
        let ad = [b"BH personal seed seal v1\0".as_slice(), &header].concat();
        let (nonce, ciphertext) = crypto::aead_seal(&key, &ad, &[7; 32]).unwrap();
        let mut frame = b"BHPDEL01BHPERS01".to_vec();
        frame.extend(header);
        frame.extend(ct);
        frame.extend(nonce);
        frame.extend(ciphertext);
        frame.extend(by.id().0);
        let signature = by.ordinary.sign(&frame);
        frame.extend(signature);
        frame
    }
    /// Apply a signed event this account's devices accept.
    pub fn apply(&mut self, event: &AccountEvent) {
        self.accept(event.clone());
    }
    pub fn create(first: &Device) -> Self {
        let recovery =
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
        let draft = AccountEvent::genesis(first.keys.clone(), recovery);
        let genesis = draft
            .finish(first.control.sign(draft.signing_bytes()))
            .unwrap();
        let id = AccountId::of_genesis(&genesis).unwrap();
        let bytes = genesis.as_bytes().to_vec();
        Self {
            verified: VerifiedAccount::from_genesis(id, &bytes).unwrap(),
            log: LogId {
                kind: LogKind::Account,
                id: account_log_id(&bytes).unwrap(),
            },
            id,
            originals: vec![bytes.clone()],
            genesis: bytes,
            personal: None,
        }
    }
    /// A signed control the account's devices accept, applied to this view.
    pub fn add_device(&mut self, by: &Device, new: &Device) -> Vec<u8> {
        let draft = self.verified.add_device(by.id(), new.keys.clone()).unwrap();
        self.accept(
            draft
                .finish(by.control.sign(draft.signing_bytes()))
                .unwrap(),
        )
    }
    pub fn remove_self(&mut self, device: &Device) -> Vec<u8> {
        let draft = self.verified.remove_self(device.id()).unwrap();
        self.accept(
            draft
                .finish(device.control.sign(draft.signing_bytes()))
                .unwrap(),
        )
    }
    fn accept(&mut self, event: AccountEvent) -> Vec<u8> {
        self.verified.apply(event.as_bytes()).unwrap();
        self.originals.push(event.as_bytes().to_vec());
        event.as_bytes().to_vec()
    }
    /// The verified view at an earlier position, as an older device holds it.
    pub fn at(&self, position: usize) -> VerifiedAccount {
        let history: Vec<&[u8]> = self.originals[..position]
            .iter()
            .map(Vec::as_slice)
            .collect();
        let mut view = VerifiedAccount::from_genesis(self.id, history[0]).unwrap();
        view.apply_batch(&history[1..]).unwrap();
        view
    }
}

/// An account as signup leaves it, under `password` and a fresh code: its
/// recovery record and personal key published, and the request that stores
/// its home objects.
pub struct Signup {
    pub account: Account,
    pub code: bh_account::recovery::RecoveryCode,
    pub record: Vec<u8>,
    pub recovery_seal: Vec<u8>,
    pub store: ToService,
}
impl Signup {
    pub fn new(device: &Device, password: &str) -> Self {
        use bh_account::recovery;
        let keys = recovery::RecoveryKeys::generate();
        let draft = AccountEvent::genesis(device.keys.clone(), keys.public());
        let genesis = draft
            .finish(device.control.sign(draft.signing_bytes()))
            .unwrap();
        let id = AccountId::of_genesis(&genesis).unwrap();
        let bytes = genesis.as_bytes().to_vec();
        let mut account = Account {
            verified: VerifiedAccount::from_genesis(id, &bytes).unwrap(),
            log: LogId {
                kind: LogKind::Account,
                id: account_log_id(&bytes).unwrap(),
            },
            id,
            originals: vec![bytes.clone()],
            genesis: bytes,
            personal: None,
        };
        let code = recovery::RecoveryCode::generate();
        let record = recovery::prepare_record(
            &account.verified,
            &keys,
            &recovery::Password::new(password).unwrap(),
            &code,
        )
        .unwrap();
        let draft = account
            .verified
            .prepare_recovery_record(device.id(), record.digest())
            .unwrap();
        account.accept(
            draft
                .finish(device.control.sign(draft.signing_bytes()))
                .unwrap(),
        );
        let key = PersonalKey::generate();
        let publication = personal::prepare_publication(&account.verified, &key).unwrap();
        let draft = account
            .verified
            .publish_personal_key(
                device.id(),
                publication.public(),
                publication.device_digest(),
                publication.recovery_digest(),
            )
            .unwrap();
        account.accept(
            draft
                .finish(device.control.sign(draft.signing_bytes()))
                .unwrap(),
        );
        account.personal = Some(key);
        let store = ToService::StoreHomeObjects {
            prefix: account.verified.head(),
            record: record.as_bytes().to_vec(),
            device_seal: publication.device_seal().to_vec(),
            recovery_seal: publication.recovery_seal().to_vec(),
        };
        Self {
            account,
            code,
            record: record.as_bytes().to_vec(),
            recovery_seal: publication.recovery_seal().to_vec(),
            store,
        }
    }
}

/// An in-memory ordered log store standing in for the edge and its log
/// objects: it verifies every permit at its clock against the pinned root and
/// enforces what the log object does: a control's predecessor is the control
/// head, a control sets the epoch (all zeros closes it), content needs the
/// open epoch, bodies must be staged, and the route is committed.
pub struct FakeEdge {
    root: [u8; 32],
    receipt_key: SigningKey,
    receipt_cert: receipt::CertifiedReceiptKey,
    clock: Arc<FixedClock>,
    logs: Mutex<HashMap<(u8, [u8; 32]), Log>>,
    pub down: AtomicBool,
    pub corrupt_receipt: AtomicBool,
    pub corrupt_coverage_receipt: AtomicBool,
    pub omit_receipt: AtomicBool,
    pub corrupt_ordering: AtomicBool,
    pub corrupt_body: AtomicBool,
    pub fail_retire_once: AtomicBool,
    pub hide_batch: AtomicBool,
    /// Milliseconds the clock moves forward during each read.
    pub read_takes: AtomicU64,
    pub reads: AtomicU64,
    /// Reads of a log's controls, under ReadControls or ReadControlRange
    /// permits.
    pub control_reads: AtomicU64,
    /// Rewrites the control rows a control read selects from, as a server
    /// that omits or substitutes controls would. Endpoints stay genuine.
    pub rewrite_controls: Mutex<Option<ControlRewrite>>,
    /// Control reads carry no endpoint.
    pub withhold_endpoint: AtomicBool,
    pub malformed_endpoint: AtomicBool,
    pub wrong_coverage_root: AtomicBool,
    /// A bounded control read answers with the current endpoint, as a
    /// server that does not hold a scan to its first one.
    pub ignore_through: AtomicBool,
    /// Ordered on the control route once the next control read is served.
    pub append_after_control_read: Mutex<Option<(LogId, OpaqueEvent)>>,
    /// Swap the final event after the first page was captured; a later
    /// bounded page gets another independently signed root at that position.
    pub fork_after_control_read: Mutex<Option<(LogId, usize, OpaqueEvent, Route)>>,
    /// Home-object bundles stored, by account log.
    pub home_objects: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}
pub type ControlRewrite = Box<dyn Fn(&mut Vec<(Commitment, OpaqueEvent)>) + Send + Sync>;
struct Log {
    entries: Vec<(Commitment, OpaqueEvent)>,
    epoch: [u8; 32],
    control: Head,
    staged: HashMap<Digest, Vec<u8>>,
}
impl Default for Log {
    fn default() -> Self {
        Self {
            entries: vec![],
            epoch: [0; 32],
            control: Head::EMPTY,
            staged: HashMap::new(),
        }
    }
}
impl Log {
    fn head(&self) -> Head {
        self.entries.last().map_or(Head::EMPTY, |(c, _)| c.head())
    }
}
fn key(log: LogId) -> (u8, [u8; 32]) {
    (log.kind as u8, log.id)
}
impl FakeEdge {
    pub fn new(root_key: &SigningKey, clock: Arc<FixedClock>) -> Arc<Self> {
        let receipt_key = SigningKey::generate();
        let receipt_cert = receipt::verify_certificate(
            &root_key.public(),
            &receipt::certify(root_key, receipt_key.public()),
        )
        .unwrap();
        Arc::new(Self {
            root: root_key.public(),
            receipt_key,
            receipt_cert,
            clock,
            logs: Mutex::default(),
            down: AtomicBool::new(false),
            corrupt_receipt: AtomicBool::new(false),
            corrupt_coverage_receipt: AtomicBool::new(false),
            omit_receipt: AtomicBool::new(false),
            corrupt_ordering: AtomicBool::new(false),
            corrupt_body: AtomicBool::new(false),
            fail_retire_once: AtomicBool::new(false),
            hide_batch: AtomicBool::new(false),
            read_takes: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            control_reads: AtomicU64::new(0),
            rewrite_controls: Mutex::new(None),
            withhold_endpoint: AtomicBool::new(false),
            malformed_endpoint: AtomicBool::new(false),
            wrong_coverage_root: AtomicBool::new(false),
            ignore_through: AtomicBool::new(false),
            append_after_control_read: Mutex::new(None),
            fork_after_control_read: Mutex::new(None),
            home_objects: Mutex::default(),
        })
    }
    fn verify(&self, signed: &[u8]) -> Result<Permit, String> {
        permit::verify(self.root, signed, self.clock.now()).map_err(|e| format!("{e:?}"))
    }
    pub fn stage(&self, signed: &[u8], body: &[u8]) -> Result<(), String> {
        let permit = self.verify(signed)?;
        let Scope::Stage {
            log,
            body: commitment,
            len,
        } = permit.scope
        else {
            return Err("scope".into());
        };
        let object = BodyObject::new(body.to_vec()).map_err(|e| format!("{e:?}"))?;
        if object.commitment() != commitment || body.len() != len as usize {
            return Err("body".into());
        }
        self.logs
            .lock()
            .unwrap()
            .entry(key(log))
            .or_default()
            .staged
            .insert(commitment, body.to_vec());
        Ok(())
    }
    pub fn append(&self, signed: &[u8], event: &OpaqueEvent) -> Result<Head, String> {
        let permit = self.verify(signed)?;
        let Scope::Append {
            log,
            event: digest,
            body,
            epoch,
            after,
            attached,
        } = permit.scope
        else {
            return Err("scope".into());
        };
        if digest != event.digest() {
            return Err("event".into());
        }
        // As the log object does: a permit with a predecessor is a control.
        let route = if after.is_some() {
            Route::Control
        } else {
            Route::Content
        };
        let mut logs = self.logs.lock().unwrap();
        let entry = logs.entry(key(log)).or_default();
        if let Some((ordered, _)) = entry
            .entries
            .iter()
            .find(|(c, _)| c.event_id() == event.publication_id(route))
        {
            if ordered.event_digest() != digest || ordered.route() != route {
                return Err("Conflict".into());
            }
            return Ok(ordered.head());
        }
        match after {
            Some(after) if after != entry.control => return Err("Predecessor".into()),
            None if epoch == [0; 32] || epoch != entry.epoch => return Err("Epoch".into()),
            _ => {}
        }
        if [body, attached]
            .into_iter()
            .flatten()
            .any(|b| !entry.staged.contains_key(&b))
        {
            return Err("NotStaged".into());
        }
        let before = entry
            .entries
            .last()
            .map_or(bh_sync::OrderState::EMPTY, |(c, _)| c.after());
        let ordered = Commitment::order(BaseId(log.id), before, event, route).unwrap();
        entry.entries.push((ordered, event.clone()));
        if after.is_some() {
            entry.epoch = epoch;
            entry.control = ordered.head();
        }
        Ok(ordered.head())
    }
    pub fn head(&self, log: LogId) -> Head {
        self.logs
            .lock()
            .unwrap()
            .get(&key(log))
            .map_or(Head::EMPTY, Log::head)
    }
    /// The log's epoch: the last control's, all zeros once closed.
    pub fn epoch(&self, log: LogId) -> [u8; 32] {
        self.logs
            .lock()
            .unwrap()
            .get(&key(log))
            .map_or([0; 32], |l| l.epoch)
    }
    /// Keep only the log's first `len` entries: a server serving another
    /// history from here on. Its receipts sign whatever it then holds.
    pub fn truncate(&self, log: LogId, len: usize) {
        let mut logs = self.logs.lock().unwrap();
        let entry = logs.entry(key(log)).or_default();
        entry.entries.truncate(len);
        entry.control = entry
            .entries
            .iter()
            .rev()
            .find(|(c, _)| c.route() == Route::Control)
            .map_or(Head::EMPTY, |(c, _)| c.head());
    }
    /// Order an event as the log object would, with no permit: what another
    /// history's server holds.
    pub fn force_append(&self, log: LogId, event: &OpaqueEvent, route: Route) -> Commitment {
        let mut logs = self.logs.lock().unwrap();
        let entry = logs.entry(key(log)).or_default();
        let before = entry
            .entries
            .last()
            .map_or(OrderState::EMPTY, |(c, _)| c.after());
        let ordered = Commitment::order(BaseId(log.id), before, event, route).unwrap();
        entry.entries.push((ordered, event.clone()));
        if route == Route::Control {
            entry.control = ordered.head();
        }
        ordered
    }
    /// Control rows after `after` up to the endpoint at `through`, or the
    /// current one, as the log object captures them, and that endpoint
    /// with a receipt for its head.
    fn control_read(
        &self,
        log: LogId,
        after: u64,
        through: Option<u64>,
    ) -> Result<LogRead, EdgeError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.control_reads.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err(EdgeError::Unavailable);
        }
        self.clock.advance(self.read_takes.load(Ordering::SeqCst));
        let through = through.filter(|_| !self.ignore_through.load(Ordering::SeqCst));
        // The read answers from the log as it is now; later hooks change it
        // after. Only a rewrite hook needs its own copy of the whole log:
        // otherwise the page is read in place, so the fake's own work stays
        // one page, whatever the log's length.
        let rewrite = self.rewrite_controls.lock().unwrap();
        let logs = self.logs.lock().unwrap();
        let empty = Vec::new();
        let all = logs.get(&key(log)).map_or(&empty, |e| &e.entries);
        let target = through.unwrap_or_else(|| all.last().map_or(0, |(c, _)| c.after().position()));
        let endpoint = if target == 0 {
            Ok(OrderState::EMPTY)
        } else {
            all.iter()
                .find(|(c, _)| c.after().position() == target)
                .map(|(c, _)| c.after())
                .ok_or(EdgeError::Refused)
        };
        let page = |controls: &mut dyn Iterator<Item = &(Commitment, OpaqueEvent)>| -> Vec<(Vec<u8>, Vec<u8>)> {
            controls
                .filter(|(c, _)| (after + 1..=target).contains(&c.after().position()))
                .take(64)
                .map(|(c, e)| (c.encode().to_vec(), e.encode()))
                .collect()
        };
        let items = match rewrite.as_ref() {
            Some(rewrite) => {
                let mut controls: Vec<_> = all
                    .iter()
                    .filter(|(c, _)| c.route() == Route::Control)
                    .cloned()
                    .collect();
                rewrite(&mut controls);
                page(&mut controls.iter())
            }
            None => page(&mut all.iter().filter(|(c, _)| c.route() == Route::Control)),
        };
        drop(logs);
        drop(rewrite);
        if let Some((log, event)) = self.append_after_control_read.lock().unwrap().take() {
            self.force_append(log, &event, Route::Control);
        }
        if let Some((log, before, event, route)) =
            self.fork_after_control_read.lock().unwrap().take()
        {
            self.truncate(log, before);
            self.force_append(log, &event, route);
        }
        let endpoint = endpoint?;
        let receipt = (endpoint != OrderState::EMPTY).then(|| {
            let wrong_root = SigningKey::generate();
            let alternate = self.wrong_coverage_root.load(Ordering::SeqCst).then(|| {
                receipt::verify_certificate(
                    &wrong_root.public(),
                    &receipt::certify(&wrong_root, self.receipt_key.public()),
                )
                .unwrap()
            });
            let mut signed = receipt::sign(
                alternate.as_ref().unwrap_or(&self.receipt_cert),
                &self.receipt_key,
                BaseId(log.id),
                endpoint.head(BaseId(log.id)),
            )
            .unwrap();
            if self.corrupt_coverage_receipt.load(Ordering::SeqCst) {
                signed[receipt::RECEIPT_LEN - 1] ^= 1;
            }
            signed
        });
        let coverage =
            (!self.withhold_endpoint.load(Ordering::SeqCst)).then_some(CoverageEndpoint {
                order: if self.malformed_endpoint.load(Ordering::SeqCst) {
                    OrderState::EMPTY
                } else {
                    endpoint
                },
                receipt,
            });
        Ok(LogRead {
            items,
            receipt: None,
            coverage,
        })
    }
    /// Ordered `(commitment, event, body)` after `position`, as a device's
    /// pull receives them.
    pub fn after(&self, log: LogId, position: u64) -> Vec<(Commitment, OpaqueEvent, Vec<u8>)> {
        let logs = self.logs.lock().unwrap();
        let Some(entry) = logs.get(&key(log)) else {
            return vec![];
        };
        entry
            .entries
            .iter()
            .filter(|(c, _)| c.head().position > position)
            .map(|(c, e)| {
                let body = bh_sync::referenced_body(e)
                    .ok()
                    .and_then(|b| entry.staged.get(&b).cloned())
                    .unwrap_or_default();
                (*c, e.clone(), body)
            })
            .collect()
    }
}
impl EdgeReader for FakeEdge {
    fn retire_home_objects(&self, signed: Vec<u8>) -> BoxFuture<'_, Result<(), EdgeError>> {
        Box::pin(async move {
            if self.down.load(Ordering::SeqCst)
                || self.fail_retire_once.swap(false, Ordering::SeqCst)
            {
                return Err(EdgeError::Unavailable);
            }
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            let Scope::RetireHomeObjects { log, prefix_digest } = permit.scope else {
                return Err(EdgeError::Refused);
            };
            let mut objects = self.home_objects.lock().unwrap();
            match objects.get(&log.id) {
                Some(_) if prefix_digest != Digest([0; 32]) => {
                    objects.remove(&log.id);
                }
                Some(_) => return Err(EdgeError::Refused),
                None => {}
            }
            Ok(())
        })
    }
    fn read_log_with_receipt(&self, signed: Vec<u8>) -> BoxFuture<'_, Result<LogRead, EdgeError>> {
        Box::pin(async move {
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            let log = match permit.scope {
                Scope::ReadEvents { log, .. } => log,
                Scope::ReadControls { log, after } => return self.control_read(log, after, None),
                Scope::ReadControlRange {
                    log,
                    after,
                    through,
                } => return self.control_read(log, after, Some(through)),
                _ => return Err(EdgeError::Refused),
            };
            let mut items = self.read_log(signed).await?;
            let mut receipt = if log.kind == LogKind::Base && !items.is_empty() {
                let tail = bh_sync::Commitment::decode(&items.last().unwrap().0)
                    .map_err(|_| EdgeError::Malformed)?
                    .head();
                Some(
                    receipt::sign(&self.receipt_cert, &self.receipt_key, BaseId(log.id), tail)
                        .unwrap(),
                )
            } else {
                None
            };
            if self.corrupt_ordering.load(Ordering::SeqCst)
                && let Some((commitment, _)) = items.first_mut()
            {
                commitment[48] ^= 1;
            }
            if self.omit_receipt.load(Ordering::SeqCst) {
                receipt = None;
            }
            if self.hide_batch.load(Ordering::SeqCst) {
                items.clear();
                receipt = None;
            }
            if self.corrupt_receipt.load(Ordering::SeqCst)
                && let Some(bytes) = &mut receipt
            {
                bytes[receipt::RECEIPT_LEN - 1] ^= 1;
            }
            Ok(LogRead {
                items,
                receipt,
                coverage: None,
            })
        })
    }
    fn read_log(
        &self,
        signed: Vec<u8>,
    ) -> BoxFuture<'_, Result<Vec<(Vec<u8>, Vec<u8>)>, EdgeError>> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(EdgeError::Unavailable);
            }
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            self.clock.advance(self.read_takes.load(Ordering::SeqCst));
            let (log, positions, controls) = match permit.scope {
                Scope::ReadEvents { log, first, last } => (log, first..=last, false),
                Scope::ReadControls { log, after } => {
                    self.control_reads.fetch_add(1, Ordering::SeqCst);
                    (log, after + 1..=u64::MAX, true)
                }
                _ => return Err(EdgeError::Refused),
            };
            let logs = self.logs.lock().unwrap();
            let Some(entry) = logs.get(&key(log)) else {
                return Ok(vec![]);
            };
            Ok(entry
                .entries
                .iter()
                .filter(|(c, _)| {
                    // Selection needs only the position, not the global Head
                    // hash for every preceding event in this synthetic log.
                    positions.contains(&c.after().position())
                        && (!controls || c.route() == Route::Control)
                })
                .take(64)
                .map(|(c, e)| (c.encode(), e.encode()))
                .collect())
        })
    }
    /// As the account home does: the exact bundle the permit names, once.
    fn store_home_objects(
        &self,
        signed: Vec<u8>,
        bundle: Vec<u8>,
    ) -> BoxFuture<'_, Result<HomeObjectsAck, EdgeError>> {
        Box::pin(async move {
            if self.down.load(Ordering::SeqCst) {
                return Err(EdgeError::Unavailable);
            }
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            let Scope::StoreHomeObjects {
                log,
                prefix_digest,
                bundle_digest,
            } = permit.scope
            else {
                return Err(EdgeError::Refused);
            };
            if home_objects::digest(&bundle).ok() != Some(bundle_digest) {
                return Err(EdgeError::Refused);
            }
            let mut stored = self.home_objects.lock().unwrap();
            if stored.entry(log.id).or_insert(bundle.clone()) != &bundle {
                return Err(EdgeError::Refused);
            }
            Ok(HomeObjectsAck {
                prefix_digest,
                bundle_digest,
            })
        })
    }
    fn read_bodies(&self, signed: Vec<u8>) -> BoxFuture<'_, Result<Vec<Vec<u8>>, EdgeError>> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                return Err(EdgeError::Unavailable);
            }
            let permit = self.verify(&signed).map_err(|_| EdgeError::Refused)?;
            let Scope::ReadBodies { log, bodies } = permit.scope else {
                return Err(EdgeError::Refused);
            };
            let logs = self.logs.lock().unwrap();
            let entry = logs.get(&key(log)).ok_or(EdgeError::Refused)?;
            // Only ordered bodies are served, and an account log's staging
            // ones, which only the service's own permits can read.
            bodies
                .iter()
                .map(|b| {
                    let ordered = log.kind == LogKind::Account
                        || entry
                            .entries
                            .iter()
                            .any(|(_, e)| bh_sync::referenced_body(e).ok() == Some(*b));
                    match entry.staged.get(b) {
                        Some(bytes) if ordered => {
                            let mut returned = bytes.clone();
                            if self.corrupt_body.load(Ordering::SeqCst) {
                                returned[0] ^= 3;
                            }
                            Ok(returned)
                        }
                        _ => Err(EdgeError::Refused),
                    }
                })
                .collect()
        })
    }
}

/// Every durable row of one base's projection on the service's disk, byte
/// for byte: its control record, binding and pending control, and its
/// selected BASE copy generation's first uses and copy rows, whichever
/// generation number holds them. Unselected candidate staging is not the
/// base's projection.
pub fn projection_rows(path: &std::path::Path, base: [u8; 32]) -> Vec<Vec<rusqlite::types::Value>> {
    let db = rusqlite::Connection::open(path).unwrap();
    let mut rows = vec![];
    let mut collect = |sql: &str, params: &[&dyn rusqlite::ToSql]| {
        let mut statement = db.prepare(sql).unwrap();
        let width = statement.column_count();
        let generation = (0..width).find(|&i| statement.column_name(i).ok() == Some("generation"));
        let mut query = statement.query(params).unwrap();
        while let Some(row) = query.next().unwrap() {
            rows.push(
                (0..width)
                    .map(|i| match generation == Some(i) {
                        true => rusqlite::types::Value::Null,
                        false => row.get::<_, rusqlite::types::Value>(i).unwrap(),
                    })
                    .collect(),
            );
        }
    };
    for table in [
        "bases",
        "base_controls",
        "base_account_changes",
        "base_pending",
        "base_control_ids",
    ] {
        collect(
            &format!("SELECT * FROM {table} WHERE base=?1 ORDER BY 1, 2"),
            &[&base.as_slice()],
        );
    }
    collect(
        "SELECT * FROM projection_selected WHERE kind=2 AND source=?1",
        &[&base.as_slice()],
    );
    let generation: Option<i64> = rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT generation FROM projection_selected WHERE kind=2 AND source=?1",
            [base.as_slice()],
            |r| r.get(0),
        )
        .ok();
    if let Some(generation) = generation {
        // Its staged raw path is replay evidence a stop may pin, not
        // authority: a rebuilt generation holds the whole path, an
        // incrementally confirmed one only its registration's.
        collect(
            "SELECT * FROM base_ids WHERE base=?1 AND generation=?2 ORDER BY 3",
            &[&base.as_slice(), &generation],
        );
        for table in [
            "projection_sources",
            "projection_current",
            "projection_active",
            "projection_devices",
            "projection_keys",
            "projection_times",
            "projection_copies",
        ] {
            collect(
                &format!(
                    "SELECT * FROM {table} WHERE kind=2 AND source=?1 AND generation=?2 ORDER BY 5"
                ),
                &[&base.as_slice(), &generation],
            );
        }
    }
    rows
}

/// A base's durable authority, whichever generation holds its copy: its
/// control record, binding and pending control, and its selected copy's
/// current cut, summary and opening.
pub fn base_authority(path: &std::path::Path, base: [u8; 32]) -> Vec<Vec<rusqlite::types::Value>> {
    let db = rusqlite::Connection::open(path).unwrap();
    let mut rows = vec![];
    for sql in [
        "SELECT * FROM bases WHERE base=?1",
        "SELECT * FROM base_controls WHERE base=?1",
        "SELECT * FROM base_pending WHERE base=?1",
        "SELECT c.position, c.hash, c.summary, c.stopped, c.opening FROM projection_selected s
         JOIN projection_current c ON (c.account,c.kind,c.source,c.generation)=(s.account,s.kind,s.source,s.generation)
         WHERE s.kind=2 AND s.source=?1",
    ] {
        let mut statement = db.prepare(sql).unwrap();
        let width = statement.column_count();
        let mut query = statement.query([base.as_slice()]).unwrap();
        while let Some(row) = query.next().unwrap() {
            rows.push(
                (0..width)
                    .map(|i| row.get::<_, rusqlite::types::Value>(i).unwrap())
                    .collect(),
            );
        }
    }
    rows
}

/// Each of a base's generations: its number, phase (0 staging, 1 published,
/// 2 discarded) and how many rows of any table it still holds.
pub fn base_generations(path: &std::path::Path, base: [u8; 32]) -> Vec<(i64, i64, i64)> {
    let db = rusqlite::Connection::open(path).unwrap();
    let rows = [
        "base_raw",
        "base_ids",
        "projection_copies",
        "projection_times",
        "projection_devices",
        "projection_keys",
        "projection_active",
        "projection_current",
        "projection_sources",
    ]
    .map(|table| {
        let scope = match table.starts_with("base_") {
            true => "t.base=g.base",
            false => "t.kind=2 AND t.source=g.base",
        };
        format!("(SELECT COUNT(*) FROM {table} t WHERE {scope} AND t.generation=g.generation)")
    })
    .join(" + ");
    let mut statement = db
        .prepare(&format!(
            "SELECT g.generation, g.phase, {rows} FROM base_generations g WHERE g.base=?1 ORDER BY 1"
        ))
        .unwrap();
    statement
        .query_map([base.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// A base's durable genesis status: 1 provisional, 2 accepted; None for
/// no projection, or one recorded before canonical order.
pub fn base_status(path: &std::path::Path, base: [u8; 32]) -> Option<i64> {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT status FROM base_controls WHERE base=?1",
            [base.as_slice()],
            |r| r.get(0),
        )
        .ok()
        .flatten()
}

/// The hosting root, a permit key it certifies, a clock, an edge and a disk.
pub struct Harness {
    pub dir: tempfile::TempDir,
    pub root: SigningKey,
    pub clock: Arc<FixedClock>,
    pub edge: Arc<FakeEdge>,
    seed: [u8; 32],
    recovery_seed: [u8; 32],
}
impl Harness {
    pub fn new() -> Self {
        let root = SigningKey::generate();
        let clock = Arc::new(FixedClock::new(TIME_START));
        Self {
            edge: FakeEdge::new(&root, clock.clone()),
            dir: tempfile::tempdir().unwrap(),
            root,
            clock,
            seed: bh_crypto::random(),
            recovery_seed: bh_crypto::random(),
        }
    }
    /// The home's recovery key and its certificate under the hosting root.
    pub fn recovery_key(&self) -> RecoveryHomeKey {
        let key = KemKey::from_seed(&Secret::from_slice(&self.recovery_seed).unwrap());
        let certificate = self.recovery_certificate();
        RecoveryHomeKey::new(key, certificate, &self.root.public()).unwrap()
    }
    /// What a recovering device pins: the recovery key's certificate.
    pub fn recovery_certificate(&self) -> RecoveryKeyCertificate {
        let key = KemKey::from_seed(&Secret::from_slice(&self.recovery_seed).unwrap());
        certify_recovery_key(&self.root, &key.public())
    }
    pub fn keys(&self) -> PermitKeys {
        let key = SigningKey::from_seed(&bh_crypto::Secret::from_slice(&self.seed).unwrap());
        let certificate = permit::certify(&self.root, key.public());
        PermitKeys::new(key, certificate).unwrap()
    }
    pub fn service(&self) -> Service {
        Service::open_with_recovery(
            &self.dir.path().join("authz.sqlite"),
            self.keys(),
            self.recovery_key(),
            self.clock.clone(),
            self.edge.clone(),
        )
        .unwrap()
    }
    /// A permit signed outside the service, as another instance would issue.
    pub fn sign(&self, scope: Scope) -> Vec<u8> {
        let key = SigningKey::generate();
        let certificate = permit::certify(&self.root, key.public());
        permit::sign(
            &key,
            &certificate,
            &Permit {
                scope,
                issued_ms: self.clock.now(),
                deadline_ms: self.clock.now() + 30_000,
                batch: [0; 16],
            },
        )
    }
    /// Order an original account event directly, outside any service.
    pub fn order_account_event(&self, account: &Account, original: &[u8]) -> Head {
        self.order_original(account.log, original)
    }
    /// Order an original account event on `log`, outside any service.
    pub fn order_original(&self, log: LogId, original: &[u8]) -> Head {
        let event = account_log_wrap(original, None).unwrap();
        let permit = self.sign(Scope::Append {
            log,
            event: event.digest(),
            body: None,
            epoch: ACCOUNT_EPOCH,
            after: Some(self.edge.head(log)),
            attached: None,
        });
        self.edge.append(&permit, &event).unwrap()
    }
    /// Order the account's whole known history on the edge.
    pub fn publish(&self, account: &Account) {
        let known = self.edge.head(account.log).position as usize;
        for original in &account.originals[known..] {
            self.order_account_event(account, original);
        }
    }
    /// The service's disk.
    pub fn disk(&self) -> std::path::PathBuf {
        self.dir.path().join("authz.sqlite")
    }
    pub fn permit(&self, signed: &[u8]) -> Permit {
        permit::verify(self.root.public(), signed, self.clock.now()).unwrap()
    }
}

/// A connection over a fixed channel binding, with its first challenge.
pub fn connect(service: &Service) -> (Connection, [u8; 32], [u8; 32]) {
    let binding = bh_crypto::random();
    let (connection, challenge) = service.connect(binding);
    let FromService::Challenge { challenge } = challenge else {
        panic!("first message is a challenge")
    };
    (connection, binding, challenge)
}
pub fn proof_at(
    view: &VerifiedAccount,
    device: &Device,
    binding: [u8; 32],
    challenge: [u8; 32],
) -> Box<[u8; device_auth::PROOF_LEN]> {
    let request = device_auth::prepare(
        view,
        device.id(),
        Context {
            channel_binding: binding,
            challenge,
        },
    )
    .unwrap();
    let signature = device.ordinary.sign(request.message());
    Box::new(*request.finish(signature).unwrap().as_bytes())
}
/// A proof in the possession format signed by any key, for a device the
/// account may not have: the format is fixed, so it can be built directly.
pub fn raw_proof(
    account: &Account,
    device: &Device,
    binding: [u8; 32],
    challenge: [u8; 32],
) -> Box<[u8; device_auth::PROOF_LEN]> {
    let head = account.verified.head();
    let mut unsigned = 1u16.to_be_bytes().to_vec();
    unsigned.extend(account.id.0);
    unsigned.extend(device.id().0);
    unsigned.extend(head.position.to_be_bytes());
    unsigned.extend(head.hash);
    unsigned.extend(binding);
    unsigned.extend(challenge);
    let signature = device
        .ordinary
        .sign(&[b"bh/sync-device-possession/v1\0".as_slice(), &unsigned].concat());
    unsigned.extend(signature);
    Box::new(unsigned.try_into().unwrap())
}
pub fn authenticate_message(
    account: &Account,
    device: &Device,
    binding: [u8; 32],
    challenge: [u8; 32],
) -> ToService {
    ToService::Authenticate {
        proof: proof_at(&account.verified, device, binding, challenge),
        account: account.id,
        device: device.id(),
        genesis: account.genesis.clone(),
    }
}
/// Connect and authenticate `device` at the account's latest head.
pub async fn session(service: &Service, account: &Account, device: &Device) -> Connection {
    let (mut connection, binding, challenge) = connect(service);
    let answer = connection
        .handle(authenticate_message(account, device, binding, challenge))
        .await;
    assert!(
        matches!(answer, FromService::Authenticated { account_head } if account_head == account.verified.head()),
        "authenticated: {answer:?}"
    );
    connection
}
/// Submit an original account control and order it with the permit.
pub async fn submit(
    harness: &Harness,
    connection: &mut Connection,
    account: &Account,
    original: &[u8],
) -> FromService {
    let answer = connection
        .handle(ToService::SubmitControl {
            log: account.log,
            event: original.to_vec(),
            delivery: None,
            attachment: None,
        })
        .await;
    if let FromService::Permits { items } = &answer {
        let permit = items[0].as_ref().unwrap();
        harness
            .edge
            .append(permit, &account_log_wrap(original, None).unwrap())
            .unwrap();
    }
    answer
}
/// Register a base genesis and order it with the permits.
pub fn order_genesis(harness: &Harness, answer: &FromService, genesis: &BaseGenesis) {
    let FromService::Permits { items } = answer else {
        panic!("permits: {answer:?}")
    };
    harness
        .edge
        .stage(items[0].as_ref().unwrap(), &genesis.body)
        .unwrap();
    harness
        .edge
        .append(items[1].as_ref().unwrap(), &genesis.descriptor)
        .unwrap();
}
/// Stage a rotation's padded body on the session's account log under a
/// permit the session asks for, as a device does before it submits the
/// rotation; the commitment that submission names.
pub async fn stage_rotation(
    harness: &Harness,
    connection: &mut Connection,
    log: LogId,
    raw: &[u8],
) -> Digest {
    let body = bh_authz::proto::rotation_body(raw).unwrap();
    stage_body(harness, connection, log, body.bytes()).await
}
/// Stage exact body bytes on `log` under a permit the session asks for.
pub async fn stage_body(
    harness: &Harness,
    connection: &mut Connection,
    log: LogId,
    bytes: &[u8],
) -> Digest {
    let body = BodyObject::new(bytes.to_vec()).unwrap();
    let permit = single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![Want::Stage {
                    log,
                    body: body.commitment(),
                    len: bytes.len() as u32,
                }],
            })
            .await,
    );
    harness.edge.stage(&permit, bytes).unwrap();
    body.commitment()
}
pub fn single_permit(answer: FromService) -> Vec<u8> {
    let FromService::Permits { mut items } = answer else {
        panic!("permits: {answer:?}")
    };
    assert_eq!(items.len(), 1);
    items.remove(0).unwrap()
}
/// A base genesis-shaped event: a 1024-byte envelope whose first 32 bytes
/// commit to its detached body, and that body.
pub fn base_event(fill: u8) -> (OpaqueEvent, Vec<u8>) {
    let body = vec![fill; 1024];
    let commitment = BodyObject::new(body.clone()).unwrap().commitment();
    let mut envelope = vec![fill; 1024];
    envelope[..32].copy_from_slice(&commitment.0);
    (
        OpaqueEvent::new(EventId(bh_crypto::random()), envelope).unwrap(),
        body,
    )
}
pub fn read_events(log: LogId) -> Want {
    Want::ReadEvents {
        log,
        first: 1,
        last: 64,
    }
}
