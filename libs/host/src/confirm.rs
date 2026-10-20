//! Narrow owner-confirmed actions on the app-gated Mac login-keychain route.
//!
//! A fresh confirmation of first-device genesis permits only its next
//! recovery record and personal-key publication, chained by the signed heads
//! and bound to the first device's control key, account and author. No other
//! action uses that confirmation; grants live in memory only.
//!
//! Approving a device is one control action: its addition and the copy of
//! exactly that addition into the own base. The addition's fresh owner
//! confirmation therefore also covers that one copy, signed later because
//! the base's copy can only be prepared once the addition is ordered.
//!
//! The host opens the action for one account, control key and native
//! generation just before the addition's prompt. Only the store, after that
//! fresh confirmation and its signature, turns it into a grant naming the
//! exact signed addition (its signing bytes and signature). Later the host
//! may arm that grant for one base-control message whose request copies
//! exactly that addition; the store then signs exactly that message once
//! without prompting. Everything else prompts as before. A grant is used
//! once, lasts as long as the pairing's copy approval, lives only in
//! memory, and ends on lock, cancellation before staging or any failure.
//! An armed copy whose grant ended meanwhile is refused, never prompted
//! for: it is signed from the background. It never exposes a key and is
//! never visible to a page.
use bh_account::{AccountEvent, AccountId, DeviceId, SignupKind, platform::KeyStoreError};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

/// How long one confirmation covers its copy: the pairing's copy approval.
pub const LIFE: Duration = bh_sync_client::pairing::SESSION_LIFE;

struct Scope {
    account: AccountId,
    generation: u64,
}
enum Grant {
    /// The host is about to ask for the addition's confirmation.
    Opening(Scope),
    /// The person confirmed signing `event`; one copy of it may be signed.
    Confirmed {
        scope: Scope,
        event: Vec<u8>,
        until: Instant,
    },
    /// Matched to one copy: exactly `message` may be signed once.
    Armed { message: Vec<u8>, until: Instant },
    /// Only the next first-device setup event on this exact signed chain.
    Signup {
        account: AccountId,
        author: DeviceId,
        previous: [u8; 32],
        next: SignupKind,
    },
}

#[derive(Default)]
struct Gate {
    /// At most one grant per control key.
    grants: HashMap<[u8; 32], Grant>,
    /// Prevent an in-flight approval/signature from reinstating a revoked grant.
    revisions: HashMap<[u8; 32], u64>,
    /// Copies armed and not yet signed or withdrawn, by key and message:
    /// signed only under their own grant, never after a prompt.
    armed: HashSet<([u8; 32], Vec<u8>)>,
}

/// The grants of one process.
#[derive(Clone, Default)]
pub struct ActionGate(Arc<Mutex<Gate>>);

impl ActionGate {
    fn gate(&self) -> std::sync::MutexGuard<'_, Gate> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Host: the next confirmed control signature by `key` is a device
    /// addition the person is approving for `account` at `generation`.
    pub fn open(&self, key: [u8; 32], account: AccountId, generation: u64) {
        self.revoke(key);
        self.gate().grants.insert(
            key,
            Grant::Opening(Scope {
                account,
                generation,
            }),
        );
    }
    /// Host: a fresh confirmation of finishing an already staged addition,
    /// asked for by the person after the earlier grant was lost. Grants one
    /// copy of exactly `event` only if `confirm` succeeds.
    pub async fn reconfirm(
        &self,
        key: [u8; 32],
        account: AccountId,
        generation: u64,
        event: &[u8],
        confirm: impl Future<Output = Result<(), KeyStoreError>>,
    ) -> Result<(), KeyStoreError> {
        self.revoke(key);
        confirm.await?;
        self.gate().grants.insert(
            key,
            Grant::Confirmed {
                scope: Scope {
                    account,
                    generation,
                },
                event: event.to_vec(),
                until: Instant::now() + LIFE,
            },
        );
        Ok(())
    }
    /// Host: use the grant for the copy of `copies` whose signing bytes are
    /// `message`. False, changing nothing, unless a live grant names exactly
    /// this key, account, generation and signed addition. Once armed, that
    /// message is signed only under this grant, until it is signed or
    /// withdrawn (`disarm`).
    pub fn arm(
        &self,
        key: [u8; 32],
        account: AccountId,
        generation: u64,
        copies: &[u8],
        message: &[u8],
    ) -> bool {
        let mut gate = self.gate();
        let until = match gate.grants.get(&key) {
            Some(Grant::Confirmed {
                scope,
                event,
                until,
            }) if scope.account == account
                && scope.generation == generation
                && event.as_slice() == copies
                && Instant::now() < *until =>
            {
                *until
            }
            _ => return false,
        };
        gate.grants.insert(
            key,
            Grant::Armed {
                message: message.to_vec(),
                until,
            },
        );
        gate.armed.insert((key, message.to_vec()));
        true
    }
    /// Host: the armed copy of `message` will not be signed after all.
    pub fn disarm(&self, key: [u8; 32], message: &[u8]) {
        let mut gate = self.gate();
        gate.armed.remove(&(key, message.to_vec()));
        if matches!(gate.grants.get(&key), Some(Grant::Armed { message: armed, .. }) if armed == message)
        {
            gate.grants.remove(&key);
        }
    }
    /// End `key`'s grant: the action was cancelled before staging, or failed.
    pub fn revoke(&self, key: [u8; 32]) {
        let mut gate = self.gate();
        gate.grants.remove(&key);
        *gate.revisions.entry(key).or_default() += 1;
    }
    /// A failed key lookup cannot identify which grant to revoke; end all
    /// signup continuations instead. Dropping an ordinary store clone does not
    /// call this: surviving clones still own the same gate.
    pub fn revoke_signups(&self) {
        let keys: Vec<_> = self
            .gate()
            .grants
            .iter()
            .filter_map(|(key, grant)| matches!(grant, Grant::Signup { .. }).then_some(*key))
            .collect();
        for key in keys {
            self.revoke(key);
        }
    }
    fn revision(&self, key: [u8; 32]) -> u64 {
        *self.gate().revisions.get(&key).unwrap_or(&0)
    }
    /// End every grant, as a restart does. (A lock already ends them: each
    /// grant names the generation it was confirmed at.)
    #[cfg(test)]
    pub fn clear(&self) {
        let keys: Vec<_> = self.gate().grants.keys().copied().collect();
        for key in keys {
            self.revoke(key);
        }
        self.gate().armed.clear();
    }

    /// Store: how `message` by `key` may be signed, using up its grant. Any
    /// other message ends an armed grant.
    fn take_armed(&self, key: [u8; 32], message: &[u8]) -> Armed {
        let mut gate = self.gate();
        let armed = gate.armed.remove(&(key, message.to_vec()));
        let granted = match gate.grants.remove(&key) {
            Some(Grant::Armed {
                message: granted,
                until,
            }) => granted == message && Instant::now() < until,
            Some(Grant::Signup {
                account,
                author,
                previous,
                next,
            }) => {
                if let Some(found) = AccountEvent::signup_message(message, &key)
                    && found.kind == next
                    && found.account == account
                    && found.author == author
                    && found.previous == previous
                {
                    return Armed::Signup(found);
                }
                false
            }
            Some(other @ (Grant::Opening(_) | Grant::Confirmed { .. })) => {
                gate.grants.insert(key, other);
                false
            }
            None => false,
        };
        match (armed, granted) {
            (true, true) => Armed::Sign,
            (true, false) => Armed::Lost,
            (false, _) => Armed::Not,
        }
    }
    /// Store: after a fresh confirmation and the signature of `message`,
    /// grant one copy of exactly that addition if an action was opened.
    fn confirmed(
        &self,
        key: [u8; 32],
        message: &[u8],
        signature: &[u8; 64],
        revision: u64,
        genesis: Option<bh_account::SignupMessage>,
    ) {
        let mut gate = self.gate();
        if gate.revisions.get(&key).copied().unwrap_or(0) != revision {
            return;
        }
        if let Some(Grant::Opening(scope)) = gate.grants.remove(&key) {
            gate.grants.insert(
                key,
                Grant::Confirmed {
                    scope,
                    event: [message, signature].concat(),
                    until: Instant::now() + LIFE,
                },
            );
        } else if let Some(found) = genesis {
            // The parser already checked genesis; verification precedes this call.
            let head = bh_crypto::hash(&[message, signature].concat());
            gate.grants.insert(
                key,
                Grant::Signup {
                    account: AccountId(head),
                    author: found.author,
                    previous: head,
                    next: SignupKind::RecoveryRecord,
                },
            );
        }
    }
    fn continue_signup(
        &self,
        key: [u8; 32],
        message: &[u8],
        signature: &[u8; 64],
        found: bh_account::SignupMessage,
        revision: u64,
    ) {
        if found.kind != SignupKind::RecoveryRecord || self.revision(key) != revision {
            return;
        }
        // The unsigned message was strictly decoded and this signature verified.
        let head = bh_crypto::hash(&[message, signature].concat());
        let mut gate = self.gate();
        if gate.revisions.get(&key).copied().unwrap_or(0) == revision {
            gate.grants.insert(
                key,
                Grant::Signup {
                    account: found.account,
                    author: found.author,
                    previous: head,
                    next: SignupKind::PersonalKey,
                },
            );
        }
    }
}

/// How a store may sign one message.
enum Armed {
    /// The armed copy, under its grant: no prompt.
    Sign,
    Signup(bh_account::SignupMessage),
    /// An armed copy whose grant ended: refused, never prompted for.
    Lost,
    /// Not an armed copy: only after a fresh prompt.
    Not,
}

/// A control signature by `key` on an app-enforced store: an armed pairing
/// copy or one of the two chained first-device signup continuations signs
/// without `prompt`. A lost armed copy is refused, never prompted for. Every
/// other signature needs a fresh prompt; cancellation or revocation during
/// that prompt signs nothing, and any failure ends the key's grant.
pub async fn sign_control_gated(
    gate: &ActionGate,
    key: [u8; 32],
    message: &[u8],
    prompt: impl Future<Output = Result<(), KeyStoreError>>,
    sign: impl FnOnce() -> Result<[u8; 64], KeyStoreError>,
) -> Result<[u8; 64], KeyStoreError> {
    let revision = gate.revision(key);
    match gate.take_armed(key, message) {
        Armed::Sign => return sign(),
        Armed::Signup(found) => {
            return match sign() {
                Ok(signature) if bh_crypto::verify(&key, message, &signature).is_ok() => {
                    gate.continue_signup(key, message, &signature, found, revision);
                    Ok(signature)
                }
                Ok(_) => {
                    gate.revoke(key);
                    Err(KeyStoreError::InvalidSignature)
                }
                Err(error) => {
                    gate.revoke(key);
                    Err(error)
                }
            };
        }
        Armed::Lost => return Err(KeyStoreError::Unavailable),
        Armed::Not => {}
    }
    if let Err(error) = prompt.await {
        gate.revoke(key);
        return Err(error);
    }
    if gate.revision(key) != revision {
        return Err(KeyStoreError::Unavailable);
    }
    match sign() {
        Ok(signature) => {
            let genesis = AccountEvent::signup_message(message, &key)
                .filter(|found| found.kind == SignupKind::Genesis);
            if genesis.is_some() && bh_crypto::verify(&key, message, &signature).is_err() {
                gate.revoke(key);
                return Err(KeyStoreError::InvalidSignature);
            }
            gate.confirmed(key, message, &signature, revision, genesis);
            Ok(signature)
        }
        Err(error) => {
            gate.revoke(key);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const KEY: [u8; 32] = [7; 32];
    const OTHER_KEY: [u8; 32] = [8; 32];
    const ACCOUNT: AccountId = AccountId([1; 32]);
    const ADDITION: &[u8] = b"exact addition signing bytes";
    const SIGNATURE: [u8; 64] = [9; 64];
    const COPY: &[u8] = b"bh/original-envelope/v1\0exact copy";

    fn added() -> Vec<u8> {
        [ADDITION, &SIGNATURE].concat()
    }

    /// A store whose prompt answers as told, counting prompts and signatures.
    struct Store {
        gate: ActionGate,
        answer: Cell<Result<(), KeyStoreError>>,
        prompts: Cell<usize>,
        signed: Cell<usize>,
    }
    impl Store {
        fn new(gate: &ActionGate) -> Self {
            Self {
                gate: gate.clone(),
                answer: Cell::new(Ok(())),
                prompts: Cell::new(0),
                signed: Cell::new(0),
            }
        }
        async fn sign(&self, key: [u8; 32], message: &[u8]) -> Result<[u8; 64], KeyStoreError> {
            sign_control_gated(
                &self.gate,
                key,
                message,
                async {
                    self.prompts.set(self.prompts.get() + 1);
                    self.answer.get()
                },
                || {
                    self.signed.set(self.signed.get() + 1);
                    Ok(SIGNATURE)
                },
            )
            .await
        }
    }

    // A regression to three prompts (or skipping a signature) must fail here.
    #[tokio::test(start_paused = true)]
    async fn signup_chains_three_signatures_under_one_confirmation() {
        use bh_account::{AccountEvent, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount};
        use bh_crypto::SigningKey;

        let gate = ActionGate::default();
        let control = SigningKey::generate();
        let keys =
            DevicePublicKeys::new(SigningKey::generate().public(), control.public(), [7; 1216])
                .unwrap();
        let recovery = RecoveryPublicKeys::new(SigningKey::generate().public(), [8; 1216]);
        let prompts = Cell::new(0);
        let signed = Cell::new(0);
        let genesis_request = AccountEvent::genesis(keys.clone(), recovery);
        let sign = |message: &[u8]| {
            signed.set(signed.get() + 1);
            Ok(control.sign(message))
        };
        let approve = || async {
            prompts.set(prompts.get() + 1);
            Ok(())
        };
        let genesis_signature = sign_control_gated(
            &gate,
            control.public(),
            genesis_request.signing_bytes(),
            approve(),
            || sign(genesis_request.signing_bytes()),
        )
        .await
        .unwrap();
        let genesis = genesis_request.finish(genesis_signature).unwrap();
        let anchor = AccountId::of_genesis(&genesis).unwrap();
        let mut account = VerifiedAccount::from_genesis(anchor, genesis.as_bytes()).unwrap();
        let record_request = account
            .prepare_recovery_record(keys.id(), [13; 32])
            .unwrap();
        let record_signature = sign_control_gated(
            &gate,
            control.public(),
            record_request.signing_bytes(),
            approve(),
            || sign(record_request.signing_bytes()),
        )
        .await
        .unwrap();
        let record = record_request.finish(record_signature).unwrap();
        account.apply(record.as_bytes()).unwrap();
        let publish_request = account
            .publish_personal_key(keys.id(), [14; 1216], [15; 32], [16; 32])
            .unwrap();
        let publish_signature = sign_control_gated(
            &gate,
            control.public(),
            publish_request.signing_bytes(),
            approve(),
            || sign(publish_request.signing_bytes()),
        )
        .await
        .unwrap();
        publish_request.finish(publish_signature).unwrap();
        assert_eq!(signed.get(), 3);
        assert_eq!(
            prompts.get(),
            1,
            "genesis confirmation covers only its two chained setup signatures"
        );
    }

    struct SignupStore {
        gate: ActionGate,
        control: bh_crypto::SigningKey,
        keys: bh_account::DevicePublicKeys,
        prompts: Cell<usize>,
        signed: Cell<usize>,
        refuse: Cell<bool>,
        fail_sign: Cell<bool>,
    }
    impl SignupStore {
        fn new() -> Self {
            let control = bh_crypto::SigningKey::generate();
            let keys = bh_account::DevicePublicKeys::new(
                bh_crypto::SigningKey::generate().public(),
                control.public(),
                [7; 1216],
            )
            .unwrap();
            Self {
                gate: ActionGate::default(),
                control,
                keys,
                prompts: Cell::new(0),
                signed: Cell::new(0),
                refuse: Cell::new(false),
                fail_sign: Cell::new(false),
            }
        }
        async fn sign(&self, key: [u8; 32], message: &[u8]) -> Result<[u8; 64], KeyStoreError> {
            sign_control_gated(
                &self.gate,
                key,
                message,
                async {
                    self.prompts.set(self.prompts.get() + 1);
                    if self.refuse.get() {
                        Err(KeyStoreError::AuthenticationCancelled)
                    } else {
                        Ok(())
                    }
                },
                || {
                    if self.fail_sign.replace(false) {
                        return Err(KeyStoreError::StorageFailure);
                    }
                    self.signed.set(self.signed.get() + 1);
                    Ok(self.control.sign(message))
                },
            )
            .await
        }
        fn genesis(&self) -> bh_account::SigningRequest {
            bh_account::AccountEvent::genesis(
                self.keys.clone(),
                bh_account::RecoveryPublicKeys::new(
                    bh_crypto::SigningKey::generate().public(),
                    [8; 1216],
                ),
            )
        }
        async fn account(&self) -> bh_account::VerifiedAccount {
            let request = self.genesis();
            let sig = self
                .sign(self.control.public(), request.signing_bytes())
                .await
                .unwrap();
            let event = request.finish(sig).unwrap();
            bh_account::VerifiedAccount::from_genesis(
                AccountId::of_genesis(&event).unwrap(),
                event.as_bytes(),
            )
            .unwrap()
        }
        async fn record(&self, account: &mut bh_account::VerifiedAccount) {
            let request = account
                .prepare_recovery_record(self.keys.id(), [13; 32])
                .unwrap();
            let sig = self
                .sign(self.control.public(), request.signing_bytes())
                .await
                .unwrap();
            account
                .apply(request.finish(sig).unwrap().as_bytes())
                .unwrap();
        }
        async fn publication(&self, account: &mut bh_account::VerifiedAccount) {
            let request = account
                .publish_personal_key(self.keys.id(), [14; 1216], [15; 32], [16; 32])
                .unwrap();
            let sig = self
                .sign(self.control.public(), request.signing_bytes())
                .await
                .unwrap();
            account
                .apply(request.finish(sig).unwrap().as_bytes())
                .unwrap();
        }
    }

    #[tokio::test]
    async fn signup_grant_rejects_other_kinds_and_wrong_predecessor() {
        let store = SignupStore::new();
        let account = store.account().await;
        let add = account
            .add_device(
                store.keys.id(),
                bh_account::DevicePublicKeys::new(
                    bh_crypto::SigningKey::generate().public(),
                    bh_crypto::SigningKey::generate().public(),
                    [19; 1216],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            store
                .sign(store.control.public(), add.signing_bytes())
                .await
                .unwrap()
                .len(),
            64
        );
        assert_eq!(store.prompts.get(), 2, "AddDevice is a separate control");
        let record = account
            .prepare_recovery_record(store.keys.id(), [13; 32])
            .unwrap();
        store
            .sign(store.control.public(), record.signing_bytes())
            .await
            .unwrap();
        assert_eq!(store.prompts.get(), 3, "mismatch ended the signup grant");

        let store = SignupStore::new();
        let account = store.account().await;
        let record = account
            .prepare_recovery_record(store.keys.id(), [13; 32])
            .unwrap();
        let mut wrong = record.signing_bytes().to_vec();
        let previous_offset = b"BaseHero account event\0".len() + 2 + 2 + 8;
        wrong[previous_offset] ^= 1;
        assert!(AccountEvent::signup_message(&wrong, &store.control.public()).is_some());
        store.sign(store.control.public(), &wrong).await.unwrap();
        assert_eq!(store.prompts.get(), 2);
        store
            .sign(store.control.public(), record.signing_bytes())
            .await
            .unwrap();
        assert_eq!(store.prompts.get(), 3, "wrong previous ended the grant");
    }

    #[tokio::test]
    async fn signup_grant_rejects_other_account_author_and_base_control() {
        let store = SignupStore::new();
        let account = store.account().await;
        let request = account
            .prepare_recovery_record(store.keys.id(), [13; 32])
            .unwrap();
        let header = b"BaseHero account event\0".len() + 2 + 2 + 8 + 32;
        for index in [header, header + 32] {
            // account, then author
            let store = SignupStore::new();
            let account = store.account().await;
            let request = account
                .prepare_recovery_record(store.keys.id(), [13; 32])
                .unwrap();
            let mut wrong = request.signing_bytes().to_vec();
            wrong[index] ^= 1;
            assert!(AccountEvent::signup_message(&wrong, &store.control.public()).is_some());
            store.sign(store.control.public(), &wrong).await.unwrap();
            assert_eq!(store.prompts.get(), 2, "account/author mismatch prompts");
            store
                .sign(store.control.public(), request.signing_bytes())
                .await
                .unwrap();
            assert_eq!(
                store.prompts.get(),
                3,
                "account/author mismatch ended the grant"
            );
        }
        store
            .sign(store.control.public(), b"bh/base-control/v1\0non-account")
            .await
            .unwrap();
        store
            .sign(store.control.public(), request.signing_bytes())
            .await
            .unwrap();
        assert_eq!(store.prompts.get(), 3, "base control ends the grant");
    }

    #[tokio::test]
    async fn signup_grant_rejects_later_account_change_at_position_three() {
        let store = SignupStore::new();
        let mut account = store.account().await;
        store.record(&mut account).await;
        let add = account
            .add_device(
                store.keys.id(),
                bh_account::DevicePublicKeys::new(
                    bh_crypto::SigningKey::generate().public(),
                    bh_crypto::SigningKey::generate().public(),
                    [19; 1216],
                )
                .unwrap(),
            )
            .unwrap();
        store
            .sign(store.control.public(), add.signing_bytes())
            .await
            .unwrap();
        assert_eq!(store.prompts.get(), 2);
        store.publication(&mut account).await;
        assert_eq!(store.prompts.get(), 3, "later change ended the grant");
    }

    #[tokio::test]
    async fn signup_grant_is_per_key_and_only_through_position_three() {
        let store = SignupStore::new();
        let mut account = store.account().await;
        let record = account
            .prepare_recovery_record(store.keys.id(), [13; 32])
            .unwrap();
        let other = bh_crypto::SigningKey::generate().public();
        store.sign(other, record.signing_bytes()).await.unwrap();
        assert_eq!(store.prompts.get(), 2, "another key cannot use the grant");
        store.record(&mut account).await;
        store.publication(&mut account).await;
        assert_eq!(store.prompts.get(), 2, "only original key continued");
        let add = account
            .add_device(
                store.keys.id(),
                bh_account::DevicePublicKeys::new(
                    bh_crypto::SigningKey::generate().public(),
                    bh_crypto::SigningKey::generate().public(),
                    [19; 1216],
                )
                .unwrap(),
            )
            .unwrap();
        store
            .sign(store.control.public(), add.signing_bytes())
            .await
            .unwrap();
        assert_eq!(store.prompts.get(), 3, "fourth event prompts");
        store
            .sign(store.control.public(), b"bh/base-control/v1\0non-account")
            .await
            .unwrap();
        assert_eq!(store.prompts.get(), 4, "base control prompts");
    }

    #[tokio::test]
    async fn cancelled_or_failed_signup_ends_grant_and_retry_prompts() {
        let store = SignupStore::new();
        let genesis = store.genesis();
        store.refuse.set(true);
        assert_eq!(
            store
                .sign(store.control.public(), genesis.signing_bytes())
                .await,
            Err(KeyStoreError::AuthenticationCancelled)
        );
        assert_eq!(store.signed.get(), 0);
        store.refuse.set(false);
        let mut account = store.account().await;
        let record = account
            .prepare_recovery_record(store.keys.id(), [13; 32])
            .unwrap();
        store.fail_sign.set(true);
        assert_eq!(
            store
                .sign(store.control.public(), record.signing_bytes())
                .await,
            Err(KeyStoreError::StorageFailure)
        );
        assert_eq!(store.signed.get(), 1);
        store.record(&mut account).await;
        assert_eq!(
            store.prompts.get(),
            3,
            "cancel, retry genesis, failed continuation, retry record"
        );
    }

    #[tokio::test]
    async fn revoke_replace_or_failed_key_lookup_forgets_signup() {
        for end in ["revoke", "replace", "key lookup"] {
            let store = SignupStore::new();
            let account = store.account().await;
            let record = account
                .prepare_recovery_record(store.keys.id(), [13; 32])
                .unwrap();
            match end {
                "revoke" => store.gate.revoke(store.control.public()),
                "replace" => store.gate.open(store.control.public(), ACCOUNT, 4),
                _ => store.gate.revoke_signups(),
            }
            store
                .sign(store.control.public(), record.signing_bytes())
                .await
                .unwrap();
            assert_eq!(
                store.prompts.get(),
                2,
                "{end} must require a new confirmation"
            );
        }
    }

    #[tokio::test]
    async fn failed_cryptographic_signup_signature_does_not_grant_continuation() {
        let store = SignupStore::new();
        let genesis = store.genesis();
        let result = sign_control_gated(
            &store.gate,
            store.control.public(),
            genesis.signing_bytes(),
            async { Ok(()) },
            || Ok([0; 64]),
        )
        .await;
        assert_eq!(result, Err(KeyStoreError::InvalidSignature));
        // An invalid signature must not leave a no-prompt grant behind.
        let request = genesis
            .finish(store.control.sign(genesis.signing_bytes()))
            .unwrap();
        let account = bh_account::VerifiedAccount::from_genesis(
            AccountId::of_genesis(&request).unwrap(),
            request.as_bytes(),
        )
        .unwrap();
        let record = account
            .prepare_recovery_record(store.keys.id(), [13; 32])
            .unwrap();
        store
            .sign(store.control.public(), record.signing_bytes())
            .await
            .unwrap();
        assert_eq!(store.prompts.get(), 1);
    }

    #[tokio::test]
    async fn revoke_during_genesis_prompt_signs_nothing() {
        let store = SignupStore::new();
        let request = store.genesis();
        let result = sign_control_gated(
            &store.gate,
            store.control.public(),
            request.signing_bytes(),
            async {
                store.gate.revoke(store.control.public());
                Ok(())
            },
            || {
                store.signed.set(store.signed.get() + 1);
                Ok(store.control.sign(request.signing_bytes()))
            },
        )
        .await;
        assert_eq!(result, Err(KeyStoreError::Unavailable));
        assert_eq!(store.signed.get(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn confirmed_addition_covers_exactly_one_copy_of_itself() {
        let gate = ActionGate::default();
        let store = Store::new(&gate);
        gate.open(KEY, ACCOUNT, 4);
        assert_eq!(store.sign(KEY, ADDITION).await, Ok(SIGNATURE));
        assert_eq!(store.prompts.get(), 1);
        assert!(gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
        assert_eq!(store.sign(KEY, COPY).await, Ok(SIGNATURE));
        assert_eq!(store.prompts.get(), 1, "the copy reuses the confirmation");
        assert_eq!(store.signed.get(), 2);
        // Used once: the same copy again, or any other control, prompts.
        assert!(!gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
        assert_eq!(store.sign(KEY, COPY).await, Ok(SIGNATURE));
        assert_eq!(store.prompts.get(), 2);
        assert_eq!(store.sign(KEY, b"another control").await, Ok(SIGNATURE));
        assert_eq!(store.prompts.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_or_failed_confirmation_signs_and_grants_nothing() {
        for failure in [
            KeyStoreError::AuthenticationCancelled,
            KeyStoreError::Unavailable,
        ] {
            let gate = ActionGate::default();
            let store = Store::new(&gate);
            store.answer.set(Err(failure));
            gate.open(KEY, ACCOUNT, 4);
            assert_eq!(store.sign(KEY, ADDITION).await, Err(failure));
            assert_eq!(store.signed.get(), 0, "no signature without confirmation");
            assert!(!gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
            // A later confirmation of the same bytes, with no action open,
            // grants nothing either.
            store.answer.set(Ok(()));
            assert_eq!(store.sign(KEY, ADDITION).await, Ok(SIGNATURE));
            assert!(!gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ordinary_control_signatures_open_no_action() {
        let gate = ActionGate::default();
        let store = Store::new(&gate);
        assert_eq!(store.sign(KEY, ADDITION).await, Ok(SIGNATURE));
        assert!(!gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
    }

    #[tokio::test(start_paused = true)]
    async fn wrong_account_key_generation_or_event_cannot_use_it() {
        let gate = ActionGate::default();
        let store = Store::new(&gate);
        gate.open(KEY, ACCOUNT, 4);
        store.sign(KEY, ADDITION).await.unwrap();
        let mut other_event = added();
        other_event[0] ^= 1;
        assert!(!gate.arm(OTHER_KEY, ACCOUNT, 4, &added(), COPY));
        assert!(!gate.arm(KEY, AccountId([2; 32]), 4, &added(), COPY));
        assert!(!gate.arm(KEY, ACCOUNT, 5, &added(), COPY));
        assert!(!gate.arm(KEY, ACCOUNT, 4, &other_event, COPY));
        // Another key's signature never consumes it, and prompts.
        assert_eq!(store.sign(OTHER_KEY, COPY).await, Ok(SIGNATURE));
        assert_eq!(store.prompts.get(), 2);
        // The right request still works once.
        assert!(gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
        // Armed for exactly one message: another one prompts and revokes
        // it, and the armed copy is then refused, never prompted for.
        assert_eq!(
            store.sign(KEY, b"bh/original-envelope/v1\0other").await,
            Ok(SIGNATURE)
        );
        assert_eq!(store.prompts.get(), 3);
        assert_eq!(store.sign(KEY, COPY).await, Err(KeyStoreError::Unavailable));
        assert_eq!(store.prompts.get(), 3, "revoked by the unexpected message");
        // Refused once: a later deliberate signature of it prompts.
        assert_eq!(store.sign(KEY, COPY).await, Ok(SIGNATURE));
        assert_eq!(store.prompts.get(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn an_armed_copy_whose_grant_ends_is_refused_without_a_prompt() {
        for end in ["revoke", "open", "reconfirm", "disarm"] {
            let gate = ActionGate::default();
            let store = Store::new(&gate);
            gate.open(KEY, ACCOUNT, 4);
            store.sign(KEY, ADDITION).await.unwrap();
            assert!(gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
            match end {
                "revoke" => gate.revoke(KEY),
                "open" => gate.open(KEY, ACCOUNT, 4),
                "reconfirm" => gate
                    .reconfirm(KEY, ACCOUNT, 4, b"another event", async { Ok(()) })
                    .await
                    .unwrap(),
                _ => gate.disarm(KEY, COPY),
            }
            // Withdrawn by the host, it is no longer an automatic copy.
            let withdrawn = end == "disarm";
            let expected = if withdrawn {
                Ok(SIGNATURE)
            } else {
                Err(KeyStoreError::Unavailable)
            };
            assert_eq!(store.sign(KEY, COPY).await, expected, "{end}");
            assert_eq!(store.prompts.get(), 1 + usize::from(withdrawn), "{end}");
            assert_eq!(store.signed.get(), 1 + usize::from(withdrawn), "{end}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_lock_and_revocation_end_it() {
        let gate = ActionGate::default();
        let store = Store::new(&gate);
        gate.open(KEY, ACCOUNT, 4);
        store.sign(KEY, ADDITION).await.unwrap();
        tokio::time::advance(LIFE + Duration::from_secs(1)).await;
        assert!(!gate.arm(KEY, ACCOUNT, 4, &added(), COPY), "expired");

        gate.open(KEY, ACCOUNT, 4);
        store.sign(KEY, ADDITION).await.unwrap();
        gate.clear();
        assert!(!gate.arm(KEY, ACCOUNT, 4, &added(), COPY), "locked");

        gate.open(KEY, ACCOUNT, 4);
        store.sign(KEY, ADDITION).await.unwrap();
        gate.revoke(KEY);
        assert!(
            !gate.arm(KEY, ACCOUNT, 4, &added(), COPY),
            "cancelled before staging"
        );

        // Armed but not used in time: refused, not prompted for.
        gate.open(KEY, ACCOUNT, 4);
        store.sign(KEY, ADDITION).await.unwrap();
        assert!(gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
        tokio::time::advance(LIFE + Duration::from_secs(1)).await;
        assert_eq!(store.sign(KEY, COPY).await, Err(KeyStoreError::Unavailable));
        assert_eq!(store.prompts.get(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_reconfirmation_covers_one_copy_after_a_restart() {
        let gate = ActionGate::default();
        let store = Store::new(&gate);
        // Cancelled: nothing granted.
        store
            .answer
            .set(Err(KeyStoreError::AuthenticationCancelled));
        assert_eq!(
            gate.reconfirm(KEY, ACCOUNT, 4, &added(), async { store.answer.get() })
                .await,
            Err(KeyStoreError::AuthenticationCancelled)
        );
        assert!(!gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
        store.answer.set(Ok(()));
        gate.reconfirm(KEY, ACCOUNT, 4, &added(), async { store.answer.get() })
            .await
            .unwrap();
        assert!(gate.arm(KEY, ACCOUNT, 4, &added(), COPY));
        assert_eq!(store.sign(KEY, COPY).await, Ok(SIGNATURE));
        assert_eq!(store.prompts.get(), 0, "the reconfirmation was the prompt");
    }
}
