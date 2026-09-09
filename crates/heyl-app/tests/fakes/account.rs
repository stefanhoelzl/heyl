//! A complete synthetic account, built from a test recovery code.
//!
//! Everything the real backend would serve is constructed here with our own
//! primitives: the Argon2id parameters and checksum in `secretInfo`, the
//! profile-seed locks, the vault-key locks, the published public keys, and a
//! commit blob encrypted under the vault secret. So the offline suite runs the
//! *whole* M2 use case — typed code → Argon2id → seed → chain → decrypted
//! document — with no network and no credential.
//!
//! **What this proves and does not.** It proves the plumbing: that every link
//! composes, that the tiers do not cross, that a stale generation is refused.
//! It cannot prove our **context salts** agree with heylogin's, because the
//! ciphertexts here were made with those same salts. Only the live
//! `#[ignore]`d test does that. Any artifact that could prove it offline would,
//! by construction, be openable with a committed key (DESIGN.md §6).

use std::collections::HashMap;

use heyl_crypto::{
    EncryptionPrivateKey, Nonce, RecoveryParams, SecretSalt, Seed, SymKey, recovery,
};
use heyl_domain::{
    Authenticator, AuthenticatorId, AuthenticatorKeys, AuthenticatorPublicKeys,
    AuthenticatorSecret, AuthenticatorType, Challenge, Commit, CommitId, HighSecurity,
    KeyGenerationId, Profile, ProfileAuthenticatorLock, ProfileId, ProfilePublicKeys, ProfileSeed,
    Session, SessionId, SessionUnlock, Storable, SyncSnapshot, Timestamp, Tokens, VaultCommits,
    VaultId, VaultProfileLock, VaultSummary, VaultType,
};

/// The test recovery code. Six groups of four digits, hashed **with** the
/// dashes, exactly as §4 specifies.
pub const TEST_CODE: &str = "1111-2222-3333-4444-5555-6666";

/// Deliberately cheap: 8 MiB, one iteration, under 10 ms.
///
/// The production parameters are attacker-supplied and already bounded by
/// `heyl_crypto::recovery::RecoveryParams`. What this fixture needs to prove is
/// that the code→seed plumbing is right, not that Argon2 is slow — so CI does
/// not carry a memory-heavy hash in every run.
pub const TEST_PARAMS: RecoveryParams = RecoveryParams {
    memory_cost_kib: 8 * 1024,
    iterations: 1,
    parallelism: 1,
};

/// Argon2id needs at least 8 bytes of salt.
pub const TEST_SALT: &[u8] = b"heyl-test-salt-0";

fn uuid(tag: u8, n: u8) -> String {
    format!("00000000-0000-4000-8000-0000{tag:02x}0000{n:02x}")
}

/// A whole synthetic account.
pub struct Account {
    /// The seed the test code derives.
    pub seed: Seed,
    /// Which authenticator.
    pub authenticator_id: AuthenticatorId,
    /// Which profile.
    pub profile_id: ProfileId,
    /// Which vault.
    pub vault_id: VaultId,
    /// Which session.
    pub session_id: SessionId,
    /// The vault's `vaultSecret`.
    pub vault_secret: SymKey,
    /// The session key the unlock grant is sealed to.
    pub session_key: EncryptionPrivateKey,
    /// The plaintext document the commit blob holds.
    pub document: Vec<u8>,
}

impl Account {
    /// Build it, deriving the seed from [`TEST_CODE`] exactly as login will.
    pub fn new() -> Self {
        let derived = recovery::derive_recovery_seed(TEST_CODE, TEST_SALT, TEST_PARAMS)
            .expect("test parameters are valid");
        let seed = Seed::from_bytes(&derived);

        // A real heymerge envelope, uncompressed (0x7B). The re-key builder in
        // tools/ substitutes a genuine heylogin document here; the framing and
        // envelope shape are the same either way.
        let document =
            br#"{"type":"LoginVaultContentV2","version":2,"content":{"logins":{},"settings":{}}}"#
                .to_vec();

        Self {
            seed,
            authenticator_id: AuthenticatorId::parse(&uuid(0xaa, 1)).expect("valid"),
            profile_id: ProfileId::parse(&uuid(0xbb, 1)).expect("valid"),
            vault_id: VaultId::parse(&uuid(0xcc, 1)).expect("valid"),
            session_id: SessionId::parse(&uuid(0xdd, 1)).expect("valid"),
            vault_secret: SymKey::from_bytes(&[0x5a; 32]),
            session_key: EncryptionPrivateKey::from_bytes(&[0x7e; 32]),
            document,
        }
    }

    fn secret_salt() -> SecretSalt {
        SecretSalt::from_bytes([0xa5; 32])
    }

    fn keys(&self) -> AuthenticatorKeys {
        AuthenticatorKeys::derive(self.authenticator_id, &self.seed, &Self::secret_salt())
            .expect("derives")
    }

    fn generation() -> KeyGenerationId {
        KeyGenerationId::new("generation-1")
    }

    fn storable_profile_seed() -> ProfileSeed<Storable> {
        ProfileSeed::from_bytes(&[0x11; 32])
    }

    fn high_profile_seed() -> ProfileSeed<HighSecurity> {
        ProfileSeed::from_bytes(&[0x22; 32])
    }

    /// `secretInfo` for the `BACKUP_CODE` authenticator, checksum and all.
    fn recovery_secret(&self) -> AuthenticatorSecret {
        let checksum = heyl_crypto::hash_data(self.seed.expose_secret()).to_vec();
        AuthenticatorSecret::Recovery(heyl_domain::RecoverySecret {
            checksum,
            salt: TEST_SALT.to_vec(),
            params: TEST_PARAMS,
        })
    }

    /// The id of the push authenticator a recovery would disconnect.
    pub fn push_authenticator_id() -> AuthenticatorId {
        AuthenticatorId::parse(&uuid(0xaa, 2)).expect("valid")
    }

    /// What `CreateChallenge` would return: no `secretSalt`, no public keys.
    ///
    /// `with_push` decides whether the account still has a phone attached —
    /// i.e. whether a recovery has anything to destroy.
    pub fn challenge_with(&self, challenge: &str, with_push: bool) -> Challenge {
        let mut authenticators = vec![Authenticator {
            id: self.authenticator_id,
            authenticator_type: AuthenticatorType::BackupCode,
            secret: self.recovery_secret(),
            secret_salt: None,
            public_keys: AuthenticatorPublicKeys::default(),
        }];
        if with_push {
            authenticators.push(Authenticator {
                id: Self::push_authenticator_id(),
                authenticator_type: AuthenticatorType::Push,
                secret: heyl_domain::AuthenticatorSecret::Opaque,
                secret_salt: None,
                public_keys: AuthenticatorPublicKeys::default(),
            });
        }
        Challenge {
            user_id: "test-user".to_owned(),
            challenge: challenge.to_owned(),
            authenticators,
        }
    }

    /// A challenge for an account with nothing left to disconnect.
    pub fn challenge(&self, challenge: &str) -> Challenge {
        self.challenge_with(challenge, false)
    }

    /// What `AuthenticatorService.List` would return: `secretSalt` and every
    /// published public key, derived so `doctor`'s comparison passes.
    pub fn authenticators(&self) -> Vec<Authenticator> {
        let keys = self.keys();
        let login = heyl_domain::login_signing_key(&self.seed).expect("derives");
        let identity = keys.identity_signing_key().verifying_key();

        vec![Authenticator {
            id: self.authenticator_id,
            authenticator_type: AuthenticatorType::BackupCode,
            secret: self.recovery_secret(),
            secret_salt: Some(Self::secret_salt()),
            public_keys: AuthenticatorPublicKeys {
                login_sig: Some(login.verifying_key()),
                high_security_identity_sig: Some(identity),
                storable_sig: Some(identity),
                ..AuthenticatorPublicKeys::default()
            },
        }]
    }

    fn profile_lock(&self) -> ProfileAuthenticatorLock {
        // Sealed to the authenticator's profile-seed encryption key, so the
        // round trip exercises the real unwrap rather than a hand-made blob.
        let to = EncryptionPrivateKey::derive(
            self.seed.expose_secret(),
            Some(Self::secret_salt().as_bytes()),
            heyl_crypto::context::AUTHENTICATOR_PROFILE_SEED_ENCRYPTION,
        )
        .expect("derives")
        .public_key();
        let ephemeral = EncryptionPrivateKey::from_bytes(&[0x33; 32]);

        ProfileAuthenticatorLock {
            authenticator_id: self.authenticator_id,
            profile_id: self.profile_id,
            profile_key_generation_id: Self::generation(),
            encrypted_storable_profile_seed: to.seal(
                &ephemeral,
                &Nonce::from_bytes([1; 24]),
                Self::storable_profile_seed().expose_secret(),
            ),
            encrypted_high_security_profile_seed: to.seal(
                &ephemeral,
                &Nonce::from_bytes([2; 24]),
                Self::high_profile_seed().expose_secret(),
            ),
        }
    }

    fn profile(&self) -> Profile {
        let storable = Self::storable_profile_seed();
        let high = Self::high_profile_seed();

        Profile {
            id: self.profile_id,
            key_generation_id: Self::generation(),
            authenticator_locks: vec![self.profile_lock()],
            public_keys: ProfilePublicKeys {
                storable_vault_key_enc: Some(
                    storable
                        .vault_key_encryption_key()
                        .expect("derives")
                        .public_key(),
                ),
                high_security_vault_key_enc: Some(
                    high.vault_key_encryption_key()
                        .expect("derives")
                        .public_key(),
                ),
                storable_sig: Some(
                    storable
                        .identity_signing_key()
                        .expect("derives")
                        .verifying_key(),
                ),
                high_security_identity_sig: Some(
                    high.identity_signing_key()
                        .expect("derives")
                        .verifying_key(),
                ),
                storable_profile_seed_enc: Some(
                    storable
                        .profile_key_encryption_key()
                        .expect("derives")
                        .public_key(),
                ),
                high_security_profile_seed_enc: Some(
                    high.profile_key_encryption_key()
                        .expect("derives")
                        .public_key(),
                ),
                ..ProfilePublicKeys::default()
            },
        }
    }

    fn vault_lock(&self) -> VaultProfileLock {
        let ephemeral = EncryptionPrivateKey::from_bytes(&[0x44; 32]);
        VaultProfileLock {
            locking_profile_id: self.profile_id,
            locking_profile_key_generation_id: Self::generation(),
            encrypted_storable_vault_key: Self::storable_profile_seed()
                .vault_key_encryption_key()
                .expect("derives")
                .public_key()
                .seal(
                    &ephemeral,
                    &Nonce::from_bytes([3; 24]),
                    self.vault_secret.expose_secret(),
                ),
            encrypted_high_security_vault_key: Self::high_profile_seed()
                .vault_key_encryption_key()
                .expect("derives")
                .public_key()
                .seal(&ephemeral, &Nonce::from_bytes([4; 24]), &[0x6b; 32]),
            encrypted_vault_message_private_key: None,
        }
    }

    /// The unlock grant: the seed, sealed to our session key (§6).
    fn session_unlock(&self) -> SessionUnlock {
        let ephemeral = EncryptionPrivateKey::from_bytes(&[0x55; 32]);
        SessionUnlock {
            encrypted_secret: self.session_key.public_key().seal(
                &ephemeral,
                &Nonce::from_bytes([5; 24]),
                self.seed.expose_secret(),
            ),
            authenticator_id: self.authenticator_id,
        }
    }

    /// What `Sync` would return.
    pub fn sync(&self, with_unlock: bool) -> SyncSnapshot {
        SyncSnapshot {
            server_time: Some(Timestamp::from_millisecond(1_757_376_000_000).expect("valid")),
            token_refresh_needed: false,
            client_outdated: false,
            session_unlock: with_unlock.then(|| self.session_unlock()),
            sessions: vec![Session {
                id: self.session_id,
                unlocked_until: Some(
                    Timestamp::from_millisecond(1_757_462_400_000).expect("valid"),
                ),
            }],
            vaults: vec![VaultSummary {
                id: self.vault_id,
                vault_type: VaultType::Private,
                generation_id: Self::generation(),
                commit_id: Some(CommitId::parse(&uuid(0xee, 1)).expect("valid")),
                profile_ids: vec![self.profile_id],
            }],
            profiles: vec![self.profile()],
        }
    }

    /// What `CreateTokens` would return.
    pub fn tokens(&self) -> Tokens {
        Tokens {
            access_token: "test-access-token".to_owned(),
            expires_at: None,
            session_id: self.session_id,
            sync: self.sync(true),
        }
    }

    /// What `ListCommits` would return, with the document encrypted under the
    /// vault secret exactly as a real commit is.
    pub fn commits(&self) -> HashMap<VaultId, VaultCommits> {
        let blob = self
            .vault_secret
            .encrypt(&Nonce::from_bytes([6; 24]), &self.document);

        HashMap::from([(
            self.vault_id,
            VaultCommits {
                current_generation_id: Self::generation(),
                commits: vec![Commit {
                    id: CommitId::parse(&uuid(0xee, 1)).expect("valid"),
                    blob,
                }],
                profile_lock: Some(self.vault_lock()),
            },
        )])
    }

    /// The key that verifies our login signature.
    pub fn login_verifier(&self) -> heyl_crypto::VerifyingKey {
        heyl_domain::login_signing_key(&self.seed)
            .expect("derives")
            .verifying_key()
    }
}
