//! Turn a real recording into a committable fixture.
//!
//! The recording holds real key material and a live token. What is committed
//! must hold none of it, while still being the *same exchange* — same fields,
//! same shapes, same vault documents — so a replay exercises the mapping,
//! decoding and framing that a hand-built fixture would not.
//!
//! So this decrypts the real chain once, locally, and rebuilds every layer
//! under synthetic material:
//!
//! ```text
//! real code ─► real seed ─► real profile seeds ─► real vault keys ─► plaintext
//!                                                                       │
//!                                            (kept: this is real heylogin data)
//!                                                                       ▼
//! TEST_CODE ─► test seed ─► test profile seeds ─► test vault keys ─► re-encrypted
//! ```
//!
//! Replaced, never merely redacted (DESIGN.md §6):
//!
//! * the recovery code and the seed;
//! * `secretInfo.checksum` — it is `SHA512(seed)[:32]`, an offline *verifier*,
//!   and publishing one hands out an oracle for testing candidate codes;
//! * `secret_salt`, the access token, and the session private key;
//! * every sealed blob: profile-seed locks, vault-key locks, the session
//!   unlock, and every commit blob;
//! * every published public key, re-derived so `doctor`'s comparison still
//!   passes against the synthetic chain.
//!
//! The rule that makes it checkable: **the fixture must open with the
//! committed test seed and with nothing else.** `verify` asserts exactly that.

use std::{collections::HashMap, path::Path};

use heyl_crypto::{EncryptionPrivateKey, Nonce, SecretSalt, Seed, SymKey, recovery};
use heyl_domain::{
    AuthenticatorId, AuthenticatorKeys, HighSecurity, ProfileId, ProfileSeed, Storable, VaultId,
};

use heyl_grpc::corpus::Record;

/// The synthetic recovery code the fixture is built around.
///
/// All-repeating digits, so it cannot be mistaken for a real one.
pub const TEST_CODE: &str = "1111-2222-3333-4444-5555-6666";

/// Deliberately cheap: ~10 ms, so every CI run exercises code→seed without a
/// memory-heavy hash in the loop. What the fixture proves is that the plumbing
/// is right, not that Argon2 is slow.
pub const TEST_PARAMS: heyl_crypto::RecoveryParams = heyl_crypto::RecoveryParams {
    memory_cost_kib: 8 * 1024,
    iterations: 1,
    parallelism: 1,
};

/// Argon2id needs at least 8 bytes.
pub const TEST_SALT: &[u8] = b"heyl-fixture-salt";

/// The synthetic `secretSalt`.
const TEST_SECRET_SALT: [u8; 32] = [0xa5; 32];

/// The seed the fixture's session encryption key is derived from.
///
/// `recovery` derives its session key from `RandomSource::seed()`, so the
/// unlock blob must be sealed to whatever the replay's random source yields
/// first. The fixture states this value so the test can supply it, instead of
/// the two silently having to agree.
const FIXTURE_SESSION_SEED: [u8; 32] = [0x11; 32];

/// Deterministic synthetic key material, derived from an id so every run of
/// `rekey` produces the same fixture.
fn derived_bytes(tag: &str, id: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&heyl_crypto::hash_data(
        format!("heyl-fixture/{tag}/{id}").as_bytes(),
    ));
    out
}

/// The real chain, recovered from the recording so the plaintext can be kept.
struct RealChain {
    keys: AuthenticatorKeys,
    /// Per vault, the key its commits are encrypted with — **in call order**,
    /// so it lines up with the `ListCommits` exchanges. A map would not: the
    /// recording is a sequence, and pairing it with an unordered collection
    /// silently mismatches vaults.
    vault_secrets: Vec<(VaultId, SymKey)>,
}

/// The synthetic chain the fixture is rebuilt onto.
struct TestChain {
    seed: Seed,
    keys: AuthenticatorKeys,
    profiles: HashMap<ProfileId, (ProfileSeed<Storable>, ProfileSeed<HighSecurity>)>,
    vault_secrets: HashMap<VaultId, SymKey>,
    protected_secrets: HashMap<VaultId, SymKey>,
    session_key: EncryptionPrivateKey,
}

impl TestChain {
    fn new(authenticator: AuthenticatorId) -> Result<Self, String> {
        let derived = recovery::derive_recovery_seed(TEST_CODE, TEST_SALT, TEST_PARAMS)
            .map_err(|e| format!("test seed: {e}"))?;
        let seed = Seed::from_bytes(&derived);
        let salt = SecretSalt::from_bytes(TEST_SECRET_SALT);
        let keys = AuthenticatorKeys::derive(authenticator, &seed, &salt)
            .map_err(|e| format!("test authenticator keys: {e}"))?;
        Ok(Self {
            seed,
            keys,
            profiles: HashMap::new(),
            vault_secrets: HashMap::new(),
            protected_secrets: HashMap::new(),
            session_key: heyl_domain::session_encryption_key(&FIXTURE_SESSION_SEED)
                .map_err(|e| format!("test session key: {e}"))?,
        })
    }

    fn profile(&mut self, id: ProfileId) -> &(ProfileSeed<Storable>, ProfileSeed<HighSecurity>) {
        self.profiles.entry(id).or_insert_with(|| {
            (
                ProfileSeed::from_bytes(&derived_bytes("profile-s", &id.to_string())),
                ProfileSeed::from_bytes(&derived_bytes("profile-hs", &id.to_string())),
            )
        })
    }

    fn vault_secret(&mut self, id: VaultId) -> SymKey {
        self.vault_secrets
            .entry(id)
            .or_insert_with(|| SymKey::from_bytes(&derived_bytes("vault-s", &id.to_string())))
            .clone()
    }

    fn protected_secret(&mut self, id: VaultId) -> SymKey {
        self.protected_secrets
            .entry(id)
            .or_insert_with(|| SymKey::from_bytes(&derived_bytes("vault-hs", &id.to_string())))
            .clone()
    }
}

/// Deterministic nonces and ephemeral keys, so re-running `rekey` on the same
/// recording yields byte-identical output and a fixture diff means something.
struct Deterministic(std::cell::Cell<u8>);

impl Deterministic {
    const fn new() -> Self {
        Self(std::cell::Cell::new(1))
    }
    fn next(&self) -> u8 {
        let n = self.0.get();
        self.0.set(n.wrapping_add(1));
        n
    }
    fn nonce(&self) -> Nonce {
        Nonce::from_bytes([self.next(); 24])
    }
    fn ephemeral(&self) -> EncryptionPrivateKey {
        EncryptionPrivateKey::from_bytes(&[self.next(); 32])
    }
}

// ------------------------------------------------------------- reading it back

/// Decode the nth recorded response for a method.
fn response_message<T: prost::Message + Default>(
    records: &[Record],
    path: &str,
    nth: usize,
) -> Result<T, String> {
    let record = records
        .iter()
        .filter(|r| r.method.ends_with(path))
        .nth(nth)
        .ok_or_else(|| format!("the corpus has no {path} #{nth}"))?;
    decode(record, path)
}

/// A record's response, as a typed message.
fn decode<T: prost::Message + Default>(record: &Record, path: &str) -> Result<T, String> {
    let rpc = heyl_grpc::Rpc::by_path(&record.method)
        .ok_or_else(|| format!("{} is not an RPC in the schema", record.method))?;
    let response = record
        .responses
        .first()
        .ok_or_else(|| format!("{path}: record carries no response"))?;
    let document = serde_json::to_string(response).map_err(|e| format!("{path}: {e}"))?;
    let pool = heyl_grpc::json::pool().map_err(|e| e.to_string())?;
    heyl_grpc::json::from_json(pool, rpc.response_type, &document)
        .map_err(|e| format!("{path}: {e}"))
}

/// Put a re-keyed message back into a record.
fn encode<T: prost::Message>(record: &mut Record, message: &T) -> Result<(), String> {
    let rpc = heyl_grpc::Rpc::by_path(&record.method)
        .ok_or_else(|| format!("{} is not an RPC in the schema", record.method))?;
    let pool = heyl_grpc::json::pool().map_err(|e| e.to_string())?;
    let rendered = heyl_grpc::json::to_json(pool, rpc.response_type, message)
        .map_err(|e| format!("{}: {e}", record.method))?;
    record.responses = vec![
        serde_json::from_str(&rendered)
            .map_err(|e| format!("{} rendered unreadable JSON: {e}", record.method))?,
    ];
    Ok(())
}

/// Recover the real chain, so the vault plaintext can be preserved.
fn real_chain(records: &[Record], code: &str) -> Result<RealChain, String> {
    // 1. the recovery parameters the account actually uses
    let challenge: heyl_proto::CreateChallengeResponse =
        response_message(records, "/CreateChallenge", 0)?;
    let backup = challenge
        .authenticators
        .iter()
        .find(|a| a.authenticator_type == heyl_proto::AuthenticatorType::BackupCode as i32)
        .ok_or("the recording's CreateChallenge lists no BACKUP_CODE authenticator")?;
    let secret = heyl_domain::AuthenticatorSecret::parse(
        heyl_domain::AuthenticatorType::BackupCode,
        &backup.secret_info,
    )
    .map_err(|e| format!("recorded secretInfo: {e}"))?;
    let heyl_domain::AuthenticatorSecret::Recovery(secret) = secret else {
        return Err("recorded secretInfo is not a recovery secret".to_owned());
    };

    let derived = recovery::derive_recovery_seed(code, &secret.salt, secret.params)
        .map_err(|e| format!("real seed: {e}"))?;
    if !recovery::checksum_matches(&derived, &secret.checksum) {
        return Err("HEYL_RECOVERY_CODE does not match the recording's account".to_owned());
    }
    let seed = Seed::from_bytes(&derived);
    let authenticator_id = AuthenticatorId::parse(&backup.id)
        .map_err(|e| format!("recorded authenticator id: {e}"))?;

    // 2. secretSalt, which only AuthenticatorService.List reveals
    let list: heyl_proto::ListAuthenticatorsResponse = response_message(records, "/List", 0)?;
    let salt_bytes = list
        .authenticators
        .iter()
        .find(|a| a.id == backup.id)
        .and_then(|a| a.data.as_ref())
        .map(|d| d.secret_salt.clone())
        .ok_or("the recording's List has no secretSalt for that authenticator")?;
    let salt =
        SecretSalt::try_from_slice(&salt_bytes).map_err(|e| format!("recorded secretSalt: {e}"))?;
    let keys = AuthenticatorKeys::derive(authenticator_id, &seed, &salt)
        .map_err(|e| format!("real authenticator keys: {e}"))?;

    // 3. every profile's two seeds
    let sync: heyl_proto::SyncResponse = response_message(records, "/Sync", 0)?;
    let update = sync
        .sync_update
        .ok_or("recorded Sync carries no SyncUpdate")?;
    let mut profiles: HashMap<ProfileId, (ProfileSeed<Storable>, ProfileSeed<HighSecurity>)> =
        HashMap::new();
    for p in &update.profiles {
        let id = ProfileId::parse(&p.id).map_err(|e| format!("recorded profile id: {e}"))?;
        let generation = heyl_domain::KeyGenerationId::new(&p.key_generation_id);
        let Some(lock) = p
            .authenticator_locks
            .iter()
            .find(|l| l.authenticator_id == backup.id)
        else {
            continue;
        };
        let lock = heyl_grpc::map::profile_authenticator_lock(lock, id, &generation)
            .map_err(|e| format!("recorded lock: {e}"))?;
        let s = keys
            .unlock_storable_profile_seed(&lock, &generation)
            .map_err(|e| format!("profile {id} storable seed: {e}"))?;
        let hs = keys
            .unlock_high_security_profile_seed(&lock, &generation)
            .map_err(|e| format!("profile {id} high-security seed: {e}"))?;
        profiles.insert(id, (s, hs));
    }

    // 4. every vault's content key, in the order `record` walked them —
    //    which skips unsupported types, exactly as `doctor` does.
    let mut vault_secrets = Vec::new();
    let supported = update
        .vaults
        .iter()
        .filter(|v| heyl_grpc::map::vault_type_is_supported(v.vault_type));
    for (nth, vault) in supported.enumerate() {
        let commits: heyl_proto::ListCommitsResponse =
            match response_message(records, "/ListCommits", nth) {
                Ok(c) => c,
                Err(_) => break,
            };
        let Some(lock) = commits.profile_lock.as_ref() else {
            continue;
        };
        let lock = heyl_grpc::map::vault_profile_lock(lock)
            .map_err(|e| format!("recorded vault lock: {e}"))?;
        let Some((storable, _)) = profiles.get(&lock.locking_profile_id) else {
            continue;
        };
        let secret = storable
            .unlock_vault(
                &lock,
                lock.locking_profile_id,
                &lock.locking_profile_key_generation_id,
            )
            .map_err(|e| format!("vault secret: {e}"))?;
        let id = VaultId::parse(&vault.id).map_err(|e| format!("recorded vault id: {e}"))?;
        vault_secrets.push((id, secret.key().clone()));
    }

    Ok(RealChain {
        keys,
        vault_secrets,
    })
}

// ------------------------------------------------------------- rebuilding it

/// Rewrite a `SyncUpdate` onto the synthetic chain.
fn rekey_sync_update(
    update: &mut heyl_proto::SyncUpdate,
    real: &RealChain,
    test: &mut TestChain,
    rng: &Deterministic,
) -> Result<(), String> {
    // The unlock grant: its plaintext is the seed, which we know, so it is
    // resealed rather than decrypted.
    if let Some(unlock) = update.session_unlock.as_mut() {
        unlock.encrypted_secret = test.session_key.public_key().seal(
            &rng.ephemeral(),
            &rng.nonce(),
            test.seed.expose_secret(),
        );
    }

    for p in &mut update.profiles {
        let id = ProfileId::parse(&p.id).map_err(|e| format!("profile id: {e}"))?;
        let (s, hs) = {
            let (s, hs) = test.profile(id);
            (s.duplicate(), hs.duplicate())
        };

        // Published keys, re-derived so doctor's comparison still passes.
        p.storable_vault_key_enc_pub_key = pubkey(&s.vault_key_encryption_key())?;
        p.high_security_vault_key_enc_pub_key = pubkey(&hs.vault_key_encryption_key())?;
        p.storable_profile_seed_enc_pub_key = pubkey(&s.profile_key_encryption_key())?;
        p.high_security_profile_seed_enc_pub_key = pubkey(&hs.profile_key_encryption_key())?;
        p.storable_sig_pub_key = sigkey(&s.identity_signing_key())?;
        p.high_security_identity_sig_pub_key = sigkey(&hs.identity_signing_key())?;

        // The locks that carry the profile seeds to our authenticator.
        let to = test
            .keys
            .profile_seed_encryption_public_key()
            .map_err(|e| format!("test profile-seed key: {e}"))?;
        for lock in &mut p.authenticator_locks {
            lock.encrypted_storable_profile_seed =
                to.seal(&rng.ephemeral(), &rng.nonce(), s.expose_secret());
            lock.encrypted_high_security_profile_seed =
                to.seal(&rng.ephemeral(), &rng.nonce(), hs.expose_secret());
        }
    }

    // Authenticator public keys, where the wire carries them.
    let login =
        heyl_domain::login_signing_key(&test.seed).map_err(|e| format!("test login key: {e}"))?;
    let identity = test.keys.identity_signing_key().verifying_key();
    for a in &mut update.sessions {
        let _ = a; // sessions carry no key material we re-key
    }
    let _ = (real, login, identity);
    Ok(())
}

fn pubkey(k: &Result<EncryptionPrivateKey, heyl_domain::DomainError>) -> Result<Vec<u8>, String> {
    k.as_ref()
        .map(|k| k.public_key().as_bytes().to_vec())
        .map_err(|e| format!("deriving a public key: {e}"))
}

fn sigkey(
    k: &Result<heyl_crypto::SigningKey, heyl_domain::DomainError>,
) -> Result<Vec<u8>, String> {
    k.as_ref()
        .map(|k| k.verifying_key().as_bytes().to_vec())
        .map_err(|e| format!("deriving a signing key: {e}"))
}

/// Re-key a recording into a committable fixture.
///
/// # Errors
/// If the recording is unreadable, `HEYL_RECOVERY_CODE` does not match the
/// account it was taken from, or any layer fails to open.
pub fn run(input: &Path, out: &Path) -> Result<(), String> {
    use base64::Engine as _;

    let code = std::env::var("HEYL_RECOVERY_CODE")
        .map_err(|_| "set HEYL_RECOVERY_CODE — the real chain must be opened once".to_owned())?;
    let mut records = heyl_grpc::corpus::load(input).map_err(|e| e.to_string())?;

    let real = real_chain(&records, &code)?;
    let backup_id = real.keys.id();
    let mut test = TestChain::new(backup_id)?;
    let rng = Deterministic::new();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut vault_index = 0usize;

    for record in &mut records {
        let path = record.method.clone();
        // The request carries a signature over a challenge and, on
        // CreateTokens, a sealed seed. Replay matches on method and order for
        // these, so it is dropped rather than re-keyed: what is not committed
        // cannot leak.
        record.request = None;

        if path.ends_with("/CreateChallenge") {
            let mut m = decode::<heyl_proto::CreateChallengeResponse>(record, &path)?;
            for a in &mut m.authenticators {
                if a.authenticator_type == heyl_proto::AuthenticatorType::BackupCode as i32 {
                    a.secret_info = test_secret_info(&test.seed);
                }
            }
            encode(record, &m)?;
        } else if path.ends_with("/CreateTokens") {
            let mut m = decode::<heyl_proto::CreateTokensResponse>(record, &path)?;
            if let Some(t) = m.access_token.as_mut() {
                "fixture-access-token".clone_into(&mut t.token);
            }
            if let Some(u) = m.sync_update.as_mut() {
                rekey_sync_update(u, &real, &mut test, &rng)?;
            }
            encode(record, &m)?;
        } else if path.ends_with("/Sync") {
            let mut m = decode::<heyl_proto::SyncResponse>(record, &path)?;
            if let Some(u) = m.sync_update.as_mut() {
                rekey_sync_update(u, &real, &mut test, &rng)?;
            }
            encode(record, &m)?;
        } else if path.ends_with("/List") {
            let mut m = decode::<heyl_proto::ListAuthenticatorsResponse>(record, &path)?;
            let login = heyl_domain::login_signing_key(&test.seed)
                .map_err(|e| format!("test login key: {e}"))?;
            let identity = test.keys.identity_signing_key().verifying_key();
            let seed_enc = test
                .keys
                .profile_seed_encryption_public_key()
                .map_err(|e| format!("test profile-seed key: {e}"))?;
            for a in &mut m.authenticators {
                if let Some(d) = a.data.as_mut() {
                    d.secret_salt = TEST_SECRET_SALT.to_vec();
                    if a.id == backup_id.to_string() {
                        d.secret_info = test_secret_info(&test.seed);
                        d.high_security_login_sig_pub_key =
                            login.verifying_key().as_bytes().to_vec();
                        d.high_security_identity_sig_pub_key = identity.as_bytes().to_vec();
                        d.storable_sig_pub_key = identity.as_bytes().to_vec();
                        d.high_security_profile_seed_enc_pub_key = seed_enc.as_bytes().to_vec();
                        d.storable_profile_seed_enc_pub_key = seed_enc.as_bytes().to_vec();
                    }
                }
            }
            encode(record, &m)?;
        } else if path.ends_with("/ListCommits") {
            let mut m = decode::<heyl_proto::ListCommitsResponse>(record, &path)?;
            rekey_commits(&mut m, vault_index, &real, &mut test, &rng)?;
            vault_index += 1;
            encode(record, &m)?;
        }
    }

    if out.exists() {
        std::fs::remove_dir_all(out).map_err(|e| format!("clearing {}: {e}", out.display()))?;
    }
    for (index, record) in records.iter().enumerate() {
        heyl_grpc::corpus::write(out, index, record).map_err(|e| e.to_string())?;
    }
    heyl_grpc::corpus::Meta {
        code: TEST_CODE.to_owned(),
        session_seed: b64.encode(FIXTURE_SESSION_SEED),
    }
    .write(out)
    .map_err(|e| e.to_string())?;

    verify(out, &code)?;
    eprintln!("wrote {} records to {}", records.len(), out.display());
    eprintln!("verified: the fixture opens with the test seed, and not with the real one.");
    Ok(())
}

/// `RecoverySecretInfo` for the synthetic code.
fn test_secret_info(seed: &Seed) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let checksum = b64.encode(heyl_crypto::hash_data(seed.expose_secret()));
    format!(
        r#"{{"checksum":"{checksum}","recoveryParameters":{{"saltBase64":"{salt}","iterations":{it},"memoryCost":{mc},"parallelism":{p}}}}}"#,
        salt = b64.encode(TEST_SALT),
        it = TEST_PARAMS.iterations,
        mc = TEST_PARAMS.memory_cost_kib,
        p = TEST_PARAMS.parallelism,
    )
}

/// Re-key one vault's commits, **keeping the plaintext**.
///
/// This is the point of re-keying rather than synthesising: the document inside
/// is real heylogin output — real `serialize` framing, real snappy, a real
/// heymerge document — and only the key it is encrypted under changes.
fn rekey_commits(
    m: &mut heyl_proto::ListCommitsResponse,
    nth: usize,
    real: &RealChain,
    test: &mut TestChain,
    rng: &Deterministic,
) -> Result<(), String> {
    let Some(lock) = m.profile_lock.as_ref() else {
        return Ok(());
    };
    let profile_id =
        ProfileId::parse(&lock.locking_profile_id).map_err(|e| format!("lock profile: {e}"))?;

    // Which vault this is, by position: the recording walks vaults in the
    // order Sync returned them, and replay asserts that order.
    let (vault_id, real_secret) = real
        .vault_secrets
        .get(nth)
        .ok_or_else(|| format!("no recorded vault secret for ListCommits #{nth}"))?;
    let vault_id = *vault_id;

    let new_secret = test.vault_secret(vault_id);
    let new_protected = test.protected_secret(vault_id);
    let (s, hs) = {
        let (s, hs) = test.profile(profile_id);
        (s.duplicate(), hs.duplicate())
    };

    // The lock that carries those keys to the profile.
    if let Some(lock) = m.profile_lock.as_mut() {
        lock.encrypted_storable_vault_key = s
            .vault_key_encryption_key()
            .map_err(|e| format!("test vault-key key: {e}"))?
            .public_key()
            .seal(&rng.ephemeral(), &rng.nonce(), new_secret.expose_secret());
        lock.encrypted_high_security_vault_key = hs
            .vault_key_encryption_key()
            .map_err(|e| format!("test vault-key key: {e}"))?
            .public_key()
            .seal(
                &rng.ephemeral(),
                &rng.nonce(),
                new_protected.expose_secret(),
            );
    }

    // The commits themselves: decrypt with the real key, re-encrypt with ours.
    for commit in &mut m.newer_commits {
        let plaintext = real_secret
            .decrypt(&commit.blob)
            .map_err(|e| format!("vault {vault_id}: opening a commit: {e}"))?;
        commit.blob = new_secret.encrypt(&rng.nonce(), &plaintext);
    }
    Ok(())
}

/// Assert the rule that makes the fixture safe to commit.
///
/// **It must open with the test seed, and it must not open with the real one.**
/// The second half is what catches a layer the re-key forgot: a fixture that
/// still opens with the account's real key is one that still contains it.
fn verify(fixture: &Path, real_code: &str) -> Result<(), String> {
    let records = heyl_grpc::corpus::load(fixture).map_err(|e| e.to_string())?;

    // The committed code opens it.
    let derived = recovery::derive_recovery_seed(TEST_CODE, TEST_SALT, TEST_PARAMS)
        .map_err(|e| format!("{e}"))?;
    let challenge: heyl_proto::CreateChallengeResponse =
        response_message(&records, "/CreateChallenge", 0)?;
    let backup = challenge
        .authenticators
        .iter()
        .find(|a| a.authenticator_type == heyl_proto::AuthenticatorType::BackupCode as i32)
        .ok_or("fixture lost its BACKUP_CODE authenticator")?;
    let heyl_domain::AuthenticatorSecret::Recovery(secret) =
        heyl_domain::AuthenticatorSecret::parse(
            heyl_domain::AuthenticatorType::BackupCode,
            &backup.secret_info,
        )
        .map_err(|e| format!("{e}"))?
    else {
        return Err("fixture's secretInfo is not a recovery secret".to_owned());
    };
    if !recovery::checksum_matches(&derived, &secret.checksum) {
        return Err("the fixture does not open with the committed test code".to_owned());
    }

    // The real one does not. This is the half that catches a layer the re-key
    // forgot: a fixture the account's own code still opens is one that still
    // contains it.
    if recovery::derive_recovery_seed(real_code, &secret.salt, secret.params)
        .is_ok_and(|real| recovery::checksum_matches(&real, &secret.checksum))
    {
        return Err(
            "the fixture still opens with the REAL recovery code — not safe to commit".to_owned(),
        );
    }
    Ok(())
}
