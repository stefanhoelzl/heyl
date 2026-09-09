//! Wire → domain mapping.
//!
//! This module is the boundary. Below it nothing has ever seen a `prost` type;
//! above it nothing has ever seen a domain type. Every conversion is fallible
//! in the same direction: a field the schema says must be there and is not is
//! [`ApiError::MalformedResponse`], because that means our understanding and
//! heylogin's behaviour disagree — a bug to investigate, not a blip to retry.

use heyl_crypto::{EncryptionPublicKey, SecretSalt, Signature, VerifyingKey};
use heyl_domain::{
    Authenticator, AuthenticatorId, AuthenticatorPublicKeys, AuthenticatorSecret,
    AuthenticatorType, Challenge, Commit, CommitId, KeyGenerationId, Profile,
    ProfileAuthenticatorLock, ProfileId, ProfilePublicKeys, Session, SessionId, SessionUnlock,
    SyncSnapshot, Timestamp, Tokens, VaultId, VaultProfileLock, VaultSummary, VaultType,
};
use heyl_ports::ApiError;

fn missing(what: impl Into<String>) -> ApiError {
    ApiError::MalformedResponse { what: what.into() }
}

/// Parse a UUID field that the schema requires.
macro_rules! id {
    ($ty:ident, $value:expr, $what:expr) => {
        $ty::parse($value).map_err(|_| missing(format!("{} is not a UUID: {:?}", $what, $value)))
    };
}

/// An optional UUID field: empty string means absent, anything else must parse.
macro_rules! opt_id {
    ($ty:ident, $value:expr, $what:expr) => {
        if $value.is_empty() {
            Ok(None)
        } else {
            id!($ty, $value, $what).map(Some)
        }
    };
}

/// Empty `bytes` means "not published", which is normal before login.
fn opt_verifying_key(bytes: &[u8]) -> Option<VerifyingKey> {
    (!bytes.is_empty())
        .then(|| VerifyingKey::try_from_slice(bytes).ok())
        .flatten()
}

fn opt_encryption_key(bytes: &[u8]) -> Option<EncryptionPublicKey> {
    (!bytes.is_empty())
        .then(|| EncryptionPublicKey::try_from_slice(bytes).ok())
        .flatten()
}

fn opt_signature(bytes: &[u8]) -> Option<Signature> {
    (!bytes.is_empty())
        .then(|| Signature::try_from_slice(bytes).ok())
        .flatten()
}

fn timestamp(ts: &prost_types::Timestamp) -> Option<Timestamp> {
    let millis = i64::from(ts.nanos) / 1_000_000;
    Timestamp::from_millisecond(ts.seconds.checked_mul(1000)?.checked_add(millis)?).ok()
}

/// `domain.AuthenticatorType` → the domain enum. `reserved 5` means the
/// discriminants are not contiguous, so this is a match rather than a cast.
fn authenticator_type(value: i32) -> Option<AuthenticatorType> {
    match heyl_proto::AuthenticatorType::try_from(value).ok()? {
        heyl_proto::AuthenticatorType::Push => Some(AuthenticatorType::Push),
        heyl_proto::AuthenticatorType::BackupCode => Some(AuthenticatorType::BackupCode),
        heyl_proto::AuthenticatorType::BackupOs => Some(AuthenticatorType::BackupOs),
        heyl_proto::AuthenticatorType::Dummy => Some(AuthenticatorType::Dummy),
        heyl_proto::AuthenticatorType::SessionUnlock => Some(AuthenticatorType::SessionUnlock),
        heyl_proto::AuthenticatorType::Webauthn => Some(AuthenticatorType::Webauthn),
        heyl_proto::AuthenticatorType::OrganizationService => {
            Some(AuthenticatorType::OrganizationService)
        }
        heyl_proto::AuthenticatorType::Unknown => None,
    }
}

fn vault_type(value: i32) -> Option<VaultType> {
    match heyl_proto::VaultType::try_from(value).ok()? {
        heyl_proto::VaultType::Meta => Some(VaultType::Meta),
        heyl_proto::VaultType::Private => Some(VaultType::Private),
        heyl_proto::VaultType::Team => Some(VaultType::Team),
        heyl_proto::VaultType::TeamMeta => Some(VaultType::TeamMeta),
        heyl_proto::VaultType::Inbox => Some(VaultType::Inbox),
        heyl_proto::VaultType::InboxMeta => Some(VaultType::InboxMeta),
        heyl_proto::VaultType::OrganizationPersonal => Some(VaultType::OrganizationPersonal),
        heyl_proto::VaultType::OrganizationAdmin => Some(VaultType::OrganizationAdmin),
        heyl_proto::VaultType::OrganizationLoginSummary => {
            Some(VaultType::OrganizationLoginSummary)
        }
        heyl_proto::VaultType::Unknown => None,
    }
}

/// The domain's session type, on the wire.
#[must_use]
pub const fn session_type(value: heyl_domain::SessionType) -> heyl_proto::SessionType {
    match value {
        heyl_domain::SessionType::Unspecified => heyl_proto::SessionType::Unknown,
        heyl_domain::SessionType::SelfUnlockingPrimary => {
            heyl_proto::SessionType::SelfUnlockingPrimary
        }
        heyl_domain::SessionType::SelfUnlockingSecondary => {
            heyl_proto::SessionType::SelfUnlockingSecondary
        }
        heyl_domain::SessionType::BackupOs => heyl_proto::SessionType::BackupOs,
        heyl_domain::SessionType::BackupCode => heyl_proto::SessionType::BackupCode,
        heyl_domain::SessionType::Connected => heyl_proto::SessionType::Connected,
    }
}

/// A profile's lock on one authenticator.
///
/// `owner` is the profile the lock was *read out of*.
///
/// The wire message repeats `profile_id` and `profile_key_generation_id`
/// inside the lock, but the backend leaves them **empty** when the lock is
/// nested inside the `SyncUpdateProfile` that already identifies it — which is
/// every lock we see on the login path. So they are inherited from the owner
/// when absent, and only checked when the backend actually sends them: a lock
/// nested under the wrong profile would otherwise send us down the chain with
/// a mismatched key and surface as an opaque authentication failure.
/// # Errors
/// [`ApiError::MalformedResponse`] if an id is not a UUID, or if the nested
/// `profile_id` disagrees with the profile the lock arrived under.
pub fn profile_authenticator_lock(
    lock: &heyl_proto::ProfileAuthenticatorLock,
    owner: ProfileId,
    owner_generation: &KeyGenerationId,
) -> Result<ProfileAuthenticatorLock, ApiError> {
    let profile_id = match opt_id!(
        ProfileId,
        &lock.profile_id,
        "ProfileAuthenticatorLock.profile_id"
    )? {
        None => owner,
        Some(stated) if stated == owner => stated,
        Some(stated) => {
            return Err(missing(format!(
                "ProfileAuthenticatorLock.profile_id {stated} does not match the profile {owner} it was sent under"
            )));
        }
    };

    Ok(ProfileAuthenticatorLock {
        authenticator_id: id!(
            AuthenticatorId,
            &lock.authenticator_id,
            "ProfileAuthenticatorLock.authenticator_id"
        )?,
        profile_id,
        profile_key_generation_id: if lock.profile_key_generation_id.is_empty() {
            owner_generation.clone()
        } else {
            KeyGenerationId::new(&lock.profile_key_generation_id)
        },
        encrypted_storable_profile_seed: lock.encrypted_storable_profile_seed.clone(),
        encrypted_high_security_profile_seed: lock.encrypted_high_security_profile_seed.clone(),
    })
}

/// A vault's lock on one profile.
/// # Errors
/// [`ApiError::MalformedResponse`] if `locking_profile_id` is not a UUID.
pub fn vault_profile_lock(
    lock: &heyl_proto::VaultProfileLock,
) -> Result<VaultProfileLock, ApiError> {
    Ok(VaultProfileLock {
        locking_profile_id: id!(
            ProfileId,
            &lock.locking_profile_id,
            "VaultProfileLock.locking_profile_id"
        )?,
        locking_profile_key_generation_id: KeyGenerationId::new(
            &lock.locking_profile_key_generation_id,
        ),
        encrypted_storable_vault_key: lock.encrypted_storable_vault_key.clone(),
        encrypted_high_security_vault_key: lock.encrypted_high_security_vault_key.clone(),
        encrypted_vault_message_private_key: (!lock.encrypted_vault_message_private_key.is_empty())
            .then(|| lock.encrypted_vault_message_private_key.clone()),
    })
}

fn profile(p: &heyl_proto::SyncUpdateProfile) -> Result<Profile, ApiError> {
    let id = id!(ProfileId, &p.id, "SyncUpdateProfile.id")?;
    let generation = KeyGenerationId::new(&p.key_generation_id);
    Ok(Profile {
        id,
        key_generation_id: generation.clone(),
        authenticator_locks: p
            .authenticator_locks
            .iter()
            .map(|l| profile_authenticator_lock(l, id, &generation))
            .collect::<Result<_, _>>()?,
        public_keys: ProfilePublicKeys {
            high_security_identity_sig: opt_verifying_key(&p.high_security_identity_sig_pub_key),
            storable_sig: opt_verifying_key(&p.storable_sig_pub_key),
            high_security_vault_key_enc: opt_encryption_key(&p.high_security_vault_key_enc_pub_key),
            storable_vault_key_enc: opt_encryption_key(&p.storable_vault_key_enc_pub_key),
            high_security_profile_seed_enc: opt_encryption_key(
                &p.high_security_profile_seed_enc_pub_key,
            ),
            storable_profile_seed_enc: opt_encryption_key(&p.storable_profile_seed_enc_pub_key),
            high_security_vault_key_enc_signature: opt_signature(
                &p.high_security_vault_key_enc_pub_key_signature,
            ),
            storable_vault_key_enc_signature: opt_signature(
                &p.storable_vault_key_enc_pub_key_signature,
            ),
            high_security_profile_seed_enc_signature: opt_signature(
                &p.high_security_profile_seed_enc_pub_key_signature,
            ),
            storable_profile_seed_enc_signature: opt_signature(
                &p.storable_profile_seed_enc_pub_key_signature,
            ),
            storable_sig_signature: opt_signature(&p.storable_sig_pub_key_signature),
        },
    })
}

fn vault(v: &heyl_proto::sync_update::Vault) -> Result<Option<VaultSummary>, ApiError> {
    // A vault whose type we cannot even name is dropped rather than guessed at:
    // `doctor` reports what it was given, and an unknown discriminant means the
    // schema moved under us.
    let Some(vault_type) = vault_type(v.vault_type) else {
        return Ok(None);
    };
    Ok(Some(VaultSummary {
        id: id!(VaultId, &v.id, "SyncUpdate.Vault.id")?,
        vault_type,
        generation_id: KeyGenerationId::new(&v.generation_id),
        commit_id: opt_id!(CommitId, &v.commit_id, "SyncUpdate.Vault.commit_id")?,
        profile_ids: v
            .profiles
            .iter()
            .map(|p| id!(ProfileId, &p.id, "SyncUpdate.Vault.Profile.id"))
            .collect::<Result<_, _>>()?,
    }))
}

fn session(s: &heyl_proto::sync_update::Session) -> Result<Session, ApiError> {
    Ok(Session {
        id: id!(SessionId, &s.id, "SyncUpdate.Session.id")?,
        unlocked_until: s.unlocked_until.as_ref().and_then(timestamp),
    })
}

/// `SyncUpdate` → [`SyncSnapshot`].
/// # Errors
/// [`ApiError::MalformedResponse`] if any required id is not a UUID.
pub fn sync_update(u: &heyl_proto::SyncUpdate) -> Result<SyncSnapshot, ApiError> {
    Ok(SyncSnapshot {
        server_time: u.server_time.as_ref().and_then(timestamp),
        token_refresh_needed: u.token_refresh_needed,
        client_outdated: u.client_outdated,
        session_unlock: u
            .session_unlock
            .as_ref()
            .map(|s| {
                Ok::<_, ApiError>(SessionUnlock {
                    encrypted_secret: s.encrypted_secret.clone(),
                    authenticator_id: id!(
                        AuthenticatorId,
                        &s.authenticator_id,
                        "SyncUpdate.SessionUnlock.authenticator_id"
                    )?,
                })
            })
            .transpose()?,
        sessions: u.sessions.iter().map(session).collect::<Result<_, _>>()?,
        vaults: u
            .vaults
            .iter()
            .filter_map(|v| vault(v).transpose())
            .collect::<Result<_, _>>()?,
        profiles: u.profiles.iter().map(profile).collect::<Result<_, _>>()?,
    })
}

/// `CreateChallengeResponse` → [`Challenge`].
///
/// Authenticators of a type we cannot name are dropped: `SESSION_UNLOCK` and
/// friends appear in listings and must not fail the whole response (§4).
/// # Errors
/// [`ApiError::MalformedResponse`] if an id is not a UUID, or a `secretInfo`
/// we do model cannot be read.
pub fn challenge(r: &heyl_proto::CreateChallengeResponse) -> Result<Challenge, ApiError> {
    let authenticators = r
        .authenticators
        .iter()
        .filter_map(|a| {
            let kind = authenticator_type(a.authenticator_type)?;
            Some((|| {
                Ok::<_, ApiError>(Authenticator {
                    id: id!(
                        AuthenticatorId,
                        &a.id,
                        "CreateChallengeResponse.Authenticator.id"
                    )?,
                    authenticator_type: kind,
                    secret: AuthenticatorSecret::parse(kind, &a.secret_info)
                        .map_err(|e| missing(e.to_string()))?,
                    // CreateChallenge runs before login, so no secretSalt and
                    // no public keys are revealed here.
                    secret_salt: None,
                    public_keys: AuthenticatorPublicKeys::default(),
                })
            })())
        })
        .collect::<Result<_, _>>()?;

    Ok(Challenge {
        user_id: r.user_id.clone(),
        challenge: r.challenge.clone(),
        authenticators,
    })
}

/// `Authenticator` (from `AuthenticatorService.List`) → the domain type.
///
/// This is the only call that reveals `secretSalt`, and the only source of the
/// published public keys `doctor` compares against.
/// # Errors
/// [`ApiError::MalformedResponse`] if `data` is absent, an id is not a UUID,
/// or `secret_salt` is not 32 bytes.
pub fn authenticator(a: &heyl_proto::Authenticator) -> Result<Option<Authenticator>, ApiError> {
    let data = a
        .data
        .as_ref()
        .ok_or_else(|| missing("Authenticator.data"))?;
    let Some(kind) = authenticator_type(data.authenticator_type) else {
        return Ok(None);
    };

    Ok(Some(Authenticator {
        id: id!(AuthenticatorId, &a.id, "Authenticator.id")?,
        authenticator_type: kind,
        secret: AuthenticatorSecret::parse(kind, &data.secret_info)
            .map_err(|e| missing(e.to_string()))?,
        secret_salt: (!data.secret_salt.is_empty())
            .then(|| SecretSalt::try_from_slice(&data.secret_salt))
            .transpose()
            .map_err(|_| missing("Authenticator.secret_salt is not 32 bytes"))?,
        public_keys: AuthenticatorPublicKeys {
            login_sig: opt_verifying_key(&data.high_security_login_sig_pub_key),
            high_security_identity_sig: opt_verifying_key(&data.high_security_identity_sig_pub_key),
            storable_sig: opt_verifying_key(&data.storable_sig_pub_key),
            high_security_profile_seed_enc: opt_encryption_key(
                &data.high_security_profile_seed_enc_pub_key,
            ),
            storable_profile_seed_enc: opt_encryption_key(&data.storable_profile_seed_enc_pub_key),
            high_security_profile_seed_enc_signature: opt_signature(
                &data.high_security_profile_seed_enc_pub_key_signature,
            ),
            storable_profile_seed_enc_signature: opt_signature(
                &data.storable_profile_seed_enc_pub_key_signature,
            ),
            storable_sig_signature: opt_signature(&data.storable_sig_pub_key_signature),
        },
    }))
}

/// `CreateTokensResponse` → [`Tokens`].
/// # Errors
/// [`ApiError::MalformedResponse`] if `access_token` or `session_id` is absent
/// or malformed.
pub fn tokens(r: &heyl_proto::CreateTokensResponse) -> Result<Tokens, ApiError> {
    let token = r
        .access_token
        .as_ref()
        .ok_or_else(|| missing("CreateTokensResponse.access_token"))?;
    Ok(Tokens {
        access_token: token.token.clone(),
        expires_at: token.expires_at.as_ref().and_then(timestamp),
        session_id: id!(SessionId, &r.session_id, "CreateTokensResponse.session_id")?,
        sync: r
            .sync_update
            .as_ref()
            .map(sync_update)
            .transpose()?
            .unwrap_or_default(),
    })
}

/// `ListCommitsResponse` → [`heyl_domain::VaultCommits`].
/// # Errors
/// [`ApiError::MalformedResponse`] if a commit id is not a UUID.
pub fn vault_commits(
    r: &heyl_proto::ListCommitsResponse,
) -> Result<heyl_domain::VaultCommits, ApiError> {
    Ok(heyl_domain::VaultCommits {
        current_generation_id: KeyGenerationId::new(&r.current_generation_id),
        commits: r
            .newer_commits
            .iter()
            .map(|c| {
                Ok::<_, ApiError>(Commit {
                    id: id!(CommitId, &c.id, "ListCommitsResponse.Commit.id")?,
                    blob: c.blob.clone(),
                })
            })
            .collect::<Result<_, _>>()?,
        profile_lock: r
            .profile_lock
            .as_ref()
            .map(vault_profile_lock)
            .transpose()?,
    })
}
