//! Creating, unlocking, locking and removing a session.

use heyl_crypto::Seed;
use heyl_domain::{AuthenticatorKeys, SessionId, SessionPolicy, Timestamp};
use heyl_ports::{QrStyle, StoredSecret};

use super::{
    SESSION_TYPE, Slot, adopt, exists, forget, index_add, index_remove, metadata, pair_url,
    respond, self_grant, show_pairing, write_policy,
};
use crate::{AppError, Ports, meta_vault, unlock::Unlocked};

/// What `CreateLongPollChannelChallenge` is keyed by: the base64 of a SHA-512
/// truncated to 32 bytes, over the public key the QR carries.
fn pairing_hash(public: &heyl_crypto::EncryptionPublicKey) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(heyl_crypto::hash_data(public.as_bytes()))
}

/// What a `session create` ended up with.
pub struct Created {
    /// The session the backend minted.
    pub session_id: SessionId,
    /// The name the phone will show, after disambiguation.
    pub display: String,
    /// When the self-granted unlock lapses, if one was asked for.
    pub unlocked_until: Option<Timestamp>,
}

/// What a `session remove` managed to do.
pub struct Removed {
    /// Whether the vault entry was tombstoned, so the app stops listing it.
    pub tombstoned: bool,
    /// Whether the backend session was deleted.
    pub deleted: bool,
}

/// Pair a new session, register it, and store its credentials.
///
/// One QR scan per session, deliberately: minting a session from another one's
/// unlock is possible, but this way every session's seed comes straight from
/// the phone and no session can conjure another.
///
/// The seed lives in memory for this function and is dropped at the end of it.
///
/// `announce` is handed the pairing URL the moment it exists — before the
/// long-poll blocks on a person. It is a callback rather than a return value
/// because the URL is only useful *during* the call: a caller rendering
/// documents prints one for it there and then, so a wrapper can draw its own
/// code or open the link while this function is still waiting for the swipe.
///
/// # Errors
/// [`AppError::SlotExists`] if the slot is taken, or any failure pairing,
/// registering or storing.
pub async fn create(
    ports: &Ports<'_>,
    slot: &Slot,
    display: Option<&str>,
    policy: SessionPolicy,
    unlock_now: bool,
    style: QrStyle,
    announce: &dyn Fn(&str),
) -> Result<Created, AppError> {
    if exists(ports, slot).await {
        return Err(AppError::SlotExists {
            slot: slot.name().to_owned(),
        });
    }

    // The pairing keypair is ephemeral and unsigned: the phone seals the seed
    // to its public half, and nothing else ever sees it.
    let pairing_key = heyl_crypto::EncryptionPrivateKey::derive(
        &ports.random.seed(),
        None,
        heyl_crypto::context::LONG_POLL_LOGIN_ENCRYPTION,
    )
    .map_err(AppError::Crypto)?;
    let public = pairing_key.public_key();

    let url = pair_url(&public);
    show_pairing(ports, &url, style);
    announce(&url);

    let hash = pairing_hash(&public);

    // Long-polls: this does not return until the phone answers.
    ports.terminal.note("waiting for the swipe…");
    let challenge = ports.api.create_long_poll_channel_challenge(&hash).await?;

    let plaintext = pairing_key
        .open(&challenge.encrypted_secret)
        .map_err(|_| AppError::UnlockUndecryptable)?;
    let seed = Seed::try_from_slice(&plaintext).map_err(|_| AppError::UnlockUndecryptable)?;

    let session_key =
        heyl_domain::session_encryption_key(&ports.random.seed()).map_err(AppError::Domain)?;
    let response = respond(&seed, &challenge.challenge)?;

    // heylogin omits the self-grant when the reply enrolled a new
    // authenticator; we omit it unless the user asked for one at all.
    let grant =
        (unlock_now && !challenge.registration).then(|| self_grant(ports, &session_key, &seed));

    let tokens = ports
        .api
        .create_tokens(
            challenge.authenticator_id,
            &challenge.challenge,
            response.as_bytes(),
            SESSION_TYPE,
            grant,
        )
        .await
        .map_err(|e| match e {
            heyl_ports::ApiError::PermissionDenied { .. } => AppError::SignatureRejected,
            other => AppError::Api(other),
        })?;

    // Store the key first: a token without its key is useless, and the reverse
    // order would leave a usable token behind if a later write failed.
    store(
        ports,
        slot,
        StoredSecret::SessionPrivateKey,
        &crate::recovery::encode_key(&session_key),
    )
    .await?;
    store(
        ports,
        slot,
        StoredSecret::SessionId,
        &tokens.session_id.to_string(),
    )
    .await?;
    store(ports, slot, StoredSecret::AccessToken, &tokens.access_token).await?;

    ports.api.set_access_token(Some(&tokens.access_token)).await;

    let display = register(
        ports,
        slot,
        display,
        &seed,
        &session_key,
        &challenge,
        tokens.session_id,
    )
    .await?;

    write_policy(ports, tokens.session_id, policy, "").await?;
    index_add(ports, slot).await?;

    Ok(Created {
        session_id: tokens.session_id,
        display,
        unlocked_until: unlocked_at_creation(ports, tokens.session_id).await,
    })
}

/// Read back the window a self-grant produced, if there was one.
async fn unlocked_at_creation(
    ports: &Ports<'_>,
    session_id: SessionId,
) -> Option<heyl_domain::Timestamp> {
    ports
        .api
        .sync()
        .await
        .ok()
        .and_then(|sync| sync.session(session_id).and_then(|s| s.unlocked_until))
}

/// Publish the signed encryption key that lets the phone unlock us later.
///
/// Without this entry the device is invisible in the app and every unlock
/// request becomes a notification with nothing behind it — the failure
/// heylogin's own telemetry calls a ghost notification.
///
/// Returns the display name actually used, after disambiguation.
async fn register(
    ports: &Ports<'_>,
    slot: &Slot,
    display: Option<&str>,
    seed: &Seed,
    session_key: &heyl_crypto::EncryptionPrivateKey,
    challenge: &heyl_ports::LongPollChallenge,
    session_id: SessionId,
) -> Result<String, AppError> {
    let sync = ports.api.sync().await?;
    let authenticators = ports.api.list_authenticators().await?;
    let salt = authenticators
        .iter()
        .find(|a| a.id == challenge.authenticator_id)
        .and_then(|a| a.secret_salt)
        .ok_or(AppError::NoSecretSalt {
            authenticator_id: challenge.authenticator_id,
        })?;
    let keys = AuthenticatorKeys::derive(challenge.authenticator_id, seed, &salt)
        .map_err(AppError::Domain)?;

    let session = Unlocked {
        sync,
        authenticators,
        authenticator_id: challenge.authenticator_id,
        // An explicit copy, so duplicating secret material is visible at the
        // call site rather than implied. Both go out of scope with `create`.
        seed: Seed::from_bytes(seed.expose_secret()),
        keys,
    };

    let mut meta = meta_vault::open(ports, &session).await?;
    let wanted = display.map_or_else(|| slot.default_display(), str::to_owned);
    let display = heyl_vault::meta::disambiguate(&wanted, &meta.document);
    let entry = metadata(&session, session_key, display.clone(), ports.clock.now());
    heyl_vault::meta::upsert_session(&mut meta.document, session_id, &entry).map_err(|e| {
        AppError::VaultContent {
            vault: meta.id,
            source: e,
        }
    })?;
    meta.commit(ports).await?;
    Ok(display)
}

/// Ask the phone to unlock a slot, and wait for it.
///
/// Blocks until approved. `timeout_secs` bounds the wait; without one it waits
/// indefinitely, because the thing it is waiting for is a person.
///
/// # A guard we cannot implement
///
/// A session with no `SessionMetadata` entry can never be unlocked by the
/// phone: it has nothing to verify, so the request arrives as a notification
/// that opens onto nothing. Refusing up front would be better than waiting —
/// but the entry is **vault content**, and reading it needs the unlock we are
/// asking for. There is no field in `Sync` that reveals it either. So a slot
/// deregistered from the phone looks exactly like one nobody has approved yet,
/// and the only honest thing to do is say so when the wait gives up.
///
/// `create` registers as part of pairing, so a slot heyl made is registered
/// unless somebody removed the device afterwards.
///
/// # Errors
/// [`AppError::UnlockRequired`] on timeout.
pub async fn unlock_and_wait(
    ports: &Ports<'_>,
    slot: &Slot,
    timeout_secs: Option<u64>,
) -> Result<Timestamp, AppError> {
    let adopted = adopt(ports, slot).await?;
    let sync = ports.api.sync().await?;

    if let Some(session) = sync.session(adopted.session_id)
        && let Some(until) = session.unlocked_until
    {
        // Already unlocked: say so rather than buzzing the phone again.
        return Ok(until);
    }

    ports
        .api
        .request_session_unlock(&format!("heyl session unlock {}", slot.name()))
        .await?;
    ports
        .terminal
        .note(&format!("approve on your phone ({})…", slot.name()));

    poll_for_unlock(ports, adopted.session_id, timeout_secs).await
}

/// Poll `Sync` until the grant appears.
///
/// A poll rather than a stream: `SyncService.StreamingSync` is the one
/// streaming method in the schema and nothing else in this client needs it, so
/// a one-second poll during a human-scale wait is the cheaper dependency.
async fn poll_for_unlock(
    ports: &Ports<'_>,
    session_id: SessionId,
    timeout_secs: Option<u64>,
) -> Result<Timestamp, AppError> {
    const INTERVAL_MS: u64 = 1_000;
    const GHOST_HINT_MS: u64 = 45_000;
    let mut waited_ms = 0u64;

    loop {
        let sync = ports.api.sync().await?;
        if let Some(until) = sync.session(session_id).and_then(|s| s.unlocked_until) {
            return Ok(until);
        }
        if let Some(limit) = timeout_secs
            && waited_ms >= limit.saturating_mul(1_000)
        {
            return Err(AppError::UnlockRequired);
        }
        // Long enough that a person would have noticed the notification: the
        // likeliest remaining cause is a device removed from the phone, which
        // no API reveals while we are locked.
        if waited_ms == GHOST_HINT_MS {
            ports.terminal.note(
                "still waiting — if no prompt appeared, this device may have been removed \
                 from your phone; `heyl session create` re-registers it",
            );
        }
        ports.clock.sleep_millis(INTERVAL_MS).await;
        waited_ms = waited_ms.saturating_add(INTERVAL_MS);
    }
}

/// End an ordinary command, honouring the slot's policy.
///
/// A **strict** slot drops its unlock here, so the next access asks the phone
/// again. That is the whole of "confirm every access": the server-side timeout
/// bounds the window, and this closes it as soon as the work is done.
///
/// Best-effort by nature — a client that kept the seed reads straight through
/// any of this (`HEYLOGIN_SPEC.md` §6). It constrains honest software, which is
/// what heyl is; it is not a sandbox around software that is not.
///
/// # Errors
/// Never fails the command it is finishing: a failure to re-lock is reported
/// on stderr, because the secret has already been delivered and exiting
/// non-zero would misreport what happened.
pub async fn finish(ports: &Ports<'_>, slot: &Slot) {
    let Ok(adopted) = adopt(ports, slot).await else {
        return;
    };
    let Ok(sync) = ports.api.sync().await else {
        return;
    };
    let Some(session) = sync.session(adopted.session_id) else {
        return;
    };
    let policy = heyl_domain::SessionPolicy::from_wire(
        session.unlock_time_limit_minutes,
        &session.client_settings,
    );

    if policy.strict
        && let Err(e) = ports.api.delete_session_unlock(adopted.session_id).await
    {
        ports
            .terminal
            .note(&format!("warning: could not re-lock {}: {e}", slot.name()));
    }
}

/// Drop a slot's unlock now, and cancel any request pending on it.
///
/// # Errors
/// [`AppError::Port`] if the slot is unknown, [`AppError::Api`] if the backend
/// refuses.
pub async fn lock(ports: &Ports<'_>, slot: &Slot) -> Result<(), AppError> {
    let adopted = adopt(ports, slot).await?;
    ports
        .api
        .delete_session_unlock(adopted.session_id)
        .await
        .map_err(AppError::Api)
}

/// Retire a session: tombstone its entry, delete it, forget its keys.
///
/// The tombstone needs the vault, so it needs this slot's own unlock. When
/// that is impossible — a rejected token, a declined approval — `force`
/// deletes what it can and leaves the app listing a device that no longer
/// exists, which the caller is expected to report.
///
/// # Errors
/// [`AppError::UnlockRequired`] if the entry cannot be tombstoned and `force`
/// was not given.
pub async fn remove(ports: &Ports<'_>, slot: &Slot, force: bool) -> Result<Removed, AppError> {
    let adopted = adopt(ports, slot).await?;

    let tombstoned = match tombstone(ports, slot, adopted.session_id).await {
        Ok(()) => true,
        Err(e) if force => {
            ports
                .terminal
                .note(&format!("could not tombstone the device entry: {e}"));
            false
        }
        Err(e) => return Err(e),
    };

    // Deleting the session works with any valid token, so this can succeed
    // even when the tombstone could not.
    let deleted = match ports.api.delete_session(adopted.session_id).await {
        Ok(()) => true,
        Err(e) if force => {
            ports
                .terminal
                .note(&format!("could not delete the session: {e}"));
            false
        }
        Err(e) => return Err(AppError::Api(e)),
    };

    forget(ports, slot).await?;
    index_remove(ports, slot).await?;

    Ok(Removed {
        tombstoned,
        deleted,
    })
}

async fn tombstone(ports: &Ports<'_>, slot: &Slot, session_id: SessionId) -> Result<(), AppError> {
    let session = crate::unlock::run_for(ports, slot).await?;
    let mut meta = meta_vault::open(ports, &session).await?;
    heyl_vault::meta::tombstone_session(&mut meta.document, session_id, ports.clock.now())
        .map_err(|e| AppError::VaultContent {
            vault: meta.id,
            source: e,
        })?;
    meta.commit(ports).await?;
    Ok(())
}

async fn store(
    ports: &Ports<'_>,
    slot: &Slot,
    secret: StoredSecret,
    value: &str,
) -> Result<(), AppError> {
    ports
        .store
        .set(&slot.key(secret), value)
        .await
        .map_err(AppError::Port)
}
