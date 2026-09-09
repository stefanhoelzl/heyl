//! `heyl api` — heylogin's gRPC surface, by hand.
//!
//! # This is unsafe by construction
//!
//! There are **no guards here.** Every RPC in the schema is reachable by name,
//! including the destructive ones: `CreateTokens` with a `BACKUP_CODE`
//! signature disconnects your phone authenticator server-side, exactly as
//! `heyl recovery` warns about — except nothing warns you here. `derive` prints
//! key material to your terminal. Nothing is confirmed, nothing is checked.
//!
//! That is deliberate, and it is why the command exists only in a build made
//! with `--features api` and is hidden even then. **Point it at a throwaway
//! account.** The safe path exists and is named for what it does: `heyl
//! recovery` (DESIGN.md §5).
//!
//! # What is here
//!
//! One subcommand calls an RPC; the other three are pure functions with no
//! network at all. Together they close the loop, because a login is RPCs plus
//! exactly two pieces of arithmetic:
//!
//! ```text
//! heyl api call CreateChallenge '{"email":"…"}'   -> challenge, salt, params
//!   heyl api sign-challenge …                     -> signature   (pure)
//! heyl api call CreateTokens '{…,"response":"…"}' -> access token
//! heyl api call Sync                              -> the account
//!   heyl api derive …                             -> seed, profile and vault keys (pure)
//!   heyl api decode --blob … --key …              -> a heymerge document (pure)
//! ```
//!
//! Nothing is ambient: no keychain is read, and the token comes from the
//! request you build. `HEYL_TOKEN=bad heyl api call Sync` reproduces
//! `DomainError 30420` against the live backend, which is how M0 produced
//! `tests/fixtures/protocol/sync-bad-token` by hand.

use base64::Engine as _;
use clap::Subcommand;
use heyl_crypto::{RecoveryParams, SecretSalt, Seed, SymKey, derive_recovery_seed};
use heyl_grpc::{ClientContext, GrpcClient, GrpcConfig, HeyloginApi};
use heyl_ports::Terminal as _;

/// Anything `heyl api` can fail at.
///
/// Its own type rather than [`heyl_app::AppError`]: this command is not a use
/// case, and the core should not grow a catch-all variant to carry a dev
/// tool's complaints.
#[derive(Debug, thiserror::Error)]
pub enum ApiCommandError {
    /// The argument was not what it claimed to be.
    #[error("{0}")]
    Argument(String),

    /// The call failed.
    #[error(transparent)]
    Api(#[from] heyl_ports::ApiError),

    /// The keychain or terminal.
    #[error(transparent)]
    Port(#[from] heyl_ports::PortError),

    /// A cryptographic step failed.
    #[error(transparent)]
    Crypto(#[from] heyl_crypto::CryptoError),

    /// The key hierarchy refused.
    #[error(transparent)]
    Domain(#[from] heyl_domain::DomainError),

    /// The blob decrypted but was not a vault document.
    #[error(transparent)]
    Vault(#[from] heyl_vault::VaultError),

    /// The dispatch could not find or transcode the RPC.
    #[error(transparent)]
    Dispatch(#[from] heyl_grpc::DispatchError),

    /// A message could not be transcoded.
    #[error(transparent)]
    Json(#[from] heyl_grpc::json::JsonError),
}

/// The raw API surface.
#[derive(Debug, Subcommand)]
pub enum Api {
    /// Call one RPC: JSON in, protobuf-JSON out.
    ///
    /// The method is the gRPC path (`/domain.SyncService/Sync`), or any
    /// unambiguous spelling of it — `domain.SyncService/Sync`, `SyncService/Sync`
    /// or `Sync` all resolve when only one RPC matches.
    Call {
        /// Which RPC.
        method: String,

        /// The request message as JSON. Omitted means the default message.
        body: Option<String>,

        /// The bearer token. Reads `HEYL_TOKEN` when not given.
        ///
        /// Pass an empty value to send none, which is how the
        /// `sync-unauthenticated` case is reproduced.
        #[arg(long, env = "HEYL_TOKEN", hide_env_values = true)]
        token: Option<String>,

        /// The `client-type` header. 400 is `CLIENT_TYPE_CLI`.
        #[arg(long, default_value = heyl_grpc::CLIENT_TYPE_CLI)]
        client_type: String,
    },

    /// List every RPC in the schema.
    Methods {
        /// Only those whose path contains this, case-insensitively.
        filter: Option<String>,
    },

    /// Sign a challenge with a recovery code. **No network.**
    ///
    /// The one piece of arithmetic between `CreateChallenge` and
    /// `CreateTokens`. The code is read from `HEYL_RECOVERY_CODE` or prompted
    /// for — never argv, for the same reason `heyl recovery` has no `--code`.
    SignChallenge {
        /// The `challenge` from `CreateChallenge`.
        #[arg(long)]
        challenge: String,

        /// The authenticator's `secretSalt`, base64.
        #[arg(long)]
        salt: String,

        /// Argon2id memory cost, in KiB, from `secretInfo`.
        #[arg(long)]
        memory_kib: u32,

        /// Argon2id iterations, from `secretInfo`.
        #[arg(long)]
        iterations: u32,

        /// Argon2id parallelism, from `secretInfo`.
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
    },

    /// Walk the key hierarchy from a recovery code. **No network.**
    ///
    /// Prints the seed, and — given a `Sync` response to read the locks from —
    /// every profile seed and vault key under it. This is the walk `heyl
    /// doctor` performs; printing the keys rather than a comparison is what
    /// makes them usable with `decode`, and is one of the reasons this command
    /// is not shipped.
    Derive {
        /// A `Sync` response, as `heyl api call Sync` prints it.
        ///
        /// Without it only the seed is derivable: the profile seeds come out
        /// of locks the backend serves, not out of the code.
        #[arg(long)]
        sync: Option<std::path::PathBuf>,

        /// A `ListCommits` response, repeatable — one per vault.
        ///
        /// Vault keys are not in `Sync`: a `VaultProfileLock` arrives with the
        /// vault's commits, which is why the port asks for it with
        /// `force_locks`.
        #[arg(long = "commits")]
        commits: Vec<std::path::PathBuf>,

        /// Which authenticator's locks to open. Required with `--sync`.
        #[arg(long)]
        authenticator: Option<String>,

        /// The authenticator's `secretSalt`, base64.
        #[arg(long)]
        salt: String,

        /// Argon2id memory cost, in KiB.
        #[arg(long)]
        memory_kib: u32,

        /// Argon2id iterations.
        #[arg(long)]
        iterations: u32,

        /// Argon2id parallelism.
        #[arg(long, default_value_t = 1)]
        parallelism: u32,
    },

    /// Decrypt a vault blob and print the document. **No network.**
    ///
    /// Stops at the serialization framing — snappy or plain JSON — because
    /// heymerge semantics and the content schemas belong to the read path.
    /// What comes out is the document heylogin stored, which is what that work
    /// needs to be designed against.
    Decode {
        /// The sealed blob, base64.
        #[arg(long)]
        blob: String,

        /// The symmetric key that opens it, base64.
        #[arg(long)]
        key: String,
    },
}

/// Run one `heyl api` invocation.
///
/// # Errors
/// [`AppError`] if the call or the arithmetic fails.
pub async fn run(api: Api, endpoint: Option<&str>) -> Result<(), ApiCommandError> {
    match api {
        Api::Methods { filter } => {
            methods(filter.as_deref());
            Ok(())
        }
        Api::Call {
            method,
            body,
            token,
            client_type,
        } => call(&method, body.as_deref(), token, &client_type, endpoint).await,
        Api::SignChallenge {
            challenge,
            salt,
            memory_kib,
            iterations,
            parallelism,
        } => sign_challenge(&challenge, &salt, memory_kib, iterations, parallelism),
        Api::Derive {
            sync,
            commits,
            authenticator,
            salt,
            memory_kib,
            iterations,
            parallelism,
        } => derive(
            sync.as_deref(),
            &commits,
            authenticator.as_deref(),
            &salt,
            memory_kib,
            iterations,
            parallelism,
        ),
        Api::Decode { blob, key } => decode(&blob, &key),
    }
}

/// Every RPC in the schema, optionally filtered.
fn methods(filter: Option<&str>) {
    let filter = filter.unwrap_or_default().to_lowercase();
    for (path, name) in heyl_grpc::METHODS {
        if path.to_lowercase().contains(&filter) {
            println!("{path}  {name}");
        }
    }
}

/// One RPC: JSON in, protobuf-JSON out.
async fn call(
    method: &str,
    body: Option<&str>,
    token: Option<String>,
    client_type: &str,
    endpoint: Option<&str>,
) -> Result<(), ApiCommandError> {
    let path = resolve(method)?;
    let config = GrpcConfig {
        endpoint: endpoint.map_or_else(|| heyl_grpc::DEFAULT_ENDPOINT.to_owned(), str::to_owned),
        ..GrpcConfig::default()
    };
    let context = ClientContext {
        client_type: client_type.to_owned(),
        // An empty value means "send no authorization header", which is a case
        // worth being able to produce on purpose.
        access_token: token.filter(|t| !t.is_empty()),
        ..config.context()
    };
    let client = GrpcClient::new(config)?;
    let json = heyl_grpc::dispatch(
        &client as &dyn HeyloginApi,
        &context,
        path,
        body.unwrap_or_default(),
    )
    .await?;
    println!("{json}");
    Ok(())
}

/// The one piece of arithmetic between `CreateChallenge` and `CreateTokens`.
fn sign_challenge(
    challenge: &str,
    salt: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), ApiCommandError> {
    let seed = seed_from_code(salt, memory_kib, iterations, parallelism)?;
    // Utf8: the encoding `CreateTokens` accepts, established by probing the
    // live backend at M2.
    let signature =
        heyl_domain::sign_challenge(&seed, challenge, heyl_domain::ChallengeEncoding::Utf8)?;
    println!("{}", b64(signature.as_bytes()));
    Ok(())
}

/// Unseal a vault blob and print the document it frames.
fn decode(blob: &str, key: &str) -> Result<(), ApiCommandError> {
    let blob = decode_b64(blob, "blob")?;
    let key = SymKey::try_from_slice(&decode_b64(key, "key")?)?;
    let document = heyl_vault::decode(&key.decrypt(&blob)?)?;
    // Framing and body, which is as far as `heyl-vault` goes today: heymerge
    // semantics and the content schemas belong to the read path, and this
    // exists to be read while designing them.
    eprintln!(
        "{:?}  type={}  version={}",
        document.format, document.document_type, document.version
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&document.content)
            .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    );
    Ok(())
}

/// Walk the hierarchy: seed, then profile seeds, then vault keys.
#[allow(clippy::too_many_arguments)]
fn derive(
    sync: Option<&std::path::Path>,
    commits: &[std::path::PathBuf],
    authenticator: Option<&str>,
    salt: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), ApiCommandError> {
    let seed = seed_from_code(salt, memory_kib, iterations, parallelism)?;
    println!("seed{:56}{}", "", b64(seed.expose_secret()));

    let Some(sync) = sync else {
        return Ok(());
    };
    let authenticator = authenticator
        .ok_or_else(|| ApiCommandError::Argument("--sync needs --authenticator".to_owned()))?;
    let authenticator = heyl_domain::AuthenticatorId::parse(authenticator)
        .map_err(|_| ApiCommandError::Argument("--authenticator is not a UUID".to_owned()))?;
    let salt = SecretSalt::try_from_slice(&decode_b64(salt, "salt")?)?;
    let keys = heyl_domain::AuthenticatorKeys::derive(authenticator, &seed, &salt)?;

    let snapshot = snapshot_from(sync)?;
    let commits = commits
        .iter()
        .map(|path| read_json(path).and_then(|raw| Ok(heyl_grpc::json::vault_commits(&raw)?)))
        .collect::<Result<Vec<_>, ApiCommandError>>()?;

    for profile in &snapshot.profiles {
        let Some(lock) = profile.lock_for(authenticator) else {
            continue;
        };
        let storable = keys.unlock_storable_profile_seed(lock, &profile.key_generation_id)?;
        let high = keys.unlock_high_security_profile_seed(lock, &profile.key_generation_id)?;
        println!(
            "profile {}  storable       {}",
            profile.id,
            b64(storable.expose_secret())
        );
        println!(
            "profile {}  high-security  {}",
            profile.id,
            b64(high.expose_secret())
        );

        for vault in &commits {
            let Some(vault_lock) = vault.profile_lock.as_ref() else {
                continue;
            };
            if vault_lock.locking_profile_id != profile.id {
                continue;
            }
            // Two keys per vault, and they are not interchangeable:
            // `vaultSecret` opens the document, `protectedSecret` opens the
            // passwords inside it (DESIGN.md §3).
            let generation = &vault.current_generation_id;
            let secret = storable.unlock_vault(vault_lock, profile.id, generation)?;
            let protected = high.unlock_vault(vault_lock, profile.id, generation)?;
            println!(
                "  vault         vaultSecret    {}",
                b64(secret.key().expose_secret())
            );
            println!(
                "  vault         protected      {}",
                b64(protected.key().expose_secret())
            );
        }
    }
    Ok(())
}

/// Find the one RPC a spelling refers to.
///
/// Ambiguity is an error rather than a guess, for the same reason DESIGN.md §5
/// makes selector ambiguity an error: this is a tool you drive unattended, and
/// silently picking one of five `List` methods is worse than saying so.
fn resolve(method: &str) -> Result<&'static str, ApiCommandError> {
    let wanted = method.trim_start_matches('/').to_lowercase();
    let matches: Vec<&'static str> = heyl_grpc::METHODS
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| {
            let path = path.trim_start_matches('/').to_lowercase();
            path == wanted
                || path.ends_with(&format!("/{wanted}"))
                || path.ends_with(&format!(".{wanted}"))
        })
        .collect();

    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(ApiCommandError::Argument(format!(
            "no RPC matches {method:?}; `heyl api methods` lists them"
        ))),
        many => Err(ApiCommandError::Argument(format!(
            "{method:?} is ambiguous:\n  {}",
            many.join("\n  ")
        ))),
    }
}

/// The recovery code → seed, with the parameters the backend published.
fn seed_from_code(
    salt: &str,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Seed, ApiCommandError> {
    // Environment or a hidden prompt, never argv -- the same rule
    // `heyl recovery` follows, and for the same reason: a recovery code
    // unlocks every vault, so argv would leak it into `ps` and shell history.
    let terminal = heyl_platform::SystemTerminal;
    let code = match std::env::var(heyl_app::recovery::CODE_ENV) {
        Ok(code) => zeroize::Zeroizing::new(code),
        Err(_) if terminal.is_interactive() => terminal.prompt_hidden("recovery code: ")?,
        Err(_) => terminal.read_line()?,
    };

    let salt = SecretSalt::try_from_slice(&decode_b64(salt, "salt")?)?;
    let seed = derive_recovery_seed(
        &code,
        salt.as_bytes(),
        RecoveryParams {
            memory_cost_kib: memory_kib,
            iterations,
            parallelism,
        },
    )?;
    Ok(Seed::from_bytes(&seed))
}

/// A `Sync` response on disk → the domain snapshot.
///
/// The transcoding lives in `heyl-grpc`, which is the only crate allowed to
/// see a prost type; this reads the file and hands it over.
fn snapshot_from(path: &std::path::Path) -> Result<heyl_domain::SyncSnapshot, ApiCommandError> {
    Ok(heyl_grpc::json::sync_snapshot(&read_json(path)?)?)
}

/// Read a JSON document a previous `heyl api call` wrote.
fn read_json(path: &std::path::Path) -> Result<String, ApiCommandError> {
    std::fs::read_to_string(path)
        .map_err(|e| ApiCommandError::Argument(format!("cannot read {}: {e}", path.display())))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(value: &str, what: &str) -> Result<Vec<u8>, ApiCommandError> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| ApiCommandError::Argument(format!("{what} is not valid base64")))
}
