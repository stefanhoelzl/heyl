//! Typed KDF contexts.
//!
//! heylogin's context strings come in two layers, and the derivation
//! functions concatenate them: a *key-type prefix* selects what kind of key is
//! produced, and a *fixedInfo* value binds it to a purpose. The KDF sees
//! `prefix + fixedInfo` as one string.
//!
//! The prefixes are applied by the derivation functions, so the constants here
//! are fixedInfo values only. They are **typed by key kind**, which makes
//! deriving an Ed25519 key with `salt-key-symmetric-` unrepresentable rather
//! than merely wrong. That matters more here than anywhere else in the crate:
//! a mistyped context produces stable, self-consistent, *wrong* keys, and
//! nothing catches it until M2 (see DESIGN.md §6).
//!
//! Values are transcribed from `client-core/src/kdfFixedInfoValues.ts` and
//! `lib-vault-crypto/src/salts.ts`, scoped to what v1 needs. They are frozen
//! by backwards compatibility — heylogin can add a context but cannot move one
//! without orphaning every existing vault.
//!
//! The source comments note that the `salt-` naming is historic: these are
//! NIST SP 800-56A *`FixedInfo`* context bindings, not cryptographic salt.

macro_rules! context_kind {
    ($(#[$m:meta])* $name:ident, $prefix:expr) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(&'static str);

        impl $name {
            /// The key-type prefix this kind contributes to the KDF context.
            pub(crate) const PREFIX: &'static str = $prefix;

            // `SymmetricContext` has no v1 constant: heylogin derives symmetric
            // keys only in `combineSharedSecret` (SAS, M4). Vault secrets are
            // unwrapped from locks rather than derived.
            #[allow(dead_code)]
            const fn new(fixed_info: &'static str) -> Self {
                Self(fixed_info)
            }

            /// The full context string the KDF receives.
            pub(crate) fn salt(self) -> String {
                let mut s = String::with_capacity(Self::PREFIX.len() + self.0.len());
                s.push_str(Self::PREFIX);
                s.push_str(self.0);
                s
            }
        }
    };
}

context_kind!(
    /// Context for a symmetric XSalsa20-Poly1305 key.
    SymmetricContext,
    "salt-key-symmetric-"
);
context_kind!(
    /// Context for an Ed25519 signing keypair.
    SigningContext,
    "salt-key-signing-"
);
context_kind!(
    /// Context for an X25519 encryption keypair.
    EncryptionContext,
    "salt-key-encryption-"
);

/// Context for a signature, which binds to the *signed object's* kind rather
/// than to the signing key's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureContext(&'static str, &'static str);

impl SignatureContext {
    const fn encryption_key(fixed_info: &'static str) -> Self {
        Self("salt-sig-encryption-", fixed_info)
    }

    const fn signing_key(fixed_info: &'static str) -> Self {
        Self("salt-sig-signing-", fixed_info)
    }

    /// The full context string prefixed to the signed data.
    pub(crate) fn salt(self) -> String {
        let mut s = String::with_capacity(self.0.len() + self.1.len());
        s.push_str(self.0);
        s.push_str(self.1);
        s
    }
}

// ---------------------------------------------------------------- authenticator

/// Login signing key. **Derived with a null secondary seed** — that is what
/// lets login proceed before the server has revealed `secretSalt`.
pub const AUTHENTICATOR_LOGIN_SIGNING: SigningContext =
    SigningContext::new("salt-authenticator-login-signing-key-");

/// Authenticator identity signing key.
///
/// heylogin declares this constant twice — as
/// `FIXED_INFO_AUTHENTICATOR_HIGH_SECURITY_IDENTITY_SIGNING_KEY` and as
/// `FIXED_INFO_AUTHENTICATOR_STORABLE_SIGNING_KEY` — with the **same value**,
/// so the two tiers share one key at the authenticator layer. The tiers first
/// diverge at the profile layer. Represented once here, honestly, rather than
/// duplicated into a distinction that does not exist.
pub const AUTHENTICATOR_IDENTITY_SIGNING: SigningContext =
    SigningContext::new("salt-authenticator-signing-key-");

/// Authenticator profile-seed encryption key. Like the signing key above,
/// heylogin's storable and high-security constants hold the same value.
pub const AUTHENTICATOR_PROFILE_SEED_ENCRYPTION: EncryptionContext =
    EncryptionContext::new("salt-authenticator-encryption-key-");

// --------------------------------------------------------------------- profile

const PROFILE_HS_SIGNING: SigningContext =
    SigningContext::new("salt-profile-high-security-identity-signing-key-");
const PROFILE_HS_VAULT_KEY_ENCRYPTION: EncryptionContext =
    EncryptionContext::new("salt-profile-high-security-vault-key-encryption-key-");
const PROFILE_HS_PROFILE_KEY_ENCRYPTION: EncryptionContext =
    EncryptionContext::new("salt-profile-high-security-profile-key-encryption-key-");

const PROFILE_STORABLE_SIGNING: SigningContext =
    SigningContext::new("salt-profile-storable-signing-key-");
const PROFILE_STORABLE_VAULT_KEY_ENCRYPTION: EncryptionContext =
    EncryptionContext::new("salt-profile-storable-vault-key-encryption-key-");
const PROFILE_STORABLE_PROFILE_KEY_ENCRYPTION: EncryptionContext =
    EncryptionContext::new("salt-profile-storable-profile-key-encryption-key-");

// --------------------------------------------------------------------- session

/// Session encryption keypair — the key an unlock grant is encrypted to.
pub const SESSION_ENCRYPTION: EncryptionContext =
    EncryptionContext::new("salt-session-encryption-key-");

/// Signature over a session `encPubKey`, checked by a granting session before
/// it encrypts the seed to us (DESIGN.md §3, M5/M10).
pub const SESSION_ENCRYPTION_SIGNATURE: SignatureContext =
    SignatureContext::encryption_key("salt-session-encryption-key-signature-");

/// Signature over an authenticator's profile-seed encryption public key.
pub const AUTHENTICATOR_ENCRYPTION_SIGNATURE: SignatureContext =
    SignatureContext::encryption_key("salt-authenticator-encryption-key-signature-");

/// Signature over an authenticator's storable signing public key.
pub const AUTHENTICATOR_SIGNING_SIGNATURE: SignatureContext =
    SignatureContext::signing_key("salt-authenticator-signing-key-signature-");

/// Ephemeral keypair for the QR long-poll login channel (M4).
pub const LONG_POLL_LOGIN_ENCRYPTION: EncryptionContext =
    EncryptionContext::new("salt-long-poll-login-encryption-key-");

// ------------------------------------------------------------------------ tiers

mod sealed {
    pub trait Sealed {}
}

/// The two key tiers: [`Storable`] and [`HighSecurity`].
///
/// Carried as a phantom type parameter so that the storable and high-security
/// branches of the profile chain — which are structurally identical and differ
/// only in which context they use — cannot be crossed by a copy-paste. The
/// contexts hang off the tier, so picking the tier picks the context.
pub trait Tier: sealed::Sealed {
    /// Profile identity signing key context for this tier.
    const PROFILE_SIGNING: SigningContext;
    /// Profile vault-key encryption context for this tier.
    const PROFILE_VAULT_KEY_ENCRYPTION: EncryptionContext;
    /// Profile profile-key encryption context for this tier.
    const PROFILE_KEY_ENCRYPTION: EncryptionContext;
    /// Human-readable tier name, for `Debug`.
    const NAME: &'static str;
}

/// Keys that survive a lock: they yield each vault's `vaultSecret`, which
/// decrypts non-secret content (titles, usernames, URLs).
///
/// `heyl` does not actually persist them — there is no locked-but-browsable
/// state (DESIGN.md §3) — but the tier distinction is heylogin's and the
/// contexts differ, so it is modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storable {}

/// Keys that require the seed and are never persisted: they yield each vault's
/// `protectedSecret`, which decrypts passwords, TOTP secrets and card numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighSecurity {}

impl sealed::Sealed for Storable {}
impl sealed::Sealed for HighSecurity {}

impl Tier for Storable {
    const PROFILE_SIGNING: SigningContext = PROFILE_STORABLE_SIGNING;
    const PROFILE_VAULT_KEY_ENCRYPTION: EncryptionContext = PROFILE_STORABLE_VAULT_KEY_ENCRYPTION;
    const PROFILE_KEY_ENCRYPTION: EncryptionContext = PROFILE_STORABLE_PROFILE_KEY_ENCRYPTION;
    const NAME: &'static str = "Storable";
}

impl Tier for HighSecurity {
    const PROFILE_SIGNING: SigningContext = PROFILE_HS_SIGNING;
    const PROFILE_VAULT_KEY_ENCRYPTION: EncryptionContext = PROFILE_HS_VAULT_KEY_ENCRYPTION;
    const PROFILE_KEY_ENCRYPTION: EncryptionContext = PROFILE_HS_PROFILE_KEY_ENCRYPTION;
    const NAME: &'static str = "HighSecurity";
}
