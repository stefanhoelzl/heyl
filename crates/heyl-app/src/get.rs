//! `heyl get` — read one login, or one of its fields.
//!
//! The first user-facing read verb. It resolves a **vault → login → field**
//! selector, opens the vaults in scope, ranks the logins that match, and
//! returns either one field's value or the whole login with its secrets
//! decrypted. The command surface and every rule below are DESIGN.md §5.
//!
//! Secrets cross this boundary as plaintext `String`s: the CLI prints them, and
//! that is the whole point of the verb. Nothing here logs or formats them —
//! rendering is `heyl-cli`'s job.

use base64::Engine as _;
use heyl_domain::{FieldId, LoginId, ProtectedSecret, VaultId, VaultType};
use heyl_vault::login::{FieldValue, Liveness, Login, Protected};

use crate::{AppError, Ports, unlock::Unlocked};

/// Which vault to look in.
#[derive(Debug, Clone)]
pub enum VaultSelector {
    /// No `-v`/`-V`: every readable login vault, in tier order.
    Any,
    /// `-v <name>`: a vault named `private`, `inbox`, an organisation, or a team.
    Name(String),
    /// `-V <uuid>`: exactly this vault.
    Id(VaultId),
}

/// Which login to read.
#[derive(Debug, Clone)]
pub enum LoginSelector {
    /// `-l <title>`: a display name, title, or website, exact and case-insensitive.
    Name(String),
    /// `-L <uuid>`: exactly this login.
    Id(LoginId),
}

/// Which field to print.
#[derive(Debug, Clone)]
pub enum FieldSelector {
    /// No `-f`/`-F`: every non-empty field.
    All,
    /// `-f <name>`: a built-in or custom field by name.
    Name(String),
    /// `-F <uuid>`: a custom field by id.
    Id(FieldId),
}

/// A full `get` request.
#[derive(Debug, Clone)]
pub struct Query {
    /// Where to look.
    pub vault: VaultSelector,
    /// What to find.
    pub login: LoginSelector,
    /// What to print.
    pub field: FieldSelector,
}

impl Query {
    /// Build a query from the six raw flag values, validating them.
    ///
    /// Validation lives here rather than in clap so the design's exit codes
    /// hold: two selectors for one slot, or a login selector missing entirely,
    /// or a malformed UUID are all "invalid" (exit 7), not clap's usage code
    /// (DESIGN.md §5). A selector's *meaning* — whether the thing it names
    /// exists — is decided later, and is a "not found" (exit 2).
    ///
    /// # Errors
    /// [`AppError::ConflictingSelectors`], [`AppError::MissingLoginSelector`],
    /// [`AppError::MalformedSelector`] — all exit 7.
    pub fn from_flags(
        vault_name: Option<String>,
        vault_id: Option<String>,
        login_title: Option<String>,
        login_id: Option<String>,
        field_name: Option<String>,
        field_id: Option<String>,
    ) -> Result<Self, AppError> {
        let vault = match (vault_name, vault_id) {
            (Some(_), Some(_)) => {
                return Err(AppError::ConflictingSelectors {
                    a: "--vault-name",
                    b: "--vault-id",
                });
            }
            (Some(name), None) => VaultSelector::Name(name),
            (None, Some(id)) => VaultSelector::Id(
                VaultId::parse(&id)
                    .map_err(|_| AppError::MalformedSelector { what: "--vault-id" })?,
            ),
            (None, None) => VaultSelector::Any,
        };
        let login = match (login_title, login_id) {
            (Some(_), Some(_)) => {
                return Err(AppError::ConflictingSelectors {
                    a: "--login-title",
                    b: "--login-id",
                });
            }
            (Some(title), None) => LoginSelector::Name(title),
            (None, Some(id)) => LoginSelector::Id(
                LoginId::parse(&id)
                    .map_err(|_| AppError::MalformedSelector { what: "--login-id" })?,
            ),
            (None, None) => return Err(AppError::MissingLoginSelector),
        };
        let field = match (field_name, field_id) {
            (Some(_), Some(_)) => {
                return Err(AppError::ConflictingSelectors {
                    a: "--field-name",
                    b: "--field-id",
                });
            }
            (Some(name), None) => FieldSelector::Name(name),
            (None, Some(id)) => FieldSelector::Id(
                FieldId::parse(&id)
                    .map_err(|_| AppError::MalformedSelector { what: "--field-id" })?,
            ),
            (None, None) => FieldSelector::All,
        };
        Ok(Self {
            vault,
            login,
            field,
        })
    }
}

/// What `get` found, for the CLI to render.
#[derive(Debug)]
pub struct Located {
    /// How many logins matched the selector — 1 unless a name was ambiguous.
    pub match_count: usize,
    /// The liveness of the login returned, for the ambiguity warning's wording
    /// and so a caller knows it got a tombstone.
    pub liveness: Liveness,
    /// The value(s) to print.
    pub selection: Selection,
}

/// The value `get` returns.
#[derive(Debug)]
pub enum Selection {
    /// `-f`/`-F`: one field's value. Empty is a successful empty read.
    Value(String),
    /// No field flag: the whole login, decrypted.
    Login(Box<LoginView>),
}

/// A located login with its secrets decrypted, ready to render.
///
/// A `None` built-in is omitted from both forms; the `websites`/`labels`
/// vectors are omitted when empty. `change_time` renders in JSON only.
#[derive(Debug, Default)]
pub struct LoginView {
    /// The login's id.
    pub id: String,
    /// `displayHeadline` — printed as `name`.
    pub name: Option<String>,
    /// `title`, when non-empty.
    pub title: Option<String>,
    /// `username`, when non-empty.
    pub username: Option<String>,
    /// The decrypted password, when the login has a non-empty one.
    pub password: Option<String>,
    /// `websites`, in order.
    pub websites: Vec<String>,
    /// `note`, when non-empty.
    pub note: Option<String>,
    /// `tags` — printed as `labels`.
    pub labels: Vec<String>,
    /// Custom fields as `(name, decrypted value)`, in order.
    pub custom: Vec<(String, String)>,
    /// `creationTime` — printed as `created`.
    pub created: Option<String>,
    /// `editTime` — printed as `edited`.
    pub edited: Option<String>,
    /// `changeTime`, JSON only, its meaning is when the login last surfaced.
    pub change_time: Option<String>,
    /// `isDeleted`.
    pub is_deleted: bool,
    /// `isArchived`.
    pub is_archived: bool,
}

/// Run a `get`.
///
/// Asks the phone and blocks if the session is locked (bounded by `--wait`),
/// like every read (DESIGN.md §5).
///
/// # Errors
/// [`AppError::NoSuchLogin`] / [`AppError::NoSuchVault`] / [`AppError::NoSuchField`]
/// (exit 2) when a selector matches nothing; the vault-open errors (exit 1)
/// when a *named* vault will not open; the usual unlock and backend errors.
pub async fn run(
    ports: &Ports<'_>,
    slot: &crate::session::Slot,
    query: &Query,
    wait: Option<u64>,
) -> Result<Located, AppError> {
    let session = crate::unlock::ensure(ports, slot, wait).await?;

    // The vaults in scope, in tier order. A named vault that is missing or
    // unsupported is `NoSuchVault`; `Any` yields every readable login vault.
    let scope = resolve_scope(ports, &session, &query.vault).await?;

    // Gather every login the selector matches, across the scope. A vault that
    // will not open is skipped when it was not named, fatal when it was
    // (DESIGN.md §5) — `resolve_scope` already narrowed a name to one vault, so
    // a failure here on a single-vault scope is the "named" case.
    let named = !matches!(query.vault, VaultSelector::Any);
    let mut candidates: Vec<Candidate> = Vec::new();
    for vault in &scope {
        let opened = match open_vault(ports, &session, vault).await {
            Ok(opened) => opened,
            Err(e) if named => return Err(e),
            // Skipped silently: a team vault another client wrote in a format we
            // cannot read should not stop a search for your own password.
            Err(_) => continue,
        };
        for login in heyl_vault::login::logins(&opened.document) {
            if login_matches(&login, &query.login) {
                candidates.push(Candidate {
                    tier: tier(vault.vault_type),
                    login,
                    protected: opened.protected.clone(),
                });
            }
        }
    }

    let match_count = candidates.len();
    let chosen = rank(candidates).ok_or(AppError::NoSuchLogin)?;

    let liveness = chosen.login.liveness();
    let selection = match &query.field {
        FieldSelector::All => Selection::Login(Box::new(view(&chosen.login, &chosen.protected)?)),
        FieldSelector::Name(name) => {
            Selection::Value(field_by_name(&chosen.login, name, &chosen.protected)?)
        }
        FieldSelector::Id(id) => {
            Selection::Value(field_by_id(&chosen.login, *id, &chosen.protected)?)
        }
    };

    Ok(Located {
        match_count,
        liveness,
        selection,
    })
}

/// A matching login, with what it takes to rank it and decrypt it.
struct Candidate {
    tier: u8,
    login: Login,
    protected: ProtectedSecret,
}

/// An opened, folded login vault and the key that decrypts its secrets.
struct Opened {
    document: heyl_vault::Document,
    protected: ProtectedSecret,
}

/// The vaults a selector puts in scope, in tier order.
async fn resolve_scope<'a>(
    ports: &Ports<'_>,
    session: &'a Unlocked,
    selector: &VaultSelector,
) -> Result<Vec<&'a heyl_domain::VaultSummary>, AppError> {
    // Every readable login vault the account has, PRIVATE → ORG_PERSONAL →
    // TEAM → INBOX (DESIGN.md §5).
    let mut login_vaults: Vec<&heyl_domain::VaultSummary> = session
        .sync
        .vaults
        .iter()
        .filter(|v| v.vault_type.holds_logins())
        .collect();
    login_vaults.sort_by_key(|v| tier(v.vault_type));

    match selector {
        VaultSelector::Any => Ok(login_vaults),
        VaultSelector::Id(id) => login_vaults
            .into_iter()
            .find(|v| v.id == *id)
            .map(|v| vec![v])
            .ok_or(AppError::NoSuchVault),
        VaultSelector::Name(name) => {
            let matched = match_vault_name(ports, session, &login_vaults, name).await?;
            matched.map(|v| vec![v]).ok_or(AppError::NoSuchVault)
        }
    }
}

/// Resolve a `-v <name>` against the login vaults, cheapest names first.
///
/// The free names — `private`, `inbox`, and an organisation's name — are
/// matched without touching the network. Only if none of those matched are the
/// team names read, each of which costs opening the team's `groupMeta` vault
/// (DESIGN.md §5); the search stops at the first team that matches.
async fn match_vault_name<'a>(
    ports: &Ports<'_>,
    session: &Unlocked,
    login_vaults: &[&'a heyl_domain::VaultSummary],
    name: &str,
) -> Result<Option<&'a heyl_domain::VaultSummary>, AppError> {
    let wanted = name.to_lowercase();

    // Free names, in tier order (login_vaults is already sorted).
    for vault in login_vaults {
        let free = match vault.vault_type {
            VaultType::Private => Some("private".to_owned()),
            VaultType::Inbox => Some("inbox".to_owned()),
            VaultType::OrganizationPersonal => vault
                .organization_id
                .as_deref()
                .and_then(|id| session.sync.organization_name(id))
                .map(str::to_lowercase),
            _ => None,
        };
        if free.is_some_and(|n| n == wanted) {
            return Ok(Some(vault));
        }
    }

    // Team names, paid for one groupMeta decrypt at a time.
    for vault in login_vaults {
        if vault.vault_type != VaultType::Team {
            continue;
        }
        if let Some(team_name) = team_name(ports, session, vault).await?
            && team_name.to_lowercase() == wanted
        {
            return Ok(Some(vault));
        }
    }

    Ok(None)
}

/// A team vault's name, read from its paired `groupMeta` vault's `info` list.
async fn team_name(
    ports: &Ports<'_>,
    session: &Unlocked,
    team: &heyl_domain::VaultSummary,
) -> Result<Option<String>, AppError> {
    let Some(meta_id) = team.associated_vault_id else {
        return Ok(None);
    };
    let Some(meta) = session.sync.vaults.iter().find(|v| v.id == meta_id) else {
        return Ok(None);
    };
    // A groupMeta we cannot open just means we cannot name this team; that is a
    // reason to skip it, not to fail the whole command.
    let Ok(opened) = open_vault(ports, session, meta).await else {
        return Ok(None);
    };
    Ok(opened
        .document
        .content
        .get("info")
        .and_then(serde_json::Value::as_object)
        .and_then(|info| {
            info.values()
                .filter(|e| {
                    !e.get("isDeleted")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                })
                .find_map(|e| e.get("name").and_then(serde_json::Value::as_str))
                .map(str::to_owned)
        }))
}

/// Open a login (or groupMeta) vault: unlock both tiers, fold every commit.
async fn open_vault(
    ports: &Ports<'_>,
    session: &Unlocked,
    summary: &heyl_domain::VaultSummary,
) -> Result<Opened, AppError> {
    let commits = ports.api.list_commits(summary.id).await?;
    let lock = commits
        .profile_lock
        .ok_or_else(|| vault_err(summary.id, "the backend returned no profile lock"))?;
    let profile = session
        .sync
        .profile(lock.locking_profile_id)
        .ok_or_else(|| vault_err(summary.id, "locking profile is not in the sync snapshot"))?;
    let profile_lock = profile
        .lock_for(session.authenticator_id)
        .ok_or_else(|| vault_err(summary.id, "no lock for our authenticator"))?;

    let storable = session
        .keys
        .unlock_storable_profile_seed(profile_lock, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: summary.id,
            source: e,
        })?;
    let high = session
        .keys
        .unlock_high_security_profile_seed(profile_lock, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: summary.id,
            source: e,
        })?;
    let vault_secret = storable
        .unlock_vault(&lock, profile.id, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: summary.id,
            source: e,
        })?;
    let protected = high
        .unlock_vault(&lock, profile.id, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: summary.id,
            source: e,
        })?;

    let mut documents = Vec::with_capacity(commits.commits.len());
    for commit in &commits.commits {
        let plaintext = vault_secret
            .key()
            .decrypt(&commit.blob)
            .map_err(AppError::Crypto)?;
        documents.push(
            heyl_vault::decode(&plaintext).map_err(|e| AppError::VaultContent {
                vault: summary.id,
                source: e,
            })?,
        );
    }
    // A vault with no commits has nothing to read — an empty document, not an
    // error, so a search simply finds no login there.
    let document = if documents.is_empty() {
        heyl_vault::Document::empty()
    } else {
        heyl_vault::fold(&documents).map_err(|e| AppError::VaultContent {
            vault: summary.id,
            source: e,
        })?
    };

    Ok(Opened {
        document,
        protected,
    })
}

/// Whether a login answers a `-l`/`-L` selector.
fn login_matches(login: &Login, selector: &LoginSelector) -> bool {
    match selector {
        LoginSelector::Id(id) => login.id == *id,
        LoginSelector::Name(name) => login.matches_name(name),
    }
}

/// The read ranking: liveness, then vault tier, then most recently changed,
/// then id (DESIGN.md §5). The first is the winner.
fn rank(mut candidates: Vec<Candidate>) -> Option<Candidate> {
    candidates.sort_by(|a, b| {
        (a.login.liveness() as u8)
            .cmp(&(b.login.liveness() as u8))
            .then(a.tier.cmp(&b.tier))
            // Most recently changed first: reverse the recency comparison.
            .then(b.login.recency().cmp(a.login.recency()))
            .then(a.login.id.to_string().cmp(&b.login.id.to_string()))
    });
    candidates.into_iter().next()
}

/// A login's vault tier, the second ranking key.
const fn tier(vault_type: VaultType) -> u8 {
    match vault_type {
        VaultType::Private => 0,
        VaultType::OrganizationPersonal => 1,
        VaultType::Team => 2,
        VaultType::Inbox => 3,
        // Not a login vault; sorts last if one ever reaches here.
        _ => u8::MAX,
    }
}

/// Assemble a decrypted view of the whole login (the no-field form).
fn view(login: &Login, protected: &ProtectedSecret) -> Result<LoginView, AppError> {
    let password = login
        .password
        .as_ref()
        .map(|p| decrypt(protected, p))
        .transpose()?
        .filter(|s| !s.is_empty());

    let mut custom = Vec::with_capacity(login.custom_fields.len());
    for field in &login.custom_fields {
        custom.push((field.name.clone(), resolve(&field.value, protected)?));
    }

    Ok(LoginView {
        id: login.id.to_string(),
        name: login.display_headline.clone(),
        title: non_empty(&login.title),
        username: non_empty(&login.username),
        password,
        websites: login.websites.clone(),
        note: non_empty(&login.note),
        labels: login.tags.clone(),
        custom,
        created: login.created.clone(),
        edited: login.edited.clone(),
        change_time: login.change_time.clone(),
        is_deleted: login.is_deleted,
        is_archived: login.is_archived,
    })
}

/// Resolve `-f <name>`: a built-in wins a clash with a custom field of the same
/// name (DESIGN.md §5); an empty value is a successful empty read (exit 0).
fn field_by_name(
    login: &Login,
    name: &str,
    protected: &ProtectedSecret,
) -> Result<String, AppError> {
    if let Some(value) = builtin(login, name, protected)? {
        return Ok(value);
    }
    if let Some(field) = login.custom_field_by_name(name) {
        return resolve(&field.value, protected);
    }
    Err(AppError::NoSuchField)
}

/// Resolve `-F <uuid>`: a custom field by its id.
fn field_by_id(
    login: &Login,
    id: FieldId,
    protected: &ProtectedSecret,
) -> Result<String, AppError> {
    login
        .custom_field_by_id(id)
        .map_or(Err(AppError::NoSuchField), |f| resolve(&f.value, protected))
}

/// The built-in fields `-f` can name, or `None` if `name` is not one of them.
fn builtin(
    login: &Login,
    name: &str,
    protected: &ProtectedSecret,
) -> Result<Option<String>, AppError> {
    let value = match name {
        "id" => login.id.to_string(),
        "name" => login.display_headline.clone().unwrap_or_default(),
        "title" => login.title.clone(),
        "username" => login.username.clone(),
        "note" => login.note.clone(),
        "website" => login.websites.join(", "),
        "labels" => login.tags.join(", "),
        "created" => login.created.clone().unwrap_or_default(),
        "edited" => login.edited.clone().unwrap_or_default(),
        "password" => match &login.password {
            Some(p) => decrypt(protected, p)?,
            None => String::new(),
        },
        _ => return Ok(None),
    };
    Ok(Some(value))
}

/// A custom field's value, decrypted if it was protected.
fn resolve(value: &FieldValue, protected: &ProtectedSecret) -> Result<String, AppError> {
    match value {
        FieldValue::Plain(s) => Ok(s.clone()),
        FieldValue::Protected(p) => decrypt(protected, p),
    }
}

/// Open one `ProtectedValue`. An `isEmpty` value needs no key and is the empty
/// string.
fn decrypt(protected: &ProtectedSecret, value: &Protected) -> Result<String, AppError> {
    if value.is_empty {
        return Ok(String::new());
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(value.encrypted.trim())
        .map_err(|_| AppError::CorruptProtectedValue)?;
    let plaintext = protected.key().decrypt(&blob).map_err(AppError::Crypto)?;
    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

fn vault_err(vault: VaultId, what: &'static str) -> AppError {
    AppError::VaultContent {
        vault,
        source: heyl_vault::VaultError::NotADocument { what },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps)]
    fn some(s: &str) -> Option<String> {
        Some(s.to_owned())
    }

    #[test]
    fn a_bare_login_selector_is_enough() {
        let q = Query::from_flags(None, None, some("github.com"), None, None, None).expect("valid");
        assert!(matches!(q.vault, VaultSelector::Any));
        assert!(matches!(q.login, LoginSelector::Name(_)));
        assert!(matches!(q.field, FieldSelector::All));
    }

    #[test]
    fn no_login_selector_is_invalid() {
        let e = Query::from_flags(None, None, None, None, some("password"), None).unwrap_err();
        assert!(matches!(e, AppError::MissingLoginSelector));
        assert_eq!(e.exit_code() as u8, 7);
    }

    #[test]
    fn two_selectors_for_one_slot_conflict() {
        for flags in [
            Query::from_flags(some("a"), some("b"), some("x"), None, None, None),
            Query::from_flags(None, None, some("x"), some("y"), None, None),
            Query::from_flags(None, None, some("x"), None, some("f"), some("g")),
        ] {
            let e = flags.unwrap_err();
            assert!(matches!(e, AppError::ConflictingSelectors { .. }));
            assert_eq!(e.exit_code() as u8, 7);
        }
    }

    #[test]
    fn a_malformed_uuid_is_invalid_not_not_found() {
        let e = Query::from_flags(None, some("nope"), some("x"), None, None, None).unwrap_err();
        assert!(matches!(
            e,
            AppError::MalformedSelector { what: "--vault-id" }
        ));
        assert_eq!(e.exit_code() as u8, 7);
    }

    #[test]
    fn ids_that_parse_become_id_selectors() {
        let uuid = "6e577b16-1303-47c3-8579-37e59cb71276";
        let q = Query::from_flags(None, some(uuid), None, some(uuid), None, some(uuid))
            .expect("valid uuids");
        assert!(matches!(q.vault, VaultSelector::Id(_)));
        assert!(matches!(q.login, LoginSelector::Id(_)));
        assert!(matches!(q.field, FieldSelector::Id(_)));
    }
}
