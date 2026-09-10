//! Reading and writing a session's settings.
//!
//! Four keys, split by what they cost. `display-name` is vault content, so
//! writing it needs this slot's own unlock; `timeout`, `strict` and
//! `auto-extend` ride on the session record behind the access token and work
//! on a session that is locked.
//!
//! `get` never unlocks. It prints what `Sync` knows and reports the vault-side
//! name as unavailable, so reading a slot's state can never reach your phone —
//! and `session list` stays safe to run in a loop.

use core::fmt;

use heyl_domain::{SessionPolicy, Timestamp};

use super::{DEFAULT_SLOT, Slot, adopt, write_policy};
use crate::{AppError, Ports, meta_vault};

/// The settings a slot has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Setting {
    /// What the phone shows, in the device list and on the approval screen.
    /// **Vault content**: writing it needs an unlock.
    DisplayName,
    /// `unlock_time_limit_minutes`, server-enforced.
    Timeout,
    /// Drop the unlock when the command exits.
    Strict,
    /// Slide the unlock window on use.
    AutoExtend,
}

impl Setting {
    /// Every key, for `get` with no key and for help text.
    pub const ALL: [Self; 4] = [
        Self::DisplayName,
        Self::Timeout,
        Self::Strict,
        Self::AutoExtend,
    ];

    /// Parse a key as the user typed it.
    ///
    /// # Errors
    /// [`AppError::UnknownSetting`] rather than a silent no-op: a typo that
    /// quietly changes nothing is worse than one that fails.
    pub fn parse(key: &str) -> Result<Self, AppError> {
        match key {
            "display-name" => Ok(Self::DisplayName),
            "timeout" => Ok(Self::Timeout),
            "strict" => Ok(Self::Strict),
            "auto-extend" => Ok(Self::AutoExtend),
            other => Err(AppError::UnknownSetting {
                key: other.to_owned(),
            }),
        }
    }

    /// The key as it is written.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DisplayName => "display-name",
            Self::Timeout => "timeout",
            Self::Strict => "strict",
            Self::AutoExtend => "auto-extend",
        }
    }

    /// Whether changing this needs the vault, and therefore an unlock.
    #[must_use]
    pub const fn needs_unlock(self) -> bool {
        matches!(self, Self::DisplayName)
    }
}

impl fmt::Display for Setting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What `session list` shows for one slot.
pub struct SlotStatus {
    /// The local name.
    pub slot: String,
    /// Whether the backend still knows this session.
    pub known: bool,
    /// When its unlock lapses, if it is unlocked.
    pub unlocked_until: Option<Timestamp>,
    /// Whether an unlock request is outstanding.
    pub unlock_requested: bool,
    /// The policy the session record carries.
    pub policy: Option<SessionPolicy>,
}

/// Change one setting.
///
/// # Errors
/// [`AppError::UnknownSetting`] for a key that does not exist,
/// [`AppError::BadSettingValue`] for a value the key cannot take, and whatever
/// the unlock or the commit fails with for `display-name`.
pub async fn set(
    ports: &Ports<'_>,
    slot: &Slot,
    setting: Setting,
    value: &str,
) -> Result<(), AppError> {
    let adopted = adopt(ports, slot).await?;

    if setting == Setting::DisplayName {
        // Vault content: this is the one setting that costs a swipe.
        let session = crate::unlock::run_for(ports, slot).await?;
        let mut meta = meta_vault::open(ports, &session).await?;
        heyl_vault::meta::set_description(
            &mut meta.document,
            adopted.session_id,
            value,
            ports.clock.now(),
        )
        .map_err(|e| AppError::VaultContent {
            vault: meta.id,
            source: e,
        })?;
        meta.commit(ports).await?;
        return Ok(());
    }

    let sync = ports.api.sync().await?;
    let session = sync
        .session(adopted.session_id)
        .ok_or(AppError::SessionGone)?;
    let mut policy =
        SessionPolicy::from_wire(session.unlock_time_limit_minutes, &session.client_settings);

    match setting {
        Setting::Timeout => policy.timeout_minutes = parse_timeout(value)?,
        Setting::Strict => policy.strict = parse_bool(value)?,
        Setting::AutoExtend => policy.auto_extend = parse_bool(value)?,
        Setting::DisplayName => unreachable!("handled above"),
    }

    write_policy(ports, adopted.session_id, policy, &session.client_settings).await
}

/// Read settings back.
///
/// Never unlocks: `display-name` is reported as vault-side rather than
/// fetched, so this is safe to run against a locked slot.
///
/// # Errors
/// [`AppError::SessionGone`] if the backend no longer knows this session.
pub async fn get(
    ports: &Ports<'_>,
    slot: &Slot,
    setting: Option<Setting>,
) -> Result<Vec<(Setting, Option<String>)>, AppError> {
    let adopted = adopt(ports, slot).await?;
    let sync = ports.api.sync().await?;
    let session = sync
        .session(adopted.session_id)
        .ok_or(AppError::SessionGone)?;
    let policy =
        SessionPolicy::from_wire(session.unlock_time_limit_minutes, &session.client_settings);

    let wanted = setting.map_or_else(|| Setting::ALL.to_vec(), |s| vec![s]);
    Ok(wanted
        .into_iter()
        .map(|key| {
            let value = match key {
                // Deliberately not fetched: reading must not reach the phone.
                Setting::DisplayName => None,
                Setting::Timeout => Some(render_timeout(policy.timeout_minutes)),
                Setting::Strict => Some(render_bool(policy.strict).to_owned()),
                Setting::AutoExtend => Some(render_bool(policy.auto_extend).to_owned()),
            };
            (key, value)
        })
        .collect())
}

/// Every local slot, with what `Sync` knows about it.
///
/// # Errors
/// [`AppError::Port`] if the slot index cannot be read.
pub async fn list(ports: &Ports<'_>, slots: &[String]) -> Result<Vec<SlotStatus>, AppError> {
    let mut out = Vec::with_capacity(slots.len());

    for name in slots {
        let slot = Slot::new(Some(name));
        let Ok(adopted) = adopt(ports, &slot).await else {
            continue;
        };
        // A rejected token means the session was deleted elsewhere — worth
        // showing as "gone" rather than dropping silently.
        let (known, unlocked_until, unlock_requested, policy) = match ports.api.sync().await {
            Ok(sync) => {
                sync.session(adopted.session_id)
                    .map_or((false, None, false, None), |session| {
                        (
                            true,
                            session.unlocked_until,
                            session.unlock_requested_at.is_some(),
                            Some(SessionPolicy::from_wire(
                                session.unlock_time_limit_minutes,
                                &session.client_settings,
                            )),
                        )
                    })
            }
            Err(_) => (false, None, false, None),
        };

        out.push(SlotStatus {
            slot: if name.is_empty() {
                DEFAULT_SLOT.to_owned()
            } else {
                name.clone()
            },
            known,
            unlocked_until,
            unlock_requested,
            policy,
        });
    }

    Ok(out)
}

/// `90s`, `30m`, `8h` — or a bare number, read as minutes.
///
/// The backend refuses anything under a minute (`DomainError 20482`), so this
/// does too, with the same reason rather than a shrug.
///
/// # Errors
/// [`AppError::BadSettingValue`] for a value with no reading,
/// [`AppError::TimeoutTooShort`] below the backend's floor.
pub fn parse_timeout(value: &str) -> Result<u32, AppError> {
    let bad = || AppError::BadSettingValue {
        key: Setting::Timeout.name(),
        value: value.to_owned(),
        expected: "a duration like 90s, 30m or 8h",
    };

    let (number, scale) = value.strip_suffix('s').map_or_else(
        || {
            value.strip_suffix('m').map_or_else(
                || {
                    value
                        .strip_suffix('h')
                        .map_or((value, 60), |rest| (rest, 3_600))
                },
                |rest| (rest, 60),
            )
        },
        |rest| (rest, 1),
    );

    let seconds = number
        .trim()
        .parse::<u64>()
        .map_err(|_| bad())?
        .checked_mul(scale)
        .ok_or_else(bad)?;

    let minutes = u32::try_from(seconds / 60).map_err(|_| bad())?;
    if minutes < heyl_domain::MIN_TIMEOUT_MINUTES {
        return Err(AppError::TimeoutTooShort {
            minimum: heyl_domain::MIN_TIMEOUT_MINUTES,
        });
    }
    Ok(minutes)
}

fn render_timeout(minutes: u32) -> String {
    if minutes.is_multiple_of(60) {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

fn parse_bool(value: &str) -> Result<bool, AppError> {
    match value {
        "on" | "yes" | "true" => Ok(true),
        "off" | "no" | "false" => Ok(false),
        other => Err(AppError::BadSettingValue {
            key: "boolean",
            value: other.to_owned(),
            expected: "on or off",
        }),
    }
}

const fn render_bool(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations_with_units() {
        assert_eq!(parse_timeout("8h").expect("valid"), 480);
        assert_eq!(parse_timeout("30m").expect("valid"), 30);
        assert_eq!(parse_timeout("120s").expect("valid"), 2);
        assert_eq!(
            parse_timeout("60").expect("valid"),
            60,
            "bare means minutes"
        );
    }

    /// The backend's floor, refused with its own reason rather than a shrug.
    #[test]
    fn refuses_anything_under_a_minute() {
        assert!(matches!(
            parse_timeout("30s"),
            Err(AppError::TimeoutTooShort { minimum: 1 })
        ));
        assert!(matches!(
            parse_timeout("0m"),
            Err(AppError::TimeoutTooShort { .. })
        ));
    }

    #[test]
    fn rejects_nonsense() {
        assert!(parse_timeout("soon").is_err());
        assert!(parse_timeout("").is_err());
    }

    #[test]
    fn renders_round_hours_as_hours() {
        assert_eq!(render_timeout(480), "8h");
        assert_eq!(render_timeout(1), "1m");
        assert_eq!(render_timeout(90), "90m");
    }

    #[test]
    fn booleans_take_the_obvious_spellings() {
        for yes in ["on", "yes", "true"] {
            assert!(parse_bool(yes).expect("valid"));
        }
        for no in ["off", "no", "false"] {
            assert!(!parse_bool(no).expect("valid"));
        }
        assert!(parse_bool("maybe").is_err());
    }

    #[test]
    fn only_the_display_name_costs_an_unlock() {
        assert!(Setting::DisplayName.needs_unlock());
        for cheap in [Setting::Timeout, Setting::Strict, Setting::AutoExtend] {
            assert!(!cheap.needs_unlock(), "{cheap} should not need an unlock");
        }
    }

    #[test]
    fn unknown_keys_are_an_error_not_a_no_op() {
        assert!(matches!(
            Setting::parse("displayname"),
            Err(AppError::UnknownSetting { .. })
        ));
    }
}
