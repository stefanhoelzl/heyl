//! Timestamps whose only formatting is the one heymerge can compare.
//!
//! heymerge resolves conflicts with `leftUpdateTime > rightUpdateTime` — a
//! **lexicographic string comparison**. So the serialised form is semantic,
//! not cosmetic: it must be byte-compatible with JavaScript's
//! `Date.toISOString()`, which is always UTC, always a literal `Z`, and always
//! exactly three fractional digits.
//!
//! Emit `+00:00` instead of `Z`, or nanosecond precision instead of
//! milliseconds, and ordering against other clients' timestamps breaks in a
//! way that stays invisible until a merge silently goes the wrong way.
//!
//! [`Timestamp`] therefore has exactly one `Display`, and no way to reach a
//! differently formatted string.

use core::fmt;

use jiff::{Timestamp as JiffTimestamp, tz::TimeZone};

/// A timestamp that formats the way heymerge needs and no other way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(JiffTimestamp);

/// A string that was supposed to be a timestamp and was not.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a valid timestamp: {value:?}")]
pub struct ParseTimestampError {
    /// The rejected input.
    pub value: String,
}

impl Timestamp {
    /// Wrap an instant.
    #[must_use]
    pub const fn from_jiff(ts: JiffTimestamp) -> Self {
        Self(ts)
    }

    /// The underlying instant.
    #[must_use]
    pub const fn as_jiff(&self) -> JiffTimestamp {
        self.0
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub fn as_millisecond(&self) -> i64 {
        self.0.as_millisecond()
    }

    /// Build from milliseconds since the Unix epoch.
    ///
    /// # Errors
    /// [`ParseTimestampError`] if the value is outside the representable range.
    pub fn from_millisecond(ms: i64) -> Result<Self, ParseTimestampError> {
        JiffTimestamp::from_millisecond(ms)
            .map(Self)
            .map_err(|_| ParseTimestampError {
                value: ms.to_string(),
            })
    }

    /// Parse a timestamp as written by any heylogin client.
    ///
    /// # Errors
    /// [`ParseTimestampError`] if `s` is not an RFC 3339 timestamp.
    pub fn parse(s: &str) -> Result<Self, ParseTimestampError> {
        s.parse::<JiffTimestamp>()
            .map(Self)
            .map_err(|_| ParseTimestampError {
                value: s.to_owned(),
            })
    }

    /// Truncate to millisecond precision — the precision the wire format has.
    ///
    /// Applied by [`Display`](fmt::Display) anyway; exposed so that a value
    /// can be compared on the same footing as its serialised form.
    #[must_use]
    pub fn truncate_to_millis(self) -> Self {
        // as_millisecond() truncates toward zero, so round down explicitly for
        // pre-epoch instants; otherwise a value would sort after its own text.
        let ms = self.0.as_millisecond();
        let ms = if self.0.subsec_nanosecond() < 0 && self.0.subsec_nanosecond() % 1_000_000 != 0 {
            ms - 1
        } else {
            ms
        };
        JiffTimestamp::from_millisecond(ms).map_or(self, Self)
    }
}

/// `YYYY-MM-DDTHH:MM:SS.sssZ`, always — matching `Date.toISOString()`.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let truncated = self.truncate_to_millis();
        let dt = truncated.0.to_zoned(TimeZone::UTC).datetime();
        let millis = truncated.0.subsec_nanosecond() / 1_000_000;
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
            millis,
        )
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = <std::borrow::Cow<'_, str> as serde::Deserialize>::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}
