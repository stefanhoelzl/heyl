//! `getUnlockTime()`, replicated from the shipped client source.
//!
//! ```js
//! const date = new Date(new Date().getTime() + 86_400_000); // tomorrow
//! date.setHours(2, 0, 0, 0);                                // at 2am
//! ```
//!
//! Every one of these tests exists because the natural reading of §6's prose —
//! "next day at 02:00" — produces a different instant from what the client
//! actually computes.

use heyl_platform::clock::next_unlock_deadline_from;

fn utc() -> jiff::tz::TimeZone {
    jiff::tz::TimeZone::UTC
}

fn at(s: &str) -> jiff::Timestamp {
    s.parse().expect("valid timestamp")
}

/// Run at midday, the deadline is the following day at 02:00.
#[test]
fn from_midday_it_is_tomorrow_at_two() {
    let deadline = next_unlock_deadline_from(at("2026-09-09T12:00:00Z"), &utc());
    assert_eq!(deadline.to_string(), "2026-09-10T02:00:00.000Z");
}

/// The one that catches the obvious implementation. At 01:00 the *next* 02:00
/// is one hour away — but the client adds a day first, so the real answer is
/// 25 hours away.
#[test]
fn from_one_am_it_is_still_tomorrow_not_the_two_am_an_hour_away() {
    let deadline = next_unlock_deadline_from(at("2026-09-09T01:00:00Z"), &utc());
    assert_eq!(
        deadline.to_string(),
        "2026-09-10T02:00:00.000Z",
        "getUnlockTime always adds 86_400_000 ms before setting the hour"
    );
}

/// Exactly at 02:00, likewise: tomorrow.
#[test]
fn at_exactly_two_am_it_is_tomorrow() {
    let deadline = next_unlock_deadline_from(at("2026-09-09T02:00:00Z"), &utc());
    assert_eq!(deadline.to_string(), "2026-09-10T02:00:00.000Z");
}

/// Late in the evening it is the next calendar day, which is the case the
/// prose describes and the only one where prose and code agree.
#[test]
fn from_late_evening_it_is_the_next_calendar_day() {
    let deadline = next_unlock_deadline_from(at("2026-09-09T23:30:00Z"), &utc());
    assert_eq!(deadline.to_string(), "2026-09-10T02:00:00.000Z");
}

/// `setHours` is local, so the deadline lands at 02:00 *in the user's zone* —
/// not at 02:00 UTC. Berlin is UTC+2 in September, so 02:00 local is 00:00Z.
#[test]
fn the_two_am_is_local_not_utc() {
    let berlin = jiff::tz::TimeZone::get("Europe/Berlin").expect("tzdb has Berlin");
    let deadline = next_unlock_deadline_from(at("2026-09-09T12:00:00Z"), &berlin);
    assert_eq!(
        deadline.to_string(),
        "2026-09-10T00:00:00.000Z",
        "02:00 Berlin time is 00:00Z in September"
    );
}

/// The offset is an absolute 86,400,000 ms rather than a calendar day. Across
/// a DST transition the two differ, and matching the other clients on the
/// account matters more than being calendrically tidy.
#[test]
fn the_offset_is_an_absolute_day_across_a_dst_transition() {
    let berlin = jiff::tz::TimeZone::get("Europe/Berlin").expect("tzdb has Berlin");
    // Europe/Berlin leaves DST on 2026-10-25 at 03:00 local.
    let deadline = next_unlock_deadline_from(at("2026-10-24T12:00:00Z"), &berlin);
    assert_eq!(
        deadline.to_string(),
        "2026-10-25T01:00:00.000Z",
        "02:00 Berlin on the 25th is 01:00Z, after the clocks go back"
    );
}
