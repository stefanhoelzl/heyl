//! The system clock.

use heyl_domain::Timestamp;
use heyl_ports::Clock;

/// Wall-clock time from the OS.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_jiff(jiff::Timestamp::now())
    }

    fn next_unlock_deadline(&self) -> Timestamp {
        next_unlock_deadline_from(jiff::Timestamp::now(), &jiff::tz::TimeZone::system())
    }
}

/// The next 02:00 strictly after `now`, in `tz`.
///
/// heylogin's `unlockUtils.getUnlockTime()` (§6). **Local**, not UTC: it is
/// what the phone and the browser compute, and asking for a different instant
/// than every other client would expire our grants at a time the user does not
/// expect.
///
/// Split out and taking its inputs explicitly so the rollover is testable
/// without waiting for 02:00.
#[must_use]
pub fn next_unlock_deadline_from(now: jiff::Timestamp, tz: &jiff::tz::TimeZone) -> Timestamp {
    let local = now.to_zoned(tz.clone());
    let today_at_two = local
        .with()
        .hour(2)
        .minute(0)
        .second(0)
        .subsec_nanosecond(0)
        .build();

    let deadline = match today_at_two {
        // Before 02:00 today: today's is still ahead of us.
        Ok(candidate) if candidate.timestamp() > now => candidate,
        // Otherwise tomorrow's. `checked_add` on a zoned value handles the DST
        // transitions that make "add 24 hours" wrong twice a year.
        Ok(candidate) => candidate
            .checked_add(jiff::Span::new().days(1))
            .unwrap_or(candidate),
        Err(_) => return Timestamp::from_jiff(now),
    };

    Timestamp::from_jiff(deadline.timestamp())
}
