//! The system clock.

use heyl_domain::Timestamp;
use heyl_ports::Clock;

/// Wall-clock time from the OS.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[async_trait::async_trait]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_jiff(jiff::Timestamp::now())
    }

    fn next_unlock_deadline(&self) -> Timestamp {
        next_unlock_deadline_from(jiff::Timestamp::now(), &jiff::tz::TimeZone::system())
    }

    async fn sleep_millis(&self, millis: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
    }
}

/// heylogin's `unlockUtils.getUnlockTime()` (§6), replicated exactly:
///
/// ```js
/// const date = new Date(new Date().getTime() + 86_400_000); // tomorrow
/// date.setHours(2, 0, 0, 0);                                // at 2am
/// ```
///
/// Three details, all of which matter and none of which are what you would
/// write from the prose description:
///
/// * It is **always tomorrow's** 02:00, never today's. Run at 01:00 it returns
///   a deadline 25 hours away, not one hour away. "The next 02:00" is the
///   natural reading and it is wrong.
/// * The 02:00 is **local**, because `setHours` is local. Computing it in UTC
///   would expire our grants at an hour the user does not expect, and would
///   disagree with every other client on the account.
/// * The offset is exactly 86,400,000 ms — an absolute day, not a calendar
///   one. Across a DST transition those differ, and matching the other clients
///   matters more here than being calendrically tidy.
///
/// Takes its inputs explicitly so the behaviour is testable without waiting
/// for 02:00 or moving the machine's timezone.
#[must_use]
pub fn next_unlock_deadline_from(now: jiff::Timestamp, tz: &jiff::tz::TimeZone) -> Timestamp {
    let Some(tomorrow) = now.as_millisecond().checked_add(86_400_000) else {
        return Timestamp::from_jiff(now);
    };
    let Ok(tomorrow) = jiff::Timestamp::from_millisecond(tomorrow) else {
        return Timestamp::from_jiff(now);
    };

    let at_two = tomorrow
        .to_zoned(tz.clone())
        .with()
        .hour(2)
        .minute(0)
        .second(0)
        .subsec_nanosecond(0)
        .build();

    at_two.map_or(Timestamp::from_jiff(now), |z| {
        Timestamp::from_jiff(z.timestamp())
    })
}
