//! The current instant.

use heyl_domain::Timestamp;

/// Wall-clock time, as a port.
///
/// Not an OS abstraction — it is here so every timestamp is deterministic under
/// test. That matters most for §4's byte-exact `updateTime`, where heymerge
/// resolves conflicts by *lexicographic string comparison* and a merge silently
/// goes the wrong way if the instant or its formatting is off (DESIGN.md §4).
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Timestamp;

    /// The next 02:00 in the **local** timezone, strictly after `now`.
    ///
    /// heylogin's `unlockUtils.getUnlockTime()` — the hard cap on a session
    /// unlock (§6). Local rather than UTC because that is what the phone and
    /// the browser compute, and asking for a different instant than every other
    /// client would make our grants expire at a time the user does not expect.
    fn next_unlock_deadline(&self) -> Timestamp;
}
