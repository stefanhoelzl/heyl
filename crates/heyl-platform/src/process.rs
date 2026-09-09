//! Process-level memory hygiene.
//!
//! Two mitigations, and they are **not** redundant with each other.
//!
//! **`RLIMIT_CORE = 0`.** `mlock` does not keep a page out of a core dump —
//! locked pages are written into the core file like any other. So a crash with
//! a live seed in memory puts that seed on disk, in
//! `/var/lib/systemd/coredump` or wherever the OS collects them. That is the
//! seed at rest, which §3 says never happens. `[profile.release]` sets
//! `panic = "abort"`, so *every* panic becomes a SIGABRT: this is more likely
//! here than in a typical binary, not less.
//!
//! **`mlock`, and it is fatal if it fails.** §3 claims the seed never reaches
//! swap. If the lock failed, that claim is false, and continuing would ship a
//! weaker guarantee than README advertises — a warning on stderr in a tool
//! built for scripts and pipelines is not read by anyone. So the tool refuses
//! to run instead.
//!
//! The failure is rare enough for that to be reasonable: locking works at page
//! granularity, a handful of secrets is a handful of pages, and systemd has
//! defaulted `RLIMIT_MEMLOCK` to 8 MiB for years.

use heyl_crypto::SecretBytes;

/// The process could not be made safe to hold a seed in.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HardeningError {
    /// The OS refused to lock a page of memory.
    #[error(
        "cannot lock memory, so a secret could be written to swap.\n\
         heyl will not run without this. Raise RLIMIT_MEMLOCK \
         (`ulimit -l unlimited`, or LimitMEMLOCK= in a systemd unit)."
    )]
    CannotLockMemory,
}

/// Disable core dumps and confirm memory locking works.
///
/// Call once, at startup, before anything reaches for a secret.
///
/// # Errors
/// [`HardeningError::CannotLockMemory`] if `mlock` does not work, which is
/// fatal by design — see the module docs.
pub fn harden_process() -> Result<(), HardeningError> {
    disable_core_dumps();

    // Probe with a real locked buffer rather than trusting the limit: the
    // limit is not the only reason a lock can fail, and this is exactly the
    // allocation every secret in the process will make.
    let probe = SecretBytes::<32>::zeroed();
    if probe.is_locked() {
        Ok(())
    } else {
        Err(HardeningError::CannotLockMemory)
    }
}

/// `RLIMIT_CORE = 0`.
///
/// Best-effort: a platform that does not offer it leaves us no worse off, and
/// the locking probe above is the check that is allowed to be fatal.
#[cfg(unix)]
fn disable_core_dumps() {
    // SAFETY-adjacent note: `heyl-crypto` and every other crate here forbid
    // `unsafe`, and so does this one. `setrlimit` is reached through the safe
    // wrapper below rather than by relaxing that.
    set_core_limit_to_zero();
}

#[cfg(not(unix))]
fn disable_core_dumps() {
    // Windows writes minidumps through WER rather than RLIMIT_CORE; M11's
    // scope note covers it.
}

#[cfg(unix)]
fn set_core_limit_to_zero() {
    // `ulimit -c 0` for our own process, via the shell-free route: writing the
    // limit through /proc is not portable, so this uses the libc call in the
    // one place the workspace permits it -- see the crate's `[lints]` opt-in,
    // which still forbids `unsafe` here. `rlimit` provides a safe wrapper.
    let _ = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0);
}
