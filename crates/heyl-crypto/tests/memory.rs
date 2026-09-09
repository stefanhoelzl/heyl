//! Memory hygiene: DESIGN.md §3's claim that the seed is never at rest.
//!
//! A swapped page is a copy of the seed on disk, so `mlock` is not a nicety
//! here — it is what makes the claim true between the moment the seed is
//! decrypted and the moment the process exits.

use heyl_crypto::{Seed, SymKey};

/// The governing limit, in bytes; `None` when it cannot be determined or is
/// unlimited.
#[cfg(target_os = "linux")]
fn memlock_limit() -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = limits.lines().find(|l| l.contains("locked memory"))?;
    let soft = line.split_whitespace().nth(3)?;
    soft.parse().ok()
}

#[cfg(not(target_os = "linux"))]
fn memlock_limit() -> Option<u64> {
    None
}

/// Where the OS allows locking at all, every secret buffer must actually be
/// locked — not merely have asked to be.
///
/// Guarded by the limit rather than asserted unconditionally, so a container
/// with a tiny `RLIMIT_MEMLOCK` reports an environment fact instead of a false
/// failure. One page is plenty for a 32-byte buffer.
#[test]
fn secrets_are_locked_where_the_os_permits_it() {
    let Some(limit) = memlock_limit() else {
        return; // unlimited, or not determinable on this platform
    };
    if limit < 64 * 1024 {
        eprintln!("skipped: RLIMIT_MEMLOCK is {limit} bytes, too low to lock a page");
        return;
    }

    assert!(
        Seed::from_bytes(&[1u8; 32]).is_locked(),
        "seed should be mlocked"
    );
    assert!(
        SymKey::from_bytes(&[2u8; 32]).is_locked(),
        "symmetric key should be mlocked"
    );
}

/// When locking is refused the buffer must still be usable: `heyl-cli` warns,
/// it does not abort. This is the fallback DESIGN.md §4 promises.
#[test]
fn a_secret_works_whether_or_not_locking_succeeded() {
    let key = SymKey::from_bytes(&[3u8; 32]);
    let blob = key.encrypt(&heyl_crypto::Nonce::from_bytes([4u8; 24]), b"payload");
    let opened = key
        .decrypt(&blob)
        .expect("round trips regardless of lock state");
    assert_eq!(opened.as_slice(), b"payload");
}

/// Locks are never released, so a long-running process must not exhaust
/// `RLIMIT_MEMLOCK` by deriving many keys.
///
/// This replaces an earlier test that asserted the opposite — that locks are
/// released on drop — which is the behaviour that turned out to unlock pages
/// under still-live secrets. The property it was protecting is still worth
/// protecting; it just holds for a different reason now. `mlock` is
/// page-granular and 32-byte allocations cluster in one size class, so
/// churning secrets re-locks a page that is already locked rather than
/// consuming a new one.
#[test]
fn many_secrets_lock_few_pages() {
    let Some(limit) = memlock_limit() else { return };
    if limit < 64 * 1024 {
        return;
    }
    // If every iteration consumed a fresh page this would need ~5000 of them,
    // well past the ~2048 an 8 MiB limit affords.
    for i in 0..5000u32 {
        let seed = Seed::from_bytes(&[u8::try_from(i % 256).expect("in range"); 32]);
        assert!(
            seed.is_locked(),
            "lock failed on iteration {i}; the locked set is growing per secret"
        );
    }
}

/// Whether the page holding `addr` is locked, per `/proc/self/smaps`.
///
/// `mlock` splits the enclosing VMA, so the mapping containing a locked page
/// reports a non-zero `Locked:` and carries `lo` in `VmFlags`.
#[cfg(target_os = "linux")]
fn page_is_locked(addr: usize) -> Option<bool> {
    let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
    let mut current: Option<bool> = None;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ')
            && let Some((lo, hi)) = range.split_once('-')
            && let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
        {
            current = Some(addr >= lo && addr < hi);
            continue;
        }
        if current == Some(true)
            && let Some(rest) = line.strip_prefix("Locked:")
        {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb > 0);
        }
    }
    None
}

/// The regression this file exists for: dropping one secret must not unlock
/// the page a different, still-live secret is sitting on.
///
/// `mlock` is page-granular, so a handful of 32-byte secrets share one page.
/// Releasing a lock on drop unlocked that page for all of them — silently
/// here, and on Windows as an `ERROR_NOT_LOCKED` panic out of
/// `region::LockGuard::drop`. Nothing in the suite caught it until the
/// cross-platform matrix ran the tests on Windows.
#[cfg(target_os = "linux")]
#[test]
fn dropping_a_secret_leaves_its_neighbours_locked() {
    let Some(limit) = memlock_limit() else { return };
    if limit < 64 * 1024 {
        return;
    }

    // Enough to be confident two of them share a page: ~56 fit in 4 KiB.
    let mut secrets: Vec<Seed> = (0u8..64).map(|i| Seed::from_bytes(&[i; 32])).collect();
    let Some(survivor) = secrets.last() else {
        unreachable!("just built 64")
    };
    let watched = survivor.expose_secret().as_ptr() as usize;
    let Some(true) = page_is_locked(watched) else {
        eprintln!("skipped: smaps does not report the page as locked to begin with");
        return;
    };

    // Drop every other secret, including any sharing the watched page.
    secrets.truncate(1);
    secrets.shrink_to_fit();

    assert_eq!(
        page_is_locked(watched),
        Some(true),
        "dropping neighbouring secrets unlocked the page under a live one"
    );
    assert!(secrets[0].is_locked(), "the survivor still reports locked");
}
