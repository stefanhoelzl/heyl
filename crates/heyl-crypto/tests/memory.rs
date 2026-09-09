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

/// Locks are released on drop, so a long-running process cannot exhaust
/// `RLIMIT_MEMLOCK` by deriving many keys.
#[test]
fn locks_are_released_when_secrets_are_dropped() {
    let Some(limit) = memlock_limit() else { return };
    if limit < 64 * 1024 {
        return;
    }
    // Far more locks than the limit could hold simultaneously if they leaked:
    // a page each against an 8 MiB limit is ~2048.
    for i in 0..5000u32 {
        let seed = Seed::from_bytes(&[u8::try_from(i % 256).expect("in range"); 32]);
        assert!(
            seed.is_locked(),
            "lock failed on iteration {i}; guards are leaking"
        );
    }
}
