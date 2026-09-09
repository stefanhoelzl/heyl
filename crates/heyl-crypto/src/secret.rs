//! Locked, zeroizing byte buffers for secret material.
//!
//! Every secret newtype in this crate wraps [`SecretBytes`], which:
//!
//! * lives on the heap, so its address is stable and `mlock` stays valid
//!   across moves of the wrapper;
//! * is `mlock`ed, so the bytes are never written to swap, and **the lock is
//!   never released** — see below;
//! * zeroizes on drop, before the memory is freed;
//! * implements no `Deref`, no `AsRef<[u8]>`, no `Serialize`, and a `Debug`
//!   that redacts — the bytes are reachable only through
//!   [`SecretBytes::expose_secret`], which makes every access site greppable
//!   in one query.
//!
//! **Why the lock is never released.** `mlock` works on whole pages, and a
//! 32-byte buffer shares its page with other secrets. `region::lock` rounds the
//! address down and the size up to page boundaries, and `region::unlock`'s own
//! documentation warns that "unlocking one mapping may unlock another mapping
//! that shares the same page". Releasing a lock on drop therefore unlocked
//! pages that *other, still-live* secrets were sitting on — silently on Linux
//! and macOS, and on Windows loudly, because `VirtualUnlock` keeps no lock
//! count and fails with `ERROR_NOT_LOCKED` the second time. The guarantee §3
//! claims was not holding.
//!
//! So the guard is deliberately leaked with [`core::mem::forget`]. Locking for
//! longer than strictly necessary is the safe direction for a property that
//! means "never swapped while live", and the cost is bounded: 32-byte
//! allocations cluster in one allocator size class, so churning thousands of
//! secrets touches a single page, and a `heyl doctor` run with dozens live at
//! once touches three. Both are far under Windows' lockable-page ceiling,
//! which is its minimum working set (~50 pages) less overhead.
//!
//! `mlock` can fail — most often `RLIMIT_MEMLOCK` on a constrained system.
//! That is not fatal and this crate does not report it, because a leaf crate
//! with no I/O has nowhere to report to; [`SecretBytes::is_locked`] exposes it
//! so `heyl-cli` can warn once at startup.
//!
//! Core-dump exclusion is deliberately *not* here: it is a process-wide
//! concern that `heyl-cli` handles with `RLIMIT_CORE = 0`, rather than a
//! `madvise` call pushed into the leaf crypto crate.

use core::fmt;

use zeroize::Zeroize;

use crate::error::CryptoError;

/// A fixed-size buffer of secret bytes: heap-allocated, `mlock`ed, zeroizing.
pub struct SecretBytes<const N: usize> {
    // Whether `mlock` succeeded, not a guard: the lock is never released, so
    // there is nothing to hold. See the module docs.
    locked: bool,
    bytes: Box<[u8; N]>,
}

impl<const N: usize> SecretBytes<N> {
    /// An all-zero buffer, locked if the OS allows it.
    #[must_use]
    pub fn zeroed() -> Self {
        let bytes = Box::new([0u8; N]);
        // Leaked on purpose: dropping the guard would unlock the whole page,
        // including any other live secret on it. Module docs have the full
        // reasoning. `forget` is safe, so `unsafe_code = "forbid"` still holds.
        let locked = match region::lock(bytes.as_ptr(), N) {
            Ok(guard) => {
                core::mem::forget(guard);
                true
            }
            Err(_) => false,
        };
        Self { locked, bytes }
    }

    /// Copy `bytes` into a fresh locked buffer.
    ///
    /// The caller's copy is theirs to zeroize; this cannot do it for them.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; N]) -> Self {
        let mut this = Self::zeroed();
        this.bytes.copy_from_slice(bytes);
        this
    }

    /// Copy a slice into a fresh locked buffer.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if `slice` is not exactly `N` bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != N {
            return Err(CryptoError::BadLength {
                len: slice.len(),
                expected: N,
            });
        }
        let mut this = Self::zeroed();
        this.bytes.copy_from_slice(slice);
        Ok(this)
    }

    /// The secret bytes.
    ///
    /// Named so that every site that touches key material greps in one query.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Whether the buffer is actually `mlock`ed.
    ///
    /// `false` means the OS refused — typically `RLIMIT_MEMLOCK`. The buffer
    /// still zeroizes; it is simply swappable. `heyl-cli` refuses to start in
    /// that case rather than warning — see `heyl_platform::process`.
    ///
    /// `true` can also mean the page was already locked by an earlier secret.
    /// That is the same guarantee, not a weaker one.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Fill the buffer in place. Internal: keeps secrets off the stack.
    pub(crate) fn fill_from(&mut self, src: &[u8]) {
        self.bytes.copy_from_slice(src);
    }
}

impl<const N: usize> Clone for SecretBytes<N> {
    fn clone(&self) -> Self {
        Self::from_bytes(&self.bytes)
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        // Before the allocation is freed. The lock outlives this and every
        // other secret on the page, deliberately — see the module docs.
        self.bytes.zeroize();
    }
}

/// Redacts. There is no way to get bytes out of a formatter.
impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(<redacted>)")
    }
}

/// Non-short-circuiting, like heylogin's own `uint8ArrayEqual`.
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..N {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        diff == 0
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}
