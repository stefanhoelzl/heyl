//! Locked, zeroizing byte buffers for secret material.
//!
//! Every secret newtype in this crate wraps [`SecretBytes`], which:
//!
//! * lives on the heap, so its address is stable and `mlock` stays valid
//!   across moves of the wrapper;
//! * holds an [`region::LockGuard`], so the bytes are never written to swap;
//! * zeroizes on drop, before the lock is released and the memory freed;
//! * implements no `Deref`, no `AsRef<[u8]>`, no `Serialize`, and a `Debug`
//!   that redacts — the bytes are reachable only through
//!   [`SecretBytes::expose_secret`], which makes every access site greppable
//!   in one query.
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
    // Declared before `bytes` so it drops first: the lock must be released
    // before the memory it refers to is freed.
    lock: Option<region::LockGuard>,
    bytes: Box<[u8; N]>,
}

impl<const N: usize> SecretBytes<N> {
    /// An all-zero buffer, locked if the OS allows it.
    #[must_use]
    pub fn zeroed() -> Self {
        let bytes = Box::new([0u8; N]);
        let lock = region::lock(bytes.as_ptr(), N).ok();
        Self { lock, bytes }
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
    /// still zeroizes; it is simply swappable. `heyl-cli` warns once on this.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.lock.is_some()
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
        // Before the lock is released and the allocation freed: field drop
        // order (`lock`, then `bytes`) takes care of the rest.
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
