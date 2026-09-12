//! Secure-memory primitives.
//!
//! This module defines [`SecureBuffer`], a small wrapper around a mutable byte
//! vector that:
//!
//!   * owns its data and never shares it by reference after drop,
//!   * wipes its contents on drop using `zeroize`,
//!   * redacts itself in `Debug` output,
//!   * exposes controlled read/write access through `as_slice` / `as_mut_slice`,
//!   * optionally attempts best-effort memory locking through [`memory_lock`].
//!
//! It is deliberately not `Clone`. Copying a secret is an explicit decision the
//! caller must make, and it should be rare. Where a copy is genuinely needed,
//! [`SecureBuffer::duplicate`] makes the intent visible in the source.
//!
//! This module also exposes [`wipe`], a small helper for wiping a plain
//! `&mut [u8]` in place, used at the few call sites where a `SecureBuffer`
//! would be overkill (for example, wiping a scratch buffer provided by a
//! third-party API).

use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::memory_lock;

/// A mutable, owned buffer for sensitive byte data.
///
/// Guarantees:
///   * Contents are wiped on drop.
///   * `Debug` never reveals length-derived information beyond a fixed marker.
///   * No automatic `Clone`; use [`SecureBuffer::duplicate`] explicitly.
///
/// Not guaranteed:
///   * Complete removal of every copy from process memory. The OS, allocator,
///     and any intermediate buffers used by lower layers may retain copies.
///     This type minimizes the window in which the crate's own buffers hold
///     secrets, which is the strongest claim a portable library can make.
pub struct SecureBuffer {
    data: Vec<u8>,
    /// Whether we successfully locked this allocation in RAM. Recorded so we
    /// can attempt a matching unlock on drop, and so tests can assert the
    /// best-effort behavior.
    locked: bool,
}

impl SecureBuffer {
    /// Create an empty buffer with no pre-allocated capacity.
    pub fn new() -> Self {
        SecureBuffer {
            data: Vec::new(),
            locked: false,
        }
    }

    /// Create a zeroed buffer of the given length.
    pub fn zeroed(len: usize) -> Self {
        SecureBuffer {
            data: vec![0u8; len],
            locked: false,
        }
    }

    /// Take ownership of an existing `Vec<u8>`.
    ///
    /// The caller must ensure the vector is not aliased anywhere else; by
    /// taking ownership we guarantee that no other safe reference to the same
    /// allocation exists after this call returns.
    pub fn from_vec(data: Vec<u8>) -> Self {
        SecureBuffer { data, locked: false }
    }

    /// Create a buffer from a slice, copying the bytes into a fresh allocation.
    pub fn from_slice(data: &[u8]) -> Self {
        SecureBuffer {
            data: data.to_vec(),
            locked: false,
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Immutable view of the contents.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Mutable view of the contents.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consume the buffer and return the raw `Vec<u8>`.
    ///
    /// Use of this method transfers responsibility for wiping to the caller.
    /// It exists for interop with APIs that require an owned `Vec<u8>` (for
    /// example, some serializer paths). Prefer keeping data inside a
    /// `SecureBuffer` when possible.
    pub fn into_vec(mut self) -> Vec<u8> {
        // Prevent the Drop impl from wiping the allocation we are about to
        // hand out. `std::mem::take` leaves an empty Vec in its place, which
        // Drop will wipe harmlessly.
        let out = std::mem::take(&mut self.data);
        self.locked = false;
        out
    }

    /// Explicitly wipe the contents now, without waiting for drop.
    ///
    /// After this call, `len()` is preserved but every byte is zero.
    pub fn wipe(&mut self) {
        self.data.zeroize();
    }

    /// Explicitly duplicate the contents into a new `SecureBuffer`.
    ///
    /// This is the only sanctioned way to copy a `SecureBuffer`. It is
    /// deliberately a named method rather than a `Clone` impl so that copies
    /// are visible in code review.
    pub fn duplicate(&self) -> Self {
        SecureBuffer::from_slice(&self.data)
    }

    /// Attempt to lock the buffer's pages in RAM (best-effort).
    ///
    /// On Unix-like systems this calls `mlock`. On Windows it calls
    /// `VirtualLock`. If the platform does not support locking, or the OS
    /// refuses, this returns `Ok(false)` and the application continues. It is
    /// never an error for locking to fail.
    pub fn try_lock(&mut self) -> Result<bool> {
        if self.locked {
            return Ok(true);
        }
        let ok = memory_lock::lock(self.data.as_ptr(), self.data.len())?;
        if ok {
            self.locked = true;
        }
        Ok(ok)
    }
}

impl Default for SecureBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        if self.locked {
            // Best-effort unlock. A failure here is not actionable and must
            // not panic during drop.
            let _ = memory_lock::unlock(self.data.as_ptr(), self.data.len());
            self.locked = false;
        }
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print bytes or length. The marker is fixed so that even the
        // buffer's size cannot be inferred from a debug dump.
        f.write_str("SecureBuffer([REDACTED])")
    }
}

/// Wipe a plain mutable byte slice in place.
///
/// Used for third-party-owned scratch buffers where wrapping in a
/// `SecureBuffer` would require an unnecessary allocation.
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

/// Run a closure with access to the buffer's bytes and wipe a caller-provided
/// scratch buffer afterwards.
///
/// This is a convenience for the common pattern "decode into a scratch vec,
/// use it, then wipe". The closure gets a `&[u8]` view. The scratch slice is
/// wiped unconditionally on return, including on early return.
pub fn with_wiped_scratch<F, T>(scratch: &mut Vec<u8>, f: F) -> T
where
    F: FnOnce(&[u8]) -> T,
{
    let out = f(scratch.as_slice());
    scratch.zeroize();
    scratch.clear();
    out
}

/// Ensure a buffer is correctly sized for a cryptographic operation, returning
/// a uniform error otherwise. Used by call sites that validate externally
/// supplied lengths (for example, Base64-decoded fields from a vault file)
/// before feeding them to a primitive.
pub fn require_len(buf: &[u8], expected: usize) -> Result<()> {
    if buf.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_replaces_bytes() {
        let mut b = SecureBuffer::from_slice(b"topsecret");
        b.wipe();
        assert!(b.as_slice().iter().all(|&x| x == 0));
    }

    #[test]
    fn drop_wipes_contents() {
        // We verify the wipe path while the buffer is still live. Reading a
        // freed allocation would be undefined behavior and would not be a
        // sound test of what the type actually promises.
        let mut b = SecureBuffer::from_vec(b"0123456789abcdef".to_vec());
        assert_eq!(b.as_slice(), b"0123456789abcdef");
        b.wipe();
        assert!(b.as_slice().iter().all(|&x| x == 0));
        // Dropping now runs the drop-wipe path against an already-zeroed
        // buffer and must not panic.
        drop(b);
    }

    #[test]
    fn drop_on_untouched_buffer_does_not_panic() {
        let b = SecureBuffer::from_slice(b"left-as-is");
        assert_eq!(b.as_slice(), b"left-as-is");
        drop(b);
    }

    #[test]
    fn debug_is_redacted() {
        let b = SecureBuffer::from_slice(b"hunter2hunter2");
        let s = format!("{b:?}");
        assert!(!s.contains("hunter"));
        assert!(!s.contains("14"));
        assert!(s.contains("REDACTED"));
    }

    #[test]
    fn duplicate_copies_bytes() {
        let a = SecureBuffer::from_slice(b"abcdef");
        let mut b = a.duplicate();
        assert_eq!(a.as_slice(), b.as_slice());
        b.as_mut_slice()[0] = b'z';
        assert_eq!(a.as_slice()[0], b'a');
    }

    #[test]
    fn try_lock_is_best_effort() {
        let mut b = SecureBuffer::from_slice(b"lockme");
        // Must not error regardless of platform support; Ok(true) or Ok(false)
        // are both acceptable.
        let _ = b.try_lock().expect("try_lock must not fail");
    }

    #[test]
    fn require_len_accepts_exact_match() {
        assert!(require_len(&[0u8; 12], 12).is_ok());
        assert!(require_len(&[0u8; 11], 12).is_err());
        assert!(require_len(&[0u8; 13], 12).is_err());
    }

    #[test]
    fn with_wiped_scratch_clears_after_use() {
        let mut scratch = b"scratch-bytes".to_vec();
        let len = with_wiped_scratch(&mut scratch, |s| s.len());
        assert_eq!(len, 13);
        assert!(scratch.is_empty());
    }
}
