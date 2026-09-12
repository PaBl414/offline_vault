//! Best-effort memory locking, isolated to a single module.
//!
//! This is the only module in the crate that is allowed to contain `unsafe`
//! code. It wraps exactly two platform operations:
//!
//!   * `mlock` / `munlock` on Unix-like systems,
//!   * `VirtualLock` / `VirtualUnlock` on Windows.
//!
//! Both are advisory with respect to the operating system's resource limits.
//! A failure here is *not* an application error: the caller must be able to
//! continue running without memory locking. For that reason, both functions
//! return `Result<bool>` where `Ok(false)` means "the platform refused or does
//! not support locking".
//!
//! The API takes a raw pointer and a length. The caller is responsible for
//! ensuring the pointer and length describe a live, owned allocation for the
//! duration of the call. [`crate::security::SecureBuffer`] is the intended
//! caller and satisfies that invariant.

use crate::error::Result;

/// Attempt to lock `len` bytes starting at `ptr` into RAM.
///
/// Returns `Ok(true)` if the platform performed the lock, `Ok(false)` if the
/// platform does not support locking or the OS refused (for example, the
/// process's `RLIMIT_MEMLOCK` is exhausted). Never returns an error merely
/// because locking was declined.
///
/// # Safety
///
/// The caller must ensure `ptr` is a valid pointer to at least `len`
/// initialized bytes in an allocation owned by the caller, and that the
/// allocation remains live for the duration of this call.
pub fn lock(ptr: *const u8, len: usize) -> Result<bool> {
    if len == 0 {
        return Ok(false);
    }
    platform::lock(ptr, len)
}

/// Reverse of [`lock`]. Best-effort, same semantics.
///
/// # Safety
///
/// Same requirements as [`lock`]. It is not an error to call `unlock` on a
/// range that was never locked; the OS will simply report success or failure
/// and both outcomes are ignored by the caller.
pub fn unlock(ptr: *const u8, len: usize) -> Result<bool> {
    if len == 0 {
        return Ok(false);
    }
    platform::unlock(ptr, len)
}

// ---------------------------------------------------------------------------
// Unix implementation
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod platform {
    use super::Result;

    #[allow(unsafe_code)]
    pub fn lock(ptr: *const u8, len: usize) -> Result<bool> {
        // SAFETY: the caller contract guarantees `ptr` points to `len` live,
        // owned bytes. `mlock` only reads the address range to establish
        // page residency; it does not dereference through the pointer in a
        // way that requires the memory to be initialized beyond what the
        // caller already guarantees.
        let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
        Ok(rc == 0)
    }

    #[allow(unsafe_code)]
    pub fn unlock(ptr: *const u8, len: usize) -> Result<bool> {
        // SAFETY: identical to `lock`. `munlock` only uses the address range
        // to release page residency.
        let rc = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
        Ok(rc == 0)
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use super::Result;
    use winapi::shared::basetsd::SIZE_T;
    use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};

    #[allow(unsafe_code)]
    pub fn lock(ptr: *const u8, len: usize) -> Result<bool> {
        // SAFETY: the caller contract guarantees `ptr` points to `len` live,
        // owned bytes. `VirtualLock` only uses the address range to establish
        // residency of the containing pages.
        let ok = unsafe { VirtualLock(ptr as *mut _, len as SIZE_T) };
        Ok(ok != 0)
    }

    #[allow(unsafe_code)]
    pub fn unlock(ptr: *const u8, len: usize) -> Result<bool> {
        // SAFETY: identical to `lock`.
        let ok = unsafe { VirtualUnlock(ptr as *mut _, len as SIZE_T) };
        Ok(ok != 0)
    }
}

// ---------------------------------------------------------------------------
// Fallback for platforms with neither `mlock` nor `VirtualLock`
// ---------------------------------------------------------------------------

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::Result;

    pub fn lock(_ptr: *const u8, _len: usize) -> Result<bool> {
        Ok(false)
    }

    pub fn unlock(_ptr: *const u8, _len: usize) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_is_a_noop() {
        assert!(!lock(std::ptr::null(), 0).unwrap());
        assert!(!unlock(std::ptr::null(), 0).unwrap());
    }

    #[test]
    fn lock_unlock_roundtrip_on_live_buffer() {
        // Exercise the platform path against a real heap allocation. Failure
        // to lock (e.g. working-set quota on Windows, RLIMIT_MEMLOCK on
        // Unix) is acceptable; the test only asserts that neither call
        // panics or returns an error.
        let mut v = vec![0u8; 4096];
        let ptr = v.as_ptr();
        let len = v.len();
        let locked = lock(ptr, len).expect("lock must not error");
        // Whether `locked` is true or false is environment dependent.
        let unlocked = unlock(ptr, len).expect("unlock must not error");
        // If we locked, we must be able to unlock. If the platform refused to
        // lock, unlocking is still allowed to succeed or fail.
        if locked {
            assert!(unlocked);
        }
        // Prevent the compiler from eliminating the buffer before the calls.
        v[0] = 1;
        std::hint::black_box(&v);
    }
}
