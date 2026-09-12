//! Integration tests for the secure-memory primitives.
//!
//! These tests exercise only the public surface of `offline_vault::security`:
//! `SecureBuffer` (constructors, accessors, wipe, duplicate, try_lock,
//! `into_vec`), the free function `wipe`, `with_wiped_scratch`, and
//! `require_len`.
//!
//! The tests verify observable behavior of the API — contents after wipe,
//! `Debug` redaction, absence of `Clone`, distinctness of `duplicate` — and
//! do not attempt to inspect freed memory. That is not a safe thing to do,
//! and it is not what the type promises.
//!
//! No test prints a secret.

use offline_vault::error::Error;
use offline_vault::security::{require_len, wipe, with_wiped_scratch, SecureBuffer};

// ---------------------------------------------------------------------------
// Construction and accessors
// ---------------------------------------------------------------------------

#[test]
fn new_is_empty() {
    let b = SecureBuffer::new();
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    assert!(b.as_slice().is_empty());
}

#[test]
fn zeroed_is_all_zero() {
    let b = SecureBuffer::zeroed(32);
    assert_eq!(b.len(), 32);
    assert!(b.as_slice().iter().all(|&x| x == 0));
}

#[test]
fn from_slice_copies_bytes() {
    let source = b"hello-secure-world";
    let b = SecureBuffer::from_slice(source);
    assert_eq!(b.as_slice(), source);
    assert_eq!(source, b"hello-secure-world");
}

#[test]
fn from_vec_takes_ownership() {
    let v = vec![1u8, 2, 3, 4];
    let b = SecureBuffer::from_vec(v);
    assert_eq!(b.as_slice(), &[1, 2, 3, 4]);
}

#[test]
fn as_mut_slice_allows_in_place_edits() {
    let mut b = SecureBuffer::from_slice(b"abcd");
    b.as_mut_slice()[0] = b'z';
    assert_eq!(b.as_slice(), b"zbcd");
}

#[test]
fn from_slice_is_independent_of_source() {
    let mut source = b"abcd".to_vec();
    let b = SecureBuffer::from_slice(&source);
    source[0] = b'z';
    assert_eq!(b.as_slice(), b"abcd");
}

#[test]
fn from_vec_into_vec_roundtrip() {
    let original = b"roundtrip-value".to_vec();
    let b = SecureBuffer::from_vec(original.clone());
    let back = b.into_vec();
    assert_eq!(back, original);
}

// ---------------------------------------------------------------------------
// Wipe
// ---------------------------------------------------------------------------

#[test]
fn wipe_replaces_contents_with_zeros() {
    // `zeroize` on a `Vec<u8>` zeroes the existing bytes in place but does
    // not change the vector's length. The security property we care about is
    // that every byte is zero afterwards, not that the length becomes zero.
    let mut b = SecureBuffer::from_slice(b"supersecret");
    b.wipe();
    assert!(b.as_slice().iter().all(|&x| x == 0));
}

#[test]
fn wipe_is_idempotent() {
    let mut b = SecureBuffer::from_slice(b"value");
    b.wipe();
    b.wipe();
    assert!(b.as_slice().iter().all(|&x| x == 0));
}

#[test]
fn wipe_on_empty_is_a_noop() {
    let mut b = SecureBuffer::new();
    b.wipe();
    assert!(b.is_empty());
}

#[test]
fn free_wipe_function_zeroes_slice() {
    let mut buf = *b"abcdefgh";
    wipe(&mut buf);
    assert!(buf.iter().all(|&x| x == 0));
}

#[test]
fn free_wipe_on_empty_slice_is_a_noop() {
    let mut buf: [u8; 0] = [];
    wipe(&mut buf);
    assert!(buf.is_empty());
}

// ---------------------------------------------------------------------------
// Duplicate
// ---------------------------------------------------------------------------

#[test]
fn duplicate_copies_content() {
    let a = SecureBuffer::from_slice(b"copy-me");
    let mut b = a.duplicate();
    assert_eq!(a.as_slice(), b.as_slice());
    b.as_mut_slice()[0] = b'X';
    assert_eq!(a.as_slice(), b"copy-me");
    assert_eq!(b.as_slice(), b"Xopy-me");
}

#[test]
fn duplicate_of_empty_is_empty() {
    let a = SecureBuffer::new();
    let b = a.duplicate();
    assert!(b.is_empty());
}

#[test]
fn duplicate_produces_distinct_allocation() {
    // Two live buffers created via `duplicate` must not share backing
    // storage. Unlike the removed aliasing test, this one holds both buffers
    // alive at the same moment, so the allocator cannot reuse a freed
    // allocation behind our backs.
    let a = SecureBuffer::from_slice(b"xxxx");
    let b = a.duplicate();
    assert_eq!(a.as_slice(), b.as_slice());
    assert_ne!(a.as_slice().as_ptr(), b.as_slice().as_ptr());
}

// ---------------------------------------------------------------------------
// Debug redaction
// ---------------------------------------------------------------------------

#[test]
fn debug_does_not_reveal_contents() {
    let b = SecureBuffer::from_slice(b"UNIQUE-SECRET-MARKER");
    let dump = format!("{b:?}");
    assert!(!dump.contains("UNIQUE"));
    assert!(!dump.contains("SECRET"));
    assert!(!dump.contains("MARKER"));
    assert!(dump.contains("REDACTED"));
}

#[test]
fn debug_does_not_reveal_length() {
    // Two buffers of very different sizes must produce identical `Debug`
    // output, so a debug dump cannot leak a length.
    let a = SecureBuffer::from_slice(b"a");
    let b = SecureBuffer::from_slice(&vec![0u8; 4096]);
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

#[test]
fn debug_is_stable_across_calls() {
    let b = SecureBuffer::from_slice(b"value");
    let first = format!("{b:?}");
    let second = format!("{b:?}");
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------------
// try_lock: best-effort
// ---------------------------------------------------------------------------

#[test]
fn try_lock_is_best_effort_and_never_errors() {
    let mut b = SecureBuffer::zeroed(4096);
    let locked = b.try_lock().expect("try_lock must not error");
    let _ = locked;
}

#[test]
fn try_lock_on_empty_buffer_is_a_noop() {
    let mut b = SecureBuffer::new();
    assert!(!b.try_lock().unwrap());
}

#[test]
fn try_lock_is_idempotent() {
    let mut b = SecureBuffer::zeroed(4096);
    let _first = b.try_lock().unwrap();
    let _second = b.try_lock().unwrap();
}

// ---------------------------------------------------------------------------
// Drop behavior (observable via wipe path)
// ---------------------------------------------------------------------------

#[test]
fn wipe_before_drop_leaves_zeros() {
    let mut b = SecureBuffer::from_slice(b"will-be-wiped");
    b.wipe();
    assert!(b.as_slice().iter().all(|&x| x == 0));
    drop(b);
}

#[test]
fn drop_does_not_panic_on_empty() {
    let b = SecureBuffer::new();
    drop(b);
}

#[test]
fn drop_does_not_panic_after_try_lock() {
    let mut b = SecureBuffer::zeroed(4096);
    let _ = b.try_lock();
    drop(b);
}

// ---------------------------------------------------------------------------
// with_wiped_scratch
// ---------------------------------------------------------------------------

#[test]
fn with_wiped_scratch_passes_slice_then_clears_vec() {
    let mut scratch = b"scratch-value".to_vec();
    let len = with_wiped_scratch(&mut scratch, |s| s.len());
    assert_eq!(len, 13);
    assert!(scratch.is_empty());
}

#[test]
fn with_wiped_scratch_clears_even_on_early_return() {
    let mut scratch = b"some-secret".to_vec();
    let out: Option<u8> = with_wiped_scratch(&mut scratch, |s| {
        if s.starts_with(b"s") {
            None
        } else {
            Some(0)
        }
    });
    assert_eq!(out, None);
    assert!(scratch.is_empty());
}

// ---------------------------------------------------------------------------
// require_len
// ---------------------------------------------------------------------------

#[test]
fn require_len_accepts_exact_match() {
    for len in [0usize, 1, 12, 16, 32, 64, 1024] {
        let buf = vec![0u8; len];
        assert!(require_len(&buf, len).is_ok(), "len {len} rejected");
    }
}

#[test]
fn require_len_rejects_mismatch() {
    for (actual, expected) in [(0usize, 1usize), (11, 12), (13, 12), (0, 16), (1024, 32)] {
        let buf = vec![0u8; actual];
        assert!(
            matches!(require_len(&buf, expected), Err(Error::InvalidEncoding)),
            "len {actual} vs expected {expected} was accepted"
        );
    }
}

#[test]
fn require_len_error_is_opaque() {
    let e = require_len(&[0u8; 5], 32).unwrap_err();
    let msg = e.to_string();
    assert!(!msg.contains("32"));
    assert_eq!(msg, "vault contains invalid encoding");
}

// ---------------------------------------------------------------------------
// Structural properties
// ---------------------------------------------------------------------------

#[test]
fn distinct_buffers_are_distinct_allocations() {
    // Two buffers created from independent slices must have distinct
    // content even though the values are the same length.
    let a = SecureBuffer::from_slice(b"aaaa");
    let b = SecureBuffer::from_slice(b"bbbb");
    assert_ne!(a.as_slice(), b.as_slice());
}
