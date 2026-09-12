//! Integration tests for the clipboard guard's conditional auto-clear.
//!
//! These tests use the public `ClipboardBackend` trait and `ClipboardGuard`
//! type from `offline_vault::clipboard`. They never touch the real system
//! clipboard: a mock backend records every `set_text` and `clear` call and
//! lets each test control what the clipboard contains.
//!
//! ## Where the timing-sensitive tests live
//!
//! `ClipboardGuard` deliberately does not expose its `clear_after` duration
//! through the public API. Tests that need to observe the deadline firing —
//! "clear fires after 20 seconds", "clear is skipped when the value was
//! replaced", "clear is skipped when `get_text` fails" — therefore live in
//! the inline `#[cfg(test)] mod tests` inside `src/clipboard.rs`, where the
//! private field is reachable and the deadline can be shortened to a few
//! milliseconds.
//!
//! This file covers what can be asserted without waiting for the real
//! 20-second timeout: that `copy` places the value on the clipboard, that a
//! second `copy` replaces the first, that `poll` before the deadline is a
//! no-op, that `cancel` drops our retained copy without touching the
//! clipboard, that backend errors propagate, and that `Drop` behaves.
//!
//! No test prints a secret. The literal strings used are placeholders whose
//! only purpose is to be observed as clipboard content.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use offline_vault::clipboard::{ClipboardBackend, ClipboardGuard, CLEAR_AFTER};
use offline_vault::error::Error;

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct State {
    content: Arc<Mutex<Option<String>>>,
    set_calls: Arc<Mutex<u32>>,
    clear_calls: Arc<Mutex<u32>>,
    /// When true, `get_text` returns `Err(Error::Clipboard)`, emulating a
    /// clipboard that is temporarily unavailable.
    fail_get: Arc<Mutex<bool>>,
}

impl State {
    fn content(&self) -> Option<String> {
        self.content.lock().unwrap().clone()
    }
    fn clear_calls(&self) -> u32 {
        *self.clear_calls.lock().unwrap()
    }
    fn set_calls(&self) -> u32 {
        *self.set_calls.lock().unwrap()
    }
    fn set_fail_get(&self, v: bool) {
        *self.fail_get.lock().unwrap() = v;
    }
}

struct MockClipboard {
    state: State,
}

impl ClipboardBackend for MockClipboard {
    fn get_text(&mut self) -> Result<String, Error> {
        if *self.state.fail_get.lock().unwrap() {
            return Err(Error::Clipboard);
        }
        self.state
            .content
            .lock()
            .unwrap()
            .clone()
            .ok_or(Error::Clipboard)
    }
    fn set_text(&mut self, text: String) -> Result<(), Error> {
        *self.state.content.lock().unwrap() = Some(text);
        *self.state.set_calls.lock().unwrap() += 1;
        Ok(())
    }
    fn clear(&mut self) -> Result<(), Error> {
        *self.state.content.lock().unwrap() = None;
        *self.state.clear_calls.lock().unwrap() += 1;
        Ok(())
    }
}

/// Build a guard backed by a fresh `MockClipboard`. The returned `State`
/// gives the test direct access to what the backend saw.
///
/// The guard uses the production `CLEAR_AFTER` deadline. None of the tests
/// in this file wait for it to elapse; the deadline-firing tests live in
/// `src/clipboard.rs`.
fn guard_with_mock_backend() -> (ClipboardGuard, State) {
    let state = State::default();
    let backend = Box::new(MockClipboard {
        state: state.clone(),
    });
    (ClipboardGuard::with_backend(backend), state)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn clear_after_is_20_seconds() {
    // This is a security-relevant constant. If it changes, this test forces
    // a review.
    assert_eq!(CLEAR_AFTER, Duration::from_secs(20));
}

// ---------------------------------------------------------------------------
// copy
// ---------------------------------------------------------------------------

#[test]
fn copy_places_value_on_clipboard() {
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("pending-secret").unwrap();
    assert_eq!(state.content(), Some("pending-secret".to_string()));
    assert_eq!(state.set_calls(), 1);
    assert_eq!(state.clear_calls(), 0);
}

#[test]
fn second_copy_replaces_first() {
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("first").unwrap();
    guard.copy("second").unwrap();
    assert_eq!(state.content(), Some("second".to_string()));
    assert_eq!(state.set_calls(), 2);
    // No clear should have run: no deadline has elapsed.
    assert_eq!(state.clear_calls(), 0);
}

#[test]
fn copy_does_not_clear_previously_pending_on_second_call() {
    // A second `copy` replaces the retained secret and the clipboard
    // contents, but it must not invoke `clear` on the backend.
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("one").unwrap();
    guard.copy("two").unwrap();
    assert_eq!(state.clear_calls(), 0);
}

// ---------------------------------------------------------------------------
// poll before deadline
// ---------------------------------------------------------------------------

#[test]
fn poll_before_deadline_does_nothing() {
    // The deadline is CLEAR_AFTER (20 seconds). Polling immediately must be
    // a no-op: the clipboard still holds our value and no clear was called.
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("still-here").unwrap();
    guard.poll();
    assert_eq!(state.content(), Some("still-here".to_string()));
    assert_eq!(state.clear_calls(), 0);
}

#[test]
fn repeated_poll_before_deadline_is_idempotent() {
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("value").unwrap();
    for _ in 0..8 {
        guard.poll();
    }
    assert_eq!(state.content(), Some("value".to_string()));
    assert_eq!(state.clear_calls(), 0);
}

// ---------------------------------------------------------------------------
// cancel
// ---------------------------------------------------------------------------

#[test]
fn cancel_does_not_touch_clipboard() {
    // `cancel` drops our copy of the secret but leaves whatever is on the
    // clipboard alone. This is deliberate: another application may have
    // replaced it since our copy, and clearing blind would risk clobbering
    // their data.
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("ours").unwrap();
    guard.cancel();
    assert_eq!(state.content(), Some("ours".to_string()));
    assert_eq!(state.clear_calls(), 0);
}

#[test]
fn cancel_is_safe_without_a_prior_copy() {
    let (mut guard, _state) = guard_with_mock_backend();
    guard.cancel();
    // No panic, no backend call.
}

#[test]
fn cancel_after_copy_then_poll_does_not_clear() {
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("ours").unwrap();
    guard.cancel();
    guard.poll();
    // The deadline was cleared by `cancel`, so `poll` has nothing to do.
    assert_eq!(state.content(), Some("ours".to_string()));
    assert_eq!(state.clear_calls(), 0);
}

// ---------------------------------------------------------------------------
// copy error propagation
// ---------------------------------------------------------------------------

/// Backend whose `set_text` always fails. Used to assert that the guard
/// propagates the error rather than storing a secret that was never placed
/// on the clipboard.
struct FailingSetBackend;

impl ClipboardBackend for FailingSetBackend {
    fn get_text(&mut self) -> Result<String, Error> {
        Err(Error::Clipboard)
    }
    fn set_text(&mut self, _text: String) -> Result<(), Error> {
        Err(Error::Clipboard)
    }
    fn clear(&mut self) -> Result<(), Error> {
        Err(Error::Clipboard)
    }
}

#[test]
fn copy_propagates_backend_error() {
    let mut guard = ClipboardGuard::with_backend(Box::new(FailingSetBackend));
    let err = guard.copy("value").unwrap_err();
    assert!(matches!(err, Error::Clipboard));
}

// ---------------------------------------------------------------------------
// Drop behavior
// ---------------------------------------------------------------------------

#[test]
fn drop_with_no_pending_copy_is_a_noop() {
    let state = State::default();
    {
        let _guard = ClipboardGuard::with_backend(Box::new(MockClipboard {
            state: state.clone(),
        }));
    }
    assert_eq!(state.clear_calls(), 0);
    assert_eq!(state.set_calls(), 0);
}

#[test]
fn drop_after_cancel_does_not_clear() {
    let state = State::default();
    {
        let mut guard = ClipboardGuard::with_backend(Box::new(MockClipboard {
            state: state.clone(),
        }));
        guard.copy("value").unwrap();
        guard.cancel();
    }
    // `cancel` cleared the deadline, so `Drop` must not attempt a clear.
    assert_eq!(state.clear_calls(), 0);
    assert_eq!(state.content(), Some("value".to_string()));
}

// ---------------------------------------------------------------------------
// Trait-object ergonomics
// ---------------------------------------------------------------------------

#[test]
fn guard_accepts_any_boxed_backend() {
    // Compile-time exercise of the trait-object form used by `App`.
    let state = State::default();
    let backend: Box<dyn ClipboardBackend> = Box::new(MockClipboard {
        state: state.clone(),
    });
    let mut guard = ClipboardGuard::with_backend(backend);
    guard.copy("x").unwrap();
    assert_eq!(state.content(), Some("x".to_string()));
}

#[test]
fn failing_get_backend_is_tolerated_by_poll() {
    // When the clipboard is temporarily unreadable, `poll` must not panic
    // and must not attempt a blind clear. Since the deadline has not
    // elapsed here, we only assert that the call is safe.
    let (mut guard, state) = guard_with_mock_backend();
    guard.copy("ours").unwrap();
    state.set_fail_get(true);
    guard.poll();
    assert_eq!(state.clear_calls(), 0);
}
