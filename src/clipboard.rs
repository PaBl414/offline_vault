//! Clipboard handling with conditional auto-clear.
//!
//! ## Behavior
//!
//! When a secret is copied:
//!
//!   1. The secret is placed on the system clipboard.
//!   2. A copy of the secret is retained in a [`SecureBuffer`].
//!   3. A deadline is recorded ([`CLEAR_AFTER`] from now).
//!
//! On every `poll()` after the deadline:
//!
//!   * The current clipboard text is read.
//!   * It is compared to the retained secret in **constant time**.
//!   * If and only if they match, the clipboard is cleared.
//!   * The retained secret is wiped in either case.
//!
//! This means we never overwrite clipboard contents that some other
//! application placed there after us. It also means we never clear the
//! clipboard if the user (or another program) has since copied something
//! else.
//!
//! ## What we do not guarantee
//!
//!   * We cannot restore whatever was on the clipboard before we wrote to it.
//!     Standard clipboard APIs do not provide that, and any attempt to save
//!     and restore the previous contents would require reading them, which
//!     would let us see secrets placed there by other applications.
//!   * A program that continuously reads the clipboard can capture our secret
//!     before the deadline. Clearing the clipboard reduces the window, not
//!     the fundamental exposure of putting a secret on the system clipboard.
//!
//! ## Time
//!
//! `std::time::Instant` is used. `poll()` is expected to be called from the
//! GUI's per-frame update loop; the guard performs no background work.

use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::security::SecureBuffer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How long a copied secret remains on the clipboard before we attempt to
/// clear it (if it is still ours).
pub const CLEAR_AFTER: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// Backend abstraction
// ---------------------------------------------------------------------------

/// Minimal clipboard abstraction. A trait exists so the auto-clear logic can
/// be unit-tested deterministically without touching the real clipboard.
pub trait ClipboardBackend {
    fn get_text(&mut self) -> Result<String>;
    fn set_text(&mut self, text: String) -> Result<()>;
    fn clear(&mut self) -> Result<()>;
}

/// Real backend backed by the `arboard` crate.
struct SystemClipboard(arboard::Clipboard);

impl SystemClipboard {
    fn new() -> Result<Self> {
        arboard::Clipboard::new()
            .map(SystemClipboard)
            .map_err(|_| Error::Clipboard)
    }
}

impl ClipboardBackend for SystemClipboard {
    fn get_text(&mut self) -> Result<String> {
        self.0.get_text().map_err(|_| Error::Clipboard)
    }

    fn set_text(&mut self, text: String) -> Result<()> {
        self.0.set_text(text).map_err(|_| Error::Clipboard)
    }

    fn clear(&mut self) -> Result<()> {
        self.0.clear().map_err(|_| Error::Clipboard)
    }
}

// ---------------------------------------------------------------------------
// ClipboardGuard
// ---------------------------------------------------------------------------

/// Owns the clipboard backend and the state needed for conditional clearing.
///
/// A single guard lives for the lifetime of the GUI. Calling [`copy`] replaces
/// any previous pending secret; the previous secret buffer is wiped first.
pub struct ClipboardGuard {
    backend: Box<dyn ClipboardBackend>,
    /// The secret we most recently put on the clipboard, retained so we can
    /// check on the deadline whether the clipboard still holds it.
    secret: SecureBuffer,
    /// When to attempt the clear. `None` means nothing is pending.
    deadline: Option<Instant>,
    /// Duration after a copy to wait before attempting to clear. Test code
    /// shortens this; production uses [`CLEAR_AFTER`].
    clear_after: Duration,
}

impl ClipboardGuard {
    /// Construct a guard backed by the real system clipboard.
    pub fn new() -> Result<Self> {
        Ok(Self::with_backend(Box::new(SystemClipboard::new()?)))
    }

    /// Construct a guard from any backend. Used by tests and, potentially, by
    /// alternative front-ends that want to supply their own clipboard.
    pub fn with_backend(backend: Box<dyn ClipboardBackend>) -> Self {
        Self {
            backend,
            secret: SecureBuffer::new(),
            deadline: None,
            clear_after: CLEAR_AFTER,
        }
    }

    /// Place `value` on the clipboard and start the clear timer.
    ///
    /// Any previous pending secret is wiped before the new one is stored.
    /// The value is not logged, printed, or included in any error message.
    pub fn copy(&mut self, value: &str) -> Result<()> {
        // Wipe any previous pending secret before storing the new one.
        self.secret.wipe();

        // The standard clipboard API requires an owned `String`. That copy
        // is unavoidable; we keep no further copies of it.
        self.backend.set_text(value.to_owned())?;

        // Retain our own copy for the conditional comparison on the deadline.
        self.secret = SecureBuffer::from_slice(value.as_bytes());
        self.deadline = Some(Instant::now() + self.clear_after);
        Ok(())
    }

    /// Advance the auto-clear state machine. Safe to call every frame.
    ///
    /// If the deadline has not been reached, does nothing. If it has, reads
    /// the current clipboard, clears it only if it still equals the secret
    /// we placed there, and wipes our retained copy regardless.
    pub fn poll(&mut self) {
        let now = Instant::now();
        if self.deadline.is_some_and(|d| now >= d) {
            self.try_clear();
            self.deadline = None;
        }
    }

    /// Cancel any pending clear and wipe the retained secret.
    ///
    /// Called on lock and on shutdown. Does not modify the clipboard: the
    /// user may still want what is there until the timer would have fired,
    /// but we drop our copy of the secret immediately.
    pub fn cancel(&mut self) {
        self.secret.wipe();
        self.deadline = None;
    }

    /// The conditional clear itself.
    fn try_clear(&mut self) {
        // Read the current clipboard. If we cannot read it, do not touch it;
        // clearing blind would risk clobbering another application's data.
        let current = match self.backend.get_text() {
            Ok(t) => t,
            Err(_) => {
                self.secret.wipe();
                return;
            }
        };

        // Constant-time comparison. Length is public information about the
        // secret and does not need to be concealed from the local process;
        // the comparison itself is what must not leak via timing.
        let still_ours = current.len() == self.secret.len()
            && bool::from(current.as_bytes().ct_eq(self.secret.as_slice()));

        if still_ours {
            // Best-effort clear; a failure here is not actionable and must
            // not surface as an application error.
            let _ = self.backend.clear();
        }

        // Wipe our retained copy either way.
        self.secret.wipe();
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        // On shutdown, attempt the same conditional clear so a secret is not
        // left on the clipboard if we still own it.
        if self.deadline.is_some() {
            self.try_clear();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    struct SharedState {
        content: Arc<Mutex<Option<String>>>,
        clear_calls: Arc<Mutex<u32>>,
        set_calls: Arc<Mutex<u32>>,
    }

    struct MockClipboard {
        state: SharedState,
    }

    impl MockClipboard {
        fn new() -> (Self, SharedState) {
            let state = SharedState::default();
            (
                MockClipboard {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    impl ClipboardBackend for MockClipboard {
        fn get_text(&mut self) -> Result<String> {
            self.state
                .content
                .lock()
                .unwrap()
                .clone()
                .ok_or(Error::Clipboard)
        }

        fn set_text(&mut self, text: String) -> Result<()> {
            *self.state.content.lock().unwrap() = Some(text);
            *self.state.set_calls.lock().unwrap() += 1;
            Ok(())
        }

        fn clear(&mut self) -> Result<()> {
            *self.state.content.lock().unwrap() = None;
            *self.state.clear_calls.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn short_guard(state: SharedState, ms: u64) -> ClipboardGuard {
        let backend = Box::new(MockClipboard { state });
        let mut guard = ClipboardGuard::with_backend(backend);
        guard.clear_after = Duration::from_millis(ms);
        guard
    }

    #[test]
    fn copy_stores_secret_and_sets_deadline() {
        let (_mock, state) = MockClipboard::new();
        let mut guard = short_guard(state.clone(), 1000);
        guard.copy("hunter2hunter2").unwrap();
        assert_eq!(
            state.content.lock().unwrap().clone(),
            Some("hunter2hunter2".to_string())
        );
        assert_eq!(guard.secret.as_slice(), b"hunter2hunter2");
        assert!(guard.deadline.is_some());
    }

    #[test]
    fn poll_before_deadline_does_nothing() {
        let (_mock, state) = MockClipboard::new();
        let mut guard = short_guard(state.clone(), 60_000);
        guard.copy("secret").unwrap();
        guard.poll();
        assert_eq!(
            state.content.lock().unwrap().clone(),
            Some("secret".to_string())
        );
        assert_eq!(*state.clear_calls.lock().unwrap(), 0);
    }

    #[test]
    fn poll_after_deadline_clears_when_unchanged() {
        let (_mock, state) = MockClipboard::new();
        let mut guard = short_guard(state.clone(), 5);
        guard.copy("secret").unwrap();
        std::thread::sleep(Duration::from_millis(15));
        guard.poll();
        assert!(state.content.lock().unwrap().is_none());
        assert_eq!(*state.clear_calls.lock().unwrap(), 1);
        // The retained secret has been wiped.
        assert!(guard.secret.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn poll_after_deadline_does_not_clear_if_replaced() {
        let (_mock, state) = MockClipboard::new();
        let mut guard = short_guard(state.clone(), 5);
        guard.copy("ours").unwrap();
        // Another app replaces the clipboard before the deadline.
        *state.content.lock().unwrap() = Some("theirs".to_string());
        std::thread::sleep(Duration::from_millis(15));
        guard.poll();
        // We must not have cleared the other app's data.
        assert_eq!(
            state.content.lock().unwrap().clone(),
            Some("theirs".to_string())
        );
        assert_eq!(*state.clear_calls.lock().unwrap(), 0);
        // Our retained copy is still wiped.
        assert!(guard.secret.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn poll_after_deadline_does_not_clear_if_emptied() {
        let (_mock, state) = MockClipboard::new();
        let mut guard = short_guard(state.clone(), 5);
        guard.copy("ours").unwrap();
        // Someone else clears the clipboard.
        *state.content.lock().unwrap() = None;
        std::thread::sleep(Duration::from_millis(15));
        guard.poll();
        // `get_text` returns Err in the mock; we must not panic and must not
        // call clear again.
        assert_eq!(*state.clear_calls.lock().unwrap(), 0);
        assert!(guard.secret.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn second_copy_replaces_first() {
        let (_mock, state) = MockClipboard::new();
        let mut guard = short_guard(state.clone(), 60_000);
        guard.copy("first").unwrap();
        guard.copy("second").unwrap();
        assert_eq!(
            state.content.lock().unwrap().clone(),
            Some("second".to_string())
        );
        assert_eq!(guard.secret.as_slice(), b"second");
    }

    #[test]
    fn cancel_wipes_secret_and_clears_deadline() {
        let (_mock, state) = MockClipboard::new();
        let mut guard = short_guard(state.clone(), 60_000);
        guard.copy("secret").unwrap();
        guard.cancel();
        assert!(guard.secret.as_slice().iter().all(|&b| b == 0));
        assert!(guard.deadline.is_none());
        // Clipboard content is left alone by cancel().
        assert_eq!(
            state.content.lock().unwrap().clone(),
            Some("secret".to_string())
        );
    }

    #[test]
    fn drop_attempts_conditional_clear() {
        let (_mock, state) = MockClipboard::new();
        {
            let mut guard = short_guard(state.clone(), 60_000);
            guard.copy("secret").unwrap();
            // Drop runs while the clipboard still contains our secret.
        }
        assert!(state.content.lock().unwrap().is_none());
    }
}
