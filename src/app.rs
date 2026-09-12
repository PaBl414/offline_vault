//! Application state machine.
//!
//! [`App`] sits between the GUI (`ui.rs`) and the vault, storage, clipboard,
//! and auto-lock layers. It owns the current vault state, drives the
//! inactivity timer and clipboard poll each frame, and exposes a small,
//! typed API for the GUI:
//!
//!   * `state()` — read the current [`AppState`].
//!   * `entries()` — read the entry list (empty while locked).
//!   * `create_vault(password, confirm)` / `unlock(password)` / `lock()`.
//!   * `add_entry`, `update_entry`, `remove_entry` — mutate the unlocked vault
//!     and persist it atomically.
//!   * `copy_password(id)` / `copy_username(id)` — hand a secret to the
//!     clipboard guard without an intermediate clone.
//!   * `tick(input)` — one call per GUI frame; polls the clipboard and drives
//!     auto-lock.
//!
//! The GUI never sees a master password, a Master Key, a KEK, a Vault Key,
//! or an unwrapped payload. It sees entries and error strings, nothing more.
//!
//! ## Locking semantics
//!
//! `lock()` replaces the current state with `Locked { path }`. The previous
//! `UnlockedVault` is dropped, which runs `ZeroizeOnDrop` on every entry and
//! wipes the Vault Key inside its [`crate::security::SecureBuffer`]. The
//! clipboard guard deliberately keeps its pending 20-second timer running, so
//! a password copied just before locking is still cleared on schedule.

use std::path::{Path, PathBuf};

use crate::autolock::{self, AutoLock};
use crate::clipboard::{ClipboardBackend, ClipboardGuard};
use crate::error::{Error, Result};
use crate::storage;
use crate::vault::{Entry, UnlockedVault, VaultFile};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum accepted master-password length, in characters.
pub const MIN_MASTER_PASSWORD_LEN: usize = 12;

/// Environment variable that overrides the default vault path. Intended for
/// users who keep their vault somewhere other than the default location.
pub const VAULT_PATH_ENV: &str = "OFFLINE_VAULT_PATH";

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// The three states the application can be in.
pub enum AppState {
    /// No vault file exists at the resolved path. The GUI should offer to
    /// create one.
    NoVault,
    /// A vault file exists; the user must enter the master password.
    Locked { path: PathBuf },
    /// The vault is decrypted in memory. `path` is the file it was loaded
    /// from, so saves go back to the same location.
    Unlocked { path: PathBuf, vault: UnlockedVault },
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    state: AppState,
    vault_path: PathBuf,
    clipboard: ClipboardGuard,
    autolock: AutoLock,
    /// Last user-facing error message. Never contains a secret; produced only
    /// from [`crate::error::Error`]'s `Display` implementation or a small
    /// number of fixed strings.
    error: Option<String>,
}

impl App {
    /// Construct the application. Resolves the vault path, opens the system
    /// clipboard (falling back to a no-op backend if the clipboard is not
    /// available), and inspects the vault file to decide the initial state.
    pub fn new() -> Result<Self> {
        let clipboard = match ClipboardGuard::new() {
            Ok(g) => g,
            // A headless or clipboard-less environment still allows the user
            // to view the vault; copy operations will return `Error::Clipboard`.
            Err(_) => ClipboardGuard::with_backend(Box::new(NullClipboard)),
        };
        Self::with_vault_path_and_clipboard(resolve_vault_path(), clipboard)
    }

    /// Construct an `App` with an explicit vault path and clipboard guard.
    /// Used by `new` and by tests.
    pub fn with_vault_path_and_clipboard(
        vault_path: PathBuf,
        clipboard: ClipboardGuard,
    ) -> Result<Self> {
        let state = if storage::vault_exists(&vault_path) {
            AppState::Locked {
                path: vault_path.clone(),
            }
        } else {
            AppState::NoVault
        };

        Ok(Self {
            state,
            vault_path,
            clipboard,
            autolock: AutoLock::new(),
            error: None,
        })
    }

    // -- Accessors ----------------------------------------------------------

    /// Current application state.
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Resolved vault path. Always set, even before the vault is created.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// The entry list while unlocked, or an empty slice while locked.
    pub fn entries(&self) -> &[Entry] {
        match &self.state {
            AppState::Unlocked { vault, .. } => vault.entries(),
            _ => &[],
        }
    }

    /// Whether the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, AppState::Unlocked { .. })
    }

    /// Most recent user-facing error, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Clear the current error.
    pub fn clear_error(&mut self) {
        self.error = None;
    }

    // -- Lifecycle ----------------------------------------------------------

    /// Create a brand-new vault at the resolved path. Refuses to overwrite an
    /// existing vault. On success the state becomes `Unlocked` with an empty
    /// entry list.
    pub fn create_vault(&mut self, password: &str, confirm: &str) -> Result<()> {
        self.error = None;

        if password.chars().count() < MIN_MASTER_PASSWORD_LEN {
            let e = Error::PasswordTooShort {
                min: MIN_MASTER_PASSWORD_LEN,
            };
            self.error = Some(e.to_string());
            return Err(e);
        }
        if password != confirm {
            let e = Error::PasswordMismatch;
            self.error = Some(e.to_string());
            return Err(e);
        }
        if storage::vault_exists(&self.vault_path) {
            let e = Error::VaultAlreadyExists;
            self.error = Some(e.to_string());
            return Err(e);
        }

        let (file, unlocked) = VaultFile::new(password)?;
        let bytes = file.to_bytes()?;
        storage::write_vault_atomic(&self.vault_path, &bytes)?;

        self.state = AppState::Unlocked {
            path: self.vault_path.clone(),
            vault: unlocked,
        };
        self.autolock.note_activity();
        Ok(())
    }

    /// Attempt to unlock an existing vault with the given master password.
    ///
    /// Any cryptographic failure — wrong password, tampered wrapped key,
    /// tampered payload — surfaces as [`Error::Authentication`]. The `Display`
    /// string of that error is what the GUI shows; it is deliberately
    /// uninformative about which internal check failed.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        self.error = None;

        let path = match &self.state {
            AppState::Locked { path } => path.clone(),
            AppState::NoVault => {
                let e = Error::VaultNotFound;
                self.error = Some(e.to_string());
                return Err(e);
            }
            AppState::Unlocked { .. } => {
                // Already unlocked. Treat as a no-op so a stray double-click
                // on Unlock cannot corrupt state.
                return Ok(());
            }
        };

        let bytes = storage::read_vault(&path)?;
        let file = VaultFile::from_bytes(&bytes)?;
        let unlocked = file.unlock(password)?;

        self.state = AppState::Unlocked {
            path,
            vault: unlocked,
        };
        self.autolock.note_activity();
        Ok(())
    }

    /// Lock the vault. Wipes the Vault Key and clears the in-memory entry
    /// list. Safe to call when already locked.
    pub fn lock(&mut self) {
        self.error = None;

        let path = match &self.state {
            AppState::Unlocked { path, .. } => path.clone(),
            _ => return,
        };

        // Explicitly wipe before dropping so the intent is visible in the
        // source. The subsequent state replacement drops the `UnlockedVault`
        // anyway, which runs `ZeroizeOnDrop` on every remaining entry and
        // wipes the Vault Key again.
        if let AppState::Unlocked { vault, .. } = &mut self.state {
            vault.lock();
        }
        self.state = AppState::Locked { path };
        self.autolock.note_activity();
    }

    /// Persist the current unlocked vault. No-op when locked.
    pub fn save(&mut self) -> Result<()> {
        let (path, file) = match &self.state {
            AppState::Unlocked { path, vault } => {
                let sealed = vault.seal()?;
                (path.clone(), sealed)
            }
            _ => return Ok(()),
        };
        let bytes = file.to_bytes()?;
        storage::write_vault_atomic(&path, &bytes)?;
        Ok(())
    }

    // -- Entry operations ---------------------------------------------------

    /// Add an entry and persist the vault. Errors if the vault is locked or
    /// the entry fails validation.
    pub fn add_entry(&mut self, entry: Entry) -> Result<()> {
        {
            let vault = self.unlocked_mut()?;
            vault.add_entry(entry)?;
        }
        self.save()
    }

    /// Replace an existing entry by id and persist. Returns `false` if no
    /// entry had that id (in which case the file is not rewritten).
    pub fn update_entry(&mut self, entry: Entry) -> Result<bool> {
        let changed = {
            let vault = self.unlocked_mut()?;
            vault.update_entry(entry)?
        };
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Delete an entry by id and persist. Returns `true` if an entry was
    /// removed (in which case the file is rewritten).
    pub fn remove_entry(&mut self, id: &str) -> Result<bool> {
        let removed = {
            let vault = self.unlocked_mut()?;
            vault.remove_entry(id)
        };
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    // -- Clipboard ----------------------------------------------------------

    /// Copy the password of the entry with the given id. The value never
    /// leaves the entry as an owned `String` in this function: the clipboard
    /// guard borrows it directly, so there is no intermediate plaintext copy.
    pub fn copy_password(&mut self, id: &str) -> Result<()> {
        let Self {
            state, clipboard, ..
        } = self;
        let vault = match state {
            AppState::Unlocked { vault, .. } => vault,
            _ => return Err(Error::VaultNotFound),
        };
        let entry = vault
            .entries()
            .iter()
            .find(|e| e.id == id)
            .ok_or(Error::VaultNotFound)?;
        clipboard.copy(&entry.password)
    }

    /// Copy the username of the entry with the given id.
    pub fn copy_username(&mut self, id: &str) -> Result<()> {
        let Self {
            state, clipboard, ..
        } = self;
        let vault = match state {
            AppState::Unlocked { vault, .. } => vault,
            _ => return Err(Error::VaultNotFound),
        };
        let entry = vault
            .entries()
            .iter()
            .find(|e| e.id == id)
            .ok_or(Error::VaultNotFound)?;
        clipboard.copy(&entry.username)
    }

    // -- Per-frame tick -----------------------------------------------------

    /// Drive the clipboard poll and the auto-lock timer. Called once per GUI
    /// frame. `input` is the current egui input state; only genuine user
    /// activity resets the inactivity timer.
    pub fn tick(&mut self, input: &egui::InputState) {
        // The clipboard poll must run regardless of lock state, because a
        // copied secret may still be pending clear when the vault is locked.
        self.clipboard.poll();

        if self.is_unlocked() {
            if autolock::user_activity_in(input) {
                self.autolock.note_activity();
            }
            if self.autolock.should_lock() {
                self.lock();
            }
        }
    }

    // -- Internal helpers ---------------------------------------------------

    fn unlocked_mut(&mut self) -> Result<&mut UnlockedVault> {
        match &mut self.state {
            AppState::Unlocked { vault, .. } => Ok(vault),
            _ => Err(Error::VaultNotFound),
        }
    }
}

// ---------------------------------------------------------------------------
// Null clipboard backend
// ---------------------------------------------------------------------------

/// Backend used when the system clipboard is not available. Every method
/// returns [`Error::Clipboard`], so a copy attempt surfaces a clean error to
/// the user instead of panicking.
struct NullClipboard;

impl ClipboardBackend for NullClipboard {
    fn get_text(&mut self) -> Result<String> {
        Err(Error::Clipboard)
    }
    fn set_text(&mut self, _text: String) -> Result<()> {
        Err(Error::Clipboard)
    }
    fn clear(&mut self) -> Result<()> {
        Err(Error::Clipboard)
    }
}

// ---------------------------------------------------------------------------
// Vault path resolution
// ---------------------------------------------------------------------------

/// Resolve the vault path from the environment or platform defaults.
///
/// Precedence:
///   1. `OFFLINE_VAULT_PATH` if set and non-empty.
///   2. On Unix: `$HOME/.local/share/offline-vault/vault.json`.
///   3. On Windows: `%APPDATA%\offline-vault\vault.json`.
///   4. Otherwise: `./vault.json` in the current working directory.
///
/// A file picker is intentionally not used: adding a GUI file-dialog crate
/// would expand the dependency surface for no security benefit, and a fixed,
/// documented location is easier for users to back up.
fn resolve_vault_path() -> PathBuf {
    if let Some(p) = std::env::var_os(VAULT_PATH_ENV) {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_vault_path()
}

#[cfg(unix)]
fn default_vault_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => {
            PathBuf::from(h).join(".local/share/offline-vault/vault.json")
        }
        _ => PathBuf::from("vault.json"),
    }
}

#[cfg(windows)]
fn default_vault_path() -> PathBuf {
    match std::env::var_os("APPDATA") {
        Some(a) if !a.is_empty() => {
            PathBuf::from(a).join("offline-vault").join("vault.json")
        }
        _ => PathBuf::from("vault.json"),
    }
}

#[cfg(not(any(unix, windows)))]
fn default_vault_path() -> PathBuf {
    PathBuf::from("vault.json")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::ClipboardBackend;
    use crate::crypto::{self, KdfParams, KEY_LEN, KDF_NAME_ARGON2ID, SALT_LEN};
    use crate::vault::{EncryptedBlob, KdfSection, SUPPORTED_VERSION};

    /// A clipboard backend that succeeds on `set_text`/`clear` and returns
    /// `Err(Error::Clipboard)` on `get_text`. Good enough for the app tests,
    /// which do not exercise the auto-clear path.
    struct TestClipboard;

    impl ClipboardBackend for TestClipboard {
        fn get_text(&mut self) -> Result<String> {
            Err(Error::Clipboard)
        }
        fn set_text(&mut self, _text: String) -> Result<()> {
            Ok(())
        }
        fn clear(&mut self) -> Result<()> {
            Ok(())
        }
    }

    fn make_app(path: PathBuf) -> App {
        let clipboard = ClipboardGuard::with_backend(Box::new(TestClipboard));
        App::with_vault_path_and_clipboard(path, clipboard).expect("app")
    }

    /// Write a vault file using fast Argon2id parameters, so tests run
    /// quickly while still exercising the real wrap/unwrap path.
    fn write_fast_vault(path: &Path, password: &str) -> Result<()> {
        let params = KdfParams {
            name: KDF_NAME_ARGON2ID.to_string(),
            salt: crypto::random_bytes::<SALT_LEN>()?.to_vec(),
            time_cost: 1,
            memory_cost: 19 * 1024,
            parallelism: 1,
            hash_len: KEY_LEN as u32,
        };
        let mk = crypto::derive_master_key(password.as_bytes(), &params)?;
        let kek = crypto::derive_kek(mk.as_slice())?;
        let vk = crypto::random_vault_key()?;
        let (wn, wc) = crypto::wrap_vault_key(kek.as_slice(), vk.as_slice())?;
        let (vn, vc) = crypto::encrypt_vault(vk.as_slice(), b"[]")?;
        let file = VaultFile {
            version: SUPPORTED_VERSION,
            kdf: KdfSection::from_kdf_params(&params),
            wrapped_key: EncryptedBlob::from_raw(&wn, &wc),
            vault: EncryptedBlob::from_raw(&vn, &vc),
        };
        storage::write_vault_atomic(path, &file.to_bytes()?)
    }

    #[test]
    fn new_app_with_missing_vault_is_no_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let app = make_app(path.clone());
        assert!(matches!(app.state(), AppState::NoVault));
        assert_eq!(app.vault_path(), path.as_path());
        assert!(app.entries().is_empty());
        assert!(!app.is_unlocked());
    }

    #[test]
    fn new_app_with_existing_vault_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let app = make_app(path);
        assert!(matches!(app.state(), AppState::Locked { .. }));
    }

    #[test]
    fn short_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut app = make_app(path);
        let err = app.create_vault("short", "short").unwrap_err();
        assert!(matches!(err, Error::PasswordTooShort { min: 12 }));
        assert!(app.error().is_some());
        assert!(matches!(app.state(), AppState::NoVault));
    }

    #[test]
    fn mismatched_passwords_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut app = make_app(path);
        let err = app
            .create_vault("correct horse battery staple", "different passphrase value")
            .unwrap_err();
        assert!(matches!(err, Error::PasswordMismatch));
        assert!(matches!(app.state(), AppState::NoVault));
    }

    #[test]
    fn create_refuses_to_overwrite_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path.clone());
        let err = app
            .create_vault("correct horse battery staple", "correct horse battery staple")
            .unwrap_err();
        assert!(matches!(err, Error::VaultAlreadyExists));
        // The existing file must be untouched.
        assert!(storage::vault_exists(&path));
    }

    #[test]
    fn unlock_with_correct_password_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path);
        app.unlock("correct horse battery staple").unwrap();
        assert!(app.is_unlocked());
        assert!(app.entries().is_empty());
    }

    #[test]
    fn unlock_with_wrong_password_fails_opaquely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path);
        let err = app.unlock("wrong password entirely").unwrap_err();
        assert!(matches!(err, Error::Authentication));
        assert!(!app.is_unlocked());
        // The error message shown to the user must not contain any crypto
        // vocabulary.
        let msg = app.error().unwrap_or("");
        assert!(!msg.to_lowercase().contains("nonce"));
        assert!(!msg.to_lowercase().contains("tag"));
        assert!(!msg.to_lowercase().contains("gcm"));
        assert!(!msg.to_lowercase().contains("argon"));
    }

    #[test]
    fn lock_clears_entries_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path);
        app.unlock("correct horse battery staple").unwrap();
        app.add_entry(Entry::new("t", "u", "p", "u", "t", "n").unwrap())
            .unwrap();
        assert_eq!(app.entries().len(), 1);
        app.lock();
        assert!(!app.is_unlocked());
        assert!(app.entries().is_empty());
    }

    #[test]
    fn lock_when_already_locked_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path);
        app.lock();
        assert!(matches!(app.state(), AppState::Locked { .. }));
    }

    #[test]
    fn add_entry_persists_across_lock_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path.clone());
        app.unlock("correct horse battery staple").unwrap();
        let e = Entry::new("Title", "alice", "secret-pw", "https://x", "TOTPSECRET", "note")
            .unwrap();
        let id = e.id.clone();
        app.add_entry(e).unwrap();
        app.lock();

        // Reopen and confirm the entry survived the lock + save + reopen.
        let mut app2 = make_app(path);
        app2.unlock("correct horse battery staple").unwrap();
        assert_eq!(app2.entries().len(), 1);
        assert_eq!(app2.entries()[0].id, id);
        assert_eq!(app2.entries()[0].username, "alice");
        assert_eq!(app2.entries()[0].password, "secret-pw");
        assert_eq!(app2.entries()[0].totp, "TOTPSECRET");
    }

    #[test]
    fn update_entry_replaces_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path.clone());
        app.unlock("correct horse battery staple").unwrap();
        let e = Entry::new("T", "u", "old-pw", "", "", "").unwrap();
        let id = e.id.clone();
        app.add_entry(e).unwrap();

        let mut updated = Entry::new("T", "u", "new-pw", "", "", "").unwrap();
        updated.id = id.clone();
        assert!(app.update_entry(updated).unwrap());

        app.lock();
        let mut app2 = make_app(path);
        app2.unlock("correct horse battery staple").unwrap();
        assert_eq!(app2.entries()[0].password, "new-pw");
    }

    #[test]
    fn remove_entry_deletes_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path.clone());
        app.unlock("correct horse battery staple").unwrap();
        let e = Entry::new("T", "u", "p", "", "", "").unwrap();
        let id = e.id.clone();
        app.add_entry(e).unwrap();
        assert!(app.remove_entry(&id).unwrap());

        app.lock();
        let mut app2 = make_app(path);
        app2.unlock("correct horse battery staple").unwrap();
        assert!(app2.entries().is_empty());
    }

    #[test]
    fn entry_operations_fail_when_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path);
        let e = Entry::new("T", "u", "p", "", "", "").unwrap();
        assert!(app.add_entry(e).is_err());
        assert!(app.remove_entry("whatever").is_err());
    }

    #[test]
    fn copy_when_locked_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        write_fast_vault(&path, "correct horse battery staple").unwrap();
        let mut app = make_app(path);
        assert!(app.copy_password("anything").is_err());
        assert!(app.copy_username("anything").is_err());
    }
}
