//! Structured application errors.
//!
//! Every variant here is designed so that its `Display` output is safe to show
//! to a user, and its `Debug` output is safe to include in a developer log
//! (though this crate does not log). No variant carries a secret, a key, a
//! decrypted payload, a clipboard value, or a master password.
//!
//! Cryptographic failures are collapsed into a single opaque variant on
//! purpose: distinguishing "wrong password" from "tampered ciphertext" from
//! "malformed wrapped key" would leak information about internal state to an
//! attacker who can observe error messages.

use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Application-wide error type.
///
/// The variants are intentionally coarse. Anything that could be used as an
/// oracle about cryptographic state is folded into [`Error::Authentication`].
#[derive(Debug, Error)]
pub enum Error {
    // ---- Cryptographic failures -------------------------------------------
    /// Any failure to authenticate or decrypt. This deliberately covers wrong
    /// password, corrupted wrapped key, corrupted vault payload, mismatched
    /// AAD, and GCM tag failure. The caller must not distinguish between them
    /// in user-facing output.
    #[error("authentication failed")]
    Authentication,

    /// Failure to derive a key (for example, invalid Argon2 parameters).
    /// This is a configuration/programming error and never a user input error.
    #[error("key derivation failed")]
    KeyDerivation,

    /// A cryptographic operation failed for a reason that is not an
    /// authentication failure (for example, an internal size mismatch in a
    /// primitive wrapper).
    #[error("cryptographic operation failed")]
    Crypto,

    // ---- Vault / file format ----------------------------------------------
    /// The vault file could not be parsed as the expected JSON structure.
    #[error("vault file is not valid")]
    VaultFormat,

    /// The vault file has a `version` field that this build does not support.
    #[error("unsupported vault version")]
    UnsupportedVersion,

    /// One or more KDF parameters in the vault are outside the accepted range.
    #[error("vault contains invalid key-derivation parameters")]
    InvalidKdfParameters,

    /// A Base64-encoded field could not be decoded.
    #[error("vault contains invalid encoding")]
    InvalidEncoding,

    /// The decrypted payload did not match the expected entry schema.
    #[error("vault contents are not valid")]
    InvalidEntry,

    // ---- Storage -----------------------------------------------------------
    /// Generic I/O failure against the vault path or its directory.
    /// The `std::io::Error` is preserved for debugging but is only rendered
    /// as a coarse category to the user.
    #[error("storage error: {kind}")]
    Storage { kind: StorageErrorKind },

    /// A vault already exists at the requested path; creating a new vault
    /// would overwrite it. Refused by design.
    #[error("a vault already exists at that location")]
    VaultAlreadyExists,

    /// The requested vault path does not exist.
    #[error("no vault found at that location")]
    VaultNotFound,

    /// Saving failed before the atomic rename, so the previous vault is
    /// guaranteed to be untouched.
    #[error("could not save vault; previous file was left unchanged")]
    SaveFailed,

    // ---- User input --------------------------------------------------------
    /// Master password did not satisfy the minimum length requirement.
    #[error("master password must be at least {min} characters")]
    PasswordTooShort { min: usize },

    /// The two master-password fields did not match during vault creation.
    #[error("passwords do not match")]
    PasswordMismatch,

    // ---- Clipboard ---------------------------------------------------------
    /// The system clipboard could not be accessed.
    #[error("clipboard unavailable")]
    Clipboard,

    // ---- Auto-lock ---------------------------------------------------------
    /// Internal clock source failed. The application will lock rather than
    /// continue with an unreliable timer.
    #[error("internal clock unavailable")]
    Clock,
}

/// Coarse category for I/O failures. We map `std::io::ErrorKind` down to a
/// small set so that user-facing messages never embed a raw OS error string
/// that might include a path or other environment detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageErrorKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidInput,
    Other,
}

impl std::fmt::Display for StorageErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            StorageErrorKind::NotFound => "not found",
            StorageErrorKind::PermissionDenied => "permission denied",
            StorageErrorKind::AlreadyExists => "already exists",
            StorageErrorKind::InvalidInput => "invalid input",
            StorageErrorKind::Other => "I/O error",
        };
        f.write_str(s)
    }
}

impl StorageErrorKind {
    /// Classify an `std::io::Error` without preserving its message.
    pub fn from_io(err: &std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        match err.kind() {
            NotFound => StorageErrorKind::NotFound,
            PermissionDenied => StorageErrorKind::PermissionDenied,
            AlreadyExists => StorageErrorKind::AlreadyExists,
            InvalidInput | InvalidData => StorageErrorKind::InvalidInput,
            _ => StorageErrorKind::Other,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        // Deliberately drop the `std::io::Error` payload: it may contain a
        // path or other environment detail we do not want in user-visible
        // errors or in a `Debug` dump.
        Error::Storage {
            kind: StorageErrorKind::from_io(&err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_error_is_opaque() {
        let msg = Error::Authentication.to_string();
        assert_eq!(msg, "authentication failed");
        assert!(!msg.to_lowercase().contains("key"));
        assert!(!msg.to_lowercase().contains("password"));
        assert!(!msg.to_lowercase().contains("nonce"));
        assert!(!msg.to_lowercase().contains("tag"));
    }

    #[test]
    fn storage_error_does_not_leak_io_message() {
        let io = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "secret-path-abc123: permission denied",
        );
        let err: Error = io.into();
        let rendered = err.to_string();
        assert!(!rendered.contains("secret-path-abc123"));
        assert!(rendered.contains("permission denied"));
    }

    #[test]
    fn io_kinds_map_to_expected_categories() {
        assert_eq!(
            StorageErrorKind::from_io(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            StorageErrorKind::NotFound
        );
        assert_eq!(
            StorageErrorKind::from_io(&std::io::Error::from(
                std::io::ErrorKind::PermissionDenied
            )),
            StorageErrorKind::PermissionDenied
        );
        assert_eq!(
            StorageErrorKind::from_io(&std::io::Error::from(std::io::ErrorKind::AlreadyExists)),
            StorageErrorKind::AlreadyExists
        );
        assert_eq!(
            StorageErrorKind::from_io(&std::io::Error::from(std::io::ErrorKind::Other)),
            StorageErrorKind::Other
        );
    }
}
