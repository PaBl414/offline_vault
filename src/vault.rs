//! Vault model, on-disk format, and lifecycle.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, KdfParams, KDF_NAME_ARGON2ID, NONCE_LEN, SALT_LEN};
use crate::error::{Error, Result};
use crate::security::SecureBuffer;

/// Maximum size of the vault JSON file on disk.
pub const MAX_VAULT_FILE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum size of the decrypted vault payload (entries JSON).
pub const MAX_DECRYPTED_BYTES: usize = 48 * 1024 * 1024;
/// Maximum number of entries in a vault.
pub const MAX_ENTRIES: usize = 100_000;

pub const MAX_ID_BYTES: usize = 128;
pub const MAX_TITLE_BYTES: usize = 1024;
pub const MAX_USERNAME_BYTES: usize = 4096;
pub const MAX_PASSWORD_BYTES: usize = 16 * 1024;
pub const MAX_URL_BYTES: usize = 4096;
pub const MAX_TOTP_BYTES: usize = 1024;
pub const MAX_NOTES_BYTES: usize = 64 * 1024;

/// The only supported vault format version.
pub const SUPPORTED_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: KdfSection,
    pub wrapped_key: EncryptedBlob,
    pub vault: EncryptedBlob,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct KdfSection {
    pub name: String,
    pub salt: String,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
    pub hash_len: u32,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EncryptedBlob {
    pub nonce: String,
    pub ciphertext: String,
}

impl KdfSection {
    pub fn to_kdf_params(&self) -> Result<KdfParams> {
        if self.name != KDF_NAME_ARGON2ID {
            return Err(Error::InvalidKdfParameters);
        }
        let salt = B64
            .decode(self.salt.as_bytes())
            .map_err(|_| Error::InvalidEncoding)?;
        if salt.len() != SALT_LEN {
            return Err(Error::InvalidKdfParameters);
        }
        let params = KdfParams {
            name: self.name.clone(),
            salt,
            time_cost: self.time_cost,
            memory_cost: self.memory_cost,
            parallelism: self.parallelism,
            hash_len: self.hash_len,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn from_kdf_params(params: &KdfParams) -> Self {
        Self {
            name: params.name.clone(),
            salt: B64.encode(&params.salt),
            time_cost: params.time_cost,
            memory_cost: params.memory_cost,
            parallelism: params.parallelism,
            hash_len: params.hash_len,
        }
    }
}

impl EncryptedBlob {
    pub fn decode_nonce(&self) -> Result<Vec<u8>> {
        let n = B64
            .decode(self.nonce.as_bytes())
            .map_err(|_| Error::InvalidEncoding)?;
        if n.len() != NONCE_LEN {
            return Err(Error::InvalidEncoding);
        }
        Ok(n)
    }

    pub fn decode_ciphertext(&self) -> Result<Vec<u8>> {
        let c = B64
            .decode(self.ciphertext.as_bytes())
            .map_err(|_| Error::InvalidEncoding)?;
        if c.len() < 16 {
            return Err(Error::InvalidEncoding);
        }
        Ok(c)
    }

    pub fn from_raw(nonce: &[u8], ciphertext: &[u8]) -> Self {
        Self {
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        }
    }
}

impl VaultFile {
    pub fn new(password: &str) -> Result<(Self, UnlockedVault)> {
        if password.is_empty() {
            return Err(Error::PasswordTooShort { min: 12 });
        }

        let kdf_params = KdfParams::new_vault_default()?;
        let master_key = crypto::derive_master_key(password.as_bytes(), &kdf_params)?;
        let kek = crypto::derive_kek(master_key.as_slice())?;
        let vault_key = crypto::random_vault_key()?;

        let (wrap_nonce, wrap_ct) = crypto::wrap_vault_key(kek.as_slice(), vault_key.as_slice())?;

        let initial_payload = b"[]";
        let (vault_nonce, vault_ct) = crypto::encrypt_vault(vault_key.as_slice(), initial_payload)?;

        let file = VaultFile {
            version: SUPPORTED_VERSION,
            kdf: KdfSection::from_kdf_params(&kdf_params),
            wrapped_key: EncryptedBlob::from_raw(&wrap_nonce, &wrap_ct),
            vault: EncryptedBlob::from_raw(&vault_nonce, &vault_ct),
        };

        let unlocked = UnlockedVault {
            entries: Vec::new(),
            vault_key,
            wrapped_key: file.wrapped_key.clone(),
            kdf: file.kdf.clone(),
            version: file.version,
        };

        Ok((file, unlocked))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_VAULT_FILE_BYTES {
            return Err(Error::VaultFormat);
        }
        let parsed: VaultFile = serde_json::from_slice(bytes).map_err(|_| Error::VaultFormat)?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Error::VaultFormat)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != SUPPORTED_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let _ = self.kdf.to_kdf_params()?;
        let _ = self.wrapped_key.decode_nonce()?;
        let _ = self.wrapped_key.decode_ciphertext()?;
        let _ = self.vault.decode_nonce()?;
        let _ = self.vault.decode_ciphertext()?;
        Ok(())
    }

    pub fn unlock(&self, password: &str) -> Result<UnlockedVault> {
        self.validate()?;

        let kdf_params = self.kdf.to_kdf_params()?;
        let master_key = crypto::derive_master_key(password.as_bytes(), &kdf_params)?;
        let kek = crypto::derive_kek(master_key.as_slice())?;

        let wrap_nonce = self.wrapped_key.decode_nonce()?;
        let wrap_ct = self.wrapped_key.decode_ciphertext()?;
        let vault_key = crypto::unwrap_vault_key(kek.as_slice(), &wrap_nonce, &wrap_ct)?;

        let payload_nonce = self.vault.decode_nonce()?;
        let payload_ct = self.vault.decode_ciphertext()?;
        let payload = crypto::decrypt_vault(vault_key.as_slice(), &payload_nonce, &payload_ct)?;

        if payload.len() > MAX_DECRYPTED_BYTES {
            return Err(Error::VaultFormat);
        }

        let entries: Vec<Entry> =
            serde_json::from_slice(payload.as_slice()).map_err(|_| Error::InvalidEntry)?;
        validate_entries(&entries)?;

        Ok(UnlockedVault {
            entries,
            vault_key,
            wrapped_key: self.wrapped_key.clone(),
            kdf: self.kdf.clone(),
            version: self.version,
        })
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub totp: String,
    pub notes: String,
}

impl Entry {
    pub fn new(
        title: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        url: impl Into<String>,
        totp: impl Into<String>,
        notes: impl Into<String>,
    ) -> Result<Self> {
        let entry = Entry {
            id: new_id()?,
            title: title.into(),
            username: username.into(),
            password: password.into(),
            url: url.into(),
            totp: totp.into(),
            notes: notes.into(),
        };
        validate_entry(&entry)?;
        Ok(entry)
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("totp", &"[REDACTED]")
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

pub fn new_id() -> Result<String> {
    let bytes = crypto::random_bytes::<16>()?;
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).map_err(|_| Error::Crypto)?;
    }
    Ok(s)
}

fn validate_entry(e: &Entry) -> Result<()> {
    if e.id.is_empty() || e.id.len() > MAX_ID_BYTES {
        return Err(Error::InvalidEntry);
    }
    if !e.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidEntry);
    }
    if e.title.len() > MAX_TITLE_BYTES
        || e.username.len() > MAX_USERNAME_BYTES
        || e.password.len() > MAX_PASSWORD_BYTES
        || e.url.len() > MAX_URL_BYTES
        || e.totp.len() > MAX_TOTP_BYTES
        || e.notes.len() > MAX_NOTES_BYTES
    {
        return Err(Error::InvalidEntry);
    }
    Ok(())
}

fn validate_entries(entries: &[Entry]) -> Result<()> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::InvalidEntry);
    }
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    for e in entries {
        validate_entry(e)?;
        if !seen.insert(e.id.as_str()) {
            return Err(Error::InvalidEntry);
        }
    }
    Ok(())
}

/// The in-memory, unlocked vault.
pub struct UnlockedVault {
    entries: Vec<Entry>,
    vault_key: SecureBuffer,
    wrapped_key: EncryptedBlob,
    kdf: KdfSection,
    version: u32,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print entries, the Vault Key, or the wrapped key material.
        f.write_str("UnlockedVault([REDACTED])")
    }
}

impl UnlockedVault {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn entries_mut(&mut self) -> &mut Vec<Entry> {
        &mut self.entries
    }

    pub fn add_entry(&mut self, entry: Entry) -> Result<()> {
        validate_entry(&entry)?;
        if self.entries.iter().any(|e| e.id == entry.id) {
            return Err(Error::InvalidEntry);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Error::InvalidEntry);
        }
        self.entries.push(entry);
        Ok(())
    }

    pub fn update_entry(&mut self, entry: Entry) -> Result<bool> {
        validate_entry(&entry)?;
        for slot in self.entries.iter_mut() {
            if slot.id == entry.id {
                *slot = entry;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn remove_entry(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        before != self.entries.len()
    }

    pub fn seal(&self) -> Result<VaultFile> {
        let raw = serde_json::to_vec(&self.entries).map_err(|_| Error::VaultFormat)?;
        let json = Zeroizing::new(raw);

        if json.len() > MAX_DECRYPTED_BYTES {
            return Err(Error::VaultFormat);
        }

        let (nonce, ct) = crypto::encrypt_vault(self.vault_key.as_slice(), &json)?;

        Ok(VaultFile {
            version: self.version,
            kdf: self.kdf.clone(),
            wrapped_key: self.wrapped_key.clone(),
            vault: EncryptedBlob::from_raw(&nonce, &ct),
        })
    }

    pub fn lock(&mut self) {
        self.entries.clear();
        self.entries.shrink_to_fit();
        let fresh = SecureBuffer::new();
        self.vault_key = fresh;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KEY_LEN;

    fn fast_create(password: &str) -> Result<(VaultFile, UnlockedVault)> {
        let kdf_params = KdfParams {
            name: KDF_NAME_ARGON2ID.to_string(),
            salt: crate::crypto::random_bytes::<SALT_LEN>()?.to_vec(),
            time_cost: 1,
            memory_cost: 19 * 1024,
            parallelism: 1,
            hash_len: KEY_LEN as u32,
        };
        let master_key = crypto::derive_master_key(password.as_bytes(), &kdf_params)?;
        let kek = crypto::derive_kek(master_key.as_slice())?;
        let vault_key = crypto::random_vault_key()?;
        let (wrap_nonce, wrap_ct) = crypto::wrap_vault_key(kek.as_slice(), vault_key.as_slice())?;
        let (vault_nonce, vault_ct) = crypto::encrypt_vault(vault_key.as_slice(), b"[]")?;
        let file = VaultFile {
            version: SUPPORTED_VERSION,
            kdf: KdfSection::from_kdf_params(&kdf_params),
            wrapped_key: EncryptedBlob::from_raw(&wrap_nonce, &wrap_ct),
            vault: EncryptedBlob::from_raw(&vault_nonce, &vault_ct),
        };
        let unlocked = UnlockedVault {
            entries: Vec::new(),
            vault_key,
            wrapped_key: file.wrapped_key.clone(),
            kdf: file.kdf.clone(),
            version: file.version,
        };
        Ok((file, unlocked))
    }

    #[test]
    fn create_then_unlock_roundtrip() {
        let (file, _) = fast_create("correct horse battery staple").unwrap();
        let bytes = file.to_bytes().unwrap();
        let parsed = VaultFile::from_bytes(&bytes).unwrap();
        let vault = parsed.unlock("correct horse battery staple").unwrap();
        assert_eq!(vault.entries().len(), 0);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (file, _) = fast_create("correct horse battery staple").unwrap();
        let err = file.unlock("wrong password entirely").unwrap_err();
        assert!(matches!(err, Error::Authentication));
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let (mut file, _) = fast_create("correct horse battery staple").unwrap();
        let mut chars: Vec<char> = file.wrapped_key.ciphertext.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        file.wrapped_key.ciphertext = chars.into_iter().collect();

        let err = file.unlock("correct horse battery staple").unwrap_err();
        assert!(matches!(
            err,
            Error::Authentication | Error::InvalidEncoding
        ));
    }

    #[test]
    fn tampered_vault_payload_is_rejected() {
        let (mut file, _) = fast_create("correct horse battery staple").unwrap();
        let mut chars: Vec<char> = file.vault.ciphertext.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        file.vault.ciphertext = chars.into_iter().collect();

        let err = file.unlock("correct horse battery staple").unwrap_err();
        assert!(matches!(
            err,
            Error::Authentication | Error::InvalidEncoding
        ));
    }

    #[test]
    fn roundtrip_with_entries_preserves_content() {
        let (_, mut unlocked) = fast_create("correct horse battery staple").unwrap();
        let entry = Entry::new(
            "Example",
            "alice",
            "hunter2hunter2",
            "https://example.com",
            "JBSWY3DPEHPK3PXP",
            "notes",
        )
        .unwrap();
        let id = entry.id.clone();
        unlocked.add_entry(entry).unwrap();

        let sealed = unlocked.seal().unwrap();
        let bytes = sealed.to_bytes().unwrap();
        let parsed = VaultFile::from_bytes(&bytes).unwrap();
        let reopened = parsed.unlock("correct horse battery staple").unwrap();

        assert_eq!(reopened.entries().len(), 1);
        let e = &reopened.entries()[0];
        assert_eq!(e.id, id);
        assert_eq!(e.title, "Example");
        assert_eq!(e.username, "alice");
        assert_eq!(e.password, "hunter2hunter2");
        assert_eq!(e.url, "https://example.com");
        assert_eq!(e.totp, "JBSWY3DPEHPK3PXP");
        assert_eq!(e.notes, "notes");
    }

    #[test]
    fn validation_rejects_bad_versions_and_fields() {
        let (mut file, _) = fast_create("correct horse battery staple").unwrap();
        file.version = 2;
        assert!(matches!(
            VaultFile::from_bytes(&file.to_bytes().unwrap()),
            Err(Error::UnsupportedVersion)
        ));

        let (file, _) = fast_create("correct horse battery staple").unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&file.to_bytes().unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("vault");
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(matches!(
            VaultFile::from_bytes(&bytes),
            Err(Error::VaultFormat)
        ));
    }

    #[test]
    fn validation_rejects_weak_kdf_parameters() {
        let (mut file, _) = fast_create("correct horse battery staple").unwrap();
        file.kdf.memory_cost = 1024;
        assert!(matches!(
            VaultFile::from_bytes(&file.to_bytes().unwrap()),
            Err(Error::InvalidKdfParameters)
        ));
    }

    #[test]
    fn entry_validation_rejects_oversized_fields() {
        let mut e = Entry::new("t", "u", "p", "u", "t", "n").unwrap();
        e.title = "x".repeat(MAX_TITLE_BYTES + 1);
        assert!(matches!(validate_entry(&e), Err(Error::InvalidEntry)));
    }

    #[test]
    fn entry_validation_rejects_duplicate_ids() {
        let e1 = Entry::new("t1", "u", "p", "u", "t", "n").unwrap();
        let mut e2 = Entry::new("t2", "u", "p", "u", "t", "n").unwrap();
        e2.id = e1.id.clone();
        let v = vec![e1, e2];
        assert!(matches!(validate_entries(&v), Err(Error::InvalidEntry)));
    }

    #[test]
    fn locking_clears_state() {
        let (_, mut unlocked) = fast_create("correct horse battery staple").unwrap();
        let entry = Entry::new("t", "u", "p", "u", "t", "n").unwrap();
        unlocked.add_entry(entry).unwrap();
        assert_eq!(unlocked.entries().len(), 1);
        unlocked.lock();
        assert_eq!(unlocked.entries().len(), 0);
        assert_eq!(unlocked.vault_key.len(), 0);
    }
}
