//! Integration tests for the vault format, entry model, and lifecycle.
//!
//! These tests use only the public API of the library. Vault creation here
//! uses reduced Argon2id cost via a hand-built `KdfParams`, because
//! `VaultFile::new` uses the production defaults and would make the suite
//! slow. The rest of the code path — wrap/unwrap, encrypt/decrypt, JSON
//! serialization, entry validation — is identical to production.
//!
//! No test prints a secret. The largest literal used as a password is the
//! well-known phrase `"correct horse battery staple"`, a public test value.

use offline_vault::crypto::{
    self, KdfParams, KEY_LEN, KDF_NAME_ARGON2ID, SALT_LEN,
};
use offline_vault::error::Error;
use offline_vault::vault::{
    EncryptedBlob, Entry, KdfSection, UnlockedVault, VaultFile, MAX_ID_BYTES,
    MAX_NOTES_BYTES, MAX_PASSWORD_BYTES, MAX_TITLE_BYTES, MAX_TOTP_BYTES,
    MAX_URL_BYTES, MAX_USERNAME_BYTES, SUPPORTED_VERSION,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Cheap-but-valid KDF parameters for tests. They satisfy
/// `KdfParams::validate`; they are not the production defaults.
fn fast_params(salt: [u8; SALT_LEN]) -> KdfParams {
    KdfParams {
        name: KDF_NAME_ARGON2ID.to_string(),
        salt: salt.to_vec(),
        time_cost: 1,
        memory_cost: 19 * 1024,
        parallelism: 1,
        hash_len: KEY_LEN as u32,
    }
}

/// Build a vault with the given password and empty entry list, using fast
/// KDF parameters. Returns the serialized file bytes and the unlocked vault.
fn create_fast(password: &str) -> (Vec<u8>, UnlockedVault) {
    let params = fast_params([0x5au8; SALT_LEN]);
    let mk = crypto::derive_master_key(password.as_bytes(), &params).unwrap();
    let kek = crypto::derive_kek(mk.as_slice()).unwrap();
    let vk = crypto::random_vault_key().unwrap();

    let (wn, wc) = crypto::wrap_vault_key(kek.as_slice(), vk.as_slice()).unwrap();
    let (vn, vc) = crypto::encrypt_vault(vk.as_slice(), b"[]").unwrap();

    let file = VaultFile {
        version: SUPPORTED_VERSION,
        kdf: KdfSection::from_kdf_params(&params),
        wrapped_key: EncryptedBlob::from_raw(&wn, &wc),
        vault: EncryptedBlob::from_raw(&vn, &vc),
    };
    let unlocked = file.unlock(password).unwrap();
    (file.to_bytes().unwrap(), unlocked)
}

/// Flip the first Base64 character of a string to its neighbour. Used to
/// corrupt a Base64 field while keeping it syntactically valid, so the
/// failure we observe is authentication, not decoding.
fn corrupt_b64(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Create / reopen
// ---------------------------------------------------------------------------

#[test]
fn create_then_unlock_roundtrip_empty_vault() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let parsed = VaultFile::from_bytes(&bytes).unwrap();
    let vault = parsed.unlock("correct horse battery staple").unwrap();
    assert_eq!(vault.entries().len(), 0);
}

#[test]
fn create_then_unlock_roundtrip_with_entries() {
    let (_, mut unlocked) = create_fast("correct horse battery staple");
    let entry = Entry::new(
        "Example",
        "alice",
        "the-password",
        "https://example.com",
        "JBSWY3DPEHPK3PXP",
        "some notes",
    )
    .unwrap();
    let id = entry.id.clone();
    unlocked.add_entry(entry).unwrap();

    let sealed = unlocked.seal().unwrap();
    let reopened_bytes = sealed.to_bytes().unwrap();
    let parsed = VaultFile::from_bytes(&reopened_bytes).unwrap();
    let reopened = parsed.unlock("correct horse battery staple").unwrap();

    assert_eq!(reopened.entries().len(), 1);
    let e = &reopened.entries()[0];
    assert_eq!(e.id, id);
    assert_eq!(e.title, "Example");
    assert_eq!(e.username, "alice");
    assert_eq!(e.password, "the-password");
    assert_eq!(e.url, "https://example.com");
    assert_eq!(e.totp, "JBSWY3DPEHPK3PXP");
    assert_eq!(e.notes, "some notes");
}

#[test]
fn reopening_the_same_file_bytes_is_deterministic() {
    let (bytes, _) = create_fast("passphrase-value-1");
    let a = VaultFile::from_bytes(&bytes)
        .unwrap()
        .unlock("passphrase-value-1")
        .unwrap();
    let b = VaultFile::from_bytes(&bytes)
        .unwrap()
        .unlock("passphrase-value-1")
        .unwrap();
    assert_eq!(a.entries().len(), b.entries().len());
}

#[test]
fn vault_file_new_uses_production_defaults() {
    let (file, _) = VaultFile::new("correct horse battery staple").unwrap();
    file.validate().unwrap();
    assert_eq!(file.version, SUPPORTED_VERSION);
    assert_eq!(file.kdf.name, KDF_NAME_ARGON2ID);
    assert_eq!(file.kdf.time_cost, 3);
    assert_eq!(file.kdf.memory_cost, 65_536);
    assert_eq!(file.kdf.parallelism, 1);
    assert_eq!(file.kdf.hash_len, KEY_LEN as u32);
}

// ---------------------------------------------------------------------------
// Wrong password
// ---------------------------------------------------------------------------

#[test]
fn wrong_password_is_rejected_opaque() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let file = VaultFile::from_bytes(&bytes).unwrap();
    let err = file.unlock("not the right password").unwrap_err();
    assert!(matches!(err, Error::Authentication));
    let msg = err.to_string().to_lowercase();
    for forbidden in ["nonce", "tag", "gcm", "argon", "kdf", "key"] {
        assert!(
            !msg.contains(forbidden),
            "error message leaked `{forbidden}`: {msg}"
        );
    }
}

#[test]
fn empty_password_is_rejected() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let file = VaultFile::from_bytes(&bytes).unwrap();
    assert!(matches!(file.unlock(""), Err(Error::Authentication)));
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

#[test]
fn tampered_wrapped_key_nonce_is_rejected() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut file = VaultFile::from_bytes(&bytes).unwrap();
    file.wrapped_key.nonce = corrupt_b64(&file.wrapped_key.nonce);
    assert!(matches!(
        file.unlock("correct horse battery staple"),
        Err(Error::Authentication | Error::InvalidEncoding)
    ));
}

#[test]
fn tampered_wrapped_key_ciphertext_is_rejected() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut file = VaultFile::from_bytes(&bytes).unwrap();
    file.wrapped_key.ciphertext = corrupt_b64(&file.wrapped_key.ciphertext);
    assert!(matches!(
        file.unlock("correct horse battery staple"),
        Err(Error::Authentication | Error::InvalidEncoding)
    ));
}

#[test]
fn tampered_vault_nonce_is_rejected() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut file = VaultFile::from_bytes(&bytes).unwrap();
    file.vault.nonce = corrupt_b64(&file.vault.nonce);
    assert!(matches!(
        file.unlock("correct horse battery staple"),
        Err(Error::Authentication | Error::InvalidEncoding)
    ));
}

#[test]
fn tampered_vault_ciphertext_is_rejected() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut file = VaultFile::from_bytes(&bytes).unwrap();
    file.vault.ciphertext = corrupt_b64(&file.vault.ciphertext);
    assert!(matches!(
        file.unlock("correct horse battery staple"),
        Err(Error::Authentication | Error::InvalidEncoding)
    ));
}

#[test]
fn swapped_ciphertexts_are_rejected_by_aad_binding() {
    // Move the wrapped-key ciphertext into the vault slot and vice versa.
    // Because the two use different AADs, both must fail authentication.
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut file = VaultFile::from_bytes(&bytes).unwrap();
    std::mem::swap(&mut file.wrapped_key, &mut file.vault);
    assert!(matches!(
        file.unlock("correct horse battery staple"),
        Err(Error::Authentication)
    ));
}

// ---------------------------------------------------------------------------
// Format validation
// ---------------------------------------------------------------------------

#[test]
fn rejects_empty_input() {
    assert!(matches!(
        VaultFile::from_bytes(b""),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_non_json_input() {
    assert!(matches!(
        VaultFile::from_bytes(b"this is not json"),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_json_of_wrong_type() {
    assert!(matches!(
        VaultFile::from_bytes(b"[1, 2, 3]"),
        Err(Error::VaultFormat)
    ));
    assert!(matches!(
        VaultFile::from_bytes(b"\"a string\""),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_missing_required_fields() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let base: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for missing in ["version", "kdf", "wrapped_key", "vault"] {
        let mut v = base.clone();
        v.as_object_mut().unwrap().remove(missing);
        let bad = serde_json::to_vec(&v).unwrap();
        assert!(
            matches!(VaultFile::from_bytes(&bad), Err(Error::VaultFormat)),
            "missing `{missing}` was accepted"
        );
    }
}

#[test]
fn rejects_unknown_top_level_field() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("surprise".into(), serde_json::json!(1));
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_wrong_field_types() {
    let (bytes, _) = create_fast("correct horse battery staple");

    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["version"] = serde_json::json!("one");
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::VaultFormat)
    ));

    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["kdf"]["salt"] = serde_json::json!(42);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_unsupported_version() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["version"] = serde_json::json!(2);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::UnsupportedVersion)
    ));
}

#[test]
fn rejects_invalid_base64_in_salt() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["kdf"]["salt"] = serde_json::json!("!!! not base64 !!!");
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn rejects_wrong_salt_length() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let short_salt = B64.encode([0u8; 8]);
    v["kdf"]["salt"] = serde_json::json!(short_salt);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidKdfParameters)
    ));
}

#[test]
fn rejects_invalid_base64_in_ciphertext() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["vault"]["ciphertext"] = serde_json::json!("%%%");
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn rejects_wrong_nonce_length() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let short_nonce = B64.encode([0u8; 8]);
    v["vault"]["nonce"] = serde_json::json!(short_nonce);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn rejects_truncated_ciphertext() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // 15 bytes is one short of the 16-byte GCM tag.
    let tiny = B64.encode([0u8; 15]);
    v["vault"]["ciphertext"] = serde_json::json!(tiny);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidEncoding)
    ));
}

#[test]
fn rejects_weak_kdf_parameters_in_file() {
    let (bytes, _) = create_fast("correct horse battery staple");

    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["kdf"]["memory_cost"] = serde_json::json!(1024);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidKdfParameters)
    ));

    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["kdf"]["time_cost"] = serde_json::json!(0);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidKdfParameters)
    ));

    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["kdf"]["name"] = serde_json::json!("scrypt");
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidKdfParameters)
    ));
}

#[test]
fn rejects_wrong_hash_len_in_file() {
    let (bytes, _) = create_fast("correct horse battery staple");
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["kdf"]["hash_len"] = serde_json::json!(16);
    let bad = serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        VaultFile::from_bytes(&bad),
        Err(Error::InvalidKdfParameters)
    ));
}

// ---------------------------------------------------------------------------
// Entry validation
// ---------------------------------------------------------------------------

#[test]
fn entry_new_produces_valid_entry() {
    let e = Entry::new("t", "u", "p", "u", "totp", "notes").unwrap();
    assert!(!e.id.is_empty());
    assert!(e.id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(e.title, "t");
    assert_eq!(e.username, "u");
    assert_eq!(e.password, "p");
}

#[test]
fn entry_new_rejects_oversized_title() {
    let big = "x".repeat(MAX_TITLE_BYTES + 1);
    assert!(Entry::new(big, "u", "p", "u", "t", "n").is_err());
}

#[test]
fn entry_validation_rejects_each_oversized_field() {
    let cases: [(&str, usize); 6] = [
        ("title", MAX_TITLE_BYTES),
        ("username", MAX_USERNAME_BYTES),
        ("password", MAX_PASSWORD_BYTES),
        ("url", MAX_URL_BYTES),
        ("totp", MAX_TOTP_BYTES),
        ("notes", MAX_NOTES_BYTES),
    ];
    for (field, max) in cases {
        let mut e = Entry::new("t", "u", "p", "u", "t", "n").unwrap();
        let big = "x".repeat(max + 1);
        match field {
            "title" => e.title = big,
            "username" => e.username = big,
            "password" => e.password = big,
            "url" => e.url = big,
            "totp" => e.totp = big,
            "notes" => e.notes = big,
            _ => unreachable!(),
        }
        let (_, mut vault) = create_fast("correct horse battery staple");
        assert!(vault.add_entry(e).is_err(), "accepted oversized {field}");
    }
}

#[test]
fn entry_id_must_be_ascii_hex() {
    let mut e = Entry::new("t", "u", "p", "u", "t", "n").unwrap();
    e.id = "not hex!!!".into();
    let (_, mut vault) = create_fast("correct horse battery staple");
    assert!(vault.add_entry(e).is_err());
}

#[test]
fn entry_id_must_not_exceed_max_id_bytes() {
    let mut e = Entry::new("t", "u", "p", "u", "t", "n").unwrap();
    e.id = "a".repeat(MAX_ID_BYTES + 1);
    let (_, mut vault) = create_fast("correct horse battery staple");
    assert!(vault.add_entry(e).is_err());
}

#[test]
fn duplicate_ids_are_rejected_on_add() {
    let (_, mut vault) = create_fast("correct horse battery staple");
    let e1 = Entry::new("t1", "u", "p", "u", "t", "n").unwrap();
    let id = e1.id.clone();
    vault.add_entry(e1).unwrap();

    let mut e2 = Entry::new("t2", "u", "p", "u", "t", "n").unwrap();
    e2.id = id;
    assert!(vault.add_entry(e2).is_err());
}

#[test]
fn duplicate_ids_are_rejected_on_load() {
    // Craft a vault whose decrypted payload contains two entries with the
    // same id by pushing directly through `entries_mut`, bypassing
    // `add_entry`'s check. The loader must reject the result on reopen.
    let (_, mut unlocked) = create_fast("correct horse battery staple");
    let e1 = Entry::new("t1", "u", "p", "u", "t", "n").unwrap();
    let mut e2 = Entry::new("t2", "u", "p", "u", "t", "n").unwrap();
    e2.id = e1.id.clone();
    unlocked.entries_mut().push(e1);
    unlocked.entries_mut().push(e2);

    let sealed = unlocked.seal().unwrap();
    let bytes = sealed.to_bytes().unwrap();
    let parsed = VaultFile::from_bytes(&bytes).unwrap();
    assert!(matches!(
        parsed.unlock("correct horse battery staple"),
        Err(Error::InvalidEntry)
    ));
}

#[test]
fn update_replaces_entry_by_id() {
    let (_, mut vault) = create_fast("correct horse battery staple");
    let e = Entry::new("old", "u", "p", "u", "t", "n").unwrap();
    let id = e.id.clone();
    vault.add_entry(e).unwrap();

    let mut updated = Entry::new("new", "u", "p2", "u", "t", "n").unwrap();
    updated.id = id.clone();
    assert!(vault.update_entry(updated).unwrap());

    let stored = vault.entries().iter().find(|e| e.id == id).unwrap();
    assert_eq!(stored.title, "new");
    assert_eq!(stored.password, "p2");
}

#[test]
fn update_missing_id_returns_false() {
    let (_, mut vault) = create_fast("correct horse battery staple");
    let mut e = Entry::new("t", "u", "p", "u", "t", "n").unwrap();
    e.id = "ffffffffffffffffffffffffffffffff".into();
    assert!(!vault.update_entry(e).unwrap());
}

#[test]
fn remove_returns_true_only_when_present() {
    let (_, mut vault) = create_fast("correct horse battery staple");
    let e = Entry::new("t", "u", "p", "u", "t", "n").unwrap();
    let id = e.id.clone();
    vault.add_entry(e).unwrap();
    assert!(vault.remove_entry(&id));
    assert!(!vault.remove_entry(&id));
}

// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------

#[test]
fn lock_clears_entries() {
    let (_, mut vault) = create_fast("correct horse battery staple");
    vault
        .add_entry(Entry::new("t", "u", "p", "u", "t", "n").unwrap())
        .unwrap();
    assert_eq!(vault.entries().len(), 1);
    vault.lock();
    assert_eq!(vault.entries().len(), 0);
}

// ---------------------------------------------------------------------------
// Debug redaction
// ---------------------------------------------------------------------------

#[test]
fn entry_debug_redacts_secrets() {
    let e = Entry::new(
        "Visible Title",
        "visible-user",
        "SUPER-SECRET-PASSWORD",
        "https://visible.example.com",
        "SUPER-SECRET-TOTP",
        "SECRET-NOTES",
    )
    .unwrap();
    let dump = format!("{e:?}");
    assert!(!dump.contains("SUPER-SECRET-PASSWORD"));
    assert!(!dump.contains("SUPER-SECRET-TOTP"));
    assert!(!dump.contains("SECRET-NOTES"));
    assert!(dump.contains("[REDACTED]"));
    assert!(dump.contains("Visible Title"));
}
