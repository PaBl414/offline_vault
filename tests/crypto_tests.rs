//! Integration tests for the public cryptographic API.
//!
//! These tests use only the public surface of the `offline_vault` library.
//! No test prints a secret. The largest literal used as input is the
//! well-known phrase `b"correct horse battery staple"`, which is a public
//! test value, not a credential.
//!
//! ## Note on the Argon2id known-answer vector
//!
//! The published Argon2id vectors (for example, from RFC 9106 and the
//! `argon2` crate's own test suite) use an 8-byte salt. Our vault format
//! fixes the salt at 16 bytes and `KdfParams::validate` rejects anything
//! else, so those vectors cannot be driven through `derive_master_key`
//! without weakening a format rule. That specific vector is therefore
//! exercised as an inline `#[cfg(test)]` test inside `src/crypto.rs`, where
//! the `argon2` crate is available directly.

use std::collections::HashSet;

use offline_vault::crypto::{
    self, KdfParams, AAD_VAULT, AAD_VAULT_KEY, KDF_NAME_ARGON2ID, KEY_LEN, NONCE_LEN, SALT_LEN,
};
use offline_vault::error::Error;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Cheap-but-valid Argon2id parameters for tests. They satisfy
/// `KdfParams::validate`; they are not the production defaults. They keep
/// the suite well under a second.
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

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

#[test]
fn argon2id_is_deterministic() {
    let params = fast_params([0x11; SALT_LEN]);
    let a = crypto::derive_master_key(b"correct horse battery staple", &params).unwrap();
    let b = crypto::derive_master_key(b"correct horse battery staple", &params).unwrap();
    assert_eq!(a.len(), KEY_LEN);
    assert_eq!(a.as_slice(), b.as_slice());
}

#[test]
fn argon2id_is_salt_sensitive() {
    let p1 = fast_params([0x00; SALT_LEN]);
    let p2 = fast_params([0x01; SALT_LEN]);
    let a = crypto::derive_master_key(b"same password", &p1).unwrap();
    let b = crypto::derive_master_key(b"same password", &p2).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn argon2id_is_password_sensitive() {
    let params = fast_params([0x22; SALT_LEN]);
    let a = crypto::derive_master_key(b"password one", &params).unwrap();
    let b = crypto::derive_master_key(b"password two", &params).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn argon2id_output_is_exactly_32_bytes() {
    let params = fast_params([0x33; SALT_LEN]);
    let key = crypto::derive_master_key(b"whatever", &params).unwrap();
    assert_eq!(key.len(), KEY_LEN);
}

// ---------------------------------------------------------------------------
// KdfParams validation
// ---------------------------------------------------------------------------

#[test]
fn kdf_params_reject_unknown_algorithm_name() {
    let mut p = fast_params([0u8; SALT_LEN]);
    p.name = "scrypt".into();
    assert!(matches!(p.validate(), Err(Error::InvalidKdfParameters)));
}

#[test]
fn kdf_params_reject_wrong_salt_length() {
    let mut p = fast_params([0u8; SALT_LEN]);
    p.salt = vec![0u8; SALT_LEN - 1];
    assert!(matches!(p.validate(), Err(Error::InvalidKdfParameters)));

    let mut p = fast_params([0u8; SALT_LEN]);
    p.salt = vec![0u8; SALT_LEN + 1];
    assert!(matches!(p.validate(), Err(Error::InvalidKdfParameters)));
}

#[test]
fn kdf_params_reject_weak_or_extreme_costs() {
    let mut p = fast_params([0u8; SALT_LEN]);
    p.time_cost = 0;
    assert!(p.validate().is_err());

    let mut p = fast_params([0u8; SALT_LEN]);
    p.time_cost = 1024;
    assert!(p.validate().is_err());

    let mut p = fast_params([0u8; SALT_LEN]);
    p.memory_cost = 1024;
    assert!(p.validate().is_err());

    let mut p = fast_params([0u8; SALT_LEN]);
    p.memory_cost = 8 * 1024 * 1024;
    assert!(p.validate().is_err());

    let mut p = fast_params([0u8; SALT_LEN]);
    p.parallelism = 0;
    assert!(p.validate().is_err());
}

#[test]
fn kdf_params_reject_wrong_hash_len() {
    let mut p = fast_params([0u8; SALT_LEN]);
    p.hash_len = 16;
    assert!(matches!(p.validate(), Err(Error::InvalidKdfParameters)));

    let mut p = fast_params([0u8; SALT_LEN]);
    p.hash_len = 64;
    assert!(matches!(p.validate(), Err(Error::InvalidKdfParameters)));
}

#[test]
fn new_vault_default_params_satisfy_validate() {
    let p = KdfParams::new_vault_default().unwrap();
    p.validate().unwrap();
    assert_eq!(p.name, KDF_NAME_ARGON2ID);
    assert_eq!(p.salt.len(), SALT_LEN);
    assert_eq!(p.hash_len, KEY_LEN as u32);
    assert_eq!(p.parallelism, 1);
}

// ---------------------------------------------------------------------------
// HKDF-SHA256
// ---------------------------------------------------------------------------

#[test]
fn hkdf_is_deterministic_and_32_bytes() {
    let mk = [0x42u8; KEY_LEN];
    let a = crypto::derive_kek(&mk).unwrap();
    let b = crypto::derive_kek(&mk).unwrap();
    assert_eq!(a.len(), KEY_LEN);
    assert_eq!(a.as_slice(), b.as_slice());
}

#[test]
fn hkdf_differs_for_different_master_key() {
    let a = crypto::derive_kek(&[0u8; KEY_LEN]).unwrap();
    let b = crypto::derive_kek(&[1u8; KEY_LEN]).unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

#[test]
fn hkdf_rejects_wrong_length_master_key() {
    assert!(crypto::derive_kek(&[0u8; KEY_LEN - 1]).is_err());
    assert!(crypto::derive_kek(&[0u8; KEY_LEN + 1]).is_err());
}

// ---------------------------------------------------------------------------
// AES-256-GCM wrap of the Vault Key
// ---------------------------------------------------------------------------

#[test]
fn wrap_and_unwrap_roundtrip() {
    let kek = [0x33u8; KEY_LEN];
    let vk = [0x44u8; KEY_LEN];

    let (nonce, ct) = crypto::wrap_vault_key(&kek, &vk).unwrap();
    assert_eq!(nonce.len(), NONCE_LEN);
    assert_eq!(ct.len(), KEY_LEN + 16);

    let unwrapped = crypto::unwrap_vault_key(&kek, &nonce, &ct).unwrap();
    assert_eq!(unwrapped.as_slice(), &vk);
}

#[test]
fn wrap_rejects_tampered_ciphertext() {
    let kek = [0x33u8; KEY_LEN];
    let vk = [0x44u8; KEY_LEN];
    let (nonce, mut ct) = crypto::wrap_vault_key(&kek, &vk).unwrap();
    ct[0] ^= 0x01;
    assert!(matches!(
        crypto::unwrap_vault_key(&kek, &nonce, &ct),
        Err(Error::Authentication)
    ));
}

#[test]
fn wrap_rejects_tampered_nonce() {
    let kek = [0x33u8; KEY_LEN];
    let vk = [0x44u8; KEY_LEN];
    let (mut nonce, ct) = crypto::wrap_vault_key(&kek, &vk).unwrap();
    nonce[0] ^= 0x01;
    assert!(matches!(
        crypto::unwrap_vault_key(&kek, &nonce, &ct),
        Err(Error::Authentication)
    ));
}

#[test]
fn wrap_rejects_wrong_kek() {
    let kek = [0x33u8; KEY_LEN];
    let vk = [0x44u8; KEY_LEN];
    let (nonce, ct) = crypto::wrap_vault_key(&kek, &vk).unwrap();
    let bad = [0x55u8; KEY_LEN];
    assert!(matches!(
        crypto::unwrap_vault_key(&bad, &nonce, &ct),
        Err(Error::Authentication)
    ));
}

#[test]
fn wrap_rejects_wrong_length_kek() {
    let vk = [0x44u8; KEY_LEN];
    let (nonce, ct) = crypto::wrap_vault_key(&[0x33u8; KEY_LEN], &vk).unwrap();
    assert!(matches!(
        crypto::unwrap_vault_key(&[0u8; KEY_LEN - 1], &nonce, &ct),
        Err(Error::Crypto)
    ));
}

#[test]
fn wrap_rejects_wrong_length_vault_key() {
    assert!(crypto::wrap_vault_key(&[0u8; KEY_LEN], &[0u8; KEY_LEN - 1]).is_err());
    assert!(crypto::wrap_vault_key(&[0u8; KEY_LEN], &[0u8; KEY_LEN + 1]).is_err());
}

#[test]
fn unwrap_rejects_truncated_ciphertext() {
    let kek = [0x33u8; KEY_LEN];
    let nonce = [0u8; NONCE_LEN];
    let short = vec![0u8; 15];
    assert!(matches!(
        crypto::unwrap_vault_key(&kek, &nonce, &short),
        Err(Error::Authentication)
    ));
}

#[test]
fn unwrap_rejects_wrong_nonce_length() {
    let kek = [0x33u8; KEY_LEN];
    let (_, ct) = crypto::wrap_vault_key(&kek, &[0x44u8; KEY_LEN]).unwrap();
    let bad_nonce = vec![0u8; NONCE_LEN - 1];
    assert!(matches!(
        crypto::unwrap_vault_key(&kek, &bad_nonce, &ct),
        Err(Error::Authentication)
    ));
}

// ---------------------------------------------------------------------------
// AES-256-GCM vault payload
// ---------------------------------------------------------------------------

#[test]
fn vault_payload_roundtrip() {
    let vk = [0x66u8; KEY_LEN];
    let pt = b"{\"entries\":[]}";
    let (nonce, ct) = crypto::encrypt_vault(&vk, pt).unwrap();
    assert_eq!(nonce.len(), NONCE_LEN);
    let recovered = crypto::decrypt_vault(&vk, &nonce, &ct).unwrap();
    assert_eq!(recovered.as_slice(), pt);
}

#[test]
fn vault_payload_rejects_tampered_ciphertext() {
    let vk = [0x66u8; KEY_LEN];
    let (nonce, mut ct) = crypto::encrypt_vault(&vk, b"data").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x80;
    assert!(matches!(
        crypto::decrypt_vault(&vk, &nonce, &ct),
        Err(Error::Authentication)
    ));
}

#[test]
fn vault_payload_rejects_tampered_nonce() {
    let vk = [0x66u8; KEY_LEN];
    let (mut nonce, ct) = crypto::encrypt_vault(&vk, b"data").unwrap();
    nonce[NONCE_LEN - 1] ^= 0x01;
    assert!(matches!(
        crypto::decrypt_vault(&vk, &nonce, &ct),
        Err(Error::Authentication)
    ));
}

#[test]
fn vault_payload_rejects_wrong_key() {
    let vk = [0x66u8; KEY_LEN];
    let (nonce, ct) = crypto::encrypt_vault(&vk, b"data").unwrap();
    let bad = [0x67u8; KEY_LEN];
    assert!(matches!(
        crypto::decrypt_vault(&bad, &nonce, &ct),
        Err(Error::Authentication)
    ));
}

#[test]
fn vault_payload_rejects_truncated_ciphertext() {
    let vk = [0x66u8; KEY_LEN];
    let nonce = [0u8; NONCE_LEN];
    assert!(matches!(
        crypto::decrypt_vault(&vk, &nonce, &[0u8; 15]),
        Err(Error::Authentication)
    ));
}

// ---------------------------------------------------------------------------
// AAD separation
// ---------------------------------------------------------------------------

#[test]
fn vault_and_wrapped_key_use_distinct_aad() {
    assert_ne!(AAD_VAULT_KEY, AAD_VAULT);
    assert_eq!(AAD_VAULT_KEY, b"vault_key");
    assert_eq!(AAD_VAULT, b"vault");
}

#[test]
fn cross_purpose_ciphertext_is_rejected() {
    let key = [0x77u8; KEY_LEN];
    let plaintext = [0x88u8; KEY_LEN];

    let (wrap_nonce, wrap_ct) = crypto::wrap_vault_key(&key, &plaintext).unwrap();
    assert!(matches!(
        crypto::decrypt_vault(&key, &wrap_nonce, &wrap_ct),
        Err(Error::Authentication)
    ));

    let (vault_nonce, vault_ct) = crypto::encrypt_vault(&key, &plaintext).unwrap();
    assert!(matches!(
        crypto::unwrap_vault_key(&key, &vault_nonce, &vault_ct),
        Err(Error::Authentication)
    ));
}

// ---------------------------------------------------------------------------
// Nonce uniqueness
// ---------------------------------------------------------------------------

#[test]
fn nonces_are_unique_for_vault_encryption() {
    let key = [0x99u8; KEY_LEN];
    let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::new();
    for _ in 0..256 {
        let (n, _) = crypto::encrypt_vault(&key, b"payload").unwrap();
        assert!(seen.insert(n), "AES-GCM nonce reuse detected");
    }
}

#[test]
fn nonces_are_unique_for_key_wrapping() {
    let kek = [0xaau8; KEY_LEN];
    let vk = [0xbbu8; KEY_LEN];
    let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::new();
    for _ in 0..256 {
        let (n, _) = crypto::wrap_vault_key(&kek, &vk).unwrap();
        assert!(seen.insert(n), "AES-GCM nonce reuse detected");
    }
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

#[test]
fn random_bytes_are_not_constant() {
    let a = crypto::random_bytes::<32>().unwrap();
    let b = crypto::random_bytes::<32>().unwrap();
    assert_ne!(a, b);
}

#[test]
fn random_vault_key_is_32_bytes() {
    let k = crypto::random_vault_key().unwrap();
    assert_eq!(k.len(), KEY_LEN);
}

#[test]
fn random_vault_keys_are_distinct() {
    let a = crypto::random_vault_key().unwrap();
    let b = crypto::random_vault_key().unwrap();
    assert_ne!(a.as_slice(), b.as_slice());
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn format_constants_match_specification() {
    assert_eq!(SALT_LEN, 16);
    assert_eq!(NONCE_LEN, 12);
    assert_eq!(KEY_LEN, 32);
    assert_eq!(KDF_NAME_ARGON2ID, "argon2id");
}
