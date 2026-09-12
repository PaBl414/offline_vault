//! Cryptographic primitives: Argon2id KDF, HKDF-SHA256, AES-256-GCM.
//!
//! Every operation here delegates to a vetted RustCrypto primitive. Nothing in
//! this file re-implements a cryptographic algorithm, a KDF, an authentication
//! tag, or a random number generator.
//!
//! ## Key hierarchy implemented here
//!
//! ```text
//!   master password --Argon2id--> Master Key (32 bytes)
//!   Master Key      --HKDF-SHA256 (info=b"vault-key-encryption")--> KEK (32 bytes)
//!   random          ------------> Vault Key (32 bytes)
//!   KEK             --AES-256-GCM (AAD=b"vault_key")--> wrapped Vault Key
//!   Vault Key       --AES-256-GCM (AAD=b"vault")------> encrypted vault payload
//! ```
//!
//! ## HKDF salt
//!
//! RFC 5869 defines an empty salt as `HashLen` zero bytes. We use that default
//! (`Hkdf::new(None, ikm)`) because the input keying material is already a
//! high-entropy Argon2id output; adding an attacker-known salt would not
//! increase security. This choice is made explicitly, not by accident.
//!
//! ## Nonces
//!
//! Every encryption call generates a fresh 12-byte nonce from the operating
//! system CSPRNG. The nonce is returned to the caller so it can be stored
//! alongside the ciphertext. This module never reuses a nonce with the same
//! AES key.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::security::SecureBuffer;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Length of the Argon2id salt, in bytes.
pub const SALT_LEN: usize = 16;

/// Length of every AES-256-GCM nonce, in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of the Master Key, KEK, and Vault Key, in bytes.
pub const KEY_LEN: usize = 32;

/// AAD used when wrapping the Vault Key with the KEK.
pub const AAD_VAULT_KEY: &[u8] = b"vault_key";

/// AAD used when encrypting the vault payload with the Vault Key.
pub const AAD_VAULT: &[u8] = b"vault";

/// HKDF `info` string for the KEK derivation.
pub const HKDF_INFO_KEK: &[u8] = b"vault-key-encryption";

/// The only accepted KDF name in this version of the format.
pub const KDF_NAME_ARGON2ID: &str = "argon2id";

// ---------------------------------------------------------------------------
// Accepted Argon2id parameter bounds
// ---------------------------------------------------------------------------
//
// These bounds exist so that a hostile or corrupted vault file cannot force
// the application to allocate hundreds of GiB or spin for hours on unlock.
// The defaults used for new vaults are well within these bounds.

/// Minimum accepted `time_cost`.
pub const ARGON2_MIN_TIME_COST: u32 = 1;
/// Maximum accepted `time_cost`.
pub const ARGON2_MAX_TIME_COST: u32 = 16;

/// Minimum accepted `memory_cost`, in KiB. 19 MiB is the OWASP floor.
pub const ARGON2_MIN_MEMORY_KIB: u32 = 19 * 1024;
/// Maximum accepted `memory_cost`, in KiB. 1 GiB ceiling as a DoS guard.
pub const ARGON2_MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// Minimum accepted `parallelism`.
pub const ARGON2_MIN_PARALLELISM: u32 = 1;
/// Maximum accepted `parallelism`.
pub const ARGON2_MAX_PARALLELISM: u32 = 4;

/// The only accepted `hash_len`. Fixed at 32 bytes by the format.
pub const ARGON2_HASH_LEN: u32 = 32;

// ---------------------------------------------------------------------------
// KdfParams
// ---------------------------------------------------------------------------

/// Parameters describing how the Master Key is derived from the master
/// password. These are serialized into the vault file so that future vault
/// versions can change the defaults without breaking old vaults.
#[derive(Clone, Debug)]
pub struct KdfParams {
    pub name: String,
    pub salt: Vec<u8>,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
    pub hash_len: u32,
}

impl KdfParams {
    /// Parameters used when creating a new vault. The salt must already be a
    /// fresh, cryptographically random 16-byte value.
    pub fn new_vault_default() -> Result<Self> {
        let salt = random_bytes::<SALT_LEN>()?.to_vec();
        Ok(Self {
            name: KDF_NAME_ARGON2ID.to_string(),
            salt,
            time_cost: 3,
            memory_cost: 65_536,
            parallelism: 1,
            hash_len: ARGON2_HASH_LEN,
        })
    }

    /// Validate the parameters loaded from a vault file.
    ///
    /// Rejects unknown KDF names, wrong salt lengths, wrong hash length, and
    /// values outside the accepted cost bounds. It is never acceptable to
    /// silently weaken parameters: if a stored vault uses values this build
    /// does not accept, unlocking fails with an opaque error rather than
    /// proceeding with reduced cost.
    pub fn validate(&self) -> Result<()> {
        if self.name != KDF_NAME_ARGON2ID {
            return Err(Error::InvalidKdfParameters);
        }
        if self.salt.len() != SALT_LEN {
            return Err(Error::InvalidKdfParameters);
        }
        if self.hash_len != ARGON2_HASH_LEN {
            return Err(Error::InvalidKdfParameters);
        }
        if self.time_cost < ARGON2_MIN_TIME_COST || self.time_cost > ARGON2_MAX_TIME_COST {
            return Err(Error::InvalidKdfParameters);
        }
        if self.memory_cost < ARGON2_MIN_MEMORY_KIB || self.memory_cost > ARGON2_MAX_MEMORY_KIB {
            return Err(Error::InvalidKdfParameters);
        }
        if self.parallelism < ARGON2_MIN_PARALLELISM
            || self.parallelism > ARGON2_MAX_PARALLELISM
        {
            return Err(Error::InvalidKdfParameters);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Fill a fixed-size array with bytes from the OS CSPRNG.
///
/// This is the only source of randomness used by the crate for secrets.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|_| Error::Crypto)?;
    Ok(out)
}

/// Generate a fresh 32-byte Vault Key.
pub fn random_vault_key() -> Result<SecureBuffer> {
    let bytes = random_bytes::<KEY_LEN>()?;
    Ok(SecureBuffer::from_slice(&bytes))
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

/// Derive the 32-byte Master Key from the master password using Argon2id.
///
/// The parameter set is taken entirely from `params`; nothing is hard-coded
/// here beyond the algorithm identifier. `params.validate()` must have been
/// called by the caller (or the vault loader) before reaching this function;
/// we validate again defensively because the cost is negligible compared to
/// the Argon2id computation itself.
pub fn derive_master_key(password: &[u8], params: &KdfParams) -> Result<SecureBuffer> {
    params.validate()?;

    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.hash_len as usize),
    )
    .map_err(|_| Error::KeyDerivation)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = vec![0u8; params.hash_len as usize];
    argon2
        .hash_password_into(password, &params.salt, &mut out)
        .map_err(|_| Error::KeyDerivation)?;

    Ok(SecureBuffer::from_vec(out))
}

// ---------------------------------------------------------------------------
// HKDF-SHA256
// ---------------------------------------------------------------------------

/// Derive the 32-byte KEK from the Master Key using HKDF-SHA256.
///
/// The HKDF salt is `None`, which RFC 5869 defines as `HashLen` zero bytes.
/// See the module-level doc comment for the rationale.
pub fn derive_kek(master_key: &[u8]) -> Result<SecureBuffer> {
    if master_key.len() != KEY_LEN {
        return Err(Error::KeyDerivation);
    }

    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = vec![0u8; KEY_LEN];
    hk.expand(HKDF_INFO_KEK, &mut okm)
        .map_err(|_| Error::KeyDerivation)?;

    Ok(SecureBuffer::from_vec(okm))
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

/// AES-256-GCM wrap of the Vault Key by the KEK.
///
/// Returns the freshly generated 12-byte nonce and the ciphertext-with-tag as
/// produced by `aes-gcm` (tag appended to the ciphertext). The caller stores
/// both in the vault file.
pub fn wrap_vault_key(kek: &[u8], vault_key: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    if kek.len() != KEY_LEN || vault_key.len() != KEY_LEN {
        return Err(Error::Crypto);
    }

    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: vault_key,
                aad: AAD_VAULT_KEY,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((nonce_bytes, ciphertext))
}

/// AES-256-GCM unwrap of the Vault Key.
///
/// Any failure — wrong KEK, tampered ciphertext, wrong AAD, wrong nonce — is
/// reported as `Error::Authentication` without distinguishing between them.
pub fn unwrap_vault_key(
    kek: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<SecureBuffer> {
    if kek.len() != KEY_LEN {
        return Err(Error::Crypto);
    }
    if nonce_bytes.len() != NONCE_LEN {
        return Err(Error::Authentication);
    }
    // A GCM ciphertext is at least the 16-byte tag.
    if ciphertext.len() < 16 {
        return Err(Error::Authentication);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: AAD_VAULT_KEY,
            },
        )
        .map_err(|_| Error::Authentication)?;

    // The unwrapped Vault Key is defined as exactly 32 bytes. A mismatch here
    // means the wrapped key was not produced by this application.
    if plaintext.len() != KEY_LEN {
        return Err(Error::Authentication);
    }

    Ok(SecureBuffer::from_vec(plaintext))
}

/// AES-256-GCM encrypt of the vault payload with the Vault Key.
pub fn encrypt_vault(
    vault_key: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    if vault_key.len() != KEY_LEN {
        return Err(Error::Crypto);
    }

    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: AAD_VAULT,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((nonce_bytes, ciphertext))
}

/// AES-256-GCM decrypt of the vault payload with the Vault Key.
///
/// Any failure is reported as `Error::Authentication`. The decrypted payload
/// is returned in a `SecureBuffer` so it is wiped when the caller drops it.
pub fn decrypt_vault(
    vault_key: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<SecureBuffer> {
    if vault_key.len() != KEY_LEN {
        return Err(Error::Crypto);
    }
    if nonce_bytes.len() != NONCE_LEN {
        return Err(Error::Authentication);
    }
    if ciphertext.len() < 16 {
        return Err(Error::Authentication);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: AAD_VAULT,
            },
        )
        .map_err(|_| Error::Authentication)?;

    Ok(SecureBuffer::from_vec(plaintext))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_test_params(salt: [u8; SALT_LEN]) -> KdfParams {
        // Parameters chosen only to keep the unit test fast. They satisfy
        // `validate()`, which is what matters here; the production defaults
        // are the Argon2id values documented in `KdfParams::new_vault_default`.
        KdfParams {
            name: KDF_NAME_ARGON2ID.to_string(),
            salt: salt.to_vec(),
            time_cost: 1,
            memory_cost: 19 * 1024,
            parallelism: 1,
            hash_len: ARGON2_HASH_LEN,
        }
    }

    // -----------------------------------------------------------------------
    // Argon2id known-answer vector
    // -----------------------------------------------------------------------
    //
    // The canonical published vectors for Argon2id (RFC 9106 and the
    // RustCrypto `argon2` test suite) use an 8-byte salt: `b"somesalt"`.
    // Our vault format fixes the salt at 16 bytes and `KdfParams::validate`
    // rejects anything else, so this vector cannot be exercised through the
    // public `derive_master_key` function. We therefore call the `argon2`
    // crate directly with the canonical parameters and confirm that the
    // derived key matches the published value byte-for-byte.
    //
    // Vector (Argon2id v=0x13, t=2, m=65536, p=1, hash_len=32,
    //          password="password", salt=b"somesalt"):
    //   09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7

    #[test]
    fn argon2id_known_answer_vector() {
        let params = Params::new(65_536, 2, 1, Some(32)).expect("valid params");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = [0u8; 32];
        argon2
            .hash_password_into(b"password", b"somesalt", &mut out)
            .expect("hash_password_into");

        let expected: [u8; 32] = [
            0x09, 0x31, 0x61, 0x15, 0xd5, 0xcf, 0x24, 0xed,
            0x5a, 0x15, 0xa3, 0x1a, 0x3b, 0xa3, 0x26, 0xe5,
            0xcf, 0x32, 0xed, 0xc2, 0x47, 0x02, 0x98, 0x7c,
            0x02, 0xb6, 0x56, 0x6f, 0x61, 0x91, 0x3c, 0xf7,
        ];

        assert_eq!(
            out, expected,
            "Argon2id output does not match the published test vector"
        );
    }

    // -----------------------------------------------------------------------
    // Higher-level behavior
    // -----------------------------------------------------------------------

    #[test]
    fn argon2id_is_deterministic_and_sensitive_to_inputs() {
        let params = fast_test_params([0x11u8; SALT_LEN]);

        let a = derive_master_key(b"correct horse battery staple", &params).unwrap();
        let b = derive_master_key(b"correct horse battery staple", &params).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        assert_eq!(a.len(), KEY_LEN);

        let c = derive_master_key(b"wrong horse battery staple", &params).unwrap();
        assert_ne!(a.as_slice(), c.as_slice());

        let mut other_salt = params.clone();
        other_salt.salt = vec![0x22u8; SALT_LEN];
        let d = derive_master_key(b"correct horse battery staple", &other_salt).unwrap();
        assert_ne!(a.as_slice(), d.as_slice());
    }

    #[test]
    fn kdf_params_validation_rejects_bad_values() {
        let good = fast_test_params([0u8; SALT_LEN]);
        assert!(good.validate().is_ok());

        let mut bad = good.clone();
        bad.name = "scrypt".into();
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.salt = vec![0u8; SALT_LEN - 1];
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.hash_len = 16;
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.time_cost = 0;
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.memory_cost = 1024;
        assert!(bad.validate().is_err());

        let mut bad = good.clone();
        bad.parallelism = 0;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn hkdf_produces_deterministic_32_bytes() {
        let mk = [0x42u8; KEY_LEN];
        let a = derive_kek(&mk).unwrap();
        let b = derive_kek(&mk).unwrap();
        assert_eq!(a.len(), KEY_LEN);
        assert_eq!(a.as_slice(), b.as_slice());

        // Different master key must yield a different KEK.
        let mut other = mk;
        other[0] ^= 0xff;
        let c = derive_kek(&other).unwrap();
        assert_ne!(a.as_slice(), c.as_slice());

        // Wrong-size master key is rejected.
        assert!(derive_kek(&[0u8; KEY_LEN - 1]).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = [0x33u8; KEY_LEN];
        let vk = [0x44u8; KEY_LEN];

        let (nonce, ct) = wrap_vault_key(&kek, &vk).unwrap();
        assert_eq!(nonce.len(), NONCE_LEN);
        // 32-byte plaintext + 16-byte tag.
        assert_eq!(ct.len(), KEY_LEN + 16);

        let unwrapped = unwrap_vault_key(&kek, &nonce, &ct).unwrap();
        assert_eq!(unwrapped.as_slice(), &vk);
    }

    #[test]
    fn wrap_unwrap_rejects_tampering() {
        let kek = [0x33u8; KEY_LEN];
        let vk = [0x44u8; KEY_LEN];
        let (nonce, ct) = wrap_vault_key(&kek, &vk).unwrap();

        // Flip one byte of ciphertext.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(matches!(
            unwrap_vault_key(&kek, &nonce, &bad_ct),
            Err(Error::Authentication)
        ));

        // Flip one byte of nonce.
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0x01;
        assert!(matches!(
            unwrap_vault_key(&kek, &bad_nonce, &ct),
            Err(Error::Authentication)
        ));

        // Wrong KEK.
        let bad_kek = [0x55u8; KEY_LEN];
        assert!(matches!(
            unwrap_vault_key(&bad_kek, &nonce, &ct),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn vault_encrypt_decrypt_roundtrip() {
        let vk = [0x66u8; KEY_LEN];
        let plaintext = b"hello, encrypted vault";

        let (nonce, ct) = encrypt_vault(&vk, plaintext).unwrap();
        let pt = decrypt_vault(&vk, &nonce, &ct).unwrap();
        assert_eq!(pt.as_slice(), plaintext);

        // Tampering fails.
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        assert!(matches!(
            decrypt_vault(&vk, &nonce, &bad),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn nonces_are_not_reused() {
        // Ten consecutive encryptions under the same key must produce ten
        // distinct nonces. This is a probabilistic check, not a proof; the
        // probability of a collision in 10 draws from 2^96 is negligible.
        let key = [0x77u8; KEY_LEN];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let (nonce, _) = encrypt_vault(&key, b"x").unwrap();
            assert!(seen.insert(nonce), "nonce collision in AES-256-GCM");
        }
    }

    #[test]
    fn random_bytes_are_not_all_zero() {
        // Sanity check that the OS RNG is plumbed through. The probability of
        // a 32-byte all-zero draw from a correct RNG is 2^-256.
        let bytes = random_bytes::<32>().unwrap();
        assert_ne!(bytes, [0u8; 32]);
    }
}
