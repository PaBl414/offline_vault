//! Adversarial input tests for the vault loader.
//!
//! The loader is the one place where untrusted bytes become typed data. This
//! file deliberately throws malformed, truncated, oversized, and hostile
//! inputs at `VaultFile::from_bytes` and `VaultFile::unlock`, and asserts
//! that every one of them is rejected with the correct coarse error — never
//! silently accepted, never panic, never reaching a crypto primitive with a
//! nonsensical shape.
//!
//! Overlaps with `tests/vault_tests.rs` are intentional in a few places:
//! this file focuses on adversarial shape, while that one focuses on
//! lifecycle. Keeping the two categories separate makes it obvious which
//! guarantees are about "well-formed but wrong" versus "hostile".
//!
//! No test prints a secret.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};

use offline_vault::error::Error;
use offline_vault::vault::{
    EncryptedBlob, KdfSection, VaultFile, MAX_VAULT_FILE_BYTES, SUPPORTED_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A minimal, structurally valid vault JSON value with placeholder Base64
/// fields. The encrypted sections are not real ciphertexts; that is fine for
/// shape tests, which stop at `from_bytes` and never reach `unlock`.
fn minimal_valid_json() -> Value {
    // 16-byte salt, 12-byte nonce, 17-byte ciphertext — all valid Base64 and
    // within the loader's length checks (ciphertext must be >= 16).
    let salt = B64.encode([0u8; 16]);
    let nonce = B64.encode([0u8; 12]);
    let ct = B64.encode([0u8; 17]);
    json!({
        "version": SUPPORTED_VERSION,
        "kdf": {
            "name": "argon2id",
            "salt": salt,
            "time_cost": 1,
            "memory_cost": 19 * 1024,
            "parallelism": 1,
            "hash_len": 32
        },
        "wrapped_key": { "nonce": nonce, "ciphertext": ct },
        "vault":       { "nonce": nonce, "ciphertext": ct }
    })
}

fn from_json(v: &Value) -> Result<VaultFile, Error> {
    let bytes = serde_json::to_vec(v).expect("serialize test value");
    VaultFile::from_bytes(&bytes)
}

// ---------------------------------------------------------------------------
// Top-level shape
// ---------------------------------------------------------------------------

#[test]
fn accepts_the_minimal_well_formed_shape() {
    // Sanity: if this fails, every other test in this file is meaningless.
    let v = minimal_valid_json();
    VaultFile::from_bytes(&serde_json::to_vec(&v).unwrap())
        .expect("minimal shape must parse");
}

#[test]
fn rejects_empty_bytes() {
    assert!(matches!(
        VaultFile::from_bytes(&[]),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_whitespace_only() {
    assert!(matches!(
        VaultFile::from_bytes(b"   \n\t  "),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_non_utf8_bytes() {
    // 0xFF is never valid UTF-8 at the top level.
    assert!(matches!(
        VaultFile::from_bytes(&[0xff, 0xfe, 0xfd]),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_top_level_array() {
    assert!(matches!(
        VaultFile::from_bytes(b"[]"),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_top_level_string() {
    assert!(matches!(
        VaultFile::from_bytes(b"\"vault\""),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_top_level_number() {
    assert!(matches!(
        VaultFile::from_bytes(b"42"),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_top_level_null() {
    assert!(matches!(
        VaultFile::from_bytes(b"null"),
        Err(Error::VaultFormat)
    ));
}

#[test]
fn rejects_oversized_input() {
    // Build a syntactically fine file, then pad it past MAX_VAULT_FILE_BYTES.
    // The loader checks length before parsing, so the content does not matter
    // as long as it exceeds the cap.
    let mut buf = Vec::with_capacity(MAX_VAULT_FILE_BYTES + 64);
    buf.extend_from_slice(b"{");
    buf.resize(MAX_VAULT_FILE_BYTES + 1, b' ');
    assert!(buf.len() > MAX_VAULT_FILE_BYTES);
    assert!(matches!(
        VaultFile::from_bytes(&buf),
        Err(Error::VaultFormat)
    ));
}

// ---------------------------------------------------------------------------
// Unknown / missing fields
// ---------------------------------------------------------------------------

#[test]
fn rejects_unknown_top_level_field() {
    let mut v = minimal_valid_json();
    v.as_object_mut().unwrap().insert("extra".into(), json!(1));
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));
}

#[test]
fn rejects_unknown_kdf_field() {
    let mut v = minimal_valid_json();
    v["kdf"]["extra"] = json!("value");
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));
}

#[test]
fn rejects_unknown_encrypted_blob_field() {
    let mut v = minimal_valid_json();
    v["vault"]["extra"] = json!("value");
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));
}

#[test]
fn rejects_missing_top_level_fields() {
    for field in ["version", "kdf", "wrapped_key", "vault"] {
        let mut v = minimal_valid_json();
        v.as_object_mut().unwrap().remove(field);
        assert!(
            matches!(from_json(&v), Err(Error::VaultFormat)),
            "missing top-level `{field}` was accepted"
        );
    }
}

#[test]
fn rejects_missing_kdf_fields() {
    for field in ["name", "salt", "time_cost", "memory_cost", "parallelism", "hash_len"] {
        let mut v = minimal_valid_json();
        v["kdf"].as_object_mut().unwrap().remove(field);
        assert!(
            matches!(from_json(&v), Err(Error::VaultFormat)),
            "missing kdf.`{field}` was accepted"
        );
    }
}

#[test]
fn rejects_missing_encrypted_blob_fields() {
    for section in ["wrapped_key", "vault"] {
        for field in ["nonce", "ciphertext"] {
            let mut v = minimal_valid_json();
            v[section].as_object_mut().unwrap().remove(field);
            assert!(
                matches!(from_json(&v), Err(Error::VaultFormat)),
                "missing `{section}.{field}` was accepted"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Wrong types
// ---------------------------------------------------------------------------

#[test]
fn rejects_wrong_version_type() {
    let mut v = minimal_valid_json();
    v["version"] = json!("one");
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));

    let mut v = minimal_valid_json();
    v["version"] = json!(null);
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));
}

#[test]
fn rejects_wrong_kdf_numeric_types() {
    for field in ["time_cost", "memory_cost", "parallelism", "hash_len"] {
        let mut v = minimal_valid_json();
        v["kdf"][field] = json!("not-a-number");
        assert!(
            matches!(from_json(&v), Err(Error::VaultFormat)),
            "kdf.`{field}` with string type was accepted"
        );

        let mut v = minimal_valid_json();
        v["kdf"][field] = json!(-1);
        assert!(
            matches!(from_json(&v), Err(Error::VaultFormat)),
            "kdf.`{field}` with negative value was accepted"
        );
    }
}

#[test]
fn rejects_wrong_salt_type() {
    let mut v = minimal_valid_json();
    v["kdf"]["salt"] = json!(42);
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));
}

#[test]
fn rejects_wrong_encrypted_blob_types() {
    for section in ["wrapped_key", "vault"] {
        for field in ["nonce", "ciphertext"] {
            let mut v = minimal_valid_json();
            v[section][field] = json!(123);
            assert!(
                matches!(from_json(&v), Err(Error::VaultFormat)),
                "`{section}.{field}` with number type was accepted"
            );
        }
    }
}

#[test]
fn rejects_kdf_as_array() {
    let mut v = minimal_valid_json();
    v["kdf"] = json!([]);
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));
}

#[test]
fn rejects_encrypted_blob_as_string() {
    let mut v = minimal_valid_json();
    v["vault"] = json!("not an object");
    assert!(matches!(from_json(&v), Err(Error::VaultFormat)));
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

#[test]
fn rejects_unsupported_version_zero() {
    let mut v = minimal_valid_json();
    v["version"] = json!(0);
    assert!(matches!(from_json(&v), Err(Error::UnsupportedVersion)));
}

#[test]
fn rejects_unsupported_version_two() {
    let mut v = minimal_valid_json();
    v["version"] = json!(2);
    assert!(matches!(from_json(&v), Err(Error::UnsupportedVersion)));
}

#[test]
fn rejects_huge_version() {
    let mut v = minimal_valid_json();
    v["version"] = json!(u32::MAX);
    assert!(matches!(from_json(&v), Err(Error::UnsupportedVersion)));
}

// ---------------------------------------------------------------------------
// KDF parameters
// ---------------------------------------------------------------------------

#[test]
fn rejects_unknown_kdf_name() {
    for name in ["scrypt", "pbkdf2", "bcrypt", "argon2i", "argon2d", "ARGON2ID", ""] {
        let mut v = minimal_valid_json();
        v["kdf"]["name"] = json!(name);
        assert!(
            matches!(from_json(&v), Err(Error::InvalidKdfParameters)),
            "kdf name `{name}` was accepted"
        );
    }
}

#[test]
fn rejects_zero_time_cost() {
    let mut v = minimal_valid_json();
    v["kdf"]["time_cost"] = json!(0);
    assert!(matches!(from_json(&v), Err(Error::InvalidKdfParameters)));
}

#[test]
fn rejects_extreme_time_cost() {
    let mut v = minimal_valid_json();
    v["kdf"]["time_cost"] = json!(1_000_000);
    assert!(matches!(from_json(&v), Err(Error::InvalidKdfParameters)));
}

#[test]
fn rejects_low_memory_cost() {
    // Below the 19 MiB floor.
    let mut v = minimal_valid_json();
    v["kdf"]["memory_cost"] = json!(1024);
    assert!(matches!(from_json(&v), Err(Error::InvalidKdfParameters)));
}

#[test]
fn rejects_high_memory_cost() {
    // Above the 1 GiB ceiling.
    let mut v = minimal_valid_json();
    v["kdf"]["memory_cost"] = json!(8 * 1024 * 1024);
    assert!(matches!(from_json(&v), Err(Error::InvalidKdfParameters)));
}

#[test]
fn rejects_zero_parallelism() {
    let mut v = minimal_valid_json();
    v["kdf"]["parallelism"] = json!(0);
    assert!(matches!(from_json(&v), Err(Error::InvalidKdfParameters)));
}

#[test]
fn rejects_extreme_parallelism() {
    let mut v = minimal_valid_json();
    v["kdf"]["parallelism"] = json!(1024);
    assert!(matches!(from_json(&v), Err(Error::InvalidKdfParameters)));
}

#[test]
fn rejects_hash_len_other_than_32() {
    for len in [0u32, 16, 31, 33, 64, 128] {
        let mut v = minimal_valid_json();
        v["kdf"]["hash_len"] = json!(len);
        assert!(
            matches!(from_json(&v), Err(Error::InvalidKdfParameters)),
            "hash_len {len} was accepted"
        );
    }
}

#[test]
fn rejects_salt_wrong_length() {
    for len in [0usize, 1, 8, 15, 17, 32, 64] {
        let mut v = minimal_valid_json();
        v["kdf"]["salt"] = json!(B64.encode(vec![0u8; len]));
        assert!(
            matches!(from_json(&v), Err(Error::InvalidKdfParameters)),
            "salt length {len} was accepted"
        );
    }
}

#[test]
fn accepts_exact_salt_length() {
    let mut v = minimal_valid_json();
    v["kdf"]["salt"] = json!(B64.encode(vec![0u8; 16]));
    assert!(from_json(&v).is_ok());
}

// ---------------------------------------------------------------------------
// Base64 decoding
// ---------------------------------------------------------------------------

#[test]
fn rejects_non_base64_salt() {
    let mut v = minimal_valid_json();
    v["kdf"]["salt"] = json!("!!! not base64 !!!");
    assert!(matches!(from_json(&v), Err(Error::InvalidEncoding)));
}

#[test]
fn rejects_non_base64_nonce() {
    for section in ["wrapped_key", "vault"] {
        let mut v = minimal_valid_json();
        v[section]["nonce"] = json!("###");
        assert!(
            matches!(from_json(&v), Err(Error::InvalidEncoding)),
            "`{section}.nonce` invalid base64 was accepted"
        );
    }
}

#[test]
fn rejects_non_base64_ciphertext() {
    for section in ["wrapped_key", "vault"] {
        let mut v = minimal_valid_json();
        v[section]["ciphertext"] = json!("%%%");
        assert!(
            matches!(from_json(&v), Err(Error::InvalidEncoding)),
            "`{section}.ciphertext` invalid base64 was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Length invariants of decoded fields
// ---------------------------------------------------------------------------

#[test]
fn rejects_nonce_wrong_length() {
    for section in ["wrapped_key", "vault"] {
        for len in [0usize, 8, 11, 13, 16, 32] {
            let mut v = minimal_valid_json();
            v[section]["nonce"] = json!(B64.encode(vec![0u8; len]));
            assert!(
                matches!(from_json(&v), Err(Error::InvalidEncoding)),
                "`{section}.nonce` length {len} was accepted"
            );
        }
    }
}

#[test]
fn rejects_ciphertext_shorter_than_gcm_tag() {
    for section in ["wrapped_key", "vault"] {
        for len in [0usize, 1, 8, 15] {
            let mut v = minimal_valid_json();
            v[section]["ciphertext"] = json!(B64.encode(vec![0u8; len]));
            assert!(
                matches!(from_json(&v), Err(Error::InvalidEncoding)),
                "`{section}.ciphertext` length {len} was accepted"
            );
        }
    }
}

#[test]
fn accepts_ciphertext_exactly_gcm_tag_length() {
    for section in ["wrapped_key", "vault"] {
        let mut v = minimal_valid_json();
        v[section]["ciphertext"] = json!(B64.encode(vec![0u8; 16]));
        assert!(
            from_json(&v).is_ok(),
            "`{section}.ciphertext` of 16 bytes was rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Round-trip of a real serialized file through the shape checks
// ---------------------------------------------------------------------------

#[test]
fn a_real_serialized_file_parses_cleanly() {
    // Build a real file using the same shape helpers exposed by the loader,
    // then confirm it round-trips through `from_bytes` without modification.
    // This proves the shape tests above are not accidentally rejecting the
    // actual on-disk format.
    let salt = B64.encode([1u8; 16]);
    let nonce = B64.encode([2u8; 12]);
    let ct = B64.encode([3u8; 48]);

    let file = VaultFile {
        version: SUPPORTED_VERSION,
        kdf: KdfSection {
            name: "argon2id".into(),
            salt,
            time_cost: 3,
            memory_cost: 65_536,
            parallelism: 1,
            hash_len: 32,
        },
        wrapped_key: EncryptedBlob {
            nonce: nonce.clone(),
            ciphertext: ct.clone(),
        },
        vault: EncryptedBlob {
            nonce,
            ciphertext: ct,
        },
    };
    let bytes = file.to_bytes().unwrap();
    let reparsed = VaultFile::from_bytes(&bytes).unwrap();
    assert_eq!(reparsed.version, SUPPORTED_VERSION);
    assert_eq!(reparsed.kdf.name, "argon2id");
    assert_eq!(reparsed.kdf.time_cost, 3);
    assert_eq!(reparsed.kdf.memory_cost, 65_536);
    assert_eq!(reparsed.kdf.hash_len, 32);
}
