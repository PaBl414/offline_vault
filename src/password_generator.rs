//! Cryptographically secure password generation.
//!
//! ## Design
//!
//!   * Randomness comes exclusively from the operating system CSPRNG via
//!     `getrandom`. No user-space PRNG is used.
//!   * Character selection uses **rejection sampling** on a uniformly random
//!     byte stream, so the distribution over the chosen alphabet is exactly
//!     uniform. We do not use `byte % alphabet.len()`, which would bias the
//!     output toward the first `256 % len` characters.
//!   * The output string is wrapped in a [`SecureBuffer`] as UTF-8 bytes so
//!     the intermediate buffer is wiped on drop. The final `String` returned
//!     to the caller is the caller's responsibility, and the caller
//!     (`ui.rs`) is expected to move it directly into the entry being
//!     edited.
//!
//! ## What "avoid predictable patterns" means here
//!
//! The generator draws each character independently and uniformly from the
//! chosen alphabet. It does **not** attempt to reject outputs that happen to
//! contain repeated or sequentially adjacent characters: doing so would
//! *reduce* entropy (it conditions the output on a pattern) and give a false
//! sense of additional security. The only predictability we actively avoid
//! is the predictable bias of modulo reduction, which rejection sampling
//! removes exactly.
//!
//! If the caller selects no character classes, generation fails with a
//! coarse error rather than silently substituting a default alphabet.

use crate::error::{Error, Result};
use crate::security::SecureBuffer;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Minimum generated password length. Below this we refuse to generate.
pub const MIN_LENGTH: usize = 8;

/// Maximum generated password length. Above this the UI slider is capped.
pub const MAX_LENGTH: usize = 128;

/// Default length used when the dialog is first opened.
pub const DEFAULT_LENGTH: usize = 24;

// ---------------------------------------------------------------------------
// Character classes
// ---------------------------------------------------------------------------

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

/// Which character classes to draw from.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            length: DEFAULT_LENGTH,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        }
    }
}

impl Options {
    /// Return the concatenation of every enabled class as a single alphabet.
    ///
    /// Returns `Err(Error::Crypto)` if no class is enabled. This is a
    /// caller-visible failure: the UI must surface "select at least one
    /// character type" rather than silently fall back.
    pub fn alphabet(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        if self.lowercase {
            out.extend_from_slice(LOWERCASE);
        }
        if self.uppercase {
            out.extend_from_slice(UPPERCASE);
        }
        if self.digits {
            out.extend_from_slice(DIGITS);
        }
        if self.symbols {
            out.extend_from_slice(SYMBOLS);
        }
        if out.is_empty() {
            return Err(Error::Crypto);
        }
        Ok(out)
    }

    /// Whether at least one character class is enabled.
    pub fn has_any_class(&self) -> bool {
        self.uppercase || self.lowercase || self.digits || self.symbols
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate a password using the given options.
///
/// Errors:
///   * `Error::Crypto` if no character class is enabled, the length is out of
///     bounds, or the OS RNG fails.
pub fn generate(opts: &Options) -> Result<String> {
    if !opts.has_any_class() {
        return Err(Error::Crypto);
    }
    if opts.length < MIN_LENGTH || opts.length > MAX_LENGTH {
        return Err(Error::Crypto);
    }

    let alphabet = opts.alphabet()?;
    let alpha_len = alphabet.len();

    // Rejection sampling: each output character uses one random byte. Bytes
    // `>= limit` are rejected. `limit` is the largest multiple of `alpha_len`
    // that fits in a `u8`, so `byte % alpha_len` for `byte < limit` is
    // uniformly distributed.
    let limit = (u8::MAX as usize / alpha_len) * alpha_len;
    let limit = if limit == 0 {
        u8::MAX as usize + 1
    } else {
        limit
    };

    let mut out = SecureBuffer::zeroed(opts.length);

    // Read random bytes in chunks. We overshoot slightly because some bytes
    // will be rejected; the loop below draws more if needed.
    let mut filled = 0usize;
    let mut chunk = [0u8; 256];
    while filled < opts.length {
        getrandom::getrandom(&mut chunk).map_err(|_| Error::Crypto)?;
        for &b in chunk.iter() {
            if (b as usize) < limit {
                out.as_mut_slice()[filled] = alphabet[(b as usize) % alpha_len];
                filled += 1;
                if filled == opts.length {
                    break;
                }
            }
        }
    }

    // Convert to a String. This allocates a new buffer containing the same
    // bytes; the SecureBuffer's own bytes are wiped on drop at end of scope.
    //
    // Every byte in `alphabet` is ASCII, so `out` is valid UTF-8 by
    // construction; the `from_utf8` check is a defensive belt-and-braces.
    let s = std::str::from_utf8(out.as_slice())
        .map_err(|_| Error::Crypto)?
        .to_string();

    Ok(s)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn default_length_is_within_bounds() {
        let d = Options::default();
        assert!(d.length >= MIN_LENGTH);
        assert!(d.length <= MAX_LENGTH);
    }

    #[test]
    fn no_classes_enabled_is_an_error() {
        let opts = Options {
            length: 16,
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
        };
        assert!(!opts.has_any_class());
        assert!(generate(&opts).is_err());
        assert!(opts.alphabet().is_err());
    }

    #[test]
    fn length_out_of_bounds_is_an_error() {
        let too_short = Options {
            length: MIN_LENGTH - 1,
            ..Options::default()
        };
        assert!(generate(&too_short).is_err());

        let too_long = Options {
            length: MAX_LENGTH + 1,
            ..Options::default()
        };
        assert!(generate(&too_long).is_err());
    }

    #[test]
    fn generates_requested_length() {
        for len in [MIN_LENGTH, 16, 32, MAX_LENGTH] {
            let opts = Options {
                length: len,
                ..Options::default()
            };
            let s = generate(&opts).unwrap();
            assert_eq!(s.len(), len);
        }
    }

    #[test]
    fn only_uses_selected_classes() {
        let opts = Options {
            length: 64,
            uppercase: false,
            lowercase: true,
            digits: false,
            symbols: false,
        };
        let s = generate(&opts).unwrap();
        assert!(s.bytes().all(|b| b.is_ascii_lowercase()));

        let opts = Options {
            length: 64,
            uppercase: false,
            lowercase: false,
            digits: true,
            symbols: false,
        };
        let s = generate(&opts).unwrap();
        assert!(s.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn two_draws_differ() {
        // Probabilistic: the chance that two 24-character passwords over a
        // ~90-character alphabet collide is astronomically small.
        let opts = Options::default();
        let a = generate(&opts).unwrap();
        let b = generate(&opts).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn distribution_over_alphabet_is_roughly_uniform() {
        // Draw many characters from a single-digit alphabet and assert that
        // every digit appears. A biased modulo implementation would still
        // pass this, so the test is a smoke test, not a proof of uniformity.
        //
        // We generate several maximum-length passwords rather than one
        // over-long string, because `generate` deliberately refuses to
        // produce more than `MAX_LENGTH` characters.
        let opts = Options {
            length: MAX_LENGTH,
            uppercase: false,
            lowercase: false,
            digits: true,
            symbols: false,
        };

        let mut seen: HashSet<u8> = HashSet::new();
        // A few draws of MAX_LENGTH characters each gives us several hundred
        // samples without exceeding the per-call bound. Ten draws is more
        // than enough to see all ten digits with overwhelming probability.
        for _ in 0..10 {
            let s = generate(&opts).unwrap();
            assert_eq!(s.len(), MAX_LENGTH);
            for b in s.bytes() {
                seen.insert(b);
            }
        }
        for d in b"0123456789" {
            assert!(seen.contains(d), "missing digit {}", *d as char);
        }
    }
}
