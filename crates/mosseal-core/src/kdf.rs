//! Key derivation (spec 02 § Key derivation).
//!
//! Two mutually exclusive paths (spec 02: Argon2id replaces HKDF in password
//! mode — not layered):
//!
//! - **Default (no password) — HKDF-SHA256**
//!   `ikm = INTERNAL_SECRET`, `salt = envelope salt`, `info = binding`, 32-byte key.
//!   The URL salt's purpose is per-link key compartmentalization, *not*
//!   confidentiality against binary holders (the binary is public).
//!
//! - **Password mode — Argon2id**
//!   `input = binding ‖ 0x1F ‖ secret ‖ 0x1F ‖ password`, `salt = envelope salt`,
//!   `m=19 MiB, t=2, p=1, len=32` (OWASP floor, `minimum` profile).
//!   Password entropy gates the offline attack; the internal secret alone is
//!   then insufficient.

use crate::binding;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2 memory cost in KiB per profile (spec 02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Profile {
    /// OWASP 2024 floor: 19 MiB, t=2, p=1.
    Minimum,
    /// UX-friendlier upper bound for interactive use: 47 MiB, t=2, p=1.
    Interactive,
}

impl Argon2Profile {
    /// Compile-time profile from the CLI build (default `minimum`).
    pub fn from_build() -> Self {
        match option_env!("MOSSEAL_ARGON2_PROFILE") {
            Some("interactive") => Self::Interactive,
            _ => Self::Minimum,
        }
    }

    pub fn m_kib(self) -> u32 {
        match self {
            Self::Minimum => 19 * 1024,
            Self::Interactive => 47 * 1024,
        }
    }

    pub fn t(self) -> u32 {
        2
    }

    pub fn p(self) -> u32 {
        1
    }
}

impl Default for Argon2Profile {
    fn default() -> Self {
        Self::from_build()
    }
}

/// Derived 32-byte AES-256 key. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never render key material, even in debug logs
        f.write_str("DerivedKey(..)")
    }
}

/// HKDF-SHA256 default path.
pub fn derive_hkdf(internal_secret: &[u8], salt: &[u8; 16], binding_str: &[u8]) -> DerivedKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), internal_secret);
    let mut key = [0u8; 32];
    // infallible for 32-byte outputs
    hk.expand(binding_str, &mut key)
        .expect("32-byte HKDF expand");
    DerivedKey(key)
}

/// Argon2id password path (spec 02): input combines binding, secret, password so
/// password entropy gates offline attacks.
pub fn derive_argon2(
    internal_secret: &[u8],
    password: &[u8],
    salt: &[u8; 16],
    binding_str: &[u8],
    profile: Argon2Profile,
) -> Result<DerivedKey, String> {
    let mut input =
        Vec::with_capacity(binding_str.len() + internal_secret.len() + password.len() + 2);
    input.extend_from_slice(binding_str);
    input.push(binding::SEP);
    input.extend_from_slice(internal_secret);
    input.push(binding::SEP);
    input.extend_from_slice(password);
    // scrub the combined input as soon as we're done with it
    let input = zeroize::Zeroizing::new(input);

    let params = Params::new(profile.m_kib(), profile.t(), profile.p(), Some(32))
        .map_err(|e| format!("argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(&input, salt, &mut key)
        .map_err(|e| format!("argon2 derive: {e}"))?;
    Ok(DerivedKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_is_deterministic_and_salted() {
        let b = b"mosseal/v1\x1Fa.com".to_vec();
        let k1 = derive_hkdf(b"secret", &[1; 16], &b);
        let k2 = derive_hkdf(b"secret", &[1; 16], &b);
        let k3 = derive_hkdf(b"secret", &[2; 16], &b);
        let k4 = derive_hkdf(b"other", &[1; 16], &b);
        assert_eq!(k1.0, k2.0, "same inputs → same key");
        assert_ne!(k1.0, k3.0, "salt compartmentalizes links");
        assert_ne!(k1.0, k4.0, "secret change rotates keys");
    }

    #[test]
    fn argon2_minimum_profile_deterministic() {
        let b = b"mosseal/v1\x1Fa.com".to_vec();
        let p = Argon2Profile::Minimum;
        assert_eq!(p.m_kib(), 19 * 1024);
        let k1 = derive_argon2(b"secret", b"pw", &[1; 16], &b, p).unwrap();
        let k2 = derive_argon2(b"secret", b"pw", &[1; 16], &b, p).unwrap();
        let k3 = derive_argon2(b"secret", b"WRONG", &[1; 16], &b, p).unwrap();
        assert_eq!(k1.0, k2.0);
        assert_ne!(
            k1.0, k3.0,
            "wrong password → different key (BAD_PASSWORD via GCM tag)"
        );
    }

    #[test]
    fn argon2_differs_from_hkdf() {
        let b = b"mosseal/v1\x1Fa.com".to_vec();
        let hk = derive_hkdf(b"secret", &[1; 16], &b);
        let ar = derive_argon2(b"secret", b"", &[1; 16], &b, Argon2Profile::Minimum).unwrap();
        assert_ne!(hk.0, ar.0);
    }

    #[test]
    fn debug_never_leaks_key() {
        let k = derive_hkdf(b"secret", &[1; 16], b"info");
        assert_eq!(format!("{k:?}"), "DerivedKey(..)");
    }

    #[test]
    fn interactive_profile_params() {
        let p = Argon2Profile::Interactive;
        assert_eq!(p.m_kib(), 47 * 1024);
        assert_eq!(p.t(), 2);
        assert_eq!(p.p(), 1);
        assert_ne!(p.m_kib(), Argon2Profile::Minimum.m_kib());
    }

    #[test]
    fn default_profile_matches_build_default() {
        assert_eq!(Argon2Profile::default(), Argon2Profile::from_build());
    }
}
