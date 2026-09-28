//! Key-epoch registry (spec 02 § Key epochs).
//!
//! Up to 256 compile-time secrets select via the envelope's `key_epoch` byte.
//! The registry is **sparse**: the epoch byte indexes a slot that may be a
//! *hole*. A hole means that epoch has been **retired** — links sealed under
//! it fail with `EPOCH_RETIRED`, while every other epoch keeps its number and
//! keeps opening.
//!
//! ```text
//! slots = [ Some(secret0), None /* retired */, Some(secret2) ]
//! ```
//!
//! `mosseal rotate` appends a fresh `MOSSEAL_SECRET_<n+1>`; retiring the oldest
//! epoch after the grace window blanks its slot (an empty entry in the
//! `;`-joined registry string). Retirement is the actual invalidation event —
//! the only revocation-adjacent story in a stateless system.
//!
//! The registry string is produced by the CLI builder (spec 05) as an
//! `obfuse!` literal in the generated `secrets.rs`; entries are base64url
//! 32-byte secrets joined with `;`, and an **empty entry is a retired hole**.

use crate::{ErrorCode, MossealError, Result};

/// Parsed compile-time epoch registry. Built once at startup from the
/// generated `secrets.rs` registry string, or injected in tests / the Node
/// path.
#[derive(Debug, Clone)]
pub struct EpochRegistry {
    /// Index = epoch byte. `None` = retired hole.
    slots: Vec<Option<[u8; 32]>>,
}

impl EpochRegistry {
    /// Build a dense registry from raw 32-byte secrets. Epoch = index.
    /// (Convenience for tests and the conformance vectors; the CLI path uses
    /// [`EpochRegistry::parse`] so holes are preserved.)
    pub fn new(secrets: Vec<[u8; 32]>) -> Self {
        Self {
            slots: secrets.into_iter().map(Some).collect(),
        }
    }

    /// Build a sparse registry from explicit slots (`None` = retired hole).
    pub fn from_slots(slots: Vec<Option<[u8; 32]>>) -> Self {
        Self { slots }
    }

    /// Parse a registry string (base64url entries joined by `;`).
    ///
    /// An **empty entry is a retired hole** (`None`); a non-empty entry must
    /// decode to exactly 32 bytes. Fails when the registry has no active
    /// secret at all.
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(MossealError::new(
                ErrorCode::EpochRetired,
                "epoch registry empty (build without MOSSEAL secrets?)",
            ));
        }
        use base64::Engine;
        let mut slots: Vec<Option<[u8; 32]>> = Vec::new();
        for (i, entry) in s.split(';').enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                // Retired hole — keep the slot so later epochs keep their index.
                slots.push(None);
                continue;
            }
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(entry)
                .map_err(|e| {
                    MossealError::new(
                        ErrorCode::EpochRetired,
                        format!("epoch {i} secret malformed: {e}"),
                    )
                })?;
            let arr: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                MossealError::new(
                    ErrorCode::EpochRetired,
                    format!("epoch {i} secret must be 32 bytes, got {}", v.len()),
                )
            })?;
            slots.push(Some(arr));
        }
        let reg = Self { slots };
        if reg.is_empty() {
            return Err(MossealError::new(
                ErrorCode::EpochRetired,
                "epoch registry has no active secret (all epochs retired?)",
            ));
        }
        Ok(reg)
    }

    /// Sealing epoch: the highest active (non-retired) epoch (spec 02).
    pub fn latest_epoch(&self) -> Result<u8> {
        self.slots
            .iter()
            .rposition(|s| s.is_some())
            .map(|i| i as u8)
            .ok_or_else(|| {
                MossealError::new(
                    ErrorCode::EpochRetired,
                    "no active epoch to seal with (all epochs retired?)",
                )
            })
    }

    /// Number of **active** (non-retired) secrets.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Total slots, including retired holes.
    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fetch the secret for an epoch byte. A retired hole or an out-of-range
    /// epoch yields `EPOCH_RETIRED` (spec 02 error taxonomy).
    pub fn secret(&self, epoch: u8) -> Result<&[u8; 32]> {
        self.slots
            .get(epoch as usize)
            .and_then(|s| s.as_ref())
            .ok_or_else(|| {
                MossealError::new(
                    ErrorCode::EpochRetired,
                    format!(
                        "key epoch {epoch} not in registry ({} active of {} slots)",
                        self.len(),
                        self.slots.len()
                    ),
                )
            })
    }

    /// Fetch the latest active secret (for sealing).
    pub fn latest_secret(&self) -> Result<&[u8; 32]> {
        let epoch = self.latest_epoch()?;
        self.secret(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &[u8; 32]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    }

    #[test]
    fn latest_and_lookup() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let reg = EpochRegistry::new(vec![a, b]);
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.latest_epoch().unwrap(), 1);
        assert_eq!(reg.secret(0).unwrap(), &a);
        assert_eq!(reg.secret(1).unwrap(), &b);
        let err = reg.secret(2).unwrap_err();
        assert_eq!(err.code, ErrorCode::EpochRetired);
    }

    #[test]
    fn parse_registry() {
        let a = [9u8; 32];
        let reg = EpochRegistry::parse(&format!("{};{}", b64(&a), b64(&a))).unwrap();
        assert_eq!(reg.len(), 2);

        assert!(EpochRegistry::parse("").is_err());
        // non-32-byte secret rejected
        assert!(EpochRegistry::parse("AAAA").is_err());
    }

    #[test]
    fn sparse_registry_retires_holes() {
        let a = [1u8; 32];
        let c = [3u8; 32];
        // epoch 1 retired: "A;;C"
        let reg = EpochRegistry::parse(&format!("{};;{}", b64(&a), b64(&c))).unwrap();
        assert_eq!(reg.slots(), 3);
        assert_eq!(reg.len(), 2);
        // Retired hole → EPOCH_RETIRED.
        assert_eq!(reg.secret(1).unwrap_err().code, ErrorCode::EpochRetired);
        // Kept epochs keep their numbers.
        assert_eq!(reg.secret(0).unwrap(), &a);
        assert_eq!(reg.secret(2).unwrap(), &c);
        // Latest active is the highest non-hole.
        assert_eq!(reg.latest_epoch().unwrap(), 2);
        assert_eq!(reg.latest_secret().unwrap(), &c);
    }

    #[test]
    fn all_holes_is_an_error() {
        assert!(EpochRegistry::parse(";;").is_err());
    }
}
