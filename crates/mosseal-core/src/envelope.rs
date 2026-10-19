//! Envelope binary format (spec 01).
//!
//! Layout (all integers little-endian), shared by v1 and v2:
//!
//! ```text
//! offset  size  field
//! 0       1     version       (0x01 v1, 0x02 v2)
//! 1       1     flags         bit0: password-protected
//!                                 bit1: expiry present
//!                                 bits 2-7: reserved, must be 0
//! 2       1     key_epoch
//! 3       1     salt_len      (always 16)
//! 4       16    salt
//! 20      1     nonce_len     (always 12)
//! 21      12    nonce
//! 33      var   ciphertext    AES-256-GCM over inner plaintext (incl. 16B tag)
//! ```
//!
//! Inner plaintext by version:
//!
//! ```text
//! v1: payload                    (no key commitment)
//! v2: key_commit(16) ‖ payload
//! ```
//!
//! Inner payload (what gets encrypted; also length-prefixed binary, u32 data len):
//!
//! ```text
//! kind : u8          0x01 = token, 0x02 = binary_blob, 0x03 = multi (v2 only)
//! exp  : u64 LE      unix seconds, 0 = no expiry
//! data_len : u32 LE
//! data : [u8; data_len]
//! ```
//!
//! v2's `key_commit` (see [`key_commit`]) is verified right after AEAD
//! decryption and before payload parsing, closing the AES-GCM
//! partitioning/forgery hole where a crafted ciphertext could decrypt to
//! different valid plaintexts under different keys.

use crate::{ErrorCode, MossealError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 1 + 1 + 1 + 1 + SALT_LEN + 1 + NONCE_LEN; // 33

pub mod flags {
    pub const PASSWORD: u8 = 0b0000_0001;
    pub const EXPIRY: u8 = 0b0000_0010;
    pub const RESERVED_MASK: u8 = 0b1111_1100;
}

pub mod kind {
    pub const TOKEN: u8 = 0x01;
    pub const BINARY_BLOB: u8 = 0x02;
    /// N-secret slot-table payload (v2 envelopes only; spec 01 § MULTI kind).
    pub const MULTI: u8 = 0x03;
}

/// Key commitment for v2 envelopes (spec 01/02): the AEAD plaintext is
/// prefixed with `SHA-256("mosseal/v2" ‖ key)[..16]`.
///
/// Verified before payload parsing; a mismatch takes the same error path as a
/// GCM tag failure. This binds the plaintext to the exact derived key, so a
/// crafted ciphertext cannot decrypt to different valid plaintexts under
/// different keys (critical once "which key is real" becomes adversarial in
/// deniable mode).
pub mod key_commit {
    use sha2::{Digest, Sha256};

    /// Commitment length in bytes (plaintext prefix overhead per v2 layer).
    pub const LEN: usize = 16;

    /// Domain-separation tag (ASCII, no separator).
    pub const DOMAIN: &[u8] = b"mosseal/v2";

    /// Build the commitment for a derived 32-byte AEAD key.
    pub fn build(key: &[u8; 32]) -> [u8; LEN] {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(key);
        let digest = h.finalize();
        digest[..LEN].try_into().unwrap()
    }

    /// Constant-time prefix check: does `prefix` commit to `key`?
    pub fn matches(prefix: &[u8], key: &[u8; 32]) -> bool {
        if prefix.len() != LEN {
            return false;
        }
        let expect = build(key);
        // No early exit: every byte always participates in the comparison.
        let mut diff = 0u8;
        for (a, b) in prefix.iter().zip(expect.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// `MULTI` payload (kind `0x03`, spec 01 § MULTI kind): N independently
/// Argon2id-keyed slot records inside one password-less v2 envelope.
///
/// Wire format (all integers little-endian):
///
/// ```text
/// multi_version : u8 = 0x01
/// slot_count    : u8  (1..=MAX_SLOTS)
/// per slot:
///   slot_salt  : [u8; 16]     fresh per slot
///   slot_nonce : [u8; 12]     fresh per slot
///   slot_ct_len: u32 LE
///   slot_ct    : AES-256-GCM( key_commit(16) ‖ slot_payload , AAD = slot AAD )
/// ```
///
/// `slot_payload` is the ordinary [`Payload`] struct reused verbatim, so slot
/// data inherits the payload cap and kind validation. Each slot runs its own
/// Argon2id derivation (never one run sliced into N keys — slicing would let
/// any single password holder derive all slot keys).
pub mod multi {
    use super::{key_commit, SALT_LEN, TAG_LEN};

    /// Current `multi_blob` version byte.
    pub const MULTI_VERSION: u8 = 0x01;

    /// Default slot cap (D7); override at build time with
    /// `MOSSEAL_MULTI_MAX_SLOTS=8` (only 4 or 8 are valid).
    const fn validated_max_slots() -> usize {
        match option_env!("MOSSEAL_MULTI_MAX_SLOTS") {
            None => 4,
            Some(s) => {
                let b = s.as_bytes();
                if b.len() == 1 && b[0] == b'4' {
                    4
                } else if b.len() == 1 && b[0] == b'8' {
                    8
                } else {
                    panic!("MOSSEAL_MULTI_MAX_SLOTS must be 4 or 8")
                }
            }
        }
    }

    /// Maximum number of slots in a `MULTI` envelope (seal rejects more with
    /// `TOO_MANY_SLOTS`; open rejects a malformed higher count with
    /// `MALFORMED_ENVELOPE`).
    pub const MAX_SLOTS: usize = validated_max_slots();

    /// One encrypted slot: fresh salt/nonce plus the AEAD ciphertext over
    /// `key_commit ‖ slot_payload` under that slot's Argon2id key.
    #[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct SlotRecord {
        pub salt: [u8; SALT_LEN],
        pub nonce: [u8; 12],
        pub ciphertext: Vec<u8>,
    }

    /// Decoded `multi_blob` (`payload.data` of a `MULTI` envelope).
    #[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct MultiBlob {
        pub version: u8,
        pub slots: Vec<SlotRecord>,
    }

    /// Slot AAD (spec 01): binds the slot's position and parameters into its
    /// GCM tag — `multi_version ‖ slot_count ‖ slot_index ‖ slot_salt ‖
    /// slot_nonce` (31 bytes).
    pub fn slot_aad(
        multi_version: u8,
        slot_count: u8,
        slot_index: u8,
        slot: &SlotRecord,
    ) -> [u8; 31] {
        let mut aad = [0u8; 31];
        aad[0] = multi_version;
        aad[1] = slot_count;
        aad[2] = slot_index;
        aad[3..3 + SALT_LEN].copy_from_slice(&slot.salt);
        aad[3 + SALT_LEN..].copy_from_slice(&slot.nonce);
        aad
    }

    impl MultiBlob {
        pub fn encode(&self) -> crate::Result<Vec<u8>> {
            if self.version != MULTI_VERSION {
                return Err(crate::MossealError::new(
                    crate::ErrorCode::MalformedEnvelope,
                    format!("multi version {} not supported", self.version),
                ));
            }
            let count = self.slots.len();
            if count == 0 || count > MAX_SLOTS {
                return Err(crate::MossealError::new(
                    if count > MAX_SLOTS {
                        crate::ErrorCode::TooManySlots
                    } else {
                        crate::ErrorCode::MalformedEnvelope
                    },
                    format!("slot count {count} outside 1..={MAX_SLOTS}"),
                ));
            }
            let mut out = Vec::with_capacity(2 + count * (SALT_LEN + 12 + 4));
            out.push(self.version);
            out.push(count as u8);
            for slot in &self.slots {
                out.extend_from_slice(&slot.salt);
                out.extend_from_slice(&slot.nonce);
                out.extend_from_slice(&(slot.ciphertext.len() as u32).to_le_bytes());
                out.extend_from_slice(&slot.ciphertext);
            }
            Ok(out)
        }

        pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
            if bytes.len() < 2 {
                return Err(malformed("multi blob truncated"));
            }
            let version = bytes[0];
            if version != MULTI_VERSION {
                return Err(crate::MossealError::new(
                    crate::ErrorCode::MalformedEnvelope,
                    format!("multi version {version} not supported"),
                ));
            }
            let count = bytes[1] as usize;
            if count == 0 || count > MAX_SLOTS {
                return Err(malformed(format!(
                    "slot count {count} outside 1..={MAX_SLOTS}"
                )));
            }
            let mut rest = &bytes[2..];
            let mut slots = Vec::with_capacity(count);
            for _ in 0..count {
                if rest.len() < SALT_LEN + 12 + 4 {
                    return Err(malformed("slot header truncated"));
                }
                let salt: [u8; SALT_LEN] = rest[..SALT_LEN].try_into().unwrap();
                let nonce: [u8; 12] = rest[SALT_LEN..SALT_LEN + 12].try_into().unwrap();
                let ct_len =
                    u32::from_le_bytes(rest[SALT_LEN + 12..SALT_LEN + 12 + 4].try_into().unwrap())
                        as usize;
                rest = &rest[SALT_LEN + 12 + 4..];
                // Every legitimate slot plaintext starts with the key
                // commitment (16 B) plus the GCM tag (16 B); anything shorter
                // is definitionally malformed, not a wrong password.
                if ct_len < TAG_LEN + key_commit::LEN {
                    return Err(malformed("slot ciphertext too short"));
                }
                if rest.len() < ct_len {
                    return Err(malformed("slot ciphertext overruns blob"));
                }
                slots.push(SlotRecord {
                    salt,
                    nonce,
                    ciphertext: rest[..ct_len].to_vec(),
                });
                rest = &rest[ct_len..];
            }
            if !rest.is_empty() {
                return Err(malformed("trailing bytes after last slot"));
            }
            Ok(MultiBlob { version, slots })
        }
    }

    fn malformed(detail: impl Into<String>) -> crate::MossealError {
        crate::MossealError::new(crate::ErrorCode::MalformedEnvelope, detail)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sample_blob() -> MultiBlob {
            MultiBlob {
                version: MULTI_VERSION,
                slots: vec![
                    SlotRecord {
                        salt: [0x01; SALT_LEN],
                        nonce: [0x02; 12],
                        ciphertext: vec![0xAA; 48],
                    },
                    SlotRecord {
                        salt: [0x03; SALT_LEN],
                        nonce: [0x04; 12],
                        ciphertext: vec![0xBB; 64],
                    },
                ],
            }
        }

        #[test]
        fn roundtrip_multi_blob() {
            let blob = sample_blob();
            let bytes = blob.encode().unwrap();
            assert_eq!(MultiBlob::decode(&bytes).unwrap(), blob);
            // Layout: version(1) + count(1) + per slot [16+12+4+ct].
            assert_eq!(bytes.len(), 2 + (16 + 12 + 4 + 48) + (16 + 12 + 4 + 64));
            assert_eq!(bytes[0], MULTI_VERSION);
            assert_eq!(bytes[1], 2);
        }

        #[test]
        fn max_slots_matches_build_flag() {
            // The override is compile-time (D7): the default build is 4, and
            // a `MOSSEAL_MULTI_MAX_SLOTS=8` build (CI `multi-max-slots` job)
            // must see 8. Invalid values fail compilation (const panic).
            let expected = match option_env!("MOSSEAL_MULTI_MAX_SLOTS") {
                Some("8") => 8,
                _ => 4,
            };
            assert_eq!(MAX_SLOTS, expected);
        }

        #[test]
        fn rejects_empty_and_over_cap_counts() {
            let mut blob = sample_blob();
            blob.slots.clear();
            assert_eq!(
                blob.encode().unwrap_err().code,
                crate::ErrorCode::MalformedEnvelope
            );
            let template = sample_blob().slots[0].clone();
            while blob.slots.len() <= MAX_SLOTS {
                blob.slots.push(template.clone());
            }
            assert_eq!(
                blob.encode().unwrap_err().code,
                crate::ErrorCode::TooManySlots
            );
        }

        #[test]
        fn decode_rejects_hostile_blobs() {
            let good = sample_blob().encode().unwrap();
            // Truncated at every boundary.
            for cut in 0..good.len() {
                let code = MultiBlob::decode(&good[..cut]).unwrap_err().code;
                assert_eq!(code, crate::ErrorCode::MalformedEnvelope, "cut {cut}");
            }
            // Trailing junk.
            let mut trailing = good.clone();
            trailing.push(0xFF);
            assert!(MultiBlob::decode(&trailing).is_err());
            // Unknown multi version.
            let mut future = good.clone();
            future[0] = 0x02;
            assert!(MultiBlob::decode(&future).is_err());
            // Zero / over-cap slot count byte.
            let mut zero = good.clone();
            zero[1] = 0;
            assert!(MultiBlob::decode(&zero).is_err());
            let mut over = good.clone();
            over[1] = MAX_SLOTS as u8 + 1;
            assert!(MultiBlob::decode(&over).is_err());
            // Hostile ct_len (shorter than tag + commitment).
            let mut short_ct = good.clone();
            short_ct[2 + 16 + 12..2 + 16 + 12 + 4].copy_from_slice(&1u32.to_le_bytes());
            assert!(MultiBlob::decode(&short_ct).is_err());
            // Hostile ct_len (overrun).
            let mut overrun = good.clone();
            overrun[2 + 16 + 12..2 + 16 + 12 + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(MultiBlob::decode(&overrun).is_err());
        }

        #[test]
        fn slot_aad_binds_index_and_params() {
            let blob = sample_blob();
            let a0 = slot_aad(MULTI_VERSION, 2, 0, &blob.slots[0]);
            let a1 = slot_aad(MULTI_VERSION, 2, 1, &blob.slots[0]);
            // Same slot at a different index → different AAD (reorder breaks).
            assert_ne!(a0, a1);
            assert_eq!(a0[0], MULTI_VERSION);
            assert_eq!(a0[1], 2);
            assert_eq!(a0[2], 0);
            assert_eq!(&a0[3..19], &blob.slots[0].salt[..]);
            assert_eq!(&a0[19..], &blob.slots[0].nonce[..]);
        }
    }
}

/// Decoded outer envelope header + ciphertext. Header fields feed the AEAD
/// AAD (spec 02 § Cipher): binding the metadata into the GCM tag so header
/// tampering fails before payload parsing.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Envelope {
    pub version: u8,
    pub flags: u8,
    pub key_epoch: u8,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// The AAD bytes for AES-GCM: exactly the header prefix of the wire format
    /// (`version | flags | key_epoch | salt | nonce`), excluding length bytes
    /// which are fixed by the version.
    pub fn aad(&self) -> [u8; HEADER_LEN - 2] {
        // version(1) + flags(1) + epoch(1) + salt(16) + nonce(12) = 31 bytes
        let mut aad = [0u8; HEADER_LEN - 2];
        aad[0] = self.version;
        aad[1] = self.flags;
        aad[2] = self.key_epoch;
        aad[3..3 + SALT_LEN].copy_from_slice(&self.salt);
        aad[3 + SALT_LEN..].copy_from_slice(&self.nonce);
        aad
    }
}

/// Inner plaintext payload (spec 01 § Inner payload).
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Payload {
    pub kind: u8,
    /// Unix seconds; 0 = no expiry.
    pub exp: u64,
    pub data: Vec<u8>,
}

impl Payload {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.data.len() > crate::MAX_PAYLOAD_BYTES {
            return Err(MossealError::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "{} bytes exceeds cap of {}",
                    self.data.len(),
                    crate::MAX_PAYLOAD_BYTES
                ),
            ));
        }
        let mut out = Vec::with_capacity(1 + 8 + 4 + self.data.len());
        out.push(self.kind);
        out.extend_from_slice(&self.exp.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1 + 8 + 4 {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                "payload truncated",
            ));
        }
        let kind = bytes[0];
        let exp = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        let data_len = u32::from_le_bytes(bytes[9..13].try_into().unwrap()) as usize;
        // `checked_add` guards against a hostile u32 length overflowing usize
        // on 32-bit targets (would otherwise panic in debug builds).
        let expected = 13usize.checked_add(data_len).ok_or_else(|| {
            MossealError::new(ErrorCode::MalformedEnvelope, "payload length overflow")
        })?;
        if bytes.len() != expected {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                "payload length mismatch",
            ));
        }
        Ok(Payload {
            kind,
            exp,
            data: bytes[13..].to_vec(),
        })
    }
}

/// Encode outer envelope to wire bytes.
pub fn encode(env: &Envelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + env.ciphertext.len());
    out.push(env.version);
    out.push(env.flags);
    out.push(env.key_epoch);
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&env.salt);
    out.push(NONCE_LEN as u8);
    out.extend_from_slice(&env.nonce);
    out.extend_from_slice(&env.ciphertext);
    out
}

/// Decode outer envelope from wire bytes.
pub fn decode(bytes: &[u8]) -> Result<Envelope> {
    if bytes.len() < HEADER_LEN {
        return Err(MossealError::new(
            ErrorCode::MalformedEnvelope,
            "envelope truncated",
        ));
    }
    let version = bytes[0];
    // v1 links stay openable forever (permanent read path); anything above
    // the current version is forward-incompatible; 0 is malformed.
    if !(crate::MIN_OPEN_VERSION..=crate::ENVELOPE_VERSION).contains(&version) {
        return Err(MossealError::new(
            if version > crate::ENVELOPE_VERSION {
                ErrorCode::UnsupportedVersion
            } else {
                ErrorCode::MalformedEnvelope
            },
            format!("version byte {version}"),
        ));
    }
    let flags = bytes[1];
    if flags & flags::RESERVED_MASK != 0 {
        return Err(MossealError::new(
            ErrorCode::MalformedEnvelope,
            "reserved flag bits set",
        ));
    }
    let key_epoch = bytes[2];
    if bytes[3] as usize != SALT_LEN {
        return Err(MossealError::new(
            ErrorCode::MalformedEnvelope,
            "unexpected salt length",
        ));
    }
    let salt: [u8; SALT_LEN] = bytes[4..4 + SALT_LEN].try_into().unwrap();
    if bytes[4 + SALT_LEN] as usize != NONCE_LEN {
        return Err(MossealError::new(
            ErrorCode::MalformedEnvelope,
            "unexpected nonce length",
        ));
    }
    let nonce: [u8; NONCE_LEN] = bytes[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN]
        .try_into()
        .unwrap();
    let ciphertext = bytes[HEADER_LEN..].to_vec();
    if ciphertext.len() < TAG_LEN {
        return Err(MossealError::new(
            ErrorCode::MalformedEnvelope,
            "ciphertext shorter than GCM tag",
        ));
    }
    Ok(Envelope {
        version,
        flags,
        key_epoch,
        salt,
        nonce,
        ciphertext,
    })
}

/// base64url (no padding) codec for the URL fragment (spec 01).
pub mod b64 {
    use base64::Engine;

    pub fn encode(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> Envelope {
        Envelope {
            version: 1,
            flags: flags::PASSWORD | flags::EXPIRY,
            key_epoch: 3,
            salt: [0xAB; SALT_LEN],
            nonce: [0xCD; NONCE_LEN],
            ciphertext: vec![0x11; 32],
        }
    }

    #[test]
    fn roundtrip_envelope() {
        let env = sample_envelope();
        let bytes = encode(&env);
        assert_eq!(decode(&bytes).unwrap(), env);
    }

    #[test]
    fn rejects_truncated() {
        let bytes = encode(&sample_envelope());
        for cut in 0..HEADER_LEN {
            assert!(decode(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn rejects_reserved_bits() {
        let mut env = sample_envelope();
        env.flags |= 0b0000_0100;
        let bytes = encode(&env);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_future_version() {
        let mut env = sample_envelope();
        env.version = crate::ENVELOPE_VERSION + 1;
        let bytes = encode(&env);
        match decode(&bytes).unwrap_err().code {
            ErrorCode::UnsupportedVersion => {}
            other => panic!("wrong code: {other:?}"),
        }
    }

    #[test]
    fn accepts_v1_and_v2() {
        for v in [1u8, 2u8] {
            let mut env = sample_envelope();
            env.version = v;
            let bytes = encode(&env);
            assert_eq!(decode(&bytes).unwrap().version, v, "version {v} openable");
        }
    }

    #[test]
    fn key_commit_builds_and_verifies() {
        let key = [0x42u8; 32];
        let commit = key_commit::build(&key);
        assert_eq!(commit.len(), key_commit::LEN);
        assert!(key_commit::matches(&commit, &key));
        // Different key → different commitment, no match.
        let other = [0x43u8; 32];
        assert_ne!(commit, key_commit::build(&other));
        assert!(!key_commit::matches(&commit, &other));
        // Wrong-length prefix never matches.
        assert!(!key_commit::matches(&commit[..15], &key));
    }

    #[test]
    fn key_commit_is_domain_separated() {
        use sha2::{Digest, Sha256};
        let key = [7u8; 32];
        // Must not equal the un-tagged hash prefix (domain separation).
        let mut h = Sha256::new();
        h.update(key);
        let raw: [u8; 16] = h.finalize()[..16].try_into().unwrap();
        assert_ne!(key_commit::build(&key), raw);
        // First byte of the domain tag dominates: "mosseal/v2" = 0x6d...
        let mut h = Sha256::new();
        h.update(key_commit::DOMAIN);
        h.update(key);
        let expect: [u8; 16] = h.finalize()[..16].try_into().unwrap();
        assert_eq!(key_commit::build(&key), expect);
    }

    #[test]
    fn aad_is_header_prefix() {
        let env = sample_envelope();
        let aad = env.aad();
        assert_eq!(aad.len(), HEADER_LEN - 2);
        assert_eq!(aad[0], 1);
        assert_eq!(aad[1], env.flags);
        assert_eq!(aad[2], 3);
        assert_eq!(&aad[3..19], &env.salt[..]);
        assert_eq!(&aad[19..], &env.nonce[..]);
    }

    #[test]
    fn payload_roundtrip_and_cap() {
        let p = Payload {
            kind: kind::TOKEN,
            exp: 12345,
            data: b"tok_abc123".to_vec(),
        };
        assert_eq!(Payload::decode(&p.encode().unwrap()).unwrap(), p);

        let big = Payload {
            kind: kind::TOKEN,
            exp: 0,
            data: vec![7u8; crate::MAX_PAYLOAD_BYTES + 1],
        };
        assert!(matches!(
            big.encode().unwrap_err().code,
            ErrorCode::PayloadTooLarge
        ));
    }

    #[test]
    fn payload_rejects_trailing() {
        let mut bytes = Payload {
            kind: 1,
            exp: 1,
            data: vec![1],
        }
        .encode()
        .unwrap();
        bytes.push(0xFF);
        assert!(Payload::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_salt_length() {
        let mut bytes = encode(&sample_envelope());
        bytes[3] = 15; // salt_len must be SALT_LEN (16)
        let err = decode(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
    }

    #[test]
    fn rejects_bad_nonce_length() {
        let mut bytes = encode(&sample_envelope());
        bytes[4 + SALT_LEN] = 11; // nonce_len must be NONCE_LEN (12)
        let err = decode(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
    }

    #[test]
    fn rejects_ciphertext_shorter_than_tag() {
        let bytes = encode(&sample_envelope());
        let truncated = &bytes[..HEADER_LEN + TAG_LEN - 1];
        let err = decode(truncated).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
    }

    #[test]
    fn rejects_zero_version_as_malformed() {
        let mut bytes = encode(&sample_envelope());
        bytes[0] = 0;
        let err = decode(&bytes).unwrap_err();
        // Below the current version → malformed; above → unsupported.
        assert_eq!(err.code, ErrorCode::MalformedEnvelope);
    }

    #[test]
    fn b64_roundtrip_and_rejects_invalid() {
        let raw = [0x00, 0x01, 0xFE, 0xFF, 0x7F];
        let s = b64::encode(&raw);
        // URL-safe, unpadded (spec 01).
        assert!(!s.contains('='));
        assert!(!s.contains('+') && !s.contains('/'));
        assert_eq!(b64::decode(&s).unwrap(), raw);
        assert!(b64::decode("not!base64!!").is_err());
    }
}
