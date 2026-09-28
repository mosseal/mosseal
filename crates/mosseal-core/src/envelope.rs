//! Envelope binary format (spec 01).
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version       (0x01 for v1)
//! 1       1     flags         bit0: password-protected
//!                                 bit1: expiry present
//!                                 bits 2-7: reserved, must be 0
//! 2       1     key_epoch
//! 3       1     salt_len      (always 16 in v1)
//! 4       16    salt
//! 20      1     nonce_len     (always 12 in v1)
//! 21      12    nonce
//! 33      var   ciphertext    AES-256-GCM over inner payload (incl. 16B tag)
//! ```
//!
//! Inner payload (what gets encrypted; also length-prefixed binary, u8 data len):
//!
//! ```text
//! kind : u8          0x01 = token, 0x02 = binary_blob
//! exp  : u64 LE      unix seconds, 0 = no expiry
//! data_len : u8
//! data : [u8; data_len]
//! ```

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
                    "{} bytes exceeds v1 cap of {}",
                    self.data.len(),
                    crate::MAX_PAYLOAD_BYTES
                ),
            ));
        }
        let mut out = Vec::with_capacity(1 + 8 + 1 + self.data.len());
        out.push(self.kind);
        out.extend_from_slice(&self.exp.to_le_bytes());
        out.push(self.data.len() as u8);
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1 + 8 + 1 {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                "payload truncated",
            ));
        }
        let kind = bytes[0];
        let exp = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        let data_len = bytes[9] as usize;
        if bytes.len() != 10 + data_len {
            return Err(MossealError::new(
                ErrorCode::MalformedEnvelope,
                "payload length mismatch",
            ));
        }
        Ok(Payload {
            kind,
            exp,
            data: bytes[10..].to_vec(),
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
    if version != crate::ENVELOPE_VERSION {
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
        env.version = 2;
        let bytes = encode(&env);
        match decode(&bytes).unwrap_err().code {
            ErrorCode::UnsupportedVersion => {}
            other => panic!("wrong code: {other:?}"),
        }
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
            data: vec![7u8; 256],
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
