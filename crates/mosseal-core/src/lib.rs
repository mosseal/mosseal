//! MOSSEAL core: platform-agnostic implementation of end-to-end authenticated
//! link envelopes.
//!
//! This crate implements the specs in `specs/00`–`specs/09`. It contains no
//! platform-specific code; WASM bindings live in `mosseal-wasm` and CLI in
//! `mosseal-cli`.
//!
//! Layout (mirrors spec 02):
//! - [`envelope`] — binary envelope format encode/decode (spec 01)
//! - [`kdf`] — key derivation: HKDF default path + Argon2id password path
//! - [`binding`] — domain binding string construction (spec 03)
//! - [`epoch`] — key-epoch registry (spec 02 § Key epochs)
//! - [`time`] — expiry enforcement + internet-time sources (spec 07)
//! - [`seal`] — top-level seal/open orchestration

pub mod binding;
pub mod envelope;
pub mod epoch;
pub mod kdf;
pub mod seal;
pub mod time;
/// Error taxonomy shared across wasm ↔ TS boundary (specs 01–02).
/// Codes are stable and machine-readable; apps must not string-match prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorCode {
    #[error("malformed envelope")]
    MalformedEnvelope,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("unsupported kind")]
    UnsupportedKind,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("domain mismatch")]
    DomainMismatch,
    #[error("bad password")]
    BadPassword,
    #[error("expired")]
    Expired,
    #[error("strict time unavailable")]
    StrictTimeUnavailable,
    #[error("epoch retired")]
    EpochRetired,
    #[error("wasm init failed")]
    WasmInitFailed,
}

impl ErrorCode {
    /// Stable, machine-readable code string (spec 02 § wasm-bindgen surface).
    ///
    /// This is the exact value the wasm layer puts in `JsError` messages and
    /// the TS wrapper matches against (`MossealErrorCode`). It is deliberately
    /// distinct from the `thiserror` `Display` prose: apps must never
    /// string-match human text, only these codes.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::MalformedEnvelope => "MALFORMED_ENVELOPE",
            ErrorCode::UnsupportedVersion => "UNSUPPORTED_VERSION",
            ErrorCode::UnsupportedKind => "UNSUPPORTED_KIND",
            ErrorCode::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            ErrorCode::DomainMismatch => "DOMAIN_MISMATCH",
            ErrorCode::BadPassword => "BAD_PASSWORD",
            ErrorCode::Expired => "EXPIRED",
            ErrorCode::StrictTimeUnavailable => "STRICT_TIME_UNAVAILABLE",
            ErrorCode::EpochRetired => "EPOCH_RETIRED",
            ErrorCode::WasmInitFailed => "WASM_INIT_FAILED",
        }
    }
}

/// Max `data` bytes permitted in v1 envelopes (u8 length prefix, spec 01).
pub const MAX_PAYLOAD_BYTES: usize = 255;

/// Envelope format version byte for v1 (spec 01).
pub const ENVELOPE_VERSION: u8 = 1;

/// A top-level error carrying a stable code plus optional detail.
#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct MossealError {
    pub code: ErrorCode,
    pub detail: String,
}

impl MossealError {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, MossealError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The code strings are a wire contract: the wasm layer puts them in
    /// `JsError` messages and `@mosseal/core`'s `fromWasmError` matches them
    /// verbatim (spec 02). Any change here is a breaking change.
    #[test]
    fn error_code_strings_are_stable() {
        let cases = [
            (ErrorCode::MalformedEnvelope, "MALFORMED_ENVELOPE"),
            (ErrorCode::UnsupportedVersion, "UNSUPPORTED_VERSION"),
            (ErrorCode::UnsupportedKind, "UNSUPPORTED_KIND"),
            (ErrorCode::PayloadTooLarge, "PAYLOAD_TOO_LARGE"),
            (ErrorCode::DomainMismatch, "DOMAIN_MISMATCH"),
            (ErrorCode::BadPassword, "BAD_PASSWORD"),
            (ErrorCode::Expired, "EXPIRED"),
            (ErrorCode::StrictTimeUnavailable, "STRICT_TIME_UNAVAILABLE"),
            (ErrorCode::EpochRetired, "EPOCH_RETIRED"),
            (ErrorCode::WasmInitFailed, "WASM_INIT_FAILED"),
        ];
        assert_eq!(cases.len(), 10, "all taxonomy codes are covered");
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected, "code {code:?} string drifted");
        }
    }

    /// The machine-readable code must differ from the human `Display` prose so
    /// apps can never accidentally string-match the wrong thing (spec 02).
    #[test]
    fn as_str_is_not_the_display_prose() {
        assert_eq!(ErrorCode::BadPassword.to_string(), "bad password");
        assert_ne!(
            ErrorCode::BadPassword.to_string(),
            ErrorCode::BadPassword.as_str()
        );
    }

    #[test]
    fn mosseal_error_carries_code_and_detail() {
        let e = MossealError::new(ErrorCode::PayloadTooLarge, "too big");
        assert_eq!(e.code, ErrorCode::PayloadTooLarge);
        assert_eq!(e.detail, "too big");
        assert!(e.to_string().contains("too big"));
    }
}
