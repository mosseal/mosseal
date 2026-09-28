//! End-to-end seal → open integration tests through the **public** API only.
//!
//! The unit tests in `src/*.rs` exercise internals; this file treats
//! `mosseal-core` as a consumer would (spec 02/04). It pins three properties
//! spec 08 cares about at the native level:
//!
//! 1. **Round-trip fidelity** across the kind × password × expiry matrix.
//! 2. **Portability** — a link sealed once opens on every whitelisted host.
//! 3. **No leaks** — neither the fragment nor any error detail exposes the
//!    plaintext or the password.
//!
//! A golden-fragment assertion locks the wire bytes: any accidental format or
//! KDF change fails here before it can silently brick existing links.

use mosseal_core::{
    binding,
    envelope::{self, flags, kind},
    epoch::EpochRegistry,
    kdf::Argon2Profile,
    seal::{SealContext, SealInput},
    time::{FetchTimes, TimeMode, TimeSource},
    ErrorCode,
};

/// Fixed test secrets (spec 08: never the consumer's). Sparse — epoch 1 is a
/// retired hole, so the registry exercises the retirement path too.
const SECRET_0: [u8; 32] = [0x11; 32];
const SECRET_2: [u8; 32] = [0x33; 32];

/// Fixed test whitelist (spec 08).
const DOMAINS: [&str; 2] = ["a.test", "b.test"];

struct NoFetch;
impl FetchTimes for NoFetch {
    fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
        None
    }
}

struct FixedFetch(f64);
impl FetchTimes for FixedFetch {
    fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
        Some(self.0)
    }
}

fn ctx() -> SealContext {
    SealContext {
        epochs: EpochRegistry::from_slots(vec![Some(SECRET_0), None, Some(SECRET_2)]),
        whitelist: DOMAINS.iter().map(|s| s.to_string()).collect(),
        argon_profile: Argon2Profile::Minimum,
        time_mode: TimeMode::Lenient,
        runtime_hostname: None,
        time_sources: Vec::new(),
    }
}

fn input(kind_byte: u8, exp: Option<u64>, password: Option<&str>) -> SealInput {
    SealInput {
        data: b"tok_abc123".to_vec(),
        kind: kind_byte,
        exp,
        password: password.map(|p| p.as_bytes().to_vec()),
        deterministic_salt: Some([0x01; 16]),
        deterministic_nonce: Some([0x02; 12]),
        deterministic_epoch: None,
    }
}

/// Spec 08 § conformance: the exact fragment the vectors crate records for
/// `token-nopass-exp0`. If this drifts, the wire format or KDF changed.
const GOLDEN_TOKEN_NOPASS_EXP0: &str =
    "AQACEAEBAQEBAQEBAQEBAQEBAQEMAgICAgICAgICAgIC8yHQexOIOEoaSAdmh6hhExeb87jgGfhQKFAcyKr8eaxiRS5oq89s";

#[test]
fn golden_fragment_is_stable() {
    let c = ctx();
    let frag = c.seal(&input(kind::TOKEN, None, None)).unwrap();
    assert_eq!(frag, GOLDEN_TOKEN_NOPASS_EXP0);
    // Sealed at the latest ACTIVE epoch (2), not the retired hole (1).
    let bytes = envelope::b64::decode(&frag).unwrap();
    assert_eq!(bytes[2], 2);
}

#[test]
fn roundtrip_matrix() {
    let c = ctx();
    for kind_byte in [kind::TOKEN, kind::BINARY_BLOB] {
        for password in [None, Some("hunter2")] {
            for (exp, fetcher_now) in [(None, None), (Some(2_000u64), Some(1_000f64))] {
                let frag = c
                    .seal(&input(kind_byte, exp, password))
                    .unwrap_or_else(|e| panic!("seal failed: {e}"));
                let out = match fetcher_now {
                    Some(now) => c.open(&frag, password.map(str::as_bytes), &FixedFetch(now)),
                    None => c.open(&frag, password.map(str::as_bytes), &NoFetch),
                }
                .unwrap_or_else(|e| panic!("open failed: {e}"));
                assert_eq!(out.data, b"tok_abc123");
                assert_eq!(out.kind, kind_byte);
                assert_eq!(out.exp, exp.unwrap_or(0));
            }
        }
    }
}

#[test]
fn flag_bits_match_inputs() {
    let c = ctx();
    let plain = c.seal(&input(kind::TOKEN, None, None)).unwrap();
    let bytes = envelope::b64::decode(&plain).unwrap();
    assert_eq!(bytes[1] & flags::PASSWORD, 0);
    assert_eq!(bytes[1] & flags::EXPIRY, 0);

    let both = c
        .seal(&input(kind::TOKEN, Some(2_000), Some("pw")))
        .unwrap();
    let bytes = envelope::b64::decode(&both).unwrap();
    assert_eq!(bytes[1] & flags::PASSWORD, flags::PASSWORD);
    assert_eq!(bytes[1] & flags::EXPIRY, flags::EXPIRY);
}

#[test]
fn fragment_is_url_fragment_safe() {
    let c = ctx();
    let frag = c.seal(&input(kind::TOKEN, None, None)).unwrap();
    // base64url, unpadded (spec 01) — safe inside a `#ms=` fragment.
    assert!(!frag.contains(['+', '/', '=', '#', '?', '&']));
    assert!(envelope::b64::decode(&frag).is_ok());
}

#[test]
fn link_is_portable_across_all_whitelisted_hosts() {
    let c = ctx();
    let frag = c.seal(&input(kind::TOKEN, None, None)).unwrap();
    for host in DOMAINS {
        let mut c2 = ctx();
        c2.runtime_hostname = Some(host.to_string());
        assert!(
            c2.open(&frag, None, &NoFetch).is_ok(),
            "link must open on whitelisted host {host}"
        );
    }
}

#[test]
fn link_is_not_portable_to_an_unlisted_host() {
    let c = ctx();
    let frag = c.seal(&input(kind::TOKEN, None, None)).unwrap();
    let mut c2 = ctx();
    c2.runtime_hostname = Some("evil.test".to_string());
    let err = c2.open(&frag, None, &NoFetch).unwrap_err();
    assert_eq!(err.code, ErrorCode::DomainMismatch);
}

#[test]
fn no_plaintext_or_password_leaks_anywhere() {
    let c = ctx();
    let secret_data = "tok_SUPER_SECRET_1234567890";
    let secret_pw = "pw_SUPER_SECRET_9876543210";
    let input = SealInput {
        data: secret_data.as_bytes().to_vec(),
        password: Some(secret_pw.as_bytes().to_vec()),
        ..input(kind::TOKEN, Some(2_000), Some(secret_pw))
    };
    let frag = c.seal(&input).unwrap();

    // The fragment is ciphertext: neither plaintext nor password appear, in
    // raw or base64 form.
    assert!(!frag.contains(secret_data));
    assert!(!frag.contains(secret_pw));
    let raw = envelope::b64::decode(&frag).unwrap();
    assert!(!contains_subslice(&raw, secret_data.as_bytes()));
    assert!(!contains_subslice(&raw, secret_pw.as_bytes()));

    // Wrong-password errors must not echo the supplied password either.
    let err = c.open(&frag, Some(b"wrong_guess"), &NoFetch).unwrap_err();
    assert_eq!(err.code, ErrorCode::BadPassword);
    assert!(!err.detail.contains("wrong_guess"));
    assert!(!err.detail.contains(secret_pw));
    assert!(!err.detail.contains(secret_data));
}

#[test]
fn error_taxonomy_is_reachable_via_public_api() {
    let c = ctx();
    let good = c.seal(&input(kind::TOKEN, None, None)).unwrap();

    // MALFORMED_ENVELOPE — not base64url.
    assert_eq!(
        c.open("not!base64!!", None, &NoFetch).unwrap_err().code,
        ErrorCode::MalformedEnvelope
    );

    // UNSUPPORTED_VERSION — bump the version byte.
    let mut bytes = envelope::b64::decode(&good).unwrap();
    bytes[0] = 0x02;
    assert_eq!(
        c.open(&envelope::b64::encode(&bytes), None, &NoFetch)
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedVersion
    );

    // EPOCH_RETIRED — point at the retired hole (epoch 1).
    let mut bytes = envelope::b64::decode(&good).unwrap();
    bytes[2] = 0x01;
    assert_eq!(
        c.open(&envelope::b64::encode(&bytes), None, &NoFetch)
            .unwrap_err()
            .code,
        ErrorCode::EpochRetired
    );

    // PAYLOAD_TOO_LARGE — seal over the v1 cap.
    let oversized = SealInput {
        data: vec![0u8; mosseal_core::MAX_PAYLOAD_BYTES + 1],
        ..input(kind::TOKEN, None, None)
    };
    assert_eq!(
        c.seal(&oversized).unwrap_err().code,
        ErrorCode::PayloadTooLarge
    );

    // BAD_PASSWORD — wrong password on a protected link.
    let pw = c.seal(&input(kind::TOKEN, None, Some("pw"))).unwrap();
    assert_eq!(
        c.open(&pw, Some(b"WRONG"), &NoFetch).unwrap_err().code,
        ErrorCode::BadPassword
    );

    // EXPIRED — past expiry with mocked net time.
    let expiring = c.seal(&input(kind::TOKEN, Some(500), None)).unwrap();
    assert_eq!(
        c.open(&expiring, None, &FixedFetch(1_000.0))
            .unwrap_err()
            .code,
        ErrorCode::Expired
    );

    // STRICT_TIME_UNAVAILABLE — strict mode with no reachable net time.
    let mut strict = ctx();
    strict.time_mode = TimeMode::Strict;
    let expiring = strict.seal(&input(kind::TOKEN, Some(2_000), None)).unwrap();
    assert_eq!(
        strict.open(&expiring, None, &NoFetch).unwrap_err().code,
        ErrorCode::StrictTimeUnavailable
    );

    // DOMAIN_MISMATCH — open on an unlisted host.
    let mut offhost = ctx();
    offhost.runtime_hostname = Some("evil.test".to_string());
    assert_eq!(
        offhost.open(&good, None, &NoFetch).unwrap_err().code,
        ErrorCode::DomainMismatch
    );

    // UNSUPPORTED_KIND — an unknown payload kind byte.
    let unknown = c.seal(&input(0x09, None, None)).unwrap();
    assert_eq!(
        c.open(&unknown, None, &NoFetch).unwrap_err().code,
        ErrorCode::UnsupportedKind
    );
}

#[test]
fn whitelist_reordering_does_not_brick_links() {
    // Spec 03: the binding string sorts the whitelist, so a `.env` reorder must
    // not invalidate existing links.
    let c = ctx();
    let frag = c.seal(&input(kind::TOKEN, None, None)).unwrap();

    let mut reordered = ctx();
    reordered.whitelist = vec!["b.test".to_string(), "a.test".to_string()];
    assert!(reordered.open(&frag, None, &NoFetch).is_ok());

    // And the canonical binding strings are byte-identical.
    assert_eq!(
        binding::binding_string(&["a.test".into(), "b.test".into()]),
        binding::binding_string(&["b.test".into(), "a.test".into()])
    );
}

/// Does `haystack` contain the `needle` byte sequence?
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}
