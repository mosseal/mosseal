//! Robustness / fuzz-style smoke test (spec 08 § Fuzzing).
//!
//! The real `cargo fuzz` target lives behind nightly + `cargo-fuzz` (see
//! `fuzz/`). This deterministic, dependency-free test is the CI-friendly
//! companion: it throws a large, seeded corpus of mutated/hostile inputs at the
//! decode/open paths and asserts the two invariants spec 08 cares about:
//!
//! 1. **No panics** — malformed input must never abort.
//! 2. **Taxonomy only** — every failure carries one of the stable error codes.
//!
//! It is deliberately deterministic (a fixed xorshift PRNG) so a failure
//! reproduces exactly; the nightly fuzzer explores the same surface without
//! bounds.

use mosseal_core::{
    binding,
    envelope::{self, HEADER_LEN},
    epoch::EpochRegistry,
    kdf::Argon2Profile,
    seal::{SealContext, SealInput},
    time::{FetchTimes, TimeMode, TimeSource},
    ErrorCode,
};

/// Fixed test secrets (never the consumer's).
const SECRET_0: [u8; 32] = [0x11; 32];
const SECRET_2: [u8; 32] = [0x33; 32];

struct NoFetch;
impl FetchTimes for NoFetch {
    fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
        None
    }
}

fn ctx() -> SealContext {
    SealContext {
        // Sparse: epoch 1 retired.
        epochs: EpochRegistry::from_slots(vec![Some(SECRET_0), None, Some(SECRET_2)]),
        whitelist: vec!["a.test".to_string(), "b.test".to_string()],
        argon_profile: Argon2Profile::Minimum,
        time_mode: TimeMode::Lenient,
        runtime_hostname: None,
        time_sources: Vec::new(),
    }
}

/// Deterministic xorshift64 PRNG (no dev-dependency needed).
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n
    }
}

/// Every code the taxonomy defines — a failure must be exactly one of these.
fn is_known_code(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::MalformedEnvelope
            | ErrorCode::UnsupportedVersion
            | ErrorCode::UnsupportedKind
            | ErrorCode::PayloadTooLarge
            | ErrorCode::DomainMismatch
            | ErrorCode::BadPassword
            | ErrorCode::Expired
            | ErrorCode::StrictTimeUnavailable
            | ErrorCode::EpochRetired
            | ErrorCode::WasmInitFailed
    )
}

#[test]
fn decode_never_panics_on_arbitrary_bytes() {
    let mut rng = Rng(0xC0FFEE12_34567890);
    for _ in 0..20_000 {
        let len = rng.below(96);
        let mut bytes = vec![0u8; len];
        for b in bytes.iter_mut() {
            *b = rng.next_u8();
        }
        // decode must return Ok or a taxonomy error — never panic.
        if let Err(e) = envelope::decode(&bytes) {
            assert!(is_known_code(e.code), "unexpected code {:?}", e.code);
        }
    }
}

#[test]
fn decode_never_panics_on_mutated_valid_envelopes() {
    // Seed from a real envelope so mutations land on meaningful structure.
    let c = ctx();
    let valid = c
        .seal(&SealInput {
            data: b"tok_abc123".to_vec(),
            kind: envelope::kind::TOKEN,
            exp: Some(2_000_000_000),
            password: Some(b"hunter2".to_vec()),
            deterministic_salt: Some([0x01; 16]),
            deterministic_nonce: Some([0x02; 12]),
            deterministic_epoch: None,
        })
        .unwrap();
    let base = envelope::b64::decode(&valid).unwrap();

    let mut rng = Rng(0xDEAD_BEEF_0BAD_F00D);
    for _ in 0..20_000 {
        let mut bytes = base.clone();
        // Mutate 1..=4 random bytes.
        let n = 1 + rng.below(4);
        for _ in 0..n {
            if bytes.is_empty() {
                break;
            }
            let idx = rng.below(bytes.len());
            bytes[idx] = rng.next_u8();
        }
        // Occasionally truncate or extend.
        match rng.below(8) {
            0 if !bytes.is_empty() => {
                let cut = rng.below(bytes.len());
                bytes.truncate(cut);
            }
            1 => bytes.extend_from_slice(&[rng.next_u8(), rng.next_u8()]),
            _ => {}
        }
        if let Err(e) = envelope::decode(&bytes) {
            assert!(is_known_code(e.code), "unexpected code {:?}", e.code);
        }
    }
}

#[test]
fn open_never_panics_on_hostile_fragments() {
    let c = ctx();
    let fetcher = NoFetch;

    // Hand-picked hostile strings + random base64url-ish noise.
    let fixed = [
        "",
        "!",
        "=",
        "not!base64",
        "AAAA",
        "////",
        "\u{1F600}\u{1F4A9}",
        &"A".repeat(4096),
    ];
    for s in fixed {
        // Either opens or fails with a taxonomy code — never panics.
        if let Err(e) = c.open(s, None, &fetcher) {
            assert!(
                is_known_code(e.code),
                "unexpected code {:?} for {s:?}",
                e.code
            );
        }
    }

    // Random noise shaped like a fragment value.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut rng = Rng(0x5EED_5EED_5EED_5EED);
    for _ in 0..10_000 {
        let len = rng.below(160);
        let s: String = (0..len)
            .map(|_| ALPHABET[rng.below(ALPHABET.len())] as char)
            .collect();
        if let Err(e) = c.open(&s, Some(b"pw"), &fetcher) {
            assert!(is_known_code(e.code), "unexpected code {:?}", e.code);
        }
    }
}

#[test]
fn truncated_envelope_at_every_boundary() {
    let c = ctx();
    let valid = c
        .seal(&SealInput {
            data: b"tok".to_vec(),
            kind: envelope::kind::TOKEN,
            exp: None,
            password: None,
            deterministic_salt: Some([0x03; 16]),
            deterministic_nonce: Some([0x04; 12]),
            deterministic_epoch: None,
        })
        .unwrap();
    let bytes = envelope::b64::decode(&valid).unwrap();
    // Every prefix must fail cleanly (never panic); the full bytes decode.
    for cut in 0..bytes.len() {
        let frag = envelope::b64::encode(&bytes[..cut]);
        if let Err(e) = c.open(&frag, None, &NoFetch) {
            assert!(
                is_known_code(e.code),
                "unexpected code {:?} at cut {cut}",
                e.code
            );
        }
    }
    assert!(envelope::decode(&bytes).is_ok());
    assert!(bytes.len() > HEADER_LEN);
}

#[test]
fn whitelist_validation_never_panics() {
    // binding validation on arbitrary host lists must never panic.
    let inputs: Vec<Vec<String>> = vec![
        vec![],
        vec![String::new()],
        vec!["A.COM".to_string()],
        vec!["a.com".to_string(), "a.com".to_string()],
        vec!["\u{0}".to_string()],
        vec!["a".repeat(5000)],
        vec!["user.github.io".to_string(), "github.io".to_string()],
    ];
    for wl in inputs {
        // Ok or Err, but no panic.
        let _ = binding::validate_whitelist(&wl);
    }
}
