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
    seal::{
        CoverDecoy, CoverMode, DeniableSealInput, HiddenSpec, MultiSealInput, MultiSlot,
        SealContext, SealInput, SizeClass,
    },
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
            | ErrorCode::TooManySlots
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
            deterministic_version: None,
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
            deterministic_version: None,
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

// --- v2 additions: MULTI blobs + deniable covers (spec 08 § Fuzzing) ---
//
// Argon2id costs ~30–60 ms per derive, so open-path mutation counts here are
// budgeted (tens, not tens of thousands); the decode-level multi-blob pass
// stays cheap and high-volume.

fn multi_fragment(c: &SealContext) -> String {
    c.seal_multi(&MultiSealInput {
        slots: vec![
            MultiSlot {
                password: b"fuzz-pw-one".to_vec(),
                data: b"fuzz_one".to_vec(),
                kind: envelope::kind::TOKEN,
                exp: None,
            },
            MultiSlot {
                password: b"fuzz-pw-two".to_vec(),
                data: b"fuzz_two".to_vec(),
                kind: envelope::kind::BINARY_BLOB,
                exp: None,
            },
        ],
        deterministic_slot_salts: Some(vec![[0x51; 16], [0x52; 16]]),
        deterministic_slot_nonces: Some(vec![[0x61; 12], [0x62; 12]]),
        deterministic_salt: Some([0x71; 16]),
        deterministic_nonce: Some([0x72; 12]),
        deterministic_epoch: None,
    })
    .unwrap()
}

/// Decrypt a password-less outer envelope directly (HKDF — no Argon2) and
/// return its payload. Test-only recovery of raw blob/cover bytes.
fn outer_payload(c: &SealContext, frag: &str) -> envelope::Payload {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload as GcmPayload},
        Aes256Gcm,
    };
    let env = envelope::decode(&envelope::b64::decode(frag).unwrap()).unwrap();
    let b = binding::binding_string(&c.whitelist);
    let key =
        mosseal_core::kdf::derive_hkdf(c.epochs.secret(env.key_epoch).unwrap(), &env.salt, &b);
    let cipher = Aes256Gcm::new((&key.0).into());
    let pt = cipher
        .decrypt(
            &env.nonce.into(),
            GcmPayload {
                msg: env.ciphertext.as_ref(),
                aad: &env.aad(),
            },
        )
        .unwrap();
    envelope::Payload::decode(&pt[envelope::key_commit::LEN..]).unwrap()
}

#[test]
fn multi_blob_decode_never_panics_on_arbitrary_bytes() {
    let mut rng = Rng(0x0A11_CEB0_B5EE_D5ED);
    for _ in 0..20_000 {
        let len = rng.below(256);
        let mut bytes = vec![0u8; len];
        for b in bytes.iter_mut() {
            *b = rng.next_u8();
        }
        if let Err(e) = envelope::multi::MultiBlob::decode(&bytes) {
            assert!(is_known_code(e.code), "unexpected code {:?}", e.code);
        }
    }
}

#[test]
fn multi_blob_decode_never_panics_on_mutations() {
    let c = ctx();
    let frag = multi_fragment(&c);
    // Recover the raw multi blob via a direct outer decrypt (no Argon2).
    let payload = outer_payload(&c, &frag);
    assert_eq!(payload.kind, envelope::kind::MULTI);

    let mut rng = Rng(0xB0BC_A75E_EDF0_0D11);
    for _ in 0..20_000 {
        let mut bytes = payload.data.clone();
        let n = 1 + rng.below(4);
        for _ in 0..n {
            if bytes.is_empty() {
                break;
            }
            let idx = rng.below(bytes.len());
            bytes[idx] = rng.next_u8();
        }
        match rng.below(8) {
            0 if !bytes.is_empty() => bytes.truncate(rng.below(bytes.len())),
            1 => bytes.extend_from_slice(&[rng.next_u8(), rng.next_u8()]),
            _ => {}
        }
        if let Err(e) = envelope::multi::MultiBlob::decode(&bytes) {
            assert!(is_known_code(e.code), "unexpected code {:?}", e.code);
        }
    }
}

#[test]
fn multi_open_never_panics_on_mutated_fragments() {
    let c = ctx();
    let frag = multi_fragment(&c);
    let base = envelope::b64::decode(&frag).unwrap();

    let mut rng = Rng(0xCAFE_F00D_DEAD_BEEF);
    for i in 0..12 {
        let mut bytes = base.clone();
        let n = 1 + rng.below(4);
        for _ in 0..n {
            let idx = rng.below(bytes.len());
            bytes[idx] = rng.next_u8();
        }
        let mutated = envelope::b64::encode(&bytes);
        // Rotate passwords so both slots' Argon2 paths get exercised.
        let pw = if i % 2 == 0 {
            &b"fuzz-pw-one"[..]
        } else {
            &b"fuzz-pw-two"[..]
        };
        if let Err(e) = c.open(&mutated, Some(pw), &NoFetch) {
            assert!(is_known_code(e.code), "unexpected code {:?}", e.code);
        }
    }
}

fn deniable_fragment(c: &SealContext) -> String {
    c.seal_deniable(&DeniableSealInput {
        cover_mode: CoverMode::Plain,
        cover_password: None,
        cover_decoy: CoverDecoy::Random,
        hidden_password: b"fuzz-hidden-pw".to_vec(),
        hidden: HiddenSpec::Single {
            data: b"fuzz_hidden".to_vec(),
            kind: envelope::kind::TOKEN,
            exp: None,
            deterministic_salt: Some([0x81; 16]),
            deterministic_nonce: Some([0x82; 12]),
            deterministic_epoch: None,
        },
        size_class: Some(SizeClass::Kib1),
        deterministic_salt: Some([0x91; 16]),
        deterministic_nonce: Some([0x92; 12]),
        deterministic_padding: Some([0x93; 32]),
        deterministic_epoch: None,
    })
    .unwrap()
}

#[test]
fn deniable_open_never_panics_on_mutated_fragments() {
    let c = ctx();
    let frag = deniable_fragment(&c);
    let base = envelope::b64::decode(&frag).unwrap();
    assert_eq!(base.len(), SizeClass::Kib1.total_bytes());

    let mut rng = Rng(0xDEAD_5EED_C0FF_EE01);
    for _ in 0..10 {
        let mut bytes = base.clone();
        let n = 1 + rng.below(4);
        for _ in 0..n {
            let idx = rng.below(bytes.len());
            bytes[idx] = rng.next_u8();
        }
        let mutated = envelope::b64::encode(&bytes);
        if let Err(e) = c.open_deniable(&mutated, None, Some(b"fuzz-hidden-pw"), &NoFetch) {
            assert!(is_known_code(e.code), "unexpected code {:?}", e.code);
        }
    }
}

/// Hostile masked-length values in the cover layout: recovery must fail with
/// a taxonomy code, never panic or read out of bounds (spec 09 § recovery).
#[test]
fn deniable_hostile_masked_lengths_fail_closed() {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload as GcmPayload},
        Aes256Gcm,
    };
    let c = ctx();
    let frag = deniable_fragment(&c);
    let env = envelope::decode(&envelope::b64::decode(&frag).unwrap()).unwrap();

    // Recover the cover plaintext (password-less cover → HKDF, cheap).
    let b = binding::binding_string(&c.whitelist);
    let key =
        mosseal_core::kdf::derive_hkdf(c.epochs.secret(env.key_epoch).unwrap(), &env.salt, &b);
    let cipher = Aes256Gcm::new((&key.0).into());
    let pt = cipher
        .decrypt(
            &env.nonce.into(),
            GcmPayload {
                msg: env.ciphertext.as_ref(),
                aad: &env.aad(),
            },
        )
        .unwrap();
    let payload = envelope::Payload::decode(&pt[envelope::key_commit::LEN..]).unwrap();

    // Hostile masked_len values: 0, 1, 49 (below floor), huge (u32::MAX),
    // exactly data_len, data_len - 4.
    let data_len = payload.data.len();
    for hostile in [
        0u32,
        1,
        49,
        63,
        u32::MAX,
        data_len as u32,
        (data_len - 4) as u32,
    ] {
        let mut data = payload.data.clone();
        data[0..4].copy_from_slice(&hostile.to_le_bytes());
        let mut new_pt = Vec::new();
        new_pt.extend_from_slice(&envelope::key_commit::build(&key.0));
        new_pt.extend_from_slice(
            &envelope::Payload {
                kind: payload.kind,
                exp: payload.exp,
                data,
            }
            .encode()
            .unwrap(),
        );
        let mut new_env = env.clone();
        new_env.ciphertext = cipher
            .encrypt(
                &env.nonce.into(),
                GcmPayload {
                    msg: &new_pt,
                    aad: &env.aad(),
                },
            )
            .unwrap();
        let hostile_frag = envelope::b64::encode(&envelope::encode(&new_env));
        let err = c
            .open_deniable(&hostile_frag, None, Some(b"fuzz-hidden-pw"), &NoFetch)
            .unwrap_err();
        assert!(
            is_known_code(err.code),
            "unexpected code {:?} for masked_len {hostile}",
            err.code
        );
    }
}
