#![no_main]
//! Fuzz target: `envelope::decode` (spec 08 § Fuzzing).
//!
//! Invariant: arbitrary bytes must NEVER panic. Failures are limited to the
//! stable error taxonomy (`MALFORMED_ENVELOPE` / `UNSUPPORTED_VERSION`).
//!
//! Two passes per input:
//!  1. raw decode of the arbitrary bytes;
//!  2. decode of a valid v2 template mutated at fuzz-input-driven offsets —
//!     keeps the v1/v2 header surface (version byte, flags, lengths) under
//!     structured attack even when the raw pass never leaves junk space.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mosseal_core::envelope::decode(data);

    // Valid v2 envelope (fixed test secret, no password → HKDF, fast).
    let ctx = mosseal_core::seal::SealContext {
        epochs: mosseal_core::epoch::EpochRegistry::from_slots(vec![Some([0x11; 32])]),
        whitelist: vec!["a.test".to_string()],
        argon_profile: mosseal_core::kdf::Argon2Profile::Minimum,
        time_mode: mosseal_core::time::TimeMode::Lenient,
        runtime_hostname: None,
        time_sources: Vec::new(),
    };
    let input = mosseal_core::seal::SealInput {
        data: b"fuzz".to_vec(),
        kind: mosseal_core::envelope::kind::TOKEN,
        exp: None,
        password: None,
        deterministic_salt: Some([1; 16]),
        deterministic_nonce: Some([2; 12]),
        deterministic_epoch: None,
        deterministic_version: None,
    };
    if let Ok(frag) = ctx.seal(&input) {
        if let Ok(mut bytes) = mosseal_core::envelope::b64::decode(&frag) {
            // Mutate 0..=4 bytes at fuzz-driven wrapped offsets (header bytes
            // are tiny targets; wrapped indexing keeps every offset class in
            // play, including version/flags/lengths).
            for b in data.iter().take(4) {
                let idx = (*b as usize) % bytes.len();
                bytes[idx] ^= *b;
            }
            let _ = mosseal_core::envelope::decode(&bytes);
        }
    }
});
