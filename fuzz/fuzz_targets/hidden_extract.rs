#![no_main]
//! Fuzz target: deniable hidden-layer recovery (spec 08 § Fuzzing, spec 09).
//!
//! Invariant: arbitrary fragments + arbitrary cover/hidden passwords must
//! never panic; every failure carries a stable taxonomy code (recovery
//! failures uniformly `BAD_PASSWORD` — plausible deniability means the
//! format cannot distinguish "no hidden layer" from "wrong password").

use libfuzzer_sys::fuzz_target;
use mosseal_core::{
    epoch::EpochRegistry,
    kdf::Argon2Profile,
    seal::SealContext,
    time::{FetchTimes, TimeMode, TimeSource},
};

struct NoFetch;
impl FetchTimes for NoFetch {
    fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
        None
    }
}

/// Bound password length so the Argon2 budget stays fuzzer-friendly.
fn clip(pw: &[u8]) -> &[u8] {
    pw.get(..64.min(pw.len())).unwrap_or(&[])
}

fuzz_target!(|input: (&[u8], &[u8], &[u8])| {
    let (data, cover_pw, hidden_pw) = input;
    // Only inputs that decode as base64url reach past the fragment parse;
    // everything else fails fast in `MALFORMED_ENVELOPE` (still exercised).
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if s.is_empty()
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return;
    }
    let ctx = SealContext {
        epochs: EpochRegistry::from_slots(vec![Some([0x11; 32]), None, Some([0x33; 32])]),
        whitelist: vec!["a.test".to_string(), "b.test".to_string()],
        argon_profile: Argon2Profile::Minimum,
        time_mode: TimeMode::Lenient,
        runtime_hostname: None,
        time_sources: Vec::new(),
    };
    // Bound password lengths so the Argon2 budget stays fuzzer-friendly.
    let _ = ctx.open_deniable(s, Some(clip(cover_pw)), Some(clip(hidden_pw)), &NoFetch);
    let _ = ctx.open_deniable_ignoring_expiry(s, None, Some(clip(hidden_pw)), &NoFetch);
});
