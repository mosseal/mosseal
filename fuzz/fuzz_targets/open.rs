#![no_main]
//! Fuzz target: `SealContext::open` (spec 08 § Fuzzing).
//!
//! Invariant: arbitrary fragment strings must never panic; the result is either
//! a clean open or a taxonomy error. Uses the sparse test registry (epoch 1
//! retired) so retirement paths are exercised too.

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

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let ctx = SealContext {
        epochs: EpochRegistry::from_slots(vec![Some([0x11; 32]), None, Some([0x33; 32])]),
        whitelist: vec!["a.test".to_string(), "b.test".to_string()],
        argon_profile: Argon2Profile::Minimum,
        time_mode: TimeMode::Lenient,
        runtime_hostname: None,
        // Empty = `time::DEFAULT_TIME_SOURCES`; the injected `NoFetch` never
        // reaches the network, so the expiry path stays deterministic.
        time_sources: Vec::new(),
    };
    // Password present so the Argon2 path is reachable, but only for inputs
    // that look like a fragment (avoid spending the whole budget on Argon2).
    let pw: Option<&[u8]> = if s.len() < 64 { Some(b"pw") } else { None };
    let _ = ctx.open(s, pw, &NoFetch);
});
