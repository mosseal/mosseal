#![no_main]
//! Fuzz target: `envelope::decode` (spec 08 § Fuzzing).
//!
//! Invariant: arbitrary bytes must NEVER panic. Failures are limited to the
//! stable error taxonomy (`MALFORMED_ENVELOPE` / `UNSUPPORTED_VERSION`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mosseal_core::envelope::decode(data);
});
