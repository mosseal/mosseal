//! Format-drift tripwire (spec 08 § CI): regenerate vectors in-memory and
//! diff against the checked-in `vectors.json`. A mismatch means the envelope
//! format or KDF changed without regenerating the vectors — fail loudly.

use std::path::PathBuf;

fn vectors_path() -> PathBuf {
    // Co-located with the generator crate (spec 08).
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors.json")
}

#[test]
fn checked_in_vectors_match_generator() {
    let path = vectors_path();
    let checked_in = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nRun `cargo run -p mosseal-vectors` to generate it.",
            path.display()
        )
    });
    let generated = mosseal_vectors::generate();
    assert_eq!(
        checked_in, generated,
        "vectors.json is stale — regenerate with `cargo run -p mosseal-vectors`"
    );
}
