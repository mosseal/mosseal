//! `mosseal-vectors` — write or check the conformance vectors (spec 08).
//!
//! Usage:
//!   cargo run -p mosseal-vectors            # write vectors.json in this crate
//!   cargo run -p mosseal-vectors -- --check # diff vs checked-in; exit 1 on drift
//!   cargo run -p mosseal-vectors -- --stdout
//!
//! CI runs `--check` on native to catch accidental format drift in PRs.

use std::path::PathBuf;
use std::process::ExitCode;

fn vectors_path() -> PathBuf {
    // Co-located with the generator crate (spec 08).
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors.json")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let generated = mosseal_vectors::generate();
    let path = vectors_path();

    if args.iter().any(|a| a == "--stdout") {
        print!("{generated}");
        return ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--check") {
        match mosseal_vectors::check_file(&path, &generated) {
            Ok(()) => {
                println!("✔ vectors.json is up to date");
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!("✘ {reason}");
                ExitCode::FAILURE
            }
        }
    } else {
        match mosseal_vectors::write_file(&path, &generated) {
            Ok(()) => {
                println!("✔ wrote {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("✘ cannot write {}: {e}", path.display());
                ExitCode::FAILURE
            }
        }
    }
}
