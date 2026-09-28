//! Thin binary entry point. All logic lives in the `mosseal_cli` library so it
//! can be tested without spawning a process.

fn main() -> anyhow::Result<()> {
    mosseal_cli::run()
}
