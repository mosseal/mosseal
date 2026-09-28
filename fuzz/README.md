# MOSSEAL fuzz targets

Nightly-only [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) targets for the
decoder and open paths (spec 08 § Fuzzing).

| Target | Entry point | Invariant |
|---|---|---|
| `decode` | `envelope::decode` | arbitrary bytes never panic; only `MALFORMED_ENVELOPE` / `UNSUPPORTED_VERSION` |
| `open` | `SealContext::open` | arbitrary strings never panic; clean open or taxonomy error |

## Why this is a separate workspace

`cargo fuzz` needs a **nightly** toolchain (libFuzzer + sanitizers). This directory is
its own workspace root and is **excluded** from the root `Cargo.toml`, so the stable
`cargo test --workspace` / `clippy` jobs never try to build it.

## Stable-toolchain counterpart

`crates/mosseal-core/tests/fuzz_smoke.rs` runs a deterministic, seeded corpus (arbitrary
bytes, mutated valid envelopes, hostile fragments, every truncation boundary) on the
**stable** toolchain and asserts the same invariants. It runs in the `rust-native` CI job,
so the no-panic property is checked on every PR without nightly.

## Running

```bash
cd fuzz
cargo +nightly fuzz run decode -- -max_total_time=60
cargo +nightly fuzz run open   -- -max_total_time=60
```

A crash writes an artifact under `fuzz/artifacts/<target>/`; reproduce it with
`cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>`.

## Platform notes

- **CI runs this on Linux** (`.github/workflows/ci.yml` → `fuzz-smoke`). Never rely on
  Windows for the sanitizer build.
- **Windows caveat.** The targets compile and link fine on Windows nightly, but
  *execution* may fail with `STATUS_DLL_NOT_FOUND` (0xc0000135) or `STATUS_DLL_INIT_FAILED`
  (0xc0000142): `cargo-fuzz` needs an ASAN runtime (`clang_rt.asan_dynamic-*.dll`) matching
  the nightly toolchain's clang, and a VS2019/VS2022-bundled clang-12 runtime is usually
  incompatible. If you must run locally on Windows, install an LLVM/VS toolchain whose
  clang matches the nightly compiler, or use WSL.
- If sanitizers are unavailable, `--sanitizer none` is **not** a workaround here (libFuzzer
  still needs `__sancov` symbols that rustc only emits with the sanitizer flags). Use Linux
  or WSL instead.
