# Changelog

All notable changes to MOSSEAL are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the envelope-format caveat described in [`docs/versioning.md`](docs/versioning.md).

## [Unreleased]

### Added

- **`mosseal-core`** — platform-agnostic crypto engine (spec 02):
  - `envelope.rs` — spec 01 binary format, AAD = header prefix, base64url codec, u32 payload length prefix.
  - `binding.rs` — spec 03 sorted-whitelist binding string + exact-match runtime gate.
  - `epoch.rs` — spec 02 key-epoch registry with `EPOCH_RETIRED` semantics.
  - `kdf.rs` — HKDF-SHA256 default path, Argon2id password path (D10: replaces, not layers).
  - `time.rs` — spec 07 time sources/parsers, strict/lenient modes, cache, skew.
  - `seal.rs` — `SealContext::{seal, open}` orchestration and the full error taxonomy.
- **`mosseal-wasm`** — wasm-bindgen surface (`Mosseal::new/seal/open`,
  `register_time_fetcher` JS bridge) and the `secrets.rs` codegen slot.
- **`mosseal-cli`** (Rust) — `seal` / `open` / `gen-secret` trusted admin path.
- **`mosseal`** (npm CLI builder, spec 05) — `init`, `build`, `rotate`, `doctor`;
  compile-time secret injection via generated `obfuse!` literals; `--dry-run` planner.
- **`@mosseal/core`** (npm TS wrapper, spec 04) — `Mosseal.load()`, URL layer
  (`generateShareUrl`, `openFromUrl`, `isMossealUrl`, `scrubFragmentFromUrl`),
  `MossealError` mirroring the wasm taxonomy, and the JS time-fetcher bridge.
- **Conformance vectors** (spec 08) — `crates/mosseal-vectors` generates the checked-in
  `vectors.json`; `tests/drift.rs` is the format-drift tripwire; the Node suite
  reproduces seal/open byte-exactly against the real wasm.
- **Robustness / fuzz coverage** (spec 08) — `fuzz/` holds nightly `cargo fuzz` targets
  (`decode`, `open`); `crates/mosseal-core/tests/fuzz_smoke.rs` is the stable-toolchain
  deterministic counterpart (arbitrary bytes, mutated envelopes, hostile fragments,
  every truncation boundary → no panics, taxonomy-only errors).
- **URL/QR budget test** (spec 08) — QR-friendly payload (255 B + password) → URL ≤ 512 bytes
  and a `qrcode`/`jsqr` roundtrip that decodes back to the exact URL.
- **Browser suite** (spec 08, Playwright) — `packages/core/e2e/` drives the real wrapper
  against the real consumer-compiled wasm in Chromium: cross-host portability +
  `DOMAIN_MISMATCH` via `page.route`-fulfilled fake hosts (`a.test`/`b.test`/`c.test`),
  the strict/lenient net-time matrix (spec 07) via mocked time sources, and a network-tab
  assertion that no `#ms=` fragment ever appears in an outgoing request.
- **Argon2id timing assertion** (spec 08) — password mode must dominate HKDF and stay
  under the UX ceiling (see the timing note under *Changed*).
- **CI** (`.github/workflows/ci.yml`) — `rust-native` (fmt/clippy/test incl. `fuzz_smoke`/
  vectors drift on win+linux), `fuzz-smoke` (nightly `cargo fuzz`, Linux), `wasm-node`
  (conformance wasm + vitest + URL/QR budget + timing), `wasm-browser` (Playwright),
  `packages` (CLI unit tests + `npm pack --dry-run`), and `doctor-clean` (`mosseal doctor`
  + an end-to-end `init`/`build` from the packed tarball inside a `node:22-bookworm`
  container).
- **Supply-chain gate** (spec 06) — `deny.toml` (advisories, license allow-list, banned
  crates, crates.io-only sources) + a `supply-chain` CI job running `cargo deny` and
  `cargo machete` (the manual unused-dep audit is now enforced).
- **Coverage report** (spec 08) — a report-only `coverage` CI job uploads the
  `cargo llvm-cov` summary as an artifact. No hard floor yet (deliberate).
- **Browser `wasm-bindgen-test` leg** (spec 08) — the `wasm-test` job is now a
  node/chrome matrix, so browser-only paths (`web_sys::window` hostname detection) run
  where they actually execute.
- **Release automation** (spec 06) — `scripts/release.mjs` (`--check` / `--version X.Y.Z`)
  bumps all manifests in lockstep, regenerates `vectors.json`, and refreshes the vendored
  crate; a `release.yml` `workflow_dispatch` job wires it up. Publishing stays manual.
- **Package READMEs** — `packages/mosseal/README.md` (CLI usage, env vars,
  prerequisites, **consumer GitHub Actions snippet** with `rust-cache` +
  `jetli/wasm-pack-action`) and `packages/core/README.md` (wrapper API, error codes,
  notes). Both ship in the npm tarballs and render on the package pages.
- **Docs** — `docs/versioning.md` (semver + envelope-version policy) and
  `docs/epoch-rotation.md` (rotation runbook).
- **Full Rust test-coverage pass** — the workspace went from 45 to **100 tests**:
  `mosseal-cli` gained a `src/lib.rs` + thin bin and is now covered by 10 unit and
  8 `assert_cmd` integration tests; `mosseal-core` gained 26 unit + 9 end-to-end
  integration tests (incl. a golden-fragment lock, a no-leak assertion, and the
  full error taxonomy); `mosseal-vectors` gained an `UNSUPPORTED_KIND` vector,
  roundtrip re-open checks, and `--check`/`--stdout` coverage; `mosseal-wasm` gained
  `wasm-bindgen-test` coverage (new `wasm-test` CI job). Native coverage is
  **91.6% regions / 91.2% lines** (`cargo llvm-cov`).

### Fixed

- **CI `install-action` shorthand** — `taiki-e/install-action@<tool>` only resolves
  when a tag with that exact tool name exists, and `cargo-fuzz` is not in the action's
  supported-tools list, so the workflow failed with *"Missing required input `tool`"*.
  All three usages now use the documented `@v2` + `tool:` form (`cargo-fuzz` falls back
  to cargo-binstall/source; `cargo-deny`/`cargo-machete` install together).
- **`MOSSEAL_TIME_SOURCES` was a no-op** — the env var was validated by `mosseal build`
  but never consumed, so the wasm crates always used the three default time sources.
  It is now wired end-to-end: the builder bakes a third `secrets.rs` slot
  (`time_sources_str()`), `mosseal-core::time::parse_time_sources()` turns it into
  sources, `SealContext.time_sources` carries them, and the resolver uses them instead
  of `DEFAULT_TIME_SOURCES` when non-empty (spec 07). Covered by core unit tests and
  three new Playwright cases against a custom-source build.
- **wasm build** — activate `getrandom` `wasm_js`/`js` features and pass the required
  `wasm-opt` feature flags so `mosseal build` compiles the template end-to-end.
- **Error-code contract** — `js_err` now emits the stable machine-readable code
  (`BAD_PASSWORD`) instead of thiserror's `Display` prose.
- **wasm clock panic** — `SystemTime::now()` panics on `wasm32-unknown-unknown`; the wasm
  fetchers now use `js_sys::Date::now()` via `FetchTimes::system_now_secs()`.
- **Time-source loop** — a failed source now `continue`s instead of aborting the whole
  loop, so "first success wins across sources" (spec 07) actually holds.
- **Epoch list validation** — `mosseal build` rejects a malformed epoch list (a
  non-32-byte secret, an empty registry) instead of silently truncating. Note: this
  originally *rejected gaps* like `{0, 2}`, but that was superseded by the sparse
  registry (see *Changed*) — gaps are now preserved as retired holes.
- **Codegen escaping** — generated `secrets.rs` literals are escaped defensively.
- **`mosseal open --ignore-expiry` was a no-op** — the flag returned before
  enforcing (and before printing) anything, so expired links could never be opened
  for admin debugging. `SealContext::open_ignoring_expiry()` now skips only the
  expiry check; domain binding, key-epoch, password, and the AEAD tag are still
  fully verified.

### Changed

- **Envelope payload length prefix is now `u32`** (spec 01) — the inner payload's `data_len`
  field widened from `u8` to a little-endian `u32`, removing the old 255-byte ceiling. The
  seal API still enforces a practical `MAX_PAYLOAD_BYTES` cap (now **4096 bytes**) and errors
  with `PAYLOAD_TOO_LARGE` beyond it; the URL layer keeps its advisory 512-byte warning.
  **Breaking wire-format change** — the envelope `version` byte stays `0x01` (no package has
  been published yet), so links sealed by an older build will not open. `MAX_PAYLOAD_BYTES`
  is exported from `mosseal-core` for callers that need the current cap.
- **Argon2id timing assertion (spec 08)** — the original `≥ 250 ms` floor was
  unreachable: the `minimum` profile is the OWASP floor (19 MiB, t=2, p=1, decision D8),
  which measures ~30–60 ms in wasm. The assertion now checks the *relative* signal
  (Argon2 ≫ HKDF) plus the `< 1.5 s` UX ceiling, which is what actually catches a
  compiled-out Argon2.
- **Sparse key-epoch registry** — the epoch registry is now **sparse**: a
  retired epoch is a *hole* (an empty entry in the `;`-joined registry string),
  so links sealed under it fail with `EPOCH_RETIRED` while **every other epoch
  keeps its number and keeps opening**. Previously the registry was positional
  and contiguous-from-0, so retiring the oldest epoch either failed validation
  or silently re-keyed surviving links. `mosseal rotate` now appends past the
  highest slot and never renumbers; `mosseal build` reports active vs. retired
  epochs. See [`docs/epoch-rotation.md`](docs/epoch-rotation.md).
- **Toolchain** — JS/TS sources migrated to **TypeScript 7** built with **Vite 8**;
  lint via **oxlint**. Rust workspace MSRV is **1.85**.
- **Spec 01** — URL shape amended to `#ms=<base64url(envelope)>` (the format `version`
  byte lives inside the binary envelope; the earlier `#ms=<version-char>.<b64url>` draft
  was dropped).
- **`@mosseal/core` payload kind renamed** — the `0x02` kind is now `"binary_blob"`
  (was `"app_state"`), aligning the TS union with spec 01's canonical name. **Breaking
  for callers passing `kind: "app_state"`**; the wire byte (`0x02`) is unchanged, so
  existing links still open. The Rust constant is `kind::BINARY_BLOB`.
- **Strict-mode cross-source drift sanity** (spec 07 § optional v1.1) — strict mode now
  parses every reachable time source and rejects with `STRICT_TIME_UNAVAILABLE` when two
  disagree by more than 90 s, defending against a single spoofed source. Lenient mode is
  unchanged (first success wins). `FetchTimes` gained `fetch_all_unix_secs` (defaulted,
  so existing fetchers are unaffected).

### Added

- **`mosseal doctor --network`** — opt-in time-source reachability probe (spec 05). The
  default `doctor` run stays fast and air-gapped-CI-safe; `--network` adds a check that
  fails with a hint when the network is unreachable (strict-time builds would fail
  `open()`).

### Fixed

- **Doc drift** — corrected stale statements that contradicted shipped code:
  `MOSSEAL_TIME_SOURCES` is no longer described as "not yet wired" (spec 05), the URL
  shape in specs 00/09 is `#ms=<base64url(envelope)>` (not `#ms=1.<...>`), spec 08's CI
  table lists the `wasm-test` node+chrome matrix plus the `supply-chain`/`coverage` jobs,
  and spec 01 no longer calls the `0x02` kind "(future)".

[Unreleased]: https://github.com/codynhanpham/mosseal/commits/main
