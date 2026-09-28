# MOSSEAL

**M**ostly **O**bfuscated **S**tateless **S**ystem for **E**nd-to-End **A**uthenticated **L**inks.

A Rust→WASM + TypeScript library for sharing secret tokens or small app-state blobs through plain URLs (including QR codes) on static hosts (such as GitHub Pages), with zero server or backend requirement.

## Why?

This library is designed for quickly sharing low security or short-lived secrets (e.g. personal access tokens, ephemeral session keys, or small app-state blobs) through static links without requiring a backend server. Casual inspection of the secret is prevented by obfuscation and optional password-based encryption, while the link itself is a bearer credential that can be revoked by expiration or key rotation.

It is **not** a replacement for TLS, PKI, or any other cryptographic protocol. It is purely a convenience tool for sharing secrets in relatively low-risk scenarios.


## Threat Model & Security Guarantees

- **Default mode (no password):** Domain-bound obfuscated envelope (white-box cryptography). This is a **speed bump**, not mathematical secrecy. Anyone with access to the client wasm binary and the link can reverse the binary to extract the secret and decrypt offline.
- **Optional password mode:** Argon2id-derived key upgrade. With a password, confidentiality is real and proportional to password strength × Argon2 compute cost; the binary contributes environment binding and salt compartmentalization.
- **Not a Zero-Knowledge Proof:** MOSSEAL is not a zero-knowledge proof. The transport medium (URL host, static CDN, server access logs, link-preview crawlers) receives zero knowledge of the payload because the ciphertext resides exclusively in the URL fragment (`#ms=...`).

### Threat Matrix

| Threat | Default (no password) | With password |
|---|---|---|
| Server logs / link preview bots / chat scrapers | ✅ Strong (fragment never sent to server) | ✅ Strong |
| Casual copy-paste snooping | ✅ Strong | ✅ Strong |
| Reversed wasm binary + link | ❌ Fails (by design) | ✅ Holds (password unknown) |
| Offline password brute-force | N/A | ⚠️ Slowed by Argon2id cost parameters |
| DevTools inspection at time of token *use* | ❌ Out of scope | ❌ Out of scope |
| Link revocation / replay prevention | ❌ Bearer credential; expiry + key epoch rotation | ❌ Bearer credential; expiry + key epoch rotation |


## Limitations By Design

1. **Client-side secrets cannot be hidden from the client:** All obfuscation raises reverse-engineering cost, never to mathematical certainty.
2. **Obfuscation is a speed bump:** In-wasm string obfuscation (`obfuse` AEAD string encryption with ChaCha20-Poly1305) and WebAssembly compilation raise decompilation friction against tools like `wasm-decomp` or Ghidra, but strings and keys are reconstructible in memory.
3. **Decrypted tokens are observable at use:** Once unpacked in the browser, tokens used in outgoing HTTP headers (e.g. `Authorization`) or DOM nodes are visible in DevTools.
4. **Domain binding is client-enforced:** Domain binding gates execution against `window.location.hostname` in browser builds and binds the sorted whitelist into KDF derivation. However, runtime checks in the browser can be bypassed by patching WebAssembly or tampering with browser globals.
5. **Links are bearer credentials:** There is no centralized database or revocation authority. Key epoch rotation and payload expiration are the only revocation-adjacent mechanisms.
6. **Expiry enforcement:** Expiring links query multi-source CORS-compatible internet time (Cloudflare trace, TimeAPI, WorldTimeAPI) to prevent system clock manipulation. If network time is unavailable, lenient mode falls back to local clock while strict mode refuses to decrypt.


## Architecture & Components

```
mosseal/
├── crates/
│   ├── mosseal-core/    # Platform-agnostic crypto engine (AES-256-GCM, HKDF, Argon2id, envelope format)
│   ├── mosseal-wasm/    # wasm-bindgen bindings, obfuse! secrets.rs slot, JS time bridge
│   └── mosseal-cli/     # Native admin CLI for trusted token sealing, opening, secret generation
├── packages/
│   ├── mosseal/         # Node.js CLI builder (`mosseal init`, `build`, `rotate`, `doctor`)
│   └── core/            # TypeScript runtime wrapper (`@mosseal/core`), URL fragment parser, loader
└── specs/               # Normative technical specifications (00 through 09)
```

### Build & Distribution Flow

1. **`mosseal init`**: Generates a cryptographically strong 32-byte base64url secret (`MOSSEAL_SECRET_0`) and scaffolds `.env`.
2. **`mosseal build`**:
   - Pre-validates environment variables (epoch secrets present and 32 bytes, holes
     allowed for retired epochs, domain whitelist syntax, argon parameters).
   - Generates `secrets.rs` with `obfuse!(...)` encrypted literals into a temporary build of the template.
   - Spawns `wasm-pack build --target bundler` emitting artifacts to `mosseal-out/`.
   - Generates `meta.json` build provenance metadata (without secrets).
3. **`@mosseal/core`**: Loads the compiled WebAssembly bundle in browser (Vite, webpack) or Node.js environments and exposes ergonomic `generateShareUrl()` and `openFromUrl()` APIs.


## Quick Start

### 1. Install & Initialize (Developer / Site Owner)

```bash
# In your static site repository
npm install -D mosseal
npm install @mosseal/core

# Initialize environment configuration (.env)
npx mosseal init
```

Configure your `.env`:
```env
MOSSEAL_SECRET_0="<generated-base64url-32-byte-secret>"
MOSSEAL_ALLOWED_DOMAINS="user.github.io,example.com"
MOSSEAL_ARGON2_PROFILE="minimum"
MOSSEAL_STRICT_TIME="false"
```

Ensure `.env` and `mosseal-out/` are added to your `.gitignore`.

### 2. Build WASM Module

```bash
# Add to package.json scripts: "prebuild": "mosseal build"
npx mosseal build
```

### 3. Application Usage

```ts
import { Mosseal } from "@mosseal/core";
import wasmInit from "./mosseal-out/mosseal_wasm.js";

// Initialize wasm once
const mosseal = await Mosseal.load(wasmInit);

// Seal a link (e.g. for sharing)
const shareUrl = await mosseal.generateShareUrl({
  data: "ghp_PersonalAccessToken12345",
  password: "optional-user-password",
  expSecs: 3600, // expires in 1 hour
  kind: "token"
});

// Open a link on reception
if (mosseal.isMossealUrl(window.location.href)) {
  try {
    const result = await mosseal.openFromUrl(window.location.href, {
      password: "optional-user-password"
    });
    console.log("Decrypted token:", result.data);

    // Clean fragment from address bar
    window.history.replaceState({}, document.title, mosseal.scrubFragmentFromUrl(window.location.href));
  } catch (err) {
    console.error("Failed to open link:", err.code);
  }
}
```


## Packages

| Package | Purpose | Docs |
|---|---|---|
| `mosseal` (npm, devDep) | CLI builder: validates env, injects secrets, compiles the per-consumer wasm | [`packages/mosseal/README.md`](packages/mosseal/README.md) |
| `@mosseal/core` (npm) | Runtime TS wrapper: loads wasm, URL fragments, error taxonomy | [`packages/core/README.md`](packages/core/README.md) |
| `mosseal-core` (crate) | Platform-agnostic crypto engine | `specs/02-crypto-core.md` |
| `mosseal-wasm` (crate) | wasm-bindgen bindings | `specs/02-crypto-core.md` |
| `mosseal-cli` (crate) | Native admin CLI (`seal`/`open`/`gen-secret`) | `specs/02-crypto-core.md` |

**Deploying to CI?** See [CI & Publishing](#ci--publishing) below, and the consumer
GitHub Actions snippet in
[`packages/mosseal/README.md`](packages/mosseal/README.md#consumer-ci-github-actions)
(Rust toolchain + `rust-cache` + `jetli/wasm-pack-action`, secrets via env vars).


## Development & Testing

- **Rust Workspace**:
  ```bash
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  cargo fmt --all --check
  cargo run -p mosseal-vectors -- --check   # conformance-vector drift tripwire
  ```
- **Rust coverage** (report-only; no gate):
  ```bash
  rustup component add llvm-tools-preview   # once
  cargo install cargo-llvm-cov --locked     # once
  cargo llvm-cov --workspace --summary-only
  ```
  Native coverage is ~91% regions / ~91% lines. The `mosseal-wasm` crate shows 0%
  natively by construction (wasm-bindgen code is not host-instrumentable) and is
  covered instead by `wasm-pack test --node` plus the Node/browser suites.
- **Prerequisites**:
  - Rust $\ge 1.85$ (Edition 2021)
  - `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
  - `wasm-pack`: `cargo install wasm-pack`
  - Node.js $\ge 20.19$ (or $\ge 22.12$) — required by the Vite 8 toolchain
- **JS/TS packages**:
  ```bash
  # core (@mosseal/core) — Vite 8 library build + tsc declarations (TypeScript 7)
  cd packages/core     && npm install && npm run typecheck && npm run lint && npm run build && npm test
  # CLI (mosseal) — Vite 8 SSR build into dist/mosseal.js
  cd packages/mosseal  && npm install && npm run typecheck && npm run lint && npm run build
  ```
  The toolchain is **TypeScript 7** + **Vite 8** + **oxlint**.
  Note: TypeScript 7 is the native Go port and ships **no** JavaScript compiler API, so
  `typescript-eslint` and `vite-plugin-dts` are not usable with it — lint runs on `oxlint`
  and declarations are emitted by `tsc --emitDeclarationOnly`.
- **Browser suite** (Playwright, spec 08):
  ```bash
  cd packages/core
  npx playwright install chromium   # once
  npm run test:e2e                  # builds the web wasm fixtures + harness, runs Chromium
  ```
  Drives the real wrapper against the real consumer-compiled wasm; cross-host portability
  and net time are faked with `page.route` (no DNS/TLS needed).
- **Wasm unit tests** (wasm-bindgen, spec 08):
  ```bash
  wasm-pack test --node crates/mosseal-wasm
  ```
  Covers the wasm-only surface (generated-secrets parse, the `JsError` machine-code
  contract, placeholder init failure).


## CI & Publishing

### Repository CI (`.github/workflows/ci.yml`)

Runs on every push to `main` and every pull request. Nine jobs:

| Job | Runner | What it guards |
|---|---|---|
| `rust-native` | ubuntu + windows | `cargo fmt --check`, strict `clippy`, `cargo test --workspace` (incl. the deterministic `fuzz_smoke` suite), and the `vectors.json` drift tripwire. |
| `fuzz-smoke` | ubuntu (nightly) | 60 s each on the `decode` / `open` `cargo fuzz` targets. |
| `supply-chain` | ubuntu | `cargo deny` (advisories, license allow-list, banned crates, crates.io-only sources) + `cargo machete` (no unused direct deps). |
| `coverage` | ubuntu | `cargo llvm-cov` summary uploaded as an artifact. **Report-only** — no floor yet. |
| `wasm-test` | ubuntu (node + chrome) | `wasm-pack test` for the wasm-only surface; the Chromium leg exercises `web_sys::window` hostname detection. |
| `wasm-node` | ubuntu | Builds the conformance wasm and runs the byte-exact vector suite + URL/QR budget + Argon2 timing. |
| `wasm-browser` | ubuntu (chromium) | Playwright: cross-host portability, `DOMAIN_MISMATCH`, strict/lenient net-time matrix, custom `MOSSEAL_TIME_SOURCES`, no-fragment-leak assertion. |
| `packages` | ubuntu | Builds both npm packages, runs the CLI unit tests, and verifies `npm pack --dry-run` contents. |
| `doctor-clean` | ubuntu (`node:22-bookworm`) | `mosseal doctor` + an end-to-end `init`/`build` from the **packed tarball** in a clean container. |

Run the same checks locally before pushing:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p mosseal-vectors -- --check
cargo deny --all-features check && cargo machete   # needs cargo-deny / cargo-machete
```

### Releasing (`.github/workflows/release.yml` + `scripts/release.mjs`)

The release checklist is scripted so the lockstep manifest bump, the regenerated
`vectors.json`, and the refreshed vendored crate cannot be skipped. Publishing itself
stays manual (npm token, CHANGELOG entry, etc.).

```bash
# Verify every manifest agrees on one version (also run in CI):
node scripts/release.mjs --check

# Bump + regenerate (preview first with --dry-run):
node scripts/release.mjs --version 0.2.0
```

`--version` updates the workspace `Cargo.toml`, both `package.json` files, and the
template `Cargo.toml` (+ its vendored `mosseal-core-<ver>` path) in lockstep, then
regenerates `vectors.json` and re-packages the vendored crate.

The `release` workflow (`workflow_dispatch`) runs the consistency check and, in `bump`
mode, executes the script and uploads the resulting diff as an artifact.

**Release steps:**

1. Add a `CHANGELOG.md` entry under the new version heading. *(manual)*
2. Run `node scripts/release.mjs --version <X.Y.Z>` (or the `release` workflow in `bump` mode).
3. If the envelope layout changed, bump the `version` byte in `mosseal-core` and update spec 01. *(manual)*
4. Review the regenerated `vectors.json` + vendored crate diff.
5. Commit, tag `v<X.Y.Z>`, and publish both npm packages:
   ```bash
   (cd packages/core    && npm publish)
   (cd packages/mosseal && npm publish)
   ```

See [`docs/versioning.md`](docs/versioning.md) for the full semver + envelope-version policy.

### Deploying a consumer site

Compile-time injection means the Rust toolchain runs in **your** CI. The canonical
GitHub Actions snippet (Rust toolchain + `Swatinem/rust-cache` +
`jetli/wasm-pack-action`, secrets via env vars, `mosseal doctor` for fast failure) lives
in [`packages/mosseal/README.md`](packages/mosseal/README.md#consumer-ci-github-actions).

> **Windows runners:** always use `jetli/wasm-pack-action` (or `npx wasm-pack`), never
> `curl … | sh`.


## Specifications

Detailed technical specifications can be found under `specs/`:
- `00-overview-threat-model.md` — Security positioning, threat matrix, honest limitations
- `01-envelope-format.md` — Binary header structure, base64url encoding, AAD
- `02-crypto-core.md` — Crypto primitives (HKDF, Argon2id, AES-256-GCM, zeroization)
- `03-domain-binding.md` — Whitelist binding and runtime hostname gate
- `04-ts-wrapper.md` — TypeScript client wrapper `@mosseal/core`
- `05-cli-builder.md` — CLI builder `mosseal`
- `06-packaging-ci.md` — Packaging layout, CI pipeline, static hosting
- `07-time-enforcement.md` — Multi-source internet time, clock skew tolerance
- `08-testing-conformance.md` — Test vectors, fuzzing, cross-runtime tests

Operational docs live under `docs/`:
- [`docs/versioning.md`](docs/versioning.md) — Semver policy and the envelope-`version` byte
- [`docs/epoch-rotation.md`](docs/epoch-rotation.md) — Key-epoch rotation & retirement runbook
- [`docs/development.md`](docs/development.md) — Dependency policy, vendored-crate refresh, local checks

