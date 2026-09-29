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
│   ├── mosseal-admin-wasm/ # Admin wasm surface for the TS CLI (gen-secret/seal/open parity)
│   └── mosseal-cli/     # Native admin CLI for trusted token sealing, opening, secret generation
├── packages/
│   ├── mosseal/         # Node.js CLI builder (`mosseal init`, `build`, `rotate`, `doctor`)
│   └── core/            # TypeScript runtime wrapper (`@mosseal/core`), URL fragment parser, loader
└── specs/               # Normative technical specifications (00 through 08)
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
npm install -D @mosseal/cli
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


## Detailed Usage

This section walks through both supported surfaces end-to-end: the **TypeScript**
path (the `mosseal` CLI builder + `@mosseal/core` runtime wrapper) and the **Rust**
path (the native `mosseal` admin CLI + the `mosseal-core` library). Example outputs
are shown as they appear on a real run.

### TypeScript

#### 1. Scaffold and configure (once per site)

```bash
npm install -D @mosseal/cli
npm install @mosseal/core
npx mosseal init
```

`init` generates a fresh 32-byte base64url epoch secret and merges it into `.env`
non-destructively (existing keys are never overwritten):

```text
✔ wrote MOSSEAL_SECRET_0 to /home/you/site/.env
✔ .env is gitignored.

Next steps:
  1. Add your deployment hostnames to .env:
       MOSSEAL_ALLOWED_DOMAINS=your-site.github.io
  2. Optional:
       MOSSEAL_STRICT_TIME=false        # strict = fail open() without net time
       MOSSEAL_ARGON2_PROFILE=minimum   # or "interactive"
  3. Build the per-consumer wasm:
       mosseal build                    # emits ./mosseal-out/
  4. Add "prebuild": "mosseal build" to package.json scripts.
```

If `.env` is **not** gitignored, `init` refuses to stay quiet:

```text
⚠ DANGER: .env is NOT gitignored. Epoch secrets are the keys to every
  link your app seals. Add `.env` to .gitignore BEFORE committing.
  If it was ever committed, rotate ALL epochs and purge history.
```

Edit `.env` to add your hostnames, then verify the toolchain:

```bash
npx mosseal doctor
```

```text
✔ node >=20 — v22.12.0
✔ cargo — cargo 1.85.0 (7f08ace4f 2025-11-24)
✔ rustc — rustc 1.85.0 (4d91de4e4 2025-02-17)
✔ wasm-pack — wasm-pack 0.13.1
✔ wasm32-unknown-unknown target
```

Add `--network` to also probe time-source reachability (useful before enabling
`MOSSEAL_STRICT_TIME=true`):

```text
✔ network reachability (time sources) — reachable
```

#### 2. Build the per-consumer wasm

```bash
npx mosseal build
```

The CLI validates `.env`, generates an obfuscated `secrets.rs`, and runs
`wasm-pack build --target bundler` into `./mosseal-out/`:

```text
✔ env ok: 1 active epoch(s), 1 domain(s), argon=minimum, time=lenient
[INFO]: 🎯  Checking for the Wasm target...
[INFO]: 🌀  Compiling to Wasm...
[INFO]: ✨   Done in 42.3s
[INFO]: 📦   Your wasm pkg is ready to publish at /home/you/site/mosseal-out.
✔ build complete → /home/you/site/mosseal-out
```

Use `--dry-run` to validate without writing or compiling, and `--out-dir <dir>` to
change the output location:

```text
✔ env ok: 1 active epoch(s), 1 domain(s), argon=minimum, time=lenient
dry-run: validation passed, skipping wasm-pack build
```

Wire it into your bundler so it always runs first:

```jsonc
// package.json
{
  "scripts": {
    "prebuild": "mosseal build",
    "build": "vite build"
  }
}
```

#### 3. Seal and open links at runtime

```ts
import { Mosseal, MossealError, MossealErrorCode } from "@mosseal/core";
import wasmInit from "./mosseal-out/mosseal_wasm.js";

// One-time init (idempotent; concurrent calls coalesce).
const mosseal = await Mosseal.load(wasmInit);

// --- Sender: seal a token into a shareable URL ---
const shareUrl = mosseal.generateShareUrl({
  data: "ghp_PersonalAccessToken12345",
  password: "optional-user-password", // omit for the default (no-password) mode
  expSecs: 3600,                      // omit/0 = never expires (offline-capable)
  kind: "token",                      // or "binary_blob"
});
// → "https://your-site.github.io/#ms=AQG...<base64url envelope>"

// --- Receiver: open a link ---
if (mosseal.isMossealUrl(window.location.href)) {
  try {
    const { data, exp, kind } = await mosseal.openFromUrl(window.location.href, {
      password: "optional-user-password",
    });
    console.log("Decrypted token:", data); // "ghp_PersonalAccessToken12345"
    console.log("Expires at:", exp);       // 1759000000 (unix seconds), or 0
    console.log("Kind:", kind);            // "token"

    // Scrub the fragment from the address bar once you've persisted `data`.
    window.history.replaceState(
      {},
      document.title,
      mosseal.scrubFragmentFromUrl(window.location.href)
    );
  } catch (err) {
    if (err instanceof MossealError) {
      // Match on the stable code, never the message text.
      switch (err.code) {
        case MossealErrorCode.BadPassword:
          console.error("Wrong password — ask the sender to re-share.");
          break;
        case MossealErrorCode.Expired:
          console.error("This link has expired.");
          break;
        case MossealErrorCode.DomainMismatch:
          console.error("This link belongs to a different site.");
          break;
        default:
          console.error("Could not open link:", err.code);
      }
    }
  }
}
```

Alternatively, encode/decode bare fragment instead of a full URL:

```ts
const fragment = mosseal.sealFragment({ data: "ghp_...", expSecs: 900 });
// → "AQG...<base64url envelope>"  (the part after "#ms=")
const result = await mosseal.openFragment(fragment);
```

> **Size budget:** `generateShareUrl` warns when the final URL exceeds 512 bytes,
> because QR codes shrink quickly beyond that. The envelope itself allows payloads
> up to 4096 bytes (`MAX_PAYLOAD_BYTES`), but keep `data` small — around 255 bytes
> is the practical ceiling for a scannable QR code.

#### 4. Rotate keys

```bash
npx mosseal rotate
```

```text
✔ appended MOSSEAL_SECRET_1 (now sealing with epoch 1).

Rotation notes (spec 02 § Key epochs):
  • Links sealed under epochs 0..0 keep opening during the grace window.
  • The actual invalidation event is RETIRING an old epoch: delete its
    MOSSEAL_SECRET_<n> line from .env. open() then fails with EPOCH_RETIRED
    for links sealed under it, while every other epoch keeps opening.
  • Retiring an epoch leaves a HOLE in the list — that is expected. Do NOT
    renumber the remaining secrets: epoch indices are positional, so
    renumbering would silently re-key every surviving link.
  • After your grace period (e.g. 30 days), delete the oldest epoch line.
    You may retire epochs in any order; each hole is independent.
```

See [`docs/epoch-rotation.md`](docs/epoch-rotation.md) for the full runbook.

#### 5. Admin commands (seal / open / gen-secret)

The trusted admin surface of the native `mosseal-cli` binary is also available
through the TS CLI, so you can seal and open links without a Rust toolchain.
Sealing/opening runs a precompiled admin wasm shipped in `@mosseal/cli`;
`gen-secret` uses `node:crypto`.

```bash
SECRET=$(npx mosseal gen-secret)                 # fresh 32-byte base64url secret
FRAG=$(npx mosseal seal "ghp_..." \
  --epochs "$SECRET" --domains user.github.io)   # → "AQG...<fragment>"
npx mosseal open "$FRAG" \
  --epochs "$SECRET" --domains user.github.io
# → kind: 1
#   exp:  0
#   data: ghp_...
```

Password + expiry, and admin debugging of an expired link:

```bash
npx mosseal seal "ghp_..." --password hunter2 --exp 1759000000 \
  --epochs "$SECRET" --domains user.github.io

# --ignore-expiry skips ONLY the expiry check; domain, epoch, password, and
# the AEAD tag are still verified.
npx mosseal open "$FRAG" --epochs "$SECRET" --domains user.github.io --ignore-expiry
```

Epochs and domains fall back to `MOSSEAL_EPOCHS` / `MOSSEAL_ALLOWED_DOMAINS`,
then to the `.env` slots — the same config `init`/`rotate`/`build` use.

The admin commands are behaviourally interchangeable with the native
`mosseal-cli` binary: identical envelope bytes, identical stdout
(`kind`/`exp`/`data`), and identical errors — both emit
`Error: <CODE>: <detail>` (e.g. `Error: BAD_PASSWORD: gcm tag mismatch`) and
`exit 1`. A fragment sealed by either surface opens in the other.

### Rust

The Rust surface has two parts: the **native admin CLI** (`mosseal-cli`, binary
name `mosseal`) for trusted-machine sealing/opening, and the **`mosseal-core`
library** for embedding the crypto engine directly.

#### Native admin CLI

The CLI is the trusted admin path (spec 03): it skips the runtime hostname gate
and never blocks on network time. Epochs and domains come from flags or the
`MOSSEAL_EPOCHS` / `MOSSEAL_ALLOWED_DOMAINS` environment variables.

```bash
# Generate a fresh 32-byte base64url epoch secret.
cargo run -p mosseal-cli -- gen-secret
# → "kQ7...<43-char base64url>"

# Seal a token into a fragment (prompts for the token if omitted).
cargo run -p mosseal-cli -- seal "ghp_PersonalAccessToken12345" \
  --epochs "$MOSSEAL_EPOCHS" \
  --domains user.github.io
# → "AQG...<base64url envelope>"

# Seal with a password and a 1-hour expiry.
cargo run -p mosseal-cli -- seal "ghp_..." \
  --password "hunter2" --exp 1759000000 \
  --epochs "$MOSSEAL_EPOCHS" --domains user.github.io

# Open and verify a fragment.
cargo run -p mosseal-cli -- open "AQG...<fragment>" \
  --epochs "$MOSSEAL_EPOCHS" --domains user.github.io
```

`open` prints a three-line report:

```text
kind: 1
exp:  0
data: ghp_PersonalAccessToken12345
```

`kind` is the numeric payload kind (`1` = token, `2` = binary blob) and `exp` is
unix seconds (`0` = never expires). A wrong password or a tampered envelope exits
non-zero and prints the stable error code without leaking the token:

```text
Error: BAD_PASSWORD: gcm tag mismatch
```

For admin debugging of an expired link, `--ignore-expiry` skips **only** the
expiry check — domain binding, key epoch, password, and the AEAD tag are still
verified:

```bash
cargo run -p mosseal-cli -- open "AQG...<fragment>" \
  --epochs "$MOSSEAL_EPOCHS" --domains user.github.io --ignore-expiry
```

```text
kind: 1
exp:  1
data: ghp_...
```

#### `mosseal-core` library

Add the crate as a path (or workspace) dependency and drive `SealContext`
directly. The library is platform-agnostic — no wasm, no browser globals.

```toml
# Cargo.toml
[dependencies]
mosseal-core = { path = "crates/mosseal-core" }
```

```rust
use mosseal_core::{
    binding,
    epoch::EpochRegistry,
    envelope::kind,
    kdf::Argon2Profile,
    seal::{SealContext, SealInput},
    time::{FetchTimes, TimeMode, TimeSource},
};

/// No-op net-time fetcher: trusted callers never block on network time.
struct NoFetch;
impl FetchTimes for NoFetch {
    fn fetch_unix_secs(&self, _s: &[TimeSource]) -> Option<f64> {
        None
    }
}

fn main() -> anyhow::Result<()> {
    // 1. Build a deployment context: epoch registry + domain whitelist.
    let epochs = EpochRegistry::parse("kQ7...<base64url>;...")?;
    let whitelist = binding::parse_domain_list("user.github.io,example.com");
    binding::validate_whitelist(&whitelist)?;

    let ctx = SealContext {
        epochs,
        whitelist,
        argon_profile: Argon2Profile::Minimum,
        time_mode: TimeMode::Lenient,
        runtime_hostname: None, // trusted path: skip the runtime host gate
        time_sources: Vec::new(), // empty = spec 07 defaults
    };

    // 2. Seal a token (no password, no expiry).
    let fragment = ctx.seal(&SealInput {
        data: b"ghp_PersonalAccessToken12345".to_vec(),
        kind: kind::TOKEN,
        exp: None,
        password: None,
        deterministic_salt: None,
        deterministic_nonce: None,
        deterministic_epoch: None,
    })?;
    println!("{fragment}"); // → "AQG...<base64url envelope>"

    // 3. Open it back (verifies domain, epoch, password, and AEAD tag).
    let out = ctx.open(&fragment, None, &NoFetch)?;
    println!("kind: {}", out.kind); // 1
    println!("exp:  {}", out.exp);  // 0
    println!("data: {}", String::from_utf8_lossy(&out.data));
    // → "ghp_PersonalAccessToken12345"

    Ok(())
}
```

Errors carry a stable, machine-readable [`ErrorCode`] — match on it, never on the
human-readable `Display` prose:

```rust
use mosseal_core::ErrorCode;

match ctx.open(&fragment, Some(b"wrong"), &NoFetch) {
    Ok(out) => println!("opened: {}", String::from_utf8_lossy(&out.data)),
    Err(e) if e.code == ErrorCode::BadPassword => eprintln!("wrong password"),
    Err(e) if e.code == ErrorCode::Expired => eprintln!("link expired"),
    Err(e) => eprintln!("{}: {}", e.code.as_str(), e.detail),
}
```

The full taxonomy is `MALFORMED_ENVELOPE`, `UNSUPPORTED_VERSION`,
`UNSUPPORTED_KIND`, `PAYLOAD_TOO_LARGE`, `DOMAIN_MISMATCH`, `BAD_PASSWORD`,
`EXPIRED`, `STRICT_TIME_UNAVAILABLE`, `EPOCH_RETIRED`, and `WASM_INIT_FAILED`.

> **Deterministic sealing** (`deterministic_salt` / `deterministic_nonce` /
> `deterministic_epoch`) exists only for conformance vectors (spec 08). Leave them
> `None` in application code so every link gets fresh randomness.

## Packages

| Package | Purpose | Docs |
|---|---|---|
| `@mosseal/cli` (npm, devDep) | CLI builder: validates env, injects secrets, compiles the per-consumer wasm; also exposes the admin surface (`gen-secret`/`seal`/`open`) | [`packages/mosseal/README.md`](packages/mosseal/README.md) |
| `@mosseal/core` (npm) | Runtime TS wrapper: loads wasm, URL fragments, error taxonomy | [`packages/core/README.md`](packages/core/README.md) |
| `mosseal-core` (crate) | Platform-agnostic crypto engine | `specs/02-crypto-core.md` |
| `mosseal-wasm` (crate) | wasm-bindgen bindings | `specs/02-crypto-core.md` |
| `mosseal-cli` (crate) | Native admin CLI (`seal`/`open`/`gen-secret`) | `specs/02-crypto-core.md` |

**Deploying to CI?** See [`docs/development.md`](docs/development.md#ci--publishing), and the consumer
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
- [`docs/development.md`](docs/development.md) — Dependency policy, vendored-crate refresh, local checks, CI & publishing

