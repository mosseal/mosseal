# Spec 02 — Crypto Core & WASM Workspace

## Goal

Core cryptography lives in platform-agnostic Rust (`mosseal-core`), exposed to WASM via
`mosseal-wasm` (compiled via wasm-pack) and to CLI/native tooling via `mosseal-cli`. All
cryptography lives in the Rust codebase; the TS wrapper never touches raw key material.

## Workspace layout

```
crates/
├── mosseal-core/         # Platform-agnostic crypto engine (lib rlib)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs        # Error taxonomy, re-exports
│   │   ├── envelope.rs   # Spec 01 binary format encode/decode
│   │   ├── kdf.rs        # Key derivation (HKDF path + Argon2id path)
│   │   ├── binding.rs    # Domain binding string construction & exact check
│   │   ├── epoch.rs      # Key-epoch registry parser & lookup
│   │   ├── time.rs       # Spec 07 time enforcement, parsing & fallback
│   │   └── seal.rs       # SealContext orchestrator (seal / open)
│   └── tests/
│       ├── fuzz_smoke.rs # Deterministic robustness corpus (stable toolchain)
│       └── seal_open.rs  # End-to-end seal→open integration
├── mosseal-wasm/         # wasm-bindgen cdylib/rlib surface
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs        # Mosseal struct, seal(), open(), register_time_fetcher()
│       └── secrets.rs    # Codegen slot: obfuse!(...) literals injected by CLI
└── mosseal-cli/          # Native admin CLI (seal, open, gen-secret)
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs        # Cli/Command, run(), context_from, seal/open helpers
    │   └── main.rs       # Thin binary shim over the library
    └── tests/
        └── cli.rs        # assert_cmd integration tests (real binary)
```

`mosseal-core` builds as an `rlib` so native Node tests, fuzzers, and the admin CLI can reuse
the exact same code — cross-target conformance falls out for free. `mosseal-wasm` builds as
`cdylib` and `rlib` for WebAssembly targets.

## Key derivation

### Default (no password) — HKDF-SHA256

```
ikm  = INTERNAL_SECRET            (obfuse!-encrypted literal from secrets.rs)
salt = envelope salt (16 B)
info = "mosseal/v1" || binding    (see spec 03)
key  = HKDF-SHA256(ikm, salt, info, 32)
```

The URL salt's *purpose* is per-link key compartmentalization (one leaked link/key analysis does
not weaken others) — it must be documented as such. It provides **no** confidentiality against
an attacker holding the binary, since the binary is public.

### Password mode — Argon2id (replaces HKDF entirely, not layered)

```
input = binding || 0x1F || INTERNAL_SECRET || 0x1F || password   (0x1F = unit separator)
salt  = envelope salt
key   = Argon2id(input, salt, m=19 MiB, t=2, p=1, len=32)
```

Rationale: password and internal secret are combined into one PBKDF input so password entropy
gates the offline attack; the internal secret alone is then insufficient. Binding in the input
preserves environment gating.

Parameters are **compile-time constants** (OWASP 2024 floor: 19 MiB, t=2, p=1). Tuning knob
`MOSSEAL_ARGON2_PROFILE` in the CLI selects `minimum` (19 MiB) or `interactive` (47 MiB, t=2).
Note: wasm runs Argon2 ~2–3× slower than native; attackers brute-force natively, so params are
tuned against *native* attack cost, and UX budget (target < 1 s in-browser derive) is validated
in the conformance suite.

Use RustCrypto `argon2` 0.6 crate with `hash_password_into` (raw, not the PHC-string API).

## Cipher

AES-256-GCM (RustCrypto `aes-gcm` 0.11), 12-byte nonce, 16-byte tag appended (default crate
behavior). AAD = the envelope header bytes `[version|flags|key_epoch|salt|nonce]` — binds
metadata into the tag so header tampering fails before payload parsing.

## Key epochs (rotation)

`key_epoch` byte selects among up to 256 compile-time secrets. The registry is
**sparse**: the epoch byte indexes a slot that may be a **hole** (a retired epoch).

The CLI builder generates `secrets.rs` containing obfuscated literals:
```rust
pub fn epochs_registry_str() -> String {
    obfuse!("secret0;;secret2").to_string()   // epoch 1 retired (empty entry)
}
```

- CLI generates a fresh `MOSSEAL_SECRET_<n+1>` on demand (`mosseal rotate`), keeping prior
  secrets in the list so old links still open during the grace window.
- Seal always uses the **highest active** epoch; open tries the envelope's epoch.
- **Retirement** = blanking a slot (an empty entry in the `;`-joined registry string, i.e.
  deleting that `MOSSEAL_SECRET_<n>` line from `.env`). A link sealed under a retired epoch
  fails with `EPOCH_RETIRED`; **every other epoch keeps its number and keeps opening**.
- Epoch indices are **positional and must never be renumbered**: renumbering the remaining
  secrets would silently re-key every surviving link. Holes are expected and preserved.
- This is the only revocation-adjacent story available in a stateless system: retiring an
  epoch invalidates all links sealed under it, independently of the others.

## Obfuscation of secrets

`obfuse` (compile-time AEAD string encryption with ChaCha20-Poly1305 and secure zeroize-on-drop)
for embedded secret strings and domain whitelist strings. Documented as a speed bump only.
Do **not** store secrets as plain byte arrays or static string slices (`strings` on the .wasm
would reveal them).

## Zeroization

- All key buffers, derived keys, plaintext payload buffers are wrapped in `zeroize::Zeroizing`.
- Sensitive intermediate buffers and obfuse-decrypted strings are wiped on drop.
- After `open()` returns the token to JS, the wasm linear memory page containing the plaintext
  is overwritten (best-effort scrub loop; document that wasm GC/linear memory cannot guarantee
  erasure — see 04 handoff notes).
- The TS wrapper is instructed to also zero its JS-side buffer after persisting to IndexedDB.

## Randomness

`rand` 0.10 with `getrandom` 0.4 (`wasm_js` feature enabled on wasm32-unknown-unknown targets).
For legacy / transitive dependencies pulling `getrandom` 0.2 in WASM builds, the `js` feature is
enabled via `getrandom = { version = "0.2", features = ["js"] }`. Salt is 16 B, nonce is 12 B.

## wasm-bindgen surface

```rust
#[wasm_bindgen]
pub struct Mosseal { /* ctx: SealContext */ }

#[wasm_bindgen]
impl Mosseal {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Mosseal, JsError>;

    #[wasm_bindgen]
    pub fn seal(
        &self,
        data: String,
        password: Option<String>,
        exp_secs: Option<f64>,
        kind: Option<u8>,
    ) -> Result<String, JsError>;

    #[wasm_bindgen]
    pub async fn open(
        &self,
        link: String,
        password: Option<String>,
    ) -> Result<JsValue, JsError>;
}

#[wasm_bindgen]
pub fn register_time_fetcher(fetch: js_sys::Function);
```

`JsError` messages are **stable, machine-readable codes** from the shared error taxonomy
(`spec 01` + below), not free-form prose.

| Code | Layer |
|---|---|
| `MALFORMED_ENVELOPE` | envelope decoding / base64 |
| `UNSUPPORTED_VERSION` | version mismatch |
| `UNSUPPORTED_KIND` | payload kind unknown to this build |
| `PAYLOAD_TOO_LARGE` | payload exceeds the `MAX_PAYLOAD_BYTES` cap (4096 B) |
| `DOMAIN_MISMATCH` | binding check |
| `BAD_PASSWORD` | GCM tag failure in password mode |
| `EXPIRED` | time check |
| `STRICT_TIME_UNAVAILABLE` | strict mode, net time unreachable |
| `EPOCH_RETIRED` | epoch byte not in registry |
| `WASM_INIT_FAILED` | wasm init / module load failure (spec 04) |

Panic hygiene: use `console_error_panic_hook` so a panic surfaces as a JS exception rather than
a silent trap.

## Release profile

```toml
[profile.release]
opt-level = "z"
lto = true
strip = true
codegen-units = 1
panic = "abort"
```
