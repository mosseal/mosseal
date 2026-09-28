# MOSSEAL — Overview & Threat Model

**MOSSEAL** = **M**ostly **O**bfuscated **S**tateless **S**ystem for **E**nd-to-End **A**uthenticated **L**inks.

A Rust→WASM + TypeScript library for sharing secret tokens / small app-state blobs through plain
URLs (including QR codes) on static hosts (GitHub Pages etc.), with no backend.

## Positioning (decided)

- **Default mode:** domain-bound obfuscated envelope (white-box cryptography). This is a *speed
  bump*, not mathematical secrecy. Anyone who reverses the wasm binary can decrypt password-less
  links offline.
- **Optional password mode:** Argon2id-derived key upgrade. With a password, confidentiality is
  real and proportional to password strength × Argon2 cost; the binary then contributes only
  environment binding.
- This is **not** a Zero-Knowledge Proof and must never be marketed as one. The transport medium
  (URL host, chat logs, server logs, link-preview bots) has "zero knowledge" of the payload —
  that is the extent of the claim.

## Scope (v1)

Library + CLI + tests. The core risk this project addresses is cross-target correctness —
native Rust, Node-wasm, and browser-wasm must produce and open identical links. A demo
application is not part of v1.

## What the system defends against

| Threat | Default (no password) | With password |
|---|---|---|
| Server logs / link-preview bots / chat scrapers | ✅ Strong (fragment never sent to server) | ✅ Strong |
| Casual copy-paste snooping | ✅ Strong | ✅ Strong |
| Reversed wasm binary + link | ❌ Fails (by design) | ✅ Holds (password unknown) |
| Offline password brute-force | n/a | ⚠️ Slowed by Argon2id only |
| DevTools inspection at time of token *use* | ❌ Out of scope | ❌ Out of scope |
| Link revocation / replay prevention | ❌ Bearer credential; expiry + key epoch are the only mitigations | same |

## Honest limitations (must appear in README)

1. Client-side secrets cannot be hidden from the client. All obfuscation raises cost, never to
   certainty.
2. In-wasm string obfuscation (`obfuse` AEAD string encryption) and wasm compilation are speed bumps
   against reverse engineering (wasm-decomp, Ghidra). Strings are reconstructible in memory.
3. The decrypted token is always observable when actually used (e.g. `Authorization` header in
   the Network tab).
4. Domain binding is bypassable by patching the wasm or proxying `window.location`.
5. Links are bearer credentials: no revocation, replay is inherent.
6. Expiry enforcement is client-side; see `07-time-enforcement.md` for the clock-spoofing
   analysis.

## Architecture summary

```
┌────────────┐   prebuild (consumer CI)    ┌───────────────────────────┐
│ .env       │──▶ mosseal CLI (Node) ─────▶│ wasm-pack build          │
│ secrets    │   validates env, codegens   │ generated secrets.rs      │
└────────────┘   obfuse! literals           └─────────────┬─────────────┘
                                                          │ mosseal-out/ (bundler target)
┌─────────────────────────────────────────────────────────▼─────────┐
│ Consumer static site                                              │
│  TS wrapper (@mosseal/core) ──▶ wasm: seal() / open()             │
│  URL: https://site.example/#ms=<base64url(envelope)>               │
└───────────────────────────────────────────────────────────────────┘
```

## Document map

| File | Component |
|---|---|
| `01-envelope-format.md` | URL fragment layout, binary payload schema, base64url encoding |
| `02-crypto-core.md` | Rust workspace: core crypto, AES-GCM, Argon2id, zeroization, key epochs |
| `03-domain-binding.md` | Hostname whitelist model and KDF binding string |
| `04-ts-wrapper.md` | TypeScript API surface, Node/browser loading, IndexedDB handoff |
| `05-cli-builder.md` | npm CLI: env validation, wasm-pack invocation, outputs |
| `06-packaging-ci.md` | npm package layout, consumer CI pipeline, GitHub Pages notes |
| `07-time-enforcement.md` | Expiry, multi-source HTTP time, strict/lenient modes |
| `08-testing-conformance.md` | Cross-target test vectors, CI matrix, fuzzing |
