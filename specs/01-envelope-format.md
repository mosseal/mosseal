# Spec 01 — Share-Link Envelope Format

## Goal

Define a compact, versioned, QR-friendly binary envelope carried entirely in the URL fragment.

## URL shape

```
https://<host>/<path>#ms=<base64url(envelope)>

Example:
https://user.github.io/app/#ms=AQGAAQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKiss
```

Rules:

- Everything after `#` is **never sent to the server** (browser guarantee) — GitHub Pages logs and
  link-preview bots see ciphertext only.
- Prefix `ms=` is required so consumers can detect MOSSEAL links among other hash usage
  (e.g. anchor navigation). The consuming app must tolerate other fragments.
- Exactly **one** fragment value; all envelope fields live inside the base64url blob (a split
  `?payload=&nonce=#salt` form would double URL size).
- No query parameters are ever used for envelope data.
- The fragment value is the base64url encoding of the **whole binary envelope** (see layout below).
  The format `version` byte is the first byte *inside* that binary envelope — it is **not** a
  separate character prefix on the fragment. (An earlier draft of this spec showed
  `#ms=<version-char>.<base64url(payload)>`; that split form was dropped because it duplicated the
  version information already carried in the binary layout and added a delimiter to parse.)

## Envelope binary layout (little-endian unless noted)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | envelope format version, `0x01` for this spec |
| 1 | 1 | `flags` | bit 0: password-protected; bit 1: expiry present; bits 2–7 reserved (must be 0) |
| 2 | 1 | `key_epoch` | key-epoch byte (see 02-crypto-core) |
| 3 | 1 | `salt_len` | always 16 in v1 |
| 4 | 16 | `salt` | random per-link (compartmentalizes links; NOT a secrecy input against binary holders) |
| 20 | 1 | `nonce_len` | always 12 in v1 |
| 21 | 12 | `nonce` | AES-GCM nonce |
| 33 | var | `ciphertext` | AES-256-GCM over the inner payload struct below (includes 16-byte tag) |

Base64url encoding (**no** padding `=` characters; URL-safe alphabet `-`/`_`) of the whole envelope.

Size budget: a 128-byte token + metadata ≈ 200 bytes binary ≈ 270 base64url chars — comfortably
under QR-code practical limits (~2 KB, and far under v40 max). The wrapper should warn if the
final URL exceeds 512 bytes (QR version shrinks quickly beyond that).

## Inner payload (what gets encrypted)

Versioned binary struct (serde-serialized with a compact format — `postcard` or manual
fixed-layout encode; JSON is rejected to save space):

| Field | Type | Notes |
|---|---|---|
| `kind` | u8 enum | `0x01 = token`, `0x02 = binary_blob` |
| `exp` | u64 seconds-or-0 | Unix epoch UTC; `0` = no expiry |
| `data_len` | u32 LE | byte length of `data` |
| `data` | `[u8; data_len]` | the secret material |

`exp` sits **inside** the AEAD-protected region, so it is tamper-proof (modifying it breaks the
GCM tag). Enforcement is separate — see 07.

## Versioning & compatibility

- Envelope `version` and payload `kind` are separate axes. Unknown `version` → wrapper error
  `UNSUPPORTED_VERSION` (forward incompatibility is intentional; bump version byte rather than
  adding flags).
- Reserved flag bits must be zero on seal; non-zero on open → error `MALFORMED_ENVELOPE`.

## Error taxonomy (envelope layer)

| Code | Meaning |
|---|---|
| `MALFORMED_ENVELOPE` | bad base64url, truncated, bad lengths, reserved bits set |
| `UNSUPPORTED_VERSION` | version byte > current |

> Over-long URLs are an **advisory warning** at seal time (spec 04 § URL layer), not an
> error code — the taxonomy deliberately has no `URL_TOO_LONG`.

## Open items (decided within this spec)

- The `data` length prefix is a **u32** (little-endian), so the wire format itself permits payloads
  up to `u32::MAX`. The seal API still enforces a practical `MAX_PAYLOAD_BYTES` cap (4096 bytes)
  and errors with `PAYLOAD_TOO_LARGE` beyond it, keeping links within URL/QR budgets. The URL
  layer additionally emits an **advisory** warning (not an error) once the final share URL exceeds
  512 bytes.
