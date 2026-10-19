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
| 0 | 1 | `version` | envelope format version: `0x01` (v1), `0x02` (v2) |
| 1 | 1 | `flags` | bit 0: password-protected; bit 1: expiry present; bits 2–7 reserved (must be 0) |
| 2 | 1 | `key_epoch` | key-epoch byte (see 02-crypto-core) |
| 3 | 1 | `salt_len` | always 16 |
| 4 | 16 | `salt` | random per-link (compartmentalizes links; NOT a secrecy input against binary holders) |
| 20 | 1 | `nonce_len` | always 12 |
| 21 | 12 | `nonce` | AES-GCM nonce |
| 33 | var | `ciphertext` | AES-256-GCM over the inner plaintext below (includes 16-byte tag) |

Base64url encoding (**no** padding `=` characters; URL-safe alphabet `-`/`_`) of the whole envelope.

Size budget: a 128-byte token + metadata ≈ 200 bytes binary ≈ 270 base64url chars — comfortably
under QR-code practical limits (~2 KB, and far under v40 max). The wrapper should warn if the
final URL exceeds 512 bytes (QR version shrinks quickly beyond that). **Deniable links are
exempt** from the advisory: they are padded to fixed size classes by design (spec 09).

## Inner plaintext (what gets encrypted)

The AEAD plaintext is **version-dependent**:

| Version | Plaintext |
|---|---|
| v1 | `payload` (the struct below) |
| v2 | `key_commit(16) ‖ payload` |

### Key commitment (v2 only)

```
key_commit = SHA-256("mosseal/v2" || key)[0..16]
```

`key` is the derived 32-byte AEAD key. Open verifies the prefix **immediately after** AEAD
decryption and **before** payload parsing; a mismatch takes the same error path as a GCM tag
failure (`BAD_PASSWORD` in password mode, `MALFORMED_ENVELOPE` otherwise). This closes the
AES-GCM partitioning/forgery hole where a crafted ciphertext could decrypt to different valid
plaintexts under different keys — critical once "which key is real" becomes adversarial in
deniable mode. Cost: **+16 bytes** on every v2 link.

### Inner payload struct (shared by both versions)

| Field | Type | Notes |
|---|---|---|
| `kind` | u8 enum | `0x01 = token`, `0x02 = binary_blob`, `0x03 = multi` (v2 only) |
| `exp` | u64 seconds-or-0 | Unix epoch UTC; `0` = no expiry |
| `data_len` | u32 LE | byte length of `data` |
| `data` | `[u8; data_len]` | the secret material |

`exp` sits **inside** the AEAD-protected region, so it is tamper-proof (modifying it breaks the
GCM tag). Enforcement is separate — see 07.

## `MULTI` kind (`0x03`, v2 only)

An explicit N-secret mode: `payload.data` carries a `multi_blob` of independently
Argon2id-keyed slot records inside one password-less v2 envelope. Per-slot expiry is
authoritative, so the outer `exp` **must** be `0` on seal and the outer PASSWORD flag is `0`
(the outer layer is keyed by the epoch secret + binding, exactly like any password-less link;
slot content is independently password-keyed).

```
multi_version : u8 = 0x01
slot_count    : u8  (1..=MAX_SLOTS)
per slot:
  slot_salt  : [u8; 16]     fresh per slot
  slot_nonce : [u8; 12]     fresh per slot
  slot_ct_len: u32 LE
  slot_ct    : AES-256-GCM( key_commit(16) ‖ slot_payload , AAD = slot AAD )
```

- `slot_payload` is the inner payload struct **reused verbatim** (kind ‖ exp ‖ data_len ‖
  data), so slot data inherits the `MAX_PAYLOAD_BYTES` cap and kind validation. Slot kinds are
  `token`/`binary_blob` only — nesting `multi` inside a slot is rejected with
  `UNSUPPORTED_KIND`.
- **Slot AAD** = `multi_version ‖ slot_count ‖ slot_index ‖ slot_salt ‖ slot_nonce` (31 B) —
  binds the slot's position and parameters into its GCM tag, so reordering or swapping slots
  breaks their tags.
- **Slot key derivation:** each slot runs its **own** Argon2id over its own salt (spec 02 §
  MULTI key derivation). Never one Argon2 run sliced into N keys — slicing would let any single
  password holder derive all slot keys and destroy isolation.
- **Slot cap:** `MAX_SLOTS = 4` by default; a compile-time override
  `MOSSEAL_MULTI_MAX_SLOTS=8` (values 4 or 8 only, validated at compile time) raises it. Seal
  rejects `slot_count > MAX_SLOTS` with `TOO_MANY_SLOTS`; open rejects a malformed higher
  count with `MALFORMED_ENVELOPE`.
- **Open:** slots are tried in order with the caller's password; the first slot whose AEAD tag
  and commitment verify wins. Structural failures after a verified decrypt (payload, kind,
  expiry) propagate their own codes. All slots failing yields `BAD_PASSWORD` with **no oracle**
  about which slot almost matched.
- Cost note: open performs up to `slot_count` Argon2 derives (~30–60 ms each in wasm at the
  `minimum` profile); seal performs exactly `slot_count`.

## Embedded envelopes (deniable mode, v2 only)

A v2 `binary_blob` envelope may carry a complete hidden v2 envelope inside `payload.data` at a
password-derived offset, padded to a fixed **size class** (1024 / 2048 / 4096 total envelope
bytes) so all deniable links in a class are byte-length-identical. The layout, offset scheme,
and honest limitations are specified in `09-deniability.md`.

## Versioning & compatibility

- Envelope `version` and payload `kind` are separate axes. `decode` accepts versions `1..=2`;
  a version byte above the current one → wrapper error `UNSUPPORTED_VERSION` (forward
  incompatibility is intentional; bump version byte rather than adding flags). Version `0` →
  `MALFORMED_ENVELOPE`.
- **Seals always emit v2.** v1 is a permanent read path: every v1 link keeps opening through
  the same `open()` (version dispatch is internal; callers cannot tell which version served
  the open except via the CLI's `version:` line).
- v1 envelopes accept kinds `0x01`/`0x02` only — a v1 `multi` is `UNSUPPORTED_KIND`.
- Reserved flag bits must be zero on seal; non-zero on open → error `MALFORMED_ENVELOPE`.

## Error taxonomy (envelope layer)

| Code | Meaning |
|---|---|
| `MALFORMED_ENVELOPE` | bad base64url, truncated, bad lengths, reserved bits set, malformed multi blob |
| `UNSUPPORTED_VERSION` | version byte > current |
| `TOO_MANY_SLOTS` | seal-time: multi slot count exceeds `MAX_SLOTS` |

> Over-long URLs are an **advisory warning** at seal time (spec 04 § URL layer), not an
> error code — the taxonomy deliberately has no `URL_TOO_LONG`.

## Open items (decided within this spec)

- The `data` length prefix is a **u32** (little-endian), so the wire format itself permits payloads
  up to `u32::MAX`. The seal API still enforces a practical `MAX_PAYLOAD_BYTES` cap (4096 bytes)
  and errors with `PAYLOAD_TOO_LARGE` beyond it, keeping links within URL/QR budgets. The URL
  layer additionally emits an **advisory** warning (not an error) once the final share URL exceeds
  512 bytes. A hidden envelope embedded in a deniable cover counts against the cover payload's
  cap, which is what effectively bounds deniable hidden content (the 4 KiB class leaves
  ~3.9 KiB of hidden envelope budget).
