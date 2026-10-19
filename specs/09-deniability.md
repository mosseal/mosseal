# Spec 09 — Deniable Links

## Goal

Plausible deniability for shared links: one encrypted string that opens to a plausible cover
secret under one password and to a hidden layer under another (the VeraCrypt model), while
every non-deniable link keeps working through the same pipeline unchanged.

This is **layered AEAD composition**, not polymorphic encryption (not Canetti-style
same-ciphertext-N-plaintexts); that stronger construction is explicitly out of scope.

## Construction

A deniable link is a **normal v2 envelope** (kind `binary_blob`) whose `payload.data` embeds a
complete hidden v2 envelope plus padding:

```
cover payload.data layout:

  offset 0        4 B    masked_len = LE32(hidden_len) ⊕ LE32(arg[4..8])
  offset 4 .. offset     pre-padding (decoy / CSPRNG filler)
  offset .. +hidden_len  the hidden envelope's wire bytes
  remainder               tail padding (decoy / CSPRNG filler)
```

### Password-derived offset

```
arg    = Argon2id(binding || 0x1F || "mosseal/v2/offset" || 0x1F || hidden_password,
                  cover_salt, profile, len = 32)
offset = 4 + (LE32(arg[0..4]) mod (data_len − 4 − hidden_len))
```

- The offset derive uses **no epoch secret** (decision D6, spec 02 § Deniable offset
  derivation): the locating receiver holds only the hidden password; the binary supplies the
  binding string. The dedicated domain tag keeps it separated from every envelope-key derive.
- **`HIDDEN_MIN = 64`** is the recovery validation floor for `hidden_len`.
- Open (hidden password known): derive `arg`, read `masked_len` at `[0..4)`, unmask
  `hidden_len`, validate `HIDDEN_MIN ≤ hidden_len ≤ data_len − 5`, recompute `offset`, slice,
  then run the **normal v2 open path** on the slice with the hidden password (recursion depth
  cap = 1 — a normal `open` never probes for hidden layers; hidden access is explicit-only:
  `openHidden` / `open --hidden-password`).

> **Deviation from the original plan (documented):** PLAN §3.3 placed `masked_len` at
> `[offset−4 .. offset)` and used the modulus `data_len − 4 − HIDDEN_MIN`. That formula cannot
> guarantee `offset + hidden_len ≤ data_len` — for a 2 KiB hidden envelope in the 4 KiB class
> it fails ~49 % of the time — while open-side recovery needs `hidden_len` *before* computing
> the offset. The implemented scheme stores the masked length at the fixed position `[0..4)`
> and uses the modulus `data_len − 4 − hidden_len`, which always fits by construction and
> needs a single Argon2 derive. Security is identical: the masked bytes are uniform at any
> position (they are the XOR of the length with Argon2 output), and the offset remains
> password-derived.

### Cover modes (decision D4, selectable)

| Mode | Cover keying | Hidden receiver needs | Binary holder sees |
|---|---|---|---|
| `cover=hidden` | Argon2id over the cover password (PASSWORD flag set) | **both** passwords | ciphertext only |
| `cover=plain` | HKDF (password-less) | only the hidden password | opaque high-entropy bytes — the hidden envelope's *existence* is visible, its content is not |

Cover `exp` is always `0` (the cover is structural; hidden slots carry their own expiry). Cover
kind is always `binary_blob` — enforced at seal (a token cover has nowhere to hide bytes).

### Decoy content (decision D10)

The cover's plausible content is the padding itself plus optional user-supplied decoy bytes
(seal-time choice). User decoy bytes are cycled into the padding regions; otherwise CSPRNG
filler is used.

### Size classes (decision D5)

Deniable seals target a fixed **total envelope size**: 1 KiB, 2 KiB, or 4 KiB. The cover
`data_len` is padded so `header(33) + tag(16) + commitment(16) + payload header(13) + data_len`
equals the class exactly; all deniable links in a class are byte-length-identical regardless
of secret count. Seal picks the smallest class that fits unless the caller pins one; a pinned
class that cannot fit the hidden envelope fails with `PAYLOAD_TOO_LARGE`.

Consequence: a 2 KiB class link is ≈ 2.7 KB base64url — **over the 512-byte QR advisory**.
Deniable links are URL/clipboard/NFC transport; the advisory does not apply to this mode (the
size class is the statement).

### Hidden envelope contents

A full v2 envelope — either a `MULTI` (N secrets) or a single password-keyed
`token`/`binary_blob` — with its own salt/nonce/epoch. The hidden password locates the layer
(offset + masked length) **and** opens it:

- **Single:** the hidden envelope is keyed by the hidden password.
- **`MULTI`:** the hidden password must equal one slot's password (enforced at seal). That
  password's holder locates the layer and opens their slot. **Other slot holders cannot locate
  the layer without it** — inherent to a single fixed offset; see honest limitations below.
  Same epoch registry (same deployment): retiring an epoch kills cover **and** hidden layers.

## Open flows

| Flow | Passwords | Behavior |
|---|---|---|
| Normal open (`open`) | cover password (mode=hidden) | returns the cover payload (opaque blob) |
| Hidden open (`openHidden`) | cover password (mode=hidden) + hidden password | recovers + opens the hidden layer |
| Admin (`--ignore-expiry`) | as above | skips the hidden layer's expiry; the cover's `exp` is structural 0 and never enforced |

Recovery failures — wrong hidden password, absent hidden layer, corrupt layout — uniformly
yield `BAD_PASSWORD`. This is deliberate: plausible deniability means the format **cannot**
distinguish "no hidden layer" from "wrong password", so no error, detail string, or timing may
differentiate them.

## Honest residual leaks (mandatory in README + spec 00)

1. **Not deniable against the binary holder in `cover=plain` mode** — the hidden envelope's
   *existence* is visible as opaque bytes (content is not).
2. **Suspicion without proof** — an examiner who knows the format can never *exclude* a hidden
   layer (AEAD failures and random bytes are the answer); this is plausible deniability, not
   proof of absence.
3. **Length classes** reduce but do not eliminate size metadata (canonical sizes only).
4. **Password existence** — `cover=hidden` sets the PASSWORD flag, but ordinary password links
   do too; the deniable claim is about content.
5. **App-side behavior** — code paths, logging, and telemetry after a cover open are outside
   the format's reach; the wrapper must not probe for hidden layers on a normal open.
6. **Hidden `MULTI` is single-locator** — only the hidden-password holder can find the layer;
   other slot holders need it too.
7. **Not polymorphic encryption** — layered AEAD (VeraCrypt model), not
   same-ciphertext-N-plaintexts.

## Cost notes

- Seal: one Argon2 per hidden slot + one offset derive (+ one cover Argon2 in `cover=hidden`).
- Hidden open: one offset derive + the hidden envelope's derives (per-slot try-in-order for a
  hidden `MULTI`).
- At the `minimum` profile each derive is ~30–60 ms in wasm.
