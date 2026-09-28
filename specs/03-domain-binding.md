# Spec 03 — Domain Binding

## Goal

Bind envelopes to a set of whitelisted hostnames so a reversed binary alone cannot decrypt
links outside the deployment's origins — while keeping links portable across *all* whitelisted
hosts of the same deployment (fixes the chat's multi-domain breakage bug).

## Decision (user)

Domain binding uses a **list of whitelisted hostnames**, configured at compile time.

## Model

Two distinct roles, deliberately separated:

1. **KDF binding string** — the cryptographic input. Must be *canonical and deployment-stable*.
2. **Runtime allow-list check** — the enforcement gate. A runtime UX/security guard.

The bug in the original chat: using the *runtime* hostname inside the KDF means a link created
on `user.github.io` cannot be opened on the same site served at `custom-domain.com`. We avoid
this by never putting a specific runtime hostname into the KDF.

### 1. Binding string (goes into KDF `info` / Argon2 input)

```
binding = "mosseal/v1" || 0x1F || join(sorted(whitelist), ",")
```

- The **entire sorted whitelist** participates, not the current host. All whitelisted origins
  therefore share one binding, and links are portable across them.
- Changing the whitelist (adding/removing hosts) **changes the binding**, invalidating all
  previously sealed links. This is intended: the whitelist is part of the deployment's
  cryptographic identity and changes only with a new epoch-style rotation.

### 2. Runtime allow-list check (in `open()`/`seal()`, before KDF work)

- In browser builds: read `window.location.hostname`; require it to be in the whitelist, else
  error `DOMAIN_MISMATCH`. Exact match only — no suffix/wildcard matching in v1 (`evil-user.github.io`
  must not match `github.io`).
- In Node/non-browser: the check is skipped (CLI/admin tooling seals links from trusted
  machines). This is the "trusted-node-server" path from the chat, formalized. The whitelist
  still participates in the binding string, so a Node-sealed link only opens on whitelisted
  hosts.

### Compile-time configuration

```
MOSSEAL_ALLOWED_DOMAINS="user.github.io,custom-domain.com,www.custom-domain.com"
```

Validated by the CLI build and injected as an `obfuse!` literal into generated `secrets.rs`.
Missing or empty values cause the CLI pre-validation check to fail immediately with an actionable
error before invoking `wasm-pack`.

### Threat notes (carried from assessment)

- This check is bypassable by patching the wasm or proxying `window.location` — it raises the
  bar, it does not cryptographically bind to the true origin.
- Exact-match semantics chosen deliberately; wildcard support is a non-goal for v1 (complexity
  and subdomain-takeover footguns).
- `localhost` in the whitelist is a dev convenience; document that shipping it to production
  weakens binding (any local page could open links). The CLI **warns** (does not block) if
  `localhost` is present.

## Test requirements

- Link sealed on host A of whitelist opens on host B of same whitelist (portability).
- Link fails to open with `DOMAIN_MISMATCH` on host not in whitelist.
- Whitelist order-insensitivity (sorted before binding) — reordering `.env` must not
  invalidate links.
- Node-sealed link opens in whitelisted browser; fails `DOMAIN_MISMATCH` elsewhere.
