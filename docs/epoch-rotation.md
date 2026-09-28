# Epoch Rotation Runbook

MOSSEAL is stateless: there is no server, no database, and no revocation
authority. The **only** way to invalidate links is to **retire a key epoch**
(spec 02 § Key epochs). This runbook is the operational procedure.

> **Mental model.** An *epoch* is a numbered 32-byte secret baked into your
> compiled wasm. Every link records the epoch it was sealed under. Sealing
> always uses the **highest active** epoch; opening uses the link's epoch.
> Retiring an epoch makes links sealed under it fail with `EPOCH_RETIRED`,
> while every other epoch keeps working.

## Concepts

| Term | Meaning |
|---|---|
| **Epoch** | A numbered secret (`MOSSEAL_SECRET_<n>`), index = epoch byte in the envelope. |
| **Active** | The secret is present in `.env`; links under it open. |
| **Retired** | The secret was removed; links under it fail with `EPOCH_RETIRED`. |
| **Hole** | A retired epoch's slot. Holes are **preserved** so later epochs keep their numbers. |
| **Grace window** | The period you keep an old epoch active after rotating, so existing links still open. |

Epoch indices are **positional**. A hole is an empty entry in the `;`-joined
registry string (e.g. `secret0;;secret2` = epoch 1 retired). **Never renumber**
the remaining secrets — that would silently re-key every surviving link.

## When to rotate

- **Routine hygiene** — periodically (e.g. quarterly), so a leaked link's blast
  radius is bounded by the grace window.
- **Suspected leak** — a link was shared too widely, or a secret may have been
  exposed. Rotate, then retire the compromised epoch **immediately** (skip the
  grace window if the leak is confirmed).
- **Whitelist change** — adding/removing a domain changes the binding string and
  invalidates *all* links (spec 03). This is a separate, heavier operation; see
  "Whitelist changes" below.

## Procedure

### 1. Rotate (add a new epoch)

```bash
npx mosseal rotate
```

This appends `MOSSEAL_SECRET_<N+1>` (where `N` is the highest existing index) to
`.env` and leaves all prior epochs in place. New links are now sealed under the
new epoch; old links keep opening.

Preview without writing:

```bash
npx mosseal rotate --dry-run
```

### 2. Rebuild and deploy

```bash
npx mosseal build      # regenerates secrets.rs, recompiles the wasm
# deploy mosseal-out/ with your site
```

The new build contains **all** active epochs, so it can open both new and old
links. Deploy it before retiring anything.

### 3. Wait out the grace window

Keep the old epoch active for as long as you want existing links to work
(e.g. 30 days). During this window, both old and new links open.

### 4. Retire the old epoch

Delete the `MOSSEAL_SECRET_<n>` line from `.env`:

```diff
  MOSSEAL_SECRET_0=<...>
- MOSSEAL_SECRET_1=<...>   # retire this epoch
  MOSSEAL_SECRET_2=<...>
```

Then rebuild and deploy:

```bash
npx mosseal build
```

Links sealed under epoch 1 now fail with `EPOCH_RETIRED`. Links under epochs 0
and 2 are unaffected. The registry string becomes `secret0;;secret2` — the hole
is expected.

> **Do not renumber.** Leave `MOSSEAL_SECRET_2` named `_2`. Renaming it to `_1`
> would make epoch-2 links resolve to the wrong key (they would fail with
> `BAD_PASSWORD`, not `EPOCH_RETIRED`) and would break the grace window for
> every surviving epoch.

### 5. Verify

```bash
npx mosseal build --dry-run
```

The output reports active vs. retired epochs, e.g.
`env ok: 2 active epoch(s) (+1 retired), ...`. Confirm the counts match your
intent before deploying.

## Retiring multiple epochs

You may retire epochs in **any order**; each hole is independent. To retire
several, delete each `MOSSEAL_SECRET_<n>` line and rebuild once. Trailing holes
(the highest epochs) are trimmed automatically — retiring the newest epoch is
allowed but unusual (it just moves the sealing epoch down to the next active
one).

## Whitelist changes

Changing `MOSSEAL_ALLOWED_DOMAINS` changes the **binding string**, which is part
of the KDF input (spec 03). This invalidates **all** previously sealed links,
regardless of epoch. Treat a whitelist change as a full re-issue:

1. Update `MOSSEAL_ALLOWED_DOMAINS`.
2. Rotate to a fresh epoch (so new links are clearly distinguishable).
3. Rebuild and deploy.
4. Retire old epochs once you accept that old links are dead.

## Failure modes & troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `EPOCH_RETIRED` on a link you expected to work | Its epoch was retired (or the link's epoch byte is out of range) | Restore the epoch secret, or accept the link is dead |
| `BAD_PASSWORD` on a link that has no password | The epoch was **renumbered**, so the link resolves to the wrong key | Restore the original numbering (never renumber) |
| `EPOCH_RETIRED` on **all** links | The registry has no active secret (all epochs retired) | Restore at least one `MOSSEAL_SECRET_<n>` |
| Build fails: "No MOSSEAL_SECRET_0 found" | `.env` missing or empty | `npx mosseal init` |
| Build fails: "must decode to exactly 32 bytes" | A secret was truncated/edited | Regenerate with `npx mosseal init` / `rotate` |

## Security notes

- **Retirement is the only revocation.** There is no per-link revocation; a
  bearer link is valid until its epoch is retired or its `exp` passes.
- **Grace windows are a trade-off.** A longer window keeps old links working but
  keeps a compromised secret live longer. For a confirmed leak, retire
  immediately and accept that old links break.
- **Secrets live in `.env`.** Ensure `.env` is gitignored (`mosseal init` warns
  loudly if it is not). If a secret was ever committed, rotate **and** purge
  history.
- **The compiled wasm contains all active epochs.** Anyone with the binary can
  extract them (obfuscation is a speed bump, spec 00). Retirement only helps
  once the old secret is removed from the deployed binary.
