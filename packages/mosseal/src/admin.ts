/**
 * Admin commands (spec 05 § admin surface): `gen-secret`, `seal`, `open`.
 *
 * These mirror the native `mosseal-cli` binary's trusted-admin path so the
 * same operations are available through `npx mosseal` without a Rust
 * toolchain. Sealing/opening runs the precompiled admin wasm
 * (`crates/mosseal-admin-wasm`); `gen-secret` is pure `node:crypto` (byte-
 * identical to the native implementation).
 *
 * Epochs/domains resolve in this order:
 *   1. explicit `--epochs` / `--domains` flags,
 *   2. `MOSSEAL_EPOCHS` / `MOSSEAL_ALLOWED_DOMAINS` environment variables,
 *   3. the `.env` file's `MOSSEAL_SECRET_<n>` slots + `MOSSEAL_ALLOWED_DOMAINS`
 *      (the same config `init`/`rotate`/`build` use).
 */
import { randomBytes } from "node:crypto";
import { join, resolve } from "node:path";
import { Admin, KIND_BINARY_BLOB, KIND_TOKEN } from "./admin-wasm.js";
import { loadEnvFile } from "./dotenv.js";
import { validateEnv } from "./env.js";

export interface AdminOpts {
  cwd?: string;
  /** `--epochs`: base64url secrets joined by `;` (holes = empty entries). */
  epochs?: string;
  /** `--domains`: comma-separated bare lowercase hostnames. */
  domains?: string;
  /** `--password`: omit to prompt (TTY) or use no password. */
  password?: string;
  /** `--password` with no value: prompt on the TTY (echo off). */
  passwordPrompt?: boolean;
  /** `--exp`: unix seconds; omit/0 = never expires. */
  exp?: number;
  /** `--kind`: `token` (default) or `binary_blob`. */
  kind?: string;
  /** `--ignore-expiry` (open only): skip the expiry check. */
  ignoreExpiry?: boolean;
}

/** Generate a fresh 32-byte epoch secret as base64url (no padding). */
export function genSecret(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * Resolve the epoch registry string. Precedence: flag → env → `.env` slots.
 * The `.env` path reuses `validateEnv` so holes (retired epochs) are preserved
 * exactly as `build` would see them.
 *
 * Presence is tested with `!== undefined` (not truthiness) so an explicit empty
 * `--epochs ""` reaches the wasm and fails with the same `EPOCH_RETIRED` the
 * native CLI reports, rather than silently falling through to `.env`.
 */
function resolveEpochs(opts: AdminOpts, cwd: string): string {
  if (opts.epochs !== undefined) return opts.epochs;
  if (process.env.MOSSEAL_EPOCHS !== undefined) return process.env.MOSSEAL_EPOCHS;

  loadEnvFile(join(cwd, ".env"));
  const { config } = validateEnv(process.env);
  // Slot-indexed secrets → `;`-joined registry (null hole → empty entry).
  return config.secrets.map((s) => s ?? "").join(";");
}

/** Resolve the domain whitelist string. Precedence: flag → env → `.env`. */
function resolveDomains(opts: AdminOpts, cwd: string): string {
  if (opts.domains !== undefined) return opts.domains;
  if (process.env.MOSSEAL_ALLOWED_DOMAINS !== undefined) {
    return process.env.MOSSEAL_ALLOWED_DOMAINS;
  }

  loadEnvFile(join(cwd, ".env"));
  const raw = process.env.MOSSEAL_ALLOWED_DOMAINS;
  if (raw === undefined) {
    throw new Error(
      "No domains configured. Pass --domains <host,...> or set " +
        "MOSSEAL_ALLOWED_DOMAINS (in the environment or .env)."
    );
  }
  return raw;
}

/** Map a `--kind` string to its payload kind byte (spec 01). */
function parseKind(kind: string | undefined): number {
  switch ((kind ?? "token").toLowerCase()) {
    case "token":
      return KIND_TOKEN;
    // `binary-blob` is the canonical spelling (matches the native CLI's clap
    // value); `binary_blob`/`blob` are accepted aliases.
    case "binary-blob":
    case "binary_blob":
    case "blob":
      return KIND_BINARY_BLOB;
    default:
      throw new Error(
        `invalid value '${kind}' for '--kind <KIND>' [possible values: token, binary-blob]`
      );
  }
}

/**
 * Prompt for a password on the TTY with echo disabled (mirrors the native
 * CLI's `rpassword`). Throws when stdin is not a TTY so scripts fail loudly
 * instead of hanging.
 */
export function promptPassword(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error(
      "Cannot prompt for a password: stdin is not a TTY. Pass --password <pw>."
    );
  }
  return new Promise((resolvePromise, reject) => {
    const stdin = process.stdin;
    process.stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    let value = "";
    const cleanup = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      process.stderr.write("\n");
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          cleanup();
          resolvePromise(value);
          return;
        }
        if (ch === "\u0003") {
          // Ctrl-C
          cleanup();
          reject(new Error("aborted"));
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

/** Resolve the password: explicit flag wins; otherwise prompt when a TTY. */
async function resolvePassword(opts: AdminOpts, prompt: string): Promise<string | undefined> {
  if (opts.password !== undefined) return opts.password;
  if (opts.passwordPrompt) return await promptPassword(prompt);
  return undefined;
}

/** `mosseal gen-secret` — print a fresh 32-byte base64url epoch secret. */
export function cmdGenSecret(): { ok: true } {
  console.log(genSecret());
  return { ok: true };
}

/** `mosseal seal <token>` — seal a token into a share-link fragment. */
export async function cmdSeal(token: string | undefined, opts: AdminOpts = {}): Promise<{ ok: true }> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const data = token ?? (await promptPassword("Token to seal: "));
  const password = await resolvePassword(opts, "Password (empty for none): ");

  const admin = Admin.create(resolveEpochs(opts, cwd), resolveDomains(opts, cwd));
  try {
    const fragment = admin.seal(data, {
      password: password || undefined,
      expSecs: opts.exp,
      kind: parseKind(opts.kind),
    });
    console.log(fragment);
  } finally {
    admin.free();
  }
  return { ok: true };
}

/** `mosseal open <fragment>` — open and verify a fragment. */
export async function cmdOpen(fragment: string, opts: AdminOpts = {}): Promise<{ ok: true }> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const password = await resolvePassword(opts, "Password (empty for none): ");

  const admin = Admin.create(resolveEpochs(opts, cwd), resolveDomains(opts, cwd));
  try {
    const out = admin.open(fragment, {
      password: password || undefined,
      ignoreExpiry: opts.ignoreExpiry,
    });
    console.log(`kind: ${out.kind}\nexp:  ${out.exp}\ndata: ${out.data}`);
  } finally {
    admin.free();
  }
  return { ok: true };
}
