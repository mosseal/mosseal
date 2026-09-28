/**
 * Environment validation (spec 05 § `mosseal build` flow, step 1).
 *
 * Pre-validates the consumer's env BEFORE spawning wasm-pack, because
 * `env!()` compile errors are cryptic. Fail fast with actionable messages.
 */
import { createHash } from "node:crypto";

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const HOSTNAME_RE = /^[a-z0-9.-]+$/;

export const ARGON2_PROFILES = ["minimum", "interactive"] as const;
export type Argon2Profile = (typeof ARGON2_PROFILES)[number];

export interface ValidatedConfig {
  /**
   * Slot-indexed epoch secrets. Index = epoch byte; `null` = a **retired
   * hole** (that epoch was removed after its grace window). At least one
   * entry is non-null. Trailing holes are trimmed.
   */
  secrets: (string | null)[];
  domains: string[];
  strictTime: boolean;
  argonProfile: string;
  timeSources: string[] | null;
}

export interface ValidateEnvResult {
  config: ValidatedConfig;
  warnings: string[];
}

type EnvRecord = Record<string, string | undefined>;

/**
 * Parse and validate the full MOSSEAL env surface.
 * @throws {Error} with an actionable message on the first invalid entry
 */
export function validateEnv(env: EnvRecord): ValidateEnvResult {
  const warnings: string[] = [];

  // --- Epoch secrets: slot-indexed, holes allowed (retired epochs) ---
  // Collect every MOSSEAL_SECRET_<n> key present so a hole like {0, 2} is
  // preserved as a retired slot rather than silently truncated. Epoch indices
  // are positional: a hole means that epoch was retired (spec 02 § Key
  // epochs) and links sealed under it must fail with EPOCH_RETIRED while
  // every other epoch keeps its number.
  const present = new Map<number, string>();
  for (const key of Object.keys(env)) {
    const m = /^MOSSEAL_SECRET_(\d+)$/.exec(key);
    if (!m) continue;
    const raw = env[key];
    if (raw === undefined || raw === "") continue;
    present.set(Number(m[1]), raw);
  }

  if (present.size === 0) {
    throw new Error(
      "No MOSSEAL_SECRET_0 found. Run `mosseal init` to scaffold .env, " +
        "or set MOSSEAL_SECRET_0 (base64url, 32 bytes)."
    );
  }

  // Highest present index defines the slot count; missing indices are holes.
  const maxIndex = Math.max(...present.keys());
  const secrets: (string | null)[] = [];
  for (let i = 0; i <= maxIndex; i++) {
    const raw = present.get(i);
    if (raw === undefined) {
      // Retired hole — keep the slot so later epochs keep their index.
      secrets.push(null);
      continue;
    }
    if (!B64URL_RE.test(raw)) {
      throw new Error(
        `MOSSEAL_SECRET_${i} is not valid base64url (got ${describe(raw)}). ` +
          `Regenerate with: mosseal init`
      );
    }
    const bytes = Buffer.from(raw, "base64url");
    if (bytes.length !== 32) {
      throw new Error(
        `MOSSEAL_SECRET_${i} must decode to exactly 32 bytes, got ${bytes.length}. ` +
          `Regenerate with: mosseal init`
      );
    }
    secrets.push(raw);
  }
  // Trim trailing holes (a trailing hole is meaningless — nothing above it).
  while (secrets.length > 0 && secrets[secrets.length - 1] === null) {
    secrets.pop();
  }
  if (secrets.length === 0) {
    throw new Error(
      "No MOSSEAL_SECRET_0 found. Run `mosseal init` to scaffold .env, " +
        "or set MOSSEAL_SECRET_0 (base64url, 32 bytes)."
    );
  }

  // --- Allowed domains: bare lowercase hostnames, exact-match (spec 03) ---
  const domainsRaw = env.MOSSEAL_ALLOWED_DOMAINS;
  if (!domainsRaw || !domainsRaw.trim()) {
    throw new Error(
      "MOSSEAL_ALLOWED_DOMAINS is required (comma-separated bare lowercase " +
        "hostnames, e.g. user.github.io,custom-domain.com)."
    );
  }
  const domains = domainsRaw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (domains.length === 0) {
    throw new Error("MOSSEAL_ALLOWED_DOMAINS is empty after parsing.");
  }
  for (const host of domains) {
    if (!HOSTNAME_RE.test(host)) {
      throw new Error(
        `Invalid hostname in MOSSEAL_ALLOWED_DOMAINS: ${JSON.stringify(host)}. ` +
          `Entries must be bare lowercase hostnames — no scheme, port, path, ` +
          `or uppercase (spec 03).`
      );
    }
    if (host === "localhost" || host.endsWith(".localhost")) {
      warnings.push(
        `localhost is in MOSSEAL_ALLOWED_DOMAINS — fine for dev, but shipping ` +
          `it to production weakens domain binding (any local page could open links).`
      );
    }
  }

  // --- STRICT_TIME: "true"/"false", default false (spec 07) ---
  const strictRaw = (env.MOSSEAL_STRICT_TIME ?? "false").trim().toLowerCase();
  if (strictRaw !== "true" && strictRaw !== "false") {
    throw new Error(
      `MOSSEAL_STRICT_TIME must be "true" or "false", got ${JSON.stringify(strictRaw)}.`
    );
  }

  // --- ARGON2_PROFILE: minimum (default) | interactive (spec 02) ---
  const profileRaw = (env.MOSSEAL_ARGON2_PROFILE ?? "minimum").trim().toLowerCase();
  if (!(ARGON2_PROFILES as readonly string[]).includes(profileRaw)) {
    throw new Error(
      `MOSSEAL_ARGON2_PROFILE must be one of ${ARGON2_PROFILES.join("|")}, ` +
        `got ${JSON.stringify(profileRaw)}.`
    );
  }

  // --- TIME_SOURCES: optional override (spec 07) ---
  const timeSourcesRaw = env.MOSSEAL_TIME_SOURCES?.trim();
  let timeSources: string[] | null = null;
  if (timeSourcesRaw) {
    const urls = timeSourcesRaw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (urls.length === 0) {
      throw new Error("MOSSEAL_TIME_SOURCES is set but empty after parsing.");
    }
    for (const u of urls) {
      let parsed: URL;
      try {
        parsed = new URL(u);
      } catch {
        throw new Error(
          `MOSSEAL_TIME_SOURCES entry is not a valid URL: ${JSON.stringify(u)}.`
        );
      }
      if (parsed.protocol !== "https:") {
        throw new Error(
          `MOSSEAL_TIME_SOURCES entries must be https:// (mixed content + ` +
            `spoofing): ${JSON.stringify(u)}.`
        );
      }
    }
    warnings.push(
      "MOSSEAL_TIME_SOURCES override is set — ensure every source is " +
        "CORS-enabled and body-parseable (spec 07), or strict mode will fail."
    );
    timeSources = urls;
  }

  return {
    config: {
      secrets,
      domains,
      strictTime: strictRaw === "true",
      argonProfile: profileRaw,
      timeSources,
    },
    warnings,
  };
}

/**
 * Fingerprint of the validated config for `meta.json` provenance.
 * Never contains secret material — only a hash of it.
 */
export function configFingerprint(config: ValidatedConfig): string {
  const h = createHash("sha256");
  h.update(config.secrets.join(";"));
  h.update(config.domains.slice().sort().join(","));
  h.update(config.strictTime ? "strict" : "lenient");
  h.update(config.argonProfile);
  return h.digest("base64url").slice(0, 16);
}

function describe(raw: string): string {
  if (raw.length > 24) return `${raw.slice(0, 24)}…`;
  return raw;
}
