/**
 * .env file planner (spec 05 § Implementation: "All file writes go through a
 * `--dry-run`-able planner for testability").
 *
 * Merging is non-destructive: existing keys are never overwritten.
 *
 * NOTE: this is an internal parser — the package has NO runtime `dotenv`
 * dependency (spec 05 was corrected: the CLI only needs simple KEY=VALUE
 * lines and loads them into `process.env` itself).
 */
import { readFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { execFileSync } from "node:child_process";

export type DotenvEntry = [key: string, value: string];

export interface MergeResult {
  /** True when at least one update needs writing. */
  changed: boolean;
  /** New .env contents, or null when nothing needs writing. */
  text: string | null;
  /** Keys that already existed and were therefore left untouched. */
  skipped: string[];
}

/**
 * Parse a .env file into ordered [key, value] pairs.
 */
export function parseDotenv(text: string): DotenvEntry[] {
  const entries: DotenvEntry[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    // strip surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    entries.push([key, value]);
  }
  return entries;
}

/**
 * Serialize ordered [key, value] pairs back to .env text.
 */
export function serializeDotenv(entries: DotenvEntry[]): string {
  return entries.map(([k, v]) => `${k}=${v}`).join("\n") + "\n";
}

/**
 * Merge `updates` into an existing .env file non-destructively.
 * Existing keys keep their values; new keys are appended.
 */
export function mergeDotenv(envPath: string, updates: DotenvEntry[]): MergeResult {
  let entries: DotenvEntry[] = [];
  if (existsSync(envPath)) {
    entries = parseDotenv(readFileSync(envPath, "utf8"));
  }
  const existing = new Map(entries);
  const skipped: string[] = [];
  for (const [k, v] of updates) {
    if (existing.has(k)) {
      skipped.push(k);
    } else {
      entries.push([k, v]);
    }
  }
  const changed = skipped.length < updates.length;
  return {
    changed,
    text: changed ? serializeDotenv(entries) : null,
    skipped,
  };
}

/**
 * Load a .env file into `process.env` WITHOUT overwriting existing vars
 * (real environment wins, mirroring dotenv semantics). Used by `build` and
 * `rotate`.
 */
export function loadEnvFile(envPath: string): string[] {
  if (!existsSync(envPath)) return [];
  const loaded: string[] = [];
  for (const [k, v] of parseDotenv(readFileSync(envPath, "utf8"))) {
    if (process.env[k] === undefined) {
      process.env[k] = v;
      loaded.push(k);
    }
  }
  return loaded;
}

/**
 * Check whether a path is ignored by the repo's .gitignore (spec 05: `init`
 * refuses to write .env if it would be committed — the #1 footgun).
 *
 * Uses `git check-ignore` when git is available; falls back to a heuristic
 * scan of .gitignore files for `.env` patterns.
 *
 * @returns true = ignored (safe), false = NOT ignored (danger),
 *          null = cannot determine (no git, no .gitignore found).
 */
export function isGitIgnored(envPath: string, cwd: string): boolean | null {
  try {
    // exit 0 = ignored; exit 1 = not ignored; other = git broken → heuristic
    execFileSync("git", ["check-ignore", "-q", envPath], { cwd, stdio: "ignore" });
    return true;
  } catch (err) {
    if ((err as { status?: number })?.status === 1) return false;
    // git missing or repo broken → fall through to heuristic
  }
  return heuristicGitIgnore(envPath, cwd);
}

function heuristicGitIgnore(envPath: string, cwd: string): boolean | null {
  const giPath = join(cwd, ".gitignore");
  if (!existsSync(giPath)) return null;
  const patterns = readFileSync(giPath, "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"));
  const name = basename(envPath);
  return patterns.some((p) => {
    const pat = p.replace(/^\//, "").replace(/\/$/, "");
    if (pat === name || pat === ".env" || pat === ".env.*" || pat === ".env*") return true;
    if (pat.endsWith("*") && name.startsWith(pat.slice(0, -1))) return true;
    return false;
  });
}
