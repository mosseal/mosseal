/**
 * `dotenv.ts` tests (spec 05 § Implementation: non-destructive .env merge,
 * gitignore footgun check).
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseDotenv,
  serializeDotenv,
  mergeDotenv,
  loadEnvFile,
  isGitIgnored,
} from "../src/dotenv.js";

const tmpDirs: string[] = [];
function makeTmp(): string {
  const d = mkdtempSync(join(tmpdir(), "mosseal-dotenv-"));
  tmpDirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("parseDotenv", () => {
  it("parses KEY=VALUE lines, skipping blanks and comments", () => {
    const entries = parseDotenv(
      ["# comment", "", "A=1", "  B = two  ", "not-a-pair"].join("\n")
    );
    expect(entries).toEqual([
      ["A", "1"],
      ["B", "two"],
    ]);
  });

  it("strips surrounding single and double quotes", () => {
    expect(parseDotenv(`A="x y"\nB='z'`)).toEqual([
      ["A", "x y"],
      ["B", "z"],
    ]);
  });

  it("keeps '=' inside the value", () => {
    expect(parseDotenv("A=b=c")).toEqual([["A", "b=c"]]);
  });

  it("handles CRLF line endings", () => {
    expect(parseDotenv("A=1\r\nB=2\r\n")).toEqual([
      ["A", "1"],
      ["B", "2"],
    ]);
  });
});

describe("serializeDotenv", () => {
  it("round-trips through parse", () => {
    const entries: [string, string][] = [
      ["A", "1"],
      ["B", "two"],
    ];
    expect(parseDotenv(serializeDotenv(entries))).toEqual(entries);
  });

  it("ends with a trailing newline", () => {
    expect(serializeDotenv([["A", "1"]])).toBe("A=1\n");
  });
});

describe("mergeDotenv", () => {
  it("appends new keys to a missing file", () => {
    const dir = makeTmp();
    const p = join(dir, ".env");
    const res = mergeDotenv(p, [["MOSSEAL_SECRET_0", "abc"]]);
    expect(res.changed).toBe(true);
    expect(res.skipped).toEqual([]);
    expect(res.text).toBe("MOSSEAL_SECRET_0=abc\n");
  });

  it("never overwrites an existing key", () => {
    const dir = makeTmp();
    const p = join(dir, ".env");
    writeFileSync(p, "MOSSEAL_SECRET_0=keep\n");
    const res = mergeDotenv(p, [["MOSSEAL_SECRET_0", "new"]]);
    expect(res.changed).toBe(false);
    expect(res.text).toBeNull();
    expect(res.skipped).toEqual(["MOSSEAL_SECRET_0"]);
  });

  it("appends only the missing keys, preserving order", () => {
    const dir = makeTmp();
    const p = join(dir, ".env");
    writeFileSync(p, "A=1\n");
    const res = mergeDotenv(p, [
      ["A", "x"],
      ["B", "2"],
    ]);
    expect(res.changed).toBe(true);
    expect(res.skipped).toEqual(["A"]);
    expect(res.text).toBe("A=1\nB=2\n");
  });
});

describe("loadEnvFile", () => {
  it("loads keys into process.env without overwriting existing vars", () => {
    const dir = makeTmp();
    const p = join(dir, ".env");
    writeFileSync(p, "MOSSEAL_TEST_LOADED=fromfile\nMOSSEAL_TEST_KEEP=fromfile\n");
    process.env.MOSSEAL_TEST_KEEP = "fromenv";
    try {
      const loaded = loadEnvFile(p);
      expect(process.env.MOSSEAL_TEST_LOADED).toBe("fromfile");
      expect(process.env.MOSSEAL_TEST_KEEP).toBe("fromenv");
      expect(loaded).toContain("MOSSEAL_TEST_LOADED");
      expect(loaded).not.toContain("MOSSEAL_TEST_KEEP");
    } finally {
      delete process.env.MOSSEAL_TEST_LOADED;
      delete process.env.MOSSEAL_TEST_KEEP;
    }
  });

  it("returns [] for a missing file", () => {
    const dir = makeTmp();
    expect(loadEnvFile(join(dir, "nope.env"))).toEqual([]);
  });
});

describe("isGitIgnored", () => {
  it("returns true when .gitignore lists .env", () => {
    const dir = makeTmp();
    writeFileSync(join(dir, ".gitignore"), "node_modules/\n.env\n");
    expect(isGitIgnored(join(dir, ".env"), dir)).toBe(true);
  });

  it("returns false when .gitignore exists but omits .env", () => {
    const dir = makeTmp();
    writeFileSync(join(dir, ".gitignore"), "node_modules/\n");
    expect(isGitIgnored(join(dir, ".env"), dir)).toBe(false);
  });

  it("returns null when there is no .gitignore", () => {
    const dir = makeTmp();
    expect(isGitIgnored(join(dir, ".env"), dir)).toBeNull();
  });

  it("matches a glob pattern like .env*", () => {
    const dir = makeTmp();
    writeFileSync(join(dir, ".gitignore"), ".env*\n");
    expect(isGitIgnored(join(dir, ".env"), dir)).toBe(true);
  });
});

describe("mergeDotenv + write round-trip", () => {
  it("writes merged text that re-parses to the expected entries", () => {
    const dir = makeTmp();
    const p = join(dir, ".env");
    writeFileSync(p, "MOSSEAL_ALLOWED_DOMAINS=example.com\n");
    const res = mergeDotenv(p, [["MOSSEAL_SECRET_0", "abc"]]);
    writeFileSync(p, res.text!);
    expect(existsSync(p)).toBe(true);
    expect(parseDotenv(readFileSync(p, "utf8"))).toEqual([
      ["MOSSEAL_ALLOWED_DOMAINS", "example.com"],
      ["MOSSEAL_SECRET_0", "abc"],
    ]);
  });
});
