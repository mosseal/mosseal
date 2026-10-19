/**
 * Admin command tests (spec 05 § admin surface): `gen-secret`, `seal`, `open`.
 *
 * These drive the real vendored admin wasm (built from
 * `crates/mosseal-admin-wasm`) so the TS CLI's crypto is pinned to the same
 * implementation the native `mosseal-cli` uses. The artifact is a derived build
 * output (not committed), so it is regenerated on demand when missing.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.js";
import { genSecret } from "../src/admin.js";
import { hasVendoredAdminWasm, syncAdminWasm } from "../../../scripts/sync-admin-wasm.mjs";

const tmpDirs: string[] = [];
function makeTmp(): string {
  const d = mkdtempSync(join(tmpdir(), "mosseal-admin-"));
  tmpDirs.push(d);
  return d;
}

let logSpy: ReturnType<typeof vi.spyOn>;

beforeAll(() => {
  // The vendored admin wasm is generated on demand and not committed.
  if (!hasVendoredAdminWasm()) syncAdminWasm();
}, 120_000);

beforeEach(() => {
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});
afterEach(() => {
  logSpy.mockRestore();
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
  for (const k of Object.keys(process.env)) {
    if (k.startsWith("MOSSEAL_")) delete process.env[k];
  }
});

function logged(): string {
  return logSpy.mock.calls.map((c: unknown[]) => c.join(" ")).join("\n");
}

function secret(seed = 1): string {
  return Buffer.alloc(32, seed).toString("base64url");
}

describe("gen-secret", () => {
  it("prints a 32-byte base64url secret", async () => {
    await run(["gen-secret"]);
    const out = logged().trim();
    expect(out).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(out, "base64url")).toHaveLength(32);
  });

  it("is byte-identical in shape to the native implementation", () => {
    const s = genSecret();
    expect(Buffer.from(s, "base64url")).toHaveLength(32);
    expect(s).not.toContain("=");
    expect(genSecret()).not.toBe(genSecret());
  });
});

describe("v2 admin surface (multi + deniable)", () => {
  it("open prints the version line (D9: CLI-only exposure)", async () => {
    const s = secret(3);
    await run(["seal", "tok_v2", "--epochs", s, "--domains", "a.test"]);
    const frag = logged().trim();
    logSpy.mockClear();
    await run(["open", frag, "--epochs", s, "--domains", "a.test"]);
    expect(logged()).toMatch(/version: 2/);
    expect(logged()).toMatch(/data: tok_v2/);
  });

  it("seal-multi round-trips each slot and rejects wrong passwords", async () => {
    const s = secret(4);
    await run([
      "seal-multi",
      "--slot",
      "pw-one=secret_one",
      "--slot",
      "pw-two=secret_two",
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    const frag = logged().trim();
    expect(frag).toMatch(/^[A-Za-z0-9_-]+$/);

    logSpy.mockClear();
    await run(["open", frag, "--password", "pw-two", "--epochs", s, "--domains", "a.test"]);
    expect(logged()).toMatch(/data: secret_two/);
    expect(logged()).toMatch(/version: 2/);

    await expect(
      run(["open", frag, "--password", "WRONG", "--epochs", s, "--domains", "a.test"])
    ).rejects.toThrow(/BAD_PASSWORD/);
  });

  it("seal-deniable hides and recovers a hidden layer (plain cover)", async () => {
    const s = secret(5);
    await run([
      "seal-deniable",
      "--cover-mode",
      "plain",
      "--hidden-slot",
      "hpw=hidden_secret",
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    const frag = logged().trim();
    // 1 KiB size class → a long fragment (padded), unlike single links.
    expect(frag.length).toBeGreaterThan(1000);

    logSpy.mockClear();
    await run([
      "open",
      frag,
      "--hidden-password",
      "hpw",
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    expect(logged()).toMatch(/data: hidden_secret/);
    expect(logged()).toMatch(/version: 2/);

    // A normal open shows only the opaque cover blob — no secret leak.
    logSpy.mockClear();
    await run(["open", frag, "--epochs", s, "--domains", "a.test"]);
    expect(logged()).toMatch(/kind: 2/);
    expect(logged()).not.toMatch(/hidden_secret/);

    await expect(
      run([
        "open",
        frag,
        "--hidden-password",
        "WRONG",
        "--epochs",
        s,
        "--domains",
        "a.test",
      ])
    ).rejects.toThrow(/BAD_PASSWORD/);
  });

  it("seal-deniable hidden cover requires the cover password to open", async () => {
    const s = secret(6);
    await run([
      "seal-deniable",
      "--cover-password",
      "cover-pw",
      "--hidden-slot",
      "hpw=hidden_secret",
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    const frag = logged().trim();

    await expect(
      run([
        "open",
        frag,
        "--hidden-password",
        "hpw",
        "--epochs",
        s,
        "--domains",
        "a.test",
      ])
    ).rejects.toThrow(/BAD_PASSWORD/);

    logSpy.mockClear();
    await run([
      "open",
      frag,
      "--password",
      "cover-pw",
      "--hidden-password",
      "hpw",
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    expect(logged()).toMatch(/data: hidden_secret/);
  });

  it("parseSlotArg splits on the first equals, validates, and never echoes credentials", async () => {
    const { parseSlotArg } = await import("../src/admin.js");
    expect(parseSlotArg("pw=secret=with=equals")).toEqual({
      password: "pw",
      data: "secret=with=equals",
    });
    for (const bad of ["no-equals", "=empty", "hunter2:secret"]) {
      let message = "";
      try {
        parseSlotArg(bad);
      } catch (e) {
        message = String(e);
      }
      expect(message).toMatch(/PASSWORD=SECRET/);
      // The raw argument contains credentials; it must not reach the error.
      expect(message).not.toContain(bad);
      expect(message).not.toContain("hunter2");
    }
  });

  it("seal-multi honors slots-file kind and expSecs (native parity)", async () => {
    const s = secret(7);
    const dir = makeTmp();
    const slotsFile = join(dir, "slots.json");
    writeFileSync(
      slotsFile,
      JSON.stringify([
        { password: "pw1", data: "secret_one" },
        { password: "pw2", data: "secret_two", kind: "binary-blob", expSecs: 4102444800 },
      ])
    );
    await run([
      "seal-multi",
      "--slots-file",
      slotsFile,
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    const frag = logged().trim();

    // String kind + expSecs ride through: slot 2 opens as kind 2 with exp.
    logSpy.mockClear();
    await run([
      "open",
      frag,
      "--password",
      "pw2",
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    expect(logged()).toMatch(/kind: 2/);
    expect(logged()).toMatch(/exp: {2}4102444800/);

    // Numeric kind form is accepted too (shared slots-file schema).
    writeFileSync(
      slotsFile,
      JSON.stringify([{ password: "pw3", data: "secret_three", kind: 2 }])
    );
    logSpy.mockClear();
    await run([
      "seal-multi",
      "--slots-file",
      slotsFile,
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    const frag2 = logged().trim();
    logSpy.mockClear();
    await run([
      "open",
      frag2,
      "--password",
      "pw3",
      "--epochs",
      s,
      "--domains",
      "a.test",
    ]);
    expect(logged()).toMatch(/kind: 2/);
  });

  it("seal-deniable rejects --slot instead of silently dropping it", async () => {
    const s = secret(8);
    await expect(
      run([
        "seal-deniable",
        "--cover-mode",
        "plain",
        "--slot",
        "lost=secret",
        "--hidden-slot",
        "hpw=hidden",
        "--epochs",
        s,
        "--domains",
        "a.test",
      ])
    ).rejects.toThrow(/--hidden-slot/);
  });

  it("seal-multi rejects fractional expSecs (cross-surface parity)", async () => {
    const s = secret(9);
    const dir = makeTmp();
    const slotsFile = join(dir, "slots.json");
    writeFileSync(
      slotsFile,
      JSON.stringify([{ password: "pw", data: "d", expSecs: 3600.5 }])
    );
    await expect(
      run([
        "seal-multi",
        "--slots-file",
        slotsFile,
        "--epochs",
        s,
        "--domains",
        "a.test",
      ])
    ).rejects.toThrow(/MALFORMED_ENVELOPE/);
  });
});

describe("seal / open round-trip", () => {
  it("seals then opens a token via flags", async () => {
    const s = secret(7);
    await run(["seal", "tok_abc123", "--epochs", s, "--domains", "a.test"]);
    const frag = logged().trim();
    expect(frag).toMatch(/^[A-Za-z0-9_-]+$/);

    logSpy.mockClear();
    await run(["open", frag, "--epochs", s, "--domains", "a.test"]);
    expect(logged()).toMatch(/kind: 1/);
    expect(logged()).toMatch(/exp: {2}0/);
    expect(logged()).toMatch(/data: tok_abc123/);
  });

  it("round-trips a password-protected link", async () => {
    const s = secret(7);
    await run([
      "seal", "pw_tok", "--password", "hunter2",
      "--epochs", s, "--domains", "a.test",
    ]);
    const frag = logged().trim();

    logSpy.mockClear();
    await run([
      "open", frag, "--password", "hunter2",
      "--epochs", s, "--domains", "a.test",
    ]);
    expect(logged()).toMatch(/data: pw_tok/);
  });

  it("rejects a wrong password with the stable code", async () => {
    const s = secret(7);
    await run([
      "seal", "pw_tok", "--password", "hunter2",
      "--epochs", s, "--domains", "a.test",
    ]);
    const frag = logged().trim();

    await expect(
      run(["open", frag, "--password", "WRONG", "--epochs", s, "--domains", "a.test"])
    ).rejects.toThrow(/BAD_PASSWORD/);
  });

  it("enforces expiry and honors --ignore-expiry", async () => {
    const s = secret(7);
    await run(["seal", "exp_tok", "--exp", "1", "--epochs", s, "--domains", "a.test"]);
    const frag = logged().trim();

    await expect(
      run(["open", frag, "--epochs", s, "--domains", "a.test"])
    ).rejects.toThrow(/EXPIRED/);

    logSpy.mockClear();
    await run([
      "open", frag, "--epochs", s, "--domains", "a.test", "--ignore-expiry",
    ]);
    expect(logged()).toMatch(/data: exp_tok/);
    expect(logged()).toMatch(/exp: {2}1/);
  });

  it("rejects a domain mismatch", async () => {
    const s = secret(7);
    await run(["seal", "tok", "--epochs", s, "--domains", "a.test"]);
    const frag = logged().trim();
    // The whitelist is bound into the AAD (spec 03), so opening under a
    // different whitelist fails the GCM tag — the same MALFORMED_ENVELOPE the
    // native CLI reports (verified against `mosseal-cli open`).
    await expect(
      run(["open", frag, "--epochs", s, "--domains", "b.test"])
    ).rejects.toThrow(/MALFORMED_ENVELOPE/);
  });
});

describe("env fallbacks", () => {
  it("reads epochs/domains from the environment", async () => {
    process.env.MOSSEAL_EPOCHS = secret(9);
    process.env.MOSSEAL_ALLOWED_DOMAINS = "env.test";
    await run(["seal", "env_tok"]);
    const frag = logged().trim();

    logSpy.mockClear();
    await run(["open", frag]);
    expect(logged()).toMatch(/data: env_tok/);
  });

  it("reads epochs/domains from .env", async () => {
    const dir = makeTmp();
    writeFileSync(
      join(dir, ".env"),
      `MOSSEAL_SECRET_0=${secret(5)}\nMOSSEAL_ALLOWED_DOMAINS=file.test\n`
    );
    await run(["seal", "file_tok", "--cwd", dir]);
    const frag = logged().trim();

    logSpy.mockClear();
    await run(["open", frag, "--cwd", dir]);
    expect(logged()).toMatch(/data: file_tok/);
  });

  it("preserves retired holes from .env", async () => {
    const dir = makeTmp();
    // Epoch 1 is a retired hole; sealing uses the latest epoch (2).
    writeFileSync(
      join(dir, ".env"),
      `MOSSEAL_SECRET_0=${secret(1)}\nMOSSEAL_SECRET_2=${secret(3)}\n` +
        `MOSSEAL_ALLOWED_DOMAINS=file.test\n`
    );
    await run(["seal", "hole_tok", "--cwd", dir]);
    const frag = logged().trim();

    logSpy.mockClear();
    await run(["open", frag, "--cwd", dir]);
    expect(logged()).toMatch(/data: hole_tok/);
  });
});

describe("arg validation", () => {
  it("requires a fragment for open", async () => {
    await expect(run(["open"])).rejects.toThrow(/open requires a <fragment>/);
  });

  it("rejects an unknown --kind", async () => {
    await expect(
      run(["seal", "tok", "--kind", "bogus", "--epochs", secret(1), "--domains", "a.test"])
    ).rejects.toThrow(/invalid value 'bogus' for '--kind/);
  });

  it("rejects a non-integer --exp", async () => {
    await expect(
      run(["seal", "tok", "--exp", "abc", "--epochs", secret(1), "--domains", "a.test"])
    ).rejects.toThrow(/invalid value 'abc' for '--exp/);
  });

  it("rejects an empty domain entry (parity with clap value_delimiter)", async () => {
    await expect(
      run(["seal", "tok", "--epochs", secret(1), "--domains", "a.test,"])
    ).rejects.toThrow(/DOMAIN_MISMATCH/);
  });

  it("prints the version for --version", async () => {
    await run(["--version"]);
    expect(logged()).toMatch(/^mosseal \d+\.\d+\.\d+/);
  });

  it("surfaces errors as `<CODE>: <detail>` (parity with the native CLI)", async () => {
    // The bin wrapper prefixes `Error: `; here we assert the message shape the
    // wrapper receives, which is what the native CLI prints after `Error: `.
    await expect(
      run(["seal", "tok", "--epochs", "AAAA", "--domains", "a.test"])
    ).rejects.toThrow(/^EPOCH_RETIRED: /);
  });
});
