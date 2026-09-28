/**
 * `env.ts` validation tests (spec 05 § build flow step 1).
 *
 * These guard the fail-fast contract: every invalid env must throw an
 * actionable message BEFORE wasm-pack runs, because `env!()` compile errors
 * are cryptic.
 */
import { describe, expect, it } from "vitest";
import { validateEnv, configFingerprint, ARGON2_PROFILES } from "../src/env.js";

/** A valid 32-byte base64url secret. */
function secret(seed = 0): string {
  return Buffer.alloc(32, seed).toString("base64url");
}

const BASE = {
  MOSSEAL_SECRET_0: secret(1),
  MOSSEAL_ALLOWED_DOMAINS: "example.com",
};

describe("validateEnv — epoch secrets", () => {
  it("accepts a single contiguous epoch", () => {
    const { config } = validateEnv({ ...BASE });
    expect(config.secrets).toEqual([secret(1)]);
  });

  it("accepts multiple contiguous epochs", () => {
    const { config } = validateEnv({
      ...BASE,
      MOSSEAL_SECRET_1: secret(2),
      MOSSEAL_SECRET_2: secret(3),
    });
    expect(config.secrets).toEqual([secret(1), secret(2), secret(3)]);
  });

  it("throws when MOSSEAL_SECRET_0 is missing", () => {
    expect(() => validateEnv({ MOSSEAL_ALLOWED_DOMAINS: "example.com" })).toThrow(
      /No MOSSEAL_SECRET_0/
    );
  });

  it("throws on a non-base64url secret", () => {
    expect(() =>
      validateEnv({ ...BASE, MOSSEAL_SECRET_0: "not valid!!" })
    ).toThrow(/not valid base64url/);
  });

  it("throws when a secret does not decode to 32 bytes", () => {
    expect(() =>
      validateEnv({ ...BASE, MOSSEAL_SECRET_0: Buffer.alloc(16).toString("base64url") })
    ).toThrow(/exactly 32 bytes/);
  });

  it("throws on a gap in the epoch list (0 then 2)", () => {
    // A gap is now a RETIRED hole, not an error: the slot is preserved so
    // epoch 2 keeps its index (spec 02 § Key epochs).
    const { config } = validateEnv({
      ...BASE,
      MOSSEAL_SECRET_2: secret(3),
    });
    expect(config.secrets).toEqual([secret(1), null, secret(3)]);
  });

  it("trims trailing holes", () => {
    const { config } = validateEnv({ ...BASE, MOSSEAL_SECRET_1: "" });
    expect(config.secrets).toEqual([secret(1)]);
  });

  it("preserves an interior hole between active epochs", () => {
    const { config } = validateEnv({
      ...BASE,
      MOSSEAL_SECRET_2: secret(3),
      MOSSEAL_SECRET_3: secret(4),
    });
    expect(config.secrets).toEqual([secret(1), null, secret(3), secret(4)]);
  });
});

describe("validateEnv — allowed domains", () => {
  it("throws when MOSSEAL_ALLOWED_DOMAINS is missing", () => {
    expect(() => validateEnv({ MOSSEAL_SECRET_0: secret(1) })).toThrow(
      /MOSSEAL_ALLOWED_DOMAINS is required/
    );
  });

  it("throws when MOSSEAL_ALLOWED_DOMAINS is blank", () => {
    expect(() =>
      validateEnv({ ...BASE, MOSSEAL_ALLOWED_DOMAINS: "   " })
    ).toThrow(/MOSSEAL_ALLOWED_DOMAINS is required/);
  });

  it("splits, trims, and drops empty entries", () => {
    const { config } = validateEnv({
      ...BASE,
      MOSSEAL_ALLOWED_DOMAINS: " a.com , b.com ,, ",
    });
    expect(config.domains).toEqual(["a.com", "b.com"]);
  });

  it("rejects a scheme/port/path hostname", () => {
    for (const bad of ["https://a.com", "a.com:443", "a.com/path", "A.COM"]) {
      expect(() =>
        validateEnv({ ...BASE, MOSSEAL_ALLOWED_DOMAINS: bad })
      ).toThrow(/Invalid hostname/);
    }
  });

  it("warns (but accepts) localhost", () => {
    const { warnings } = validateEnv({ ...BASE, MOSSEAL_ALLOWED_DOMAINS: "localhost" });
    expect(warnings.some((w) => /localhost/.test(w))).toBe(true);
  });
});

describe("validateEnv — strict time", () => {
  it("defaults to lenient", () => {
    expect(validateEnv({ ...BASE }).config.strictTime).toBe(false);
  });

  it("parses true/false case-insensitively", () => {
    expect(validateEnv({ ...BASE, MOSSEAL_STRICT_TIME: "TRUE" }).config.strictTime).toBe(true);
    expect(validateEnv({ ...BASE, MOSSEAL_STRICT_TIME: "False" }).config.strictTime).toBe(false);
  });

  it("throws on a non-boolean value", () => {
    expect(() => validateEnv({ ...BASE, MOSSEAL_STRICT_TIME: "yes" })).toThrow(
      /MOSSEAL_STRICT_TIME must be/
    );
  });
});

describe("validateEnv — argon2 profile", () => {
  it("defaults to minimum", () => {
    expect(validateEnv({ ...BASE }).config.argonProfile).toBe("minimum");
  });

  it("accepts every declared profile", () => {
    for (const p of ARGON2_PROFILES) {
      expect(validateEnv({ ...BASE, MOSSEAL_ARGON2_PROFILE: p }).config.argonProfile).toBe(p);
    }
  });

  it("throws on an unknown profile", () => {
    expect(() => validateEnv({ ...BASE, MOSSEAL_ARGON2_PROFILE: "paranoid" })).toThrow(
      /MOSSEAL_ARGON2_PROFILE must be one of/
    );
  });
});

describe("validateEnv — time sources", () => {
  it("defaults to null", () => {
    expect(validateEnv({ ...BASE }).config.timeSources).toBeNull();
  });

  it("parses an https list and warns", () => {
    const { config, warnings } = validateEnv({
      ...BASE,
      MOSSEAL_TIME_SOURCES: "https://a.test/t, https://b.test/t",
    });
    expect(config.timeSources).toEqual(["https://a.test/t", "https://b.test/t"]);
    expect(warnings.some((w) => /TIME_SOURCES override/.test(w))).toBe(true);
  });

  it("rejects a non-https source", () => {
    expect(() =>
      validateEnv({ ...BASE, MOSSEAL_TIME_SOURCES: "http://a.test/t" })
    ).toThrow(/must be https/);
  });

  it("rejects an unparseable URL", () => {
    expect(() =>
      validateEnv({ ...BASE, MOSSEAL_TIME_SOURCES: "not a url" })
    ).toThrow(/not a valid URL/);
  });
});

describe("configFingerprint", () => {
  it("is stable for identical config", () => {
    const a = validateEnv({ ...BASE }).config;
    const b = validateEnv({ ...BASE }).config;
    expect(configFingerprint(a)).toBe(configFingerprint(b));
  });

  it("changes when a secret changes", () => {
    const a = validateEnv({ ...BASE }).config;
    const b = validateEnv({ ...BASE, MOSSEAL_SECRET_0: secret(9) }).config;
    expect(configFingerprint(a)).not.toBe(configFingerprint(b));
  });

  it("is order-independent for domains", () => {
    const a = validateEnv({ ...BASE, MOSSEAL_ALLOWED_DOMAINS: "a.com,b.com" }).config;
    const b = validateEnv({ ...BASE, MOSSEAL_ALLOWED_DOMAINS: "b.com,a.com" }).config;
    expect(configFingerprint(a)).toBe(configFingerprint(b));
  });

  it("never contains raw secret material", () => {
    const cfg = validateEnv({ ...BASE }).config;
    expect(configFingerprint(cfg)).not.toContain(cfg.secrets[0]);
  });

  it("is stable across a retired hole", () => {
    const a = validateEnv({ ...BASE, MOSSEAL_SECRET_2: secret(3) }).config;
    const b = validateEnv({ ...BASE, MOSSEAL_SECRET_2: secret(3) }).config;
    expect(configFingerprint(a)).toBe(configFingerprint(b));
  });
});
