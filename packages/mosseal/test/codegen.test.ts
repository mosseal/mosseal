/**
 * `codegen.ts` tests (spec 05 § build step 3, PLAN constraint 1).
 *
 * `obfuse!` only accepts string literals, so the builder emits a Rust source
 * file. These tests pin the generated shape and the defense-in-depth escaping
 * that keeps unvalidated input from breaking the literal or injecting code.
 */
import { describe, expect, it } from "vitest";
import { generateSecretsRs, generateMetaJson } from "../src/codegen.js";
import type { ValidatedConfig } from "../src/env.js";

const CFG: ValidatedConfig = {
  secrets: ["AAAA", "BBBB"],
  domains: ["a.com", "b.com"],
  strictTime: false,
  argonProfile: "minimum",
  timeSources: null,
};

describe("generateSecretsRs", () => {
  it("joins epochs with ';' and domains with ','", () => {
    const rs = generateSecretsRs(CFG);
    expect(rs).toContain('obfuse::obfuse!("AAAA;BBBB")');
    expect(rs).toContain('obfuse::obfuse!("a.com,b.com")');
  });

  it("emits a retired hole as an empty entry", () => {
    const rs = generateSecretsRs({ secrets: ["AAAA", null, "CCCC"], domains: ["x.com"] });
    expect(rs).toContain('obfuse::obfuse!("AAAA;;CCCC")');
  });

  it("exposes the three expected functions", () => {
    const rs = generateSecretsRs(CFG);
    expect(rs).toContain("pub fn epochs_registry_str() -> String");
    expect(rs).toContain("pub fn allowed_domains_str() -> String");
    expect(rs).toContain("pub fn time_sources_str() -> String");
  });

  it("emits an empty time-source literal when there is no override", () => {
    const rs = generateSecretsRs(CFG);
    // Empty → the wasm/template layer uses `DEFAULT_TIME_SOURCES` (spec 07).
    expect(rs).toContain('obfuse::obfuse!("")');
  });

  it("joins time sources with ',' when an override is set", () => {
    const rs = generateSecretsRs({
      secrets: ["AAAA"],
      domains: ["x.com"],
      timeSources: ["https://a.test/t", "https://b.test/t"],
    });
    expect(rs).toContain('obfuse::obfuse!("https://a.test/t,https://b.test/t")');
  });

  it("carries a DO NOT COMMIT banner", () => {
    expect(generateSecretsRs(CFG)).toMatch(/DO NOT COMMIT/);
  });

  it("escapes a double quote so it cannot break the literal", () => {
    const rs = generateSecretsRs({ secrets: ['a"b'], domains: ["x.com"] });
    expect(rs).toContain('obfuse::obfuse!("a\\"b")');
    expect(rs).not.toContain('obfuse::obfuse!("a"b")');
  });

  it("escapes a backslash", () => {
    const rs = generateSecretsRs({ secrets: ["a\\b"], domains: ["x.com"] });
    expect(rs).toContain('obfuse::obfuse!("a\\\\b")');
  });

  it("escapes control characters as \\u{..}", () => {
    const rs = generateSecretsRs({ secrets: ["a\u0000b"], domains: ["x.com"] });
    expect(rs).toContain("\\u{0}");
  });

  it("escapes newlines so the literal stays on one line", () => {
    const rs = generateSecretsRs({ secrets: ["a\nb"], domains: ["x.com"] });
    expect(rs).toContain('obfuse::obfuse!("a\\nb")');
  });
});

describe("generateMetaJson", () => {
  it("emits provenance without any secret material", () => {
    const json = generateMetaJson(CFG, "fingerprint123", "0.1.0");
    const meta = JSON.parse(json);
    expect(meta).toMatchObject({
      generator: "mosseal",
      version: "0.1.0",
      epochs: 2,
      epochSlots: 2,
      argonProfile: "minimum",
      strictTime: false,
      domains: ["a.com", "b.com"],
      fingerprint: "fingerprint123",
    });
    expect(json).not.toContain("AAAA");
    expect(json).not.toContain("BBBB");
  });

  it("counts active epochs separately from slots", () => {
    const meta = JSON.parse(
      generateMetaJson(
        { ...CFG, secrets: ["AAAA", null, "CCCC"] },
        "fp",
        "0.1.0"
      )
    );
    expect(meta.epochs).toBe(2);
    expect(meta.epochSlots).toBe(3);
  });

  it("ends with a trailing newline", () => {
    expect(generateMetaJson(CFG, "fp", "0.1.0").endsWith("\n")).toBe(true);
  });
});
