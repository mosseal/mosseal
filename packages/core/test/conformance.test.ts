/**
 * Cross-target conformance suite (spec 08).
 *
 * Reproduces the native-generated `vectors.json` byte-exactly against the
 * REAL wasm (nodejs target, `conformance` feature). This is the core guard
 * against dual-runtime KDF divergence — any mismatch silently bricks links.
 *
 * The conformance wasm is built on demand (idempotent) with the FIXED test
 * secrets from `vectors.json`, never the consumer's.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { buildConformanceWasm } from "./build-conformance-wasm.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const VECTORS = JSON.parse(
  readFileSync(join(REPO_ROOT, "crates", "mosseal-vectors", "vectors.json"), "utf8")
);

interface RoundtripVector {
  name: string;
  type: "roundtrip";
  input: { data: string; kind: number; expSecs: number | null; password: string | null };
  deterministic: { salt: string; nonce: string; epoch: number | null };
  expectFragment: string;
  expectOpen: { data: string; exp: number; kind: number };
  openWithTime: number | null;
}

interface OpenErrorVector {
  name: string;
  type: "open-error";
  open: { fragment: string; password: string | null; nowSecs: number | null };
  expectError: string;
}

interface SealErrorVector {
  name: string;
  type: "seal-error";
  input: { dataLen: number; kind: number; expSecs: number | null; password: string | null };
  expectError: string;
}

type Vector = RoundtripVector | OpenErrorVector | SealErrorVector;

interface ConformanceMosseal {
  sealDeterministic(
    data: string,
    password: string | null,
    expSecs: number | null,
    kind: number | null,
    saltHex: string,
    nonceHex: string,
    epoch?: number | null
  ): string;
  open(link: string, password?: string | null): Promise<{ data: string; exp: number; kind: number }>;
  openWithTime(
    link: string,
    password: string | null,
    nowSecs: number
  ): Promise<{ data: string; exp: number; kind: number }>;
}

let wasm: ConformanceMosseal;

beforeAll(async () => {
  const dir = buildConformanceWasm();
  const mod = await import(join(dir, "mosseal_wasm.js"));
  wasm = new mod.Mosseal();
}, 120_000);

const vectors = VECTORS.vectors as Vector[];

describe("conformance vectors (spec 08)", () => {
  const roundtrips = vectors.filter((v): v is RoundtripVector => v.type === "roundtrip");
  const openErrors = vectors.filter((v): v is OpenErrorVector => v.type === "open-error");
  const sealErrors = vectors.filter((v): v is SealErrorVector => v.type === "seal-error");

  it("has vectors of every kind", () => {
    expect(roundtrips.length).toBeGreaterThan(0);
    expect(openErrors.length).toBeGreaterThan(0);
    expect(sealErrors.length).toBeGreaterThan(0);
  });

  describe("seal reproduces native byte-exactly", () => {
    for (const v of roundtrips) {
      it(v.name, () => {
        const fragment = wasm.sealDeterministic(
          v.input.data,
          v.input.password,
          v.input.expSecs,
          v.input.kind,
          v.deterministic.salt,
          v.deterministic.nonce,
          v.deterministic.epoch
        );
        expect(fragment).toBe(v.expectFragment);
      });
    }
  });

  describe("open reproduces native output", () => {
    for (const v of roundtrips) {
      it(v.name, async () => {
        const out =
          v.openWithTime === null
            ? await wasm.open(v.expectFragment, v.input.password)
            : await wasm.openWithTime(v.expectFragment, v.input.password, v.openWithTime);
        expect(out.data).toBe(v.expectOpen.data);
        expect(out.exp).toBe(v.expectOpen.exp);
        expect(out.kind).toBe(v.expectOpen.kind);
      });
    }
  });

  describe("open errors match the taxonomy", () => {
    for (const v of openErrors) {
      it(v.name, async () => {
        const call =
          v.open.nowSecs === null
            ? wasm.open(v.open.fragment, v.open.password)
            : wasm.openWithTime(v.open.fragment, v.open.password, v.open.nowSecs);
        await expect(call).rejects.toThrow(v.expectError);
      });
    }
  });

  describe("seal errors match the taxonomy", () => {
    for (const v of sealErrors) {
      it(v.name, () => {
        expect(() =>
          wasm.sealDeterministic(
            "x".repeat(v.input.dataLen),
            v.input.password,
            v.input.expSecs,
            v.input.kind,
            "00".repeat(16),
            "00".repeat(12),
            null
          )
        ).toThrow(v.expectError);
      });
    }
  });
});