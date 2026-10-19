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
  deterministic: { salt: string; nonce: string; epoch: number | null; version: number };
  expectFragment: string;
  expectOpen: { data: string; exp: number; kind: number };
  openWithTime: number | null;
}

interface MultiRoundtripVector {
  name: string;
  type: "multi-roundtrip";
  input: {
    slots: { password: string; data: string; kind: number; expSecs: number | null }[];
  };
  expectFragment: string;
  openWithTime: number | null;
  expectOpen: { password: string; data: string; exp: number; kind: number };
}

interface DeniableRoundtripVector {
  name: string;
  type: "deniable-roundtrip";
  input: {
    cover: { mode: "hidden" | "plain"; password: string | null; decoy: string | null };
    hiddenPassword: string;
    hidden: { data: string; kind: number; expSecs: number | null };
    sizeClass: number;
  };
  expectFragment: string;
  expectOpen: { coverPassword: string | null; data: string; exp: number; kind: number };
}

interface OpenErrorVector {
  name: string;
  type: "open-error";
  open: { fragment: string; password: string | null; nowSecs: number | null };
  expectError: string;
}

interface OpenHiddenErrorVector {
  name: string;
  type: "open-hidden-error";
  open: { fragment: string; coverPassword: string | null; hiddenPassword: string };
  expectError: string;
}

interface SealErrorVector {
  name: string;
  type: "seal-error";
  input: { dataLen: number; kind: number; expSecs: number | null; password: string | null };
  expectError: string;
}

interface SealMultiErrorVector {
  name: string;
  type: "seal-multi-error";
  input: { slots: number };
  expectError: string;
}

type Vector =
  | RoundtripVector
  | MultiRoundtripVector
  | DeniableRoundtripVector
  | OpenErrorVector
  | OpenHiddenErrorVector
  | SealErrorVector
  | SealMultiErrorVector;

interface ConformanceMosseal {
  sealDeterministic(
    data: string,
    password: string | null,
    expSecs: number | null,
    kind: number | null,
    saltHex: string,
    nonceHex: string,
    epoch?: number | null,
    version?: number | null
  ): string;
  sealMulti(slots: unknown, expSecs: number | null): string;
  sealDeniable(cover: unknown, hidden: unknown, sizeClass: number | null): string;
  open(link: string, password?: string | null): Promise<{ data: string; exp: number; kind: number }>;
  openHidden(
    link: string,
    coverPassword: string | null,
    hiddenPassword: string | null
  ): Promise<{ data: string; exp: number; kind: number }>;
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
  const multiRoundtrips = vectors.filter(
    (v): v is MultiRoundtripVector => v.type === "multi-roundtrip"
  );
  const deniableRoundtrips = vectors.filter(
    (v): v is DeniableRoundtripVector => v.type === "deniable-roundtrip"
  );
  const openErrors = vectors.filter((v): v is OpenErrorVector => v.type === "open-error");
  const openHiddenErrors = vectors.filter(
    (v): v is OpenHiddenErrorVector => v.type === "open-hidden-error"
  );
  const sealErrors = vectors.filter((v): v is SealErrorVector => v.type === "seal-error");
  const sealMultiErrors = vectors.filter(
    (v): v is SealMultiErrorVector => v.type === "seal-multi-error"
  );

  it("has vectors of every kind", () => {
    expect(roundtrips.length).toBeGreaterThan(0);
    expect(multiRoundtrips.length).toBeGreaterThan(0);
    expect(deniableRoundtrips.length).toBeGreaterThan(0);
    expect(openErrors.length).toBeGreaterThan(0);
    expect(openHiddenErrors.length).toBeGreaterThan(0);
    expect(sealErrors.length).toBeGreaterThan(0);
    expect(sealMultiErrors.length).toBeGreaterThan(0);
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
          v.deterministic.epoch,
          v.deterministic.version
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

  describe("multi vectors: open matches native output", () => {
    for (const v of multiRoundtrips) {
      it(v.name, async () => {
        // Open the native-recorded fragment through the wasm multi path
        // (receiver-side conformance; seal reproduction is native-gated).
        // Slot expiry is checked against the recorded vector clock.
        const out =
          v.openWithTime === null
            ? await wasm.open(v.expectFragment, v.expectOpen.password)
            : await wasm.openWithTime(v.expectFragment, v.expectOpen.password, v.openWithTime);
        expect(out.data).toBe(v.expectOpen.data);
        expect(out.exp).toBe(v.expectOpen.exp);
        expect(out.kind).toBe(v.expectOpen.kind);

        // Functional wasm-side roundtrip: sealMulti → open each slot (with
        // the vector clock so recorded expiries stay in the future).
        const frag = wasm.sealMulti(
          v.input.slots.map((s) => ({
            password: s.password,
            data: s.data,
            kind: s.kind,
            expSecs: s.expSecs,
          })),
          null
        );
        const now = VECTORS.now as number;
        for (const s of v.input.slots) {
          const o = await wasm.openWithTime(frag, s.password, now);
          expect(o.data).toBe(s.data);
          expect(o.kind).toBe(s.kind);
        }
      });
    }
  });

  describe("deniable vectors: hidden open matches native output", () => {
    for (const v of deniableRoundtrips) {
      it(v.name, async () => {
        // Hidden open of the native-recorded fragment (receiver-side).
        const out = await wasm.openHidden(
          v.expectFragment,
          v.input.cover.password,
          v.input.hiddenPassword
        );
        expect(out.data).toBe(v.expectOpen.data);
        expect(out.exp).toBe(v.expectOpen.exp);
        expect(out.kind).toBe(v.expectOpen.kind);

        // Functional wasm-side roundtrip: sealDeniable → openHidden.
        const frag = wasm.sealDeniable(
          {
            mode: v.input.cover.mode,
            password: v.input.cover.password,
            decoy: v.input.cover.decoy ?? undefined,
          },
          {
            password: v.input.hiddenPassword,
            data: v.input.hidden.data,
            kind: v.input.hidden.kind,
            expSecs: v.input.hidden.expSecs,
          },
          v.input.sizeClass
        );
        const o = await wasm.openHidden(
          frag,
          v.input.cover.password,
          v.input.hiddenPassword
        );
        expect(o.data).toBe(v.expectOpen.data);
        // Size class is exact regardless of secret count (D5). Unpadded
        // base64url: byte length = floor(chars * 3 / 4).
        expect(Math.floor((frag.length * 3) / 4)).toBe(v.input.sizeClass * 1024);
      });
    }
  });

  describe("hidden open errors match the taxonomy", () => {
    for (const v of openHiddenErrors) {
      it(v.name, async () => {
        await expect(
          wasm.openHidden(v.open.fragment, v.open.coverPassword, v.open.hiddenPassword)
        ).rejects.toThrow(v.expectError);
      });
    }
  });

  describe("seal-multi errors match the taxonomy", () => {
    for (const v of sealMultiErrors) {
      it(v.name, () => {
        const slots = Array.from({ length: v.input.slots }, (_, i) => ({
          password: `pw-${i}`,
          data: "x",
        }));
        expect(() => wasm.sealMulti(slots, null)).toThrow(v.expectError);
      });
    }
  });
});