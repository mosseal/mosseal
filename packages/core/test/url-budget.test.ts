/**
 * URL/QR budget test (spec 08 § URL/QR budget test).
 *
 * A QR-friendly payload (255 B data, password, expiry) must:
 *   - produce a final URL ≤ 512 bytes (spec 01 QR advisory), and
 *   - render a QR that decodes back to the exact same URL (zxing-equivalent
 *     roundtrip via `jsqr`, a pure-JS decoder — no canvas/native deps).
 *
 * 255 B is no longer the v1 payload cap (the envelope now uses a u32 length
 * prefix), but it remains the largest payload that keeps the share URL within
 * the 512-byte QR advisory budget.
 *
 * The QR is rasterized from the module matrix produced by `qrcode` into a
 * plain RGBA buffer, so the whole test runs in Node with no DOM.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { join } from "node:path";
import QRCode from "qrcode";
import jsQR from "jsqr";
import { buildConformanceWasm } from "./build-conformance-wasm.mjs";

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
}

let wasm: ConformanceMosseal;

beforeAll(async () => {
  const dir = buildConformanceWasm();
  const mod = await import(join(dir, "mosseal_wasm.js"));
  wasm = new mod.Mosseal();
}, 120_000);

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** 255 bytes — the largest payload that stays within the 512-byte QR budget. */
function qrBudgetPayload(): string {
  let s = "";
  while (s.length < 255) s += B64URL;
  return s.slice(0, 255);
}

const SALT = "00".repeat(16);
const NONCE = "00".repeat(12);
const BASE = "https://user.github.io/app/";

/**
 * Rasterize a QR module matrix into an RGBA buffer with a quiet zone.
 * `modules.data` is a `Uint8Array` of 0/1 per module (row-major).
 */
function rasterize(
  data: Uint8Array,
  size: number,
  scale = 4,
  quiet = 4
): { img: Uint8ClampedArray; dim: number } {
  const dim = (size + quiet * 2) * scale;
  const img = new Uint8ClampedArray(dim * dim * 4).fill(255); // white
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!data[y * size + x]) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const px = (y + quiet) * scale + dy;
          const py = (x + quiet) * scale + dx;
          const o = (px * dim + py) * 4;
          img[o] = 0;
          img[o + 1] = 0;
          img[o + 2] = 0;
          img[o + 3] = 255;
        }
      }
    }
  }
  return { img, dim };
}

describe("URL/QR budget (spec 08)", () => {
  it("QR-friendly payload (255 B + password) → URL ≤ 512 bytes", () => {
    const fragment = wasm.sealDeterministic(
      qrBudgetPayload(),
      "hunter2",
      null, // exp omitted: expiry is inside the payload, not the URL size driver
      1,
      SALT,
      NONCE,
      null
    );
    const url = `${BASE}#ms=${fragment}`;
    expect(url.length).toBeLessThanOrEqual(512);
    // Sanity: the fragment is the dominant cost and is non-trivial.
    expect(fragment.length).toBeGreaterThan(300);
  });

  it("expiry does not grow the URL (exp lives inside the AEAD payload)", () => {
    const noExp = wasm.sealDeterministic(qrBudgetPayload(), "hunter2", null, 1, SALT, NONCE, null);
    const withExp = wasm.sealDeterministic(
      qrBudgetPayload(),
      "hunter2",
      2_000_000_000,
      1,
      SALT,
      NONCE,
      null
    );
    // exp is a fixed-width u64 inside the payload → same envelope size.
    expect(withExp.length).toBe(noExp.length);
  });

  it("QR roundtrip decodes to the exact same URL", () => {
    const fragment = wasm.sealDeterministic(qrBudgetPayload(), "hunter2", null, 1, SALT, NONCE, null);
    const url = `${BASE}#ms=${fragment}`;

    // Low error-correction keeps the module count (and thus QR version) small.
    const qr = QRCode.create(url, { errorCorrectionLevel: "L" });
    const size = qr.modules.size;
    const { img, dim } = rasterize(qr.modules.data as unknown as Uint8Array, size);

    const decoded = jsQR(img, dim, dim);
    expect(decoded).not.toBeNull();
    expect(decoded!.data).toBe(url);
  });

  it("a scan-sane QR (version ≤ 20) for the QR-friendly payload", () => {
    const fragment = wasm.sealDeterministic(qrBudgetPayload(), "hunter2", null, 1, SALT, NONCE, null);
    const url = `${BASE}#ms=${fragment}`;
    const qr = QRCode.create(url, { errorCorrectionLevel: "L" });
    // Version ≈ (size - 17) / 4; ≤ 20 keeps it comfortably scannable.
    const version = (qr.modules.size - 17) / 4;
    expect(version).toBeLessThanOrEqual(20);
  });
});
