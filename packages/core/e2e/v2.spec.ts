/**
 * v2 browser coverage (spec 08 § browser suite; PLAN §5 matrix): multi
 * roundtrip / wrong password / slot cap, deniable links in both cover modes
 * with exact size classes, cross-host domain binding across all v2 modes,
 * per-slot expiry under the lenient/strict matrix, and the v2
 * commitment-tamper vector.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mockTimeSources, openHarness, WHITELISTED } from "./helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(
    join(HERE, "..", "..", "..", "crates", "mosseal-vectors", "vectors.json"),
    "utf8"
  )
);

/** Unpadded base64url: wire byte length = floor(chars * 3 / 4). */
const b64Bytes = (fragment: string) => Math.floor((fragment.length * 3) / 4);

test.describe("conformance vectors replay in the browser (spec 08 § matrix)", () => {
  // Every recorded roundtrip vector — v1 (permanent read path) and v2 —
  // must open through the browser wasm with the vector clock mocked
  // (expiring vectors pinned at the vectors' `now`).
  for (const vector of VECTORS.vectors.filter(
    (v: { type: string }) => v.type === "roundtrip"
  )) {
    test(`roundtrip vector ${vector.name}`, async ({ browser }) => {
      const ctx = await browser.newContext();
      const page = await openHarness(ctx, WHITELISTED[0]);
      await mockTimeSources(page, VECTORS.now);
      const res = await page.evaluate(
        ({ f, password }) => window.__mosseal!.openFragment(f, password ? { password } : {}),
        { f: vector.expectFragment, password: vector.input.password }
      );
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.value.data).toBe(vector.expectOpen.data);
        expect(res.value.exp).toBe(vector.expectOpen.exp);
        expect(res.value.kind).toBe(vector.expectOpen.kind === 1 ? "token" : "binary_blob");
      }
      await ctx.close();
    });
  }
});

test.describe("v2 single links (browser)", () => {
  test("v2 fragment round-trips across whitelisted hosts", async ({ browser }) => {
    const [hostA, hostB] = WHITELISTED;
    const ctxA = await browser.newContext();
    const pageA = await openHarness(ctxA, hostA);
    const fragment = await pageA.evaluate(
      (token) => window.__mosseal!.sealFragment({ data: token }),
      "tok_v2_browser"
    );
    await ctxA.close();

    const ctxB = await browser.newContext();
    const pageB = await openHarness(ctxB, hostB);
    const res = await pageB.evaluate(
      (f) => window.__mosseal!.openFragment(f),
      fragment
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.data).toBe("tok_v2_browser");
      expect(res.value.kind).toBe("token");
    }
    await ctxB.close();
  });

  test("commitment-tamper vector fails MALFORMED_ENVELOPE", async ({ browser }) => {
    const vector = VECTORS.vectors.find(
      (v: { name: string }) => v.name === "v2-commitment-missing"
    );
    expect(vector).toBeDefined();
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, WHITELISTED[0]);
    const res = await page.evaluate(
      (f) => window.__mosseal!.openFragment(f),
      vector.open.fragment
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("MALFORMED_ENVELOPE");
    await ctx.close();
  });
});

test.describe("multi links (browser)", () => {
  const SLOTS = [
    { password: "pw-one", data: "secret_one", kind: "token" },
    { password: "pw-two", data: "secret_two", kind: "binary_blob" },
  ];

  test("each password opens its own slot across hosts; wrong password fails", async ({
    browser,
  }) => {
    const [hostA, hostB] = WHITELISTED;
    const ctxA = await browser.newContext();
    const pageA = await openHarness(ctxA, hostA);
    const fragment = await pageA.evaluate(
      (slots) => window.__mosseal!.sealFragment({ slots }),
      SLOTS
    );
    await ctxA.close();

    const ctxB = await browser.newContext();
    const pageB = await openHarness(ctxB, hostB);
    for (const slot of SLOTS) {
      const res = await pageB.evaluate(
        ({ f, password }) => window.__mosseal!.openFragment(f, { password }),
        { f: fragment, password: slot.password }
      );
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.value.data).toBe(slot.data);
        expect(res.value.kind).toBe(slot.kind);
      }
    }

    const wrong = await pageB.evaluate(
      (f) => window.__mosseal!.openFragment(f, { password: "WRONG" }),
      fragment
    );
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.code).toBe("BAD_PASSWORD");
    await ctxB.close();
  });

  test("slot count over the cap fails TOO_MANY_SLOTS", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, WHITELISTED[0]);
    const res = await page.evaluate(() => {
      try {
        const slots = Array.from({ length: 5 }, (_, i) => ({
          password: `pw-${i}`,
          data: "x",
        }));
        return { ok: true, fragment: window.__mosseal!.sealFragment({ slots }) };
      } catch (e) {
        const err = e as { code?: string; message?: string };
        return { ok: false, code: err.code ?? err.message ?? String(e) };
      }
    });
    expect(res.ok).toBe(false);
    expect(String(res.code)).toContain("TOO_MANY_SLOTS");
    await ctx.close();
  });

  test("per-slot expiry is enforced against net time (lenient matrix)", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, WHITELISTED[0]);
    await mockTimeSources(page, Math.floor(Date.now() / 1000));

    const nowSecs = Math.floor(Date.now() / 1000);
    const future = await page.evaluate(
      (exp) =>
        window.__mosseal!.sealFragment({
          slots: [{ password: "pw", data: "future_secret", expSecs: exp }],
        }),
      nowSecs + 3600
    );
    const okRes = await page.evaluate(
      (f) => window.__mosseal!.openFragment(f, { password: "pw" }),
      future
    );
    expect(okRes.ok).toBe(true);

    const past = await page.evaluate(
      (exp) =>
        window.__mosseal!.sealFragment({
          slots: [{ password: "pw", data: "past_secret", expSecs: exp }],
        }),
      nowSecs - 3600
    );
    const expiredRes = await page.evaluate(
      (f) => window.__mosseal!.openFragment(f, { password: "pw" }),
      past
    );
    expect(expiredRes.ok).toBe(false);
    if (!expiredRes.ok) expect(expiredRes.code).toBe("EXPIRED");
    await ctx.close();
  });
});

test.describe("deniable links (browser)", () => {
  test("plain cover: hidden secret opens cross-host; normal open shows only the cover", async ({
    browser,
  }) => {
    const [hostA, hostB] = WHITELISTED;
    const ctxA = await browser.newContext();
    const pageA = await openHarness(ctxA, hostA);
    const fragment = await pageA.evaluate(() =>
      window.__mosseal!.sealDeniable({
        cover: { mode: "plain" },
        hidden: { password: "hidden-pw", data: "hidden_secret_browser" },
      })
    );
    await ctxA.close();
    // Size class is exact: small hidden envelope → 1 KiB wire (D5).
    expect(b64Bytes(fragment)).toBe(1024);

    const ctxB = await browser.newContext();
    const pageB = await openHarness(ctxB, hostB);
    const hidden = await pageB.evaluate(
      (f) => window.__mosseal!.openHidden(f, { hiddenPassword: "hidden-pw" }),
      fragment
    );
    expect(hidden.ok).toBe(true);
    if (hidden.ok) {
      expect(hidden.value.data).toBe("hidden_secret_browser");
      expect(hidden.value.kind).toBe("token");
    }

    // A normal open never probes for the hidden layer: opaque cover blob.
    const cover = await pageB.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(cover.ok).toBe(true);
    if (cover.ok) {
      expect(cover.value.kind).toBe("binary_blob");
      expect(cover.value.data).not.toContain("hidden_secret_browser");
    }

    // Wrong hidden password is indistinguishable from an absent layer.
    const wrong = await pageB.evaluate(
      (f) => window.__mosseal!.openHidden(f, { hiddenPassword: "WRONG" }),
      fragment
    );
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.code).toBe("BAD_PASSWORD");
    await ctxB.close();
  });

  test("hidden cover: needs both passwords; a 2 KiB class link is exact", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, WHITELISTED[0]);
    const fragment = await page.evaluate(() =>
      window.__mosseal!.sealDeniable({
        cover: { mode: "hidden", password: "cover-pw" },
        hidden: { password: "hidden-pw", data: "x".repeat(1500) },
        sizeClass: 2,
      })
    );
    expect(b64Bytes(fragment)).toBe(2048);

    const noCover = await page.evaluate(
      (f) => window.__mosseal!.openHidden(f, { hiddenPassword: "hidden-pw" }),
      fragment
    );
    expect(noCover.ok).toBe(false);
    if (!noCover.ok) expect(noCover.code).toBe("BAD_PASSWORD");

    const both = await page.evaluate(
      (f) =>
        window.__mosseal!.openHidden(f, {
          coverPassword: "cover-pw",
          hiddenPassword: "hidden-pw",
        }),
      fragment
    );
    expect(both.ok).toBe(true);
    if (both.ok) expect(both.value.data.length).toBe(1500);
    await ctx.close();
  });

  test("hidden multi slot: the hidden password locates and opens its slot", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, WHITELISTED[0]);
    const fragment = await page.evaluate(() =>
      window.__mosseal!.sealDeniable({
        cover: { mode: "plain" },
        hidden: {
          password: "hpw",
          slots: [
            { password: "hpw", data: "hidden_slot_zero" },
            { password: "other", data: "hidden_slot_one" },
          ],
        },
      })
    );
    const out = await page.evaluate(
      (f) => window.__mosseal!.openHidden(f, { hiddenPassword: "hpw" }),
      fragment
    );
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.value.data).toBe("hidden_slot_zero");
    // Single-locator limitation (spec 09): another slot's password cannot
    // even locate the layer.
    const other = await page.evaluate(
      (f) => window.__mosseal!.openHidden(f, { hiddenPassword: "other" }),
      fragment
    );
    expect(other.ok).toBe(false);
    if (!other.ok) expect(other.code).toBe("BAD_PASSWORD");
    await ctx.close();
  });
});
