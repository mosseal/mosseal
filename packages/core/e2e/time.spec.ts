/**
 * Net-time strict/lenient matrix (spec 07, spec 08 § browser suite).
 *
 * The three default time sources are mocked via `page.route` (bodies match the
 * parsers in `mosseal-core/src/time.rs`), or aborted to simulate an
 * unreachable network. Strict mode is a compile-time flag, so its cases run
 * against the separately-built `strict.html` harness.
 */
import { test, expect } from "@playwright/test";
import {
  openHarness,
  mockTimeSources,
  mockCustomTimeSource,
  TOKEN,
  WHITELISTED,
} from "./helpers.js";

/** "Now" close to browser time; the 30 s accept-skew absorbs the difference. */
const NOW = Math.floor(Date.now() / 1000);
const HOST = WHITELISTED[0];

/** Seal a token with `expSecs` and return the fragment value. */
async function sealExpiring(page: import("@playwright/test").Page, expSecs: number) {
  return page.evaluate(
    ([token, exp]) => window.__mosseal!.sealFragment({ data: token, expSecs: exp }),
    [TOKEN, expSecs] as const
  );
}

test.describe("net-time matrix (spec 07)", () => {
  test("lenient + reachable net time → opens (expiry honored)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST);
    await mockTimeSources(page, NOW);
    const fragment = await sealExpiring(page, NOW + 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(true);
    await ctx.close();
  });

  test("lenient + unreachable net time → falls back to system clock", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST);
    await mockTimeSources(page, null); // abort every source
    const fragment = await sealExpiring(page, NOW + 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(true);
    await ctx.close();
  });

  test("lenient + expired link → EXPIRED (net time is authoritative)", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST);
    await mockTimeSources(page, NOW);
    const fragment = await sealExpiring(page, NOW - 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("EXPIRED");
    await ctx.close();
  });

  test("strict + reachable net time → opens", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST, { variant: "strict" });
    await mockTimeSources(page, NOW);
    const fragment = await sealExpiring(page, NOW + 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(true);
    await ctx.close();
  });

  test("strict + unreachable net time → STRICT_TIME_UNAVAILABLE (no fallback)", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST, { variant: "strict" });
    await mockTimeSources(page, null);
    const fragment = await sealExpiring(page, NOW + 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("STRICT_TIME_UNAVAILABLE");
    await ctx.close();
  });

  test("exp = 0 never fetches net time (opens offline even in strict mode)", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST, { variant: "strict" });
    await mockTimeSources(page, null); // network is "down"
    const fragment = await page.evaluate(
      (token) => window.__mosseal!.sealFragment({ data: token }), // no expSecs
      TOKEN
    );
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.value.exp).toBe(0);
    await ctx.close();
  });
});

/**
 * N1: the baked `MOSSEAL_TIME_SOURCES` override must be the list the wasm
 * actually consults — the default hosts are never contacted (spec 07).
 */
test.describe("custom time source (N1, spec 07)", () => {
  test("the custom source is consulted, not the defaults", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST, { variant: "custom" });

    // Fail loudly if any default host is contacted at all.
    let defaultHit = false;
    for (const host of ["cloudflare.com", "timeapi.io", "worldtimeapi.org"] as const) {
      await page.route(`https://${host}/**`, async (route) => {
        defaultHit = true;
        await route.abort("failed");
      });
    }
    const custom = await mockCustomTimeSource(page, NOW);

    const fragment = await sealExpiring(page, NOW + 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(true);
    expect(custom.requested.length).toBeGreaterThan(0);
    expect(defaultHit).toBe(false);
    await ctx.close();
  });

  test("custom source honored for expiry → EXPIRED when it reports past", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST, { variant: "custom" });
    await mockCustomTimeSource(page, NOW);
    const fragment = await sealExpiring(page, NOW - 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("EXPIRED");
    await ctx.close();
  });

  test("unreachable custom source → lenient falls back to system clock", async ({
    browser,
  }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, HOST, { variant: "custom" });
    await mockCustomTimeSource(page, null); // abort the only source
    const fragment = await sealExpiring(page, NOW + 3600);
    const res = await page.evaluate((f) => window.__mosseal!.openFragment(f), fragment);
    expect(res.ok).toBe(true);
    await ctx.close();
  });
});
