/**
 * Cross-host portability + domain gate (spec 03, spec 08 § browser suite).
 *
 * Whitelisted hosts (`a.test`, `b.test` — the vectors' `domains`) are fulfilled
 * locally by `page.route`, so `location.hostname` is the fake host the wasm
 * gate checks while assets come from the single served harness.
 */
import { test, expect } from "@playwright/test";
import {
  openHarness,
  TOKEN,
  WHITELISTED,
  NOT_WHITELISTED,
} from "./helpers.js";

test.describe("cross-host portability (spec 03)", () => {
  test("a link sealed on one whitelisted host opens on another", async ({ browser }) => {
    const [hostA, hostB] = WHITELISTED;

    const ctxA = await browser.newContext();
    const pageA = await openHarness(ctxA, hostA);
    expect(await pageA.evaluate(() => window.__mosseal!.hostname())).toBe(hostA);
    const fragment = await pageA.evaluate(
      (token) => window.__mosseal!.sealFragment({ data: token, kind: "token" }),
      TOKEN
    );
    expect(fragment.length).toBeGreaterThan(0);
    await ctxA.close();

    const ctxB = await browser.newContext();
    const pageB = await openHarness(ctxB, hostB);
    expect(await pageB.evaluate(() => window.__mosseal!.hostname())).toBe(hostB);
    const res = await pageB.evaluate(
      (u) => window.__mosseal!.openUrl(u),
      `http://${hostB}/index.html#ms=${fragment}`
    );
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.data).toBe(TOKEN);
      expect(res.value.kind).toBe("token");
    }
    await ctxB.close();
  });

  test("a link fails DOMAIN_MISMATCH on a non-whitelisted host", async ({ browser }) => {
    const ctxA = await browser.newContext();
    const pageA = await openHarness(ctxA, WHITELISTED[0]);
    const fragment = await pageA.evaluate(
      (token) => window.__mosseal!.sealFragment({ data: token }),
      TOKEN
    );
    await ctxA.close();

    const ctxC = await browser.newContext();
    const pageC = await openHarness(ctxC, NOT_WHITELISTED);
    const res = await pageC.evaluate(
      (u) => window.__mosseal!.openUrl(u),
      `http://${NOT_WHITELISTED}/index.html#ms=${fragment}`
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("DOMAIN_MISMATCH");
    await ctxC.close();
  });

  test("sealing is blocked on a non-whitelisted host", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, NOT_WHITELISTED);
    // sealFragment throws the raw wasm error (message == the stable code).
    const code = await page.evaluate((token) => {
      try {
        window.__mosseal!.sealFragment({ data: token });
        return null;
      } catch (e) {
        const err = e as { code?: string; message?: string };
        return err.code ?? err.message ?? String(e);
      }
    }, TOKEN);
    expect(String(code)).toContain("DOMAIN_MISMATCH");
    await ctx.close();
  });

  test("URL detection + scrub work in the browser", async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await openHarness(ctx, WHITELISTED[0]);
    const fragment = await page.evaluate(
      (token) => window.__mosseal!.sealFragment({ data: token }),
      TOKEN
    );
    const withFragment = `http://${WHITELISTED[0]}/app#ms=${fragment}`;
    const probe = await page.evaluate(
      (u) => ({
        isMosseal: window.__mosseal!.isMossealUrl(u),
        notMosseal: window.__mosseal!.isMossealUrl("http://x.test/#anchor"),
        scrubbed: window.__mosseal!.scrub(u),
      }),
      withFragment
    );
    expect(probe.isMosseal).toBe(true);
    expect(probe.notMosseal).toBe(false);
    expect(probe.scrubbed).toBe(`http://${WHITELISTED[0]}/app`);
    await ctx.close();
  });
});
