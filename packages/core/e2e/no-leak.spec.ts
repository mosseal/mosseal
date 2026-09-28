/**
 * Network-tab assertion (spec 08): no `#ms=` fragment ever leaves the machine.
 *
 * The fragment lives in `location.hash`, which browsers do not put in the HTTP
 * request line. This test proves the *implementation* never leaks the payload
 * into a request path or query string (the real bug class: appending it as
 * `?ms=…`), by inspecting every outgoing request's path+query — the exact
 * bytes a server would receive.
 */
import { test, expect } from "@playwright/test";
import { openHarness, TOKEN, WHITELISTED } from "./helpers.js";

test("the payload fragment never appears in an outgoing request", async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await openHarness(ctx, WHITELISTED[0]);

  const leaked: string[] = [];
  let seen = 0;
  page.on("request", (req) => {
    seen++;
    try {
      const u = new URL(req.url());
      const wire = u.pathname + u.search; // what a server actually receives
      if (wire.includes("ms=")) leaked.push(wire);
    } catch {
      /* non-URL request (e.g. data:), ignore */
    }
  });

  // Seal, then navigate to a URL carrying the fragment and open from it.
  const fragment = await page.evaluate(
    (token) => window.__mosseal!.sealFragment({ data: token }),
    TOKEN
  );
  const link = `http://${WHITELISTED[0]}/index.html#ms=${fragment}`;
  await page.goto(link);
  await page.waitForFunction(() => window.__mossealReady === true);
  const res = await page.evaluate((u) => window.__mosseal!.openUrl(u), link);
  expect(res.ok).toBe(true);

  // Receiver flow step: scrub the fragment from the address bar.
  const cleaned = await page.evaluate((u) => {
    const clean = window.__mosseal!.scrub(u);
    history.replaceState({}, "", clean);
    return location.href;
  }, link);
  expect(cleaned).not.toContain("#ms=");

  // An ordinary request proves the listener is live (not a vacuous pass).
  await page.evaluate(() => fetch("/index.html").then((r) => r.ok));

  expect(seen).toBeGreaterThan(0);
  expect(leaked).toEqual([]);
  await ctx.close();
});
