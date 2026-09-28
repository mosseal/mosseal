/**
 * Browser-suite helpers (spec 08).
 *
 * - `installHostRouting` fulfils requests to fake whitelisted hosts by proxying
 *   the locally served harness, so `location.hostname` is the fake host the
 *   wasm domain gate checks (spec 03) while assets come from one place.
 * - `mockTimeSources` fulfils/aborts the three default time sources to drive
 *   the strict/lenient matrix (spec 07) without real network.
 */
import type { BrowserContext, Page, Route } from "@playwright/test";

/** Must match `PORT` in `e2e/serve.mjs`. */
export const PORT = 4173;
export const ORIGIN = `http://127.0.0.1:${PORT}`;

/** Whitelisted test hosts (vectors.json `domains`) + a non-whitelisted one. */
export const WHITELISTED = ["a.test", "b.test"] as const;
export const NOT_WHITELISTED = "c.test";
export const ALL_HOSTS = [...WHITELISTED, NOT_WHITELISTED];

/** Default time sources (spec 07) — used by the wasm fetch bridge. */
export const TIME_HOSTS = ["cloudflare.com", "timeapi.io", "worldtimeapi.org"] as const;

/** Custom source host baked into the `web-custom` fixture (spec 07). */
export const CUSTOM_TIME_HOST = "custom-time.test";

export const TOKEN = "tok_browser_12345";

/** A whole-window handle to the harness surface (see `e2e/harness/common.js`). */
export interface HarnessApi {
  hostname(): string;
  href(): string;
  sealFragment(opts: Record<string, unknown>): string;
  sealUrl(opts: Record<string, unknown>): string;
  openUrl(
    url: string,
    opts?: Record<string, unknown>
  ): Promise<{ ok: true; value: OpenValue } | { ok: false; code: string; message: string }>;
  openFragment(
    fragment: string,
    opts?: Record<string, unknown>
  ): Promise<{ ok: true; value: OpenValue } | { ok: false; code: string; message: string }>;
  isMossealUrl(url: string): boolean;
  scrub(url: string): string;
}

export interface OpenValue {
  data: string;
  exp: number;
  kind: "token" | "binary_blob";
}

declare global {
  interface Window {
    __mossealReady?: boolean;
    __mossealError?: string;
    __mosseal?: HarnessApi;
  }
}

/**
 * Fulfil any request to `hosts` with the same path from the local harness.
 * Uses Playwright's APIRequestContext (server-side), which is NOT intercepted
 * by page routes — no recursion.
 */
export async function installHostRouting(page: Page, hosts: readonly string[]): Promise<void> {
  for (const host of hosts) {
    await page.route(`http://${host}/**`, async (route: Route) => {
      const url = new URL(route.request().url());
      const resp = await page.request.get(`${ORIGIN}${url.pathname}${url.search}`);
      await route.fulfill({
        status: resp.status(),
        headers: resp.headers(),
        body: await resp.body(),
      });
    });
  }
}

/** Wait for the harness to finish initializing; throw with the harness error. */
export async function waitForReady(page: Page): Promise<void> {
  await page.waitForFunction(
    () => window.__mossealReady === true || typeof window.__mossealError === "string",
    undefined,
    { timeout: 30_000 }
  );
  const err = await page.evaluate(() => window.__mossealError ?? null);
  if (err) throw new Error(`harness init failed: ${err}`);
}

/**
 * Open a page on `host` (fake origin), with harness routing installed.
 * @param variant which compiled harness to load; `strict` uses the strict-time
 *   build, `custom` uses the `MOSSEAL_TIME_SOURCES`-override build (spec 07)
 */
export async function openHarness(
  context: BrowserContext,
  host: string,
  { variant = "lenient" }: { variant?: "lenient" | "strict" | "custom" } = {}
): Promise<Page> {
  const page = await context.newPage();
  await installHostRouting(page, ALL_HOSTS);
  const file = variant === "strict" ? "strict.html" : variant === "custom" ? "custom.html" : "index.html";
  await page.goto(`http://${host}/${file}`);
  await waitForReady(page);
  return page;
}

/** Cloudflare trace body (spec 07 parser). */
export function cloudflareBody(secs: number): string {
  return `fl=abc\nts=${secs.toFixed(3)}\nvisit_scheme=https\nh=cloudflare.com\n`;
}

/** timeapi.io body — parsed via `unixTime`. */
export function timeapiBody(secs: number): string {
  return JSON.stringify({ unixTime: secs });
}

/** worldtimeapi.org body — parsed via `unixtime`. */
export function worldtimeBody(secs: number): string {
  return JSON.stringify({ unixtime: secs });
}

/**
 * Mock all three time sources: respond with `secs`, or abort them all when
 * `secs` is null (simulating an unreachable network for the strict/lenient
 * matrix). Cross-origin CORS headers are set so the browser accepts them.
 */
export async function mockTimeSources(page: Page, secs: number | null): Promise<void> {
  for (const host of TIME_HOSTS) {
    await page.route(`https://${host}/**`, async (route: Route) => {
      if (secs === null) {
        await route.abort("failed");
        return;
      }
      const body =
        host === "cloudflare.com"
          ? cloudflareBody(secs)
          : host === "timeapi.io"
            ? timeapiBody(secs)
            : worldtimeBody(secs);
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "text/plain",
          "access-control-allow-origin": "*",
        },
        body,
      });
    });
  }
}

/**
 * Mock the baked custom source (`web-custom` fixture) with a JSON body using
 * the `unixTime` key — the parser `parse_time_sources` assigns to custom URLs
 * (spec 07). Records every request URL so a spec can prove the override was
 * consulted.
 */
export async function mockCustomTimeSource(
  page: Page,
  secs: number | null
): Promise<{ requested: string[] }> {
  const requested: string[] = [];
  await page.route(`https://${CUSTOM_TIME_HOST}/**`, async (route: Route) => {
    requested.push(route.request().url());
    if (secs === null) {
      await route.abort("failed");
      return;
    }
    await route.fulfill({
      status: 200,
      headers: {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
      },
      body: timeapiBody(secs),
    });
  });
  return { requested };
}

/**
 * Mock each default time source with a **different** time, to exercise the
 * strict-mode cross-source drift sanity (spec 07 § optional v1.1). A `null`
 * entry aborts that source.
 */
export async function mockTimeSourcesPerHost(
  page: Page,
  times: Partial<Record<(typeof TIME_HOSTS)[number], number | null>>
): Promise<void> {
  for (const host of TIME_HOSTS) {
    const secs = times[host] ?? null;
    await page.route(`https://${host}/**`, async (route: Route) => {
      if (secs === null) {
        await route.abort("failed");
        return;
      }
      const body =
        host === "cloudflare.com"
          ? cloudflareBody(secs)
          : host === "timeapi.io"
            ? timeapiBody(secs)
            : worldtimeBody(secs);
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "text/plain",
          "access-control-allow-origin": "*",
        },
        body,
      });
    });
  }
}
