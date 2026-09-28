/// <reference types="node" />
import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright config for the MOSSEAL browser suite (spec 08 § Cross-origin/
 * browser suite).
 *
 * The suite drives the REAL wrapper (`@mosseal/core`) against the REAL
 * consumer-compiled wasm in Chromium. Cross-host portability is exercised by
 * `page.route`-fulfilling fake whitelisted hosts (`a.test`/`b.test`/`c.test`)
 * from the locally served harness — no DNS or TLS needed. Net time is mocked
 * the same way (`page.route`), covering the strict/lenient matrix (spec 07).
 */
export default defineConfig({
  testDir: "./e2e",
  testMatch: /.*\.spec\.ts$/,
  fullyParallel: false, // per-page time cache; keep runs deterministic
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI
    ? [["github"], ["html", { open: "never" }]]
    : [["list"]],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // Builds both web-target wasm fixtures + bundles the harness, then serves
    // `e2e/.dist/` with `application/wasm` (required by instantiateStreaming).
    command: "node e2e/build-harness.mjs && node e2e/serve.mjs",
    url: "http://127.0.0.1:4173/index.html",
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
  },
});
