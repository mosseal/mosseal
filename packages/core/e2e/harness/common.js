/**
 * Shared browser harness (spec 08 § Cross-origin/browser suite).
 *
 * The lenient/strict entry points import their respective web-target wasm
 * fixture, await init, and install the wrapper. Everything the Playwright
 * specs need is exposed on `window.__mosseal`, so the specs stay thin and the
 * wrapper is exercised exactly as a consumer would (spec 04).
 */
import { Mosseal, MossealUrl } from "../../src/index.js";

/** Wrap a call into a serializable `{ok}` result (errors never leak prose). */
async function attempt(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, code: err?.code ?? "UNKNOWN", message: String(err?.message ?? err) };
  }
}

/**
 * @param {object} wasmMod  the web-target glue module namespace
 * @param {string} wasmUrl  the emitted `.wasm` asset URL
 */
export async function installHarness(wasmMod, wasmUrl) {
  window.__mossealReady = false;
  try {
    // Web target needs an explicit init; passing the module namespace to
    // `Mosseal.load` afterwards hits the "pre-initialized exports" path.
    await wasmMod.default({ module_or_path: wasmUrl });
    const mosseal = await Mosseal.load(wasmMod);

    window.__mosseal = {
      /** The hostname the wasm hostname gate sees (spec 03). */
      hostname: () => location.hostname,
      href: () => location.href,

      /** Seal → bare fragment value (part after `#ms=`). */
      sealFragment: (opts) => mosseal.sealFragment(opts),
      /** Seal → full share URL (fragment replaces any existing one). */
      sealUrl: (opts) => mosseal.generateShareUrl(opts),

      openUrl: (url, opts) => attempt(() => mosseal.openFromUrl(url, opts)),
      openFragment: (fragment, opts) => attempt(() => mosseal.openFragment(fragment, opts)),

      // URL helpers are module-level exports (spec 04), re-exported via the
      // `MossealUrl` namespace object — not instance methods.
      isMossealUrl: (url) => MossealUrl.isMossealUrl(url),
      scrub: (url) => MossealUrl.scrub(url),
    };
    window.__mossealReady = true;
  } catch (err) {
    window.__mossealError = String(err?.message ?? err);
    window.__mossealReady = false;
  }
}
