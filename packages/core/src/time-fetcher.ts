/**
 * Time-fetcher install (spec 04 § Time-fetcher install, spec 07).
 *
 * The wasm `WebFetch` path calls a JS-provided sync bridge function
 * (`mossealFetchTime`) registered via `register_time_fetcher` before any
 * `open()`. This module implements it: `Promise.any` over the 3 sources,
 * 4 s overall timeout, body text → array (order-stable, aligned with the
 * source list wasm passes in).
 */
import { FETCH_TIMEOUT_MS } from "./time-consts.js";

/**
 * Fetch all source URLs in parallel; resolve to an array of body texts
 * aligned by index with the input (failed sources → null entries).
 * Rejects only when the overall timeout elapses.
 */
export async function fetchAllBodies(urls: string[]): Promise<(string | null)[]> {
  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error("mosseal time fetch timeout")), FETCH_TIMEOUT_MS)
  );

  const fetches = urls.map(async (url): Promise<string | null> => {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (!res.ok) return null;
      return await res.text();
    } catch {
      return null;
    }
  });

  // Overall budget: whichever finishes last bounds the whole batch.
  const bodies = await Promise.race([Promise.all(fetches), timeout]);
  return bodies;
}

/**
 * The sync bridge wasm calls. Because fetch is async and the wasm trait is
 * sync, we use a synchronous XHR in browser contexts (the only reliable
 * sync HTTP in a page) — this runs only when an expiring link is opened.
 * Returns bodies aligned with `urls` (null for failures).
 */
export function fetchAllBodiesSync(urls: string[]): (string | null)[] {
  if (typeof XMLHttpRequest === "undefined") {
    // Node/tests: no sync XHR — report all-failed (lenient mode falls back
    // to system clock; strict mode yields STRICT_TIME_UNAVAILABLE).
    return urls.map(() => null);
  }
  return urls.map((url) => {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open("GET", url, false); // synchronous — bounded by browser timeouts
      xhr.send(null);
      if (xhr.status >= 200 && xhr.status < 300) return xhr.responseText;
      return null;
    } catch {
      return null;
    }
  });
}

/**
 * Install the fetcher into the wasm module. Must be called before any
 * `open()` of an expiring link (spec 04).
 */
export function installTimeFetcher(wasm: {
  register_time_fetcher: (fetch: (urls: string[]) => (string | null)[]) => void;
}): void {
  wasm.register_time_fetcher(fetchAllBodiesSync);
}
