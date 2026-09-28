/**
 * URL fragment parse/build (spec 04 § URL handling rules).
 *
 * Fragment shape: `#ms=<base64url(envelope)>` (spec 01). The envelope's format
 * `version` byte is the first byte *inside* the decoded binary, not a character
 * prefix on the fragment. Everything after `#` never reaches the server.
 */

const FRAGMENT_PREFIX = "#ms=";

/**
 * Extract the raw mosseal fragment value (the base64url part after `#ms=`) from
 * a URL string, or null when the URL has no mosseal fragment (tolerates
 * unrelated fragments — anchor navigation etc.).
 */
export function extractFragment(url: string): string | null {
  const hashIdx = url.indexOf("#");
  if (hashIdx === -1) return null;
  const fragment = url.slice(hashIdx);
  if (!fragment.startsWith(FRAGMENT_PREFIX)) return null;
  const value = fragment.slice(FRAGMENT_PREFIX.length);
  return value.length > 0 ? value : null;
}

/**
 * Whether a URL carries a mosseal fragment (silent detection for the
 * receiver flow — spec 04: `isMossealUrl`).
 */
export function isMossealUrl(url: string): boolean {
  return extractFragment(url) !== null;
}

/**
 * Build a share URL: replace any existing fragment on `baseUrl` with the
 * mosseal fragment. Warns (console) when the final URL exceeds 512 bytes
 * (QR advisory, spec 01) — the ONLY console use in this library.
 */
export function generateShareUrl(baseUrl: string, fragmentValue: string): string {
  const base = baseUrl.includes("#") ? baseUrl.slice(0, baseUrl.indexOf("#")) : baseUrl;
  const url = `${base}${FRAGMENT_PREFIX}${fragmentValue}`;
  if (url.length > 512) {
    // eslint-disable-next-line no-console
    console.warn(
      `mosseal: share URL is ${url.length} bytes (> 512). QR codes shrink ` +
        `quickly beyond this budget (spec 01).`
    );
  }
  return url;
}

/**
 * Strip the mosseal fragment from a URL, leaving everything else intact
 * (spec 04 receiver flow step 4: scrub after persistence succeeded).
 * Other fragments (anchors) are preserved.
 */
export function scrubFragmentFromUrl(url: string): string {
  const hashIdx = url.indexOf("#");
  if (hashIdx === -1) return url;
  if (!url.slice(hashIdx).startsWith(FRAGMENT_PREFIX)) return url;
  return url.slice(0, hashIdx);
}
