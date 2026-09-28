/**
 * @mosseal/core — public API (spec 04).
 *
 * A small, dependency-free TypeScript layer that loads the consumer-compiled
 * wasm, exposes a clean async API, handles URL parse/build, and hands the
 * decrypted token to the app for IndexedDB re-wrapping.
 *
 * The wasm binary itself is NOT in this package — it is generated
 * per-consumer by the `mosseal` CLI into the consumer's project (spec 05);
 * the consumer imports its init fn and passes it to `Mosseal.load`.
 *
 * NOTE: no `console.*` in src except the single QR-budget warning in
 * link.ts (enforced by lint rule `no-restricted-syntax`, spec 04).
 */
import { initWasm, type LoaderInput, type WasmExports, type WasmMosseal } from "./loader.js";
import { installTimeFetcher } from "./time-fetcher.js";
import { MossealError, MossealErrorCode, fromWasmError } from "./errors.js";
import {
  extractFragment,
  isMossealUrl,
  generateShareUrl,
  scrubFragmentFromUrl,
} from "./link.js";

export { MossealError, MossealErrorCode, fromWasmError };
export { isMossealUrl, scrubFragmentFromUrl };
export type { LoaderInput, WasmExports };

export type PayloadKind = "token" | "binary_blob";

const KIND_TOKEN = 0x01;
const KIND_BINARY_BLOB = 0x02;

export interface SealOptions {
  /** Secret material (token or small app-state blob). */
  data: string;
  /** Optional password — switches KDF to Argon2id (spec 02). */
  password?: string;
  /** Optional expiry in unix seconds; omit/0 = no expiry (offline-capable). */
  expSecs?: number;
  kind?: PayloadKind;
  /** Base URL to attach the fragment to (default: current URL, stripped). */
  baseUrl?: string;
}

export interface OpenResult {
  data: string;
  /** Unix seconds, or 0 when the link never expires. */
  exp: number;
  kind: PayloadKind;
}

export interface OpenUrlOptions {
  password?: string;
}

function kindToByte(kind: PayloadKind | undefined): number {
  switch (kind ?? "token") {
    case "token":
      return KIND_TOKEN;
    case "binary_blob":
      return KIND_BINARY_BLOB;
  }
}

function byteToKind(b: number): PayloadKind {
  switch (b) {
    case KIND_TOKEN:
      return "token";
    case KIND_BINARY_BLOB:
      return "binary_blob";
    default:
      throw new MossealError(MossealErrorCode.UnsupportedKind);
  }
}

export class Mosseal {
  private constructor(private readonly wasm: WasmMosseal) {}

  private static initPromise: Promise<Mosseal> | null = null;

  /**
   * One-time init. Idempotent; concurrent calls coalesce to one init
   * (spec 04 § Loader details). Errors → WASM_INIT_FAILED.
   *
   * @param loader wasm-pack bundler init fn (browser/Vite), wasm URL,
   *               wasm bytes (Node), or pre-initialized exports.
   */
  static load(loader: LoaderInput): Promise<Mosseal> {
    if (!Mosseal.initPromise) {
      Mosseal.initPromise = (async () => {
        try {
          const exports = await initWasm(loader);
          installTimeFetcher(exports);
          const instance = new exports.Mosseal();
          return new Mosseal(instance);
        } catch (err) {
          // allow a later retry after a failed init
          Mosseal.initPromise = null;
          throw new MossealError(
            MossealErrorCode.WasmInitFailed,
            err instanceof Error ? err.message : undefined
          );
        }
      })();
    }
    return Mosseal.initPromise;
  }

  /** Test/advanced: reset the coalesced init (not for app use). */
  static _reset(): void {
    Mosseal.initPromise = null;
  }

  /**
   * Seal into a full share URL (spec 04 § Public API). The fragment on
   * `baseUrl` (default: current URL) is replaced.
   */
  generateShareUrl(opts: SealOptions): string {
    const base =
      opts.baseUrl ??
      (typeof location !== "undefined" ? location.href : "https://localhost/");
    const fragment = this.sealFragment(opts);
    return generateShareUrl(base, fragment);
  }

  /**
   * Seal into the bare fragment value (the part after `#ms=`) — for apps
   * that transport the envelope themselves (QR, clipboard, etc.).
   */
  sealFragment(opts: SealOptions): string {
    return this.wasm.seal(
      opts.data,
      opts.password ?? null,
      opts.expSecs ?? null,
      kindToByte(opts.kind)
    );
  }

  /**
   * Open a full URL containing a `#ms=` fragment. Throws MALFORMED_ENVELOPE
   * only for *present but invalid* fragments; URLs without a mosseal
   * fragment throw MALFORMED_ENVELOPE too — use `isMossealUrl` for silent
   * detection first (spec 04 § URL handling rules).
   */
  async openFromUrl(url: string, opts: OpenUrlOptions = {}): Promise<OpenResult> {
    const fragment = extractFragment(url);
    if (fragment === null) {
      throw new MossealError(MossealErrorCode.MalformedEnvelope, "no mosseal fragment");
    }
    return this.openFragment(fragment, opts);
  }

  /**
   * Open a bare fragment value (the part after `#ms=`).
   */
  async openFragment(fragment: string, opts: OpenUrlOptions = {}): Promise<OpenResult> {
    try {
      const out = await this.wasm.open(fragment, opts.password ?? null);
      return { data: out.data, exp: out.exp, kind: byteToKind(out.kind) };
    } catch (err) {
      throw fromWasmError(err);
    }
  }
}

// Re-exported URL helpers bound to the class for discoverability (spec 04).
export const MossealUrl = {
  isMossealUrl,
  scrub: scrubFragmentFromUrl,
} as const;
