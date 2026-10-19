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
  /** Secret material (token or small app-state blob). Omit when `slots` is set. */
  data?: string;
  /** Optional password — switches KDF to Argon2id (spec 02). */
  password?: string;
  /** Optional expiry in unix seconds; omit/0 = no expiry (offline-capable). */
  expSecs?: number;
  kind?: PayloadKind;
  /** Base URL to attach the fragment to (default: current URL, stripped). */
  baseUrl?: string;
  /**
   * Multi-secret mode (spec 04 § multi): N independently password-keyed
   * secrets in one link. When set, `data`/`password`/`kind` are ignored in
   * favor of the per-slot values; `expSecs` applies only to slots that omit
   * their own.
   */
  slots?: SlotSpec[];
}

/** One secret of a multi-slot seal (spec 04 § multi). */
export interface SlotSpec {
  /** Slot password (required; slots have no password-less mode). */
  password: string;
  data: string;
  kind?: PayloadKind;
  /** Per-slot expiry; falls back to `SealOptions.expSecs`. */
  expSecs?: number;
}

/** Cover configuration of a deniable seal (spec 09). */
export interface DeniableCover {
  /**
   * `"hidden"` — password-keyed cover (hidden receiver needs both
   * passwords, VeraCrypt model) or `"plain"` — password-less cover (hidden
   * receiver needs only the hidden password; binary holders see the hidden
   * envelope's existence as opaque bytes). Default: `"plain"`.
   */
  mode?: "hidden" | "plain";
  /** Cover password (required when mode is `"hidden"`). */
  password?: string;
  /** User decoy content cycled into the padding; omitted = random filler. */
  decoy?: string;
}

/** Hidden-layer configuration of a deniable seal (spec 09). */
export interface DeniableHidden {
  /**
   * Locates the hidden envelope (password-derived offset) and opens it.
   * For hidden `slots`, must equal one slot's password — that password's
   * holder locates the layer and opens their slot; other slot holders
   * cannot locate it without this password.
   */
  password: string;
  /** Single-secret hidden layer (omit when `slots` is set). */
  data?: string;
  kind?: PayloadKind;
  expSecs?: number;
  /** Multi-secret hidden layer (takes precedence over `data`). */
  slots?: SlotSpec[];
}

export interface DeniableSealOptions {
  cover: DeniableCover;
  hidden: DeniableHidden;
  /** Fixed size class in KiB (1, 2, or 4); omitted = smallest that fits. */
  sizeClass?: 1 | 2 | 4;
}

export interface OpenHiddenOptions {
  coverPassword?: string;
  hiddenPassword?: string;
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

/** SlotSpec → the JSON shape the wasm `sealMulti`/hidden layer expects. */
function slotToWasm(s: SlotSpec): Record<string, unknown> {
  const out: Record<string, unknown> = { password: s.password, data: s.data };
  if (s.kind !== undefined) out.kind = kindToByte(s.kind);
  if (s.expSecs !== undefined) out.expSecs = s.expSecs;
  return out;
}

/** DeniableHidden → the JSON shape the wasm `sealDeniable` expects. */
function hiddenToWasm(h: DeniableHidden): Record<string, unknown> {
  const out: Record<string, unknown> = { password: h.password };
  if (h.slots !== undefined) out.slots = h.slots.map(slotToWasm);
  else if (h.data !== undefined) out.data = h.data;
  if (h.kind !== undefined) out.kind = kindToByte(h.kind);
  if (h.expSecs !== undefined) out.expSecs = h.expSecs;
  return out;
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
   *
   * With `opts.slots` set, seals a multi-secret `MULTI` link instead of a
   * single-secret one (spec 04 § multi).
   */
  sealFragment(opts: SealOptions): string {
    if (opts.slots !== undefined) {
      if (opts.data !== undefined) {
        throw new MossealError(
          MossealErrorCode.MalformedEnvelope,
          "provide either data or slots, not both"
        );
      }
      try {
        return this.wasm.sealMulti(
          opts.slots.map(slotToWasm),
          opts.expSecs ?? null
        );
      } catch (err) {
        throw fromWasmError(err);
      }
    }
    if (opts.data === undefined) {
      throw new MossealError(
        MossealErrorCode.MalformedEnvelope,
        "seal requires data (or slots)"
      );
    }
    try {
      return this.wasm.seal(
        opts.data,
        opts.password ?? null,
        opts.expSecs ?? null,
        kindToByte(opts.kind)
      );
    } catch (err) {
      throw fromWasmError(err);
    }
  }

  /**
   * Seal a deniable link (spec 09): a cover envelope whose payload hides a
   * complete hidden envelope at a password-derived offset, padded to a
   * fixed size class. Returns the bare fragment value.
   *
   * Deniable links are URL/clipboard transport (multi-KiB, over the QR
   * advisory — the size class is the statement).
   */
  sealDeniableFragment(opts: DeniableSealOptions): string {
    try {
      return this.wasm.sealDeniable(
        {
          mode: opts.cover.mode,
          password: opts.cover.password,
          decoy: opts.cover.decoy,
        },
        hiddenToWasm(opts.hidden),
        opts.sizeClass ?? null
      );
    } catch (err) {
      throw fromWasmError(err);
    }
  }

  /**
   * Seal a deniable link into a full share URL (see `sealDeniableFragment`).
   */
  generateDeniableShareUrl(
    opts: DeniableSealOptions & { baseUrl?: string }
  ): string {
    const base =
      opts.baseUrl ??
      (typeof location !== "undefined" ? location.href : "https://localhost/");
    const fragment = this.sealDeniableFragment(opts);
    return generateShareUrl(base, fragment);
  }

  /**
   * Open a deniable link's hidden layer (spec 09): opens the cover (with
   * its password for `cover: hidden`), then recovers and opens the hidden
   * envelope with the hidden password. Wrong hidden password or absent
   * hidden layer both throw `BAD_PASSWORD` — plausible deniability means
   * the format cannot distinguish them.
   */
  async openHiddenFragment(
    fragment: string,
    opts: OpenHiddenOptions = {}
  ): Promise<OpenResult> {
    try {
      const out = await this.wasm.openHidden(
        fragment,
        opts.coverPassword ?? null,
        opts.hiddenPassword ?? null
      );
      return { data: out.data, exp: out.exp, kind: byteToKind(out.kind) };
    } catch (err) {
      throw fromWasmError(err);
    }
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
