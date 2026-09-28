/**
 * wasm loader (spec 04 § Loader details).
 *
 * Accepts either:
 *  - a wasm-pack bundler init function (browser/Vite: `import init from ".../pkg"`), or
 *  - a URL string (browser: fetch + instantiateStreaming), or
 *  - a Buffer/Uint8Array (Node: `readFileSync(pkgPath)`), or
 *  - a pre-initialized wasm module exports object.
 *
 * `Mosseal.load` is idempotent; concurrent calls coalesce to one init
 * (handled in index.ts). Errors surface as WASM_INIT_FAILED.
 */

/** The wasm-pack `--target bundler` init function signature. */
export type WasmPackInit = (
  input?: string | RequestInfo | URL | BufferSource | Response
) => Promise<WasmExports>;

export interface WasmExports {
  Mosseal: new () => WasmMosseal;
  register_time_fetcher: (fetch: (urls: string[]) => (string | null)[]) => void;
}

export interface WasmMosseal {
  seal(
    data: string,
    password: string | null | undefined,
    expSecs: number | null | undefined,
    kind: number | null | undefined
  ): string;
  open(
    link: string,
    password: string | null | undefined
  ): Promise<{ data: string; exp: number; kind: number }>;
}

export type LoaderInput = WasmPackInit | string | Uint8Array | WasmExports;

/** Normalize any loader input into a resolved exports object. */
export async function initWasm(input: LoaderInput): Promise<WasmExports> {
  if (typeof input === "function") {
    // wasm-pack bundler init fn (browser/Vite path)
    return await (input as WasmPackInit)();
  }
  if (typeof input === "string") {
    // URL: fetch + instantiateStreaming requires application/wasm MIME
    // (GitHub Pages serves this correctly; documented in spec 06).
    const res = await fetch(input);
    if (!res.ok) {
      throw new Error(`wasm fetch failed: HTTP ${res.status}`);
    }
    const { instance } = await WebAssembly.instantiateStreaming(
      res,
      // wasm-pack bundler glue is required for full bindings; raw
      // instantiation is only used when the consumer passes a URL without
      // the glue. Prefer the init-fn path in bundlers.
      {}
    );
    return instance.exports as unknown as WasmExports;
  }
  if (input instanceof Uint8Array) {
    // Node: compile from bytes (readFileSync of the .wasm). The cast pins
    // `ArrayBuffer`-backed bytes so TS selects the instantiate overload that
    // returns `{ instance, module }` (a plain Uint8Array<ArrayBufferLike>
    // would match the module-object overload instead).
    const { instance } = await WebAssembly.instantiate(
      input as Uint8Array<ArrayBuffer>,
      {}
    );
    return instance.exports as unknown as WasmExports;
  }
  // already-initialized exports
  return input;
}
