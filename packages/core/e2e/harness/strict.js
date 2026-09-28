/**
 * Strict-time browser harness (`MOSSEAL_STRICT_TIME=true`, spec 07).
 * Built from the `conformance-wasm-web-strict` fixture — a separate wasm
 * because strict mode is a compile-time flag.
 */
import * as wasmMod from "../../test/fixtures/conformance-wasm-web-strict/mosseal_wasm.js";
import wasmUrl from "../../test/fixtures/conformance-wasm-web-strict/mosseal_wasm_bg.wasm?url";
import { installHarness } from "./common.js";

await installHarness(wasmMod, wasmUrl);
