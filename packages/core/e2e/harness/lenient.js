/**
 * Lenient-time browser harness (default compile-time mode, spec 07).
 * Built from the `conformance-wasm-web` fixture.
 */
import * as wasmMod from "../../test/fixtures/conformance-wasm-web/mosseal_wasm.js";
import wasmUrl from "../../test/fixtures/conformance-wasm-web/mosseal_wasm_bg.wasm?url";
import { installHarness } from "./common.js";

await installHarness(wasmMod, wasmUrl);
