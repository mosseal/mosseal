/**
 * Custom time-source browser harness (N1, spec 07).
 *
 * Built from the `conformance-wasm-web-custom` fixture, whose generated
 * `secrets.rs` bakes a `MOSSEAL_TIME_SOURCES` override
 * (`https://custom-time.test/api`). The spec proves the override is actually
 * consulted instead of the three defaults.
 */
import * as wasmMod from "../../test/fixtures/conformance-wasm-web-custom/mosseal_wasm.js";
import wasmUrl from "../../test/fixtures/conformance-wasm-web-custom/mosseal_wasm_bg.wasm?url";
import { installHarness } from "./common.js";

await installHarness(wasmMod, wasmUrl);
