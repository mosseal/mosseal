/**
 * Minimal static server for the browser harness (spec 08).
 *
 * Serves `e2e/.dist/` with correct MIME types — notably `application/wasm`,
 * which `WebAssembly.instantiateStreaming` requires (spec 06 static-hosting
 * note; GitHub Pages serves it correctly, this mirrors that).
 */
import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, ".dist");
const PORT = Number(process.env.PORT ?? 4173);
const HOST = "127.0.0.1";

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".wasm": "application/wasm",
  ".css": "text/css",
  ".json": "application/json",
  ".map": "application/json",
  ".ico": "image/x-icon",
};

if (!existsSync(ROOT)) {
  console.error(`harness not built — run \`node e2e/build-harness.mjs\` first (${ROOT})`);
  process.exit(1);
}

const server = createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url ?? "/", `http://${HOST}`).pathname);
  if (pathname === "/" || pathname === "") pathname = "/index.html";
  // Strip any leading traversal so a crafted path cannot escape ROOT.
  const safe = normalize(pathname).replace(/^(\.\.[/\\])+/, "").replace(/^[/\\]+/, "");
  const file = join(ROOT, safe);
  if (!existsSync(file)) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  res.writeHead(200, {
    "content-type": MIME[extname(file)] ?? "application/octet-stream",
  });
  res.end(readFileSync(file));
});

server.listen(PORT, HOST, () => {
  console.log(`mosseal browser harness on http://${HOST}:${PORT}`);
});
