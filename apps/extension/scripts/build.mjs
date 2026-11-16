import { build } from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createManifest } from "./manifest.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist", "chrome");
const { version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const serverOrigin = new URL(process.env.SENTINEL_SERVER ?? "http://localhost:8080").origin;

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const shared = {
  bundle: true,
  target: "chrome116",
  minify: process.env.NODE_ENV === "production",
  sourcemap: process.env.NODE_ENV === "production" ? false : "linked",
  define: {
    __SENTINEL_SERVER__: JSON.stringify(serverOrigin),
    __EXTENSION_VERSION__: JSON.stringify(version),
  },
  logLevel: "warning",
};

await build({
  ...shared,
  format: "esm",
  entryPoints: {
    background: join(root, "src/background.ts"),
    popup: join(root, "src/pages/popup.ts"),
    options: join(root, "src/pages/options.ts"),
    warning: join(root, "src/pages/warning.ts"),
  },
  outdir: out,
});
// Content scripts are classic scripts, not modules.
await build({ ...shared, format: "iife", entryPoints: { hover: join(root, "src/hover.ts") }, outdir: out });

await cp(join(root, "static"), out, { recursive: true });
await writeFile(join(out, "manifest.json"), JSON.stringify(createManifest({ version, serverOrigin }), null, 2));
console.log(`Built SENTINEL Protect ${version} for ${serverOrigin} -> ${out}`);
