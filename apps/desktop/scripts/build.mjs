import { build } from "esbuild";
import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist");
await rm(out, { recursive: true, force: true });
await mkdir(join(out, "renderer"), { recursive: true });

const common = { bundle: true, logLevel: "warning", sourcemap: process.env.NODE_ENV === "production" ? false : "linked" };
// Main and preload run in Electron's Node.js; the page is a plain browser script.
await build({ ...common, entryPoints: [join(root, "src/main.ts")], outfile: join(out, "main.js"), platform: "node", format: "cjs", target: "node22", external: ["electron"] });
await build({ ...common, entryPoints: [join(root, "src/preload.ts")], outfile: join(out, "preload.js"), platform: "node", format: "cjs", target: "node22", external: ["electron"] });
await build({ ...common, entryPoints: [join(root, "src/renderer/app.ts")], outfile: join(out, "renderer/app.js"), platform: "browser", format: "iife", target: "chrome130" });
for (const file of ["index.html", "styles.css", "icon.png"]) await cp(join(root, "src/renderer", file), join(out, "renderer", file));
console.log(`Built SENTINEL Desktop -> ${out}`);
