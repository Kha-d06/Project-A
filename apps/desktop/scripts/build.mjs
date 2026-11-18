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
// The terminal command (qalaa): runs on the app's own runtime in Node mode, kept outside the asar archive.
await build({ ...common, entryPoints: [join(root, "src/cli.ts")], outfile: join(out, "cli.js"), platform: "node", format: "cjs", target: "node22", sourcemap: false });
await build({ ...common, entryPoints: [join(root, "src/preload.ts")], outfile: join(out, "preload.js"), platform: "node", format: "cjs", target: "node22", external: ["electron"] });
await build({ ...common, entryPoints: [join(root, "src/renderer/app.ts")], outfile: join(out, "renderer/app.js"), platform: "browser", format: "iife", target: "chrome130" });
for (const file of ["index.html", "styles.css", "icon.png"]) await cp(join(root, "src/renderer", file), join(out, "renderer", file));
// Fonts ship with the app (it works offline, and its CSP allows only local fonts).
const FONTS = {
  "instrument-sans": ["latin-wght-normal"],
  "bricolage-grotesque": ["latin-standard-normal"],
  "jetbrains-mono": ["latin-wght-normal"],
  "noto-sans-arabic": ["arabic-wght-normal"],
  "noto-kufi-arabic": ["arabic-wght-normal"],
};
await mkdir(join(out, "renderer/fonts"), { recursive: true });
for (const [family, files] of Object.entries(FONTS)) {
  for (const file of files) {
    await cp(join(root, "node_modules/@fontsource-variable", family, "files", `${family}-${file}.woff2`), join(out, "renderer/fonts", `${family}.woff2`));
  }
}
console.log(`Built Qalaa Desktop -> ${out}`);
