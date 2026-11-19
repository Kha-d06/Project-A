import { build } from "esbuild";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { createManifest } from "./manifest.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const browser = process.env.TARGET_BROWSER === "firefox" ? "firefox" : "chrome";
const out = join(root, "dist", browser);
const { version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const serverOrigin = new URL(process.env.SENTINEL_SERVER ?? "http://localhost:8080").origin;
// Test builds (never published) grant the optional permissions up front, because
// automated browsers cannot click a permission prompt, and leave the assistant's
// shadow root open so tests can look inside it.
const testBuild = process.env.SENTINEL_TEST_BUILD === "1";

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const shared = {
  bundle: true,
  target: browser === "firefox" ? "firefox128" : "chrome116",
  minify: process.env.NODE_ENV === "production",
  sourcemap: process.env.NODE_ENV === "production" ? false : "linked",
  define: {
    __SENTINEL_SERVER__: JSON.stringify(serverOrigin),
    __EXTENSION_VERSION__: JSON.stringify(version),
    __TARGET_BROWSER__: JSON.stringify(browser),
    __TEST_BUILD__: JSON.stringify(testBuild),
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
    timeup: join(root, "src/pages/timeup.ts"),
  },
  outdir: out,
});
// Content scripts are classic scripts, not modules.
await build({
  ...shared,
  format: "iife",
  entryPoints: { hover: join(root, "src/hover.ts"), assistant: join(root, "src/assistant.ts"), search: join(root, "src/search.ts") },
  outdir: out,
});

await cp(join(root, "static"), out, { recursive: true });
const manifest = createManifest({ version, serverOrigin, browser });
if (testBuild) {
  manifest.permissions.push(...manifest.optional_permissions);
  manifest.host_permissions.push(...manifest.optional_host_permissions);
}
await writeFile(join(out, "manifest.json"), JSON.stringify(manifest, null, 2));
console.log(`Built Qalaa Protect ${version} (${browser}) for ${serverOrigin} -> ${out}`);
