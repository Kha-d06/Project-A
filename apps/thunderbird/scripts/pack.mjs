/** Packs the add-on as an .xpi (a zip) with the system's zip tool. */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync } from "node:fs";

const { version } = JSON.parse(readFileSync("manifest.json", "utf8"));
mkdirSync("dist", { recursive: true });
const out = `dist/qalaa-thunderbird-${version}.xpi`;
rmSync(out, { force: true });
execFileSync("zip", ["-r", "-q", out, "manifest.json", "_locales", "icons", "src"], { stdio: "inherit" });
console.log(`Packed ${out}`);
