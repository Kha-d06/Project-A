/**
 * Packs the add-on as an .xpi (a zip), reproducibly: the same files give the same
 * bytes. Files are copied to a staging folder, given one fixed time
 * (SOURCE_DATE_EPOCH, else the last commit's time, else 2000-01-01), and zipped
 * in sorted order without extra attributes (zip -X) or directory entries (-D).
 */
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";

const root = resolve(".");
const { version } = JSON.parse(readFileSync("manifest.json", "utf8"));
const out = resolve(`dist/qalaa-thunderbird-${version}.xpi`);
mkdirSync("dist", { recursive: true });
rmSync(out, { force: true });

function epoch() {
  if (process.env.SOURCE_DATE_EPOCH) return Number(process.env.SOURCE_DATE_EPOCH);
  try {
    return Number(execFileSync("git", ["log", "-1", "--format=%ct"], { encoding: "utf8" }).trim());
  } catch {
    return 946684800;
  }
}

const stage = mkdtempSync(join(tmpdir(), "qalaa-xpi-"));
for (const entry of ["manifest.json", "_locales", "icons", "src"]) cpSync(join(root, entry), join(stage, entry), { recursive: true });
const files = [];
const walk = (dir) => {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else files.push(relative(stage, path));
  }
};
walk(stage);
const when = new Date(epoch() * 1000);
for (const file of files) utimesSync(join(stage, file), when, when);
execFileSync("zip", ["-X", "-D", "-q", out, "-@"], { cwd: stage, input: files.join("\n"), env: { ...process.env, TZ: "UTC" } });
rmSync(stage, { recursive: true, force: true });
console.log(`Packed ${relative(root, out)} (${files.length} files)`);
