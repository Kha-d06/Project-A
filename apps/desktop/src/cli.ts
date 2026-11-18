/**
 * `qalaa`: Qalaa's terminal command (Linux, macOS). Runs on Qalaa Desktop's own
 * runtime in Node mode, so it needs no separate installation.
 *
 *   qalaa scan <files or folders>      scan and print the verdicts
 *   qalaa check "<command>"            explain what a command would do, without running it
 *   qalaa guard -- "<command>"         used by the shell hooks before a command runs:
 *                                      exit 0 = run it, 1 = do not
 *   qalaa after -- "<command>"         used after a command: scans files it downloaded
 *   qalaa terminal on|off|status       set up or remove the bash/zsh hooks
 *
 * Wording follows Qalaa: never "safe"; "no known threats" at most.
 */
import { createHash } from "node:crypto";
import { closeSync, openSync, readSync, writeSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, isAbsolute, join, resolve } from "node:path";

import { scanFile } from "./engine/scanner";
import { disableTerminal, enableTerminal, terminalStatus } from "./engine/shell-init";
import { SignatureStore } from "./engine/signatures";
import { type CommandRisk, analyseCommand, urlConcerns } from "./engine/terminal";
import type { ScanResult } from "./engine/types";
import { isDirectory, walk } from "./engine/walk";

const MAX_SCRIPT = 4 * 1024 * 1024;

// --- Output ------------------------------------------------------------------------------

const tty = process.stderr.isTTY && !process.env.NO_COLOR;
const paint = (code: string, text: string) => (tty ? `\x1b[${code}m${text}\x1b[0m` : text);
const red = (t: string) => paint("1;31", t);
const yellow = (t: string) => paint("1;33", t);
const green = (t: string) => paint("32", t);
const dim = (t: string) => paint("2", t);
const bold = (t: string) => paint("1", t);
const say = (line = "") => process.stderr.write(`${line}\n`);

function verdictLabel(result: ScanResult): string {
  if (result.verdict === "malicious") return red("known threat");
  if (result.verdict === "suspicious") return yellow("suspicious");
  if (result.verdict === "no_known_threat") return green("no known threats");
  return dim(result.error ? `not scanned (${result.error})` : "not scanned");
}

function printResult(label: string, result: ScanResult) {
  say(`  ${bold(label)}: ${verdictLabel(result)}`);
  for (const finding of result.findings.filter((f) => f.severity !== "info").slice(0, 6)) {
    say(`    ${finding.severity === "critical" || finding.severity === "high" ? red("•") : yellow("•")} ${finding.title}${finding.member ? dim(` (${finding.member})`) : ""}`);
  }
}

// --- Data shared with Qalaa Desktop ------------------------------------------------------

function dataDir(): string {
  if (process.env.QALAA_DATA_DIR) return process.env.QALAA_DATA_DIR;
  if (process.platform === "darwin") return join(homedir(), "Library", "Application Support", "Qalaa Desktop");
  return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "Qalaa Desktop");
}

async function loadSignatures(): Promise<SignatureStore> {
  const store = new SignatureStore(join(dataDir(), "signatures.json"));
  await store.open();
  return store;
}

const cacheFile = () => join(process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "qalaa", "verdicts.json");
type Cache = Record<string, { verdict: ScanResult["verdict"]; findings: ScanResult["findings"]; at: number }>;

async function readCache(): Promise<Cache> {
  try {
    return JSON.parse(await readFile(cacheFile(), "utf8")) as Cache;
  } catch {
    return {};
  }
}

async function writeCache(cache: Cache) {
  const entries = Object.entries(cache).sort((a, b) => b[1].at - a[1].at).slice(0, 2000);
  await mkdir(join(cacheFile(), ".."), { recursive: true, mode: 0o700 });
  await writeFile(cacheFile(), JSON.stringify(Object.fromEntries(entries)), { mode: 0o600 });
}

/** Scans a file, reusing an earlier verdict for exactly the same content (and the same fingerprint list). */
async function scanCached(path: string, signatures: SignatureStore, cache: Cache): Promise<ScanResult> {
  try {
    const data = await readFile(path);
    const key = `${createHash("sha256").update(data).digest("hex")}:${signatures.size}`;
    const hit = cache[key];
    if (hit && Date.now() - hit.at < 7 * 86_400_000) {
      return { path, name: basename(path), size: data.length, sha256: key.split(":")[0]!, verdict: hit.verdict, findings: hit.findings, engines: ["cache"], scannedAt: new Date(hit.at).toISOString() };
    }
    const result = await scanFile(path, { signatures });
    if (!result.error) cache[key] = { verdict: result.verdict, findings: result.findings, at: Date.now() };
    return result;
  } catch (error) {
    return { path, name: basename(path), size: 0, sha256: null, verdict: "not_scanned", findings: [], engines: [], scannedAt: new Date().toISOString(), error: error instanceof Error ? error.message : String(error) };
  }
}

// --- Fetching a script the command would run -------------------------------------------

async function fetchScript(url: string): Promise<{ data: Buffer; finalUrl: string } | { error: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(url, { redirect: "follow", signal: controller.signal, headers: { "user-agent": "curl/8.5.0" } });
    if (!response.ok) return { error: `the server answered ${response.status}` };
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
      size += chunk.length;
      if (size > MAX_SCRIPT) return { error: "the script is larger than 4 MB" };
      chunks.push(Buffer.from(chunk));
    }
    return { data: Buffer.concat(chunks), finalUrl: response.url || url };
  } catch (error) {
    return { error: controller.signal.aborted ? "it took too long to download" : error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timer);
  }
}

/** Saved under a name ending in .sh unless the address names another script type, so script rules apply. */
function scriptName(url: string): string {
  try {
    const name = basename(new URL(url).pathname);
    return /\.(sh|bash|py|pl|rb|js|ps1|php)$/i.test(name) ? name : `${name || "script"}.sh`;
  } catch {
    return "script.sh";
  }
}

// --- Asking ----------------------------------------------------------------------------

/** Reads one line from the terminal (the shell hook gives us /dev/tty as standard input). */
function ask(question: string): string {
  if (process.env.QALAA_ANSWER !== undefined) return process.env.QALAA_ANSWER; // tests and scripted use
  let fd: number;
  try {
    fd = openSync("/dev/tty", "r+");
  } catch {
    return "";
  }
  try {
    writeSync(fd, question);
    const buffer = Buffer.alloc(256);
    let text = "";
    while (!text.includes("\n")) {
      let read = 0;
      try {
        read = readSync(fd, buffer, 0, buffer.length, null);
      } catch {
        break;
      }
      if (read <= 0) break;
      text += buffer.subarray(0, read).toString("utf8");
    }
    return text.trim();
  } finally {
    closeSync(fd);
  }
}

// --- Commands ----------------------------------------------------------------------------

interface Review {
  risks: CommandRisk[];
  scans: { label: string; result: ScanResult }[];
  notes: string[];
  /** Every script the command would fetch was downloaded, scanned clean, from an address without warning signs. */
  fetchedClean: boolean;
}

async function review(line: string, cwd = process.cwd()): Promise<Review> {
  const analysis = analyseCommand(line);
  const signatures = await loadSignatures();
  const cache = await readCache();
  const scans: Review["scans"] = [];
  const notes: string[] = [];
  let fetchedClean = analysis.fetchUrls.length > 0;

  if (analysis.fetchUrls.length) {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-fetch-"));
    try {
      for (const url of analysis.fetchUrls.slice(0, 3)) {
        const concerns = urlConcerns(url);
        if (concerns.length) fetchedClean = false;
        notes.push(...concerns);
        const fetched = await fetchScript(url);
        if ("error" in fetched) {
          notes.push(`The script at ${url} could not be checked: ${fetched.error}.`);
          fetchedClean = false;
          continue;
        }
        const file = join(dir, scriptName(fetched.finalUrl));
        await writeFile(file, fetched.data);
        const result = await scanCached(file, signatures, cache);
        if (result.verdict !== "no_known_threat" || urlConcerns(fetched.finalUrl).length) fetchedClean = false;
        scans.push({ label: `script from ${new URL(fetched.finalUrl).host}`, result: { ...result, path: fetched.finalUrl } });
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
  for (const file of analysis.runFiles.slice(0, 5)) {
    const path = file.startsWith("~/") ? join(homedir(), file.slice(2)) : isAbsolute(file) ? file : resolve(cwd, file);
    try {
      if (!(await stat(path)).isFile()) continue;
    } catch {
      continue;
    }
    scans.push({ label: file, result: await scanCached(path, signatures, cache) });
  }
  await writeCache(cache).catch(() => undefined);
  if (!signatures.size) notes.push("Qalaa Desktop has not downloaded its list of known malware yet, so only the built-in rules were used.");
  if (analysis.fetchUrls.length > 3) fetchedClean = false;
  return { risks: analysis.risks, scans, notes, fetchedClean };
}

function printReview(r: Review) {
  for (const item of r.risks) {
    say(`${item.level === "block" ? red("✖") : yellow("!")} ${bold(item.title)}`);
    say(`  ${dim(item.detail)}`);
  }
  for (const scan of r.scans) printResult(scan.label, scan.result);
  for (const note of r.notes) say(`${yellow("!")} ${note}`);
}

/** 0 = run, 1 = do not. Quiet when there is nothing to say. */
async function guard(line: string): Promise<number> {
  const r = await review(line);
  // A piped install script that was downloaded and checked clean needs no question.
  if (r.fetchedClean) r.risks = r.risks.filter((x) => x.rule !== "pipe_to_shell");
  const malicious = r.scans.some((s) => s.result.verdict === "malicious");
  const serious = r.scans.some((s) => s.result.findings.some((f) => f.severity === "critical" || f.severity === "high"));
  const blocking = malicious || serious || r.risks.some((x) => x.level === "block");
  const warning = blocking || r.risks.length > 0 || r.scans.some((s) => s.result.verdict === "suspicious") || r.notes.some((n) => !n.startsWith("Qalaa Desktop has not"));
  if (!warning) {
    if (r.scans.length) say(dim(`qalaa: ${r.scans.map((s) => s.label).join(", ")}: checked, no known threats found.`));
    return 0;
  }
  say("");
  say(blocking ? red("Qalaa stopped this command") : yellow("Qalaa: check this command before running it"));
  printReview(r);
  if (blocking) {
    const answer = ask(`${bold("Type")} yes ${bold("to run it anyway, or press Enter to cancel:")} `);
    if (answer === "yes") return 0;
    say(dim("Cancelled. Nothing was run."));
    return 1;
  }
  const answer = ask(`${bold("Run it? [y/N]")} `);
  if (/^y(es)?$/i.test(answer)) return 0;
  say(dim("Cancelled. Nothing was run."));
  return 1;
}

async function after(line: string): Promise<number> {
  const { downloads } = analyseCommand(line);
  if (!downloads.length) return 0;
  const signatures = await loadSignatures();
  const cache = await readCache();
  let worst = 0;
  for (const download of downloads.slice(0, 10)) {
    const path = resolve(process.cwd(), download.output);
    try {
      const info = await stat(path);
      if (!info.isFile() || Date.now() - info.mtimeMs > 10 * 60_000) continue;
    } catch {
      continue;
    }
    const result = await scanCached(path, signatures, cache);
    if (result.verdict === "malicious" || result.verdict === "suspicious") {
      say("");
      say(result.verdict === "malicious" ? red(`Qalaa: the file you downloaded is a known threat: ${download.output}`) : yellow(`Qalaa: the file you downloaded looks suspicious: ${download.output}`));
      printResult(download.output, result);
      say(dim(result.verdict === "malicious" ? "  Do not open it. Delete it, or move it to quarantine in Qalaa Desktop." : "  Only open it if you trust where it came from."));
      worst = Math.max(worst, result.verdict === "malicious" ? 2 : 1);
    } else if (result.verdict === "no_known_threat") {
      say(dim(`qalaa: ${download.output}: checked, no known threats found.`));
    }
  }
  await writeCache(cache).catch(() => undefined);
  return worst;
}

async function scan(paths: string[]): Promise<number> {
  const signatures = await loadSignatures();
  const cache = await readCache();
  let worst = 0;
  let count = 0;
  for (const target of paths) {
    const full = resolve(target);
    const files = (await isDirectory(full)) ? walk(full) : (async function* () { yield full; })();
    for await (const file of files) {
      const result = await scanCached(file, signatures, cache);
      count += 1;
      if (result.verdict === "malicious") worst = 2;
      else if (result.verdict === "suspicious") worst = Math.max(worst, 1);
      if (result.verdict !== "no_known_threat" || paths.length === 1) printResult(file, result);
    }
  }
  await writeCache(cache).catch(() => undefined);
  say(worst ? red(`${count} file(s) checked; threats found.`) : green(`${count} file(s) checked; no known threats found.`));
  return worst;
}

async function terminal(action: string | undefined): Promise<number> {
  if (action === "on") {
    // Running from the installed launcher: reuse the same runtime and script.
    const cliScript = process.env.QALAA_CLI_SCRIPT ?? (process.argv[1] && process.argv[1].endsWith(".js") ? resolve(process.argv[1]) : null);
    const { changed } = await enableTerminal(process.execPath, cliScript, undefined, undefined, process.env.QALAA_DATA_DIR);
    say(green("Terminal protection is on for new terminals."));
    for (const file of changed) say(dim(`  updated ${file}`));
    return 0;
  }
  if (action === "off") {
    const { changed } = await disableTerminal();
    say("Terminal protection is off.");
    for (const file of changed) say(dim(`  updated ${file}`));
    return 0;
  }
  const status = await terminalStatus();
  for (const shell of status.shells) say(`${shell.shell}: ${shell.enabled ? green("on") : "off"} ${dim(`(${shell.rc})`)}`);
  return 0;
}

const HELP = `qalaa: Qalaa terminal protection

  qalaa scan <files or folders>   scan and print verdicts (exit 1 suspicious, 2 known threat)
  qalaa check "<command>"         explain what a command would do, without running it
  qalaa terminal on|off|status    check commands in bash and zsh before they run
`;

export async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  const args = rest[0] === "--" ? rest.slice(1) : rest;
  switch (command) {
    case "guard":
      return guard(args.join(" "));
    case "after":
      return after(args.join(" "));
    case "check": {
      const r = await review(args.join(" "));
      if (!r.risks.length && !r.scans.length && !r.notes.length) say(green("Nothing in this command matches Qalaa's warning signs."));
      else printReview(r);
      return r.risks.some((x) => x.level === "block") || r.scans.some((s) => s.result.verdict === "malicious") ? 2 : r.risks.length || r.scans.some((s) => s.result.verdict === "suspicious") ? 1 : 0;
    }
    case "scan":
      if (!args.length) {
        process.stdout.write(HELP);
        return 64;
      }
      return scan(args);
    case "terminal":
      return terminal(args[0]);
    default:
      process.stdout.write(HELP);
      return command ? 64 : 0;
  }
}

// Started directly (not imported by tests): process.argv = [runtime, script or "qalaa", ...arguments].
if (process.env.QALAA_CLI_IMPORTED !== "1") {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error: unknown) => {
      say(red(`qalaa: ${error instanceof Error ? error.message : String(error)}`));
      // When the checker itself fails, the command runs: a broken checker must not lock up the terminal.
      process.exit(argvIsGuard() ? 0 : 70);
    },
  );
}

function argvIsGuard(): boolean {
  return process.argv[2] === "guard";
}
