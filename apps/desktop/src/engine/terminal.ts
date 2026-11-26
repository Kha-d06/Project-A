/**
 * Terminal protection: reads a command line before the shell runs it and points
 * out what could hurt the computer. Pure functions; the `qalaa` command (cli.ts)
 * adds the network fetch, the file scans and the question to the person.
 *
 * It looks for:
 *  - scripts from the internet piped into a shell (curl ... | sh, bash <(curl ...),
 *    eval "$(wget -qO- ...)"); the CLI downloads and scans them first;
 *  - hidden characters in pasted commands (zero-width, text-direction, look-alike letters);
 *  - decoded hidden commands (base64 -d | sh), reverse shells;
 *  - commands that destroy data or switch off protection, or wipe the shell history;
 *  - persistence from the internet (keys added to authorized_keys, cron jobs);
 *  - files about to run (./x, bash x.sh, python3 x.py, ./app.AppImage), scanned first;
 *  - downloads (curl -o, wget), scanned once the command has finished;
 *  - packages with names one letter away from popular ones (typosquatting).
 *
 * A safety net, not a security boundary: the hooks run as the user inside the
 * shell, so anything already running as that user can unset them, and commands
 * run by other programs (not typed into an interactive shell) aren't seen. The
 * interface says so.
 */

export type RiskLevel = "block" | "warn";

export interface CommandRisk {
  level: RiskLevel;
  rule: string;
  title: string;
  detail: string;
}

export interface CommandAnalysis {
  risks: CommandRisk[];
  /** Scripts from the internet that this command would run. */
  fetchUrls: string[];
  /** Local files this command would run or hand to an interpreter. */
  runFiles: string[];
  /** Files this command downloads (checked afterwards). */
  downloads: { url: string | null; output: string }[];
  packages: { manager: string; name: string }[];
}

// --- Splitting a command line -----------------------------------------------------------

/** Splits on |, ;, &&, || and newlines, outside quotes. Each part is tokenised (quotes removed). */
export function segments(line: string): { tokens: string[]; pipedFromPrevious: boolean; raw: string }[] {
  const out: { tokens: string[]; pipedFromPrevious: boolean; raw: string }[] = [];
  let tokens: string[] = [];
  let token = "";
  let hasToken = false;
  let raw = "";
  let quote: "'" | '"' | null = null;
  let piped = false;
  let depth = 0; // $( ... ) and <( ... ) stay inside one token
  const pushToken = () => {
    if (hasToken) tokens.push(token);
    token = "";
    hasToken = false;
  };
  const pushSegment = (nextPiped: boolean) => {
    pushToken();
    if (tokens.length) out.push({ tokens, pipedFromPrevious: piped, raw: raw.trim() });
    tokens = [];
    raw = "";
    piped = nextPiped;
  };
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && i + 1 < line.length) token += line[++i]!;
      else token += c;
      raw += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      hasToken = true;
      raw += c;
      continue;
    }
    if (c === "\\" && i + 1 < line.length) {
      const next = line[++i]!;
      if (next !== "\n") {
        token += next;
        hasToken = true;
      }
      raw += c + next;
      continue;
    }
    if ((c === "$" || c === "<" || c === ">") && line[i + 1] === "(") {
      depth += 1;
      token += c + "(";
      hasToken = true;
      raw += c + "(";
      i += 1;
      continue;
    }
    if (depth > 0) {
      if (c === "(") depth += 1;
      if (c === ")") depth -= 1;
      token += c;
      raw += c;
      continue;
    }
    if (c === "|" && line[i + 1] === "|") {
      pushSegment(false);
      i += 1;
      continue;
    }
    if (c === "&" && line[i + 1] === "&") {
      pushSegment(false);
      i += 1;
      continue;
    }
    if (c === "|") {
      pushSegment(true);
      if (line[i + 1] === "&") i += 1;
      continue;
    }
    if (c === ";" || c === "\n") {
      pushSegment(false);
      continue;
    }
    if (c === " " || c === "\t") {
      pushToken();
      raw += c;
      continue;
    }
    token += c;
    hasToken = true;
    raw += c;
  }
  pushSegment(false);
  return out;
}

const WRAPPERS = new Set(["sudo", "doas", "env", "nohup", "time", "nice", "command", "exec", "stdbuf", "torsocks", "proxychains", "proxychains4"]);

/** The command word of a segment, skipping sudo/env/nohup and VAR=value prefixes. */
export function commandOf(tokens: string[]): { command: string; args: string[]; elevated: boolean } {
  let i = 0;
  let elevated = false;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (WRAPPERS.has(t)) {
      if (t === "sudo" || t === "doas") elevated = true;
      i += 1;
      // sudo's own options (-E, -u user, --preserve-env)
      while (i < tokens.length && tokens[i]!.startsWith("-")) i += /^-(u|g|C|h|p|U|r|t)$/.test(tokens[i]!) ? 2 : 1;
      continue;
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
      i += 1;
      continue;
    }
    break;
  }
  return { command: tokens[i] ?? "", args: tokens.slice(i + 1), elevated };
}

const base = (path: string) => path.split("/").pop() ?? path;
const SHELLS = /^(ba|z|da|k|c|tc|fi)?sh$|^(bash|zsh|dash|ksh|fish)$/;
const INTERPRETERS = /^(python[0-9.]*|perl|ruby|node|nodejs|php[0-9.]*|lua|Rscript|deno|bun)$/;
const FETCHERS = /^(curl|wget|fetch|http|https|xh|aria2c|lwp-request|GET)$/;
const URL_RE = /\b(?:https?|ftp):\/\/[^\s'"`<>|;&)]+/g;

function urlsIn(text: string): string[] {
  return [...text.matchAll(URL_RE)].map((m) => m[0].replace(/[.,]+$/, ""));
}

// --- Rules -------------------------------------------------------------------------------

const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩﻿­]/;
/** Letters from other alphabets that look like Latin ones, inside command words. */
const LOOKALIKE = /[Ѐ-ӿͰ-Ͽ！-～]/;

function risk(level: RiskLevel, rule: string, title: string, detail: string): CommandRisk {
  return { level, rule, title, detail };
}

const POPULAR_PIP = [
  "requests", "numpy", "pandas", "urllib3", "setuptools", "boto3", "botocore", "certifi", "idna", "charset-normalizer", "python-dateutil", "pyyaml", "six", "typing-extensions",
  "cryptography", "packaging", "wheel", "pip", "attrs", "jinja2", "markupsafe", "click", "flask", "django", "fastapi", "uvicorn", "pydantic", "sqlalchemy", "psycopg2",
  "pillow", "matplotlib", "scipy", "scikit-learn", "tensorflow", "torch", "transformers", "openai", "anthropic", "beautifulsoup4", "selenium", "pytest", "colorama",
  "paramiko", "pycryptodome", "pyopenssl", "aiohttp", "httpx", "websockets", "redis", "celery", "pymongo", "discord.py", "tqdm", "rich", "lxml", "docker", "kubernetes",
];
const POPULAR_NPM = [
  "react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "moment", "vue", "next", "typescript", "webpack", "babel-core", "eslint", "prettier",
  "jquery", "underscore", "request", "async", "uuid", "dotenv", "yargs", "glob", "minimist", "body-parser", "cors", "mongoose", "socket.io", "electron", "vite",
  "jest", "mocha", "colors", "node-fetch", "cross-env", "nodemon", "ws", "bcrypt", "jsonwebtoken", "discord.js", "puppeteer", "playwright", "tailwindcss", "esbuild",
];

/** Levenshtein distance, stopping early above `max`. */
export function editDistance(a: string, b: string, max = 2): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost);
      best = Math.min(best, current[j]!);
    }
    if (best > max) return max + 1;
    previous = current;
  }
  return previous[b.length]!;
}

/** A popular package this name imitates, or null (exact names and short names are left alone). */
export function lookalikeOf(name: string, manager: "pip" | "npm"): string | null {
  const clean = name.toLowerCase().replace(/_/g, "-").replace(/\[.*$/, "").replace(/[<>=!~].*$/, "").replace(/@[^/]*$/, "");
  const list = manager === "pip" ? POPULAR_PIP : POPULAR_NPM;
  if (clean.length < 4 || list.includes(clean)) return null;
  for (const popular of list) {
    const distance = editDistance(clean, popular, 2);
    if (distance === 1 || (distance === 2 && popular.length >= 8)) return popular;
    // "python-requests", "requests-py", "reqeusts2"...
    if (clean !== popular && popular.length >= 5 && (clean === `${popular}2` || clean === `${popular}3` || clean === `python-${popular}` || clean === `${popular}-python` || clean === `py${popular}`) && !list.includes(clean)) return popular;
  }
  return null;
}

function packageArgs(args: string[]): string[] {
  const names: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith("-")) {
      if (/^(-r|--requirement|-c|--constraint|-e|--editable|-i|--index-url|--extra-index-url|-t|--target|--prefix|--registry)$/.test(a)) i += 1;
      continue;
    }
    names.push(a);
  }
  return names;
}

/** Output files of a curl or wget call (relative to the current folder). */
function downloadsOf(command: string, args: string[]): { url: string | null; output: string }[] {
  const urls = args.filter((a) => /^(https?|ftp):\/\//.test(a));
  const out: { url: string | null; output: string }[] = [];
  if (command === "curl") {
    for (let i = 0; i < args.length; i++) {
      const a = args[i]!;
      if ((a === "-o" || a === "--output") && args[i + 1] && args[i + 1] !== "-") out.push({ url: urls[0] ?? null, output: args[i + 1]! });
      if (a === "-O" || a === "--remote-name" || (/^-[a-zA-Z]*O[a-zA-Z]*$/.test(a) && !a.includes("o"))) {
        for (const url of urls) {
          const name = decodeURIComponent(base(new URL(url).pathname)) || "index.html";
          out.push({ url, output: name });
        }
      }
    }
  } else if (command === "wget") {
    let explicit: string | null = null;
    let folder = "";
    for (let i = 0; i < args.length; i++) {
      const a = args[i]!;
      if ((a === "-O" || a === "--output-document") && args[i + 1]) explicit = args[i + 1]!;
      else if (a.startsWith("--output-document=")) explicit = a.slice(18);
      else if (/^-[a-zA-Z]*O$/.test(a) && args[i + 1]) explicit = args[i + 1]!;
      else if (/^-[a-zA-Z]*O(.+)$/.test(a)) explicit = /^-[a-zA-Z]*O(.+)$/.exec(a)![1]!; // -qO- or -Ofile
      if ((a === "-P" || a === "--directory-prefix") && args[i + 1]) folder = `${args[i + 1]}/`;
    }
    if (explicit === "-") return [];
    if (explicit) out.push({ url: urls[0] ?? null, output: explicit });
    else for (const url of urls) out.push({ url, output: folder + (decodeURIComponent(base(new URL(url).pathname)) || "index.html") });
  }
  return out;
}

export function analyseCommand(line: string): CommandAnalysis {
  const risks: CommandRisk[] = [];
  const fetchUrls = new Set<string>();
  const runFiles = new Set<string>();
  const downloads: CommandAnalysis["downloads"] = [];
  const packages: CommandAnalysis["packages"] = [];
  const add = (r: CommandRisk) => {
    if (!risks.some((x) => x.rule === r.rule)) risks.push(r);
  };

  if (HIDDEN.test(line)) {
    add(risk("block", "hidden_characters", "The command contains invisible characters", "Pasted commands can hide text that is not shown on screen (zero-width or text-direction characters). What runs may not be what you see. Retype it instead of pasting."));
  }
  const words = line.split(/\s+/).filter((w) => !/^["'].*["']$/.test(w));
  if (words.some((w) => LOOKALIKE.test(w) && /[a-z]/i.test(w))) {
    add(risk("block", "lookalike_characters", "The command mixes in look-alike letters", "Some letters come from another alphabet but look Latin, a trick to make a harmful command or address look familiar."));
  }

  const parts = segments(line);
  parts.forEach((part, index) => {
    const { command, args, elevated } = commandOf(part.tokens);
    const name = base(command);
    const text = part.raw;
    const previous = index > 0 ? parts[index - 1] : undefined;
    const previousCommand = previous ? base(commandOf(previous.tokens).command) : "";

    // Scripts from the internet straight into a shell or interpreter.
    if (part.pipedFromPrevious && (SHELLS.test(name) || INTERPRETERS.test(name)) && previous && (FETCHERS.test(previousCommand) || previousCommand === "base64" || previousCommand === "openssl")) {
      if (FETCHERS.test(previousCommand)) {
        for (const url of urlsIn(previous.raw)) fetchUrls.add(url);
        add(risk("warn", "pipe_to_shell", `Runs a script from the internet${elevated ? " as administrator" : ""} without saving it first`, "Whatever the server sends is run immediately, and it can differ from what you would see in a browser. Qalaa downloads and checks it first."));
      } else {
        add(risk("block", "decoded_to_shell", "Decodes hidden text and runs it as a command", "The real command is encoded so you cannot read it. This is how malicious one-liners hide what they do."));
      }
    }
    for (const token of part.tokens) {
      const inner = /^[<$]\((.*)\)$/s.exec(token)?.[1];
      if (!inner) continue;
      const innerCommand = base(commandOf(segments(inner)[0]?.tokens ?? []).command);
      if (FETCHERS.test(innerCommand) && (SHELLS.test(name) || INTERPRETERS.test(name) || name === "eval" || name === "source" || name === ".")) {
        for (const url of urlsIn(inner)) fetchUrls.add(url);
        add(risk("warn", "pipe_to_shell", `Runs a script from the internet${elevated ? " as administrator" : ""} without saving it first`, "Whatever the server sends is run immediately, and it can differ from what you would see in a browser. Qalaa downloads and checks it first."));
      }
      if (/base64\s+(-d|--decode)/.test(inner) && (SHELLS.test(name) || name === "eval")) {
        add(risk("block", "decoded_to_shell", "Decodes hidden text and runs it as a command", "The real command is encoded so you cannot read it. This is how malicious one-liners hide what they do."));
      }
    }
    if (SHELLS.test(name) && args.some((a, i) => (a === "-c" || /^-[a-z]*c$/.test(a)) && args[i + 1] && /(curl|wget)\s[^|]*\|\s*(ba|z)?sh\b/.test(args[i + 1]!))) {
      for (const url of urlsIn(text)) fetchUrls.add(url);
      add(risk("warn", "pipe_to_shell", "Runs a script from the internet without saving it first", "Whatever the server sends is run immediately. Qalaa downloads and checks it first."));
    }

    // Remote control and destruction.
    if (/\/dev\/(tcp|udp)\/[^\s/]+\/\d+/.test(text) || ((name === "nc" || name === "ncat" || name === "netcat") && args.some((a) => a === "-e" || a === "-c" || a === "--exec" || a === "--sh-exec")) || (name === "socat" && /exec:|system:/i.test(text) && /tcp/i.test(text))) {
      add(risk("block", "reverse_shell", "Opens a remote control connection", "It connects to another computer and hands it a command shell (a reverse shell). Someone on the other end could run anything here."));
    }
    if (name === "rm" && args.some((a) => /^-[a-zA-Z]*r/i.test(a) || a === "--recursive") && args.some((a) => /^(\/|\/\*|~\/?|\$HOME\/?|\/home\/?|\/etc\/?|\/usr\/?|\/boot\/?|\/var\/?|\.\.?\/?\*?)$/.test(a) || a === "--no-preserve-root")) {
      add(risk("block", "destructive", "Deletes a whole system or home folder", "This removes everything under that folder and cannot be undone."));
    }
    if ((name === "dd" && args.some((a) => /^of=\/dev\/(sd|nvme|hd|vd|mmcblk|disk)/.test(a))) || (/^mkfs(\.|$)/.test(name) && args.some((a) => /^\/dev\//.test(a))) || /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(line) || (/>\s*\/dev\/(sd|nvme|hd|vd)[a-z0-9]*/.test(text) && !/2?>\s*\/dev\/null/.test(text))) {
      add(risk("block", "destructive", "Overwrites a disk or freezes the computer", "It writes over a whole drive, formats it, or starts a process bomb. Data on that drive is lost."));
    }
    if (name === "chmod" && args.some((a) => /^-[a-zA-Z]*R/.test(a)) && args.some((a) => /^0?777$/.test(a)) && args.some((a) => /^\/(etc|usr|bin|var)?\/?$/.test(a))) {
      add(risk("block", "destructive", "Opens system files to everyone", "Making system folders writable by every user breaks the system's security."));
    }

    // Switching protection off, hiding traces.
    if ((name === "setenforce" && args[0] === "0") || (name === "ufw" && args[0] === "disable") || (name === "iptables" && args.some((a) => a === "-F" || a === "--flush")) || (name === "systemctl" && /^(stop|disable|mask)$/.test(args[0] ?? "") && args.some((a) => /^(apparmor|firewalld|ufw|auditd|clamav-daemon|clamav-freshclam|fail2ban|nftables)(\.service)?$/.test(a)))) {
      add(risk("warn", "security_off", "Switches off a security feature", "Firewalls, AppArmor, SELinux and audit logging protect the computer. Instructions that ask you to turn them off are a common trick."));
    }
    if ((name === "history" && args.includes("-c")) || /\b(unset\s+HISTFILE|HISTFILE=\/dev\/null|HISTSIZE=0)\b/.test(text) || (name === "shred" && args.some((a) => /history/.test(a)))) {
      add(risk("warn", "history_wipe", "Erases the terminal's history", "Clearing history hides what was run. Malicious instructions often end with this step."));
    }

    // Persistence fed from the internet.
    if (/>>?\s*~?[^\s]*\.ssh\/authorized_keys/.test(text) && (FETCHERS.test(name) || /(curl|wget)\s/.test(line))) {
      add(risk("block", "remote_ssh_key", "Adds a login key downloaded from the internet", "Whoever owns that key could sign in to this computer without a password."));
    }
    if (name === "crontab" && part.pipedFromPrevious && /(curl|wget|base64|\/dev\/tcp)/.test(line)) {
      add(risk("block", "remote_cron", "Schedules a command that reaches the internet", "It adds a repeating job that downloads or decodes something, a typical way for malware to stay on a computer."));
    }

    // Files about to run.
    if (/^(\.{1,2}\/|\/|~\/)/.test(command) && !/^\/(usr|bin|sbin|lib|etc)\//.test(command)) runFiles.add(command);
    if ((SHELLS.test(name) || INTERPRETERS.test(name) || name === "source" || name === ".") && args.length) {
      const file = args.find((a) => !a.startsWith("-"));
      if (file && !/^[<$]\(/.test(file) && !args.some((a) => a === "-c" || a === "-e" || a === "-m")) runFiles.add(file);
    }

    // Downloads, checked after the command.
    if (name === "curl" || name === "wget") {
      try {
        downloads.push(...downloadsOf(name, args));
      } catch {
        // malformed URL
      }
    }

    // Packages.
    const pip = /^pip[0-9.]*$/.test(name) || (INTERPRETERS.test(name) && args[0] === "-m" && /^pip/.test(args[1] ?? ""));
    const pipArgs = pip ? (args[0] === "-m" ? args.slice(2) : args) : [];
    if (pip && pipArgs[0] === "install") {
      for (const pkg of packageArgs(pipArgs.slice(1))) {
        if (/^(https?:|git\+|ftp:)|\.whl$|\.tar\.gz$/.test(pkg)) {
          add(risk("warn", "package_from_url", "Installs a Python package from an address instead of the official index", "Packages from links or archives skip the checks of the official index. Make sure you trust the source."));
          continue;
        }
        packages.push({ manager: "pip", name: pkg });
        const like = lookalikeOf(pkg, "pip");
        if (like) add(risk("warn", "package_lookalike", `“${pkg}” looks like a misspelling of “${like}”`, "Attackers publish packages with names one letter away from popular ones (typosquatting) and hide malware in them. Check the exact name."));
      }
    }
    if (/^(npm|pnpm|yarn|bun)$/.test(name) && /^(i|install|add)$/.test(args[0] ?? "")) {
      for (const pkg of packageArgs(args.slice(1))) {
        if (/^(https?:|git\+|github:|file:)/.test(pkg)) {
          add(risk("warn", "package_from_url", "Installs a package from an address instead of the registry", "Packages from links skip the registry's checks. Make sure you trust the source."));
          continue;
        }
        packages.push({ manager: name, name: pkg });
        const like = lookalikeOf(pkg, "npm");
        if (like) add(risk("warn", "package_lookalike", `“${pkg}” looks like a misspelling of “${like}”`, "Attackers publish packages with names one letter away from popular ones (typosquatting) and hide malware in them. Check the exact name."));
      }
    }
  });

  return { risks, fetchUrls: [...fetchUrls], runFiles: [...runFiles], downloads, packages };
}

/** Plain-language concerns about a script's address itself. */
export function urlConcerns(url: string): string[] {
  const concerns: string[] = [];
  try {
    const parsed = new URL(url);
    if (parsed.protocol === "http:") concerns.push("It is fetched without encryption (http), so anyone on the network could change it on the way.");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) || parsed.hostname.includes(":")) concerns.push("It comes from a bare IP address rather than a named website.");
    if (/^(bit\.ly|tinyurl\.com|is\.gd|t\.co|rebrand\.ly|cutt\.ly|shorturl\.at|rb\.gy|goo\.su)$/i.test(parsed.hostname)) concerns.push("It hides the real address behind a link shortener.");
    if (/^(pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|temp\.sh|0x0\.st|termbin\.com|ghostbin\.\w+|rentry\.co)$/i.test(parsed.hostname)) concerns.push("It comes from a paste or file-dropping site, where anyone can upload anything anonymously.");
  } catch {
    concerns.push("The address could not be read.");
  }
  return concerns;
}

/** Quick filter for the shell hooks: only these lines are worth starting the checker for. */
export const SHELL_PREFILTER =
  "(curl|wget|base64|eval|source |\\./|~/|bash |sh |zsh |python|perl|ruby|node |php |sudo |doas |pip[0-9.]* install|-m pip|npm (i|install|add)|yarn add|pnpm (i|install|add)|bun (i|install|add)|dd |mkfs|crontab|authorized_keys|setenforce|ufw |iptables|/dev/tcp|/dev/udp|nc |ncat |netcat|socat|rm -|chmod -R|history -c|HISTFILE|\\.AppImage|\\.run|\\.sh|:\\(\\))";
