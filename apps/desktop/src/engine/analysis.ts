/**
 * Deeper static analysis, all on buffers and without running anything:
 *  - Windows programs (PE): sections, packers, entropy, and the functions a
 *    program imports, grouped into capabilities (injecting into other
 *    programs, recording keys, hollowing out processes);
 *  - behaviour strings in programs and scripts (ransom notes, shadow-copy
 *    deletion, crypto miners, credential theft, reverse shells);
 *  - Office macros, decompressed (MS-OVBA) so their source can be read;
 *  - document tricks: RTF exploits, remote templates, DDE, Follina-style links,
 *    Excel 4.0 macro sheets;
 *  - web-style files: HTML smuggling and phishing attachments, scripted SVG
 *    images, OneNote droppers, internet shortcuts to remote programs.
 *
 * Weak signals (a packer, an unusual import) are "indicators": shown, but they
 * only make a file suspicious together (see combineIndicators).
 */
import type { Finding } from "./types";

// --- Helpers ----------------------------------------------------------------------------

/** Shannon entropy in bits per byte (0..8). Packed or encrypted data is close to 8. */
export function entropy(data: Buffer): number {
  if (!data.length) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const byte of data) counts[byte]!++;
  let bits = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / data.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

const TEXT_LIMIT = 16 * 1024 * 1024;

/** Printable text of a buffer: Latin-1 plus UTF-16 strings (Windows programs store many that way). */
export function readableText(buffer: Buffer): string {
  const slice = buffer.subarray(0, TEXT_LIMIT);
  const latin = slice.toString("latin1");
  const utf16 = slice.length > 1 ? slice.toString("utf16le").replace(/[^\x20-\x7e\n\\/:.]/g, " ") : "";
  return `${latin}\n${utf16}`;
}

function finding(severity: Finding["severity"], rule: string, title: string, detail: string): Finding {
  return { severity, rule, title, detail };
}

// --- Windows programs (PE) --------------------------------------------------------------

export interface PeSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawOffset: number;
  rawSize: number;
  executable: boolean;
  writable: boolean;
}

export interface PeInfo {
  is64: boolean;
  isDll: boolean;
  timestamp: number;
  sections: PeSection[];
  /** "kernel32.dll!VirtualAllocEx" (lower-case DLL, function as written). */
  imports: string[];
  importedDlls: string[];
  signed: boolean;
  dotNet: boolean;
  /** Bytes after the last section (installers and droppers keep payloads there). */
  overlaySize: number;
}

const MAX_SECTIONS = 96;
const MAX_IMPORT_DLLS = 256;
const MAX_IMPORTS = 4096;

function cString(buffer: Buffer, offset: number, max = 256): string | null {
  if (offset < 0 || offset >= buffer.length) return null;
  const end = buffer.indexOf(0, offset);
  const stop = end === -1 ? Math.min(buffer.length, offset + max) : Math.min(end, offset + max);
  return buffer.subarray(offset, stop).toString("latin1");
}

/** Parses the PE headers, sections and import table. Returns null for anything that is not a well-formed PE. */
export function parsePe(buffer: Buffer): PeInfo | null {
  try {
    if (buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) return null;
    const peOffset = buffer.readUInt32LE(0x3c);
    if (peOffset + 24 > buffer.length || buffer.readUInt32BE(peOffset) !== 0x50450000) return null;
    const coff = peOffset + 4;
    const sectionCount = Math.min(buffer.readUInt16LE(coff + 2), MAX_SECTIONS);
    const timestamp = buffer.readUInt32LE(coff + 4);
    const optionalSize = buffer.readUInt16LE(coff + 16);
    const characteristics = buffer.readUInt16LE(coff + 18);
    const optional = coff + 20;
    const magic = buffer.readUInt16LE(optional);
    if (magic !== 0x10b && magic !== 0x20b) return null;
    const is64 = magic === 0x20b;
    const directoryCount = buffer.readUInt32LE(optional + (is64 ? 108 : 92));
    const directories = optional + (is64 ? 112 : 96);
    const directory = (index: number) =>
      index < directoryCount && directories + index * 8 + 8 <= buffer.length
        ? { rva: buffer.readUInt32LE(directories + index * 8), size: buffer.readUInt32LE(directories + index * 8 + 4) }
        : { rva: 0, size: 0 };

    const sections: PeSection[] = [];
    const sectionTable = optional + optionalSize;
    for (let i = 0; i < sectionCount; i++) {
      const at = sectionTable + i * 40;
      if (at + 40 > buffer.length) break;
      const flags = buffer.readUInt32LE(at + 36);
      sections.push({
        name: buffer.subarray(at, at + 8).toString("latin1").replace(/\0.*$/s, ""),
        virtualSize: buffer.readUInt32LE(at + 8),
        virtualAddress: buffer.readUInt32LE(at + 12),
        rawSize: buffer.readUInt32LE(at + 16),
        rawOffset: buffer.readUInt32LE(at + 20),
        executable: (flags & 0x20000000) !== 0,
        writable: (flags & 0x80000000) !== 0,
      });
    }
    const toOffset = (rva: number): number => {
      for (const s of sections) {
        const span = Math.max(s.virtualSize, s.rawSize);
        if (rva >= s.virtualAddress && rva < s.virtualAddress + span) return rva - s.virtualAddress + s.rawOffset;
      }
      return rva < buffer.length ? rva : -1; // headers, or a file mapped 1:1
    };

    const imports: string[] = [];
    const importedDlls: string[] = [];
    const importDir = directory(1);
    let descriptor = importDir.rva ? toOffset(importDir.rva) : -1;
    for (let d = 0; descriptor >= 0 && descriptor + 20 <= buffer.length && d < MAX_IMPORT_DLLS; d++, descriptor += 20) {
      const lookup = buffer.readUInt32LE(descriptor);
      const nameRva = buffer.readUInt32LE(descriptor + 12);
      const thunkRva = buffer.readUInt32LE(descriptor + 16);
      if (!lookup && !nameRva && !thunkRva) break;
      const dll = cString(buffer, toOffset(nameRva))?.toLowerCase();
      if (!dll) continue;
      importedDlls.push(dll);
      let thunk = toOffset(lookup || thunkRva);
      const width = is64 ? 8 : 4;
      for (let n = 0; thunk >= 0 && thunk + width <= buffer.length && imports.length < MAX_IMPORTS; n++, thunk += width) {
        const value = is64 ? buffer.readBigUInt64LE(thunk) : BigInt(buffer.readUInt32LE(thunk));
        if (value === 0n) break;
        const byOrdinal = is64 ? (value & 0x8000000000000000n) !== 0n : (value & 0x80000000n) !== 0n;
        if (byOrdinal) continue;
        const fn = cString(buffer, toOffset(Number(value & 0x7fffffffn)) + 2);
        if (fn) imports.push(`${dll}!${fn}`);
      }
    }
    const security = directory(4);
    const lastRawEnd = sections.reduce((max, s) => Math.max(max, s.rawOffset + s.rawSize), 0);
    return {
      is64,
      isDll: (characteristics & 0x2000) !== 0,
      timestamp,
      sections,
      imports,
      importedDlls,
      // The certificate table is addressed by file offset, after the sections.
      signed: security.rva > 0 && security.size > 0,
      dotNet: directory(14).rva > 0,
      overlaySize: Math.max(0, buffer.length - Math.max(lastRawEnd, security.rva > 0 ? security.rva + security.size : 0)),
    };
  } catch {
    return null;
  }
}

const PACKER_SECTIONS: [RegExp, string][] = [
  [/^UPX\d$/i, "UPX"],
  [/^\.aspack$|^\.adata$/i, "ASPack"],
  [/^\.MPRESS\d$/i, "MPRESS"],
  [/^\.petite$/i, "Petite"],
  [/^\.nsp\d$/i, "NsPack"],
  [/^\.themida$|^\.winlice$/i, "Themida"],
  [/^\.vmp\d$/i, "VMProtect"],
  [/^\.enigma\d$/i, "Enigma Protector"],
  [/^\.pelock$/i, "PELock"],
];

function hasAll(imports: Set<string>, names: string[]): boolean {
  return names.every((name) => imports.has(name) || imports.has(`${name}a`) || imports.has(`${name}w`));
}
function hasAny(imports: Set<string>, names: string[]): boolean {
  return names.some((name) => imports.has(name) || imports.has(`${name}a`) || imports.has(`${name}w`));
}

export function peFindings(buffer: Buffer, now = Date.now()): Finding[] {
  const pe = parsePe(buffer);
  if (!pe) return [];
  const findings: Finding[] = [];
  const functions = new Set(pe.imports.map((entry) => entry.split("!")[1]!.toLowerCase()));

  const packer = pe.sections.map((s) => PACKER_SECTIONS.find(([pattern]) => pattern.test(s.name))?.[1]).find(Boolean);
  if (packer) {
    findings.push(
      finding(
        "low",
        "pe_packed",
        `Program is packed with ${packer}`,
        "Its code is compressed or encrypted so it cannot be read until it runs. Some legitimate programs do this; much malware does, to hide from scanners.",
      ),
    );
  }
  const dense = pe.sections.filter((s) => s.executable && s.rawSize > 4096 && s.rawOffset + s.rawSize <= buffer.length)
    .find((s) => entropy(buffer.subarray(s.rawOffset, s.rawOffset + s.rawSize)) > 7.2);
  if (dense && !packer) {
    findings.push(
      finding(
        "low",
        "pe_high_entropy",
        "Program code looks encrypted or compressed",
        `The “${dense.name || "unnamed"}” code section is almost random data, which usually means the real code is unpacked only when it runs.`,
      ),
    );
  }
  if (pe.sections.some((s) => s.executable && s.writable && s.rawSize > 0)) {
    findings.push(
      finding("low", "pe_wx_section", "Program has code that can rewrite itself", "A section is both writable and executable, which packers and shellcode loaders need and ordinary compilers avoid."),
    );
  }
  if (!pe.dotNet && pe.imports.length > 0 && pe.imports.length <= 4 && hasAll(functions, ["loadlibrary", "getprocaddress"])) {
    findings.push(
      finding("low", "pe_few_imports", "Program hides which system functions it uses", "It imports almost nothing and looks functions up while running, which keeps its real abilities out of view."),
    );
  }
  const injection = hasAll(functions, ["virtualallocex", "writeprocessmemory"]) && hasAny(functions, ["createremotethread", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread"]);
  if (injection) {
    findings.push(
      finding("low", "pe_injection", "Program can inject code into other programs", "It imports the functions used to write into another program's memory and start it running there. Debuggers and some security tools do this too."),
    );
  }
  if (hasAny(functions, ["ntunmapviewofsection", "zwunmapviewofsection"]) && hasAll(functions, ["setthreadcontext", "resumethread", "writeprocessmemory"])) {
    findings.push(
      finding("medium", "pe_hollowing", "Program can hollow out another program", "It imports the exact set of functions used to replace a legitimate program's code with its own (process hollowing), a technique almost only malware uses."),
    );
  }
  if (hasAny(functions, ["setwindowshookex"]) && hasAny(functions, ["getasynckeystate", "getkeyboardstate", "getkeystate"])) {
    findings.push(
      finding("low", "pe_keylogger", "Program can watch keystrokes in other programs", "It can install a system-wide keyboard hook and read key states, the building blocks of a keylogger. Hotkey and accessibility tools use them too."),
    );
  }
  if (pe.timestamp > now / 1000 + 86_400 * 2) {
    findings.push(finding("low", "pe_future_timestamp", "Program claims to be built in the future", "Its build date is later than today, which means the header was edited by hand."));
  }
  return findings;
}

// --- Behaviour strings (programs and scripts) -------------------------------------------

interface StringRule {
  rule: string;
  severity: Finding["severity"];
  title: string;
  detail: string;
  test: (text: string) => boolean;
}

const BROWSER_TARGETS = [/\\Login Data\b/, /\blogins\.json\b/, /\bkey4\.db\b/, /\\Network\\Cookies\b/, /os_crypt/];
const OTHER_TARGETS = [/\bwallet\.dat\b/i, /\\Telegram Desktop\\tdata/i, /discord(app)?\\Local Storage\\leveldb/i, /\b(Exodus|Electrum|Atomic Wallet|MetaMask)\b/, /\\FileZilla\\recentservers\.xml/i];

export const STRING_RULES: StringRule[] = [
  {
    rule: "ransom_note",
    severity: "high",
    title: "Contains a ransom demand",
    detail: "It carries the text of a ransom note: files are encrypted and must be paid for. Do not run it; if it has already run, disconnect the computer and get help.",
    test: (t) => /(your|all) (important )?files (have been|are|were) (encrypted|locked)/i.test(t) && /(bitcoin|monero|\.onion\b|tor browser|btc wallet)/i.test(t),
  },
  {
    rule: "shadow_copy_delete",
    severity: "high",
    title: "Deletes Windows recovery copies",
    detail: "It removes shadow copies or the backup catalogue so files cannot be restored, which ransomware does just before encrypting.",
    test: (t) => /vssadmin(\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?[^\n]{0,60}recoveryenabled\s+no/i.test(t),
  },
  {
    rule: "crypto_miner",
    severity: "high",
    title: "Contains a cryptocurrency miner",
    detail: "It connects to a mining pool. Hidden miners use your processor and electricity to earn money for someone else.",
    test: (t) => /stratum\+(tcp|ssl|tls):\/\//i.test(t) || (/\bxmrig\b/i.test(t) && /--donate-level|randomx|cryptonight/i.test(t)),
  },
  {
    rule: "credential_theft",
    severity: "high",
    title: "Looks for saved passwords, cookies and crypto wallets",
    detail: "It references where browsers keep saved passwords and where messengers and wallets keep their data, the shopping list of an information stealer.",
    test: (t) => {
      const browser = BROWSER_TARGETS.filter((p) => p.test(t)).length;
      const other = OTHER_TARGETS.filter((p) => p.test(t)).length;
      return browser >= 1 && other >= 1 && browser + other >= 3;
    },
  },
  {
    rule: "reverse_shell",
    severity: "high",
    title: "Opens a remote control connection",
    detail: "It connects out and hands a command shell to whoever is on the other end (a reverse shell).",
    test: (t) =>
      /bash\s+-i\s+>&\s*\/dev\/tcp\/|\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+|\bnc(at)?(\.exe)?\s+(-\w+\s+)*-e\s+(\/bin\/(ba)?sh|cmd(\.exe)?)\b/i.test(t) ||
      /System\.Net\.Sockets\.TCPClient[\s\S]{0,600}(GetStream|iex|Invoke-Expression)/i.test(t) ||
      /socket\.socket\([\s\S]{0,300}(dup2|subprocess\.(call|Popen))[\s\S]{0,200}\/bin\/(ba)?sh/i.test(t),
  },
  {
    rule: "security_disable",
    severity: "high",
    title: "Switches off the firewall or Defender",
    detail: "It turns off Windows security features. Legitimate software asks you to do this yourself, if ever.",
    test: (t) =>
      /netsh(\.exe)?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable)/i.test(t) ||
      /Set-MpPreference\s[^\n]{0,80}-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection)\s+(\$true|1)/i.test(t) ||
      /Add-MpPreference\s[^\n]{0,60}-Exclusion(Path|Process|Extension)/i.test(t),
  },
  {
    rule: "log_clearing",
    severity: "medium",
    title: "Erases Windows event logs",
    detail: "Clearing the logs hides what happened on the computer, a common step after an intrusion.",
    test: (t) => /wevtutil(\.exe)?\s+(cl|clear-log)\s|Clear-EventLog\s/i.test(t),
  },
  {
    rule: "sandbox_evasion",
    severity: "low",
    title: "Checks whether it is being analysed",
    detail: "It looks for virtual machines or analysis sandboxes, so it can behave innocently while being watched.",
    test: (t) => [/VBoxService\.exe|VBoxTray/i, /vmtoolsd\.exe|vmware tools/i, /SbieDll\.dll/i, /\bwine_get_unix_file_name\b/, /\bprocmon\.exe\b|\bwireshark\.exe\b|\bx64dbg\b|\bollydbg\b/i].filter((p) => p.test(t)).length >= 2,
  },
];

export function stringFindings(content: Buffer, text = readableText(content)): Finding[] {
  return STRING_RULES.filter((rule) => rule.test(text)).map((rule) => finding(rule.severity, rule.rule, rule.title, rule.detail));
}

// --- Scripts --------------------------------------------------------------------------

const SCRIPT_RULES: { rule: string; severity: Finding["severity"]; title: string; detail: string; pattern: RegExp }[] = [
  {
    rule: "amsi_bypass",
    severity: "high",
    title: "Disables Windows' script scanning (AMSI)",
    detail: "It patches or switches off the interface Windows uses to show scripts to antivirus software, so its next steps go unseen.",
    pattern: /amsiInitFailed|AmsiScanBuffer|AmsiUtils|amsi\.dll[\s\S]{0,200}(VirtualProtect|WriteProcessMemory)/i,
  },
  {
    rule: "base64_execute",
    severity: "high",
    title: "Decodes hidden code and runs it",
    detail: "It turns an encoded blob back into code and executes it straight away, so the real instructions are never visible in the file.",
    pattern: /FromBase64String[\s\S]{0,400}(Invoke-Expression|\biex\b|\[Reflection\.Assembly\]::Load|\.Invoke\()|(\biex\b|Invoke-Expression)[\s\S]{0,200}FromBase64String|eval\s*\(\s*(atob|unescape|decodeURIComponent|Buffer\.from)\s*\(|exec\s*\(\s*(base64\.b64decode|zlib\.decompress)|echo\s+[A-Za-z0-9+/=]{60,}\s*\|\s*base64\s+(-d|--decode)\s*\|\s*(ba)?sh/i,
  },
  {
    rule: "char_obfuscation",
    severity: "medium",
    title: "Code is deliberately scrambled",
    detail: "It builds its commands character by character so they cannot be read or matched, a common way to slip past scanners.",
    pattern: /((\[char\]\s*\d{2,3}\s*\+?\s*){20,})|((chr\w?\s*\(\s*\d{2,3}\s*\)\s*&?\s*){20,})|(String\.fromCharCode\s*\(\s*(\d{2,3}\s*,\s*){30,})/i,
  },
  {
    rule: "hidden_window",
    severity: "medium",
    title: "Starts PowerShell hidden and without its safety settings",
    detail: "Hiding the window and skipping the execution policy and profile are typical of scripts that do not want to be noticed.",
    pattern: /powershell(\.exe)?["'\s][^\n]{0,120}-w(in(dow(style)?)?)?\s+(hidden|1)\b[^\n]{0,120}-(ep|exec(ution(policy)?)?)\s+bypass|powershell(\.exe)?["'\s][^\n]{0,120}-(ep|exec(ution(policy)?)?)\s+bypass[^\n]{0,120}-w(in(dow(style)?)?)?\s+(hidden|1)\b/i,
  },
  {
    rule: "script_persistence",
    severity: "medium",
    title: "Makes itself start automatically",
    detail: "It adds a scheduled task, a Run registry entry or a cron job so it runs again after every restart.",
    pattern: /schtasks(\.exe)?\s+\/create[\s\S]{0,200}\/sc\s+(onlogon|onstart|minute|hourly)|reg(\.exe)?\s+add\s+["']?(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|(New|Set)-ItemProperty[\s\S]{0,160}CurrentVersion\\Run|\(crontab\s+-l[\s\S]{0,120}\)\s*\|\s*crontab\s+-|@reboot\s+\S/i,
  },
];

export function scriptRuleFindings(content: Buffer): Finding[] {
  const text = readableText(content.subarray(0, 4 * 1024 * 1024));
  return SCRIPT_RULES.filter((rule) => rule.pattern.test(text)).map((rule) => finding(rule.severity, rule.rule, rule.title, rule.detail));
}

// --- Office macros (MS-OVBA) ------------------------------------------------------------

/** Decompresses one MS-OVBA compressed container starting at `start` (the 0x01 signature byte). */
export function decompressVba(buffer: Buffer, start: number, limit = 1024 * 1024): Buffer | null {
  if (buffer[start] !== 0x01) return null;
  const out: number[] = [];
  let pos = start + 1;
  while (pos + 2 <= buffer.length && out.length < limit) {
    const header = buffer.readUInt16LE(pos);
    if (((header >> 12) & 0x7) !== 0x3) break;
    const chunkEnd = Math.min(buffer.length, pos + (header & 0x0fff) + 3);
    const compressed = (header & 0x8000) !== 0;
    pos += 2;
    const chunkStart = out.length;
    if (!compressed) {
      for (let i = 0; i < 4096 && pos < buffer.length; i++) out.push(buffer[pos++]!);
      continue;
    }
    while (pos < chunkEnd && out.length < limit) {
      const flags = buffer[pos++]!;
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit++) {
        if (((flags >> bit) & 1) === 0) {
          out.push(buffer[pos++]!);
          continue;
        }
        if (pos + 2 > chunkEnd) return Buffer.from(out);
        const token = buffer.readUInt16LE(pos);
        pos += 2;
        const difference = out.length - chunkStart;
        const bitCount = Math.max(Math.ceil(Math.log2(Math.max(difference, 1))), 4);
        const lengthMask = 0xffff >> bitCount;
        const length = (token & lengthMask) + 3;
        const offset = (token >> (16 - bitCount)) + 1;
        const source = out.length - offset;
        if (source < chunkStart) return Buffer.from(out); // corrupt: stop rather than read garbage
        for (let i = 0; i < length; i++) out.push(out[source + i]!);
      }
    }
    pos = chunkEnd;
  }
  return Buffer.from(out);
}

/** Every macro module's source found in a vbaProject.bin or a legacy Office file. */
export function macroSources(content: Buffer, maxModules = 50): string[] {
  const sources: string[] = [];
  const marker = Buffer.from("\x00Attribut", "latin1");
  let at = content.indexOf(marker);
  while (at >= 3 && sources.length < maxModules) {
    const source = decompressVba(content, at - 3);
    if (source && source.length > 20) sources.push(source.toString("latin1"));
    at = content.indexOf(marker, at + marker.length);
  }
  return sources;
}

const AUTO_RUN = /\b(Auto_?Open|AutoExec|AutoClose|Document_Open|Document_Close|Workbook_Open|Workbook_BeforeClose|Workbook_Activate)\b/i;
const MACRO_ACTIONS = /\b(Shell(Execute)?\s*\(|WScript\.Shell|Shell\.Application|URLDownloadToFile|MSXML2\.(Server)?XMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream|CallByName|powershell|cmd(\.exe)?\s*\/c|mshta|regsvr32|rundll32|Lib\s+"(kernel32|ntdll)")/i;

export function isOleFile(head: Buffer): boolean {
  return head.length >= 8 && head.readUInt32BE(0) === 0xd0cf11e0 && head.readUInt32BE(4) === 0xa1b11ae1;
}

export function macroFindings(content: Buffer): Finding[] {
  const sources = macroSources(content);
  const ole = isOleFile(content);
  const hasVbaProject = ole && content.includes(Buffer.from("_VBA_PROJECT", "utf16le"));
  if (!sources.length) {
    return hasVbaProject
      ? [finding("medium", "office_macros", "Document contains macros", "Macros are the most common way Office files deliver malware. Do not click “Enable content” unless you expected macros from a sender you trust.")]
      : [];
  }
  const code = sources.join("\n");
  const findings: Finding[] = [];
  if (ole) {
    findings.push(finding("medium", "office_macros", "Document contains macros", "Macros are the most common way Office files deliver malware. Do not click “Enable content” unless you expected macros from a sender you trust."));
  }
  const autorun = AUTO_RUN.test(code);
  const action = MACRO_ACTIONS.test(code);
  if (autorun && action) {
    findings.push(
      finding(
        "high",
        "macro_autorun_action",
        "Macro starts a program or downloads a file as soon as the document opens",
        "The macro runs automatically and launches commands or fetches files from the internet: the classic Office malware pattern. Do not enable content.",
      ),
    );
  } else if (action) {
    findings.push(finding("medium", "macro_action", "Macro can start programs or download files", "Ordinary document macros format text and do calculations; this one can run commands or reach the internet."));
  }
  return findings;
}

// --- Documents --------------------------------------------------------------------------

export function rtfFindings(content: Buffer): Finding[] {
  if (!content.subarray(0, 8).toString("latin1").startsWith("{\\rt")) return [];
  const text = content.subarray(0, 8 * 1024 * 1024).toString("latin1");
  const findings: Finding[] = [];
  const objects = /\\objdata|\\object\b|\\objupdate/i.test(text);
  if (objects && /equation\.3|4571756174696f6e2e33|equation native|0002ce02-0000-0000-c000-000000000046/i.test(text.replace(/\s+/g, ""))) {
    findings.push(
      finding("high", "rtf_equation_exploit", "RTF document targets the Equation Editor vulnerability", "It embeds an old Equation Editor object, the target of exploits (CVE-2017-11882 and others) that run code just by opening the document."),
    );
  } else if (objects && /\\objupdate/i.test(text)) {
    findings.push(finding("medium", "rtf_auto_object", "RTF document loads an embedded object automatically", "Objects that update on open are used to run exploit code without a click."));
  }
  return findings;
}

/** Checks parts of Office Open XML files (members of the .docx/.xlsx/.pptx zip). */
export function ooxmlPartFindings(partName: string, content: Buffer): Finding[] {
  const name = partName.toLowerCase();
  const findings: Finding[] = [];
  if (name.endsWith(".rels")) {
    const text = content.toString("utf8");
    const external = [...text.matchAll(/<Relationship\b[^>]*>/gi)].map((m) => m[0]).filter((r) => /TargetMode\s*=\s*["']External["']/i.test(r));
    if (external.some((r) => /Target\s*=\s*["'](mhtml:|ms-msdt:|search-ms:|ms-officecmd:)/i.test(r) || /Target\s*=\s*["'][^"']*!["']/.test(r))) {
      findings.push(
        finding("high", "ooxml_protocol_exploit", "Document calls a Windows protocol that can run code", "It links to an mhtml:, ms-msdt: or similar address, the trick behind “Follina” (CVE-2022-30190) that runs code when the document is opened or previewed."),
      );
    } else if (external.some((r) => /\/(attachedTemplate|oleObject|frame|subDocument)["']/i.test(r) && /Target\s*=\s*["'](https?:|\\\\|file:)/i.test(r))) {
      findings.push(
        finding("high", "ooxml_remote_template", "Document downloads a template or object from the internet when opened", "Remote templates let a harmless-looking file fetch macros or exploits after it has passed email filters (template injection)."),
      );
    }
  }
  if (/^word\/(document|header\d*|footer\d*)\.xml$/.test(name)) {
    const text = content.toString("utf8");
    if (/<w:instrText[^>]*>\s*DDE(AUTO)?\b|w:fldSimple[^>]+w:instr\s*=\s*["']\s*DDE(AUTO)?\b/i.test(text)) {
      findings.push(finding("high", "ooxml_dde", "Document runs a command through DDE", "A DDE field asks Word to start another program, a way to run commands without macros."));
    }
  }
  if (/^xl\/macrosheets\//.test(name)) {
    findings.push(finding("medium", "excel4_macros", "Workbook contains Excel 4.0 macros", "Old-style macro sheets are rarely used today except to hide malware from macro scanners."));
  }
  return findings;
}

// --- Web-style files ------------------------------------------------------------------

const HTML_EXTENSIONS = new Set(["html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg", "hta"]);

export function htmlFindings(name: string, content: Buffer): Finding[] {
  const extension = name.split(".").pop()?.toLowerCase() ?? "";
  const head = content.subarray(0, 512).toString("latin1").trimStart().toLowerCase();
  if (!HTML_EXTENSIONS.has(extension) && !head.startsWith("<!doctype html") && !head.startsWith("<html")) return [];
  const text = content.subarray(0, 8 * 1024 * 1024).toString("utf8");
  const findings: Finding[] = [];
  const bigBlob = /["'`][A-Za-z0-9+/]{20000,}={0,2}["'`]/.test(text) || /(\\x[0-9a-f]{2}){5000,}/i.test(text);
  const savesFile = /msSaveOrOpenBlob|navigator\.msSaveBlob|\.download\s*=|download\s*=\s*["'][^"']+\.(exe|zip|iso|img|js|hta|vbs|lnk|msi|one|scr)["']/i.test(text);
  if (bigBlob && savesFile && /createObjectURL|new\s+Blob\s*\(/i.test(text)) {
    findings.push(
      finding("high", "html_smuggling", "Web page builds a file and downloads it by itself", "The page carries an encoded file and saves it to your computer when opened (HTML smuggling), a way to get malware past email and web filters."),
    );
  }
  const password = /<input[^>]+type\s*=\s*["']?password/i.test(text);
  const sends = /<form[^>]+action\s*=\s*["']?https?:\/\//i.test(text) || /(fetch|\.open)\s*\(\s*["'](POST["']\s*,\s*["'])?https?:\/\//i.test(text) || /api\.telegram\.org\/bot/i.test(text);
  if (password && sends && extension !== "svg") {
    findings.push(
      finding(
        "high",
        "html_phishing_form",
        "Saved web page asks for a password and sends it to a website",
        "Sign-in pages arrive in emails as attachments so the real address is never shown. Real services never ask you to sign in from a file.",
      ),
    );
  }
  if (extension === "svg" && /<script\b|\bon(load|click)\s*=|javascript:/i.test(text)) {
    findings.push(finding("medium", "svg_script", "Image file contains a script", "Pictures do not need code. Scripted SVG images are used to redirect to phishing pages or drop files."));
  }
  if (/(window|document|top)\.location(\.href)?\s*=\s*[^;]{0,200}(atob|unescape|decodeURIComponent)\s*\(/i.test(text) || /location(\.href)?\s*=\s*["']https?:\/\/[^"']+#[^"'@]*@[^"']+["']/i.test(text)) {
    findings.push(finding("low", "html_hidden_redirect", "Web page sends you somewhere hidden", "It forwards the browser to an address it decodes at the last moment, sometimes with your email address attached."));
  }
  return findings;
}

/** OneNote files with embedded programs or scripts (used heavily in 2023 campaigns). */
export function oneNoteFindings(name: string, content: Buffer): Finding[] {
  const isOne = name.toLowerCase().endsWith(".one") || content.subarray(0, 16).equals(Buffer.from("e4525c7b8cd8a74daeb15378d02996d3", "hex"));
  if (!isOne) return [];
  const text = content.subarray(0, 32 * 1024 * 1024).toString("latin1");
  const embedded = /HTA:APPLICATION|<script\b|\x4d\x5a\x90\x00|WScript\.Shell|powershell|@echo off|cmd\.exe\s*\/c/i.test(text);
  return embedded
    ? [finding("high", "onenote_embedded", "OneNote file carries a hidden program or script", "Behind an image saying “double-click to view”, it embeds a file that runs commands. Do not click inside it.")]
    : [];
}

/** .url / .website shortcuts that open a remote program, and .library-ms / .search-ms pointing to remote shares. */
export function shortcutFindings(name: string, content: Buffer): Finding[] {
  const extension = name.split(".").pop()?.toLowerCase() ?? "";
  if (!["url", "website", "library-ms", "search-ms", "searchconnector-ms"].includes(extension)) return [];
  const text = content.subarray(0, 64 * 1024).toString("utf8");
  if (/URL\s*=\s*(file:\/\/|\\\\)[^\r\n]*\.(exe|scr|bat|cmd|js|vbs|hta|lnk|cpl|msi|dll)|URL\s*=\s*(search-ms|ms-msdt|ms-appinstaller):/i.test(text) || /<url>\s*(\\\\|https?:\/\/)[^<]*(davwwwroot|@ssl|@\d+)/i.test(text)) {
    return [finding("high", "remote_shortcut", "Shortcut opens a program from a remote computer", "Clicking it runs a file stored on someone else's server, a way to deliver malware without downloading anything first.")];
  }
  return [];
}

// --- Combining weak signals -------------------------------------------------------------

const INDICATOR_WEIGHT: Record<string, number> = {
  pe_packed: 1,
  pe_high_entropy: 1,
  pe_wx_section: 1,
  pe_few_imports: 1,
  pe_injection: 2,
  pe_keylogger: 2,
  pe_future_timestamp: 1,
  pe_hollowing: 2,
  sandbox_evasion: 2,
  char_obfuscation: 1,
  hidden_window: 1,
  script_persistence: 1,
  log_clearing: 1,
  html_hidden_redirect: 1,
  macro_action: 1,
};

/** Several weak signals together are much stronger than any one: report that as its own finding. */
export function combineIndicators(findings: Finding[]): Finding[] {
  const rules = new Set(findings.filter((f) => !f.member).map((f) => f.rule));
  const present = [...rules].filter((rule) => INDICATOR_WEIGHT[rule]);
  const score = present.reduce((sum, rule) => sum + INDICATOR_WEIGHT[rule]!, 0);
  if (present.length >= 2 && score >= 4) {
    return [
      finding(
        "high",
        "combined_indicators",
        `Several warning signs together (${present.length})`,
        "Each sign alone can have an innocent explanation, but this combination is typical of malware. Do not run it unless you know exactly where it came from.",
      ),
    ];
  }
  return [];
}
