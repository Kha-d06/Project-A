/**
 * Heuristic rules applied to file contents. They look for well-known malware
 * delivery techniques, not for specific malware families. Each rule explains
 * itself in plain language. All functions are pure and work on buffers.
 */
import type { Finding } from "./types";

// The EICAR string is the harmless, industry-standard antivirus test file.
export const EICAR = Buffer.from("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "latin1");

const DOCUMENT_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "mov", "zip",
]);
const RUNNABLE_EXTENSIONS = new Set([
  "exe", "scr", "com", "pif", "bat", "cmd", "msi", "dll", "cpl", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "lnk", "jar", "reg", "app", "dmg", "pkg", "apk", "iso", "img",
]);
const SCRIPT_EXTENSIONS = new Set(["ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "sh", "zsh", "command", "py", "pl", "lnk"]);

/** A script by name, or a file starting with "#!". */
export function isScript(name: string, content: Buffer): boolean {
  return SCRIPT_EXTENSIONS.has(extensionOf(name)) || content.subarray(0, 2).toString("latin1") === "#!";
}

export function extensionOf(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? name;
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
}

export function executableKind(head: Buffer): string | null {
  if (head.length >= 2 && head[0] === 0x4d && head[1] === 0x5a) return "Windows program";
  if (head.length >= 4 && head.readUInt32BE(0) === 0x7f454c46) return "Linux program";
  if (head.length >= 4 && [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(head.readUInt32BE(0))) {
    return "macOS program";
  }
  return null;
}

/** Problems visible from the name alone. */
export function nameFindings(name: string): Finding[] {
  const findings: Finding[] = [];
  const base = name.split(/[\\/]/).pop() ?? name;
  if (/[‮‭‏]/.test(base)) {
    findings.push({
      severity: "high",
      rule: "rtlo_name",
      title: "File name uses hidden text-direction characters",
      detail: "Invisible characters reverse part of the name so that a program can look like a document (for example “invoice‮fdp.exe” shows as “invoiceexe.pdf”).",
    });
  }
  const parts = base.toLowerCase().split(".");
  if (parts.length >= 3) {
    const last = parts[parts.length - 1] ?? "";
    const previous = parts[parts.length - 2] ?? "";
    if (RUNNABLE_EXTENSIONS.has(last) && DOCUMENT_EXTENSIONS.has(previous)) {
      findings.push({
        severity: "high",
        rule: "double_extension",
        title: `“${base}” is a program named to look like a .${previous} file`,
        detail: "Windows hides known extensions by default, so this file shows as a document but runs as a program when opened.",
      });
    }
  }
  if (/\s{6,}\.\w+$/.test(base)) {
    findings.push({
      severity: "medium",
      rule: "padded_name",
      title: "File name is padded with spaces to hide its real extension",
      detail: "Long runs of spaces push the real file type out of view in file lists.",
    });
  }
  return findings;
}

const SCRIPT_PATTERNS: { rule: string; pattern: RegExp; title: string }[] = [
  { rule: "encoded_powershell", pattern: /powershell(\.exe)?["'\s].{0,80}-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}/i, title: "Runs a hidden, encoded PowerShell command" },
  { rule: "download_execute", pattern: /(downloadstring|downloadfile|invoke-webrequest|iwr\s|start-bitstransfer|new-object\s+net\.webclient)[\s\S]{0,300}(iex|invoke-expression|start-process|\.exe)/i, title: "Downloads and runs code from the internet" },
  { rule: "lolbin_download", pattern: /(certutil(\.exe)?\s.{0,40}-urlcache|bitsadmin(\.exe)?\s.{0,40}\/transfer|mshta(\.exe)?\s+["']?https?:)/i, title: "Abuses a built-in Windows tool to fetch files" },
  { rule: "shell_run_url", pattern: /wscript\.shell[\s\S]{0,400}\.run[\s\S]{0,400}https?:\/\//i, title: "Script starts commands that contact the internet" },
  { rule: "defender_tamper", pattern: /(set-mppreference\s.{0,60}-disable|add-mppreference\s.{0,40}-exclusionpath)/i, title: "Tries to switch off or bypass Microsoft Defender" },
  { rule: "curl_pipe_shell", pattern: /(curl|wget)\s[^\n|]{0,200}\|\s*(ba|z)?sh\b/i, title: "Pipes a download straight into a shell" },
];

/** Readable text of a buffer, including UTF-16 strings (as in .lnk files). */
function textOf(buffer: Buffer): string {
  const latin = buffer.toString("latin1");
  const utf16 = buffer.length > 1 ? buffer.toString("utf16le") : "";
  return `${latin}\n${utf16.replace(/[^\x20-\x7e\n]/g, "")}`;
}

export function scriptFindings(name: string, content: Buffer): Finding[] {
  if (!isScript(name, content)) return [];
  const text = textOf(content.subarray(0, 2 * 1024 * 1024));
  return SCRIPT_PATTERNS.filter(({ pattern }) => pattern.test(text)).map(({ rule, title }) => ({
    severity: "high" as const,
    rule,
    title,
    detail: "This is a common step in malware droppers. Legitimate installers rarely do it this way. Do not run the file.",
  }));
}

export function pdfFindings(content: Buffer): Finding[] {
  if (!content.subarray(0, 1024).toString("latin1").includes("%PDF")) return [];
  const text = content.toString("latin1");
  const has = (name: string) => new RegExp(`/${name}(?![A-Za-z])`).test(text);
  const findings: Finding[] = [];
  if (has("Launch")) {
    findings.push({ severity: "high", rule: "pdf_launch", title: "PDF can launch another program", detail: "Ordinary documents have no reason to start programs." });
  }
  if ((has("JavaScript") || has("JS")) && (has("OpenAction") || has("AA"))) {
    findings.push({ severity: "medium", rule: "pdf_autorun_js", title: "PDF runs JavaScript when it opens", detail: "Used by interactive forms, and also by exploits against outdated PDF readers." });
  }
  return findings;
}

/** A program whose name says it is something else. */
export function disguiseFindings(name: string, head: Buffer): Finding[] {
  const kind = executableKind(head);
  const extension = extensionOf(name);
  if (kind && DOCUMENT_EXTENSIONS.has(extension) && extension !== "zip") {
    return [
      {
        severity: "high",
        rule: "disguised_program",
        title: `This “.${extension}” file is really a ${kind.toLowerCase()}`,
        detail: "The content is a program even though the name says otherwise. This is a classic trick to get it run.",
      },
    ];
  }
  return [];
}

export function containsEicar(content: Buffer): boolean {
  return content.includes(EICAR);
}
