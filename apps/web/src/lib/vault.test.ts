import { describe, expect, it } from "vitest";

import { WrongMasterPassword, changeMasterPassword, createVault, decryptDoc, fromBase64, newItem, pad, toBase64, unlockVault } from "./vault";
import { exportCsv, healthReport, importCsv, matchesSite, parseCsv, strengthLevel } from "./vault-tools";

// Fewer iterations keep the tests fast; the API refuses vaults below 310,000.
const FAST = 1_000;
const USER = "7c0e4b2a-0000-4000-8000-000000000001";

describe("vault encryption", () => {
  it("round-trips, and the ciphertext reveals nothing", async () => {
    const doc = { format: 1 as const, items: [newItem("login", { title: "Bank", username: "me", password: "hunter2-very-secret" })] };
    const { stored } = await createVault("correct horse battery staple", USER, doc, FAST);
    expect(atob(stored.data)).not.toContain("hunter2");
    expect(fromBase64(stored.wrapped_key)).toHaveLength(60);
    expect((fromBase64(stored.data).length - 28) % 1024).toBe(0);
    const { doc: opened, key } = await unlockVault(stored, "correct horse battery staple", USER);
    expect(opened.items[0]!.password).toBe("hunter2-very-secret");
    expect(key.extractable).toBe(false);
  });

  it("rejects a wrong master password and a vault moved to another account", async () => {
    const { stored } = await createVault("correct horse battery staple", USER, undefined, FAST);
    await expect(unlockVault(stored, "correct horse battery stapler", USER)).rejects.toBeInstanceOf(WrongMasterPassword);
    await expect(unlockVault(stored, "correct horse battery staple", "another-user")).rejects.toBeInstanceOf(WrongMasterPassword);
  });

  it("detects tampering and data swapped between vaults", async () => {
    const a = await createVault("first master password", USER, undefined, FAST);
    const b = await createVault("second master password", USER, undefined, FAST);
    const bytes = fromBase64(a.stored.data);
    bytes[bytes.length - 1]! ^= 1;
    await expect(decryptDoc(a.key, toBase64(bytes), USER)).rejects.toThrow();
    await expect(decryptDoc(a.key, b.stored.data, USER)).rejects.toThrow();
  });

  it("changes the master password with a new key and salt", async () => {
    const doc = { format: 1 as const, items: [newItem("note", { title: "Wi-Fi", notes: "router: abc" })] };
    const before = await createVault("old master password", USER, doc, FAST);
    const after = await changeMasterPassword("new master password!", USER, doc, FAST);
    expect(after.stored.kdf.salt).not.toBe(before.stored.kdf.salt);
    expect(after.stored.wrapped_key).not.toBe(before.stored.wrapped_key);
    await expect(unlockVault(after.stored, "old master password", USER)).rejects.toBeInstanceOf(WrongMasterPassword);
    expect((await unlockVault(after.stored, "new master password!", USER)).doc.items[0]!.notes).toBe("router: abc");
  });

  it("pads to whole kilobytes", () => {
    expect(pad("{}").length).toBe(1024);
    expect(pad("x".repeat(1023)).length).toBe(1024);
    expect(pad("x".repeat(1024)).length).toBe(2048);
  });
});

describe("password health", () => {
  it("rates strength pessimistically", () => {
    for (const weak of ["password", "P@ssw0rd", "Summer2026!", "qwerty123", "aaaaaaaaaaaa", "abcdefgh1234"]) expect(strengthLevel(weak), weak).toBe("weak");
    expect(strengthLevel("orbit-candle-maple-jungle-velvet")).toBe("strong");
    expect(strengthLevel("t7#Kq9!vZp2@Lm4x")).toBe("strong");
  });

  it("finds reused, weak, old and breached passwords", () => {
    const now = new Date("2026-11-17T00:00:00Z");
    const a = newItem("login", { password: "shared-Secret-91x!", passwordChanged: "2024-01-01T00:00:00Z" }, now);
    const b = newItem("login", { password: "shared-Secret-91x!" }, now);
    const c = newItem("login", { password: "letmein" }, now);
    const d = newItem("login", { password: "k2#Vt9!pQz7@Lx4w" }, now);
    const note = newItem("note", { notes: "not a password" }, now);
    const report = healthReport([a, b, c, d, note], [d.id], now);
    expect(report.reused).toEqual([[a.id, b.id]]);
    expect(report.weak).toEqual([c.id]);
    expect(report.old).toEqual([a.id]);
    expect(report.score).toBe(0);
    expect(healthReport([d], [], now).score).toBe(100);
  });
});

describe("CSV", () => {
  it("parses quotes, commas and newlines", () => {
    expect(parseCsv('a,"b,c","d ""e""\nf"\r\n1,2,3\n')).toEqual([["a", "b,c", 'd "e"\nf'], ["1", "2", "3"]]);
  });

  it("imports Chrome, Firefox and Bitwarden exports", () => {
    const chrome = importCsv("name,url,username,password,note\nBank,https://bank.example,me,s3cret,\n,https://www.mail.example/login,me@x,pw2,\n");
    expect(chrome.items.map((i) => [i.title, i.password])).toEqual([["Bank", "s3cret"], ["mail.example", "pw2"]]);
    const firefox = importCsv('"url","username","password","httpRealm"\n"https://shop.example","a","b",""\n');
    expect(firefox.items[0]).toMatchObject({ title: "shop.example", username: "a", password: "b" });
    const bitwarden = importCsv("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,note,Alarm code,1234,,,,,,\n,,login,Forum,,,,https://forum.example,me,pw,\n");
    expect(bitwarden.items.map((i) => [i.kind, i.title])).toEqual([["note", "Alarm code"], ["login", "Forum"]]);
    expect(() => importCsv("a,b\n1,2\n")).toThrow(/no password/);
  });

  it("exports values exactly and re-imports them", () => {
    const items = [newItem("login", { title: 'Say "hi", ok', url: "https://x.example", username: "-me", password: '=1+2,"\n', notes: "" })];
    const again = importCsv(exportCsv(items)).items[0]!;
    expect([again.title, again.username, again.password]).toEqual(['Say "hi", ok', "-me", '=1+2,"\n']);
  });

  it("matches sites by host", () => {
    const item = newItem("login", { url: "https://www.bank.example/login" });
    expect(matchesSite(item, "bank.example")).toBe(true);
    expect(matchesSite(item, "online.bank.example")).toBe(true);
    expect(matchesSite(item, "bank.example.evil.test")).toBe(false);
  });
});
