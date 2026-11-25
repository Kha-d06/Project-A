import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { safeName, signatureValid, updateBundle, versionNewer } from "../src/engine/scan-bundle";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUB = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
const other = generateKeyPairSync("ed25519");

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

/** A served bundle: manifest, signature and files, as the server would host them. */
function served(version: string, files: Record<string, string>, key = privateKey) {
  const listed = Object.fromEntries(Object.entries(files).map(([n, c]) => [n, { sha256: sha(Buffer.from(c)), size: Buffer.byteLength(c) }]));
  const manifest = Buffer.from(JSON.stringify({ format: 1, version, files: listed }));
  const map = new Map<string, Buffer>([["manifest.json", manifest], ["manifest.sig", Buffer.from(sign(null, manifest, key).toString("base64"))]]);
  for (const [n, c] of Object.entries(files)) map.set(n, Buffer.from(c));
  const fetched: string[] = [];
  const fetchBytes = async (url: string) => {
    const name = decodeURIComponent(url.replace("https://updates.example/b/", ""));
    fetched.push(name);
    const b = map.get(name);
    if (!b) throw new Error(`404 ${name}`);
    return b;
  };
  return { map, fetched, fetchBytes };
}

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "qalaa-bundle-"));
  return { root, base: { root, baseUrl: "https://updates.example/b/", keys: [PUB], verifyDir: async () => true } };
}

describe("scan bundle updates", () => {
  it("installs, then downloads only what changed, keeping the previous set", async () => {
    const { root, base } = await setup();
    const v1 = served("2026.11.25.1", { "rules/a.yar": "rule a { condition: false }", "model.json": "{\"m\":1}" });
    const first = await updateBundle({ ...base, fetchBytes: v1.fetchBytes });
    expect(first).toMatchObject({ updated: true, version: "2026.11.25.1", reused: [] });
    expect(first.downloaded.sort()).toEqual(["model.json", "rules/a.yar"]);

    const v2 = served("2026.11.26.1", { "rules/a.yar": "rule a { condition: true }", "model.json": "{\"m\":1}" });
    const second = await updateBundle({ ...base, fetchBytes: v2.fetchBytes });
    expect(second).toMatchObject({ updated: true, downloaded: ["rules/a.yar"], reused: ["model.json"] });
    expect(v2.fetched).not.toContain("model.json");
    expect(await readFile(join(root, "current/rules/a.yar"), "utf8")).toContain("true");
    expect(await readFile(join(root, "previous/rules/a.yar"), "utf8")).toContain("false");
    expect((await readdir(root)).filter((d) => d.startsWith("staging"))).toEqual([]);
  });

  it("refuses downgrades, other keys and tampered files, and keeps the current rules", async () => {
    const { root, base } = await setup();
    await updateBundle({ ...base, fetchBytes: served("2026.11.25.2", { "rules/a.yar": "rule a { condition: false }" }).fetchBytes });

    expect((await updateBundle({ ...base, fetchBytes: served("2026.11.25.1", { "rules/a.yar": "x" }).fetchBytes })).reason).toMatch(/older/);
    expect((await updateBundle({ ...base, fetchBytes: served("2026.11.25.2", { "rules/a.yar": "x" }).fetchBytes })).reason).toMatch(/up to date/);
    expect((await updateBundle({ ...base, fetchBytes: served("2026.12.1.1", { "rules/a.yar": "x" }, other.privateKey).fetchBytes })).reason).toMatch(/trusted key/);

    const tampered = served("2026.12.1.1", { "rules/a.yar": "rule a { condition: true }" });
    tampered.map.set("rules/a.yar", Buffer.from("rule evil { condition: true }"));
    const r = await updateBundle({ ...base, fetchBytes: tampered.fetchBytes });
    expect(r.updated).toBe(false);
    expect(r.reason).toMatch(/doesn't match.*current rules stay/);

    const refusedByScanner = await updateBundle({ ...base, verifyDir: async () => false, fetchBytes: served("2026.12.1.2", { "rules/a.yar": "y" }).fetchBytes });
    expect(refusedByScanner.reason).toMatch(/refused/);
    expect(await readFile(join(root, "current/rules/a.yar"), "utf8")).toBe("rule a { condition: false }");
    expect((await readdir(root)).filter((d) => d.startsWith("staging"))).toEqual([]);
  });

  it("does nothing without a pinned key", async () => {
    const { base } = await setup();
    const v = served("2026.11.25.1", { "rules/a.yar": "x" });
    expect((await updateBundle({ ...base, keys: [], fetchBytes: v.fetchBytes })).reason).toMatch(/no bundle signing key/);
    expect(v.fetched).toEqual([]);
  });

  it("rejects names that could leave the bundle folder", async () => {
    for (const bad of ["../x", "/etc/x", "a\\b", "a//b", "./a", ""]) expect(safeName(bad)).toBe(false);
    expect(safeName("rules/a.yar")).toBe(true);
    const { base } = await setup();
    const evil = served("2026.11.25.1", { "../escape.yar": "x" });
    await expect(updateBundle({ ...base, fetchBytes: evil.fetchBytes })).rejects.toThrow(/unsafe/);
  });

  it("compares versions numerically and checks signatures over exact bytes", () => {
    expect(versionNewer("2026.11.10.1", "2026.11.9.5")).toBe(true);
    expect(versionNewer("2026.11.9", "2026.11.9")).toBe(false);
    expect(versionNewer("latest", null)).toBe(false);
    const body = Buffer.from("{}");
    const sig = sign(null, body, privateKey).toString("base64");
    expect(signatureValid(body, sig, [PUB])).toBe(true);
    expect(signatureValid(Buffer.from("{} "), sig, [PUB])).toBe(false);
    expect(signatureValid(body, "AAAA", [PUB])).toBe(false);
  });
});
