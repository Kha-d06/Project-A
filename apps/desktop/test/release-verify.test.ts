import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { checkRelease, sha512Base64, verifyDownloadedUpdate } from "../src/engine/release-verify";
// The release manager's offline tool, so the signing and checking sides can't drift apart.
import { buildManifest, publicKeyHex, signManifest } from "../../../tools/release-signing/sign-release.mjs";

function keys() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
  return { pem, pub: publicKeyHex(pem) as string };
}

async function release(version: string, installer = Buffer.from("installer bytes")) {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-release-"));
  await writeFile(join(dir, "Qalaa-Setup.exe"), installer);
  return { dir, installer, manifest: Buffer.from(JSON.stringify(buildManifest(dir, version))) };
}

describe("signed desktop updates", () => {
  it("accepts an update signed by a pinned key, for the right file and a newer version", async () => {
    const { pem, pub } = keys();
    const { installer, manifest } = await release("1.2.0");
    const file = { name: "Qalaa-Setup.exe", sha512: sha512Base64(installer), size: installer.length };
    const base = { manifest, signature: signManifest(pem, manifest) as string, keys: [pub], updateVersion: "1.2.0", currentVersion: "1.1.0", file };
    expect(checkRelease(base)).toEqual({ ok: true });

    // Tampered installer, other key, no key, replayed old version, downgrade, expiry.
    expect(checkRelease({ ...base, file: { ...file, sha512: sha512Base64(Buffer.from("evil")) } })).toEqual({ ok: false, reason: "file" });
    expect(checkRelease({ ...base, keys: [keys().pub] })).toEqual({ ok: false, reason: "unsigned" });
    expect(checkRelease({ ...base, keys: [] })).toEqual({ ok: false, reason: "no_keys" });
    expect(checkRelease({ ...base, updateVersion: "1.3.0" })).toEqual({ ok: false, reason: "version" });
    expect(checkRelease({ ...base, currentVersion: "1.2.0" })).toEqual({ ok: false, reason: "version" });
    expect(checkRelease({ ...base, now: Date.now() + 400 * 86_400_000 })).toEqual({ ok: false, reason: "expired" });
    // A signature over different bytes (the server edited the manifest).
    const edited = Buffer.from(manifest.toString().replace("1.2.0", "1.2.0 "));
    expect(checkRelease({ ...base, manifest: edited })).toEqual({ ok: false, reason: "unsigned" });
  });

  it("fetches the manifest and signature from the feed and checks the downloaded file", async () => {
    const { pem, pub } = keys();
    const { dir, manifest } = await release("2.0.0");
    const signature = signManifest(pem, manifest) as string;
    const fetcher = (async (url: string) =>
      url.endsWith(".sig") ? new Response(signature) : url.endsWith("release-manifest.json") ? new Response(manifest) : new Response("", { status: 404 })) as unknown as typeof fetch;
    const downloadedFile = join(dir, "Qalaa-Setup.exe");
    expect(await verifyDownloadedUpdate({ feed: "https://q.example/downloads/desktop/", downloadedFile, updateVersion: "2.0.0", currentVersion: "1.0.0", keys: [pub], fetcher })).toEqual({ ok: true });
    const missing = (async () => new Response("", { status: 404 })) as unknown as typeof fetch;
    expect(await verifyDownloadedUpdate({ feed: "https://q.example/d", downloadedFile, updateVersion: "2.0.0", currentVersion: "1.0.0", keys: [pub], fetcher: missing })).toEqual({ ok: false, reason: "unsigned" });
    expect(await verifyDownloadedUpdate({ feed: "https://q.example/d", downloadedFile, updateVersion: "2.0.0", currentVersion: "1.0.0", keys: [], fetcher })).toEqual({ ok: false, reason: "no_keys" });
  });
});
