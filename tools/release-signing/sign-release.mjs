#!/usr/bin/env node
/**
 * Signs a desktop release for Qalaa's update check (apps/desktop/src/engine/release-verify.ts).
 * Run it on the release manager's offline machine, never on the server or in CI.
 *
 *   node sign-release.mjs keygen <private-key-file>
 *       Creates an ed25519 key (file mode 0600) and prints the public key to pin
 *       in RELEASE_KEYS.
 *   node sign-release.mjs sign <private-key-file> <release-dir> <version> [days-valid]
 *       Writes release-manifest.json (SHA-512 and size of every installer in the
 *       folder) and release-manifest.json.sig. Upload both next to latest.yml.
 *
 * Node built-ins only, so there is nothing to install on the signing machine.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const INSTALLERS = /\.(exe|dmg|zip|AppImage|deb|rpm)$/;

export function publicKeyHex(privatePem) {
  const der = createPublicKey(createPrivateKey(privatePem)).export({ format: "der", type: "spki" });
  return der.subarray(-32).toString("hex");
}

export function buildManifest(dir, version, daysValid = 30, now = Date.now()) {
  const files = readdirSync(dir)
    .filter((name) => INSTALLERS.test(name) && statSync(join(dir, name)).isFile())
    .sort()
    .map((name) => {
      const bytes = readFileSync(join(dir, name));
      return { name, sha512: createHash("sha512").update(bytes).digest("base64"), size: bytes.length };
    });
  if (!files.length) throw new Error(`No installers in ${dir}`);
  return { format: 1, product: "qalaa-desktop", version, expires: new Date(now + daysValid * 86_400_000).toISOString(), files };
}

export function signManifest(privatePem, manifestBytes) {
  return sign(null, manifestBytes, createPrivateKey(privatePem)).toString("base64");
}

function main([command, keyFile, dir, version, days]) {
  if (command === "keygen" && keyFile) {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ format: "pem", type: "pkcs8" });
    writeFileSync(keyFile, pem, { mode: 0o600, flag: "wx" });
    console.log(`Private key written to ${keyFile}. Keep it offline.`);
    console.log(`Public key to pin in RELEASE_KEYS: ${publicKeyHex(pem)}`);
    return;
  }
  if (command === "sign" && keyFile && dir && version) {
    const pem = readFileSync(keyFile, "utf8");
    const bytes = Buffer.from(`${JSON.stringify(buildManifest(dir, version, days ? Number(days) : 30), null, 2)}\n`);
    writeFileSync(join(dir, "release-manifest.json"), bytes);
    writeFileSync(join(dir, "release-manifest.json.sig"), `${signManifest(pem, bytes)}\n`);
    console.log(`Signed ${version} with key ${publicKeyHex(pem)}.`);
    return;
  }
  console.error("Usage: sign-release.mjs keygen <key-file> | sign <key-file> <release-dir> <version> [days-valid]");
  process.exitCode = 2;
}

if (import.meta.url === `file://${process.argv[1]}`) main(process.argv.slice(2));
