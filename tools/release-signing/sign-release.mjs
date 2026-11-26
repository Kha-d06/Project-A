#!/usr/bin/env node
/**
 * Signs a desktop release for Qalaa's update check (apps/desktop/src/engine/release-verify.ts).
 * Run keygen and sign on the release manager's offline machine only
 * (docs/release-signing-key.md); never on the server, in CI or in a development checkout.
 *
 *   node sign-release.mjs keygen <private-key-file>
 *       Creates an ed25519 key, encrypted with a passphrase you type (AES-256,
 *       PKCS#8; file mode 0600, never overwrites), and prints the public key to
 *       pin in RELEASE_KEYS. The public key is all the application needs.
 *   node sign-release.mjs pubkey <private-key-file>
 *       Prints the public key again (asks for the passphrase).
 *   node sign-release.mjs sign <private-key-file> <release-dir> <version> [days-valid]
 *       Writes release-manifest.json (SHA-512 and size of every installer in the
 *       folder) and release-manifest.json.sig. Upload both next to latest.yml.
 *   node sign-release.mjs verify <public-key-hex> <release-dir>
 *       Checks a signed folder with the public key only: run it on the machine
 *       that publishes, before upload.
 *
 * The passphrase is read from the terminal without echo, or, when stdin isn't a
 * terminal, from the first line of stdin. Node built-ins only.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const INSTALLERS = /\.(exe|dmg|zip|AppImage|deb|rpm)$/;
const MIN_PASSPHRASE = 12;

export function encryptedPem(privateKey, passphrase) {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE) throw new Error(`Use a passphrase of at least ${MIN_PASSPHRASE} characters.`);
  return privateKey.export({ format: "pem", type: "pkcs8", cipher: "aes-256-cbc", passphrase });
}

export function loadPrivateKey(pem, passphrase) {
  if (!pem.includes("ENCRYPTED PRIVATE KEY")) throw new Error("This key file isn't passphrase-protected; create a new one with keygen.");
  return createPrivateKey({ key: pem, format: "pem", passphrase });
}

export function publicKeyHex(privateKey) {
  const der = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return der.subarray(-32).toString("hex");
}

export function buildManifest(dir, version, daysValid = 30, now = Date.now()) {
  if (!/^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`"${version}" isn't a version like 1.4.0.`);
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

export function signManifest(privateKey, manifestBytes) {
  return sign(null, manifestBytes, privateKey).toString("base64");
}

/** Signature, and every listed file's size and SHA-512, with a public key only. */
export function verifyFolder(publicHex, dir) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicHex, "hex")]);
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  const bytes = readFileSync(join(dir, "release-manifest.json"));
  const sig = Buffer.from(readFileSync(join(dir, "release-manifest.json.sig"), "utf8").trim(), "base64");
  if (!verify(null, bytes, key, sig)) return { ok: false, problem: "the signature doesn't match this public key" };
  const manifest = JSON.parse(bytes.toString("utf8"));
  for (const f of manifest.files) {
    const file = readFileSync(join(dir, f.name));
    if (file.length !== f.size || createHash("sha512").update(file).digest("base64") !== f.sha512) return { ok: false, problem: `${f.name} doesn't match the manifest` };
  }
  return { ok: true, version: manifest.version, expires: manifest.expires, files: manifest.files.length };
}

async function passphrase(prompt) {
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString("utf8").split(/\r?\n/)[0] ?? "";
  }
  process.stderr.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve) => {
    let typed = "";
    const onData = (data) => {
      for (const ch of data.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.off("data", onData);
          process.stderr.write("\n");
          resolve(typed);
          return;
        }
        if (ch === "\u0003") process.exit(130);
        typed = ch === "\u007f" ? typed.slice(0, -1) : typed + ch;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function main([command, a, b, c, d]) {
  if (command === "keygen" && a) {
    const first = await passphrase("Passphrase for the new key: ");
    const pem = encryptedPem(generateKeyPairSync("ed25519").privateKey, first);
    if (process.stdin.isTTY && (await passphrase("Type it again: ")) !== first) throw new Error("The passphrases differ.");
    writeFileSync(a, pem, { mode: 0o600, flag: "wx" });
    console.log(`Encrypted private key written to ${a}. Keep it offline.`);
    console.log(`Public key to pin in RELEASE_KEYS: ${publicKeyHex(loadPrivateKey(pem, first))}`);
    return;
  }
  if (command === "pubkey" && a) {
    console.log(publicKeyHex(loadPrivateKey(readFileSync(a, "utf8"), await passphrase("Passphrase: "))));
    return;
  }
  if (command === "sign" && a && b && c) {
    const key = loadPrivateKey(readFileSync(a, "utf8"), await passphrase("Passphrase: "));
    const bytes = Buffer.from(`${JSON.stringify(buildManifest(b, c, d ? Number(d) : 30), null, 2)}\n`);
    writeFileSync(join(b, "release-manifest.json"), bytes);
    writeFileSync(join(b, "release-manifest.json.sig"), `${signManifest(key, bytes)}\n`);
    console.log(`Signed ${c} with key ${publicKeyHex(key)}.`);
    return;
  }
  if (command === "verify" && a && b) {
    const result = verifyFolder(a, b);
    console.log(result.ok ? `OK: ${result.version}, ${result.files} file(s), valid until ${result.expires}.` : `NOT OK: ${result.problem}.`);
    process.exitCode = result.ok ? 0 : 1;
    return;
  }
  console.error("Usage: sign-release.mjs keygen <key-file> | pubkey <key-file> | sign <key-file> <release-dir> <version> [days-valid] | verify <public-key-hex> <release-dir>");
  process.exitCode = 2;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
