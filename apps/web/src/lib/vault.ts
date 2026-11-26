/**
 * End-to-end encrypted password vault (browser side).
 *
 * - The master password never leaves the browser. PBKDF2-SHA256 (600,000
 *   iterations, random 16-byte salt) turns it into a key-encryption key.
 * - A random AES-256-GCM vault key encrypts the vault. It is stored on the
 *   server only wrapped (encrypted) by the key-encryption key, and is held in
 *   memory as a non-extractable CryptoKey while the vault is unlocked.
 * - Both encryptions bind the account id and their purpose as associated data,
 *   so a vault or key copied into another account, or swapped between the two
 *   fields, fails to decrypt.
 * - The plaintext is padded to a multiple of 1 KiB, so the stored size does not
 *   reveal the exact number or length of entries.
 * - Changing the master password generates a new vault key and re-encrypts.
 */

export const KDF_ITERATIONS = 600_000;
export const MIN_MASTER_LENGTH = 12;
const PAD_TO = 1024;

export type VaultItemKind = "login" | "note" | "passkey";

export interface VaultItem {
  id: string;
  kind: VaultItemKind;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  created: string;
  updated: string;
  /** When the password field last changed, for the "old password" check. */
  passwordChanged: string;
  /**
   * Two-factor secret for a login: an otpauth:// URI or a bare base32 secret.
   * Stored only inside the encrypted vault; codes are generated on the device.
   */
  totp?: string;
  /**
   * A stored passkey (WebAuthn credential), kept so it is backed up and visible
   * across devices. JSON produced when the user exports/imports a passkey.
   */
  passkey?: string;
}

export interface VaultDoc {
  format: 1;
  items: VaultItem[];
  /** This user's ECDH sharing key pair, generated on first use of sharing. */
  sharing?: {
    publicKey: string;
    privateKey: string;
    /** Recipients' key fingerprints, remembered at first share (user id → fingerprint). */
    pinned?: Record<string, string>;
  };
}

export interface StoredVault {
  kdf: { name: "PBKDF2-SHA256"; iterations: number; salt: string };
  wrapped_key: string;
  data: string;
  version: number;
}

export class WrongMasterPassword extends Error {
  constructor() {
    super("That master password does not open this vault.");
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function random(size: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(size));
}

function aad(userId: string, purpose: "key" | "data"): Uint8Array<ArrayBuffer> {
  return encoder.encode(`sentinel-vault:1:${userId}:${purpose}`);
}

async function keyEncryptionKey(master: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(master.normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

export function pad(json: string): Uint8Array<ArrayBuffer> {
  const bytes = encoder.encode(json);
  const size = Math.ceil((bytes.length + 1) / PAD_TO) * PAD_TO;
  const out = new Uint8Array(size).fill(0x20); // trailing spaces are valid JSON whitespace
  out.set(bytes);
  return out;
}

export async function encryptDoc(key: CryptoKey, doc: VaultDoc, userId: string): Promise<string> {
  const iv = random(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(userId, "data") }, key, pad(JSON.stringify(doc)));
  return toBase64(concat(iv, new Uint8Array(ciphertext)));
}

export async function decryptDoc(key: CryptoKey, data: string, userId: string): Promise<VaultDoc> {
  const bytes = fromBase64(data);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: aad(userId, "data") }, key, bytes.slice(12));
  const doc = JSON.parse(decoder.decode(plain)) as VaultDoc;
  if (doc.format !== 1 || !Array.isArray(doc.items)) throw new Error("This vault was saved by a newer version of Qalaa.");
  return doc;
}

/** A new vault key, wrapped under the master password. Returns the key in non-extractable form. */
async function newVaultKey(master: string, userId: string, iterations: number) {
  const salt = random(16);
  const kek = await keyEncryptionKey(master, salt, iterations);
  const extractable = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = random(12);
  const wrapped = await crypto.subtle.wrapKey("raw", extractable, kek, { name: "AES-GCM", iv, additionalData: aad(userId, "key") });
  const wrappedKey = concat(iv, new Uint8Array(wrapped));
  const key = await unwrap(kek, wrappedKey, userId);
  return { key, kdf: { name: "PBKDF2-SHA256" as const, iterations, salt: toBase64(salt) }, wrapped_key: toBase64(wrappedKey) };
}

function unwrap(kek: CryptoKey, wrappedKey: Uint8Array<ArrayBuffer>, userId: string): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw",
    wrappedKey.slice(12),
    kek,
    { name: "AES-GCM", iv: wrappedKey.slice(0, 12), additionalData: aad(userId, "key") },
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function createVault(master: string, userId: string, doc: VaultDoc = { format: 1, items: [] }, iterations = KDF_ITERATIONS) {
  const fresh = await newVaultKey(master, userId, iterations);
  return { key: fresh.key, stored: { kdf: fresh.kdf, wrapped_key: fresh.wrapped_key, data: await encryptDoc(fresh.key, doc, userId) } };
}

export async function unlockVault(stored: Pick<StoredVault, "kdf" | "wrapped_key" | "data">, master: string, userId: string) {
  if (stored.kdf.name !== "PBKDF2-SHA256") throw new Error("Unknown key-derivation method.");
  const kek = await keyEncryptionKey(master, fromBase64(stored.kdf.salt), stored.kdf.iterations);
  let key: CryptoKey;
  try {
    key = await unwrap(kek, fromBase64(stored.wrapped_key), userId);
  } catch {
    throw new WrongMasterPassword();
  }
  return { key, doc: await decryptDoc(key, stored.data, userId) };
}

/** Everything new: salt, key-encryption key, vault key and ciphertext. */
export function changeMasterPassword(newMaster: string, userId: string, doc: VaultDoc, iterations = KDF_ITERATIONS) {
  return createVault(newMaster, userId, doc, iterations);
}

export function newItem(kind: VaultItemKind, fields: Partial<VaultItem> = {}, now = new Date()): VaultItem {
  const iso = now.toISOString();
  return {
    id: crypto.randomUUID(),
    kind,
    title: "",
    username: "",
    password: "",
    url: "",
    notes: "",
    created: iso,
    updated: iso,
    passwordChanged: iso,
    ...fields,
  };
}
