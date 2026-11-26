/**
 * Client-side crypto for sharing vault entries and emergency access.
 *
 * Each user has an ECDH P-256 key pair. The private key is wrapped by the vault
 * key and kept inside the encrypted vault; the public key is published to the
 * server. To share, the sender derives a shared secret from an ephemeral key
 * pair and the recipient's public key (ECDH), then encrypts with AES-256-GCM.
 * The server only ever relays the ciphertext and the ephemeral public key.
 *
 * The server also hands out the recipients' public keys, so a compromised server
 * could hand out its own instead. Two defences, both on this device:
 * - a fingerprint of each key (SHA-256 of the key, 128 bits shown as 8 groups),
 *   which the two people can compare in person or by phone;
 * - the fingerprint is remembered (inside the encrypted vault) the first time
 *   you share with someone, and a different key later is a warning that has to
 *   be confirmed before anything is sealed to it.
 */
import { fromBase64, toBase64 } from "./vault";

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

export interface SharingKeyPair {
  publicKey: string; // base64 SPKI
  privateKey: string; // base64 PKCS8 — store wrapped inside the vault
}

/** Generate a fresh sharing key pair (exported as base64 for storage/transport). */
export async function generateSharingKeys(): Promise<SharingKeyPair> {
  const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveKey"]);
  const publicKey = toBase64(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
  const privateKey = toBase64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  return { publicKey, privateKey };
}

async function importPublic(base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", fromBase64(base64), ECDH, false, []);
}

async function importPrivate(base64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", fromBase64(base64), ECDH, false, ["deriveKey"]);
}

async function sharedAesKey(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey({ name: "ECDH", public: publicKey }, privateKey, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export interface SealedShare {
  ciphertext: string; // base64 iv(12) + ciphertext
  ephemeral: string; // base64 SPKI of the sender's ephemeral public key
}

/** Encrypt a payload to a recipient's public key. */
export async function sealTo(recipientPublicKey: string, payload: string): Promise<SealedShare> {
  const ephemeral = await crypto.subtle.generateKey(ECDH, true, ["deriveKey"]);
  const aes = await sharedAesKey(ephemeral.privateKey, await importPublic(recipientPublicKey));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(payload);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, data));
  const combined = new Uint8Array(iv.length + sealed.length);
  combined.set(iv);
  combined.set(sealed, iv.length);
  return {
    ciphertext: toBase64(combined),
    ephemeral: toBase64(new Uint8Array(await crypto.subtle.exportKey("spki", ephemeral.publicKey))),
  };
}

/** Decrypt a sealed share with my private key and the sender's ephemeral key. */
export async function openSealed(myPrivateKey: string, sealed: SealedShare): Promise<string> {
  const aes = await sharedAesKey(await importPrivate(myPrivateKey), await importPublic(sealed.ephemeral));
  const bytes = fromBase64(sealed.ciphertext);
  const iv = bytes.slice(0, 12);
  const data = bytes.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aes, data);
  return new TextDecoder().decode(plain);
}

/** "1a2b 3c4d …": the first 128 bits of SHA-256 over the public key, for comparing by eye. */
export async function keyFingerprint(publicKeyBase64: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", fromBase64(publicKeyBase64)));
  const hex = [...digest.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g)!.join(" ");
}

export type PinStatus = "new" | "same" | "changed";

/** Compares a recipient's current key fingerprint with the one remembered for them. */
export function pinStatus(pinned: Record<string, string> | undefined, userId: string, fingerprint: string): PinStatus {
  const known = pinned?.[userId];
  if (!known) return "new";
  return known === fingerprint ? "same" : "changed";
}

