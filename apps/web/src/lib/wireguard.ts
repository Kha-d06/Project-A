/**
 * WireGuard keys and configuration, made in the browser. The private key is
 * generated here (WebCrypto X25519), put straight into the configuration the
 * person downloads or scans, and never sent to SENTINEL.
 */
import qrcode from "qrcode-generator";

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

function base64UrlToBase64(value: string): string {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  return padded + "=".repeat((4 - (padded.length % 4)) % 4);
}

export async function generateKeyPair(): Promise<KeyPair> {
  let pair: CryptoKeyPair;
  try {
    pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  } catch {
    throw new Error("This browser cannot create WireGuard keys. Update it, or use a current Chrome, Edge, Firefox or Safari.");
  }
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  if (!jwk.d || !jwk.x) throw new Error("The key could not be exported.");
  return { privateKey: base64UrlToBase64(jwk.d), publicKey: base64UrlToBase64(jwk.x) };
}

export interface TunnelSettings {
  privateKey: string;
  address: string;
  dns: string;
  serverPublicKey: string;
  endpoint: string;
  allowedIps: string;
}

export function buildConfig(settings: TunnelSettings): string {
  return [
    "[Interface]",
    `PrivateKey = ${settings.privateKey}`,
    `Address = ${settings.address}`,
    `DNS = ${settings.dns}`,
    "",
    "[Peer]",
    `PublicKey = ${settings.serverPublicKey}`,
    `Endpoint = ${settings.endpoint}`,
    `AllowedIPs = ${settings.allowedIps}`,
    // Keeps the tunnel open through home routers and mobile networks.
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
}

/** WireGuard apps name the tunnel after the file: at most 15 of [A-Za-z0-9_=+.-]. */
export function tunnelFileName(deviceName: string): string {
  const slug = deviceName.normalize("NFKD").replace(/[^A-Za-z0-9_=+.-]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase();
  return `${`sntl-${slug || "vpn"}`.slice(0, 15).replace(/-+$/, "")}.conf`;
}

/** QR code modules for the configuration, for drawing as SVG. */
export function qrModules(text: string): boolean[][] {
  const qr = qrcode(0, "L");
  qr.addData(text, "Byte");
  qr.make();
  const size = qr.getModuleCount();
  return Array.from({ length: size }, (_, row) => Array.from({ length: size }, (_, col) => qr.isDark(row, col)));
}
