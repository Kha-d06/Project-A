/**
 * One-click VPN from the desktop app, using the owner's self-hosted Qalaa VPN.
 *
 * - The WireGuard key pair is generated here; only the public key is sent.
 * - The tunnel file (which contains the private key) is written to the app's
 *   private data folder with owner-only permissions.
 * - Linux with NetworkManager: the app imports the tunnel once and then connects
 *   and disconnects it with nmcli, no administrator password needed.
 * - Windows and macOS: connecting a tunnel needs the official WireGuard app, so
 *   the app saves the tunnel file and opens its folder for importing.
 */
import { execFile } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { AccountLinkError, type LinkedAccount } from "./account";

export const CONNECTION_NAME = "qalaa-vpn";

export interface PeerConfig {
  peer: { id: string; name: string; address: string };
  address: string;
  dns: string;
  server_public_key: string;
  endpoint: string;
  allowed_ips: string;
}

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

/** A Curve25519 key pair in WireGuard's base64 form. */
export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const pub = publicKey.export({ format: "jwk" }).x!;
  const priv = privateKey.export({ format: "jwk" }).d!;
  return { publicKey: Buffer.from(pub, "base64url").toString("base64"), privateKey: Buffer.from(priv, "base64url").toString("base64") };
}

const KEY = /^[A-Za-z0-9+/]{43}=$/;
const SAFE_LINE = /^[A-Za-z0-9.:,/ \-[\]]+$/;

/** The WireGuard tunnel file. Every value from the server is checked so nothing
 * else can be written into the file. */
export function buildConfig(config: PeerConfig, privateKey: string): string {
  for (const [name, value] of Object.entries({ address: config.address, dns: config.dns, endpoint: config.endpoint, allowed: config.allowed_ips })) {
    if (!value || !SAFE_LINE.test(value)) throw new Error(`The server sent an invalid ${name}.`);
  }
  if (!KEY.test(config.server_public_key) || !KEY.test(privateKey)) throw new Error("Invalid WireGuard key.");
  return [
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${config.address}`,
    `DNS = ${config.dns}`,
    "",
    "[Peer]",
    `PublicKey = ${config.server_public_key}`,
    `AllowedIPs = ${config.allowed_ips}`,
    `Endpoint = ${config.endpoint}`,
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
}

export async function requestPeer(account: LinkedAccount, publicKey: string, fetcher: typeof fetch = fetch): Promise<PeerConfig> {
  const response = await fetcher(`${account.server.replace(/\/$/, "")}/api/v1/devices/vpn`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json", Authorization: `Bearer ${account.token}` },
    body: JSON.stringify({ public_key: publicKey }),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) {
    let message = `The server answered ${response.status}`;
    try {
      message = ((await response.json()) as { error?: { message?: string } }).error?.message ?? message;
    } catch {
      // keep the status message
    }
    throw new AccountLinkError(message, response.status);
  }
  return (await response.json()) as PeerConfig;
}

export async function saveTunnel(folder: string, text: string): Promise<string> {
  const file = join(folder, `${CONNECTION_NAME}.conf`);
  await writeFile(file, text, { mode: 0o600 });
  return file;
}

// --- Linux: NetworkManager -------------------------------------------------------------

export type TunnelState = "connected" | "disconnected" | "not_imported" | "unsupported";

function nmcli(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("nmcli", args, { timeout: 20_000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(String(stderr || error.message).trim().slice(0, 300)));
      else resolve(String(stdout));
    });
  });
}

/** `nmcli -t -f NAME,TYPE,DEVICE connection show` → state of our connection. */
export function parseConnections(stdout: string): TunnelState {
  for (const line of stdout.split("\n")) {
    const [name, type, device] = line.split(":");
    if (name === CONNECTION_NAME && type === "wireguard") return device ? "connected" : "disconnected";
  }
  return "not_imported";
}

export async function tunnelState(platform = process.platform): Promise<TunnelState> {
  if (platform !== "linux") return "unsupported";
  try {
    return parseConnections(await nmcli(["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show"]));
  } catch {
    return "unsupported"; // NetworkManager is not installed or not running
  }
}

export async function importTunnel(file: string): Promise<void> {
  // Replace an older import so the newest key is used.
  await nmcli(["connection", "delete", CONNECTION_NAME]).catch(() => undefined);
  await nmcli(["connection", "import", "type", "wireguard", "file", file]);
  // Do not connect automatically at login: the person decides each time.
  await nmcli(["connection", "modify", CONNECTION_NAME, "connection.autoconnect", "no"]);
}

export async function connectTunnel(): Promise<void> {
  await nmcli(["connection", "up", CONNECTION_NAME]);
}

export async function disconnectTunnel(): Promise<void> {
  await nmcli(["connection", "down", CONNECTION_NAME]);
}

export async function forgetTunnel(): Promise<void> {
  await nmcli(["connection", "delete", CONNECTION_NAME]).catch(() => undefined);
}
