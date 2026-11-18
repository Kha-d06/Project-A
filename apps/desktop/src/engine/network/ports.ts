/**
 * TCP port probing. Plain connect() only — no raw sockets, so this works as an
 * ordinary user on every platform. Each port in the catalogue carries a short
 * risk note, so an open service can be explained rather than just listed.
 */
import { Socket } from "node:net";

import type { Severity } from "../types";

export interface PortInfo {
  port: number;
  name: string;
  /** Why this being open on a home device is worth noting, or null if benign. */
  risk: { severity: Severity; rule: string; note: string } | null;
}

/** The ports worth checking on a home network, about 30 of them. */
export const CATALOGUE: PortInfo[] = [
  { port: 21, name: "ftp", risk: { severity: "high", rule: "net_ftp", note: "File transfer without encryption; often left open with weak logins." } },
  { port: 22, name: "ssh", risk: { severity: "low", rule: "net_ssh", note: "Remote login. Fine if you use it; make sure it needs a key or a strong password." } },
  { port: 23, name: "telnet", risk: { severity: "critical", rule: "net_telnet", note: "Remote control with no encryption. Common on compromised cameras and routers." } },
  { port: 25, name: "smtp", risk: { severity: "medium", rule: "net_smtp", note: "A mail server on a home device is unusual and can be abused to send spam." } },
  { port: 53, name: "dns", risk: null },
  { port: 80, name: "http", risk: null },
  { port: 110, name: "pop3", risk: { severity: "medium", rule: "net_pop3", note: "Unencrypted mail retrieval." } },
  { port: 135, name: "msrpc", risk: { severity: "medium", rule: "net_msrpc", note: "Windows RPC exposed to the network." } },
  { port: 139, name: "netbios", risk: { severity: "medium", rule: "net_netbios", note: "Legacy Windows file sharing." } },
  { port: 143, name: "imap", risk: { severity: "low", rule: "net_imap", note: "Mail retrieval." } },
  { port: 445, name: "smb", risk: { severity: "high", rule: "net_smb", note: "Windows file sharing. A frequent route for worms and ransomware." } },
  { port: 554, name: "rtsp", risk: { severity: "medium", rule: "net_rtsp", note: "Camera video stream. Check it needs a password." } },
  { port: 631, name: "ipp", risk: null },
  { port: 1883, name: "mqtt", risk: { severity: "medium", rule: "net_mqtt", note: "Smart-home message bus, often with no password." } },
  { port: 1900, name: "upnp", risk: { severity: "low", rule: "net_upnp", note: "UPnP. Convenient, but lets devices open router ports by themselves." } },
  { port: 2323, name: "telnet-alt", risk: { severity: "critical", rule: "net_telnet", note: "Telnet on an alternate port. Common on IoT botnet infections." } },
  { port: 3389, name: "rdp", risk: { severity: "high", rule: "net_rdp", note: "Windows Remote Desktop. A major target if reachable." } },
  { port: 5000, name: "upnp-http", risk: { severity: "low", rule: "net_upnp", note: "UPnP control, or a device web panel." } },
  { port: 5357, name: "wsd", risk: null },
  { port: 5555, name: "adb", risk: { severity: "critical", rule: "net_adb", note: "Android Debug Bridge open to the network — full control of the device with no password." } },
  { port: 5900, name: "vnc", risk: { severity: "high", rule: "net_vnc", note: "Remote screen control. Often has no password or a weak one." } },
  { port: 6379, name: "redis", risk: { severity: "high", rule: "net_redis", note: "A database with no password by default." } },
  { port: 7547, name: "cwmp", risk: { severity: "medium", rule: "net_cwmp", note: "Router remote-management port; a known attack surface." } },
  { port: 8080, name: "http-alt", risk: null },
  { port: 8443, name: "https-alt", risk: null },
  { port: 8888, name: "http-alt2", risk: null },
  { port: 9100, name: "printer", risk: { severity: "low", rule: "net_printer", note: "Raw printing port." } },
  { port: 23023, name: "telnet-hidden", risk: { severity: "high", rule: "net_telnet", note: "Telnet on an unusual port — sometimes a backdoor." } },
  { port: 27017, name: "mongodb", risk: { severity: "high", rule: "net_mongodb", note: "A database that is often exposed with no authentication." } },
  { port: 32764, name: "backdoor", risk: { severity: "critical", rule: "net_backdoor", note: "Port tied to a known router backdoor." } },
];

/** Attempt a TCP connection and read any banner the service sends first. */
export function probe(host: string, port: number, timeoutMs = 800): Promise<{ open: boolean; banner: string | null }> {
  return new Promise((resolve) => {
    const socket = new Socket();
    let banner = "";
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ open, banner: banner.trim().slice(0, 120) || null });
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      // Give a talkative service a brief moment to greet us, then close.
      setTimeout(() => done(true), 250);
    });
    socket.once("data", (chunk) => {
      banner += chunk.toString("latin1").replace(/[^\x20-\x7e]+/g, " ");
      if (banner.length > 200) done(true);
    });
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, host);
  });
}

/** A concurrency-limited map, so a sweep never opens thousands of sockets at once. */
export async function pool<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await worker(items[index]!);
    }
  });
  await Promise.all(runners);
  return results;
}
