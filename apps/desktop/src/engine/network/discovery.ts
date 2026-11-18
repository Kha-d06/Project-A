/**
 * Finding devices and their names without special privileges:
 *  - a TCP sweep to wake the neighbour table and spot live hosts,
 *  - SSDP (UPnP) to find the router's description and media devices,
 *  - mDNS to pick up names that Apple/printers/Chromecasts announce,
 *  - NetBIOS to name Windows machines.
 *
 * The multicast listeners are best effort: anything that doesn't answer is
 * simply left without a name. Parsers are pure so they can be tested.
 */
import { createSocket } from "node:dgram";

import { probe, pool } from "./ports";

export interface SsdpReply {
  address: string;
  /** URL of the device description XML, from the LOCATION header. */
  location: string | null;
  /** SERVER header, often naming the firmware. */
  server: string | null;
}

/** Parse one SSDP/HTTPU response block into its headers. */
export function parseSsdp(text: string): { location: string | null; server: string | null } {
  const header = (name: string) => new RegExp(`^${name}:\\s*(.+)$`, "im").exec(text)?.[1]?.trim() ?? null;
  return { location: header("location"), server: header("server") };
}

/** Send an SSDP M-SEARCH and collect replies for a short window. */
export function ssdpDiscover(timeoutMs = 2000): Promise<SsdpReply[]> {
  return new Promise((resolve) => {
    const replies = new Map<string, SsdpReply>();
    const socket = createSocket({ type: "udp4", reuseAddr: true });
    const message = Buffer.from(
      "M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        'MAN: "ssdp:discover"\r\n' +
        "MX: 1\r\n" +
        "ST: ssdp:all\r\n\r\n",
    );
    socket.on("message", (buf, rinfo) => {
      const parsed = parseSsdp(buf.toString("utf8"));
      // Keep the first (or most descriptive) reply per address.
      if (!replies.has(rinfo.address) || parsed.location) replies.set(rinfo.address, { address: rinfo.address, ...parsed });
    });
    socket.on("error", () => {
      try { socket.close(); } catch { /* already closed */ }
      resolve([...replies.values()]);
    });
    socket.bind(() => {
      try {
        socket.send(message, 1900, "239.255.255.250");
      } catch { /* no multicast route */ }
    });
    setTimeout(() => {
      try { socket.close(); } catch { /* already closed */ }
      resolve([...replies.values()]);
    }, timeoutMs);
  });
}

/** Build a NetBIOS node-status request (NBSTAT) for the wildcard name. */
export function netbiosQuery(): Buffer {
  // Transaction id 0x0000, flags 0x0010 (broadcast), 1 question.
  const header = Buffer.from([0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  // Encoded name "*" padded: first-level encoding of 16 bytes ("*"+15 nulls).
  const name = Buffer.alloc(34);
  name[0] = 0x20;
  const raw = Buffer.alloc(16);
  raw[0] = 0x2a; // "*"
  for (let i = 0; i < 16; i++) {
    name[1 + i * 2] = 0x41 + (raw[i]! >> 4);
    name[2 + i * 2] = 0x41 + (raw[i]! & 0x0f);
  }
  name[33] = 0x00;
  // Question type NBSTAT (0x0021), class IN (0x0001).
  const tail = Buffer.from([0x00, 0x21, 0x00, 0x01]);
  return Buffer.concat([header, name, tail]);
}

/** Pull the first non-group NetBIOS name out of a node-status reply. */
export function parseNetbiosReply(buf: Buffer): string | null {
  try {
    // Skip the 12-byte header, the encoded name (34 bytes) and the RR header.
    let offset = 12 + 34 + 2 + 2 + 4 + 2; // type+class+ttl+rdlength
    const count = buf[offset];
    if (count === undefined) return null;
    offset += 1;
    for (let i = 0; i < count; i++) {
      const name = buf.subarray(offset, offset + 15).toString("latin1").replace(/\0+$/, "").trim();
      const flags = buf.readUInt16BE(offset + 16);
      const isGroup = (flags & 0x8000) !== 0;
      if (name && !isGroup && /[\x20-\x7e]/.test(name)) return name.replace(/[^\x20-\x7e]/g, "").trim();
      offset += 18;
    }
  } catch {
    return null;
  }
  return null;
}

/** Ask one host for its NetBIOS name over UDP 137. */
export function netbiosName(ip: string, timeoutMs = 800): Promise<string | null> {
  return new Promise((resolve) => {
    const socket = createSocket("udp4");
    let settled = false;
    const done = (name: string | null) => {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch { /* already closed */ }
      resolve(name);
    };
    socket.on("message", (buf) => done(parseNetbiosReply(buf)));
    socket.on("error", () => done(null));
    try {
      socket.send(netbiosQuery(), 137, ip);
    } catch {
      done(null);
    }
    setTimeout(() => done(null), timeoutMs);
  });
}

/**
 * A quick TCP sweep: connect to a few common ports on each address so the OS
 * fills its neighbour table, and note which hosts answered. Returns the set of
 * addresses that accepted at least one connection.
 */
export async function sweep(hosts: string[], limit = 64): Promise<Set<string>> {
  const ports = [80, 443, 22, 139, 445, 53];
  const alive = new Set<string>();
  await pool(hosts, limit, async (host) => {
    for (const port of ports) {
      const { open } = await probe(host, port, 600);
      if (open) {
        alive.add(host);
        break;
      }
    }
  });
  return alive;
}
