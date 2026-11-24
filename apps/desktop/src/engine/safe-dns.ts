/**
 * Safe DNS: a small local DNS proxy.
 *
 * - Names on Qalaa's downloaded threat list (and the person's own block list)
 *   get NXDOMAIN, so the computer never connects to them.
 * - Everything else is sent over DNS-over-HTTPS (RFC 8484) to a resolver that
 *   also blocks malware domains (Quad9 by default), so the network can't read
 *   or change the answers.
 * - Captive portals are never broken: the operating systems' connectivity-check
 *   names, and any query when DoH can't be reached (a hotel or café login page),
 *   go to the network's own DNS servers, captured when Safe DNS was turned on.
 *
 * The proxy listens on loopback only. Turning it on and off at the system level
 * is in dns-system.ts.
 */
import { type Socket, createSocket } from "node:dgram";

import { type Question, parseQuery, replyWithCode, responseCode, withId } from "./dns-wire";

export const UPSTREAMS = {
  quad9: { name: "Quad9 (blocks malware domains)", url: "https://dns.quad9.net/dns-query" },
  cloudflare: { name: "Cloudflare for Families (malware)", url: "https://security.cloudflare-dns.com/dns-query" },
} as const;
export type UpstreamId = keyof typeof UPSTREAMS;

/** Names the systems use to detect a login page; they must see the real network. */
export const CAPTIVE_CHECKS = [
  "captive.apple.com",
  "connectivitycheck.gstatic.com",
  "connectivitycheck.android.com",
  "clients3.google.com",
  "www.msftconnecttest.com",
  "www.msftncsi.com",
  "dns.msftncsi.com",
  "detectportal.firefox.com",
  "nmcheck.gnome.org",
  "network-test.debian.org",
  "connectivity-check.ubuntu.com",
];

const TIMEOUT_MS = 3_000;

/** True when `name` or any parent domain is listed. */
export function isListed(name: string, list: ReadonlySet<string>): boolean {
  let candidate = name.toLowerCase().replace(/\.$/, "");
  for (;;) {
    if (list.has(candidate)) return true;
    const dot = candidate.indexOf(".");
    if (dot < 0) return false;
    candidate = candidate.slice(dot + 1);
  }
}

export interface SafeDnsDeps {
  blocklist: () => ReadonlySet<string>;
  upstream: string;
  /** The network's own DNS servers (IPv4/IPv6 addresses), for captive portals and fallback. */
  fallback: () => string[];
  doh?: (url: string, query: Uint8Array) => Promise<Uint8Array>;
  udp?: (server: string, query: Uint8Array) => Promise<Uint8Array>;
  onBlocked?: (name: string) => void;
}

export interface SafeDnsStats {
  queries: number;
  blocked: number;
  viaDoh: number;
  viaFallback: number;
  failed: number;
}

export async function dohQuery(url: string, query: Uint8Array): Promise<Uint8Array> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/dns-message", Accept: "application/dns-message" },
    body: new Blob([new Uint8Array(query)]),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`DoH answered ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

export function udpQuery(server: string, query: Uint8Array, port = 53): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const socket = createSocket(server.includes(":") ? "udp6" : "udp4");
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error("timed out"));
    }, TIMEOUT_MS);
    socket.once("message", (message) => {
      clearTimeout(timer);
      socket.close();
      resolve(new Uint8Array(message));
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      socket.close();
      reject(error);
    });
    socket.send(query, port, server);
  });
}

export class SafeDnsProxy {
  readonly stats: SafeDnsStats = { queries: 0, blocked: 0, viaDoh: 0, viaFallback: 0, failed: 0 };
  private socket: Socket | null = null;
  private readonly doh: NonNullable<SafeDnsDeps["doh"]>;
  private readonly udp: NonNullable<SafeDnsDeps["udp"]>;

  constructor(private readonly deps: SafeDnsDeps) {
    this.doh = deps.doh ?? dohQuery;
    this.udp = deps.udp ?? ((server, query) => udpQuery(server, query));
  }

  /** Answers one query (wire format in, wire format out). */
  async resolve(query: Uint8Array): Promise<Uint8Array | null> {
    const question = parseQuery(query);
    if (!question) return null;
    this.stats.queries += 1;
    if (isListed(question.name, this.deps.blocklist())) {
      this.stats.blocked += 1;
      this.deps.onBlocked?.(question.name);
      return replyWithCode(query, question, 3);
    }
    if (!CAPTIVE_CHECKS.includes(question.name)) {
      try {
        const answer = await this.doh(this.deps.upstream, withId(query, 0));
        this.stats.viaDoh += 1;
        return withId(answer, question.id);
      } catch {
        // DoH unreachable: most often a login page that blocks everything else.
      }
    }
    return this.fallback(query, question);
  }

  private async fallback(query: Uint8Array, question: Question): Promise<Uint8Array> {
    for (const server of this.deps.fallback()) {
      try {
        const answer = await this.udp(server, query);
        if (responseCode(answer) !== 2) {
          this.stats.viaFallback += 1;
          return answer;
        }
      } catch {
        // try the next one
      }
    }
    this.stats.failed += 1;
    return replyWithCode(query, question, 2);
  }

  /** Listens on loopback only. Resolves with the port actually bound. */
  start(port: number, host = "127.0.0.1"): Promise<number> {
    return new Promise((resolve, reject) => {
      const socket = createSocket(host.includes(":") ? "udp6" : "udp4");
      socket.on("message", (message, from) => {
        void this.resolve(new Uint8Array(message)).then((answer) => {
          if (answer) socket.send(answer, from.port, from.address);
        });
      });
      socket.once("error", reject);
      socket.bind(port, host, () => {
        this.socket = socket;
        resolve(socket.address().port);
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.socket) return resolve();
      this.socket.close(() => resolve());
      this.socket = null;
    });
  }

  running(): boolean {
    return this.socket !== null;
  }
}
