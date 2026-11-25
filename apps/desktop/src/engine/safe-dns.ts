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
 * - CNAME uncloaking: an answer whose CNAME chain reaches a listed domain is
 *   refused too, so a tracker or malware host can't hide behind a harmless
 *   first name.
 * - Rebinding guard: a public name that DNS-over-HTTPS answers with a private,
 *   loopback or link-local address is refused, so a web page can't turn its own
 *   name into a way into your router or local services. Answers from the
 *   network's own DNS are left alone (company networks legitimately answer
 *   intranet names with private addresses), as are local names, names that do
 *   this on purpose (plex.direct, nip.io, sslip.io and the like) and any the
 *   person allows.
 *
 * The proxy listens on loopback only. Turning it on and off at the system level
 * is in dns-system.ts.
 */
import { type Socket, createSocket } from "node:dgram";

import { type Question, isPrivateAddress, parseAnswers, parseQuery, replyWithCode, responseCode, withId } from "./dns-wire";

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

/** Names that resolve to private addresses by design. */
export const REBIND_OK = ["plex.direct", "nip.io", "sslip.io", "localtest.me", "lvh.me", "local", "lan", "home.arpa", "internal", "localhost", "home", "corp"];

/** Local or allowed names may resolve to private addresses. */
export function rebindAllowed(name: string, allowed: ReadonlySet<string>): boolean {
  if (!name.includes(".")) return true; // single-label names are local
  return isListed(name, new Set(REBIND_OK)) || isListed(name, allowed);
}

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
  /** Extra names allowed to resolve to private addresses (the person's list). */
  rebindAllow?: () => ReadonlySet<string>;
  /** Ad and tracker lists (qalaa-dns); null means no opinion and the name is allowed. */
  filter?: (name: string) => Promise<{ blocked: boolean; rule: string | null } | null>;
}

export interface SafeDnsStats {
  queries: number;
  blocked: number;
  viaDoh: number;
  viaFallback: number;
  failed: number;
  /** Refused because a CNAME in the answer was listed. */
  cnameBlocked: number;
  /** Refused because a public name pointed at a private address. */
  rebindBlocked: number;
  /** Refused by the ad and tracker lists (the name itself or a CNAME). */
  listBlocked: number;
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
  readonly stats: SafeDnsStats = { queries: 0, blocked: 0, viaDoh: 0, viaFallback: 0, failed: 0, cnameBlocked: 0, rebindBlocked: 0, listBlocked: 0 };
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
    if (!CAPTIVE_CHECKS.includes(question.name) && (await this.listed(question.name))) {
      this.stats.blocked += 1;
      this.stats.listBlocked += 1;
      this.deps.onBlocked?.(question.name);
      return replyWithCode(query, question, 3);
    }
    if (!CAPTIVE_CHECKS.includes(question.name)) {
      try {
        const answer = await this.doh(this.deps.upstream, withId(query, 0));
        this.stats.viaDoh += 1;
        return await this.inspect(query, question, withId(answer, question.id), true);
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
          return await this.inspect(query, question, answer, false);
        }
      } catch {
        // try the next one
      }
    }
    this.stats.failed += 1;
    return replyWithCode(query, question, 2);
  }

  /** CNAME uncloaking on every answer; the rebinding guard on DoH answers only. */
  private async listed(name: string): Promise<boolean> {
    if (!this.deps.filter) return false;
    try {
      return (await this.deps.filter(name))?.blocked === true;
    } catch {
      return false; // the filter never stops a lookup
    }
  }

  private async inspect(query: Uint8Array, question: Question, answer: Uint8Array, fromDoh: boolean): Promise<Uint8Array> {
    const parsed = parseAnswers(answer);
    if (!parsed) return answer; // unreadable: passed through as before
    const list = this.deps.blocklist();
    let cloaked = parsed.cnames.find((name) => isListed(name, list));
    if (!cloaked) {
      // A tracker behind a first-party name (CNAME cloaking) is checked against the ad and tracker lists too.
      for (const name of parsed.cnames.slice(0, 8)) {
        if (await this.listed(name)) {
          cloaked = name;
          this.stats.listBlocked += 1;
          break;
        }
      }
    }
    if (cloaked) {
      this.stats.blocked += 1;
      this.stats.cnameBlocked += 1;
      this.deps.onBlocked?.(`${question.name} → ${cloaked}`);
      return replyWithCode(query, question, 3);
    }
    if (fromDoh && parsed.addresses.some(isPrivateAddress) && !rebindAllowed(question.name, this.deps.rebindAllow?.() ?? new Set())) {
      this.stats.rebindBlocked += 1;
      return replyWithCode(query, question, 3);
    }
    return answer;
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
