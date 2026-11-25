/** Safe DNS: CNAME uncloaking and the DNS-rebinding guard (P1-9). */
import { describe, expect, it } from "vitest";

import { TYPE, buildQuery, isPrivateAddress, parseAnswers, parseQuery, responseCode } from "../src/engine/dns-wire";
import { SafeDnsProxy, rebindAllowed } from "../src/engine/safe-dns";

type Record = { type: "CNAME"; target: string } | { type: "A"; address: string } | { type: "AAAA"; address: string };

/** A real-shaped answer: the question, then records whose names point back at it (compression). */
function respond(query: Uint8Array, records: Record[]): Uint8Array {
  const q = parseQuery(query)!;
  const parts: number[] = [...query.subarray(0, q.end)];
  parts[2] = 0x81;
  parts[3] = 0x80;
  parts[6] = 0;
  parts[7] = records.length;
  const encodeName = (name: string) => [...name.split(".").flatMap((l) => [l.length, ...new TextEncoder().encode(l)]), 0];
  for (const r of records) {
    parts.push(0xc0, 12); // name: pointer to the question
    const rdata =
      r.type === "CNAME"
        ? encodeName(r.target)
        : r.type === "A"
          ? r.address.split(".").map(Number)
          : r.address.split(":").flatMap((h) => [Number.parseInt(h, 16) >> 8, Number.parseInt(h, 16) & 255]);
    const type = r.type === "CNAME" ? 5 : r.type === "A" ? TYPE.A : TYPE.AAAA;
    parts.push(type >> 8, type & 255, 0, 1, 0, 0, 0, 60, rdata.length >> 8, rdata.length & 255, ...rdata);
  }
  return new Uint8Array(parts);
}

function proxy(records: Record[], list: string[] = [], viaFallback = false) {
  const blocked: string[] = [];
  const p = new SafeDnsProxy({
    blocklist: () => new Set(list),
    upstream: "https://doh.test/dns-query",
    fallback: () => ["192.0.2.53"],
    doh: async (_u, query) => {
      if (viaFallback) throw new Error("no DoH");
      return respond(query, records);
    },
    udp: async (_s, query) => respond(query, records),
    onBlocked: (name) => blocked.push(name),
    rebindAllow: () => new Set(["nas.example.net"]),
  });
  return { p, blocked };
}

describe("reading answers", () => {
  it("follows compressed names to CNAME targets and reads A/AAAA", () => {
    const query = buildQuery(1, "shop.example.com", TYPE.A);
    const parsed = parseAnswers(respond(query, [{ type: "CNAME", target: "edge.tracker.example" }, { type: "A", address: "203.0.113.7" }, { type: "AAAA", address: "2001:db8:0:0:0:0:0:1" }]));
    expect(parsed).toEqual({ cnames: ["edge.tracker.example"], addresses: ["203.0.113.7", "2001:db8:0:0:0:0:0:1"] });
  });

  it("refuses malformed or looping answers instead of guessing", () => {
    const query = buildQuery(1, "a.example", TYPE.A);
    const loop = respond(query, [{ type: "A", address: "1.2.3.4" }]);
    const bad = new Uint8Array(loop);
    bad[query.length] = 0xc0;
    bad[query.length + 1] = query.length; // a pointer to itself
    expect(parseAnswers(bad)).toBeNull();
    expect(parseAnswers(loop.subarray(0, loop.length - 2))).toBeNull();
    expect(parseAnswers(new Uint8Array(5))).toBeNull();
  });

  it("knows private, loopback, link-local and CGNAT addresses", () => {
    for (const a of ["10.0.0.1", "172.16.4.4", "172.31.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "0:0:0:0:0:0:0:1", "fd00:0:0:0:0:0:0:1", "fe80:0:0:0:0:0:0:1", "0:0:0:0:0:ffff:c0a8:101"]) {
      expect(isPrivateAddress(a), a).toBe(true);
    }
    for (const a of ["8.8.8.8", "172.32.0.1", "203.0.113.7", "2001:db8:0:0:0:0:0:1", "100.128.0.1"]) expect(isPrivateAddress(a), a).toBe(false);
  });
});

describe("Safe DNS answers", () => {
  it("refuses a harmless-looking name whose CNAME leads to a listed domain", async () => {
    const { p, blocked } = proxy([{ type: "CNAME", target: "metrics.tracker.example" }, { type: "A", address: "203.0.113.9" }], ["tracker.example"]);
    const reply = await p.resolve(buildQuery(7, "stats.news.example", TYPE.A));
    expect(responseCode(reply!)).toBe(3);
    expect(blocked).toEqual(["stats.news.example → metrics.tracker.example"]);
    expect(p.stats).toMatchObject({ blocked: 1, cnameBlocked: 1 });
  });

  it("refuses a public name that DoH answers with a private address (DNS rebinding)", async () => {
    const { p } = proxy([{ type: "A", address: "192.168.1.1" }]);
    expect(responseCode((await p.resolve(buildQuery(8, "attacker.example", TYPE.A)))!)).toBe(3);
    expect(p.stats.rebindBlocked).toBe(1);
  });

  it("lets local names, by-design services and the person's list resolve privately", async () => {
    for (const name of ["router", "printer.lan", "nas.home.arpa", "1-2-3-4.abc.plex.direct", "10.0.0.5.nip.io", "nas.example.net"]) {
      const { p } = proxy([{ type: "A", address: "10.0.0.5" }]);
      expect(responseCode((await p.resolve(buildQuery(9, name, TYPE.A)))!), name).toBe(0);
    }
    expect(rebindAllowed("evil.example", new Set())).toBe(false);
  });

  it("leaves the network's own DNS alone (intranet names on company networks)", async () => {
    const { p } = proxy([{ type: "A", address: "10.20.30.40" }], [], true);
    expect(responseCode((await p.resolve(buildQuery(10, "intranet.company.example", TYPE.A)))!)).toBe(0);
    // CNAME uncloaking still applies there.
    const { p: p2 } = proxy([{ type: "CNAME", target: "x.tracker.example" }], ["tracker.example"], true);
    expect(responseCode((await p2.resolve(buildQuery(11, "cdn.company.example", TYPE.A)))!)).toBe(3);
  });

  it("passes ordinary public answers through unchanged", async () => {
    const { p } = proxy([{ type: "CNAME", target: "shop.cdn.example" }, { type: "A", address: "203.0.113.7" }]);
    const reply = await p.resolve(buildQuery(12, "shop.example", TYPE.A));
    expect(responseCode(reply!)).toBe(0);
    expect(parseAnswers(reply!)?.addresses).toEqual(["203.0.113.7"]);
  });
});
