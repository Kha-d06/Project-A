import { describe, expect, it } from "vitest";

import { hostsFor, parseMacRoute, parseProcRoute, parseWindowsRoute, prefixFromMask, MAX_HOSTS } from "../src/engine/network/subnet";
import { parseArpDashA, parseIpNeigh, parseProcArp } from "../src/engine/network/neighbors";
import { CATALOGUE } from "../src/engine/network/ports";
import { netbiosQuery, parseNetbiosReply, parseSsdp } from "../src/engine/network/discovery";
import { vendorOf, DEFAULT_LOGINS } from "../src/engine/network/vendors";
import { adminHint, dnsServers, pageTitle, parseIgdDescription, parsePortMapping, KNOWN_RESOLVERS } from "../src/engine/network/router";
import { annotate, deviceKey, reconcile, setTrusted } from "../src/engine/network/inventory";
import { buildFindings } from "../src/engine/network/scan";
import { MAX_TRIES } from "../src/engine/network/credentials";
import type { Device } from "../src/engine/network/types";

describe("subnet guard", () => {
  it("builds the host list for a /24", () => {
    const net = hostsFor("eth0", "192.168.1.20", 24)!;
    expect(net.network).toBe("192.168.1.0");
    expect(net.cidr).toBe("192.168.1.0/24");
    expect(net.hosts).toHaveLength(253); // 254 usable minus our own address
    expect(net.hosts).toContain("192.168.1.1");
    expect(net.hosts).not.toContain("192.168.1.20"); // skip self
    expect(net.hosts).not.toContain("192.168.1.0"); // skip network
    expect(net.hosts).not.toContain("192.168.1.255"); // skip broadcast
  });

  it("refuses a network larger than the cap", () => {
    expect(hostsFor("eth0", "10.0.0.5", 20)).toBeNull(); // 4094 hosts > cap
    expect(MAX_HOSTS).toBe(1024);
  });

  it("refuses public and carrier-NAT addresses", () => {
    expect(hostsFor("eth0", "8.8.8.8", 24)).toBeNull();
    expect(hostsFor("eth0", "100.64.0.1", 24)).toBeNull();
  });

  it("accepts link-local but not odd prefixes", () => {
    expect(hostsFor("eth0", "169.254.1.1", 24)).not.toBeNull();
    expect(hostsFor("eth0", "192.168.1.1", 7)).toBeNull();
    expect(hostsFor("eth0", "192.168.1.1", 32)).toBeNull();
  });

  it("prefixFromMask handles contiguous and non-contiguous masks", () => {
    expect(prefixFromMask("255.255.255.0")).toBe(24);
    expect(prefixFromMask("255.255.0.0")).toBe(16);
    expect(prefixFromMask("255.0.255.0")).toBeNull();
  });
});

describe("route parsers", () => {
  it("reads the default gateway from /proc/net/route", () => {
    const text =
      "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
      "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
      "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
    expect(parseProcRoute(text)).toEqual({ interface: "eth0", gateway: "192.168.1.1" });
  });

  it("ignores a route with no gateway flag", () => {
    const text = "Iface\tDestination\tGateway\tFlags\n" + "eth0\t00000000\t00000000\t0001\n";
    expect(parseProcRoute(text)).toBeNull();
  });

  it("reads Windows and macOS gateways", () => {
    expect(parseWindowsRoute("Network Destination        Netmask          Gateway       Interface\n          0.0.0.0          0.0.0.0      192.168.0.1     192.168.0.42")).toBe("192.168.0.1");
    expect(parseMacRoute("   route to: default\n destination: default\n    gateway: 192.168.8.1\n interface: en0")).toBe("192.168.8.1");
  });
});

describe("neighbour parsers", () => {
  it("parses /proc/net/arp and drops incomplete entries", () => {
    const text =
      "IP address       HW type     Flags       HW address            Mask     Device\n" +
      "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n" +
      "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
    const n = parseProcArp(text);
    expect(n).toHaveLength(1);
    expect(n[0]).toEqual({ ip: "192.168.1.1", mac: "aa:bb:cc:dd:ee:ff" });
  });

  it("parses ip -j neigh and skips FAILED", () => {
    const json = JSON.stringify([
      { dst: "192.168.1.1", lladdr: "AA:BB:CC:DD:EE:01", state: ["REACHABLE"] },
      { dst: "192.168.1.2", state: ["FAILED"] },
    ]);
    const n = parseIpNeigh(json);
    expect(n).toHaveLength(1);
    expect(n[0]!.mac).toBe("aa:bb:cc:dd:ee:01");
  });

  it("parses arp -a (Windows) and arp -an (BSD/macOS)", () => {
    expect(parseArpDashA("  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic")).toEqual([{ ip: "192.168.1.1", mac: "aa:bb:cc:dd:ee:ff" }]);
    expect(parseArpDashA("router (192.168.1.1) at a1:b2:c3:d4:e5:f6 on en0 ifscope [ethernet]")).toEqual([{ ip: "192.168.1.1", mac: "a1:b2:c3:d4:e5:f6" }]);
  });
});

describe("port catalogue", () => {
  it("covers around 30 ports and flags the dangerous ones", () => {
    expect(CATALOGUE.length).toBeGreaterThanOrEqual(28);
    const telnet = CATALOGUE.find((p) => p.port === 23)!;
    expect(telnet.risk?.severity).toBe("critical");
    expect(CATALOGUE.find((p) => p.port === 5555)?.risk?.rule).toBe("net_adb");
    // Benign ports carry no risk note.
    expect(CATALOGUE.find((p) => p.port === 80)?.risk).toBeNull();
  });

  it("has no duplicate ports", () => {
    const ports = CATALOGUE.map((p) => p.port);
    expect(new Set(ports).size).toBe(ports.length);
  });
});

describe("discovery parsers", () => {
  it("parses SSDP headers case-insensitively", () => {
    const reply = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nSERVER: Linux/3.4 UPnP/1.0 MiniUPnPd/1.9\r\n\r\n";
    expect(parseSsdp(reply)).toEqual({ location: "http://192.168.1.1:5000/rootDesc.xml", server: "Linux/3.4 UPnP/1.0 MiniUPnPd/1.9" });
  });

  it("builds a NetBIOS query and reads a name back", () => {
    const query = netbiosQuery();
    expect(query.length).toBe(50);
    // Craft a minimal node-status reply with one unique name "DESKTOP".
    const header = Buffer.alloc(12 + 34 + 10);
    const name = Buffer.alloc(15);
    name.write("DESKTOP", "latin1");
    const flags = Buffer.from([0x44, 0x00, 0x00]); // not a group name
    const reply = Buffer.concat([header, Buffer.from([0x01]), name, flags]);
    expect(parseNetbiosReply(reply)).toBe("DESKTOP");
  });
});

describe("vendor lookup", () => {
  it("resolves known OUI prefixes and nothing else", () => {
    expect(vendorOf("b8:27:eb:12:34:56")).toBe("Raspberry Pi");
    expect(vendorOf("B827EB123456")).toBe("Raspberry Pi");
    expect(vendorOf("de:ad:be:ef:00:01")).toBeNull();
    expect(vendorOf(null)).toBeNull();
  });

  it("offers a short list of documented default logins", () => {
    expect(DEFAULT_LOGINS.length).toBeGreaterThanOrEqual(5);
    expect(DEFAULT_LOGINS).toContainEqual({ user: "admin", pass: "admin" });
  });
});

describe("router parsers", () => {
  it("reads a page title and builds a hint", () => {
    expect(pageTitle("<html><head><title> ASUS Router  </title></head>")).toBe("ASUS Router");
    expect(adminHint("lighttpd/1.4", "ASUS Router")).toBe("lighttpd/1.4 · ASUS Router");
    expect(adminHint(null, null)).toBeNull();
  });

  it("finds the IGD control URL and parses a port mapping", () => {
    const xml =
      "<root><device><serviceList><service>" +
      "<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>" +
      "<controlURL>/ctl/IPConn</controlURL>" +
      "</service></serviceList></device></root>";
    const igd = parseIgdDescription(xml, "http://192.168.1.1:5000/rootDesc.xml")!;
    expect(igd.serviceType).toContain("WANIPConnection:1");
    expect(igd.controlUrl).toBe("http://192.168.1.1:5000/ctl/IPConn");

    const soap =
      "<NewExternalPort>3389</NewExternalPort><NewProtocol>TCP</NewProtocol>" +
      "<NewInternalClient>192.168.1.50</NewInternalClient><NewInternalPort>3389</NewInternalPort>" +
      "<NewPortMappingDescription>rdp</NewPortMappingDescription>";
    expect(parsePortMapping(soap)).toEqual({ external: 3389, internal: "192.168.1.50:3389", protocol: "TCP", description: "rdp" });
    expect(parsePortMapping("<NewExternalPort></NewExternalPort>")).toBeNull();
  });

  it("marks the router and well-known resolvers as known DNS", async () => {
    const servers = await dnsServers("192.168.1.1", "linux", async () => "");
    expect(Array.isArray(servers)).toBe(true);
    expect(KNOWN_RESOLVERS.has("1.1.1.1")).toBe(true);
  });
});

describe("inventory", () => {
  const device = (ip: string, mac: string | null, role: Device["role"] = "device"): Device => ({ ip, mac, vendor: null, hostname: null, role, services: [], trusted: false, firstSeen: null });

  it("keys by MAC when present, otherwise by IP", () => {
    expect(deviceKey({ mac: "aa:bb:cc:dd:ee:ff", ip: "192.168.1.5" })).toBe("mac:aa:bb:cc:dd:ee:ff");
    expect(deviceKey({ mac: null, ip: "192.168.1.5" })).toBe("ip:192.168.1.5");
  });

  it("flags only genuinely new devices and not the router", () => {
    const first = reconcile({}, [device("192.168.1.1", "ro:ut:er:00:00:01", "router"), device("192.168.1.5", "aa:bb:cc:dd:ee:ff")], "2026-01-01T00:00:00Z");
    expect(first.newKeys).toEqual(["mac:aa:bb:cc:dd:ee:ff"]);

    const second = reconcile(first.inventory, [device("192.168.1.9", "11:22:33:44:55:66")], "2026-01-02T00:00:00Z");
    expect(second.newKeys).toEqual(["mac:11:22:33:44:55:66"]);
  });

  it("applies trusted flags back onto a scan", () => {
    const { inventory } = reconcile({}, [device("192.168.1.5", "aa:bb:cc:dd:ee:ff")], "2026-01-01T00:00:00Z");
    const trusted = setTrusted(inventory, "mac:aa:bb:cc:dd:ee:ff", true);
    const annotated = annotate([device("192.168.1.5", "aa:bb:cc:dd:ee:ff")], trusted);
    expect(annotated[0]!.trusted).toBe(true);
    expect(annotated[0]!.firstSeen).toBe("2026-01-01T00:00:00Z");
  });
});

describe("findings", () => {
  it("reports open telnet, a forwarded port, foreign DNS and open Wi-Fi", () => {
    const devices: Device[] = [
      { ip: "192.168.1.30", mac: null, vendor: "Camera", hostname: "cam", role: "device", services: [{ port: 23, name: "telnet", banner: null }], trusted: false, firstSeen: null },
    ];
    const findings = buildFindings(
      devices,
      { ip: "192.168.1.1", adminHttp: true, hint: null, upnp: true, portForwards: [{ external: 3389, internal: "192.168.1.50:3389", protocol: "TCP", description: "rdp" }], dns: [{ address: "5.6.7.8", known: false }] },
      { ssid: "home", risk: "open" },
    );
    const rules = findings.map((f) => f.rule);
    expect(rules).toContain("net_telnet");
    expect(rules).toContain("net_router_http");
    expect(rules).toContain("net_port_forward");
    expect(rules).toContain("net_dns_hijack");
    expect(rules).toContain("net_wifi_open");
    expect(findings.find((f) => f.rule === "net_telnet")!.severity).toBe("critical");
  });

  it("stays quiet on a clean network", () => {
    const devices: Device[] = [{ ip: "192.168.1.10", mac: null, vendor: null, hostname: null, role: "device", services: [{ port: 443, name: "https-alt", banner: null }], trusted: false, firstSeen: null }];
    expect(buildFindings(devices, { ip: "192.168.1.1", adminHttp: false, hint: null, upnp: false, portForwards: [], dns: [{ address: "192.168.1.1", known: true }] }, { ssid: "home", risk: "ok" })).toEqual([]);
  });
});

describe("credential check limits", () => {
  it("never tries more than the documented maximum", () => {
    expect(MAX_TRIES).toBeLessThanOrEqual(5);
  });
});
