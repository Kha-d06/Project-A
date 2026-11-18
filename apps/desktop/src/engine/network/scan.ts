/**
 * Orchestrating one scan of the home network. Runs the steps in order with an
 * overall time budget, turns what was found into plain-language findings, and
 * reports progress so the interface can show it live.
 *
 * All of this is read-only and local. The default-credential check is NOT part
 * of this; it is a separate, per-device, opt-in action (see credentials.ts).
 */
import { interfaces } from "../nettools";
import { wifiStatus } from "../system";
import type { Capability, Device, NetworkFinding, NetworkScan, RouterInfo } from "./types";
import { defaultGateway, hostsFor, prefixFromMask } from "./subnet";
import { neighbors } from "./neighbors";
import { ssdpDiscover, netbiosName, sweep } from "./discovery";
import { CATALOGUE, probe, pool } from "./ports";
import { vendorOf } from "./vendors";
import { checkAdmin, dnsServers, readPortForwards } from "./router";

export interface ScanOptions {
  platform?: NodeJS.Platform;
  /** Called as hosts are swept and devices are scanned, for the progress bar. */
  onProgress?: (done: number, total: number, phase: string) => void;
  /** Overall budget; the scan returns what it has when this elapses. */
  budgetMs?: number;
  /** Test hook: force a chosen network instead of reading the live interfaces. */
  forceNet?: { interface: string; address: string; prefix: number };
  /** Test hook: scan exactly these hosts (bypasses discovery and the subnet guard). */
  forceHosts?: string[];
  fetchImpl?: typeof fetch;
}

function finding(severity: NetworkFinding["severity"], rule: string, title: string, detail: string, device: string | null): NetworkFinding {
  return { severity, rule, title, detail, device };
}

/** Choose the interface whose subnet contains the default gateway. */
export async function chooseNetwork(gateway: string | null, platform: NodeJS.Platform) {
  const nics = await interfaces(platform);
  for (const nic of nics) {
    for (const addr of nic.addresses) {
      // addresses look like "192.168.1.20/24"
      const [ip, prefixStr] = addr.split("/");
      if (!ip || ip.includes(":")) continue;
      const prefix = Number(prefixStr);
      const net = Number.isFinite(prefix) ? hostsFor(nic.name, ip, prefix) : null;
      if (net && (!gateway || net.hosts.includes(gateway) || net.network.split(".").slice(0, 3).join(".") === gateway.split(".").slice(0, 3).join("."))) {
        return net;
      }
    }
  }
  return null;
}

export async function scanNetwork(options: ScanOptions = {}): Promise<NetworkScan> {
  const platform = options.platform ?? process.platform;
  const fetchImpl = options.fetchImpl ?? fetch;
  const startedAt = new Date().toISOString();
  const deadline = Date.now() + (options.budgetMs ?? 90_000);
  const capabilities: Record<string, Capability> = {};
  const progress = options.onProgress ?? (() => {});

  const gateway = options.forceHosts ? null : await defaultGateway(platform).catch(() => null);
  const net = options.forceHosts
    ? { interface: "test", address: "0.0.0.0", prefix: 32, network: "test", cidr: "test", hosts: options.forceHosts }
    : options.forceNet
      ? hostsFor(options.forceNet.interface, options.forceNet.address, options.forceNet.prefix)
      : await chooseNetwork(gateway, platform);

  if (!net) {
    return {
      startedAt, finishedAt: new Date().toISOString(), cidr: null, gateway, interface: null,
      wifi: null, devices: [], router: null, newDevices: [],
      findings: [finding("info", "net_no_network", "No home network found", "This computer isn't on a private network that can be scanned, or the network is too large.", null)],
      capabilities: { discovery: "unavailable" },
    };
  }

  // Wi-Fi security (reuses the existing system check).
  const wifi = await wifiStatus(platform).then((w) => ({ ssid: w.ssid, risk: w.risk })).catch(() => null);

  // 1. Sweep to wake the neighbour table, then read it.
  progress(0, net.hosts.length, "sweep");
  const alive = await sweep(net.hosts).catch(() => new Set<string>());
  const table = await neighbors(platform).catch(() => []);
  capabilities.neighbours = table.length ? "ok" : "unavailable";

  // 2. SSDP + build the device set from the union of alive hosts and the table.
  const ssdp = await ssdpDiscover().catch(() => []);
  const byIp = new Map<string, Device>();
  const ensure = (ip: string): Device => {
    let device = byIp.get(ip);
    if (!device) {
      device = { ip, mac: null, vendor: null, hostname: null, role: ip === gateway ? "router" : ip === net.address ? "self" : "device", services: [], trusted: false, firstSeen: null };
      byIp.set(ip, device);
    }
    return device;
  };
  for (const ip of alive) ensure(ip);
  if (options.forceHosts) for (const ip of options.forceHosts) ensure(ip); // test hosts are always present
  for (const entry of table) {
    if (!net.hosts.includes(entry.ip) && entry.ip !== gateway) continue;
    const device = ensure(entry.ip);
    device.mac = entry.mac;
    device.vendor = vendorOf(entry.mac);
  }
  for (const reply of ssdp) if (net.hosts.includes(reply.address) || reply.address === gateway) ensure(reply.address);
  ensure(net.address); // this computer

  const devices = [...byIp.values()];

  // 3. Names (NetBIOS) and port scan per device, within the budget.
  let scanned = 0;
  await pool(devices, 16, async (device) => {
    if (Date.now() > deadline) return;
    if (!device.hostname) device.hostname = await netbiosName(device.ip).catch(() => null);
    const open = await pool(CATALOGUE, 24, async (entry) => {
      if (Date.now() > deadline) return null;
      const { open: isOpen, banner } = await probe(device.ip, entry.port);
      return isOpen ? { port: entry.port, name: entry.name, banner } : null;
    });
    device.services = open.filter((s): s is NonNullable<typeof s> => s !== null);
    progress(++scanned, devices.length, "devices");
  });
  capabilities.ports = "ok";

  // 4. Router checks.
  let router: RouterInfo | null = null;
  if (gateway) {
    const admin = await checkAdmin(gateway, fetchImpl).catch(() => ({ http: false, hint: null }));
    const location = ssdp.find((r) => r.address === gateway)?.location ?? ssdp.find((r) => r.location)?.location ?? null;
    const portForwards = location ? await readPortForwards(location, fetchImpl).catch(() => []) : [];
    const dns = await dnsServers(gateway, platform).catch(() => []);
    router = { ip: gateway, adminHttp: admin.http, hint: admin.hint, portForwards, upnp: Boolean(location), dns };
    capabilities.router = "ok";
  } else {
    capabilities.router = "unavailable";
  }

  const findings = buildFindings(devices, router, wifi);
  return {
    startedAt, finishedAt: new Date().toISOString(), cidr: net.cidr, gateway, interface: net.interface,
    wifi, devices: devices.sort(sortDevices), router, findings, capabilities, newDevices: [],
  };
}

function sortDevices(a: Device, b: Device): number {
  const rank = (d: Device) => (d.role === "router" ? 0 : d.role === "self" ? 1 : 2);
  if (rank(a) !== rank(b)) return rank(a) - rank(b);
  return a.ip.localeCompare(b.ip, undefined, { numeric: true });
}

/** Turn the raw scan into plain-language findings. */
export function buildFindings(devices: Device[], router: RouterInfo | null, wifi: { ssid: string | null; risk: string } | null): NetworkFinding[] {
  const out: NetworkFinding[] = [];

  for (const device of devices) {
    const label = device.hostname || device.vendor || device.ip;
    for (const service of device.services) {
      const info = CATALOGUE.find((c) => c.port === service.port);
      if (info?.risk) out.push(finding(info.risk.severity, info.risk.rule, `${label}: ${service.name} (port ${service.port})`, info.risk.note, device.ip));
    }
  }

  if (router) {
    if (router.adminHttp) out.push(finding("medium", "net_router_http", "Router admin page uses plain HTTP", "The router's settings page isn't encrypted, so your admin password can be read on the local network. Use HTTPS if the router offers it.", router.ip));
    for (const forward of router.portForwards) {
      out.push(finding("high", "net_port_forward", `Port ${forward.external} is open to the internet`, `The router forwards external port ${forward.external} (${forward.protocol}) to ${forward.internal}${forward.description ? ` — "${forward.description}"` : ""}. Remove it if you don't recognise it.`, router.ip));
    }
    const foreignDns = router.dns.filter((d) => !d.known);
    if (foreignDns.length) out.push(finding("high", "net_dns_hijack", "Unexpected DNS server", `This network uses DNS server(s) ${foreignDns.map((d) => d.address).join(", ")} that aren't your router or a well-known provider. This can be a sign of DNS hijacking.`, router.ip));
  }

  if (wifi?.risk === "open") out.push(finding("high", "net_wifi_open", "Wi-Fi has no password", "This network is open, so anyone nearby can join it and watch unencrypted traffic.", null));
  else if (wifi?.risk === "weak") out.push(finding("medium", "net_wifi_weak", "Wi-Fi uses weak encryption (WEP)", "WEP can be broken in minutes. Switch the router to WPA2 or WPA3.", null));

  return out;
}
