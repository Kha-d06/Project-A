/**
 * Router checks. All read-only: we look at the admin page over HTTP, ask UPnP
 * for the port mappings it already has, and read which DNS servers the computer
 * is using. We never change a mapping or a setting.
 */
import { readFile } from "node:fs/promises";

import { classifyIp } from "../nettools";
import type { RouterInfo } from "./types";

/** Well-known public resolvers, so a DNS server that isn't the router can still be recognised. */
const KNOWN_RESOLVERS = new Set([
  "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15", "76.76.2.0",
]);

export interface AdminProbe {
  http: boolean;
  hint: string | null;
}

/** Look at a response from the router's web root for a vendor/firmware hint. */
export function adminHint(server: string | null, title: string | null): string | null {
  const parts = [server, title].filter((v): v is string => Boolean(v && v.trim()));
  if (!parts.length) return null;
  return parts.join(" · ").slice(0, 120);
}

/** Pull the <title> out of an HTML page. */
export function pageTitle(html: string): string | null {
  const m = /<title[^>]*>([^<]{1,100})<\/title>/i.exec(html);
  return m ? m[1]!.trim().replace(/\s+/g, " ") : null;
}

/** Check whether the gateway serves an admin page over plain HTTP. */
export async function checkAdmin(gateway: string, fetchImpl: typeof fetch = fetch): Promise<AdminProbe> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const response = await fetchImpl(`http://${gateway}/`, { signal: controller.signal, redirect: "manual" });
    clearTimeout(timer);
    const server = response.headers.get("server");
    let title: string | null = null;
    try {
      title = pageTitle((await response.text()).slice(0, 20_000));
    } catch { /* body unreadable */ }
    return { http: true, hint: adminHint(server, title) };
  } catch {
    return { http: false, hint: null };
  }
}

/** The UPnP control URL and service type, parsed from a device description XML. */
export function parseIgdDescription(xml: string, location: string): { controlUrl: string; serviceType: string } | null {
  // Look for the WANIP/PPP connection service that exposes port mappings.
  const service = /<service>([\s\S]*?)<\/service>/g;
  let match: RegExpExecArray | null;
  while ((match = service.exec(xml))) {
    const block = match[1]!;
    const type = /<serviceType>([^<]+WANI?P?PP?Connection:\d)<\/serviceType>/i.exec(block)?.[1];
    const control = /<controlURL>([^<]+)<\/controlURL>/i.exec(block)?.[1];
    if (type && control) {
      try {
        return { controlUrl: new URL(control.trim(), location).toString(), serviceType: type.trim() };
      } catch {
        return null;
      }
    }
  }
  return null;
}

/** Parse one GetGenericPortMappingEntry SOAP response. */
export function parsePortMapping(xml: string): { external: number; internal: string; protocol: string; description: string } | null {
  const get = (tag: string) => new RegExp(`<${tag}>([^<]*)</${tag}>`, "i").exec(xml)?.[1]?.trim() ?? "";
  const external = Number(get("NewExternalPort"));
  if (!external) return null;
  return {
    external,
    internal: `${get("NewInternalClient")}:${get("NewInternalPort")}`,
    protocol: get("NewProtocol") || "TCP",
    description: get("NewPortMappingDescription"),
  };
}

function soapBody(serviceType: string, index: number): string {
  return (
    '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    `<s:Body><u:GetGenericPortMappingEntry xmlns:u="${serviceType}">` +
    `<NewPortMappingIndex>${index}</NewPortMappingIndex>` +
    "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
  );
}

/** Read the router's existing port forwardings over UPnP (read-only). */
export async function readPortForwards(location: string, fetchImpl: typeof fetch = fetch): Promise<RouterInfo["portForwards"]> {
  const forwards: RouterInfo["portForwards"] = [];
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const xml = await (await fetchImpl(location, { signal: controller.signal })).text();
    clearTimeout(timer);
    const igd = parseIgdDescription(xml, location);
    if (!igd) return forwards;
    for (let index = 0; index < 50; index++) {
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), 2500);
      const response = await fetchImpl(igd.controlUrl, {
        method: "POST",
        signal: ac.signal,
        headers: { "content-type": 'text/xml; charset="utf-8"', soapaction: `"${igd.serviceType}#GetGenericPortMappingEntry"` },
        body: soapBody(igd.serviceType, index),
      }).catch(() => null);
      clearTimeout(t);
      if (!response || !response.ok) break; // past the last mapping (router returns 500)
      const mapping = parsePortMapping(await response.text());
      if (!mapping) break;
      forwards.push(mapping);
    }
  } catch { /* UPnP not available */ }
  return forwards;
}

/** DNS servers the computer is using, each marked as router / known / other. */
export async function dnsServers(gateway: string | null, platform = process.platform, run = execCmd): Promise<RouterInfo["dns"]> {
  const addresses = new Set<string>();
  try {
    if (platform === "linux") {
      const resolv = await readFile("/etc/resolv.conf", "utf8").catch(() => "");
      for (const m of resolv.matchAll(/^nameserver\s+([\d.]+)/gm)) addresses.add(m[1]!);
    } else if (platform === "win32") {
      const out = await run("powershell", ["-NoProfile", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | %{ $_.ServerAddresses } "]);
      for (const m of out.matchAll(/[\d.]+/g)) if (classifyIp(m[0]) !== null) addresses.add(m[0]);
    } else {
      const out = await run("scutil", ["--dns"]);
      for (const m of out.matchAll(/nameserver\[\d+\]\s*:\s*([\d.]+)/g)) addresses.add(m[1]!);
    }
  } catch { /* leave empty */ }
  return [...addresses].map((address) => ({ address, known: address === gateway || KNOWN_RESOLVERS.has(address) }));
}

type Runner = (cmd: string, args: string[]) => Promise<string>;
const execCmd: Runner = (cmd, args) =>
  new Promise((resolve, reject) => {
    import("node:child_process").then(({ execFile }) => {
      execFile(cmd, args, { timeout: 15_000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (error, stdout) => {
        if (error && !stdout) reject(error);
        else resolve(String(stdout));
      });
    });
  });

export { KNOWN_RESOLVERS };
