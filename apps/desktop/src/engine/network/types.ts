/**
 * Home network scanner: shared shapes.
 *
 * Everything here describes the local network the computer is attached to. The
 * scanner runs as an ordinary user with no raw sockets: it reads the system's
 * own neighbour table, makes plain TCP connections and listens for the standard
 * discovery multicasts. Wording follows Qalaa — a result is "no issues found",
 * never "safe".
 */
import type { Severity } from "../types";

/** A service found listening on a device, with why it is worth noting. */
export interface Service {
  port: number;
  /** Short protocol label, e.g. "telnet", "smb", from the port catalogue. */
  name: string;
  /** First bytes the service sent, trimmed, when it announced itself. */
  banner: string | null;
}

/** One device seen on the local network. */
export interface Device {
  ip: string;
  /** Hardware address, when the OS exposes it (not on Android 10+). */
  mac: string | null;
  /** Maker resolved from the MAC prefix, when known. */
  vendor: string | null;
  /** Name from mDNS, SSDP or NetBIOS, when it answered. */
  hostname: string | null;
  /** "router" when this is the default gateway, "self" for this computer. */
  role: "router" | "self" | "device";
  services: Service[];
  /** True once the person has marked this device as known/trusted. */
  trusted: boolean;
  /** When this device was first seen (ISO), from the saved inventory. */
  firstSeen: string | null;
}

/** A concern about the network as a whole, or about one device. */
export interface NetworkFinding {
  severity: Severity;
  /** Stable id, translated in the interface via FINDINGS_AR. */
  rule: string;
  title: string;
  detail: string;
  /** The device this is about (IP), or null for a network-wide finding. */
  device: string | null;
}

export interface RouterInfo {
  ip: string | null;
  /** Admin page reached over plain HTTP (not HTTPS). */
  adminHttp: boolean;
  /** Vendor or firmware hint from the admin page title or Server header. */
  hint: string | null;
  /** UPnP port forwardings the router reported, read-only. */
  portForwards: { external: number; internal: string; protocol: string; description: string }[];
  /** True when UPnP IGD control was reachable at all. */
  upnp: boolean;
  /** DNS servers the computer is using, and whether each is the router or a known resolver. */
  dns: { address: string; known: boolean }[];
}

export type Capability = "ok" | "unsupported" | "unavailable";

/** The result of one scan of the local network. */
export interface NetworkScan {
  startedAt: string;
  finishedAt: string;
  /** The network that was scanned, in CIDR form, e.g. "192.168.1.0/24". */
  cidr: string | null;
  gateway: string | null;
  interface: string | null;
  wifi: { ssid: string | null; risk: string } | null;
  devices: Device[];
  router: RouterInfo | null;
  findings: NetworkFinding[];
  /** Which steps could run on this system. */
  capabilities: Record<string, Capability>;
  /** New devices since the last scan (IPs), for the alert. */
  newDevices: string[];
}
