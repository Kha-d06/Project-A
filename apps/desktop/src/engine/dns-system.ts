/**
 * Turning Safe DNS on and off at the system level. Every change goes through
 * the system's consent prompt and is undone by the matching "off" command.
 *
 * - Linux (systemd-resolved): a drop-in sends all lookups to the proxy on
 *   127.0.0.1:5354. Removing the file restores the previous behaviour.
 * - Windows: connected adapters use 127.0.0.1 (the proxy on port 53); turning
 *   it off resets them to automatic (the network's DHCP servers).
 * - macOS: each network service uses 127.0.0.1; turning it off sets them back
 *   to automatic ("Empty").
 *
 * Before switching, the network's own DNS servers are recorded: the proxy uses
 * them for captive portals and whenever DNS-over-HTTPS can't be reached.
 */
import type { ElevatedCommand } from "./listeners";

export const RESOLVED_DROPIN = "/etc/systemd/resolved.conf.d/qalaa-safe-dns.conf";

export function proxyPort(platform: NodeJS.Platform): number {
  // Port 53 needs root on Linux; resolved accepts a port in DNS=. mDNS owns 5353.
  return platform === "linux" ? 5354 : 53;
}

/**
 * The network's own servers follow the proxy, so lookups still work if the
 * proxy isn't running (the system moves on when it doesn't answer).
 */
export function resolvedDropin(port: number, fallback: string[] = []): string {
  return `# Written by Qalaa Safe DNS. Delete this file to undo.\n[Resolve]\nDNS=${["127.0.0.1:" + port, ...fallback].join(" ")}\nDomains=~.\n`;
}

const safeAddress = (a: string) => /^[0-9a-f.:]+$/i.test(a);

const isLocal = (address: string) => address.startsWith("127.") || address === "::1" || address === "0.0.0.0";

/** Linux: nameservers from /run/systemd/resolve/resolv.conf (the real upstreams, not the stub). */
export function parseResolvConf(text: string): string[] {
  const servers = [...text.matchAll(/^nameserver\s+(\S+)/gm)].map((m) => m[1]!).filter((s) => !isLocal(s));
  return [...new Set(servers)];
}

/** Windows: one address per line from Get-DnsClientServerAddress … -ExpandProperty ServerAddresses. */
export function parseWindowsServers(text: string): string[] {
  const servers = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^[0-9a-f.:]+$/i.test(l) && !isLocal(l));
  return [...new Set(servers)];
}

/** macOS: `scutil --dns` lists `nameserver[0] : 192.168.1.1` for each resolver. */
export function parseScutilDns(text: string): string[] {
  const servers = [...text.matchAll(/nameserver\[\d+\]\s*:\s*(\S+)/g)].map((m) => m[1]!).filter((s) => !isLocal(s));
  return [...new Set(servers)];
}

/** macOS: `networksetup -listallnetworkservices`; skips the header and disabled (*) services. */
export function parseNetworkServices(text: string): string[] {
  return text
    .split(/\r?\n/)
    .slice(1)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("*") && /^[\w .()&+-]+$/.test(l));
}

const quoteSh = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;

/** The elevated command that turns system-wide Safe DNS on or off. */
export function switchCommand(platform: NodeJS.Platform, on: boolean, fallback: string[] = [], macServices: string[] = []): ElevatedCommand {
  const servers = ["127.0.0.1", ...fallback.filter(safeAddress)];
  if (platform === "win32") {
    const action = on ? `-ServerAddresses ${servers.map((a) => `'${a}'`).join(",")}` : "-ResetServerAddresses";
    const script = `Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex ${action} }; Clear-DnsClientCache`;
    return {
      command: "powershell.exe",
      args: ["-NoProfile", "-NonInteractive", "-Command", `Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-Command','${script.replace(/'/g, "''")}' -Verb RunAs -Wait -WindowStyle Hidden`],
    };
  }
  if (platform === "darwin") {
    const value = on ? servers.join(" ") : "Empty";
    const shell = macServices.map((s) => `/usr/sbin/networksetup -setdnsservers ${quoteSh(s)} ${value}`).join(" && ") || "true";
    return { command: "osascript", args: ["-e", `do shell script ${JSON.stringify(`${shell} && /usr/bin/dscacheutil -flushcache`)} with administrator privileges`] };
  }
  const script = on
    ? `mkdir -p /etc/systemd/resolved.conf.d && cat > ${RESOLVED_DROPIN} <<'QALAA'\n${resolvedDropin(proxyPort("linux"), fallback.filter(safeAddress))}QALAA\nsystemctl restart systemd-resolved`
    : `rm -f ${RESOLVED_DROPIN} && systemctl restart systemd-resolved`;
  return { command: "pkexec", args: ["sh", "-c", script] };
}

export function describeSwitch(platform: NodeJS.Platform, on: boolean, upstream: string): string {
  if (!on) {
    return platform === "linux"
      ? "Remove Qalaa's DNS setting from systemd-resolved, so lookups go where they did before."
      : "Set DNS back to automatic, so your network's own DNS servers are used again.";
  }
  const where = platform === "linux" ? "systemd-resolved" : platform === "win32" ? "your connected network adapters" : "your network services";
  return `Point ${where} at Qalaa's DNS on this computer, which blocks known malicious domains and sends other lookups encrypted to ${upstream}. Login pages on public Wi-Fi keep working. Your network's own DNS stays listed second, so lookups still work if Qalaa isn't running.`;
}
