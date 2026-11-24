/**
 * New listening-port alerts.
 *
 * Programs that start accepting connections from other machines are a classic
 * sign of a backdoor, and also of an app that quietly opened a service. Qalaa
 * keeps a baseline of what listens (program + port + whether other machines can
 * reach it). The first check only records the baseline; afterwards anything new
 * and reachable from the network is reported, once, until the person trusts it
 * or blocks the port.
 *
 * Blocking is reversible and goes through the system's consent prompt:
 * nftables (Linux, via pkexec), Windows Defender Firewall (netsh, UAC), and a
 * pf anchor (macOS, administrator prompt). The rules only drop incoming
 * connections to that port from other machines; loopback stays open.
 */
import type { ListeningPort } from "./security";

export interface Listener extends ListeningPort {
  key: string;
}

export interface ListenerBaseline {
  /** Listener keys seen or trusted. */
  known: string[];
  /** Ports Qalaa blocked, so the rules can be rebuilt or undone. */
  blockedPorts: number[];
  seeded: boolean;
}

export const EMPTY_BASELINE: ListenerBaseline = { known: [], blockedPorts: [], seeded: false };

/** Stable identity: the program and port, and whether it is reachable from outside. */
export function listenerKey(port: ListeningPort): string {
  const program = (port.process ?? "unknown").toLowerCase();
  return `${program}|${port.port}|${port.exposed ? "net" : "local"}`;
}

export function withKeys(ports: ListeningPort[]): Listener[] {
  return ports.map((port) => ({ ...port, key: listenerKey(port) }));
}

/**
 * Compares the current listeners with the baseline. Returns the new, exposed
 * listeners to report, and the baseline to store. The first call seeds silently.
 */
export function diffListeners(baseline: ListenerBaseline, current: ListeningPort[]): { fresh: Listener[]; baseline: ListenerBaseline } {
  const listeners = withKeys(current);
  if (!baseline.seeded) {
    return { fresh: [], baseline: { ...baseline, seeded: true, known: [...new Set([...baseline.known, ...listeners.map((l) => l.key)])] } };
  }
  const known = new Set(baseline.known);
  const fresh = listeners.filter((l) => l.exposed && !known.has(l.key) && !baseline.blockedPorts.includes(l.port));
  // Loopback-only services are recorded but never alerted on.
  const quietlyKnown = listeners.filter((l) => !l.exposed).map((l) => l.key);
  return { fresh: dedupeByKey(fresh), baseline: { ...baseline, known: [...new Set([...baseline.known, ...quietlyKnown])] } };
}

function dedupeByKey(listeners: Listener[]): Listener[] {
  const seen = new Map<string, Listener>();
  for (const l of listeners) if (!seen.has(l.key)) seen.set(l.key, l);
  return [...seen.values()];
}

export function trust(baseline: ListenerBaseline, key: string): ListenerBaseline {
  return { ...baseline, known: [...new Set([...baseline.known, key])] };
}

export function setBlocked(baseline: ListenerBaseline, port: number, blocked: boolean): ListenerBaseline {
  const ports = new Set(baseline.blockedPorts);
  if (blocked) ports.add(port);
  else ports.delete(port);
  return { ...baseline, blockedPorts: [...ports].sort((a, b) => a - b) };
}

export function validPort(port: unknown): port is number {
  return typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535;
}

// --- Block rules ---------------------------------------------------------------------

export const NFT_TABLE = "qalaa_ports";
export const PF_ANCHOR = "com.apple/250.QalaaPorts";
export const NETSH_PREFIX = "Qalaa block port ";

/**
 * The whole Linux ruleset for the ports Qalaa blocks, applied with `nft -f -`.
 * Rebuilt from the list each time, so blocking and unblocking are the same
 * operation and nothing is left behind. An empty list removes the table.
 */
export function nftRuleset(ports: number[]): string {
  const lines = [`table inet ${NFT_TABLE}`, `delete table inet ${NFT_TABLE}`];
  if (ports.length) {
    lines.push(
      `table inet ${NFT_TABLE} {`,
      `  set blocked { type inet_service; elements = { ${ports.join(", ")} } }`,
      "  chain input {",
      "    type filter hook input priority filter; policy accept;",
      '    iifname "lo" accept',
      "    tcp dport @blocked drop",
      "    udp dport @blocked drop",
      "  }",
      "}",
    );
  }
  return `${lines.join("\n")}\n`;
}

/** Windows: one inbound block rule per port (TCP and UDP), named so it can be removed. */
export function netshPortArgs(port: number, block: boolean): string[][] {
  const name = `name=${NETSH_PREFIX}${port}`;
  if (!block) return [["advfirewall", "firewall", "delete", "rule", name]];
  return ["TCP", "UDP"].map((protocol) => ["advfirewall", "firewall", "add", "rule", name, "dir=in", "action=block", `protocol=${protocol}`, `localport=${port}`, "enable=yes"]);
}

/**
 * macOS: rules for a pf anchor under com.apple/, which the stock pf.conf already
 * loads, so the system configuration is never edited. Empty list = no rules.
 */
export function pfAnchorRules(ports: number[]): string {
  if (!ports.length) return "";
  return `block drop in quick on ! lo0 proto { tcp udp } from any to any port { ${ports.join(" ")} }\n`;
}

/** Plain-language description of the change, shown before the system prompt. */
export function describeBlock(platform: NodeJS.Platform, port: number, block: boolean): string {
  const verb = block ? "Block" : "Allow again";
  const where = platform === "win32" ? "Windows Defender Firewall" : platform === "darwin" ? "the macOS packet filter (pf)" : "nftables";
  return `${verb} incoming connections from other machines to port ${port}, using ${where}. Connections from this computer itself are not affected.`;
}

export interface ElevatedCommand {
  command: string;
  args: string[];
}

/**
 * The single elevated command that applies `ports` (the full list after the
 * change). Linux: pkexec + nft; Windows: one UAC prompt running netsh for the
 * changed port; macOS: one administrator prompt loading the pf anchor.
 */
export function blockCommand(platform: NodeJS.Platform, ports: number[], changed: number, block: boolean): ElevatedCommand {
  if (platform === "win32") {
    const quote = (a: string) => (a.includes(" ") ? `"${a}"` : a);
    const script = netshPortArgs(changed, block)
      .map((args) => `netsh ${args.map(quote).join(" ")}`)
      .join(" && ");
    return {
      command: "powershell.exe",
      args: ["-NoProfile", "-NonInteractive", "-Command", `Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','${script.replace(/'/g, "''")}' -Verb RunAs -Wait -WindowStyle Hidden`],
    };
  }
  if (platform === "darwin") {
    const rules = pfAnchorRules(ports).trim();
    const shell = rules ? `echo '${rules}' | /sbin/pfctl -a ${PF_ANCHOR} -f - && /sbin/pfctl -E` : `/sbin/pfctl -a ${PF_ANCHOR} -F rules`;
    return { command: "osascript", args: ["-e", `do shell script "${shell}" with administrator privileges`] };
  }
  return { command: "pkexec", args: ["sh", "-c", `nft -f - <<'QALAA'\n${nftRuleset(ports)}QALAA`] };
}
