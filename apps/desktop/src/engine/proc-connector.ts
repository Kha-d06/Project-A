/**
 * The user-space half of the Linux process-start helper
 * (resources/qalaa-procwatchd.py, root, systemd): it listens on a local
 * socket for the helper's JSON lines and hands each program start to the
 * behaviour rules. With the helper connected every start is seen, however
 * short-lived; without it the service falls back to reading /proc.
 */
import { mkdir, rm, chmod } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { dirname } from "node:path";

import type { ProcessEvent } from "./behaviour-rules";
import type { ElevatedCommand } from "./listeners";

const MAX_LINE = 16 * 1024;

export function parseHelperLine(line: string, now: number): ProcessEvent | null {
  if (!line || line.length > MAX_LINE) return null;
  try {
    const v = JSON.parse(line) as Record<string, unknown>;
    const pid = Number(v.pid);
    const ppid = Number(v.ppid ?? 0);
    if (!Number.isInteger(pid) || pid <= 0 || !Number.isInteger(ppid) || ppid < 0) return null;
    const str = (x: unknown) => (typeof x === "string" ? x.slice(0, 4096) : "");
    const commandLine = str(v.commandLine);
    if (!commandLine) return null;
    return { pid, ppid, image: str(v.image), commandLine, parentImage: str(v.parentImage), parentCommandLine: str(v.parentCommandLine), at: now };
  } catch {
    return null;
  }
}

export class ConnectorServer {
  private server: Server | null = null;
  private clients = 0;

  constructor(
    private readonly socketPath: string,
    private readonly onEvent: (event: ProcessEvent) => void,
    private readonly onConnected: (connected: boolean) => void = () => {},
    private readonly now: () => number = Date.now,
  ) {}

  async start(): Promise<void> {
    await mkdir(dirname(this.socketPath), { recursive: true, mode: 0o700 }).catch(() => {});
    await rm(this.socketPath, { force: true }).catch(() => {});
    this.server = createServer((socket) => {
      this.clients++;
      this.onConnected(true);
      let buffer = "";
      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        if (buffer.length > MAX_LINE * 64) buffer = buffer.slice(-MAX_LINE); // a flood: keep the tail
        let i: number;
        while ((i = buffer.indexOf("\n")) >= 0) {
          const event = parseHelperLine(buffer.slice(0, i), this.now());
          buffer = buffer.slice(i + 1);
          if (event) {
            try {
              this.onEvent(event);
            } catch {
              // a rule error must never stop the stream
            }
          }
        }
      });
      socket.on("error", () => {});
      socket.on("close", () => {
        this.clients = Math.max(0, this.clients - 1);
        if (!this.clients) this.onConnected(false);
      });
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.socketPath, resolve);
    });
    // Only root (the helper) and this user can connect.
    await chmod(this.socketPath, 0o600).catch(() => {});
  }

  connected(): boolean {
    return this.clients > 0;
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(this.socketPath, { force: true }).catch(() => {});
  }
}

export const HELPER_SERVICE = "qalaa-procwatch.service";
const INSTALLED = "/usr/local/lib/qalaa/qalaa-procwatchd.py";
const UNIT = `/etc/systemd/system/${HELPER_SERVICE}`;

function quoteOk(value: string): string {
  if (!/^[A-Za-z0-9_./@-]+$/.test(value)) throw new Error("Unexpected characters in a helper path.");
  return value;
}

export function helperUnit(socketPath: string): string {
  return [
    "[Unit]",
    "Description=Qalaa program-start reports (netlink process connector)",
    "After=local-fs.target",
    "",
    "[Service]",
    "Type=simple",
    // Reports only: it never blocks or changes anything; events are dropped when Qalaa isn't running.
    `ExecStart=/usr/bin/python3 ${INSTALLED} --socket ${quoteOk(socketPath)}`,
    "Restart=on-failure",
    "RestartSec=5",
    "Nice=5",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "PrivateTmp=yes",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

/** The one pkexec command that installs and starts the helper; plain shell the person can read. */
export function installHelperCommand(bundledHelper: string, socketPath: string): ElevatedCommand {
  const script = [
    "set -e",
    "install -d -m 0755 /usr/local/lib/qalaa",
    `install -m 0755 '${quoteOk(bundledHelper)}' '${INSTALLED}'`,
    `cat > '${UNIT}' <<'QALAA_UNIT'\n${helperUnit(socketPath)}QALAA_UNIT`,
    "systemctl daemon-reload",
    `systemctl enable --now ${HELPER_SERVICE}`,
  ].join("\n");
  return { command: "pkexec", args: ["sh", "-c", script] };
}

export function uninstallHelperCommand(): ElevatedCommand {
  return { command: "pkexec", args: ["sh", "-c", `systemctl disable --now ${HELPER_SERVICE} 2>/dev/null || true\nrm -f '${UNIT}' '${INSTALLED}'\nsystemctl daemon-reload`] };
}
