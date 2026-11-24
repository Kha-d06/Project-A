import { mkdtemp, rm } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  OnAccessServer,
  SERVICE_NAME,
  decide,
  encodeResponse,
  installScript,
  onAccessSupported,
  parseRequest,
  parseServiceState,
  uninstallScript,
  unitFile,
} from "../src/engine/fanotify";
import type { ScanResult } from "../src/engine/types";

function result(verdict: ScanResult["verdict"]): ScanResult {
  return { path: "/x", name: "x", size: 1, sha256: null, verdict, findings: [], engines: [], scannedAt: "now" };
}

describe("verdict logic", () => {
  it("blocks only known-malicious files", () => {
    expect(decide(result("malicious"))).toBe("deny");
    expect(decide(result("suspicious"))).toBe("allow");
    expect(decide(result("no_known_threat"))).toBe("allow");
    expect(decide(result("not_scanned"))).toBe("allow");
  });
});

describe("protocol", () => {
  it("parses well-formed requests and rejects the rest", () => {
    expect(parseRequest('{"id":5,"path":"/home/a/f"}')).toEqual({ id: 5, path: "/home/a/f" });
    expect(parseRequest('{"id":5,"path":"relative"}')).toBeNull(); // path must be absolute
    expect(parseRequest("{bad json")).toBeNull();
    expect(parseRequest('{"id":"x","path":"/a"}')).toBeNull();
  });

  it("encodes a newline-delimited response", () => {
    expect(encodeResponse({ id: 7, verdict: "deny", reason: "malicious" })).toBe('{"id":7,"verdict":"deny","reason":"malicious"}\n');
  });
});

describe("service state", () => {
  it("maps systemctl output", () => {
    expect(parseServiceState("active\n")).toBe("active");
    expect(parseServiceState("inactive")).toBe("inactive");
    expect(parseServiceState("failed")).toBe("failed");
    expect(parseServiceState("unknown")).toBe("absent");
    expect(parseServiceState("")).toBe("absent");
  });
});

describe("install scripts", () => {
  const params = { bundledHelper: "/opt/app/onaccessd.py", socketPath: "/run/qalaa/s.sock", markRoots: ["/home"], user: "alice" };

  it("builds a unit that runs the helper as a simple service", () => {
    const unit = unitFile("/usr/local/lib/qalaa/qalaa-onaccessd.py", params.socketPath, params.markRoots, params.user);
    expect(unit).toContain("ExecStart=/usr/bin/python3 /usr/local/lib/qalaa/qalaa-onaccessd.py --socket /run/qalaa/s.sock --user alice --mark /home");
    expect(unit).toContain("Restart=on-failure");
  });

  it("installs the helper, writes the unit, enables the service", () => {
    const script = installScript(params);
    expect(script).toContain("install -m 0755 '/opt/app/onaccessd.py' '/usr/local/lib/qalaa/qalaa-onaccessd.py'");
    expect(script).toContain(`systemctl enable --now ${SERVICE_NAME}`);
    expect(script).toContain("<<'QALAA_UNIT'"); // literal here-doc, no shell expansion
  });

  it("uninstall stops and removes the service", () => {
    const script = uninstallScript();
    expect(script).toContain(`systemctl disable --now ${SERVICE_NAME}`);
    expect(script).toContain("rm -f '/etc/systemd/system/qalaa-onaccess.service'");
  });

  it("is Linux-only", () => {
    expect(onAccessSupported("linux")).toBe(true);
    expect(onAccessSupported("win32")).toBe(false);
    expect(onAccessSupported("darwin")).toBe(false);
  });
});

describe("OnAccessServer round trip", () => {
  let dir: string;
  let server: OnAccessServer | null = null;

  afterEach(async () => {
    await server?.stop();
    server = null;
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  async function ask(socketPath: string, line: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const client = createConnection(socketPath, () => client.write(`${line}\n`));
      let buffer = "";
      client.on("data", (chunk) => {
        buffer += chunk.toString();
        if (buffer.includes("\n")) {
          client.end();
          resolve(buffer.trim());
        }
      });
      client.on("error", reject);
      setTimeout(() => reject(new Error("no reply")), 3000);
    });
  }

  it("denies a malicious file, allows a clean one, and honours exclusions", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-fan-"));
    const socketPath = join(dir, "s.sock");
    let blocked: string | null = null;
    server = new OnAccessServer({
      socketPath,
      scan: async (path) => result(path.includes("evil") ? "malicious" : "no_known_threat"),
      isExcluded: (path) => path.startsWith("/home/skip"),
      onBlocked: (path) => { blocked = path; },
    });
    await server.start();

    expect(await ask(socketPath, '{"id":1,"path":"/home/a/evil"}')).toBe('{"id":1,"verdict":"deny","reason":"malicious"}');
    expect(await ask(socketPath, '{"id":2,"path":"/home/a/good"}')).toBe('{"id":2,"verdict":"allow","reason":"no_known_threat"}');
    expect(await ask(socketPath, '{"id":3,"path":"/home/skip/x"}')).toBe('{"id":3,"verdict":"allow","reason":"excluded"}');
    expect(blocked).toBe("/home/a/evil");
  });

  it("tells the credential observer about every open without changing the verdict", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-fan-"));
    const socketPath = join(dir, "s.sock");
    const seen: [number, string][] = [];
    server = new OnAccessServer({
      socketPath,
      scan: async () => result("no_known_threat"),
      onOpen: (pid, path) => {
        seen.push([pid, path]);
        if (path.includes("boom")) throw new Error("observer bug");
      },
    });
    await server.start();
    expect(await ask(socketPath, '{"id":1,"path":"/home/a/.ssh/id_ed25519","pid":42}')).toBe('{"id":1,"verdict":"allow","reason":"no_known_threat"}');
    expect(await ask(socketPath, '{"id":2,"path":"/home/a/boom","pid":43}')).toBe('{"id":2,"verdict":"allow","reason":"no_known_threat"}');
    expect(seen).toEqual([[42, "/home/a/.ssh/id_ed25519"], [43, "/home/a/boom"]]);
  });

  it("denies and signals a halt when the behaviour hook trips", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-fan-"));
    const socketPath = join(dir, "s.sock");
    let halted: number | null = null;
    server = new OnAccessServer({
      socketPath,
      scan: async () => result("no_known_threat"),
      behaviour: { feed: (pid) => (pid === 666 ? { reason: "changed 40 files", files: 40 } : null) },
      onHalt: (pid) => { halted = pid; },
    });
    await server.start();
    const reply = await ask(socketPath, '{"id":1,"path":"/home/a/doc","pid":666}');
    expect(JSON.parse(reply)).toMatchObject({ id: 1, verdict: "deny", halt: true });
    expect(halted).toBe(666);
    // A different process is unaffected.
    expect(JSON.parse(await ask(socketPath, '{"id":2,"path":"/home/a/doc","pid":5}'))).toMatchObject({ verdict: "allow" });
  });

  it("fails open when the scan errors", async () => {
    dir = await mkdtemp(join(tmpdir(), "qalaa-fan-"));
    const socketPath = join(dir, "s.sock");
    server = new OnAccessServer({ socketPath, scan: async () => { throw new Error("boom"); } });
    await server.start();
    expect(await ask(socketPath, '{"id":9,"path":"/home/a/x"}')).toBe('{"id":9,"verdict":"allow","reason":"error"}');
  });
});
