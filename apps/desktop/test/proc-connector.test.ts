import { execFile, spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { BehaviourService } from "../src/core/behaviour-service";
import { capabilityFor } from "../src/engine/process-feed";
import { ConnectorServer, helperUnit, installHelperCommand, parseHelperLine, uninstallHelperCommand } from "../src/engine/proc-connector";

const HELPER = resolve(__dirname, "../resources/qalaa-procwatchd.py");

describe("process connector helper", () => {
  it("passes its own self-test (netlink parsing, /proc reading)", async () => {
    const out = await new Promise<string>((res, rej) => execFile("python3", [HELPER, "--selftest"], (e, so) => (e ? rej(e) : res(String(so)))));
    expect(out).toContain("selftest ok");
  });

  it("accepts only well-formed lines", () => {
    expect(parseHelperLine('{"pid":5,"ppid":1,"image":"/bin/sh","commandLine":"sh -c x","parentImage":"/bin/bash","parentCommandLine":"bash"}', 7)).toEqual({ pid: 5, ppid: 1, image: "/bin/sh", commandLine: "sh -c x", parentImage: "/bin/bash", parentCommandLine: "bash", at: 7 });
    for (const bad of ["", "nope", '{"pid":-1,"commandLine":"x"}', '{"pid":5}', '{"pid":"5x","commandLine":"x"}', "x".repeat(20_000)]) expect(parseHelperLine(bad, 0)).toBeNull();
  });

  it("feeds helper events to the rules and switches the capability while connected", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-proc-"));
    const alerts: unknown[] = [];
    const behaviour = new BehaviourService({ platform: "linux", emit: (_e, p) => alerts.push(p), rows: async () => [], selfPid: 99999 });
    let connected = false;
    const server = new ConnectorServer(join(dir, "proc.sock"), (e) => void behaviour.check(e), (c) => { connected = c; behaviour.setConnector(c); });
    await server.start();
    const client = createConnection(join(dir, "proc.sock"));
    await new Promise((r) => client.once("connect", r));
    client.write('{"pid":77,"ppid":1,"image":"/usr/sbin/ufw","commandLine":"ufw disable","parentImage":"/usr/bin/sudo","parentCommandLine":"sudo ufw disable"}\nnot json\n');
    await new Promise((r) => setTimeout(r, 100));
    expect(connected).toBe(true);
    expect(behaviour.capability()).toMatchObject({ source: "proc_connector", seesShortLived: true });
    expect(alerts).toEqual([expect.objectContaining({ rule: "firewall_disabled", pid: 77, parent: "sudo" })]);
    expect(await behaviour.poll()).toEqual([]); // polling pauses while the helper reports
    client.end();
    await new Promise((r) => setTimeout(r, 100));
    expect(behaviour.capability().source).toBe("proc_poll");
    await server.stop();
  });

  it("installs with one readable pkexec script and a hardened unit", () => {
    const install = installHelperCommand("/opt/Qalaa/resources/app.asar.unpacked/dist/procwatchd.py", "/home/a/.config/qalaa/proc.sock");
    expect(install.command).toBe("pkexec");
    expect(install.args[2]).toContain("systemctl enable --now qalaa-procwatch.service");
    expect(helperUnit("/home/a/.config/qalaa/proc.sock")).toMatch(/NoNewPrivileges=yes[\s\S]*ProtectSystem=strict/);
    expect(() => installHelperCommand("/opt/x'; rm -rf / #", "/s")).toThrow(/Unexpected characters/);
    expect(uninstallHelperCommand().args[2]).toContain("disable --now qalaa-procwatch.service");
    expect(capabilityFor("darwin", true).source).toBe("ps_poll"); // the connector is Linux-only
  });

  it("refuses the helper off Linux and reports install failures plainly", async () => {
    const mac = new BehaviourService({ platform: "darwin", emit: () => {}, rows: async () => [], helper: async () => {} });
    await expect(mac.helper(true)).rejects.toThrow(/only for Linux/);
    const failing = new BehaviourService({ platform: "linux", emit: () => {}, rows: async () => [], helper: async () => Promise.reject(new Error("Not authorized")) });
    await expect(failing.helper(true)).rejects.toThrow(/could not be installed: Not authorized/);
  });

  it.runIf(process.platform === "linux" && process.getuid?.() === 0)("as root, the real helper reports a program that runs for milliseconds", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-proc-root-"));
    const seen: string[] = [];
    const server = new ConnectorServer(join(dir, "proc.sock"), (e) => void seen.push(e.commandLine));
    await server.start();
    const helper = spawn("python3", [HELPER, "--socket", join(dir, "proc.sock")], { stdio: "ignore" });
    try {
      await new Promise((r) => setTimeout(r, 800));
      for (let i = 0; i < 20 && !seen.some((c) => c.includes("qalaa-short-marker")); i++) {
        await new Promise((r) => execFile("sh", ["-c", "true qalaa-short-marker"], r));
        await new Promise((r) => setTimeout(r, 100));
      }
      expect(seen.some((c) => c.includes("qalaa-short-marker"))).toBe(true);
    } finally {
      helper.kill();
      await server.stop();
    }
  });
});
