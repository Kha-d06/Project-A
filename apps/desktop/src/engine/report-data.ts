/** Gathers the facts for each report from this computer's own readings. */
import os from "node:os";

import * as explorer from "./explorer";
import type { IntegrityStore } from "./integrity";
import type { Sampler } from "./monitor";
import { interfaces } from "./nettools";
import type { Posture } from "./posture";
import type { Report, ReportKind, ReportSection } from "./reports";
import { storage } from "./storage";
import type { HistoryPoint, SecurityEvent } from "./telemetry";

interface Inputs {
  posture: Posture;
  integrity: IntegrityStore;
  security: {
    firewall: { state: string; detail: string | null };
    encryption: { state: string; detail: string | null };
    ports: { port: number; address: string; process: string | null; exposed: boolean; risk: string | null }[] | null;
    startup: { name: string; command: string; location: string; warnings: string[] }[];
  };
  sampler: Sampler;
  history: HistoryPoint[];
  events: SecurityEvent[];
}

const gb = (bytes: number | null | undefined) => (bytes ? `${(bytes / 1e9).toFixed(1)} GB` : "—");
const rate = (bytes: number | null | undefined) => (bytes === null || bytes === undefined ? "—" : `${(bytes / 1e6).toFixed(2)} MB/s`);

function computerFacts(): [string, string][] {
  const cpus = os.cpus();
  return [
    ["Computer name", os.hostname()],
    ["Operating system", `${os.type()} ${os.release()} (${os.arch()})`],
    ["Processor", `${cpus[0]?.model.trim() ?? "—"} · ${cpus.length} logical cores`],
    ["Memory", gb(os.totalmem())],
    ["Up for", `${Math.round(os.uptime() / 3600)} h`],
  ];
}

export async function buildReport(kind: ReportKind, input: Inputs): Promise<Report> {
  const sections: ReportSection[] = [];
  const titles: Record<ReportKind, string> = { inventory: "Hardware inventory", security: "Security audit", performance: "Performance snapshot" };

  if (kind === "inventory") {
    const [disks, nics, snapshot] = await Promise.all([storage(), interfaces(), input.sampler.sample(true)]);
    sections.push({ title: "Computer", facts: computerFacts() });
    sections.push({ title: "Graphics", table: { columns: ["GPU", "Memory"], rows: snapshot.gpus.length ? snapshot.gpus.map((g) => [g.name, g.memoryTotal ? gb(g.memoryTotal) : "—"]) : [["Not reported by this system", null]] } });
    sections.push({ title: "Disks", table: { columns: ["Disk", "Model", "Type", "Size", "Health"], rows: (disks?.disks ?? []).map((d) => [d.name, d.model, d.kind.toUpperCase(), gb(d.sizeBytes), d.healthDetail ?? d.health]) } });
    sections.push({ title: "Volumes", table: { columns: ["Mount", "File system", "Size", "Used"], rows: (disks?.volumes ?? []).map((v) => [v.mount, v.fileSystem, gb(v.sizeBytes), gb(v.usedBytes)]) } });
    sections.push({ title: "Network interfaces", table: { columns: ["Interface", "Addresses", "MAC"], rows: nics.map((n) => [n.name, n.addresses.join(", "), n.mac]) } });
  }

  if (kind === "security") {
    const p = input.posture;
    sections.push({ title: "Summary", facts: [...computerFacts().slice(0, 2), ["Security posture score", p.score === null ? "Not enough information" : `${p.score} / 100`], ["Checked", p.checkedAt]] });
    sections.push({ title: "Hardening checks", table: { columns: ["Check", "Result", "Detail", "How to fix"], rows: p.checks.map((c) => [c.title, c.status.toUpperCase(), c.detail, c.status === "pass" ? null : c.fix]) } });
    const exposed = (input.security.ports ?? []).filter((port) => port.exposed);
    sections.push({ title: "Programs reachable from the network", table: { columns: ["Port", "Address", "Program", "Risk"], rows: exposed.length ? exposed.map((port) => [port.port, port.address, port.process, port.risk]) : [["None", null, null, null]] } });
    const flagged = input.security.startup.filter((item) => item.warnings.length);
    sections.push({ title: "Suspicious start-up entries", table: { columns: ["Name", "Command", "Why"], rows: flagged.length ? flagged.map((item) => [item.name, item.command, item.warnings.join("; ")]) : [["None", null, null]] } });
    sections.push({
      title: "File integrity",
      facts: [["Files watched", String(input.integrity.paths.length)], ["Unacknowledged changes", String(input.integrity.changes.length)], ["Last check", input.integrity.lastCheck ?? "—"]],
      table: input.integrity.changes.length ? { columns: ["File", "Change", "When"], rows: input.integrity.changes.map((c) => [c.path, c.kind, c.at]) } : undefined,
    });
    sections.push({ title: "Recent security events", table: { columns: ["Time", "Level", "Kind", "Event"], rows: input.events.slice(0, 50).map((e) => [e.at, e.level, e.kind, e.message]) } });
  }

  if (kind === "performance") {
    await input.sampler.sample(false);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const s = await input.sampler.sample(true);
    sections.push({
      title: "Right now",
      facts: [
        ["Processor", `${s.cpu.total}% (${s.cpu.cores.length} cores)${s.cpu.temperature !== null ? ` · ${s.cpu.temperature} °C` : ""}`],
        ["Memory", `${gb(s.memory.used)} of ${gb(s.memory.total)}`],
        ["Disk", s.disk ? `read ${rate(s.disk.readPerSec)}, write ${rate(s.disk.writePerSec)}, ${s.disk.iops} operations/s` : "—"],
        ["Network", s.network ? `down ${rate(s.network.rxPerSec)}, up ${rate(s.network.txPerSec)}` : "—"],
        ["Load average", s.load ? s.load.join(" / ") : "—"],
      ],
    });
    if (input.history.length) {
      const avg = (f: (p: HistoryPoint) => number) => input.history.reduce((sum, p) => sum + f(p), 0) / input.history.length;
      const max = (f: (p: HistoryPoint) => number) => Math.max(...input.history.map(f));
      sections.push({
        title: "Last 24 hours",
        facts: [
          ["Processor (average / peak)", `${avg((p) => p.cpu).toFixed(1)}% / ${max((p) => p.cpu).toFixed(1)}%`],
          ["Memory (average / peak)", `${avg((p) => p.memory).toFixed(1)}% / ${max((p) => p.memory).toFixed(1)}%`],
          ["Network down (average)", rate(avg((p) => p.rx))],
        ],
      });
    }
    const processes = ((await explorer.processDetails()) ?? []).sort((a, b) => (b.memoryBytes ?? 0) - (a.memoryBytes ?? 0)).slice(0, 15);
    sections.push({ title: "Programs using the most memory", table: { columns: ["Program", "PID", "Memory", "Threads"], rows: processes.map((p) => [p.name, p.pid, gb(p.memoryBytes), p.threads]) } });
  }

  return { kind, title: titles[kind], generatedAt: new Date().toISOString(), computer: os.hostname(), sections };
}
