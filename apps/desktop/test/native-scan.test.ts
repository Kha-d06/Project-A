import { existsSync } from "node:fs";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { findNativeScanner, nativeFindings, nativeScan, parseReport, scanArgs, type NativeReport } from "../src/engine/native-scan";
import { scanFile } from "../src/engine/scanner";
import { SignatureStore } from "../src/engine/signatures";

const report = (over: Partial<NativeReport> = {}): NativeReport => ({
  version: 1, size: 10, sha256: "a".repeat(64), format: "pe", bundle_version: "2026.11.25.1",
  signatures: [], model: null, indicators: [], limitations: [], verdict: "no_findings", ...over,
});

async function fakeScanner(body: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-fake-scan-"));
  const path = join(dir, "qalaa-scan");
  await writeFile(path, `#!/bin/sh\n${body}\n`);
  await chmod(path, 0o755);
  return path;
}

describe("qalaa-scan bridge", () => {
  it("turns rule matches and the model into findings, never more than suspicious for the model", () => {
    const f = nativeFindings(report({
      signatures: [
        { rule: "MAL_Emotet", namespace: "qalaa", level: "malicious", description: "Emotet loader" },
        { rule: "SUSP_Encoded_PS", namespace: "qalaa", level: "suspicious" },
        { rule: "INFO_Url", namespace: "qalaa", level: "info" },
      ],
      model: { name: "m", score: 0.97, threshold: 0.9, suspicious: true, fpr: 0.01 },
    }));
    expect(f.map((x) => [x.rule, x.severity])).toEqual([["yara_malicious", "critical"], ["yara_suspicious", "high"], ["ml_suspicious", "medium"]]);
    expect(f[0]!.detail).toContain("Emotet loader");
    expect(f[2]!.detail).toContain("1.0%");
    expect(JSON.stringify(f)).not.toMatch(/\bsafe\b|100%|guarantee/i);
    expect(nativeFindings(report({ model: { name: "m", score: 0.2, threshold: 0.9, suspicious: false, fpr: null } }))).toEqual([]);
  });

  it("passes the bundle and the caps, and ends options before the path", () => {
    expect(scanArgs({ binary: "x", bundleDir: "/b" }, "-rf")).toEqual(["scan", "--bundle", "/b", "--max-mb", "128", "--memory-mb", "1024", "--cpu-seconds", "30", "--", "-rf"]);
    expect(scanArgs({ binary: "x", bundleDir: null }, "/f")).not.toContain("--bundle");
  });

  it("refuses odd output", () => {
    expect(() => parseReport("")).toThrow(/no report/);
    expect(() => parseReport('{"error":"not a regular file"}')).toThrow(/could not read/);
    expect(() => parseReport('{"version":9}')).toThrow(/unexpected/);
  });

  it("finds the binary from an override, beside the app, or on PATH", async () => {
    const exists = async (p: string) => p === "/opt/q/qalaa-scan" || p === "/env/qalaa-scan";
    expect(await findNativeScanner({ QALAA_SCAN_BINARY: "/env/qalaa-scan" }, "/opt/q/node", exists)).toBe("/env/qalaa-scan");
    expect(await findNativeScanner({}, "/opt/q/node", exists)).toBe("/opt/q/qalaa-scan");
    expect(await findNativeScanner({ PATH: "/nope" }, "/x/node", exists)).toBeNull();
  });

  it.runIf(process.platform !== "win32")("stops a scanner that hangs", async () => {
    const binary = await fakeScanner("sleep 30");
    await expect(nativeScan({ binary, bundleDir: null }, "/etc/hostname", 300)).rejects.toThrow(/too long/);
  });

  it.runIf(process.platform !== "win32")("feeds its verdict into a normal scan", async () => {
    const out = JSON.stringify(report({ signatures: [{ rule: "MAL_Test", namespace: "q", level: "malicious" }], verdict: "known_malicious" }));
    const binary = await fakeScanner(`echo '${out}'`);
    const dir = await mkdtemp(join(tmpdir(), "qalaa-native-"));
    const file = join(dir, "x.bin");
    await writeFile(file, "harmless");
    const result = await scanFile(file, { signatures: new SignatureStore(join(dir, "sigs.json")), nativeScanner: { binary, bundleDir: null } });
    expect(result.engines).toContain("qalaa-scan");
    expect(result.verdict).toBe("malicious");
    const broken = await scanFile(file, { signatures: new SignatureStore(join(dir, "sigs.json")), nativeScanner: { binary: await fakeScanner("exit 3"), bundleDir: null } });
    expect(broken.findings.some((f) => f.rule === "native_scan_failed")).toBe(true);
    expect(broken.verdict).not.toBe("not_scanned");
  });

  const built = resolve(__dirname, "../../desktop-native/target/debug/qalaa-scan");
  it.runIf(existsSync(built))("runs the real qalaa-scan binary", async () => {
    const dir = await mkdtemp(join(tmpdir(), "qalaa-native-real-"));
    const file = join(dir, "a.txt");
    await writeFile(file, "hello");
    const r = await nativeScan({ binary: built, bundleDir: null }, file);
    expect(r.verdict).toBe("no_findings");
    expect(r.limitations.join(" ")).toMatch(/No rule bundle/);
  });
});
