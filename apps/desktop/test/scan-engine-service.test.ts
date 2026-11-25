import { describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { ScanEngineService } from "../src/core/scan-engine-service";

const deps = (over: Partial<ConstructorParameters<typeof ScanEngineService>[0]> = {}) => ({
  root: "/nonexistent/qalaa-scan-bundle",
  binary: "/opt/qalaa-scan",
  baseUrl: () => "https://server.example/api/v1/updates/scan-bundle/",
  keys: async () => ["a".repeat(64)],
  verify: async () => true,
  now: () => new Date("2026-11-25T10:00:00Z"),
  ...over,
});

describe("scan engine service", () => {
  it("says plainly what is missing", async () => {
    const none = new ScanEngineService(deps({ binary: null }));
    await none.load();
    expect(none.scanner()).toBeNull();
    expect(none.status().note).toMatch(/isn't installed/);

    const unsigned = new ScanEngineService(deps({ keys: async () => [] }));
    await unsigned.load();
    expect(unsigned.status().note).toMatch(/no rule-signing key/);
    expect(unsigned.scanner()).toEqual({ binary: "/opt/qalaa-scan", bundleDir: null });
  });

  it("uses the bundle only after an update the scanner verified", async () => {
    const s = new ScanEngineService(deps({ update: async () => ({ updated: true, version: "2026.11.25.1", downloaded: ["rules/a.yar"], reused: [] }) }));
    await s.load();
    expect(s.scanner()?.bundleDir).toBeNull();
    expect(s.status().note).toMatch(/No verified rule set yet/);
    await s.update();
    expect(s.scanner()?.bundleDir).toBe("/nonexistent/qalaa-scan-bundle/current");
    expect(s.status()).toMatchObject({ bundleVersion: "2026.11.25.1", note: null, lastUpdate: { at: "2026-11-25T10:00:00.000Z" } });
  });

  it("keeps working when the server can't be reached, and answers over IPC", async () => {
    const s = new ScanEngineService(deps({ update: async () => Promise.reject(new Error("ECONNREFUSED")) }));
    await s.load();
    const handlers = createHandlers({ version: "t", homeInput: async () => ({}) as never, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {}, scanEngine: s }, () => {});
    const r = (await handlers["scanengine.update"]!(undefined)) as { result: { reason: string } };
    expect(r.result.reason).toMatch(/Couldn't reach.*current rules stay/);
    expect(await handlers["scanengine.get"]!(undefined)).toMatchObject({ available: true, signedUpdates: true });
  });
});
