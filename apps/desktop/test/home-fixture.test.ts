import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";

import { type HomeInput, buildHome } from "../src/core/home";

/** The same file is decoded by the Rust client's tests (apps/desktop-native). */
const FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/home.json");

export const FIXTURE_INPUT: HomeInput = {
  now: new Date("2026-11-24T12:00:00Z"),
  platform: "linux",
  watchEnabled: false,
  onAccessScan: false,
  ransomwareWatch: true,
  networkWatch: false,
  cloudLookup: true,
  signatures: { count: 120_000, updatedAt: "2026-11-21T08:00:00Z", error: null },
  lastScanAt: "2026-11-23T12:00:00Z",
  lastNetworkScanAt: null,
  lastBackupAt: null,
  lastBackupError: null,
  backupConfigured: false,
  quarantineCount: 1,
  recentThreats: 1,
  ransomwareAlertAt: null,
  updateAvailable: "0.3.0",
  silentUntil: null,
};

it("the Home model matches the fixture the Rust client decodes", async () => {
  const model = buildHome(FIXTURE_INPUT);
  if (process.env.UPDATE_FIXTURES) await writeFile(FIXTURE, `${JSON.stringify(model, null, 2)}\n`);
  expect(JSON.parse(await readFile(FIXTURE, "utf8"))).toEqual(model);
});
