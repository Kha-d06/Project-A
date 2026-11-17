import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it } from "vitest";

import { type RansomwareAlert, RansomwareMonitor } from "../src/engine/ransomware";

it("raises an alert when files in a watched folder are renamed by ransomware", async () => {
  const dir = await mkdtemp(join(tmpdir(), "sentinel-ransom-"));
  const alerts: RansomwareAlert[] = [];
  const monitor = new RansomwareMonitor((alert) => alerts.push(alert));
  monitor.set([dir]);
  await new Promise((resolve) => setTimeout(resolve, 100));
  for (let i = 0; i < 9; i += 1) await writeFile(join(dir, `invoice-${i}.docx.lockbit`), Buffer.alloc(2048, i));
  await new Promise((resolve) => setTimeout(resolve, 800));
  monitor.close();
  expect(alerts).toHaveLength(1);
});
