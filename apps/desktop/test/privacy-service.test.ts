import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { type PrivacyDeps, PrivacyService } from "../src/core/privacy-service";
import type { BlockState, Device } from "../src/engine/privacy-block";
import { type DeviceUse, newUses } from "../src/engine/security";

function fakes(overrides: Partial<PrivacyDeps> = {}) {
  const state: Record<Device, BlockState> = { camera: "allowed", microphone: "allowed" };
  let uses: DeviceUse[] = [];
  let watch = true;
  const calls: string[] = [];
  const events: unknown[] = [];
  const deps: PrivacyDeps = {
    platform: "linux",
    locks: {
      supported: () => true,
      state: async (d) => state[d],
      set: async (d, block) => {
        calls.push(`pkexec ${d} ${block}`);
        state[d] = block ? "blocked" : "allowed";
      },
    },
    deviceUse: async () => ({ uses }),
    newUses: (before, now) => newUses(before, now),
    watchOn: () => watch,
    saveWatch: async (on) => {
      watch = on;
    },
    clipboard: () => ({ supported: true, enabled: true, ttlSeconds: 30, armed: { kind: "api_token", expiresAt: "2026-11-25T12:00:30.000Z", remainingMs: 21000 } }),
    serverUrl: () => "https://qalaa.example.org",
    emit: (_e, p) => events.push(p),
    now: () => Date.parse("2026-11-25T12:00:00Z"),
    ...overrides,
  };
  return { svc: new PrivacyService(deps), calls, events, setUses: (u: DeviceUse[]) => (uses = u) };
}

describe("privacy service", () => {
  it("blocks and allows the camera and microphone, with the password prompt", async () => {
    const { svc, calls } = fakes();
    expect((await svc.status()).locks).toEqual({ supported: true, camera: "allowed", microphone: "allowed" });
    const status = await svc.setLock({ device: "camera", block: true });
    expect(status.locks.camera).toBe("blocked");
    expect(calls).toEqual(["pkexec camera true"]);
    await expect(svc.setLock({ device: "speaker", block: true })).rejects.toMatchObject({ code: "bad_params" });
    await expect(svc.setLock({ device: "camera", block: "yes" })).rejects.toMatchObject({ code: "bad_params" });
  });

  it("a declined password prompt or failed lock says so and changes nothing", async () => {
    const { svc } = fakes({
      locks: {
        supported: () => true,
        state: async () => "allowed",
        set: async () => {
          throw new Error("Request dismissed");
        },
      },
    });
    await expect(svc.setLock({ device: "microphone", block: true })).rejects.toMatchObject({ code: "failed", message: "Request dismissed" });
    expect((await svc.status()).locks.microphone).toBe("allowed");
  });

  it("macOS: locks and the use watch are unavailable, and say so", async () => {
    const { svc } = fakes({ platform: "darwin", locks: { supported: () => false, state: async () => "unsupported", set: async () => {} } });
    const status = await svc.status();
    expect(status.locks).toEqual({ supported: false, camera: "unsupported", microphone: "unsupported" });
    expect(status.watch).toEqual({ on: false, supported: false });
    await expect(svc.setLock({ device: "camera", block: true })).rejects.toMatchObject({ code: "unavailable" });
    await expect(svc.setWatch({ on: true })).rejects.toMatchObject({ code: "unavailable" });
  });

  it("a program that starts using the camera is an alert and goes in the log once", async () => {
    const { svc, events, setUses } = fakes();
    setUses([{ device: "camera", app: "zoom" }]);
    expect(await svc.checkUse()).toEqual([{ device: "camera", app: "zoom" }]);
    expect(await svc.checkUse()).toEqual([]); // still on: not news
    const status = await svc.status();
    expect(status.inUse).toEqual([{ device: "camera", app: "zoom" }]);
    expect(status.log).toEqual([{ at: "2026-11-25T12:00:00.000Z", device: "camera", app: "zoom" }]);
    expect(events).toEqual([{ kind: "device_use", device: "camera", app: "zoom" }]);
    svc.stop();
  });

  it("web dashboard links only over https", async () => {
    expect((await fakes().svc.status()).web).toEqual({
      vault: "https://qalaa.example.org/dashboard/passwords",
      aliases: "https://qalaa.example.org/dashboard/privacy",
      brokers: "https://qalaa.example.org/dashboard/privacy",
    });
    expect((await fakes({ serverUrl: () => "http://localhost:8080" }).svc.status()).web).toBeNull();
    expect((await fakes({ serverUrl: () => "not a url" }).svc.status()).web).toBeNull();
  });

  it("carries the clipboard countdown for the hub", async () => {
    expect((await fakes().svc.status()).clipboard?.armed?.remainingMs).toBe(21000);
  });
});

/** The same file is decoded by the Rust client's tests (apps/desktop-native/crates/qalaa-ipc). */
const PRIVACY_FIXTURE = join(__dirname, "../../desktop-native/crates/qalaa-ipc/tests/fixtures/privacy.json");

it("privacy replies match the fixture the Rust client decodes", async () => {
  const { svc, setUses } = fakes();
  await svc.setLock({ device: "microphone", block: true });
  setUses([{ device: "camera", app: "zoom" }]);
  await svc.checkUse();
  svc.stop();
  const fixture = { status: await svc.status() };
  if (process.env.UPDATE_FIXTURES) await writeFile(PRIVACY_FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  expect(JSON.parse(await readFile(PRIVACY_FIXTURE, "utf8"))).toEqual(JSON.parse(JSON.stringify(fixture)));
});
