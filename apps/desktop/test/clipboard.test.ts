import { describe, expect, it } from "vitest";

import { ClipboardService, type Clock } from "../src/core/clipboard-service";
import { createHandlers } from "../src/core/handlers";
import { classifySecret, entropy, systemClipboard } from "../src/engine/clipboard";

describe("recognising secrets", () => {
  it("flags keys, tokens and .env lines by shape", () => {
    expect(classifySecret("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----")).toBe("private_key");
    expect(classifySecret("-----BEGIN RSA PRIVATE KEY-----")).toBe("private_key");
    expect(classifySecret("AKIAIOSFODNN7EXAMPLE")).toBe("cloud_key");
    expect(classifySecret(`ghp_${"a1B2c3D4e5".repeat(4)}`)).toBe("api_token");
    expect(classifySecret("xoxb-1234567890-abcdefghij")).toBe("api_token");
    expect(classifySecret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")).toBe("jwt");
    expect(classifySecret("DATABASE_PASSWORD=hunter2hunter2")).toBe("env_secret");
    expect(classifySecret("export STRIPE_API_KEY=sk_test_abcdefgh")).toBe("env_secret");
    expect(classifySecret("Xk9#mQ2$vL8@pR4!nT6&wZ1")).toBe("high_entropy");
  });

  it("leaves ordinary text alone", () => {
    for (const text of ["Hello, see you at 5pm", "https://example.org/a/very/long/path/with/many/parts?q=12345", "DEBUG=true", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "the-quick-brown-fox-jumps-over", "", "PUBLIC KEY-----"]) {
      expect(classifySecret(text), text).toBeNull();
    }
    expect(entropy("aaaa")).toBe(0);
    expect(entropy("abcd")).toBe(2);
  });

  it("knows when no clipboard tool applies", () => {
    expect(systemClipboard("linux", {})).toBeNull();
    expect(systemClipboard("linux", { WAYLAND_DISPLAY: "wayland-0" })).not.toBeNull();
    expect(systemClipboard("darwin", {})).not.toBeNull();
  });
});

function fakes(initial = "") {
  let text: string | null = initial;
  const writes: string[] = [];
  let now = 1_000_000;
  const timers: { at: number; fn: () => void; id: number }[] = [];
  let next = 1;
  const clock: Clock = {
    now: () => now,
    setTimeout: (fn, ms) => {
      const id = next++;
      timers.push({ at: now + ms, fn, id });
      return id;
    },
    clearTimeout: (id) => {
      const i = timers.findIndex((t) => t.id === id);
      if (i >= 0) timers.splice(i, 1);
    },
  };
  const advance = async (ms: number) => {
    now += ms;
    for (const t of timers.filter((t) => t.at <= now)) {
      timers.splice(timers.indexOf(t), 1);
      t.fn();
    }
    await new Promise((r) => setTimeout(r, 0));
  };
  const io = {
    read: async () => text,
    clear: async () => void (text = ""),
    write: async (t: string) => void (writes.push(t), (text = t)),
  };
  return { io, clock, advance, set: (t: string) => (text = t), get: () => text, writes };
}

describe("clipboard service", () => {
  it("wipes a copied secret after the TTL, telling clients the kind but never the text", async () => {
    const f = fakes();
    const events: { event: string; payload: unknown }[] = [];
    const service = new ClipboardService(f.io, (event, payload) => events.push({ event, payload }), f.clock);
    f.set("DATABASE_PASSWORD=hunter2hunter2");
    await service.poll();
    expect(service.status().armed).toMatchObject({ kind: "env_secret", remainingMs: 30_000 });
    await f.advance(10_000);
    expect(service.status().armed?.remainingMs).toBe(20_000);
    await f.advance(20_000);
    expect(f.get()).toBe("");
    expect(service.status().armed).toBeNull();
    expect(events.map((e) => e.event)).toEqual(["clipboard.armed", "clipboard.cleared"]);
    expect(JSON.stringify(events)).not.toContain("hunter2");
  });

  it("never wipes something copied afterwards", async () => {
    const f = fakes();
    const service = new ClipboardService(f.io, () => {}, f.clock);
    f.set("AKIAIOSFODNN7EXAMPLE");
    await service.poll();
    f.set("shopping list: eggs, milk");
    await service.poll();
    expect(service.status().armed).toBeNull();
    await f.advance(60_000);
    expect(f.get()).toBe("shopping list: eggs, milk");
    // Even if the poll missed the change, expiry checks the hash first.
    f.set("AKIAIOSFODNN7EXAMPLE");
    await service.poll();
    f.set("something new");
    await f.advance(30_000);
    expect(f.get()).toBe("something new");
  });

  it("Qalaa's own copies are always cleared; Clear now works at once; off means off", async () => {
    const f = fakes();
    const service = new ClipboardService(f.io, () => {}, f.clock);
    service.configure({ ttlSeconds: 15 });
    const handlers = createHandlers({ version: "t", homeInput: async () => { throw new Error("unused"); }, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {}, clipboard: service }, () => {});
    const status = (await handlers["clipboard.copy_secret"]?.({ text: "482913" })) as ReturnType<ClipboardService["status"]>;
    expect(f.writes).toEqual(["482913"]);
    expect(status.armed).toMatchObject({ kind: "copied_from_qalaa", remainingMs: 15_000 });
    await handlers["clipboard.clear_now"]?.(undefined);
    expect(f.get()).toBe("");
    await expect(handlers["clipboard.copy_secret"]?.({ text: 5 })).rejects.toThrow(/Expected the text/);

    service.configure({ enabled: false });
    f.set("AKIAIOSFODNN7EXAMPLE");
    await service.poll();
    expect(service.status().armed).toBeNull();
  });

  it("says so when the clipboard can't be reached", async () => {
    const service = new ClipboardService(null, () => {});
    expect(service.status().supported).toBe(false);
    await service.poll();
    await expect(service.copySecret("x")).rejects.toThrow(/can't be reached/);
  });
});
