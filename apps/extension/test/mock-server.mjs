/** A stand-in SENTINEL API for the extension's end-to-end tests. */
import { createServer } from "node:http";

export function startMockServer(port, { verdicts = {}, blocklist = [], assistant = null, family = null } = {}) {
  const seen = { checks: [], assistantContexts: [] };
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    const json = body ? JSON.parse(body) : {};
    const reply = (status, payload) => {
      response.writeHead(status, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      response.end(JSON.stringify(payload));
    };
    const path = new URL(request.url, "http://x").pathname;
    if (path === "/api/v1/extension/enroll") return reply(201, { installation_id: "00000000-0000-0000-0000-000000000001", refresh_token: "r", access_token: "a", expires_in: 900, linked: false });
    if (path === "/api/v1/extension/token") return reply(200, { access_token: "a", expires_in: 900 });
    if (path === "/api/v1/extension/settings") {
      const linked = Boolean(family);
      return reply(200, {
        installation_id: "00000000-0000-0000-0000-000000000001",
        linked,
        account_email: linked ? "child@example.com" : null,
        sync_events: false,
        family_blocklist: family?.domains ?? [],
        family_groups: family?.groups ?? [],
      });
    }
    if (path === "/api/v1/extension/blocklist") return reply(200, { version: `${blocklist.length}-x`, generated_at: new Date().toISOString(), hosts: blocklist, sources: ["Mock feed"] });
    if (path === "/api/v1/extension/check-url") {
      const host = new URL(json.url).hostname;
      seen.checks.push(host);
      const verdict = verdicts[host] ?? "no_known_threat";
      const reasons = verdict === "no_known_threat" ? [] : [{ severity: "high", title: `Mock warning for ${host}`, explanation: "Test reason.", source: "Mock" }];
      return reply(200, { verdict, host, reasons, sources: ["Mock"], limitations: [], checked_at: new Date().toISOString(), cache_seconds: 60 });
    }
    if (path === "/api/v1/extension/assistant") {
      seen.assistantContexts.push(json);
      if (!assistant) return reply(503, { error: { code: "assistant_unavailable", message: "Not configured." } });
      return reply(200, { answer: assistant, ai_generated: true, model: "mock" });
    }
    return reply(404, { error: { code: "not_found", message: "Not found" } });
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve({ server, seen })));
}
