import { listAlerts, recordAlert } from "../src/lib/alerts";

describe("local alert list", () => {
  it("merges repeat visits to the same site and respects the setting", async () => {
    const at = (minutes: number) => new Date(Date.UTC(2026, 10, 16, 10, minutes)).toISOString();
    await recordAlert({ host: "bad.example", verdict: "dangerous", kind: "page", at: at(0) }, true);
    await recordAlert({ host: "bad.example", verdict: "dangerous", kind: "page", at: at(2) }, true);
    await recordAlert({ host: "other.example", verdict: "suspicious", kind: "page", at: at(3) }, true);
    await recordAlert({ host: "bad.example", verdict: "dangerous", kind: "page", at: at(30) }, true);
    await recordAlert({ host: "ignored.example", verdict: "dangerous", kind: "page", at: at(31) }, false);
    expect((await listAlerts()).map((a) => `${a.host}@${a.at.slice(14, 16)}`)).toEqual([
      "bad.example@30",
      "other.example@03",
      "bad.example@02",
    ]);
  });
});
