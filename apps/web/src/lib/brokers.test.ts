import { readFileSync } from "node:fs";
import { join } from "node:path";

import { CATALOG, cleanProgress, letterFor, loadProgress, mark, rows, safeOptOutUrl, saveProgress, STORAGE_KEY } from "./brokers";

const DAY = 86_400_000;
const T0 = Date.parse("2026-11-25T10:00:00Z");

describe("data-broker checklist", () => {
  it("ships the same catalog as the desktop app", () => {
    const desktop = readFileSync(join(__dirname, "../../../desktop/src/core/data/brokers.json"), "utf8");
    expect(CATALOG).toEqual(JSON.parse(desktop));
  });

  it("links only to https opt-out pages on each company's own site", () => {
    for (const b of CATALOG.brokers) expect(safeOptOutUrl(b), b.id).not.toBeNull();
    const b = CATALOG.brokers[0]!;
    expect(safeOptOutUrl({ ...b, optOutUrl: "http://www.spokeo.com/optout" })).toBeNull();
    expect(safeOptOutUrl({ ...b, optOutUrl: "https://spokeo.com.evil.example/optout" })).toBeNull();
    expect(safeOptOutUrl({ ...b, optOutUrl: "javascript:alert(1)" })).toBeNull();
  });

  it("tracks progress, expected removal and the 90-day re-check", () => {
    let progress = mark({}, "spokeo", "requested", T0);
    progress = mark(progress, "radaris", "not_listed", T0);
    let view = rows(progress, T0 + DAY);
    const spokeo = view.rows.find((r) => r.id === "spokeo")!;
    expect(spokeo.state).toBe("requested");
    expect(spokeo.expectedBy).toBe(new Date(T0 + 3 * DAY).toISOString());
    expect(view.done).toBe(2);
    expect(view.recheckDue).toBe(0);

    view = rows(progress, T0 + 90 * DAY);
    expect(view.recheckDue).toBe(1); // a request comes due; "not listed" doesn't
    expect(view.done).toBe(1);

    progress = mark(progress, "spokeo", "requested", T0 + 90 * DAY); // re-checked: clock restarts
    expect(rows(progress, T0 + 91 * DAY).recheckDue).toBe(0);
    expect(mark(progress, "spokeo", "todo", T0)).not.toHaveProperty("spokeo");
  });

  it("drops stored progress it doesn't recognise", () => {
    expect(
      cleanProgress({
        spokeo: { state: "removed", at: "2026-11-01T00:00:00Z" },
        unknown: { state: "removed", at: "2026-11-01T00:00:00Z" },
        radaris: { state: "hacked", at: "2026-11-01T00:00:00Z" },
        acxiom: { state: "requested", at: "not a date" },
      }),
    ).toEqual({ spokeo: { state: "removed", at: "2026-11-01T00:00:00Z" } });
    expect(cleanProgress("nonsense")).toEqual({});
  });

  it("keeps progress in this browser and survives blocked storage", () => {
    window.localStorage.removeItem(STORAGE_KEY);
    expect(loadProgress()).toEqual({});
    expect(saveProgress({ spokeo: { state: "removed", at: "2026-11-01T00:00:00Z" } })).toBe(true);
    expect(loadProgress()).toHaveProperty("spokeo.state", "removed");
    const spy = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(saveProgress({})).toBe(false);
    spy.mockRestore();
    window.localStorage.setItem(STORAGE_KEY, "{not json");
    expect(loadProgress()).toEqual({});
  });

  it("fills the request letter only with a name and a valid email", () => {
    const acxiom = CATALOG.brokers.find((b) => b.id === "acxiom")!;
    expect(letterFor(acxiom, "", "a@example.com")).toBeNull();
    expect(letterFor(acxiom, "Sara", "not-an-email")).toBeNull();
    const letter = letterFor(acxiom, " Sara Ali ", "sara@example.com")!;
    expect(letter.subject).toContain("Article 17");
    expect(letter.body).toContain("Hello Acxiom");
    expect(letter.body).toContain("Name: Sara Ali");
    expect(letter.body).not.toMatch(/\{(name|email|broker)\}/);
    // Companies without their own template get the GCC personal-data-law letter.
    const spokeo = CATALOG.brokers.find((b) => b.id === "spokeo")!;
    expect(letterFor(spokeo, "Sara", "sara@example.com")!.body).toContain("Decree-Law No. 45 of 2021");
  });
});
