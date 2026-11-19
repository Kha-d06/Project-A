import { describe, expect, it } from "vitest";
import { addMinute, blockReason, dayKey, inWindow, screenTimeBlockRule, shouldReport, usageFor } from "../src/lib/screentime";

const at = (h: number, m = 0) => new Date(2026, 10, 19, h, m);
const rule = { allowed_from: "08:00", allowed_until: "20:00", daily_minutes: 60 };

describe("screen time", () => {
  it("checks the allowed window", () => {
    expect(inWindow(rule, at(7, 59))).toBe(false);
    expect(inWindow(rule, at(8))).toBe(true);
    expect(inWindow(rule, at(19, 59))).toBe(true);
    expect(inWindow(rule, at(20))).toBe(false);
    expect(inWindow({ ...rule, allowed_from: null, allowed_until: null }, at(3))).toBe(true);
    // Two families whose windows never overlap leave no time at all.
    expect(inWindow({ ...rule, allowed_from: "18:00", allowed_until: "18:00" }, at(18))).toBe(false);
  });

  it("blocks once the daily limit is used, and starts again the next day", () => {
    const day = dayKey(at(12));
    expect(day).toBe("2026-11-19");
    expect(blockReason(rule, { day, minutes: 59, reported: 0 }, at(12))).toBeNull();
    expect(blockReason(rule, { day, minutes: 60, reported: 0 }, at(12))).toBe("limit_reached");
    expect(blockReason(rule, { day: "2026-11-18", minutes: 600, reported: 0 }, at(12))).toBeNull();
    expect(blockReason(rule, { day, minutes: 0, reported: 0 }, at(21))).toBe("outside_hours");
    expect(blockReason({ ...rule, daily_minutes: 0 }, { day, minutes: 900, reported: 0 }, at(12))).toBeNull();
    expect(blockReason(null, { day, minutes: 900, reported: 0 }, at(23))).toBeNull();
  });

  it("counts minutes per day and reports in batches", () => {
    let usage = usageFor(undefined, at(9));
    for (let i = 0; i < 4; i += 1) usage = addMinute(usage, at(9, i));
    expect(usage).toEqual({ day: "2026-11-19", minutes: 4, reported: 0 });
    expect(shouldReport(usage, rule)).toBe(false);
    usage = addMinute(usage, at(9, 5));
    expect(shouldReport(usage, rule)).toBe(true);
    expect(shouldReport({ ...usage, minutes: 60, reported: 58 }, rule)).toBe(true);
    expect(addMinute(usage, new Date(2026, 10, 20, 9))).toEqual({ day: "2026-11-20", minutes: 1, reported: 0 });
  });

  it("blocks web pages above the allow list but never Qalaa's server", () => {
    const blockRule = screenTimeBlockRule("qalaa.example");
    expect(blockRule.priority).toBeGreaterThan(2);
    expect(blockRule.condition.excludedRequestDomains).toEqual(["qalaa.example"]);
    expect(blockRule.condition.resourceTypes).toEqual(["main_frame"]);
  });
});

describe("screen time rule in the rule set", () => {
  it("stays on while checks are paused, and only while blocking", async () => {
    const { buildRules } = await import("../src/lib/blocklist");
    const { DEFAULT_SETTINGS } = await import("../src/lib/settings");
    const base = { ...DEFAULT_SETTINGS, serverUrl: "https://qalaa.example", screenTime: rule };
    expect(buildRules({ ...base, screenTimeBlocked: null }, []).map((r) => r.id)).not.toContain(10);
    expect(buildRules({ ...base, paused: true, screenTimeBlocked: "limit_reached" }, []).map((r) => r.id)).toEqual([10]);
  });
});
