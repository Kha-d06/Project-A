import { RISK, SEVERITY, STATUS_LABEL } from "./risk";

describe("verdict vocabulary", () => {
  it("never describes anything as safe", () => {
    const wording = [
      ...Object.values(RISK).flatMap((risk) => [risk.label, risk.short]),
      ...Object.values(SEVERITY).map((severity) => severity.label),
      ...Object.values(STATUS_LABEL),
    ];
    for (const text of wording) expect(text.toLowerCase()).not.toMatch(/\bsafe\b/);
  });

  it("states that no known threat is not a guarantee", () => {
    expect(RISK.no_known_threat.description).toMatch(/not a guarantee/i);
  });
});
