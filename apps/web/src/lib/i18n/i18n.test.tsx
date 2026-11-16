import { render, screen } from "@testing-library/react";

import { RiskBadge } from "@/components/scan/risk-badge";

import { ar } from "./ar";
import { I18nProvider, fill } from "./client";
import { en } from "./en";
import { directionOf, negotiate } from "./locales";

describe("locale negotiation", () => {
  it.each([
    ["ar-SA,ar;q=0.9,en;q=0.8", "ar"],
    ["en-GB,en;q=0.9", "en"],
    ["fr-FR,fr;q=0.9", "en"],
    [null, "en"],
  ])("maps %s to %s", (header, locale) => expect(negotiate(header)).toBe(locale));

  it("lays Arabic out right to left", () => {
    expect(directionOf("ar")).toBe("rtl");
    expect(directionOf("en")).toBe("ltr");
  });
});

describe("Arabic dictionary", () => {
  it("never calls a verdict safe", () => {
    for (const risk of Object.values(ar.risk)) {
      expect(`${risk.label} ${risk.short}`).not.toMatch(/آمن/);
    }
    expect(ar.risk.no_known_threat.description).toContain("ليس ضمانًا");
  });

  it("uses Arabic number agreement", () => {
    expect(ar.report.warningSigns(1)).toBe("علامة تحذير واحدة");
    expect(ar.report.warningSigns(2)).toBe("علامتا تحذير");
    expect(ar.report.warningSigns(5)).toBe("5 علامات تحذير");
    expect(ar.report.warningSigns(12)).toBe("12 علامة تحذير");
    expect(en.report.warningSigns(1)).toBe("1 warning sign");
  });

  it("translates every verdict and scanner differently from English", () => {
    for (const key of Object.keys(en.risk) as (keyof typeof en.risk)[]) {
      expect(ar.risk[key].label).not.toBe(en.risk[key].label);
    }
    for (const key of Object.keys(en.scanners) as (keyof typeof en.scanners)[]) {
      expect(ar.scanners[key]).not.toBe(en.scanners[key]);
    }
  });
});

describe("I18nProvider", () => {
  it("renders components in the chosen language", () => {
    render(
      <I18nProvider locale="ar">
        <RiskBadge risk="suspicious" status="completed" />
      </I18nProvider>,
    );
    expect(screen.getByText("مشبوه")).toBeInTheDocument();
  });

  it("fills placeholders", () => {
    expect(fill("{n} of {total}", { n: 2, total: 5 })).toBe("2 of 5");
  });
});
