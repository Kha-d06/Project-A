import { t } from "./i18n";
import type { Verdict } from "./types";

export interface VerdictPresentation {
  label: string;
  detail: string;
  tone: "danger" | "warning" | "clear" | "unknown" | "neutral";
  badge: string;
  /** Interrupt navigation with the warning page. */
  interrupts: "always" | "if_enabled" | "never";
}

/**
 * Wording shown in the popup, badge and warning page. As on the website, nothing
 * is called "safe": the best result is that no known threat was found.
 */
const BASE: Record<Verdict, Omit<VerdictPresentation, "label" | "detail">> = {
  dangerous: {
    tone: "danger",
    badge: "!",
    interrupts: "always",
  },
  suspicious: {
    tone: "warning",
    badge: "!",
    interrupts: "if_enabled",
  },
  caution: {
    tone: "warning",
    badge: "?",
    interrupts: "never",
  },
  no_known_threat: {
    tone: "clear",
    badge: "",
    interrupts: "never",
  },
  unavailable: {
    tone: "unknown",
    badge: "–",
    interrupts: "never",
  },
  skipped: {
    tone: "neutral",
    badge: "",
    interrupts: "never",
  },
  blocked_by_you: {
    tone: "danger",
    badge: "×",
    interrupts: "always",
  },
  allowed_by_you: {
    tone: "neutral",
    badge: "",
    interrupts: "never",
  },
};

/** Label and detail follow the current language (see i18n.ts). */
export const VERDICTS = Object.fromEntries(
  (Object.keys(BASE) as Verdict[]).map((verdict) => [
    verdict,
    {
      ...BASE[verdict],
      get label() {
        return t().verdicts[verdict].label;
      },
      get detail() {
        return t().verdicts[verdict].detail;
      },
    },
  ]),
) as Record<Verdict, VerdictPresentation>;

export const BADGE_COLORS: Record<VerdictPresentation["tone"], string> = {
  danger: "#b42318",
  warning: "#a15c07",
  clear: "#1d6b52",
  unknown: "#4f5878",
  neutral: "#4f5878",
};

export function shouldInterrupt(verdict: Verdict, warnOnSuspicious: boolean): boolean {
  const rule = VERDICTS[verdict].interrupts;
  return rule === "always" || (rule === "if_enabled" && warnOnSuspicious);
}
