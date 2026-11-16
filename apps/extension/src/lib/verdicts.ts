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
export const VERDICTS: Record<Verdict, VerdictPresentation> = {
  dangerous: {
    label: "Dangerous",
    detail: "This site is listed in threat intelligence as malicious.",
    tone: "danger",
    badge: "!",
    interrupts: "always",
  },
  suspicious: {
    label: "Suspicious",
    detail: "Strong warning signs, such as a look-alike of a well-known brand.",
    tone: "warning",
    badge: "!",
    interrupts: "if_enabled",
  },
  caution: {
    label: "Caution",
    detail: "Some warning signs. Be careful with passwords and payments here.",
    tone: "warning",
    badge: "?",
    interrupts: "never",
  },
  no_known_threat: {
    label: "No known threat",
    detail: "Checks found no known problems. That is not a guarantee of safety.",
    tone: "clear",
    badge: "",
    interrupts: "never",
  },
  unavailable: {
    label: "Check unavailable",
    detail: "SENTINEL could not check this site, so it is not protected right now.",
    tone: "unknown",
    badge: "–",
    interrupts: "never",
  },
  skipped: {
    label: "Not checked",
    detail: "Local and private-network addresses are not checked.",
    tone: "neutral",
    badge: "",
    interrupts: "never",
  },
  blocked_by_you: {
    label: "Blocked by you",
    detail: "This site is on your block list.",
    tone: "danger",
    badge: "×",
    interrupts: "always",
  },
  allowed_by_you: {
    label: "Not checked (allowed by you)",
    detail: "This site is on your allow list, so SENTINEL does not check it.",
    tone: "neutral",
    badge: "",
    interrupts: "never",
  },
};

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
