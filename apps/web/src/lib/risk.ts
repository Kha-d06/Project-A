import type { RiskLevel, ScanStatus, Severity } from "./api/types";

/**
 * The one place verdict wording is defined. Note what is absent: there is no
 * "safe". The best outcome SENTINEL reports is that no known threat was found.
 */

export type Tone = "danger" | "warning" | "clear" | "unknown" | "neutral";

export interface RiskPresentation {
  label: string;
  short: string;
  tone: Tone;
  description: string;
}

export const RISK: Record<RiskLevel, RiskPresentation> = {
  known_malicious: {
    label: "Known threat",
    short: "Known threat",
    tone: "danger",
    description: "Reliable threat intelligence or a malware signature identifies this as malicious.",
  },
  suspicious: {
    label: "Suspicious",
    short: "Suspicious",
    tone: "warning",
    description: "Warning signs were found, but nothing confirms it is malicious.",
  },
  no_known_threat: {
    label: "No known threat detected",
    short: "No known threat",
    tone: "clear",
    description: "The checks finished without finding known indicators. This is not a guarantee of safety.",
  },
  inconclusive: {
    label: "Inconclusive",
    short: "Inconclusive",
    tone: "unknown",
    description: "A check the verdict depends on was unavailable, so no conclusion was reached.",
  },
};

export const STATUS_LABEL: Record<ScanStatus, string> = {
  queued: "Queued",
  processing: "Scanning",
  completed: "Completed",
  failed: "Failed",
  inconclusive: "Inconclusive",
};

export const SEVERITY: Record<Severity, { label: string; tone: Tone }> = {
  critical: { label: "Confirmed threat", tone: "danger" },
  high: { label: "High concern", tone: "danger" },
  medium: { label: "Warning sign", tone: "warning" },
  low: { label: "Minor concern", tone: "neutral" },
  info: { label: "For context", tone: "neutral" },
};

export const TONE_CLASSES: Record<Tone, { text: string; soft: string; border: string }> = {
  danger: { text: "text-danger", soft: "bg-danger-soft", border: "border-danger/35" },
  warning: { text: "text-warning", soft: "bg-warning-soft", border: "border-warning/35" },
  clear: { text: "text-clear", soft: "bg-clear-soft", border: "border-clear/35" },
  unknown: { text: "text-unknown", soft: "bg-unknown-soft", border: "border-unknown/35" },
  neutral: { text: "text-ink-muted", soft: "bg-surface-sunken", border: "border-line-strong" },
};

export const SCAN_TYPE_LABEL = {
  url: "Link",
  message: "Message",
  file: "File",
  qr: "QR code",
  website: "Website",
  apk: "Android app",
} as const;

export function isActive(status: ScanStatus): boolean {
  return status === "queued" || status === "processing";
}
