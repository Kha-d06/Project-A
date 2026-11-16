import { CircleHelp, Loader, OctagonAlert, ShieldCheck, TriangleAlert, XCircle } from "lucide-react";

import type { RiskLevel, ScanStatus } from "@/lib/api/types";
import { cn } from "@/lib/cn";
import { RISK, STATUS_LABEL, TONE_CLASSES, isActive } from "@/lib/risk";

const RISK_ICON: Record<RiskLevel, typeof ShieldCheck> = {
  known_malicious: OctagonAlert,
  suspicious: TriangleAlert,
  no_known_threat: ShieldCheck,
  inconclusive: CircleHelp,
};

export function RiskIcon({ risk, className }: { risk: RiskLevel; className?: string }) {
  const Icon = RISK_ICON[risk];
  return <Icon aria-hidden className={className} />;
}

/** Compact verdict chip. Always carries text and an icon, never colour alone. */
export function RiskBadge({
  risk,
  status,
  className,
}: {
  risk: RiskLevel | null;
  status: ScanStatus;
  className?: string;
}) {
  const chip = "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium";

  if (isActive(status)) {
    return (
      <span className={cn(chip, "border-line-strong text-ink-muted", className)}>
        <Loader aria-hidden className="size-3.5 motion-safe:animate-spin" />
        {STATUS_LABEL[status]}
      </span>
    );
  }
  if (status === "failed" || risk === null) {
    return (
      <span className={cn(chip, "border-line-strong text-ink-muted", className)}>
        <XCircle aria-hidden className="size-3.5" />
        Scan failed
      </span>
    );
  }
  const presentation = RISK[risk];
  const tone = TONE_CLASSES[presentation.tone];
  const Icon = RISK_ICON[risk];
  return (
    <span className={cn(chip, tone.border, tone.soft, tone.text, className)}>
      <Icon aria-hidden className="size-3.5" />
      {presentation.short}
    </span>
  );
}
