import { AlertTriangle, CircleAlert, Info } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/cn";

type Tone = "info" | "warning" | "danger";

const tones: Record<Tone, { box: string; icon: typeof Info }> = {
  info: { box: "border-line bg-surface-sunken text-ink", icon: Info },
  warning: { box: "border-warning/40 bg-warning-soft text-ink", icon: AlertTriangle },
  danger: { box: "border-danger/40 bg-danger-soft text-ink", icon: CircleAlert },
};

export function Alert({
  tone = "info",
  title,
  children,
  className,
}: {
  tone?: Tone;
  title?: string;
  children?: ReactNode;
  className?: string;
}) {
  const { box, icon: Icon } = tones[tone];
  return (
    <div
      role={tone === "info" ? "status" : "alert"}
      className={cn("flex gap-3 rounded-control border px-4 py-3 text-sm", box, className)}
    >
      <Icon
        aria-hidden
        className={cn(
          "mt-0.5 size-4 shrink-0",
          tone === "danger" ? "text-danger" : tone === "warning" ? "text-warning" : "text-ink-muted",
        )}
      />
      <div className="space-y-1">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className="text-ink-muted">{children}</div>}
      </div>
    </div>
  );
}
