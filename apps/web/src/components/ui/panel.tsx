import type { ComponentProps, ReactNode } from "react";

import { cn } from "@/lib/cn";

export function Panel({ className, ...props }: ComponentProps<"section">) {
  return (
    <section
      className={cn("rounded-panel border border-line bg-surface", className)}
      {...props}
    />
  );
}

export function PanelHeader({
  title,
  description,
  action,
  as: Heading = "h2",
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  as?: "h2" | "h3";
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-4">
      <div className="min-w-0 space-y-0.5">
        <Heading className="font-display text-base font-semibold text-ink">{title}</Heading>
        {description && <p className="text-sm text-ink-muted">{description}</p>}
      </div>
      {action}
    </div>
  );
}
