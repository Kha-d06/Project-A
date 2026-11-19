import type { ReactNode } from "react";

import { cn } from "@/lib/cn";

/**
 * A landing-page section: a heading and an optional intro, then content.
 *
 * No label above the heading and no scroll-triggered entrance: the content is
 * visible in the server-rendered HTML, whatever the visitor's motion setting or
 * whether scripts have run.
 */
export function Section({
  id,
  title,
  intro,
  children,
  className,
}: {
  id?: string;
  title: string;
  intro?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section id={id} aria-labelledby={id ? `${id}-title` : undefined} className={cn("scroll-mt-20 border-t border-line", className)}>
      <div className="mx-auto max-w-6xl px-4 py-20 sm:px-6 sm:py-24">
        <div className="grid gap-4 lg:grid-cols-12 lg:gap-8">
          <h2 id={id ? `${id}-title` : undefined} className="text-title font-medium text-ink lg:col-span-5">
            {title}
          </h2>
          {intro && <div className="max-w-xl text-ink-muted sm:text-lg sm:leading-relaxed lg:col-span-6 lg:col-start-7 lg:pt-1.5">{intro}</div>}
        </div>
        <div className="mt-10 sm:mt-12">{children}</div>
      </div>
    </section>
  );
}
