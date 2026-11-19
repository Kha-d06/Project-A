import { ShieldAlert } from "lucide-react";

import { LogoMark } from "@/components/brand/logo";
import type { Dictionary } from "@/lib/i18n/en";

type Guard = Dictionary["home"]["guard"];

/**
 * A still picture of what Qalaa Protect does: the browser was about to open a
 * look-alike page and the extension put its warning in front of it. Static on
 * purpose: the homepage has one animated moment (the hero report), and a loop
 * here would only compete with the words beside it.
 */
export function BrowserGuardVisual({ g }: { g: Guard }) {
  return (
    <div aria-hidden className="w-full select-none">
      <div className="overflow-hidden rounded-panel border border-line bg-surface">
        {/* Window chrome: the address the person was about to open. */}
        <div className="flex items-center gap-3 border-b border-line bg-surface-sunken/60 px-4 py-3">
          <span className="flex gap-1.5">
            <span className="size-2.5 rounded-full bg-line-strong" />
            <span className="size-2.5 rounded-full bg-line-strong" />
            <span className="size-2.5 rounded-full bg-line-strong" />
          </span>
          <span className="flex h-7 min-w-0 flex-1 items-center rounded-control border border-line bg-surface px-3 font-mono text-[0.75rem] text-ink-muted" dir="ltr">
            <span className="truncate">{g.address}</span>
          </span>
          <LogoMark className="size-5" />
        </div>
        {/* The warning Qalaa shows instead of the page. */}
        <div className="flex flex-col items-start gap-4 px-6 py-10 sm:px-8">
          <span className="grid size-11 place-items-center rounded-control bg-danger-soft text-danger">
            <ShieldAlert className="size-5" />
          </span>
          <div className="space-y-1.5">
            <p className="text-lg font-medium text-ink">{g.title}</p>
            <p className="max-w-sm text-[0.9375rem] text-ink-muted">{g.reason}</p>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            <span className="inline-flex h-9 items-center rounded-control bg-accent px-4 text-sm font-medium text-accent-ink">{g.back}</span>
            <span className="inline-flex h-9 items-center rounded-control px-3 text-sm text-ink-muted">{g.proceed}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
