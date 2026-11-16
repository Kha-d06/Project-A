import type { Metadata } from "next";

import { IntelLookup } from "@/components/community/intel-lookup";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Threat intelligence" };

export default async function IntelligencePage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="mx-auto max-w-4xl space-y-8 px-4 py-12 sm:px-6 sm:py-16">
      <div className="space-y-3">
        <h1 className="font-display text-title font-bold text-ink sm:text-[2.25rem]">{t.intel.title}</h1>
        <p className="text-ink-muted">
          {t.intel.intro}{" "}
          <a href="/scan?type=url" className="text-accent underline underline-offset-4">
            {t.scanners.url}
          </a>
        </p>
      </div>
      <IntelLookup />
    </div>
  );
}
