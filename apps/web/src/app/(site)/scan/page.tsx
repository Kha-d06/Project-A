import type { Metadata } from "next";
import { Suspense } from "react";

import { ScanCenter } from "@/components/scan/scan-center";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Scan something" };

export default async function ScanPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="mx-auto max-w-3xl space-y-8 px-4 py-12 sm:px-6 sm:py-16">
      <div className="space-y-3">
        <h1 className="font-display text-title font-bold text-ink sm:text-[2.25rem]">
          {t.scan.heading}
        </h1>
        <p className="text-ink-muted">{t.scan.intro}</p>
      </div>
      <Suspense>
        <ScanCenter reportBase="/scans" />
      </Suspense>
    </div>
  );
}
