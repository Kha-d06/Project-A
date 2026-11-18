import type { Metadata } from "next";
import { Suspense } from "react";

import { ScanCenter } from "@/components/scan/scan-center";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Scan something" };

export default async function ScanPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="relative isolate">
      <div aria-hidden className="bg-survey absolute inset-0 -z-10" />
      <div aria-hidden className="glow-top absolute inset-0 -z-10" />
      <div className="mx-auto max-w-3xl space-y-8 px-4 py-14 sm:px-6 sm:py-20">
        <div className="space-y-3">
          <h1 className="font-display text-title font-semibold text-balance text-ink sm:text-[2.6rem]">{t.scan.heading}</h1>
          <p className="text-pretty text-ink-muted sm:text-lg">{t.scan.intro}</p>
        </div>
        <Suspense>
          <ScanCenter reportBase="/scans" />
        </Suspense>
      </div>
    </div>
  );
}
