import type { Metadata } from "next";

import { ReportForm } from "@/components/community/report-form";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Report a scam" };

export default async function ReportPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="mx-auto max-w-2xl space-y-8 px-4 py-12 sm:px-6 sm:py-16">
      <div className="space-y-3">
        <h1 className="font-display text-title font-bold text-ink sm:text-[2.25rem]">{t.community.title}</h1>
        <p className="text-ink-muted">{t.community.intro}</p>
      </div>
      <ReportForm />
    </div>
  );
}
