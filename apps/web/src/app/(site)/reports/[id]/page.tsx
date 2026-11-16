import type { Metadata } from "next";

import { ReportStatus } from "@/components/community/report-status";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Report status", robots: { index: false } };

export default async function ReportStatusPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ token?: string }>;
}) {
  const [{ id }, { token }] = await Promise.all([params, searchParams]);
  const t = getDictionary(await getLocale());
  return (
    <div className="mx-auto max-w-2xl space-y-6 px-4 py-12 sm:px-6 sm:py-16">
      <h1 className="font-display text-title font-bold text-ink">{t.community.statusTitle}</h1>
      <ReportStatus id={id} token={token ?? null} />
    </div>
  );
}
