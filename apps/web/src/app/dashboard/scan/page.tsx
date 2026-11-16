import type { Metadata } from "next";
import { Suspense } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { ScanCenter } from "@/components/scan/scan-center";
import { getDictionary, getLocale } from "@/lib/i18n/server";

export const metadata: Metadata = { title: "Scan center" };

export default async function DashboardScanPage() {
  const t = getDictionary(await getLocale());
  return (
    <div className="max-w-3xl">
      <PageTitle title={t.dashboard.nav.scanCenter} description={t.dashboard.scanCenter.description} />
      <Suspense>
        <ScanCenter reportBase="/dashboard/scans" />
      </Suspense>
    </div>
  );
}
