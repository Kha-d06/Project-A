import type { Metadata } from "next";
import { Suspense } from "react";

import { PageTitle } from "@/components/dashboard/dashboard-shell";
import { ScanCenter } from "@/components/scan/scan-center";

export const metadata: Metadata = { title: "Scan center" };

export default function DashboardScanPage() {
  return (
    <div className="max-w-3xl">
      <PageTitle title="Scan center" description="Results are saved to your history unless you have switched that off." />
      <Suspense>
        <ScanCenter reportBase="/dashboard/scans" />
      </Suspense>
    </div>
  );
}
